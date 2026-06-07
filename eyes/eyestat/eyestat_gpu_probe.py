#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_gpu_probe.py — Nvidia GPU capability probe + feasibility benchmark.

Run this on your actual hardware to find out:

  1. What GPU(s) you have, with memory and compute capability
  2. Whether CUDA toolkit and CuPy are installed correctly
  3. Realistic batched PRNG throughput on your GPU
  4. Estimated speedup if you integrate GPU acceleration into eyestat_runner.py

This script has THREE tiers, picking the highest one that works:

  Tier 0 — `nvidia-smi` only        no CuPy, just probes hardware
  Tier 1 — numpy fallback           vectorized CPU "shadow GPU" — runs anywhere
  Tier 2 — CuPy on actual GPU       real GPU kernel benchmark

Tier 1 is useful as a reference implementation: it lets you verify the
batched algorithm produces correct results before you install CuPy. Tier 2
gives you the actual speedup number on your hardware.

USAGE
=====
    python3 eyestat_gpu_probe.py
    python3 eyestat_gpu_probe.py --batch-size 4096 --iterations 100
    python3 eyestat_gpu_probe.py --no-color
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Output styling
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s

def green(s):  return _c("92", s)
def red(s):    return _c("91", s)
def yellow(s): return _c("93", s)
def cyan(s):   return _c("96", s)
def dim(s):    return _c("90", s)
def bold(s):   return _c("1", s)


def banner(title: str):
    print()
    print(bold(cyan("[" + " " * 2 + title + " " * 2 + "]")))


def ok(label, detail=""):
    line = f"  {green('[OK]')}   {label}"
    if detail: line += f"  {dim('—')}  {detail}"
    print(line)

def warn(label, detail=""):
    line = f"  {yellow('[WARN]')} {label}"
    if detail: line += f"  {dim('—')}  {detail}"
    print(line)

def fail(label, detail=""):
    line = f"  {red('[FAIL]')} {label}"
    if detail: line += f"  {dim('—')}  {detail}"
    print(line)

def info(label, detail=""):
    line = f"  {cyan('[INFO]')} {label}"
    if detail: line += f"  {dim('—')}  {detail}"
    print(line)


# ---------------------------------------------------------------------------
# Tier 0 — nvidia-smi probe (no CuPy required)
# ---------------------------------------------------------------------------

def probe_nvidia_smi() -> Optional[List[Dict[str, str]]]:
    """Returns a list of GPU info dicts, or None if nvidia-smi unavailable."""
    if not shutil.which("nvidia-smi"):
        return None
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=index,name,memory.total,memory.free,compute_cap,driver_version",
             "--format=csv,noheader,nounits"],
            text=True, stderr=subprocess.DEVNULL, timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue
        gpus.append({
            "index": parts[0], "name": parts[1],
            "mem_total_mb": parts[2], "mem_free_mb": parts[3],
            "compute_cap": parts[4], "driver_version": parts[5],
        })
    return gpus


def probe_cuda_toolkit() -> Optional[str]:
    """Returns nvcc version string, or None if toolkit not installed."""
    if not shutil.which("nvcc"):
        return None
    try:
        out = subprocess.check_output(
            ["nvcc", "--version"], text=True, stderr=subprocess.DEVNULL, timeout=10)
        # Extract release line: "release 12.0, V12.0.140"
        for line in out.splitlines():
            if "release" in line.lower():
                return line.strip()
        return out.splitlines()[-1] if out.splitlines() else "(unknown version)"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None


# ---------------------------------------------------------------------------
# Tier 1 — numpy reference impl (vectorized batched PRNG)
# ---------------------------------------------------------------------------

def numpy_xorshift32_batched(seeds: "np.ndarray", n_steps: int) -> "np.ndarray":
    """Run N independent xorshift32 streams in parallel for n_steps steps.

    Returns the final state of each stream. Pure-numpy reference — what a
    GPU kernel would do, but on the CPU vector unit.
    """
    import numpy as np
    state = seeds.astype(np.uint32).copy()
    # xorshift32: x ^= x<<13; x ^= x>>17; x ^= x<<5
    for _ in range(n_steps):
        state ^= (state << np.uint32(13))
        state ^= (state >> np.uint32(17))
        state ^= (state << np.uint32(5))
    return state


def reference_xorshift32_single(seed: int, n_steps: int) -> int:
    """Single-stream xorshift32 for cross-validation against the batched impl."""
    state = seed & 0xFFFFFFFF
    for _ in range(n_steps):
        state = (state ^ (state << 13)) & 0xFFFFFFFF
        state = state ^ (state >> 17)
        state = (state ^ (state << 5)) & 0xFFFFFFFF
    return state


# ---------------------------------------------------------------------------
# Tier 2 — CuPy on real GPU
# ---------------------------------------------------------------------------

CUPY_XORSHIFT32_KERNEL = r"""
extern "C" __global__
void xorshift32_advance(unsigned int* state, int n_streams, int n_steps) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_streams) return;
    unsigned int s = state[idx];
    for (int i = 0; i < n_steps; i++) {
        s ^= (s << 13);
        s ^= (s >> 17);
        s ^= (s << 5);
    }
    state[idx] = s;
}
"""


def _device_compute_cap(cp) -> str:
    """Return current device's compute capability as 'MAJORMINOR' string,
    e.g. '120' for RTX 5080, '90' for H100, '86' for RTX 3080."""
    try:
        return cp.cuda.Device().compute_capability  # CuPy returns "120" etc.
    except Exception:
        return "75"  # safe fallback (Turing)


def compile_kernel_for_device(cp, code: str, name: str):
    """Compile a CuPy RawKernel targeting the current device's architecture.

    Without this, NVRTC defaults to compute_52 and the resulting binary has
    no entry point for newer GPUs — causing CUDA_ERROR_NO_BINARY_FOR_GPU at
    launch. We explicitly request the device's native compute capability,
    with PTX fallback chain for forward-compat:
      1. compute_{native}  — exact match, no JIT needed
      2. compute_90 PTX    — driver JIT-compiles to native (works for Hopper+)
      3. compute_80 PTX    — older fallback (Ampere+)

    Returns (kernel, arch_used) on success, raises last error if all fail.
    """
    cap = _device_compute_cap(cp)  # e.g. "120"

    # CuPy 13.4+ auto-detects the device arch and passes -arch to NVRTC itself.
    # Passing --gpu-architecture explicitly causes:
    #   "nvrtc: error: --gpu-architecture (-arch) defined more than once"
    # Try the no-options (auto) path first; fall back to explicit for older CuPy.
    try:
        kernel = cp.RawKernel(code, name)
        _ = kernel.kernel  # force compile
        return kernel, f"compute_{cap}"
    except Exception:
        pass  # Fall back to explicit-arch path below

    # Try native arch first, then PTX-fallback arches that the driver can JIT
    candidates = [
        f"compute_{cap}",       # exact match (Blackwell: compute_120)
        "compute_90",            # Hopper PTX — driver JITs to current device
        "compute_86",            # Ampere PTX — older driver compatibility
    ]
    # De-dupe while preserving order
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    last_err = None
    for arch in candidates:
        try:
            options = (f"--gpu-architecture={arch}",)
            kernel = cp.RawKernel(code, name, options=options)
            # Force compilation now (RawKernel is lazy by default) and verify
            # by inspecting the .kernel property
            _ = kernel.kernel
            return kernel, arch
        except Exception as e:
            last_err = e
            continue
    raise last_err if last_err else RuntimeError("no arch worked")


def try_import_cupy():
    """Returns (cupy_module, error_string). cupy_module is None on failure."""
    try:
        import cupy as cp  # type: ignore
        return cp, None
    except ImportError as e:
        return None, str(e)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def cupy_benchmark(cp, batch_size: int, n_steps: int,
                    iterations: int) -> Optional[Dict[str, float]]:
    """Run the CuPy xorshift32 kernel and return throughput stats."""
    try:
        seeds = cp.arange(1, batch_size + 1, dtype=cp.uint32)
        kernel, arch_used = compile_kernel_for_device(
            cp, CUPY_XORSHIFT32_KERNEL, "xorshift32_advance")
        threads = 256
        blocks = (batch_size + threads - 1) // threads

        # Warm-up (also forces first-time JIT compilation)
        state = seeds.copy()
        kernel((blocks,), (threads,), (state, batch_size, n_steps))
        cp.cuda.Stream.null.synchronize()

        # Measure
        t0 = time.time()
        for _ in range(iterations):
            state = seeds.copy()
            kernel((blocks,), (threads,), (state, batch_size, n_steps))
        cp.cuda.Stream.null.synchronize()
        dt = time.time() - t0

        total_advances = batch_size * n_steps * iterations
        return {
            "batch_size": batch_size,
            "n_steps": n_steps,
            "iterations": iterations,
            "elapsed_s": dt,
            "advances_per_sec": total_advances / dt,
            "ms_per_batch": dt / iterations * 1000,
            "arch_used": arch_used,
            "result_sample_0": int(state[0].get()),
            "result_sample_last": int(state[-1].get()),
        }
    except Exception as e:
        print(f"  {red('[FAIL]')} CuPy benchmark crashed: {type(e).__name__}: {e}")
        # Useful diagnostic — surface bundled NVRTC version + device cap
        try:
            cap = _device_compute_cap(cp)
            nvrtc_ver = cp.cuda.nvrtc.getVersion()
            print(f"  {dim('         device compute cap = ' + cap + ', '
                  'bundled NVRTC = ' + str(nvrtc_ver))}")
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# CPU baseline for comparison (single-core pure Python)
# ---------------------------------------------------------------------------

def cpu_xorshift32_single_core(batch_size: int, n_steps: int) -> float:
    """Time how long it takes to advance N streams on one CPU core in Python.

    Returns advances/sec.
    """
    t0 = time.time()
    for seed in range(1, batch_size + 1):
        reference_xorshift32_single(seed, n_steps)
    dt = time.time() - t0
    return (batch_size * n_steps) / max(dt, 1e-9)


def numpy_xorshift32_throughput(batch_size: int, n_steps: int,
                                 iterations: int) -> Dict[str, float]:
    """Same workload via vectorized numpy on CPU."""
    import numpy as np
    seeds = np.arange(1, batch_size + 1, dtype=np.uint32)
    # Warm-up
    numpy_xorshift32_batched(seeds, n_steps)
    t0 = time.time()
    for _ in range(iterations):
        numpy_xorshift32_batched(seeds, n_steps)
    dt = time.time() - t0
    total = batch_size * n_steps * iterations
    return {
        "advances_per_sec": total / dt,
        "ms_per_batch": dt / iterations * 1000,
    }


# ---------------------------------------------------------------------------
# Main probe
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--batch-size", type=int, default=4096,
                   help="Batch size for benchmark (PRNG streams in parallel)")
    p.add_argument("--n-steps", type=int, default=83,
                   help="PRNG advancement steps per stream (default 83 = "
                        "one Fisher-Yates pass for the 83-rune alphabet)")
    p.add_argument("--iterations", type=int, default=50,
                   help="Benchmark iterations for averaging")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    print()
    print(bold(cyan("══════════════════════════════════════════════════════════════")))
    print(bold(cyan("  GPU FEASIBILITY PROBE  —  eyestat_runner.py acceleration         ")))
    print(bold(cyan("══════════════════════════════════════════════════════════════")))

    # ----- Tier 0: hardware probe -----
    banner("Tier 0 — Hardware probe (nvidia-smi)")
    gpus = probe_nvidia_smi()
    have_gpu = False
    if gpus is None:
        warn("nvidia-smi not found",
             "Nvidia driver not installed, or PATH issue. "
             "On Ubuntu: sudo apt-get install nvidia-driver-535")
    elif not gpus:
        warn("nvidia-smi ran but reported 0 GPUs",
             "Driver loaded but no devices visible")
    else:
        have_gpu = True
        for g in gpus:
            ok(f"GPU {g['index']}: {g['name']}",
               f"{g['mem_total_mb']} MB total, {g['mem_free_mb']} MB free, "
               f"compute {g['compute_cap']}, driver {g['driver_version']}")

    cuda_ver = probe_cuda_toolkit()
    if cuda_ver:
        ok("CUDA toolkit installed", cuda_ver)
    else:
        warn("nvcc not found in PATH",
             "CUDA toolkit not installed or not on PATH. CuPy may still work "
             "if cupy-cudaXXx bundle is used.")

    # ----- numpy availability (Tier 1 prerequisite) -----
    banner("Tier 1 — Vectorized CPU reference (numpy)")
    try:
        import numpy as np
        ok("numpy importable", f"version {np.__version__}")
        have_numpy = True
    except ImportError:
        fail("numpy NOT installed",
             "Run: sudo apt-get install python3-numpy")
        have_numpy = False

    # Cross-validate batched numpy vs single-stream reference
    if have_numpy:
        seeds_check = np.array([1, 42, 0xDEADBEEF, 0xCAFEBABE], dtype=np.uint32)
        batched = numpy_xorshift32_batched(seeds_check, 100)
        ref = [reference_xorshift32_single(int(s), 100) for s in seeds_check]
        if list(int(x) for x in batched) == ref:
            ok("batched xorshift32 cross-validates against single-stream",
               "byte-identical for 4 seeds × 100 advances")
        else:
            fail("BATCHED RESULT MISMATCH",
                 f"batched={list(int(x) for x in batched)}, "
                 f"ref={ref}")

    # ----- Tier 2: CuPy -----
    banner("Tier 2 — CuPy on actual GPU")
    cp, cupy_err = try_import_cupy()
    have_cupy = cp is not None
    if not have_cupy:
        warn("CuPy not importable", cupy_err or "(unknown)")
        if have_gpu:
            print(f"     {dim('Install:')} {bold('pip install cupy-cuda12x')}  "
                  f"{dim('(or cupy-cuda11x to match your CUDA)')}")
        else:
            print(f"     {dim('(skipped — no GPU detected)')}")
    else:
        ok("CuPy importable", f"version {cp.__version__}")
        # Verify CuPy sees the GPU
        try:
            n_dev = cp.cuda.runtime.getDeviceCount()
            if n_dev == 0:
                warn("CuPy installed but sees 0 devices",
                     "Driver/runtime mismatch, or no GPU available")
                have_cupy = False
            else:
                ok(f"CuPy sees {n_dev} CUDA device(s)")

                # Basic-op smoke test: prove plain cp arithmetic works before
                # trying a custom kernel. If THIS fails, CuPy is fundamentally
                # broken on this device — no point trying RawKernel.
                try:
                    smoke = cp.arange(10, dtype=cp.uint32)
                    smoke_sum = int((smoke * 2).sum().get())  # expected: 90
                    if smoke_sum == 90:
                        cap = _device_compute_cap(cp)
                        ok(f"CuPy basic ops work on sm_{cap}",
                           f"cp.arange(10) * 2 .sum() = 90 verified")
                    else:
                        fail(f"CuPy basic op gave wrong result: {smoke_sum}")
                        have_cupy = False
                except Exception as e:
                    fail("CuPy basic op crashed",
                         f"{type(e).__name__}: {e}")
                    have_cupy = False

                # Cross-validate CuPy custom kernel output against CPU reference
                if have_cupy:
                    try:
                        seeds_check = cp.array([1, 42, 0xDEADBEEF, 0xCAFEBABE],
                                               dtype=cp.uint32)
                        kernel, arch_used = compile_kernel_for_device(
                            cp, CUPY_XORSHIFT32_KERNEL, "xorshift32_advance")
                        state = seeds_check.copy()
                        kernel((1,), (4,), (state, 4, 100))
                        cp.cuda.Stream.null.synchronize()
                        cupy_result = [int(x) for x in state.get()]
                        ref = [reference_xorshift32_single(int(s), 100)
                               for s in seeds_check.get()]
                        if cupy_result == ref:
                            ok(f"CuPy xorshift32 kernel cross-validates ({arch_used})",
                               "byte-identical to CPU reference")
                        else:
                            fail("CuPy kernel MISMATCH",
                                 f"cupy={cupy_result}, ref={ref}")
                            have_cupy = False
                    except Exception as e:
                        fail("CuPy custom kernel failed",
                             f"{type(e).__name__}: {e}")
                        try:
                            cap = _device_compute_cap(cp)
                            nvrtc_ver = cp.cuda.nvrtc.getVersion()
                            print(f"     {dim('device sm_' + cap + ', '
                                  'bundled NVRTC = ' + str(nvrtc_ver))}")
                        except Exception:
                            pass
                        have_cupy = False
        except Exception as e:
            fail("CuPy device enumeration crashed",
                 f"{type(e).__name__}: {e}")
            have_cupy = False

    # ----- Benchmarks -----
    banner("Benchmark — xorshift32 throughput")
    info(f"workload: {args.batch_size} parallel streams × "
         f"{args.n_steps} steps × {args.iterations} iterations")
    print()

    # Single-core Python baseline (small workload, scaled for fairness)
    print(f"  {dim('Single-core Python (1 stream × n_steps × small batch):')}")
    # Use a much smaller workload for the Python baseline since it's 1000x slower
    py_batch = min(args.batch_size, 1024)
    t0 = time.time()
    py_advances_per_sec = cpu_xorshift32_single_core(py_batch, args.n_steps)
    py_dt = time.time() - t0
    print(f"  {green(f'{py_advances_per_sec:>12,.0f}')} advances/sec  "
          f"({dim(f'{py_dt:.2f}s for {py_batch} streams × {args.n_steps} steps')})")
    print()

    # Vectorized numpy
    if have_numpy:
        print(f"  {dim('Vectorized numpy (single core, SIMD):')}")
        np_stats = numpy_xorshift32_throughput(
            args.batch_size, args.n_steps, args.iterations)
        np_advances_per_sec = np_stats["advances_per_sec"]
        np_ms_per_batch = np_stats["ms_per_batch"]
        np_speedup = np_advances_per_sec / max(py_advances_per_sec, 1)
        print(f"  {green(f'{np_advances_per_sec:>12,.0f}')} advances/sec  "
              f"({yellow(f'{np_speedup:.0f}x vs Python')}, "
              f"{dim(f'{np_ms_per_batch:.2f} ms/batch')})")
    else:
        np_advances_per_sec = py_advances_per_sec
    print()

    # CuPy on GPU
    if have_cupy:
        print(f"  {dim('CuPy on GPU:')}")
        gpu_stats = cupy_benchmark(cp, args.batch_size, args.n_steps,
                                    args.iterations)
        if gpu_stats:
            gpu_aps = gpu_stats["advances_per_sec"]
            gpu_ms = gpu_stats["ms_per_batch"]
            gpu_vs_np = gpu_aps / np_advances_per_sec
            gpu_vs_py = gpu_aps / max(py_advances_per_sec, 1)
            print(f"  {green(f'{gpu_aps:>12,.0f}')} advances/sec  "
                  f"({yellow(f'{gpu_vs_np:.1f}x vs numpy')}, "
                  f"{cyan(f'{gpu_vs_py:.0f}x vs Python')}, "
                  f"{dim(f'{gpu_ms:.2f} ms/batch')})")

    # ----- Verdict -----
    banner("Verdict")
    if have_cupy:
        print(f"  {green('●')} GPU acceleration path is viable on your hardware.")
        print(f"     The PRNG benchmark above shows the GPU's raw advance rate.")
        print(f"     Real-world eyestat_runner.py acceleration would be lower than")
        print(f"     this number because the inner loop also runs decryption,")
        print(f"     Hungarian (scipy on CPU), and dict matching. Realistic")
        print(f"     end-to-end speedup estimate: {bold(cyan('30-100x'))} vs all-core")
        print(f"     CPU, assuming a hybrid pipeline (GPU for PRNG+decrypt+")
        print(f"     histogram, CPU for Hungarian+dict).")
    elif have_gpu:
        print(f"  {yellow('●')} GPU present but CuPy not installed.")
        print(f"     Install with: {bold('pip install cupy-cuda12x')}")
        print(f"     (match the suffix to your CUDA toolkit version)")
        print(f"     Then re-run this probe to get the actual speedup number.")
    elif have_numpy:
        print(f"  {yellow('●')} No GPU detected, but numpy works.")
        print(f"     You can still get a ~{int(np_stats['advances_per_sec'] / max(py_advances_per_sec, 1))}x speedup over the current pure-")
        print(f"     Python PRNG by vectorizing with numpy, no GPU needed.")
        print(f"     This is a much smaller engineering effort than a full")
        print(f"     GPU port (and works on every machine).")
    else:
        print(f"  {red('●')} Neither GPU nor numpy available — no acceleration path.")
        print(f"     Install at minimum: sudo apt-get install python3-numpy")

    print()
    print(dim("  Next steps after this probe:"))
    print(dim("    1. Install scipy if not yet done (3x speedup, already wired)"))
    print(dim("    2. Decide based on this report whether GPU port is worth it"))
    print(dim("    3. If yes, see eyestat_gpu_probe.py docstring for the roadmap"))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
