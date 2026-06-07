#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_gpu_validate.py — Validate GPU park_miller + Fisher-Yates against the CPU.

This is Phase 1 of the GPU integration: prove the foundation kernels produce
byte-identical output to the existing CPU implementation. Two tests:

  1. park_miller_sequence       — 1000 seeds × 100 advances each, compare to
                                  eyestat_prngs.ParkMillerRng full state sequence
  2. park_miller_shuffled_perm  — 1000 seeds → 1000 permutations of [0, 83),
                                  compare to eyestat_prngs.ParkMillerRng.shuffled_perm(83)

If both PASS, the foundation is solid and we can write the full eyestat_gpu.py
(decryption + scoring) on top. If either FAILS, no point building the rest
until the discrepancy is resolved.

The CPU side has tricky details that the GPU MUST match exactly:
  - Seed rescue: s == 0 OR s == M (NOT just s == 0)
  - next_u32 rescue: s < 0 (NOT s <= 0)
  - next_below: rejection sampling with max_v = M - (M % n)
  - Fisher-Yates: i runs from N-1 down to 1; bound is (i+1) not i

USAGE
    source ~/.venvs/eyestat/bin/activate
    cd ~/eyestat
    python3 eyestat_gpu_validate.py
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import numpy as np

try:
    import cupy as cp
except ImportError:
    cp = None  # Deferred — only fail when a GPU code path is actually entered.


def _require_cupy():
    """Raise ImportError when a GPU code path is entered without CuPy."""
    if cp is None:
        raise ImportError(
            "CuPy required. Activate venv: source ~/.venvs/eyestat/bin/activate"
        )

# Make sure we can import eyestat_prngs from the same directory as this script
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from eyestat_prngs import ParkMillerRng
except ImportError:
    print(f"ERROR: eyestat_prngs.py not found in {SCRIPT_DIR}")
    print("Run this from your eyestat/ directory.")
    sys.exit(1)


# =============================================================================
# Output styling
# =============================================================================

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

def _c(c, s): return f"\033[{c}m{s}\033[0m" if USE_COLOR else s
def green(s):  return _c("92", s)
def red(s):    return _c("91", s)
def yellow(s): return _c("93", s)
def cyan(s):   return _c("96", s)
def dim(s):    return _c("90", s)
def bold(s):   return _c("1", s)

def ok(label, detail=""):
    print(f"  {green('[PASS]')} {label}" + (f"  {dim('—')}  {detail}" if detail else ""))
def fail(label, detail=""):
    print(f"  {red('[FAIL]')} {label}" + (f"  {dim('—')}  {detail}" if detail else ""))
def info(label, detail=""):
    print(f"  {cyan('[INFO]')} {label}" + (f"  {dim('—')}  {detail}" if detail else ""))
def banner(s):
    print(f"\n{bold(cyan('[ ' + s + ' ]'))}")


# =============================================================================
# CUDA source — both kernels share one __device__ helper
# =============================================================================

CUDA_SOURCE = r"""
// ---------------------------------------------------------------------------
// Park-Miller LCG: x_{n+1} = (16807 * x_n) mod (2^31 - 1)
// Schrage's algorithm to keep arithmetic in 32-bit signed range.
// MUST match eyestat_prngs.ParkMillerRng exactly.
// ---------------------------------------------------------------------------
extern "C" __device__ unsigned int park_miller_next(unsigned int s) {
    const int A = 16807;
    const int M = 2147483647;   // 2^31 - 1
    const int Q = 127773;       // M / A
    const int R = 2836;         // M % A

    int hi = (int)s / Q;
    int lo = (int)s - hi * Q;
    int t = A * lo - R * hi;
    if (t < 0) t += M;          // CPU uses `s < 0` (NOT <= 0)
    return (unsigned int)t;
}

// ---------------------------------------------------------------------------
// Kernel 1: park_miller_sequence
// Each thread: takes one seed, advances it n_advances times, writes ALL
// intermediate states to output[idx * n_advances : (idx+1) * n_advances].
// This lets us catch divergence anywhere in the sequence, not just at the end.
// ---------------------------------------------------------------------------
extern "C" __global__ void park_miller_sequence(
    const unsigned int* seeds_in,
    unsigned int* output,
    int n_streams,
    int n_advances
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_streams) return;

    const unsigned int M = 2147483647u;

    // CPU rescue: s = seed & 0x7FFFFFFF; if (s == 0 || s == M) s = 1
    unsigned int s = seeds_in[idx] & 0x7FFFFFFFu;
    if (s == 0u || s == M) s = 1u;

    unsigned int* my_out = output + (size_t)idx * (size_t)n_advances;
    for (int i = 0; i < n_advances; i++) {
        s = park_miller_next(s);
        my_out[i] = s;
    }
}

// ---------------------------------------------------------------------------
// Kernel 2: park_miller_shuffled_perm
// Each thread: takes one seed, produces one Fisher-Yates permutation of
// [0, alphabet_size) using next_below(i+1) with rejection sampling.
// MUST match eyestat_prngs.ParkMillerRng.shuffled_perm exactly.
// ---------------------------------------------------------------------------
extern "C" __global__ void park_miller_shuffled_perm(
    const unsigned int* seeds_in,
    unsigned char* output,
    int n_streams,
    int alphabet_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n_streams) return;

    const unsigned int M = 2147483647u;

    unsigned int s = seeds_in[idx] & 0x7FFFFFFFu;
    if (s == 0u || s == M) s = 1u;

    // Initialize identity permutation
    unsigned char* perm = output + (size_t)idx * (size_t)alphabet_size;
    for (int i = 0; i < alphabet_size; i++) {
        perm[i] = (unsigned char)i;
    }

    // Fisher-Yates: i from N-1 down to 1, swap perm[i] with perm[next_below(i+1)]
    for (int i = alphabet_size - 1; i > 0; i--) {
        unsigned int bound = (unsigned int)(i + 1);
        // Rejection sampling: max_v = M - (M % bound), accept v if v < max_v
        unsigned int max_v = M - (M % bound);
        unsigned int v;
        do {
            s = park_miller_next(s);
            v = s;
        } while (v >= max_v);
        unsigned int j = v % bound;

        unsigned char tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
}
"""


def compile_for_device(cp_module, code):
    """Compile a RawModule targeting the current device's compute capability.
    Falls back to PTX-compatible arches if native isn't supported."""
    cap = cp_module.cuda.Device().compute_capability  # e.g. "120"

    # CuPy 13.4+ auto-detects the device arch; passing --gpu-architecture
    # explicitly causes "defined more than once" with NVRTC. Try auto first.
    try:
        module = cp_module.RawModule(code=code)
        _ = module.get_function("park_miller_sequence")
        _ = module.get_function("park_miller_shuffled_perm")
        return module, f"compute_{cap}"
    except Exception:
        pass  # Fall back to explicit-arch path below

    candidates = [
        f"compute_{cap}",
        "compute_90",  # Hopper PTX → driver JIT
        "compute_86",  # Ampere PTX → driver JIT
    ]
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    last_err = None
    for arch in candidates:
        try:
            options = (f"--gpu-architecture={arch}",)
            module = cp_module.RawModule(code=code, options=options)
            # Force compile by getting both entry points
            _ = module.get_function("park_miller_sequence")
            _ = module.get_function("park_miller_shuffled_perm")
            return module, arch
        except Exception as e:
            last_err = e
            continue
    raise last_err if last_err else RuntimeError("no arch worked")


# =============================================================================
# Test 1 — park_miller_sequence
# =============================================================================

def test_park_miller_sequence(module, n_streams=1000, n_advances=100):
    """Generate park_miller sequences for N seeds × K advances on both GPU
    and CPU, byte-compare every value."""
    banner(f"Test 1: park_miller_sequence ({n_streams} seeds × {n_advances} advances)")

    # Mix of small, mid, large, and edge-case seeds
    rng = np.random.default_rng(42)
    seeds = np.concatenate([
        np.array([1, 2, 42, 16807, 2147483646], dtype=np.uint32),  # known
        rng.integers(1, 2_147_483_647, size=n_streams - 7, dtype=np.uint32),
        np.array([0, 2147483647], dtype=np.uint32),  # rescue cases
    ]).astype(np.uint32)
    assert len(seeds) == n_streams

    # ---- GPU run ----
    t0 = time.time()
    seeds_gpu = cp.asarray(seeds)
    out_gpu = cp.zeros((n_streams, n_advances), dtype=cp.uint32)
    kernel = module.get_function("park_miller_sequence")
    threads = 256
    blocks = (n_streams + threads - 1) // threads
    kernel((blocks,), (threads,),
           (seeds_gpu, out_gpu, n_streams, n_advances))
    cp.cuda.Stream.null.synchronize()
    gpu_t = time.time() - t0
    out_gpu_cpu = cp.asnumpy(out_gpu)
    info(f"GPU run", f"{gpu_t*1000:.1f} ms ({n_streams * n_advances / gpu_t / 1e9:.2f} GA/s)")

    # ---- CPU reference ----
    t0 = time.time()
    out_cpu = np.zeros((n_streams, n_advances), dtype=np.uint32)
    for i, seed in enumerate(seeds):
        rng_cpu = ParkMillerRng(int(seed))
        for k in range(n_advances):
            out_cpu[i, k] = rng_cpu.next_u32()
    cpu_t = time.time() - t0
    info(f"CPU run", f"{cpu_t*1000:.1f} ms (single-thread Python)")

    # ---- Compare ----
    if np.array_equal(out_gpu_cpu, out_cpu):
        ok("Byte-identical to CPU reference",
           f"{n_streams * n_advances:,} values matched")
        return True
    else:
        # Find first divergence for diagnosis
        diff = np.where(out_gpu_cpu != out_cpu)
        if len(diff[0]) > 0:
            i, k = diff[0][0], diff[1][0]
            fail("Output mismatch detected",
                 f"first diff at seed_idx={i} advance={k}: "
                 f"GPU={out_gpu_cpu[i, k]} CPU={out_cpu[i, k]} "
                 f"(input seed={seeds[i]})")
        else:
            fail("Output mismatch (unknown location)")
        return False


# =============================================================================
# Test 2 — park_miller_shuffled_perm
# =============================================================================

def test_park_miller_perm(module, n_streams=1000, alphabet_size=83):
    """Generate Fisher-Yates permutations for N seeds on both GPU and CPU,
    byte-compare every permutation."""
    banner(f"Test 2: park_miller_shuffled_perm ({n_streams} seeds × {alphabet_size}-perm)")

    rng = np.random.default_rng(7)
    seeds = np.concatenate([
        np.array([1, 2, 42, 16807, 2147483646], dtype=np.uint32),
        rng.integers(1, 2_147_483_647, size=n_streams - 7, dtype=np.uint32),
        np.array([0, 2147483647], dtype=np.uint32),
    ]).astype(np.uint32)
    assert len(seeds) == n_streams

    # ---- GPU run ----
    t0 = time.time()
    seeds_gpu = cp.asarray(seeds)
    out_gpu = cp.zeros((n_streams, alphabet_size), dtype=cp.uint8)
    kernel = module.get_function("park_miller_shuffled_perm")
    threads = 256
    blocks = (n_streams + threads - 1) // threads
    kernel((blocks,), (threads,),
           (seeds_gpu, out_gpu, n_streams, alphabet_size))
    cp.cuda.Stream.null.synchronize()
    gpu_t = time.time() - t0
    out_gpu_cpu = cp.asnumpy(out_gpu)
    info(f"GPU run", f"{gpu_t*1000:.1f} ms "
                    f"({n_streams / gpu_t:,.0f} perms/sec)")

    # ---- CPU reference ----
    t0 = time.time()
    out_cpu = np.zeros((n_streams, alphabet_size), dtype=np.uint8)
    for i, seed in enumerate(seeds):
        rng_cpu = ParkMillerRng(int(seed))
        perm = rng_cpu.shuffled_perm(alphabet_size)
        out_cpu[i] = np.array(perm, dtype=np.uint8)
    cpu_t = time.time() - t0
    info(f"CPU run", f"{cpu_t*1000:.1f} ms ({n_streams / cpu_t:,.0f} perms/sec)")

    # ---- Compare ----
    if np.array_equal(out_gpu_cpu, out_cpu):
        ok("Byte-identical to CPU reference",
           f"{n_streams:,} permutations matched, speedup {cpu_t/gpu_t:.1f}x")
        return True
    else:
        # Find first divergent permutation
        diff_rows = np.where((out_gpu_cpu != out_cpu).any(axis=1))[0]
        if len(diff_rows) > 0:
            i = diff_rows[0]
            fail("Permutation mismatch detected",
                 f"first diff at seed_idx={i} (seed={seeds[i]})")
            # Show a few values around the divergence
            diff_cols = np.where(out_gpu_cpu[i] != out_cpu[i])[0]
            for c in diff_cols[:3]:
                print(f"           pos {c}: GPU={out_gpu_cpu[i, c]:3d} "
                      f"CPU={out_cpu[i, c]:3d}")
        else:
            fail("Mismatch detected but couldn't locate it")
        return False


# =============================================================================
# Throughput benchmark — bigger batch
# =============================================================================

def benchmark_perm_throughput(module, batch_size=65536, alphabet_size=83,
                              iterations=20):
    """Measure peak permutation throughput on GPU."""
    banner(f"Benchmark: perm throughput ({batch_size:,} perms × {iterations} iters)")

    rng = np.random.default_rng(123)
    seeds = rng.integers(1, 2_147_483_647, size=batch_size, dtype=np.uint32)
    seeds_gpu = cp.asarray(seeds)
    out_gpu = cp.zeros((batch_size, alphabet_size), dtype=cp.uint8)
    kernel = module.get_function("park_miller_shuffled_perm")
    threads = 256
    blocks = (batch_size + threads - 1) // threads

    # Warm-up (first launch may include cubin load)
    kernel((blocks,), (threads,),
           (seeds_gpu, out_gpu, batch_size, alphabet_size))
    cp.cuda.Stream.null.synchronize()

    # Measure
    t0 = time.time()
    for _ in range(iterations):
        kernel((blocks,), (threads,),
               (seeds_gpu, out_gpu, batch_size, alphabet_size))
    cp.cuda.Stream.null.synchronize()
    dt = time.time() - t0

    total_perms = batch_size * iterations
    perms_per_sec = total_perms / dt
    ms_per_batch = dt / iterations * 1000

    info(f"Throughput", f"{perms_per_sec:>15,.0f} perms/sec  "
                       f"({ms_per_batch:.2f} ms / batch of {batch_size:,})")

    # Each ctak_right key needs ~84 perms × the same RNG continuing through them
    # (technically interleaved, but the perm count is the same). So perms/sec
    # is an upper bound on keys/sec.
    keys_per_sec_upper = perms_per_sec / 84
    info(f"Implied key ceiling",
         f"{keys_per_sec_upper:>15,.0f} keys/sec (84 perms/key for GAK family)")


# =============================================================================
# Main
# =============================================================================

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--n-streams", type=int, default=1000,
                   help="Streams to validate against CPU (default 1000)")
    p.add_argument("--n-advances", type=int, default=100,
                   help="Advances per stream in sequence test (default 100)")
    p.add_argument("--alphabet-size", type=int, default=83,
                   help="Permutation length (default 83, matches Noita data)")
    p.add_argument("--bench-batch", type=int, default=65536,
                   help="Batch size for throughput benchmark (default 65536)")
    p.add_argument("--bench-iters", type=int, default=20,
                   help="Iterations for throughput benchmark (default 20)")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()

    # --help has already exited above; only now do we need CuPy.
    _require_cupy()

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    print()
    print(bold(cyan("╔════════════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║  GPU PHASE 1 VALIDATION — park_miller + Fisher-Yates           ║")))
    print(bold(cyan("╚════════════════════════════════════════════════════════════════╝")))

    # ---- Device info ----
    banner("Device")
    dev = cp.cuda.Device()
    cap = dev.compute_capability
    name = cp.cuda.runtime.getDeviceProperties(0)['name'].decode()
    free, total = cp.cuda.runtime.memGetInfo()
    info(f"GPU: {name}",
         f"sm_{cap}, {total // (1024**2):,} MB total, {free // (1024**2):,} MB free")
    info(f"CuPy version", cp.__version__)
    rt = cp.cuda.runtime.runtimeGetVersion()
    info(f"CUDA runtime", f"{rt // 1000}.{(rt % 1000) // 10}")

    # ---- Compile ----
    banner("Kernel compilation")
    try:
        module, arch_used = compile_for_device(cp, CUDA_SOURCE)
        ok("Both kernels compiled", f"target = {arch_used}")
    except Exception as e:
        fail(f"Compilation failed", f"{type(e).__name__}: {e}")
        return 2

    # ---- Run tests ----
    test1_pass = test_park_miller_sequence(
        module, n_streams=args.n_streams, n_advances=args.n_advances)
    test2_pass = test_park_miller_perm(
        module, n_streams=args.n_streams, alphabet_size=args.alphabet_size)

    # ---- Benchmark (only if validation passed) ----
    if test1_pass and test2_pass:
        benchmark_perm_throughput(
            module, batch_size=args.bench_batch,
            alphabet_size=args.alphabet_size,
            iterations=args.bench_iters)

    # ---- Summary ----
    print()
    if test1_pass and test2_pass:
        print(bold(green("════════════════════════════════════════════════════════════════")))
        print(bold(green("  ALL VALIDATION PASSED. Foundation is solid.                   ")))
        print(bold(green("  Next step: write eyestat_gpu.py with GAK decrypt + runner integration.")))
        print(bold(green("════════════════════════════════════════════════════════════════")))
        return 0
    else:
        print(bold(red("════════════════════════════════════════════════════════════════")))
        print(bold(red("  VALIDATION FAILED. Send the [FAIL] line + first diff to me.   ")))
        print(bold(red("════════════════════════════════════════════════════════════════")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
