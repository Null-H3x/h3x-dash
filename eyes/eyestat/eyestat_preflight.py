#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_preflight.py — pre-flight check for the brute-force runner.

Run this BEFORE launching a long compute job. Verifies that:

  1. Python environment is sane (version, cores, memory, disk)
  2. All eyestat_* modules import cleanly
  3. The ciphertext data file is present, valid, and self-consistent
  4. All dictionaries load and contain plausible content
  5. Cipher kernels + PRNGs pass canonical known-answer tests
  6. The output directory is writable with enough free space
  7. The requested (modes × prngs × seed-range) compute budget is realistic

Exit codes:
  0  all green — go for launch
  1  warnings only — review and proceed if expected
  2  hard failure — do not launch

USAGE
=====
    python3 eyestat_preflight.py \\
        --data noita_eye_data.json \\
        --dict-fi  extra_words_fi.txt \\
        --dict-krl extra_words_krl.txt \\
        --dict-en  noita_wordlist.txt \\
        --modes all --prngs all \\
        --seed-start 0 --seed-end 1000000 \\
        --workers 64 \\
        --output-dir results_v1/

A copy of the full report is written to {output-dir}/preflight_report.txt.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import platform
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Output styling — cyberpunk pre-flight aesthetic, ASCII-safe
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _c(code: str, s: str) -> str:
    if not USE_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"

def green(s: str) -> str:  return _c("92", s)
def red(s: str) -> str:    return _c("91", s)
def yellow(s: str) -> str: return _c("93", s)
def cyan(s: str) -> str:   return _c("96", s)
def dim(s: str) -> str:    return _c("90", s)
def bold(s: str) -> str:   return _c("1", s)

TAG_OK   = f"[ {green('OK')}   ]"
TAG_WARN = f"[ {yellow('WARN')} ]"
TAG_FAIL = f"[ {red('FAIL')} ]"
TAG_INFO = f"[ {cyan('INFO')} ]"


# ---------------------------------------------------------------------------
# Check result accounting
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    name: str
    status: str       # "ok" | "warn" | "fail"
    detail: str = ""
    extra: List[str] = field(default_factory=list)

@dataclass
class Report:
    checks: List[CheckResult] = field(default_factory=list)
    sections: List[Tuple[str, List[CheckResult]]] = field(default_factory=list)
    _current_section: List[CheckResult] = field(default_factory=list)
    _current_section_name: str = ""

    def begin_section(self, name: str) -> None:
        if self._current_section_name:
            self.sections.append((self._current_section_name, self._current_section))
        self._current_section_name = name
        self._current_section = []
        print()
        print(bold(cyan(f"[[ {name} ]]")))

    def end(self) -> None:
        if self._current_section_name:
            self.sections.append((self._current_section_name, self._current_section))
            self._current_section_name = ""
            self._current_section = []

    def add(self, name: str, status: str, detail: str = "",
            extra: Optional[List[str]] = None) -> None:
        r = CheckResult(name=name, status=status, detail=detail,
                        extra=extra or [])
        self.checks.append(r)
        self._current_section.append(r)
        tag = {"ok": TAG_OK, "warn": TAG_WARN, "fail": TAG_FAIL}[status]
        line = f"  {tag} {name}"
        if detail:
            line += f"  {dim('—')}  {detail}"
        print(line)
        for x in r.extra:
            print(f"           {dim(x)}")

    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "fail")

    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "warn")

    def ok_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "ok")

    def write_text_report(self, path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("NOITA BF PRE-FLIGHT REPORT\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
            f.write("=" * 70 + "\n\n")
            for sec_name, results in self.sections:
                f.write(f"[[ {sec_name} ]]\n")
                for r in results:
                    tag = {"ok": "[ OK   ]", "warn": "[ WARN ]",
                           "fail": "[ FAIL ]"}[r.status]
                    f.write(f"  {tag} {r.name}")
                    if r.detail:
                        f.write(f"  --  {r.detail}")
                    f.write("\n")
                    for x in r.extra:
                        f.write(f"           {x}\n")
                f.write("\n")
            f.write("-" * 70 + "\n")
            f.write(f"TOTAL:  {self.ok_count()} OK  |  "
                    f"{self.warn_count()} WARN  |  "
                    f"{self.fail_count()} FAIL\n")


# ---------------------------------------------------------------------------
# Section 1: Environment
# ---------------------------------------------------------------------------

def check_gpu_acceleration(rep: Report) -> None:
    """Probe for Nvidia GPU + CuPy availability.

    This is an OPTIONAL section — the bf project runs fine on CPU. The
    purpose is to surface what GPU acceleration would be available if the
    eventual hybrid pipeline is enabled. Findings are reported as OK or
    WARN, never FAIL — missing GPU is not a blocker.

    Probes (in order):
      1. nvidia-smi present + reports GPU(s)
      2. nvcc / CUDA toolkit version
      3. CuPy importable
      4. CuPy can enumerate CUDA devices
      5. CuPy can perform a tiny arithmetic op on the device (smoke test)
    """
    import shutil
    import subprocess

    # ----- 1. nvidia-smi: does the OS see a Nvidia GPU? -----
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.check_output(
                ["nvidia-smi",
                 "--query-gpu=index,name,memory.total,memory.free,driver_version,compute_cap",
                 "--format=csv,noheader,nounits"],
                text=True, stderr=subprocess.DEVNULL, timeout=8)
            gpus = []
            for line in out.strip().splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 6:
                    gpus.append(parts)
            if gpus:
                for g in gpus:
                    rep.add(f"GPU {g[0]}: {g[1]}", "ok",
                            f"{g[2]} MB total, {g[3]} MB free, "
                            f"compute {g[5]}, driver {g[4]}")
            else:
                rep.add("nvidia-smi", "warn",
                        "ran but reported 0 GPUs — driver loaded but no devices visible?")
                return
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired, OSError) as e:
            rep.add("nvidia-smi", "warn",
                    f"failed to run: {type(e).__name__}: {e}")
            return
    else:
        rep.add("nvidia-smi", "warn",
                "not found in PATH — install Nvidia driver or skip if CPU-only")
        return

    # ----- 2. CUDA toolkit -----
    if shutil.which("nvcc"):
        try:
            out = subprocess.check_output(
                ["nvcc", "--version"], text=True,
                stderr=subprocess.DEVNULL, timeout=5)
            ver_line = next((ln.strip() for ln in out.splitlines()
                             if "release" in ln.lower()), None)
            if ver_line:
                # Extract release number, e.g., "Cuda compilation tools, release 12.8, V12.8.61"
                import re as _re
                m = _re.search(r"release\s+(\d+\.\d+)", ver_line)
                ver = m.group(1) if m else "(unknown)"
                # Blackwell needs >= 12.8
                if m:
                    try:
                        ver_num = float(ver)
                        if ver_num < 12.8:
                            rep.add("CUDA toolkit (nvcc)", "warn",
                                    f"{ver} — too old for RTX 50xx (need >= 12.8). "
                                    "Bundled NVRTC in CuPy may still work via PTX JIT.")
                        else:
                            rep.add("CUDA toolkit (nvcc)", "ok",
                                    f"{ver} (Blackwell-ready)")
                    except ValueError:
                        rep.add("CUDA toolkit (nvcc)", "ok", ver_line)
                else:
                    rep.add("CUDA toolkit (nvcc)", "ok", ver_line)
        except Exception as e:
            rep.add("CUDA toolkit (nvcc)", "warn",
                    f"failed to query: {type(e).__name__}: {e}")
    else:
        rep.add("CUDA toolkit (nvcc)", "warn",
                "nvcc not in PATH — CuPy uses bundled NVRTC, may still work")

    # ----- 3. CuPy importable -----
    try:
        import cupy as cp  # type: ignore
        rep.add("CuPy importable", "ok", f"version {cp.__version__}")
    except ImportError:
        rep.add("CuPy importable", "warn",
                "not installed — `pip install cupy-cuda12x>=13.4` for GPU acceleration")
        return
    except Exception as e:
        rep.add("CuPy importable", "warn",
                f"import failed: {type(e).__name__}: {e}")
        return

    # ----- 4. CuPy can enumerate devices -----
    try:
        n_dev = cp.cuda.runtime.getDeviceCount()
        if n_dev == 0:
            rep.add("CuPy device count", "warn",
                    "CuPy importable but sees 0 devices — driver/runtime mismatch?")
            return
        # Report runtime version too
        rt_ver = cp.cuda.runtime.runtimeGetVersion()
        rt_str = f"{rt_ver // 1000}.{(rt_ver % 1000) // 10}"
        rep.add(f"CuPy sees {n_dev} CUDA device(s)", "ok",
                f"CUDA runtime {rt_str} (bundled with wheel)")
    except Exception as e:
        rep.add("CuPy device probe", "warn",
                f"{type(e).__name__}: {e}")
        return

    # ----- 5. GPU smoke test: tiny add op -----
    try:
        a = cp.array([1, 2, 3, 4], dtype=cp.uint32)
        b = a + a
        cp.cuda.Stream.null.synchronize()
        result = b.get().tolist()
        if result == [2, 4, 6, 8]:
            rep.add("GPU smoke test", "ok",
                    "arithmetic on device verified [1,2,3,4]+[1,2,3,4]=[2,4,6,8]")
        else:
            rep.add("GPU smoke test", "warn",
                    f"unexpected result: {result}")
    except Exception as e:
        rep.add("GPU smoke test", "warn",
                f"GPU op failed: {type(e).__name__}: {e}")


def check_python_version(rep: Report) -> None:
    v = sys.version_info
    detail = f"Python {v.major}.{v.minor}.{v.micro} on {platform.platform()}"
    if v < (3, 8):
        rep.add("Python version", "fail",
                f"need 3.8+, found {v.major}.{v.minor}.{v.micro}")
    else:
        rep.add("Python version", "ok", detail)

def check_cpu_count(rep: Report, requested_workers: int) -> None:
    cores = os.cpu_count() or 1
    detail = f"{cores} logical core(s) available, --workers={requested_workers}"
    if requested_workers > cores:
        rep.add("CPU cores", "warn",
                f"{detail}  (oversubscribed by {requested_workers - cores})")
    elif requested_workers == 0 or requested_workers < 0:
        rep.add("CPU cores", "fail", f"--workers must be >= 1, got {requested_workers}")
    else:
        rep.add("CPU cores", "ok", detail)

def _read_meminfo() -> Optional[Tuple[int, int]]:
    """Return (total_kb, avail_kb) from /proc/meminfo, or None."""
    try:
        with open("/proc/meminfo", "r") as f:
            total = avail = None
            for line in f:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
            if total and avail:
                return total, avail
    except Exception:
        return None
    return None

def check_memory(rep: Report, workers: int) -> None:
    info = _read_meminfo()
    if info is None:
        rep.add("Memory", "warn",
                "/proc/meminfo not available — cannot verify free RAM")
        return
    total_kb, avail_kb = info
    avail_gb = avail_kb / 1024 / 1024
    total_gb = total_kb / 1024 / 1024
    # Rough estimate: ~200 MB per worker for Python + dict caches
    needed_gb = workers * 0.2
    detail = (f"{avail_gb:.1f} GB free / {total_gb:.1f} GB total  "
              f"(est. {needed_gb:.1f} GB needed for {workers} workers)")
    if avail_gb < needed_gb:
        rep.add("Memory", "warn", detail + "  — may swap")
    else:
        rep.add("Memory", "ok", detail)

def check_fork_safety(rep: Report) -> None:
    plat = sys.platform
    start_methods = mp.get_all_start_methods()
    default = mp.get_start_method(allow_none=True) or "(none set)"
    if plat == "linux" and "fork" in start_methods:
        rep.add("Multiprocessing", "ok",
                f"linux/{default} — fork available (fast spawn)")
    elif plat == "darwin":
        rep.add("Multiprocessing", "warn",
                f"darwin/{default} — spawn-only on macOS, worker startup is slower; "
                "OK but expect higher overhead for short shards")
    elif plat.startswith("win"):
        rep.add("Multiprocessing", "warn",
                f"win32/{default} — spawn-only, worker startup is slower")
    else:
        rep.add("Multiprocessing", "ok",
                f"{plat}/{default}  available: {','.join(start_methods)}")

def check_disk_space(rep: Report, output_dir: Path,
                     est_bytes: Optional[int] = None) -> None:
    # Check the parent dir if output_dir doesn't exist yet
    probe = output_dir if output_dir.exists() else output_dir.parent
    try:
        usage = shutil.disk_usage(probe)
    except Exception as e:
        rep.add("Disk space", "fail", f"could not stat {probe}: {e}")
        return
    free_gb = usage.free / 1024**3
    total_gb = usage.total / 1024**3
    detail = f"{free_gb:.1f} GB free / {total_gb:.1f} GB total at {probe}"
    if est_bytes is not None:
        est_gb = est_bytes / 1024**3
        detail += f"  (est. output ≈ {est_gb:.2f} GB)"
        if usage.free < est_bytes * 2:  # safety factor 2
            rep.add("Disk space", "warn", detail + "  — tight, consider 2× headroom")
            return
    rep.add("Disk space", "ok", detail)


# ---------------------------------------------------------------------------
# Section 2: Module imports
# ---------------------------------------------------------------------------

def check_module_imports(rep: Report) -> Optional[Tuple[Any, Any, Any, Any]]:
    """Returns (K, P, S, R) on success, None on failure."""
    modules = ["eyestat_kernels", "eyestat_prngs", "eyestat_scoring", "eyestat_runner"]
    loaded: List[Any] = []
    for name in modules:
        try:
            t0 = time.time()
            mod = __import__(name)
            dt = (time.time() - t0) * 1000
            n_attrs = sum(1 for a in dir(mod) if not a.startswith("_"))
            rep.add(f"import {name}", "ok",
                    f"{n_attrs} public symbols, {dt:.0f}ms")
            loaded.append(mod)
        except Exception as e:
            rep.add(f"import {name}", "fail", f"{type(e).__name__}: {e}")
            return None
    return tuple(loaded)  # type: ignore


# ---------------------------------------------------------------------------
# Section 3: Ciphertext data file
# ---------------------------------------------------------------------------

EXPECTED_NUM_MESSAGES = 9
EXPECTED_TOTAL_POSITIONS = 1036
EXPECTED_DECK_SIZE = 83
EXPECTED_MESSAGE_LENGTHS = [99, 103, 118, 102, 137, 124, 119, 120, 114]

def check_data_file(rep: Report, data_path: Path,
                    requested_alphabet_size: int) -> Optional[Dict[str, Any]]:
    if not data_path.exists():
        rep.add(f"data file: {data_path.name}", "fail",
                f"not found at {data_path}")
        return None
    try:
        size_kb = data_path.stat().st_size / 1024
        with open(data_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rep.add(f"data file: {data_path.name}", "ok",
                f"valid JSON, {size_kb:.1f} KB")
    except json.JSONDecodeError as e:
        rep.add(f"data file: {data_path.name}", "fail", f"JSON parse error: {e}")
        return None
    except Exception as e:
        rep.add(f"data file: {data_path.name}", "fail", f"{type(e).__name__}: {e}")
        return None

    # Required fields
    required = ["deck_size", "num_messages", "message_lengths", "ciphertexts"]
    missing = [k for k in required if k not in data]
    if missing:
        rep.add("data: required fields", "fail",
                f"missing keys: {', '.join(missing)}")
        return None
    rep.add("data: required fields", "ok",
            f"keys present: {', '.join(required)}")

    # Optional metadata
    src = data.get("_source", "(none)")
    val = data.get("_validated", "(none)")
    if val != "(none)":
        rep.add("data: validation note", "ok", f"source: {src}",
                extra=[f"validated: {val[:90]}{'…' if len(val) > 90 else ''}"])

    # Deck size cross-check
    deck = data["deck_size"]
    if deck != requested_alphabet_size:
        rep.add("data: alphabet size", "warn",
                f"data says deck_size={deck}, --alphabet-size={requested_alphabet_size}")
    elif deck != EXPECTED_DECK_SIZE:
        rep.add("data: alphabet size", "warn",
                f"deck_size={deck}, expected {EXPECTED_DECK_SIZE} for Noita eye-messages")
    else:
        rep.add("data: alphabet size", "ok", f"deck_size={deck}")

    # Message-count cross-check
    n_msgs = data["num_messages"]
    n_ct = len(data["ciphertexts"])
    n_lens = len(data["message_lengths"])
    n_labels = len(data.get("message_labels", []))
    if not (n_msgs == n_ct == n_lens):
        rep.add("data: message-count consistency", "fail",
                f"num_messages={n_msgs}, ciphertexts={n_ct}, lengths={n_lens}")
        return None
    if n_msgs != EXPECTED_NUM_MESSAGES:
        rep.add("data: num_messages", "warn",
                f"{n_msgs} (expected {EXPECTED_NUM_MESSAGES})")
    else:
        rep.add("data: message-count consistency", "ok",
                f"{n_msgs} messages, labels={n_labels}")

    # Per-message length cross-check
    actual_lens = [len(c) for c in data["ciphertexts"]]
    if actual_lens != data["message_lengths"]:
        mismatches = [i for i in range(len(actual_lens))
                     if actual_lens[i] != data["message_lengths"][i]]
        rep.add("data: per-message lengths", "fail",
                f"declared vs actual mismatch at msg indices: {mismatches}")
        return None
    total = sum(actual_lens)
    detail = f"per-message lengths match declared, total={total}"
    if total != EXPECTED_TOTAL_POSITIONS:
        rep.add("data: per-message lengths", "warn",
                detail + f" (expected {EXPECTED_TOTAL_POSITIONS} for Noita)")
    elif actual_lens != EXPECTED_MESSAGE_LENGTHS:
        rep.add("data: per-message lengths", "warn",
                detail + f"  — unexpected distribution {actual_lens}")
    else:
        rep.add("data: per-message lengths", "ok", detail)

    # Symbol-range check
    all_syms = [s for ct in data["ciphertexts"] for s in ct]
    if not all_syms:
        rep.add("data: symbol range", "fail", "no ciphertext symbols")
        return None
    mn, mx = min(all_syms), max(all_syms)
    if mn < 0 or mx >= deck:
        rep.add("data: symbol range", "fail",
                f"symbols in [{mn}, {mx}] outside [0, {deck})")
        return None
    # Distribution sanity: each symbol should appear at least once if uniform
    from collections import Counter
    cnt = Counter(all_syms)
    unique = len(cnt)
    rare = sum(1 for v in cnt.values() if v == 1)
    expected_per = total / deck
    rep.add("data: symbol range", "ok",
            f"symbols in [{mn},{mx}] ⊂ [0,{deck}); "
            f"{unique}/{deck} symbols observed, avg freq {expected_per:.1f}")

    return data


# ---------------------------------------------------------------------------
# Section 4: Dictionaries
# ---------------------------------------------------------------------------

def check_dictionary(rep: Report, S_mod: Any, lang: str, path: Path,
                     min_expected: int = 100) -> Optional[Any]:
    if not path.exists():
        rep.add(f"dict-{lang}: {path.name}", "warn",
                f"not found at {path} — runner will run with empty {lang} dict")
        return None
    size_kb = path.stat().st_size / 1024
    try:
        d = S_mod.Dictionary(lang)
        t0 = time.time()
        d.load(path)
        dt = (time.time() - t0) * 1000
    except Exception as e:
        rep.add(f"dict-{lang}: {path.name}", "fail",
                f"load failed: {type(e).__name__}: {e}")
        return None

    n = len(d)
    detail = f"{n:,} words from {size_kb:.1f} KB file, loaded in {dt:.0f}ms"
    if n < min_expected:
        rep.add(f"dict-{lang}: {path.name}", "warn",
                detail + f"  — fewer than {min_expected} words")
    else:
        rep.add(f"dict-{lang}: {path.name}", "ok", detail)

    # Sanity-check word content
    sample = list(d.words)[:5]
    if sample:
        rep.add(f"dict-{lang}: content sample", "ok",
                f"sample: {', '.join(repr(w) for w in sample[:4])}")

    # Letter-frequency sanity: each lang should have its 3 most common
    # letters in a plausible top-10
    freqs = d.letter_frequencies()
    top5 = sorted(freqs.items(), key=lambda kv: -kv[1])[:5]
    if top5:
        rep.add(f"dict-{lang}: letter freqs", "ok",
                f"top-5: {', '.join(f'{c}={p:.1f}%' for c, p in top5)}")

    return d


# ---------------------------------------------------------------------------
# Section 5: Cipher/PRNG known-answer tests
# ---------------------------------------------------------------------------

def check_prng_kats(rep: Report, P_mod: Any) -> None:
    """Hand-verified KAT subset — same values as the selftest, fast."""
    # Park-Miller seed=1 → 16807, 282475249, 1622650073, ...
    pm = P_mod.ParkMillerRng(1)
    expected = [16807, 282475249, 1622650073]
    got = [pm.next_u32() for _ in range(3)]
    if got == expected:
        rep.add("PRNG: park_miller seed=1", "ok", f"first 3: {got}")
    else:
        rep.add("PRNG: park_miller seed=1", "fail",
                f"expected {expected}, got {got}")

    # MT19937 seed=5489 → 3499211612 first
    mt = P_mod.MT19937Rng(5489)
    first = mt.next_u32()
    if first == 3499211612:
        rep.add("PRNG: mt19937 seed=5489", "ok", f"first u32: {first}")
    else:
        rep.add("PRNG: mt19937 seed=5489", "fail",
                f"expected 3499211612, got {first}")

    # Xorshift64 seed=1 → 1082269761 first
    xs = P_mod.Xorshift64Rng(1)
    first = xs.next_u32()
    if first == 1082269761:
        rep.add("PRNG: xorshift64 seed=1", "ok", f"first u32: {first}")
    else:
        rep.add("PRNG: xorshift64 seed=1", "fail",
                f"expected 1082269761, got {first}")

    # Park-Miller seed=M boundary (paranoid-pass bug #10): seed=M should
    # be auto-rescued to seed=1, producing the same first u32 (16807).
    # Before the fix, this looped forever or produced 0 forever.
    M = 2**31 - 1
    pm_b = P_mod.ParkMillerRng(M)
    v = pm_b.next_u32()
    if v == 16807:
        rep.add("PRNG: park_miller seed=M boundary", "ok",
                "rescued to seed=1 (first u32=16807, no infinite loop)")
    elif v == 0:
        rep.add("PRNG: park_miller seed=M boundary", "fail",
                "state stuck at M, produced 0 — boundary bug regression")
    else:
        rep.add("PRNG: park_miller seed=M boundary", "warn",
                f"first u32={v}, not 16807 — rescue scheme changed?")

    # Lehmer seed=M boundary (paranoid-pass bug #11)
    lh_b = P_mod.LehmerRng(M)
    v = lh_b.next_u32()
    if v == 0:
        rep.add("PRNG: lehmer seed=M boundary", "fail",
                "state stuck at M, produced 0 — boundary bug regression")
    else:
        rep.add("PRNG: lehmer seed=M boundary", "ok",
                f"rescued, first u32={v}")


def check_vigenere_kat(rep: Report, K_mod: Any) -> None:
    """Canonical KAT: ATTACKATDAWN + LEMON → LXFOPVEFRNHR."""
    pt = [ord(c) - ord("A") for c in "ATTACKATDAWN"]
    key = [ord(c) - ord("A") for c in "LEMON"]
    expected = [ord(c) - ord("A") for c in "LXFOPVEFRNHR"]
    try:
        ct = K_mod.vigenere_encrypt(pt, key, 26, K_mod.VIGENERE_PLAIN)
    except Exception as e:
        rep.add("KAT: vigenere ATTACKATDAWN", "fail",
                f"{type(e).__name__}: {e}")
        return
    if ct == expected:
        rep.add("KAT: vigenere ATTACKATDAWN", "ok",
                "ATTACKATDAWN + LEMON → LXFOPVEFRNHR")
    else:
        got = "".join(chr(c + ord("A")) for c in ct)
        rep.add("KAT: vigenere ATTACKATDAWN", "fail",
                f"expected LXFOPVEFRNHR, got {got}")


def check_pontifex_kat(rep: Report, K_mod: Any) -> None:
    """Canonical Pontifex/Solitaire KAT."""
    try:
        deck = K_mod.pontifex_key_deck_from_passphrase("CRYPTONOMICON")
        keystream, _ = K_mod.pontifex_keystream(deck, 10)
        pt = [ord(c) - ord("A") for c in "SOLITAIREX"]
        ct = [(p + k) % 26 for p, k in zip(pt, keystream)]
        expected = [ord(c) - ord("A") for c in "KIRAKSFJAN"]
    except Exception as e:
        rep.add("KAT: pontifex CRYPTONOMICON", "fail",
                f"{type(e).__name__}: {e}")
        return
    if ct == expected:
        rep.add("KAT: pontifex CRYPTONOMICON", "ok",
                "CRYPTONOMICON + SOLITAIREX → KIRAKSFJAN")
    else:
        got = "".join(chr(c + ord("A")) for c in ct)
        rep.add("KAT: pontifex CRYPTONOMICON", "fail",
                f"expected KIRAKSFJAN, got {got}")


def check_gak_roundtrip(rep: Report, K_mod: Any, P_mod: Any) -> None:
    """Round-trip a small GAK encryption/decryption."""
    alphabet = 26
    pt = list(range(20))
    prng = P_mod.ParkMillerRng(42)
    perms = [prng.shuffled_perm(alphabet) for _ in range(85)]
    try:
        ct = K_mod.gak_encrypt(pt, perms, alphabet, K_mod.GAK_CTAK_RIGHT)
        pt2 = K_mod.gak_decrypt(ct, perms, alphabet, K_mod.GAK_CTAK_RIGHT)
    except Exception as e:
        rep.add("KAT: GAK round-trip", "fail",
                f"{type(e).__name__}: {e}")
        return
    if pt == pt2:
        rep.add("KAT: GAK round-trip", "ok",
                f"CTAK_RIGHT, 20 symbols, alphabet=26")
    else:
        rep.add("KAT: GAK round-trip", "fail",
                f"PT mismatch: {pt} != {pt2}")


def check_hungarian_kat(rep: Report, S_mod: Any) -> None:
    """5×5 diagonal identity → permutation [0,1,2,3,4]."""
    cost = [[0 if i == j else 10 for j in range(5)] for i in range(5)]
    try:
        assign = S_mod.hungarian_min_cost(cost)
    except Exception as e:
        rep.add("KAT: hungarian 5×5", "fail",
                f"{type(e).__name__}: {e}")
        return
    if assign == [0, 1, 2, 3, 4]:
        rep.add("KAT: hungarian 5×5", "ok",
                "diagonal-zero cost → identity assignment")
    else:
        rep.add("KAT: hungarian 5×5", "fail",
                f"expected [0,1,2,3,4], got {assign}")


# ---------------------------------------------------------------------------
# Section 6: Output directory
# ---------------------------------------------------------------------------

def check_output_dir(rep: Report, output_dir: Path, resume: bool) -> None:
    if output_dir.exists():
        if not output_dir.is_dir():
            rep.add(f"output: {output_dir.name}", "fail",
                    f"{output_dir} exists but is not a directory")
            return
        # Check writability
        probe = output_dir / ".preflight_write_probe"
        try:
            probe.write_text("ok")
            probe.unlink()
        except Exception as e:
            rep.add(f"output: {output_dir.name}", "fail",
                    f"not writable: {e}")
            return
        # Count existing shards for resume
        shards = list(output_dir.glob("bruteforce_params_*.tsv.gz"))
        if shards and not resume:
            rep.add(f"output: {output_dir.name}", "warn",
                    f"exists with {len(shards)} existing shard(s) — "
                    "use --resume or pick a different dir")
        elif shards and resume:
            rep.add(f"output: {output_dir.name}", "ok",
                    f"--resume: {len(shards)} existing shard(s) will be skipped")
        else:
            rep.add(f"output: {output_dir.name}", "ok",
                    f"writable, empty (fresh run)")
    else:
        # Doesn't exist — try to create
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            rep.add(f"output: {output_dir.name}", "ok",
                    f"created {output_dir}")
        except Exception as e:
            rep.add(f"output: {output_dir.name}", "fail",
                    f"could not create {output_dir}: {e}")


# ---------------------------------------------------------------------------
# Section 7: Compute budget estimate
# ---------------------------------------------------------------------------

# Single-core keys/sec by mode family (empirical, pure-Python)
KEYS_PER_SEC_BY_FAMILY = {
    "gak_xgak": 6.0,
    "kak":      5.0,
    "cfb":      6.0,
    "ofb":      6.0,
    "vigenere": 8.0,
    "card":     26.0,
}

def check_compute_budget(rep: Report, R_mod: Any, P_mod: Any,
                         modes: List[str], prngs: List[str],
                         seed_start: int, seed_end: int,
                         workers: int) -> int:
    """Estimate runtime and output volume. Returns est_output_bytes."""
    # Resolve "all"
    if modes == ["all"]:
        modes = list(R_mod.MODE_REGISTRY.keys())
    if prngs == ["all"]:
        prngs = list(P_mod.PRNG_REGISTRY.keys())

    # Validate
    bad_modes = [m for m in modes if m not in R_mod.MODE_REGISTRY]
    bad_prngs = [p for p in prngs if p not in P_mod.PRNG_REGISTRY]
    if bad_modes:
        rep.add("modes valid", "fail",
                f"unknown modes: {', '.join(bad_modes)}",
                extra=[f"valid: {', '.join(sorted(R_mod.MODE_REGISTRY))}"])
    else:
        # Group by family
        families: Dict[str, List[str]] = {}
        for m in modes:
            fam = R_mod.MODE_REGISTRY[m]["family"]
            families.setdefault(fam, []).append(m)
        rep.add("modes valid", "ok",
                f"{len(modes)} mode(s): "
                + ", ".join(f"{fam}={len(v)}" for fam, v in families.items()))
    if bad_prngs:
        rep.add("prngs valid", "fail",
                f"unknown PRNGs: {', '.join(bad_prngs)}",
                extra=[f"valid: {', '.join(sorted(P_mod.PRNG_REGISTRY))}"])
    else:
        rep.add("prngs valid", "ok", f"{len(prngs)} PRNG(s): {', '.join(prngs)}")

    if bad_modes or bad_prngs:
        return 0

    # Compute total keys and weighted seconds
    n_seeds = seed_end - seed_start
    if n_seeds <= 0:
        rep.add("seed range", "fail",
                f"--seed-start={seed_start} >= --seed-end={seed_end}")
        return 0

    total_keys = 0
    total_seconds_single = 0.0
    family_summary: Dict[str, int] = {}
    for m in modes:
        fam = R_mod.MODE_REGISTRY[m]["family"]
        # Card modes use passphrase enumeration, not seed range — flag separately
        if fam == "card":
            family_summary[fam] = family_summary.get(fam, 0) + 1
            continue
        n_combos = n_seeds * len(prngs)
        total_keys += n_combos
        kps = KEYS_PER_SEC_BY_FAMILY[fam]
        total_seconds_single += n_combos / kps
        family_summary[fam] = family_summary.get(fam, 0) + 1

    if "card" in family_summary:
        rep.add("seed range: card modes", "warn",
                f"{family_summary['card']} card cipher mode(s) ignore --seed-start/end; "
                "they enumerate passphrases instead. Estimate excludes them.")

    rep.add("seed range", "ok",
            f"{n_seeds:,} seeds × {len(prngs)} PRNG(s) × "
            f"{len([m for m in modes if R_mod.MODE_REGISTRY[m]['family'] != 'card'])} "
            f"non-card mode(s) = {total_keys:,} keys")

    # Wall-clock estimate
    wall_seconds = total_seconds_single / max(workers, 1)
    def fmt_dur(s: float) -> str:
        if s < 60:        return f"{s:.0f}s"
        if s < 3600:      return f"{s/60:.1f}m"
        if s < 86400:     return f"{s/3600:.1f}h"
        if s < 86400*30:  return f"{s/86400:.1f}d"
        return f"{s/(86400*30):.1f}mo"

    detail = (f"single-core: {fmt_dur(total_seconds_single)}  |  "
              f"with {workers} workers: ≈ {fmt_dur(wall_seconds)}")
    if wall_seconds > 86400 * 7:  # > 1 week
        rep.add("compute budget", "warn",
                detail + "  — consider narrowing modes/seeds or PyPy/scipy")
    else:
        rep.add("compute budget", "ok", detail)

    # Output volume estimate: ~80 bytes/key in gzipped params + ~250/key results
    # (results only fire above threshold; assume ~1% rate as upper bound)
    est_bytes = int(total_keys * 80 + total_keys * 0.01 * 250)
    rep.add("output volume estimate", "ok",
            f"≈ {est_bytes/1024**2:.1f} MB across all shards")
    return est_bytes


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Pre-flight check for Noita brute-force runner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--data", default="noita_eye_data.json",
                   help="Ciphertext JSON file")
    p.add_argument("--dict-fi",  default="extra_words_fi.txt")
    p.add_argument("--dict-krl", default="extra_words_krl.txt")
    p.add_argument("--dict-en",  default="noita_wordlist.txt")
    p.add_argument("--modes", default="all",
                   help="Comma-separated mode names or 'all'")
    p.add_argument("--prngs", default="all",
                   help="Comma-separated PRNG names or 'all'")
    p.add_argument("--seed-start", type=int, default=0)
    p.add_argument("--seed-end",   type=int, default=1_000_000)
    p.add_argument("--workers",    type=int, default=os.cpu_count() or 1)
    p.add_argument("--output-dir", default="results_v1/")
    p.add_argument("--alphabet-size", type=int, default=83)
    p.add_argument("--resume", action="store_true",
                   help="Allow non-empty output dir (resume existing run)")
    p.add_argument("--skip-sanity", action="store_true",
                   help="Skip cipher/PRNG KAT checks (faster)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color output")
    args = p.parse_args(argv)

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    # Banner
    print()
    print(bold(cyan("┌─────────────────────────────────────────────────────────────┐")))
    print(bold(cyan("│  NOITA BF :: PRE-FLIGHT CHECK  ──  H3xDash / Null-H3x        │")))
    print(bold(cyan("└─────────────────────────────────────────────────────────────┘")))

    rep = Report()

    # === Section 1: environment ===
    rep.begin_section("Environment")
    check_python_version(rep)
    check_cpu_count(rep, args.workers)
    check_memory(rep, args.workers)
    check_fork_safety(rep)

    # === Section 1b: GPU (optional — runs CPU-only if absent) ===
    rep.begin_section("GPU acceleration (optional)")
    check_gpu_acceleration(rep)

    # === Section 2: modules ===
    rep.begin_section("Module imports")
    loaded = check_module_imports(rep)
    if loaded is None:
        _finalize(rep, Path(args.output_dir))
        return 2
    K_mod, P_mod, S_mod, R_mod = loaded

    # === Section 3: data file ===
    rep.begin_section("Ciphertext data")
    data = check_data_file(rep, Path(args.data), args.alphabet_size)

    # === Section 4: dictionaries ===
    rep.begin_section("Dictionaries")
    check_dictionary(rep, S_mod, "fi",  Path(args.dict_fi),  min_expected=10_000)
    check_dictionary(rep, S_mod, "krl", Path(args.dict_krl), min_expected=500)
    check_dictionary(rep, S_mod, "en",  Path(args.dict_en),  min_expected=500)

    # === Section 5: cipher/PRNG KATs ===
    if not args.skip_sanity:
        rep.begin_section("Cipher / PRNG sanity")
        check_prng_kats(rep, P_mod)
        check_vigenere_kat(rep, K_mod)
        check_pontifex_kat(rep, K_mod)
        check_gak_roundtrip(rep, K_mod, P_mod)
        check_hungarian_kat(rep, S_mod)
    else:
        rep.begin_section("Cipher / PRNG sanity")
        rep.add("KATs", "warn", "--skip-sanity set, kernel KATs not verified")

    # === Section 6: output dir ===
    rep.begin_section("Output directory")
    check_output_dir(rep, Path(args.output_dir), args.resume)

    # === Section 7: compute budget ===
    rep.begin_section("Compute budget")
    modes = args.modes.split(",") if args.modes != "all" else ["all"]
    prngs = args.prngs.split(",") if args.prngs != "all" else ["all"]
    est_bytes = check_compute_budget(rep, R_mod, P_mod, modes, prngs,
                                      args.seed_start, args.seed_end,
                                      args.workers)
    check_disk_space(rep, Path(args.output_dir), est_bytes if est_bytes > 0 else None)

    # === Final summary ===
    return _finalize(rep, Path(args.output_dir), args)


def _finalize(rep: Report, output_dir: Path,
              args: Optional[Any] = None) -> int:
    rep.end()
    print()
    print(bold(cyan("─" * 65)))
    fc = rep.fail_count()
    wc = rep.warn_count()
    oc = rep.ok_count()
    summary = (f"  {green(str(oc) + ' OK')}  |  "
               f"{yellow(str(wc) + ' WARN')}  |  "
               f"{red(str(fc) + ' FAIL')}")
    print(summary)

    if fc > 0:
        print()
        print(bold(red("  ✗ PRE-FLIGHT FAILED — DO NOT LAUNCH")))
        verdict = 2
    elif wc > 0:
        print()
        print(bold(yellow("  ⚠ PRE-FLIGHT WARNINGS — review before launch")))
        verdict = 1
    else:
        print()
        print(bold(green("  ✓ ALL SYSTEMS GREEN — clear for launch")))
        verdict = 0

    # Write report to output dir if it exists
    if output_dir.exists():
        try:
            rep_path = output_dir / "preflight_report.txt"
            rep.write_text_report(rep_path)
            print(dim(f"  report: {rep_path}"))
        except Exception as e:
            print(dim(f"  could not write report: {e}"))

    # Print recommended launch command
    if verdict <= 1 and args is not None:
        print()
        print(bold(cyan("  Recommended launch:")))
        cmd_parts = [
            "python3 eyestat_runner.py",
            f"--data {args.data}",
            f"--dict-fi {args.dict_fi}",
            f"--dict-krl {args.dict_krl}",
            f"--dict-en {args.dict_en}",
            f"--modes {args.modes}",
            f"--prngs {args.prngs}",
            f"--seed-start {args.seed_start}",
            f"--seed-end {args.seed_end}",
            f"--workers {args.workers}",
            f"--output-dir {args.output_dir}",
            f"--alphabet-size {args.alphabet_size}",
        ]
        if args.resume:
            cmd_parts.append("--resume")
        print("    " + dim(" \\\n    ".join(cmd_parts)))

    print(bold(cyan("─" * 65)))
    print()
    return verdict


if __name__ == "__main__":
    sys.exit(main())
