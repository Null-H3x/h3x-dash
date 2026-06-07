#!/usr/bin/env python3
"""eyesieve_preflight.py — pre-flight check for the EyeSieve pipeline.

Run this BEFORE launching any long compute job. Verifies that:

  1. Python environment is supported (version, hash randomization)
  2. Required stdlib + third-party packages are importable
  3. All eyesieve_* modules import cleanly
  4. The corpus data file is present, loads, validates, and matches the
     expected SHA-256 (catches accidental modification or corruption)
  5. Structural invariants of the corpus hold (universal positions, 3/6
     split at positions 3-5) — these are foundational assumptions of
     the Theory 1 / Theory 2 framework
  6. Selftest passes end-to-end
  7. Output directory exists and is writable
  8. System resources are adequate (CPU count, memory, disk)
  9. EyeStat reference path is reachable (warning only — required for
     scoring integration in later phases)

Exit codes:
  0  all green — go for launch
  1  warnings only — review and proceed if expected
  2  hard failure — do not launch

USAGE
=====
    python3 eyesieve_preflight.py
    python3 eyesieve_preflight.py --output-dir results/
    python3 eyesieve_preflight.py --eyestat-dir ~/Desktop/Noita/eyestat
    python3 eyesieve_preflight.py --strict          # treat warnings as failures

A full report is written to ``{output-dir}/preflight_report.txt``
(or ``preflight_report.txt`` in the current directory if no output dir
is given).

All failures carry the project's standard error-code prefix
``Internal Error Code: XD-MBYG04K-URS3LF`` for log searchability.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

# Minimum Python version. 3.10 chosen because:
#   - typing.Protocol with runtime_checkable
#   - structural pattern matching available if needed
#   - Ubuntu 24.04 ships 3.12 so this is well within reach
MIN_PYTHON = (3, 10)

# SHA-256 of the canonical noita_eye_data.json. Computed at packaging time.
# A mismatch means either the data file was modified locally (intentional or
# not) or the bundled copy drifted from the EyeStat canonical version. This
# is a hard fail because every hypothesis-space estimate downstream depends
# on the exact bytes of the corpus.
EXPECTED_DATA_SHA256 = (
    "c2840689881f2204103ddc9f10213e5f7ae69a8a9d47eb8ac330ffba13b43e2d"
)

# Minimum free resources. Tuned for the eventual full Theory 2 sweep
# (~1.5M hypotheses × telemetry + reports). Phase-1 checks are lighter.
MIN_FREE_DISK_GB = 1.0
MIN_FREE_MEMORY_MB = 512

# Eyesieve modules expected to import without side effects.
REQUIRED_MODULES = ("eyesieve_corpus", "eyesieve_permutations",
                    "eyesieve_reader", "eyesieve_sources",
                    "eyesieve_ciphers", "eyesieve_keyderiv",
                    "eyesieve_hypothesis", "eyesieve_enumerator",
                    "eyesieve_sieve", "eyesieve_scoring",
                    "eyesieve_runner", "eyesieve_mprunner")

# Stdlib modules used somewhere in the pipeline (sanity).
REQUIRED_STDLIB = ("json", "dataclasses", "collections", "pathlib",
                   "typing", "pickle", "hashlib", "multiprocessing")

# Third-party packages from requirements.txt.
REQUIRED_THIRDPARTY = ("numpy", "scipy")


# ---------------------------------------------------------------------------
# Output styling — matches eyestat aesthetic
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


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
    status: str           # "ok" | "warn" | "fail"
    detail: str = ""
    extra: list[str] = field(default_factory=list)


_results: list[CheckResult] = []


def _record(r: CheckResult) -> None:
    _results.append(r)
    tag = {"ok": TAG_OK, "warn": TAG_WARN, "fail": TAG_FAIL}[r.status]
    print(f"{tag} {r.name}")
    if r.detail:
        print(f"         {dim(r.detail)}")
    for line in r.extra:
        print(f"         {dim(line)}")


def _ok(name: str, detail: str = "", extra: list[str] | None = None) -> None:
    _record(CheckResult(name=name, status="ok", detail=detail,
                        extra=extra or []))


def _warn(name: str, detail: str = "", extra: list[str] | None = None) -> None:
    _record(CheckResult(name=name, status="warn", detail=detail,
                        extra=extra or []))


def _fail(name: str, detail: str = "", extra: list[str] | None = None) -> None:
    _record(CheckResult(name=name, status="fail",
                        detail=f"{ERROR_PREFIX} :: preflight :: {detail}"
                               if detail else ERROR_PREFIX,
                        extra=extra or []))


# ---------------------------------------------------------------------------
# Section 1: Python environment
# ---------------------------------------------------------------------------

def section_python() -> None:
    print(f"\n{TAG_INFO} {bold('1. Python environment')}")

    v = sys.version_info
    v_str = f"{v.major}.{v.minor}.{v.micro}"
    impl = platform.python_implementation()
    if (v.major, v.minor) >= MIN_PYTHON:
        _ok(f"Python version {v_str} ({impl})",
            detail=f"required: >= {'.'.join(str(x) for x in MIN_PYTHON)}")
    else:
        _fail(f"Python version {v_str} ({impl})",
              detail=f"required: >= {'.'.join(str(x) for x in MIN_PYTHON)}, "
                     f"got {v_str}")

    # Hash randomization — useful info but rarely a problem
    seed = os.environ.get("PYTHONHASHSEED")
    if seed is not None:
        _ok(f"PYTHONHASHSEED set to {seed!r}",
            detail="deterministic hashing across runs")
    else:
        _ok("PYTHONHASHSEED not set",
            detail="standard randomized hashing (no impact on EyeSieve)")

    # 64-bit Python (large allocations, dict sizes)
    if sys.maxsize > 2**32:
        _ok(f"64-bit Python ({platform.machine()})")
    else:
        _warn(f"32-bit Python ({platform.machine()})",
              detail="larger hypothesis spaces may exhaust address space")


# ---------------------------------------------------------------------------
# Section 2: Module imports
# ---------------------------------------------------------------------------

def section_imports() -> None:
    print(f"\n{TAG_INFO} {bold('2. Module imports')}")

    # Stdlib
    for mod in REQUIRED_STDLIB:
        try:
            importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001
            _fail(f"stdlib: {mod}",
                  detail=f"{type(e).__name__}: {e}")
        else:
            _ok(f"stdlib: {mod}")

    # Third-party
    for mod in REQUIRED_THIRDPARTY:
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", "?")
            _ok(f"third-party: {mod}", detail=f"version {ver}")
        except ImportError as e:
            _fail(f"third-party: {mod}",
                  detail=f"not installed — run "
                         f"`pip install -r requirements.txt` ({e})")

    # EyeSieve modules
    project_dir = Path(__file__).resolve().parent
    if str(project_dir) not in sys.path:
        sys.path.insert(0, str(project_dir))
    for mod in REQUIRED_MODULES:
        try:
            importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001
            _fail(f"eyesieve: {mod}",
                  detail=f"{type(e).__name__}: {e}")
            for line in traceback.format_exc().splitlines()[-6:]:
                _record(CheckResult(name="", status="fail", detail=line))
        else:
            _ok(f"eyesieve: {mod}")


# ---------------------------------------------------------------------------
# Section 3: Data file integrity
# ---------------------------------------------------------------------------

def section_data(data_path: Path) -> None:
    print(f"\n{TAG_INFO} {bold('3. Data file integrity')}")

    if not data_path.exists():
        _fail(f"data file present", detail=f"not found: {data_path}")
        return
    _ok(f"data file present", detail=str(data_path))

    # SHA-256
    h = hashlib.sha256()
    try:
        with data_path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        _fail("data file SHA-256",
              detail=f"cannot read: {e}")
        return
    digest = h.hexdigest()
    if digest == EXPECTED_DATA_SHA256:
        _ok("data file SHA-256 matches canonical",
            detail=f"sha256 = {digest[:16]}...{digest[-8:]}")
    else:
        _warn("data file SHA-256 differs from canonical",
              detail=f"got      {digest}",
              extra=[f"expected {EXPECTED_DATA_SHA256}",
                     "if this is intentional (e.g. you re-derived the corpus), "
                     "update EXPECTED_DATA_SHA256 in eyesieve_preflight.py"])

    # Load + validate via the corpus module (its own integrity checks)
    try:
        import eyesieve_corpus as ec
        corpus = ec.load_corpus(data_path)
    except Exception as e:  # noqa: BLE001
        _fail("corpus loads + validates",
              detail=f"{type(e).__name__}: {e}")
        return
    _ok("corpus loads + validates",
        detail=f"deck_size={corpus.deck_size}, "
               f"messages={corpus.num_messages}, "
               f"symbols={sum(corpus.lengths)}")


# ---------------------------------------------------------------------------
# Section 4: Structural invariants
# ---------------------------------------------------------------------------

def section_structure(data_path: Path) -> None:
    print(f"\n{TAG_INFO} {bold('4. Corpus structural invariants')}")

    try:
        import eyesieve_corpus as ec
        corpus = ec.load_corpus(data_path)
    except Exception as e:  # noqa: BLE001
        _fail("structure: corpus must load",
              detail=f"upstream failure: {e}")
        return

    # Universal positions = ((1, 66), (2, 5))
    univ = ec.universal_positions(corpus)
    expected_univ = ((1, 66), (2, 5))
    if univ == expected_univ:
        _ok("universal positions = ((1, 66), (2, 5))",
            detail="positions 1-2 are shared across all 9 messages")
    else:
        _warn(f"universal positions",
              detail=f"got {univ}, expected {expected_univ}",
              extra=["this is a foundational structural assumption — "
                     "if it has drifted, theory hypotheses need re-derivation"])

    # 3/6 split at positions 3, 4, 5
    groups = ec.shared_prefix_groups(corpus, max_position=6,
                                     min_group_size=3)
    for pos in (3, 4, 5):
        pos_groups = [g for g in groups if g.position == pos]
        sizes = sorted(len(g.members) for g in pos_groups)
        if sizes == [3, 6]:
            members3 = next(g.members for g in pos_groups
                            if len(g.members) == 3)
            if set(members3) == {"E1", "W1", "E2"}:
                _ok(f"position {pos} splits 3/6 with E1,W1,E2 in the 3-group")
            else:
                _warn(f"position {pos} 3/6 split, unexpected 3-group members",
                      detail=f"got {sorted(members3)}, "
                             f"expected ['E1', 'W1', 'E2']")
        else:
            _warn(f"position {pos} group sizes",
                  detail=f"got {sizes}, expected [3, 6]")


# ---------------------------------------------------------------------------
# Section 5: Selftest pass-through
# ---------------------------------------------------------------------------

def section_selftest() -> None:
    print(f"\n{TAG_INFO} {bold('5. Selftest pass-through')}")

    selftest = Path(__file__).resolve().parent / "eyesieve_selftest.py"
    if not selftest.exists():
        _fail("eyesieve_selftest.py present",
              detail=f"not found: {selftest}")
        return

    # Run as subprocess with NO_COLOR to keep output parseable
    env = dict(os.environ, NO_COLOR="1")
    try:
        proc = subprocess.run(
            [sys.executable, str(selftest)],
            capture_output=True, text=True, env=env, timeout=120,
        )
    except subprocess.TimeoutExpired:
        _fail("eyesieve_selftest.py runs", detail="timed out after 120s")
        return
    except Exception as e:  # noqa: BLE001
        _fail("eyesieve_selftest.py runs",
              detail=f"{type(e).__name__}: {e}")
        return

    out = proc.stdout
    total_line = next((l for l in out.splitlines()
                       if l.strip().startswith("total :")), "")
    pass_line = next((l for l in out.splitlines()
                      if l.strip().startswith("ok    :")), "")
    fail_line = next((l for l in out.splitlines()
                      if l.strip().startswith("fail  :")), "")

    if proc.returncode == 0:
        _ok("eyesieve_selftest.py: all green",
            detail=f"{total_line.strip()}, {pass_line.strip()}")
    elif proc.returncode == 1:
        _warn("eyesieve_selftest.py: warnings only",
              detail=f"{total_line.strip()}")
    else:
        _fail("eyesieve_selftest.py: failures",
              detail=f"{total_line.strip()}; {fail_line.strip()}",
              extra=["run `./eyesieve_selftest.py` directly for details"])


# ---------------------------------------------------------------------------
# Section 6: Output directory
# ---------------------------------------------------------------------------

def section_output_dir(output_dir: Path | None) -> None:
    print(f"\n{TAG_INFO} {bold('6. Output directory')}")

    target = output_dir if output_dir else Path.cwd()
    target = target.resolve()

    if output_dir is not None:
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _fail(f"output dir {target}",
                  detail=f"cannot create: {e}")
            return

    if not target.exists():
        _fail(f"output dir present", detail=f"missing: {target}")
        return

    # Writability probe — create + remove a temp file
    try:
        with tempfile.NamedTemporaryFile(dir=target, delete=True) as f:
            f.write(b"eyesieve preflight probe")
            f.flush()
    except OSError as e:
        _fail(f"output dir writable",
              detail=f"{target}: {e}")
        return
    _ok(f"output dir writable", detail=str(target))


# ---------------------------------------------------------------------------
# Section 7: System resources
# ---------------------------------------------------------------------------

def section_resources(output_dir: Path | None) -> None:
    print(f"\n{TAG_INFO} {bold('7. System resources')}")

    # CPU count
    n_cpu = os.cpu_count() or 1
    _ok(f"CPU count: {n_cpu}",
        detail="parallel workers will scale with this")

    # Memory — use /proc/meminfo on Linux for a portable, dependency-free read
    mem_total_mb: float | None = None
    mem_avail_mb: float | None = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total_mb = int(line.split()[1]) / 1024.0
                elif line.startswith("MemAvailable:"):
                    mem_avail_mb = int(line.split()[1]) / 1024.0
    except OSError:
        _warn("memory info", detail="/proc/meminfo unreadable (non-Linux?)")

    if mem_total_mb is not None and mem_avail_mb is not None:
        if mem_avail_mb >= MIN_FREE_MEMORY_MB:
            _ok(f"memory: {mem_avail_mb:.0f} MB available "
                f"of {mem_total_mb:.0f} MB total")
        else:
            _warn(f"memory: only {mem_avail_mb:.0f} MB available",
                  detail=f"recommended: >= {MIN_FREE_MEMORY_MB} MB free")

    # Disk
    target = (output_dir if output_dir else Path.cwd()).resolve()
    try:
        usage = shutil.disk_usage(target)
        free_gb = usage.free / (1024 ** 3)
        if free_gb >= MIN_FREE_DISK_GB:
            _ok(f"disk: {free_gb:.1f} GB free on {target}")
        else:
            _warn(f"disk: only {free_gb:.2f} GB free on {target}",
                  detail=f"recommended: >= {MIN_FREE_DISK_GB} GB")
    except OSError as e:
        _warn("disk usage", detail=f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Section 8: EyeStat integration readiness
# ---------------------------------------------------------------------------

def section_eyestat(eyestat_dir: Path | None) -> None:
    print(f"\n{TAG_INFO} {bold('8. EyeStat integration readiness')}")

    if eyestat_dir is None:
        # Use the scoring module's multi-path discovery
        try:
            import eyesieve_scoring
            discovered = eyesieve_scoring.discover_eyestat_dir()
        except ImportError:
            discovered = None

        if discovered is not None:
            eyestat_dir = discovered
            _ok(f"EyeStat dir auto-discovered",
                detail=str(eyestat_dir))
        else:
            _warn("EyeStat dir not specified or auto-discovered",
                  detail="scoring backend will not be available",
                  extra=["set $EYESTAT_DIR or pass --eyestat-dir",
                         "scoring tests skip cleanly when absent; "
                         "the sieve and runner work fine without it"])
            return
    else:
        if not eyestat_dir.exists():
            _warn(f"EyeStat dir does not exist",
                  detail=str(eyestat_dir))
            return
        _ok(f"EyeStat dir present", detail=str(eyestat_dir))

    # Probe for the scoring module
    scoring_py = eyestat_dir / "eyestat_scoring.py"
    if scoring_py.exists():
        _ok("eyestat_scoring.py reachable",
            detail=str(scoring_py))
    else:
        _warn("eyestat_scoring.py not found",
              detail=f"expected at {scoring_py}")


# ---------------------------------------------------------------------------
# Summary + report
# ---------------------------------------------------------------------------

def _summary() -> tuple[int, int, int]:
    ok    = sum(1 for r in _results if r.status == "ok")
    warn  = sum(1 for r in _results if r.status == "warn")
    fail  = sum(1 for r in _results if r.status == "fail" and r.name)
    return ok, warn, fail


def _print_summary() -> None:
    ok, warn, fail = _summary()
    total = ok + warn + fail
    print()
    print(bold("─" * 64))
    print(f"  total : {total}")
    print(f"  ok    : {green(str(ok))}")
    if warn:
        print(f"  warn  : {yellow(str(warn))}")
    if fail:
        print(f"  fail  : {red(str(fail))}")
    print(bold("─" * 64))


def _write_report(report_path: Path) -> None:
    """Write a no-color version of the full result list to a text file."""
    lines: list[str] = []
    lines.append("EyeSieve preflight report")
    lines.append("=" * 64)
    lines.append(f"python   : {sys.version.splitlines()[0]}")
    lines.append(f"platform : {platform.platform()}")
    lines.append(f"cwd      : {Path.cwd()}")
    lines.append("")
    for r in _results:
        if not r.name:
            continue
        tag = {"ok": "[OK]  ", "warn": "[WARN]", "fail": "[FAIL]"}[r.status]
        lines.append(f"{tag} {r.name}")
        if r.detail:
            lines.append(f"        {r.detail}")
        for e in r.extra:
            lines.append(f"        {e}")
    ok, warn, fail = _summary()
    lines.append("")
    lines.append("-" * 64)
    lines.append(f"total : {ok + warn + fail}")
    lines.append(f"ok    : {ok}")
    if warn:
        lines.append(f"warn  : {warn}")
    if fail:
        lines.append(f"fail  : {fail}")
    try:
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as e:
        print(f"{TAG_WARN} could not write report to {report_path}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pre-flight check for the EyeSieve pipeline."
    )
    parser.add_argument("--data", default="noita_eye_data.json",
                        help="Path to corpus JSON (default: %(default)s)")
    parser.add_argument("--output-dir", default=None,
                        help="Where eventual scan outputs will go; verified "
                             "writable (default: skip the check)")
    parser.add_argument("--eyestat-dir", default=None,
                        help="Path to the EyeStat project (default: try "
                             "~/Desktop/Noita/eyestat)")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as failures (exit 2 on any warn)")
    parser.add_argument("--report-path", default=None,
                        help="Where to write the report (default: "
                             "{output-dir}/preflight_report.txt or "
                             "./preflight_report.txt)")
    args = parser.parse_args(argv)

    data_path = Path(args.data).resolve()
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    eyestat_dir = Path(args.eyestat_dir).resolve() if args.eyestat_dir else None

    # Banner
    print(bold(cyan("\n╔══════════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║  EyeSieve // PRE-FLIGHT // pre-launch sanity sweep           ║")))
    print(bold(cyan("╚══════════════════════════════════════════════════════════════╝")))

    section_python()
    section_imports()
    section_data(data_path)
    section_structure(data_path)
    section_selftest()
    section_output_dir(output_dir)
    section_resources(output_dir)
    section_eyestat(eyestat_dir)

    _print_summary()

    # Report file
    if args.report_path:
        report_path = Path(args.report_path).resolve()
    elif output_dir:
        report_path = output_dir / "preflight_report.txt"
    else:
        report_path = Path.cwd() / "preflight_report.txt"
    _write_report(report_path)
    print(f"\n{TAG_INFO} report written to {report_path}")

    ok, warn, fail = _summary()
    if fail:
        print(f"\n{TAG_FAIL} {ERROR_PREFIX} :: preflight :: {fail} hard failure(s)")
        return 2
    if warn:
        if args.strict:
            print(f"\n{TAG_FAIL} {ERROR_PREFIX} :: preflight :: "
                  f"{warn} warning(s) treated as failures under --strict")
            return 2
        print(f"\n{yellow('warnings present — review above')}")
        return 1
    print(f"\n{green('ALL GREEN — preflight clean, cleared for launch.')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
