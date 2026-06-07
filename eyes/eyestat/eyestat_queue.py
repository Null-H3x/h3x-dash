#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_queue.py — sequential scan queue for a Cartesian product of
(cipher mode, PRNG) combinations.

Wraps eyestat_gpu_runner.py. For each (mode, prng) combo, launches one
sweep with output going to <scans-root>/<short_name>/. Skips combos
that are already complete (detected by presence of an HTML report in
their results/ subdir).

Usage:
    # Tier 1 — all 8 GAK modes × both Park-Miller variants
    ./eyestat_queue.py --tier 1

    # Or build a queue explicitly
    ./eyestat_queue.py \\
        --modes ctak_left,ptak_right,ptak_left \\
        --prngs park_miller_v0,park_miller_v1 \\
        --seed-start 0 --seed-end 2147483646 \\
        --workers 64 --languages fi \\
        --dict-en noita_wordlist.txt \\
        --threshold 13

    # Preview the queue without launching
    ./eyestat_queue.py --tier 1 --dry-run

    # Force re-running combos that are already complete
    ./eyestat_queue.py --tier 1 --force

Behavior:
- Runs sequentially (one scan at a time, full GPU per scan).
- Skips combos whose <scans-root>/<short_name>/results/*_report.html
  already exists.
- Master log appended to <scans-root>/queue.log across runs.
- Each scan's run.log is in its own scan dir (same as standalone use).
- Single Ctrl-C: finishes current scan, then exits. Double Ctrl-C:
  SIGINT to the runner so it can clean up, then exits the queue.
- Idempotent — re-run with same args to resume.

The queue itself doesn't need a venv since it just shells out — but it
relies on eyestat_gpu_runner.py being executable (chmod +x) with its
shebang pointing to the venv Python.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

# --- Short-name table for scan directory naming ---
# Folder names follow {mode}_{prng_short} so they're easy to type and
# tab-complete. Unknown PRNGs fall through to their full name.
PRNG_SHORT = {
    "park_miller_v0": "pm_v0",
    "park_miller_v1": "pm_v1",
    "xorshift32":     "xs32",
    "xorshift64":     "xs64",
    "pcg32":          "pcg",
    "splitmix64":     "smx",
    "mt19937":        "mt",
    "nr_lcg":         "nrlcg",
    "glibc_lcg":      "glcg",
    "msvc_lcg":       "mslcg",
}

# --- Preset tiers from the roadmap ---
GAK_MODES = ["ctak_right", "ctak_left",
             "ptak_right", "ptak_left",
             "xgak_sum_right", "xgak_sum_left",
             "xgak_diff_right", "xgak_diff_left"]

TIERS = {
    1: {
        "name": "GAK family × Park-Miller V0/V1 (8-cuts default)",
        "modes": GAK_MODES,
        "prngs": ["park_miller_v0", "park_miller_v1"],
        "extra_runner_args": [],
    },
    # Tier 2 will be unlocked once --treat-as-single ships:
    # 2: {
    #     "name": "GAK family × Park-Miller V0/V1 (0-cuts hypothesis)",
    #     "modes": GAK_MODES,
    #     "prngs": ["park_miller_v0", "park_miller_v1"],
    #     "extra_runner_args": ["--treat-as-single"],
    # },
}


def validate_combos_against_runner(runner_path: Path, modes: list[str],
                                    prngs: list[str]) -> list[str]:
    """Query the runner with --help and verify every mode/prng we plan
    to use is actually an accepted choice. Returns a list of error
    strings (empty if all good)."""
    errors: list[str] = []
    try:
        # Invoke via the current Python interpreter so it works whether the
        # runner is marked +x or not, and works in both venv-shebang and
        # non-venv-shebang scenarios.
        out = subprocess.run([sys.executable, str(runner_path), "--help"],
                             capture_output=True, text=True, timeout=20)
        help_text = out.stdout + out.stderr
    except Exception as e:
        # Don't block the queue on validation failure — just warn
        return [f"could not query runner --help for validation: {e}"]

    # Parse "--mode {ctak_right,ctak_left,...}" and "--prng {park_miller_v0,...}"
    import re
    def extract_choices(flag: str) -> set[str] | None:
        m = re.search(rf"{flag}\s+\{{([^}}]+)\}}", help_text)
        if not m:
            return None
        return {c.strip() for c in m.group(1).split(",")}

    mode_choices = extract_choices(r"--mode")
    prng_choices = extract_choices(r"--prng")

    if mode_choices is None:
        return ["could not parse --mode choices from runner --help"]
    if prng_choices is None:
        return ["could not parse --prng choices from runner --help"]

    for m in modes:
        if m not in mode_choices:
            close = sorted(c for c in mode_choices if m[:6] in c or c[:6] in m)
            hint = f" Did you mean: {close}?" if close else ""
            errors.append(f"unknown --mode '{m}'.{hint}")
    for p in prngs:
        if p not in prng_choices:
            close = sorted(c for c in prng_choices if p[:6] in c or c[:6] in p)
            hint = f" Did you mean: {close}?" if close else ""
            errors.append(f"unknown --prng '{p}'.{hint}")

    return errors


def short_name(mode: str, prng: str) -> str:
    """e.g. ('ctak_right', 'park_miller_v0') -> 'ctak_right_pm_v0'"""
    return f"{mode}_{PRNG_SHORT.get(prng, prng)}"


def is_complete(scan_dir: Path) -> bool:
    """A scan counts as complete if its results/ has any *_report.html.
    That file is produced by the runner's auto-HTML step at end of run.
    """
    results = scan_dir / "results"
    if not results.is_dir():
        return False
    return any(results.glob("*_report.html"))


def build_runner_cmd(args: argparse.Namespace, mode: str, prng: str,
                     output_dir: Path, runner_path: Path,
                     extra_args: Iterable[str]) -> list[str]:
    cmd = [
        str(runner_path),
        "--mode", mode,
        "--prng", prng,
        "--seed-start", str(args.seed_start),
        "--seed-end",   str(args.seed_end),
        "--workers",    str(args.workers),
        "--languages",  args.languages,
        "--dict-en",    args.dict_en,
        "--output-dir", str(output_dir),
        "--threshold",  str(args.threshold),
        "--gpu-utilization", str(args.gpu_utilization),
    ]
    if args.chi2_threshold is not None:
        cmd.extend(["--chi2-threshold", str(args.chi2_threshold)])
    if args.no_html:
        cmd.append("--no-html")
    cmd.extend(extra_args)
    return cmd


def _hms(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h: return f"{h}h{m:02d}m{s:02d}s"
    if m: return f"{m}m{s:02d}s"
    return f"{s}s"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # Queue selection — either a preset tier or explicit lists
    p.add_argument("--tier", type=int, choices=list(TIERS.keys()),
                   help="Use a preset tier from the roadmap")
    p.add_argument("--modes", default=None,
                   help="Comma-separated cipher modes "
                        f"(default {','.join(GAK_MODES)})")
    p.add_argument("--prngs", default=None,
                   help="Comma-separated PRNG names "
                        "(default: park_miller_v0,park_miller_v1)")

    # Layout
    p.add_argument("--scans-root", default="scans/",
                   help="Parent dir for scan subfolders (default: scans/)")
    p.add_argument("--runner", default="./eyestat_gpu_runner.py",
                   help="Path to eyestat_gpu_runner.py")

    # Pass-through runner args
    p.add_argument("--seed-start", type=int, default=0)
    p.add_argument("--seed-end",   type=int, default=2147483646)
    p.add_argument("--workers",    type=int, default=64)
    p.add_argument("--languages",  default="fi")
    p.add_argument("--dict-en",    default="noita_wordlist.txt")
    p.add_argument("--threshold",  type=int, default=13)
    p.add_argument("--chi2-threshold", default=None,
                   help="Pass-through to the runner (use 'off' to disable)")
    p.add_argument("--gpu-utilization", type=float, default=1.0)
    p.add_argument("--no-html", action="store_true")

    # Queue control
    p.add_argument("--dry-run", action="store_true",
                   help="Show the queue without launching anything")
    p.add_argument("--force",   action="store_true",
                   help="Re-run combos even if their HTML report exists")

    args = p.parse_args()

    # Resolve the (modes, prngs) lists. Tier preset wins if given.
    extra_runner_args: list[str] = []
    if args.tier is not None:
        tier = TIERS[args.tier]
        modes = tier["modes"]
        prngs = tier["prngs"]
        extra_runner_args = tier["extra_runner_args"]
        print(f"[queue] Tier {args.tier}: {tier['name']}")
    else:
        if not args.modes or not args.prngs:
            p.error("Must specify --tier OR (--modes AND --prngs)")
        modes = [m.strip() for m in args.modes.split(",") if m.strip()]
        prngs = [pr.strip() for pr in args.prngs.split(",") if pr.strip()]

    scans_root = Path(args.scans_root).resolve()
    scans_root.mkdir(parents=True, exist_ok=True)

    # Build the full Cartesian product
    queue = [(m, pr) for m in modes for pr in prngs]

    print(f"[queue] {len(queue)} (mode, prng) combinations to consider:\n")
    skip = []
    todo = []
    for mode, prng in queue:
        sd = scans_root / short_name(mode, prng)
        if is_complete(sd) and not args.force:
            skip.append((mode, prng, sd))
        else:
            todo.append((mode, prng, sd))

    fmt = "  [{:<8s}]  {:<14s}/  {:<14s}  →  {}"
    for mode, prng, sd in skip:
        print(fmt.format("SKIP", mode, prng,
                         sd.relative_to(Path.cwd()) if str(sd).startswith(str(Path.cwd())) else sd))
    for mode, prng, sd in todo:
        print(fmt.format("RUN", mode, prng,
                         sd.relative_to(Path.cwd()) if str(sd).startswith(str(Path.cwd())) else sd))

    seeds_per_sweep = args.seed_end - args.seed_start
    # Heuristic ETA based on observed 272k/s with chi² filter on
    eta_per_sweep_sec = seeds_per_sweep / 272_000 if seeds_per_sweep > 0 else 0
    print()
    print(f"[queue] Will RUN {len(todo)} sweep(s), SKIP {len(skip)} already-complete.")
    if todo:
        total_eta = eta_per_sweep_sec * len(todo)
        print(f"[queue] Estimated time at ~272k seeds/sec: "
              f"{_hms(eta_per_sweep_sec)} per sweep, "
              f"{_hms(total_eta)} total.")

    # Sanity-check the runner exists (do this BEFORE dry-run exit so
    # dry-runs also validate the modes/prngs).
    runner_path = Path(args.runner).resolve()
    if not runner_path.exists():
        print(f"\n[queue] ERROR: runner not found at {runner_path}",
              file=sys.stderr)
        return 1

    # Validate every (mode, prng) we plan to use is accepted by the runner.
    # This catches the class of bug where a tier preset has stale mode names.
    # Run even on --dry-run so the preview catches name mismatches early.
    val_errors = validate_combos_against_runner(runner_path, modes, prngs)
    if val_errors:
        print(f"\n[queue] ERROR: validation failed against runner:")
        for e in val_errors:
            print(f"        {e}")
        print(f"\n[queue] Refusing to launch. Fix the mode/prng names and retry.")
        return 1

    if args.dry_run:
        print("\n[queue] Dry-run — not launching.")
        return 0
    if not todo:
        print("\n[queue] Nothing to do.")
        return 0

    # Master log
    queue_log = scans_root / "queue.log"
    with open(queue_log, "a", encoding="utf-8") as ql:
        ql.write(f"\n{'='*72}\n")
        ql.write(f"[queue start] {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        ql.write(f"  to_run={len(todo)}  to_skip={len(skip)}\n")
        for mode, prng, sd in todo:
            ql.write(f"  queued: {mode} / {prng}  →  {sd}\n")

    # Ctrl-C handling: first one sets a "finish-then-exit" flag, second
    # one signals the running child to interrupt and we exit ASAP.
    stop_after_current = {"flag": False}
    current_proc = {"proc": None}

    def handle_sigint(signum, frame):
        if stop_after_current["flag"]:
            # Second Ctrl-C — forward SIGINT to child and exit
            print("\n[queue] Second Ctrl-C — forwarding to current scan.",
                  flush=True)
            if current_proc["proc"] is not None:
                try:
                    current_proc["proc"].send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
            return  # let the child finish, the loop will exit normally
        stop_after_current["flag"] = True
        print("\n[queue] Ctrl-C caught. Current scan will finish; queue "
              "will then exit. Ctrl-C again to interrupt the scan.",
              flush=True)

    signal.signal(signal.SIGINT, handle_sigint)

    queue_t0 = time.time()
    completed = 0
    failed = 0

    for i, (mode, prng, scan_dir) in enumerate(todo, 1):
        if stop_after_current["flag"] and i > 1:
            # Only break after the loop has started AT LEAST one scan,
            # so a Ctrl-C right at the start still runs nothing.
            break

        scan_dir.mkdir(parents=True, exist_ok=True)
        run_log = scan_dir / "run.log"

        cmd = build_runner_cmd(args, mode, prng, scan_dir,
                               runner_path, extra_runner_args)

        banner = (f"\n{'='*72}\n"
                  f"[{i}/{len(todo)}]  {scan_dir.name}  "
                  f"({mode} / {prng})\n"
                  f"  started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                  f"  output:  {scan_dir}\n"
                  f"{'='*72}\n")
        print(banner, flush=True)
        with open(queue_log, "a", encoding="utf-8") as ql:
            ql.write(banner)

        t0 = time.time()
        exit_code = 0
        try:
            # Open run.log with line-buffering (buffering=1) so the file
            # reflects progress in real time. Without this, the file
            # buffer can hold minutes worth of output, causing
            # eyestat_status.py to see stale data even while the runner
            # is actively progressing on the terminal.
            with open(run_log, "w", encoding="utf-8", buffering=1) as rl:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1, text=True,
                )
                current_proc["proc"] = proc
                # Tee child output to console + run.log
                assert proc.stdout is not None
                for line in proc.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    rl.write(line)
                    # Belt-and-suspenders flush: even with buffering=1,
                    # incomplete-line writes won't auto-flush. The
                    # runner's [progress] lines end with \n so this
                    # mostly catches edge cases (mid-line writes from
                    # GPU kernel compile output, tqdm-style updates).
                    if "[progress]" in line or "[shard" in line:
                        rl.flush()
                proc.wait()
                exit_code = proc.returncode
        except Exception as e:
            exit_code = -1
            print(f"\n[queue] exception while running scan: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
        finally:
            current_proc["proc"] = None

        duration = time.time() - t0
        status = "completed" if exit_code == 0 else f"FAILED (exit={exit_code})"
        if exit_code == 0:
            completed += 1
        else:
            failed += 1

        tail = (f"\n[{i}/{len(todo)}]  {status}  "
                f"in {_hms(duration)}\n")
        print(tail, flush=True)
        with open(queue_log, "a", encoding="utf-8") as ql:
            ql.write(tail)

    total = time.time() - queue_t0
    summary = (f"\n{'='*72}\n"
               f"[queue done] completed={completed}  failed={failed}  "
               f"skipped={len(skip)}  total_time={_hms(total)}\n"
               f"{'='*72}\n")
    print(summary, flush=True)
    with open(queue_log, "a", encoding="utf-8") as ql:
        ql.write(summary)

    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
