#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_status.py — live status display for a running eyestat sweep.

Polls the runner's log file + nvidia-smi + /sys thermal zones every N
seconds and renders a static vertical status block in the terminal. Does
not modify the main run — it's read-only.

Usage:
    ./eyestat_status.py path/to/results_*/run.log
    ./eyestat_status.py path/to/results_*/run.log --refresh 3

The display refreshes in place via ANSI escape codes. CTRL-C to exit.

Layout (matches user spec):
    ETA: 10.4 Min
    .1% complete

    hits = 4,250
    rate = 10,343/s

    shard 1010/200000
    keys 1.01M/2000M

    GPU: 44C Util: 4%
    CPU: 85C Util: 98%

The script tolerates the log being rewritten, truncated, or missing.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

# Match a [progress] line emitted by eyestat_gpu_runner.py. The format is:
#   [progress] shard 80/2148, keys=79,655,360/2,147,483,646, hits=12,
#              rate=266,000/s, ETA=129.5min  |  chi2 reject=100.0% min=0.00518
# (the chi2 suffix is optional — only present when filter is enabled)
PROGRESS_RE = re.compile(
    r"\[progress\]\s+"
    r"shard\s+(?P<shard_cur>\d+)/(?P<shard_tot>\d+),\s+"
    r"keys=(?P<keys_cur>[\d,]+)/(?P<keys_tot>[\d,]+),\s+"
    r"hits=(?P<hits>[\d,]+),\s+"
    r"rate=(?P<rate>[\d,]+)/s,\s+"
    r"ETA=(?P<eta>[\d.]+)min"
    r"(?:\s*\|\s*chi2\s+reject=(?P<chi2_rej>[\d.]+)%\s+"
    r"min=(?P<chi2_min>[\d.]+))?"
)

# Locate which thermal zones describe CPU cores. Vendors vary widely:
#   Intel:   "x86_pkg_temp", "coretemp"
#   AMD:     "k10temp", "zenpower"
#   Generic: any zone whose `type` contains "cpu" or "core"
CPU_THERMAL_HINTS = ("x86", "core", "cpu", "k10", "zen", "tctl")

# Same idea for /sys/class/hwmon/hwmon*/name, which is where modern kernels
# expose CPU temperatures on Ubuntu 22.04+ / 24.04 — especially for AMD
# (k10temp, zenpower) where /sys/class/thermal often only has the generic
# ACPI sensor that doesn't track core temps.
CPU_HWMON_NAMES = ("k10temp", "zenpower", "zenpower3", "coretemp",
                   "k8temp", "amdtemp")


def resolve_logfile(arg: str) -> tuple[Path, str | None]:
    """Resolve the log path argument to (logfile, scan_name).

    Three modes:
    1. arg points to a file (e.g. scans/ctak_left_pm_v0/run.log) — use it
       directly, no auto-tracking.
    2. arg points to a scan directory (has run.log inside) — use that
       run.log directly.
    3. arg points to a scans/ parent directory containing multiple scan
       subfolders — find the most-recently-modified run.log under it.
       This auto-follows the queue as it cycles through scans.

    Returns:
        (logfile_path, scan_name)
        scan_name is the parent directory's basename (e.g. "ctak_left_pm_v0"),
        or None if the path resolved to a top-level file.
    """
    p = Path(arg)

    # Mode 1: explicit file path
    if p.is_file():
        # If the parent dir looks like a scan dir, surface its name
        parent = p.parent
        if parent.name and (parent / "temp").is_dir():
            return p, parent.name
        return p, None

    # Mode 2: scan-dir (has run.log directly inside)
    if p.is_dir():
        direct = p / "run.log"
        if direct.is_file():
            return direct, p.name

        # Mode 3: scans/ parent — find newest run.log among children
        candidates = list(p.glob("*/run.log"))
        candidates = [c for c in candidates if c.is_file()]
        if candidates:
            candidates.sort(key=lambda c: c.stat().st_mtime, reverse=True)
            newest = candidates[0]
            return newest, newest.parent.name

        # Nothing yet — return a placeholder so render() shows a waiting msg
        return direct, None

    # Unresolvable — return the original; render() will show the "waiting"
    # screen until something matching appears on disk
    return p, None


def parse_last_progress(log_path: Path) -> dict | None:
    """Return the most recent [progress] line as a dict, or None."""
    if not log_path.exists():
        return None
    try:
        # Read last 16 KB — plenty for the most recent progress lines
        # without slurping the whole multi-MB log
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 16384))
            tail = f.read().decode(errors="replace")
    except OSError:
        return None

    matches = list(PROGRESS_RE.finditer(tail))
    if not matches:
        return None
    m = matches[-1]
    return {
        "shard_cur": int(m.group("shard_cur")),
        "shard_tot": int(m.group("shard_tot")),
        "keys_cur":  int(m.group("keys_cur").replace(",", "")),
        "keys_tot":  int(m.group("keys_tot").replace(",", "")),
        "hits":      int(m.group("hits").replace(",", "")),
        "rate":      int(m.group("rate").replace(",", "")),
        "eta_min":   float(m.group("eta")),
        "chi2_rej":  float(m.group("chi2_rej")) if m.group("chi2_rej") else None,
        "chi2_min":  float(m.group("chi2_min")) if m.group("chi2_min") else None,
    }


def get_gpu_stats() -> tuple[int | None, int | None]:
    """Return (temp_C, util_pct) from nvidia-smi, or (None, None)."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi",
             "--query-gpu=temperature.gpu,utilization.gpu",
             "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL, timeout=3
        ).decode().strip()
        # If multiple GPUs, take the first
        first = out.splitlines()[0]
        temp_str, util_str = (p.strip() for p in first.split(","))
        return int(temp_str), int(util_str)
    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        return None, None


def get_cpu_temp() -> int | None:
    """Return the hottest CPU temperature reading in °C, or None.

    Scans TWO locations because CPU temperature exposure varies by vendor +
    kernel version:

    1. /sys/class/hwmon/hwmon*/  — preferred. Modern AMD CPUs (Zen and up,
       via the k10temp driver) expose Tctl/Tccd here. Most Intel CPUs use
       coretemp here too. Reads `name` to identify CPU sensors, then walks
       temp*_input files.

    2. /sys/class/thermal/thermal_zone*/  — fallback. Older systems and
       generic ACPI thermal zones. Less reliable on AMD because the only
       zone is often a generic motherboard sensor, not the CPU die itself.

    On Ubuntu 24.04 with a Threadripper, #1 (k10temp) is the right path.
    """
    candidates: list[int] = []

    # ---- Path 1: /sys/class/hwmon/ ----
    try:
        for hw in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
            name_file = hw / "name"
            if not name_file.exists():
                continue
            try:
                name = name_file.read_text().strip().lower()
            except OSError:
                continue
            if not any(hint in name for hint in CPU_HWMON_NAMES):
                continue
            # Read every temp*_input under this hwmon entry
            for temp_file in sorted(hw.glob("temp*_input")):
                try:
                    raw = int(temp_file.read_text().strip())
                except (OSError, ValueError):
                    continue
                if raw > 0:
                    candidates.append(raw // 1000)
    except OSError:
        pass

    if candidates:
        return max(candidates)

    # ---- Path 2: /sys/class/thermal/thermal_zone*/ ----
    try:
        for tz in Path("/sys/class/thermal").glob("thermal_zone*"):
            type_file = tz / "type"
            temp_file = tz / "temp"
            if not (type_file.exists() and temp_file.exists()):
                continue
            try:
                tz_type = type_file.read_text().strip().lower()
            except OSError:
                continue
            if not any(hint in tz_type for hint in CPU_THERMAL_HINTS):
                continue
            try:
                raw = int(temp_file.read_text().strip())
            except (OSError, ValueError):
                continue
            candidates.append(raw // 1000)
    except OSError:
        pass

    return max(candidates) if candidates else None


# /proc/stat snapshot bookkeeping for delta-based CPU utilization
_LAST_CPU_SAMPLE: tuple[float, int] | None = None     # (idle, total)


def get_cpu_util() -> int | None:
    """Return overall CPU utilization percentage, computed as the
    delta between two /proc/stat snapshots taken `refresh` seconds apart.

    Returns None on the first call (no baseline to diff against).
    """
    global _LAST_CPU_SAMPLE
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
    except OSError:
        return None

    fields = line.split()
    if not fields or fields[0] != "cpu":
        return None
    values = [int(v) for v in fields[1:]]
    # /proc/stat order: user nice system idle iowait irq softirq steal guest guest_nice
    idle  = values[3] + (values[4] if len(values) > 4 else 0)   # idle + iowait
    total = sum(values)

    prev = _LAST_CPU_SAMPLE
    _LAST_CPU_SAMPLE = (idle, total)
    if prev is None:
        return None
    d_idle  = idle  - prev[0]
    d_total = total - prev[1]
    if d_total <= 0:
        return None
    util = 100.0 * (1.0 - d_idle / d_total)
    return max(0, min(100, int(round(util))))


def format_keys(n: int) -> str:
    """Compact representation: 1,234,567 → '1.23M'."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def format_eta(minutes: float) -> str:
    if minutes < 1:
        return f"{minutes * 60:.0f} sec"
    if minutes < 60:
        return f"{minutes:.1f} min"
    if minutes < 60 * 24:
        return f"{minutes / 60:.1f} hr"
    return f"{minutes / (60 * 24):.1f} days"


def color(s: str, code: str) -> str:
    """Wrap a string in an ANSI color code, only if stdout is a tty."""
    if not sys.stdout.isatty():
        return s
    return f"\033[{code}m{s}\033[0m"


def render(progress: dict | None,
           gpu_temp: int | None, gpu_util: int | None,
           cpu_temp: int | None, cpu_util: int | None,
           log_path: Path,
           scan_name: str | None = None) -> None:
    """Print the status block in place, overwriting the previous frame."""
    # Clear screen, move cursor to (1, 1). Works in any ANSI-capable terminal.
    sys.stdout.write("\033[2J\033[H")

    if progress is None:
        sys.stdout.write(
            f"eyestat_status — waiting for first [progress] line from\n"
            f"  {log_path}\n\n"
            f"  (the runner has to finish at least one batch before any\n"
            f"  progress line appears — usually 30-60 seconds after launch)\n")
        sys.stdout.flush()
        return

    pct = 100.0 * progress["keys_cur"] / max(progress["keys_tot"], 1)

    # Build colorized status pieces
    eta_str   = format_eta(progress["eta_min"])
    pct_str   = f"{pct:.2f}% complete"
    hits_str  = f"{progress['hits']:,}"
    rate_str  = f"{progress['rate']:,}/s"
    keys_str  = (f"{format_keys(progress['keys_cur'])}/"
                 f"{format_keys(progress['keys_tot'])}")
    shard_str = f"{progress['shard_cur']:,}/{progress['shard_tot']:,}"

    def temp_color(t: int | None, warn: int, hot: int) -> str:
        if t is None:
            return "—"
        if t >= hot:
            return color(f"{t}°C", "1;31")     # bold red
        if t >= warn:
            return color(f"{t}°C", "1;33")     # bold yellow
        return color(f"{t}°C", "1;32")         # bold green

    gpu_temp_s = temp_color(gpu_temp, 75, 83)
    cpu_temp_s = temp_color(cpu_temp, 75, 90)
    gpu_util_s = f"{gpu_util}%" if gpu_util is not None else "—"
    cpu_util_s = f"{cpu_util}%" if cpu_util is not None else "—"

    # The display block, matching the user-specified format
    lines = []
    if scan_name:
        lines.append(color(f"▶ {scan_name}", "1;35"))   # bold magenta header
        lines.append("")
    lines.extend([
        color("ETA:  ", "1;36") + eta_str,
        color("      ", "1;36") + pct_str,
        "",
        color("hits  = ", "1;36") + hits_str,
        color("rate  = ", "1;36") + rate_str,
        "",
        color("shard ", "1;36") + shard_str,
        color("keys  ", "1;36") + keys_str,
        "",
        color("GPU: ", "1;36") + f"{gpu_temp_s}  Util: {gpu_util_s}",
        color("CPU: ", "1;36") + f"{cpu_temp_s}  Util: {cpu_util_s}",
    ])
    # Chi² stats if present
    if progress.get("chi2_rej") is not None:
        lines.append("")
        lines.append(color("chi2: ", "1;36") +
                     f"reject {progress['chi2_rej']:.1f}%   "
                     f"min {progress['chi2_min']:.5f}")

    lines.append("")
    lines.append(color(f"  ↻ refresh every {REFRESH_SEC}s   "
                       f"reading: {log_path.name}   "
                       f"(Ctrl-C to exit)", "2"))   # dim

    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


REFRESH_SEC = 5    # overridden by CLI


def main() -> int:
    global REFRESH_SEC
    parser = argparse.ArgumentParser(
        description="Live status display for an eyestat sweep")
    parser.add_argument("logfile", nargs="?", default="scans/",
                        help="Path to a run.log file OR a directory. "
                             "If a directory, the tool auto-tracks the "
                             "most-recently-modified run.log under it "
                             "(useful for following a queue through "
                             "multiple scans). Default: scans/")
    parser.add_argument("--refresh", type=float, default=5.0,
                        help="Refresh interval in seconds (default: 5)")
    args = parser.parse_args()

    REFRESH_SEC = args.refresh
    log_arg = args.logfile

    # Give the user a friendly message if the default doesn't exist yet —
    # most likely cause: they ran this BEFORE launching any scans.
    log_path_initial = Path(log_arg)
    if not log_path_initial.exists():
        print(f"eyestat_status: nothing to show — path doesn't exist:")
        print(f"    {log_path_initial.resolve()}")
        print()
        if log_arg == "scans/":
            print(f"Have you launched a scan yet? Run something like:")
            print(f"    ./eyestat_queue.py --tier 1     # comprehensive sweep")
            print(f"    # OR for a single sweep:")
            print(f"    ./eyestat_gpu_runner.py --mode ctak_right \\")
            print(f"        --prng park_miller_v0 --output-dir scans/test/ ...")
            print()
            print(f"Then re-run this tool with no arguments and it'll auto-track.")
        else:
            print(f"Usage: ./eyestat_status.py [path-to-scans-dir-or-run.log]")
        return 1

    # Hide cursor for a cleaner display
    if sys.stdout.isatty():
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    try:
        # Prime the CPU-util baseline so the first display has real numbers
        get_cpu_util()
        time.sleep(0.5)

        while True:
            # Re-resolve each tick so the status tracks the queue when it
            # rotates from one scan dir's run.log to the next. If
            # arg is a single file, this is a no-op.
            log_path, scan_name = resolve_logfile(log_arg)

            progress = parse_last_progress(log_path)
            gpu_temp, gpu_util = get_gpu_stats()
            cpu_temp = get_cpu_temp()
            cpu_util = get_cpu_util()
            render(progress, gpu_temp, gpu_util, cpu_temp, cpu_util,
                   log_path, scan_name)
            time.sleep(REFRESH_SEC)

    except KeyboardInterrupt:
        # Clean exit: restore cursor, drop a final line
        if sys.stdout.isatty():
            sys.stdout.write("\033[?25h")        # show cursor again
        sys.stdout.write("\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
