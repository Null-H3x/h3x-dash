#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_recover.py — standalone recovery / aggregation tool.

Walks a eyestat_runner.py output directory and rebuilds whatever results can be
salvaged, regardless of WHY the run failed:

  - Runner killed mid-run (SIGKILL, OOM, power loss, Ctrl-C during merge)
  - Worker crashes that left error_<shard>.txt files
  - Per-key crashes that left failed_keys_<shard>.txt files
  - Disk-full mid-write that truncated a shard file
  - merge_results() never ran (no bruteforce_results.txt was produced)
  - eyestat_runner.py itself broken / can't import

This script has NO dependencies on eyestat_runner, eyestat_kernels, eyestat_prngs, or
eyestat_scoring. Pure stdlib. It will work even if every other module in the
project is broken.

OUTPUTS (in --output-dir by default, or --aggregate-to elsewhere):

  aggregated_results.txt   Merged ranked results across all readable shards,
                           same format as the runner's bruteforce_results.txt.
  recovery_report.txt      Human-readable summary: how many shards complete,
                           how many partial, how many errored, top hits, etc.
  aggregated_report.html   Optional. Only produced if eyestat_html_report.py is
                           importable alongside this script.

USAGE
=====
    # Default: scan ./eyestat_results/, write aggregated outputs into the same dir
    python3 eyestat_recover.py

    # Explicit
    python3 eyestat_recover.py --output-dir results_v1/

    # Recover into a separate directory (leaves source untouched)
    python3 eyestat_recover.py --output-dir results_v1/ --aggregate-to recovered_v1/

    # Also produce the HTML report (requires eyestat_html_report.py on path)
    python3 eyestat_recover.py --output-dir results_v1/ --html

    # Aggressively try to salvage truncated .tmp shards too
    python3 eyestat_recover.py --output-dir results_v1/ --salvage-partial

EXIT CODES
==========
  0   completed cleanly, aggregated file written
  1   completed but with warnings (some shards unreadable / errored)
  2   nothing recoverable (no readable shards found)
"""

from __future__ import annotations

import argparse
import gzip
import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Shard naming + state classification
# ---------------------------------------------------------------------------

# results_<mode>_<prng>_<seed_start_10digit>_<seed_end_10digit>.txt
# params_<mode>_<prng>_<seed_start_10digit>_<seed_end_10digit>.tsv.gz
# .tmp suffix means partial / interrupted
# error_<shard_id>.txt = fatal worker error
# failed_keys_<shard_id>.txt = per-seed errors

# Shard filenames end with `_<10digit>_<10digit>.<ext>[.tmp]`. The mode and
# prng both contain underscores (e.g., `ctak_right`, `park_miller`), so we
# can't naively split on `_`. The seed numbers are the only fixed-width
# anchor; once we strip them, we still need to know where mode ends and
# prng begins. We do that by matching the longest known mode prefix.

# Known mode names — must match eyestat_runner.MODE_REGISTRY. Listed longest-first
# so prefix-match prefers `vigenere_ct_auto` over `vigenere`.
KNOWN_MODES = [
    "vigenere_ct_auto", "vigenere_pt_auto", "vigenere_plain",
    "xgak_diff_right", "xgak_diff_left", "xgak_sum_right", "xgak_sum_left",
    "card_chameleon",
    "ctak_right", "ctak_left", "ptak_right", "ptak_left",
    "kak_right", "kak_left",
    "cfb_mod", "cfb_sub",
    "pontifex", "mirdek", "ofb",
]

SHARD_PREFIX_RE = re.compile(
    r"^(?P<kind>params|results|error|failed_keys)_(?P<rest>.+)$"
)
SHARD_TAIL_RE = re.compile(
    r"^(?P<body>.+)_(?P<seed_start>\d{10})_(?P<seed_end>\d{10})"
    r"(?P<ext>\.txt|\.tsv\.gz)"
    r"(?P<tmp>\.tmp)?$"
)


def parse_shard_filename(name: str) -> Optional[Dict[str, Any]]:
    """Parse a eyestat_runner shard filename into its components.

    Returns dict with keys: kind, mode, prng, seed_start, seed_end, ext, is_tmp.
    Returns None if name doesn't match the shard naming pattern.

    Robust to underscored mode/prng names by anchoring on the fixed-width
    seed numbers at the end and prefix-matching against KNOWN_MODES.
    """
    m1 = SHARD_PREFIX_RE.match(name)
    if not m1:
        return None
    kind = m1.group("kind")
    rest = m1.group("rest")
    m2 = SHARD_TAIL_RE.match(rest)
    if not m2:
        return None
    body = m2.group("body")  # "<mode>_<prng>"
    # Find the longest known mode that prefixes body, followed by `_`
    mode = None
    for candidate in KNOWN_MODES:
        if body == candidate or body.startswith(candidate + "_"):
            mode = candidate
            break
    if mode is None:
        # Fallback: split at the first underscore. Better than nothing.
        if "_" in body:
            mode, prng = body.split("_", 1)
        else:
            return None
    else:
        prng = body[len(mode)+1:] if len(body) > len(mode) else ""
    return {
        "kind": kind,
        "mode": mode,
        "prng": prng or "(unknown)",
        "seed_start": int(m2.group("seed_start")),
        "seed_end": int(m2.group("seed_end")),
        "ext": m2.group("ext"),
        "is_tmp": m2.group("tmp") is not None,
    }


@dataclass
class ShardInventory:
    """Per-shard file presence map."""
    mode: str
    prng: str
    seed_start: int
    seed_end: int
    has_params_final: bool = False
    has_params_tmp: bool = False
    has_results_final: bool = False
    has_results_tmp: bool = False
    has_error: bool = False
    has_failed_keys: bool = False
    error_text: str = ""
    failed_keys_count: int = 0

    @property
    def shard_id(self) -> str:
        return (f"{self.mode}_{self.prng}_"
                f"{self.seed_start:010d}_{self.seed_end:010d}")

    @property
    def state(self) -> str:
        """One of: COMPLETE, PARTIAL, ERRORED, BROKEN, UNKNOWN."""
        if self.has_error:
            return "ERRORED"
        if self.has_params_final and self.has_results_final:
            return "COMPLETE"
        if self.has_params_tmp or self.has_results_tmp:
            return "PARTIAL"
        # Has one final but not both — half-renamed, treated as broken
        if self.has_params_final ^ self.has_results_final:
            return "BROKEN"
        return "UNKNOWN"


def inventory_directory(out_dir: Path) -> Dict[str, ShardInventory]:
    """Walk a directory and classify every shard-related file by shard_id.

    Layout-aware: shards live in <out_dir>/temp/ under the new layout, or
    directly under <out_dir>/ for legacy flat layout. We scan whichever
    location actually contains shard files.
    """
    shards: Dict[str, ShardInventory] = {}

    def get_or_create(mode, prng, ss, se) -> ShardInventory:
        sid = f"{mode}_{prng}_{int(ss):010d}_{int(se):010d}"
        if sid not in shards:
            shards[sid] = ShardInventory(
                mode=mode, prng=prng,
                seed_start=int(ss), seed_end=int(se))
        return shards[sid]

    # Resolve the directory that actually contains shard files
    temp_dir = out_dir / "temp"
    scan_root = temp_dir if temp_dir.is_dir() else out_dir

    for f in sorted(scan_root.iterdir()):
        if not f.is_file():
            continue
        parsed = parse_shard_filename(f.name)
        if parsed is None:
            continue
        inv = get_or_create(parsed["mode"], parsed["prng"],
                             parsed["seed_start"], parsed["seed_end"])
        kind = parsed["kind"]
        is_tmp = parsed["is_tmp"]
        if kind == "params":
            if is_tmp: inv.has_params_tmp = True
            else: inv.has_params_final = True
        elif kind == "results":
            if is_tmp: inv.has_results_tmp = True
            else: inv.has_results_final = True
        elif kind == "error":
            inv.has_error = True
            try:
                inv.error_text = f.read_text(encoding="utf-8",
                                             errors="replace")[:2000]
            except Exception:
                inv.error_text = "(could not read error file)"
        elif kind == "failed_keys":
            inv.has_failed_keys = True
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    inv.failed_keys_count = sum(
                        1 for line in fh
                        if line.strip() and not line.startswith("#"))
            except Exception:
                pass
    return shards


# ---------------------------------------------------------------------------
# Result-file parsing (resilient to truncation)
# ---------------------------------------------------------------------------

# Header:  === mode=ctak_right prng=park_miller key=SEED:842194 max_hits=17 ===
HEADER_RE = re.compile(r"^===\s+.*max_hits=(\d+)\s+===\s*$")


def parse_results_file_safe(path: Path) -> Tuple[List[Tuple[int, str]], int]:
    """Parse a results_<shard>.txt file, returning [(max_hits, raw_block), ...].

    Robust to truncation: any incomplete trailing block (no blank line
    terminator) is dropped. Returns (entries, n_dropped).
    """
    if not path.exists():
        return [], 0
    entries: List[Tuple[int, str]] = []
    n_dropped = 0
    current_lines: List[str] = []
    current_hits: int = -1
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("=== "):
                    # Flush previous block (if it had content)
                    if current_lines:
                        entries.append((current_hits, "".join(current_lines)))
                    current_lines = [line]
                    m = HEADER_RE.match(line.rstrip("\n"))
                    current_hits = int(m.group(1)) if m else 0
                else:
                    current_lines.append(line)
            # Final flush — but only if we saw at least one complete entry's
            # worth of context (header + at least one body line)
            if current_lines:
                if len(current_lines) >= 2:
                    entries.append((current_hits, "".join(current_lines)))
                else:
                    n_dropped += 1
    except OSError as e:
        print(f"  ! could not read {path.name}: {e}", file=sys.stderr)
        return entries, n_dropped
    return entries, n_dropped


def count_params_rows_safe(path: Path) -> Tuple[int, bool]:
    """Count data rows in a params_<shard>.tsv.gz file.

    Returns (n_rows, ok). ok=False if the gzip stream was truncated;
    the partial count is still returned. Header row is not counted.
    """
    if not path.exists():
        return 0, False
    n = 0
    ok = True
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            first = True
            for line in f:
                if first:
                    first = False
                    continue  # skip header
                if line.strip():
                    n += 1
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        ok = False
        print(f"  ! params shard truncated ({path.name}): {e}",
              file=sys.stderr)
    return n, ok


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

@dataclass
class RecoveryStats:
    output_dir: str = ""
    started_at: str = ""
    finished_at: str = ""
    total_shards_seen: int = 0
    shards_complete: int = 0
    shards_partial: int = 0
    shards_errored: int = 0
    shards_broken: int = 0
    shards_unknown: int = 0
    entries_recovered: int = 0
    entries_dropped: int = 0
    keys_tried_total: int = 0
    keys_tried_estimated: bool = False
    failed_keys_total: int = 0
    truncated_params_shards: int = 0
    truncated_results_shards: int = 0
    salvaged_partial_results: int = 0
    modes_seen: List[str] = field(default_factory=list)
    prngs_seen: List[str] = field(default_factory=list)
    top_hits_by_mode: Dict[str, int] = field(default_factory=dict)
    top_entries: List[Tuple[int, str]] = field(default_factory=list)


def aggregate(out_dir: Path, aggregate_to: Path, salvage_partial: bool,
              verbose: bool) -> RecoveryStats:
    """Walk out_dir, salvage what's readable, write aggregated outputs into
    aggregate_to. Returns a RecoveryStats summary."""
    stats = RecoveryStats(
        output_dir=str(out_dir),
        started_at=time.strftime("%Y-%m-%d %H:%M:%S %Z"),
    )

    if not out_dir.is_dir():
        raise FileNotFoundError(f"--output-dir {out_dir} is not a directory")

    if verbose:
        print(f"[recover] scanning {out_dir} ...")
    inv = inventory_directory(out_dir)
    stats.total_shards_seen = len(inv)

    if not inv:
        return stats

    # Tally state buckets
    for sid, sh in inv.items():
        st = sh.state
        if st == "COMPLETE": stats.shards_complete += 1
        elif st == "PARTIAL": stats.shards_partial += 1
        elif st == "ERRORED": stats.shards_errored += 1
        elif st == "BROKEN": stats.shards_broken += 1
        else: stats.shards_unknown += 1

    # Collect unique mode/prng for the summary line
    stats.modes_seen = sorted({sh.mode for sh in inv.values()})
    stats.prngs_seen = sorted({sh.prng for sh in inv.values()})

    aggregate_to.mkdir(parents=True, exist_ok=True)
    if verbose:
        print(f"[recover] {len(inv)} unique shards: "
              f"{stats.shards_complete} complete, "
              f"{stats.shards_partial} partial, "
              f"{stats.shards_errored} errored, "
              f"{stats.shards_broken} broken")

    # ----- Collect entries from COMPLETE shards (the easy path) -----
    all_entries: List[Tuple[int, str]] = []  # (max_hits, raw_block)
    for sid, sh in sorted(inv.items()):
        if sh.state != "COMPLETE":
            continue
        results_path = out_dir / f"results_{sid}.txt"
        entries, dropped = parse_results_file_safe(results_path)
        all_entries.extend(entries)
        stats.entries_dropped += dropped
        # Count keys from the params file
        params_path = out_dir / f"params_{sid}.tsv.gz"
        n_rows, ok = count_params_rows_safe(params_path)
        stats.keys_tried_total += n_rows
        if not ok:
            stats.truncated_params_shards += 1
        # Track top hit per mode
        for mh, _ in entries:
            if mh > stats.top_hits_by_mode.get(sh.mode, 0):
                stats.top_hits_by_mode[sh.mode] = mh

    # ----- Salvage from PARTIAL shards if requested -----
    if salvage_partial:
        if verbose:
            print(f"[recover] attempting to salvage {stats.shards_partial} "
                  f"partial shard(s) ...")
        for sid, sh in sorted(inv.items()):
            if sh.state != "PARTIAL":
                continue
            # Try the .tmp results first, then .tmp params for key count
            tmp_results = out_dir / f"results_{sid}.txt.tmp"
            entries, dropped = parse_results_file_safe(tmp_results)
            if entries:
                all_entries.extend(entries)
                stats.salvaged_partial_results += 1
                if verbose:
                    print(f"  salvaged {len(entries)} entries from "
                          f"{tmp_results.name}")
            stats.entries_dropped += dropped
            tmp_params = out_dir / f"params_{sid}.tsv.gz.tmp"
            n_rows, ok = count_params_rows_safe(tmp_params)
            stats.keys_tried_total += n_rows
            stats.keys_tried_estimated = True
            if not ok:
                stats.truncated_params_shards += 1

    # ----- Count failed keys across all shards -----
    for sh in inv.values():
        stats.failed_keys_total += sh.failed_keys_count

    # ----- Sort + write aggregated results -----
    all_entries.sort(key=lambda e: -e[0])
    stats.entries_recovered = len(all_entries)
    stats.top_entries = all_entries[:25]

    agg_path = aggregate_to / "aggregated_results.txt"
    threshold_note = ("threshold unknown — derived from shard contents, "
                      "may include entries below the run's original threshold")
    with open(agg_path, "w", encoding="utf-8") as f:
        f.write(f"# Aggregated bf results recovered from {out_dir}\n")
        f.write(f"# Recovery run: {stats.started_at}\n")
        f.write(f"# {len(all_entries)} total entries ({threshold_note})\n")
        f.write(f"# Shards: {stats.shards_complete} complete, "
                f"{stats.shards_partial} partial "
                f"({stats.salvaged_partial_results} salvaged), "
                f"{stats.shards_errored} errored, "
                f"{stats.shards_broken} broken\n\n")
        for _, raw in all_entries:
            # Ensure each block ends with exactly one blank line separator
            if not raw.endswith("\n\n"):
                if raw.endswith("\n"):
                    raw = raw + "\n"
                else:
                    raw = raw + "\n\n"
            f.write(raw)
    if verbose:
        print(f"[recover] wrote {agg_path} "
              f"({stats.entries_recovered} entries)")

    # ----- Write recovery report -----
    stats.finished_at = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    rep_path = aggregate_to / "recovery_report.txt"
    write_recovery_report(rep_path, inv, stats)
    if verbose:
        print(f"[recover] wrote {rep_path}")

    return stats


def write_recovery_report(path: Path, inv: Dict[str, ShardInventory],
                          stats: RecoveryStats) -> None:
    """Write a human-readable recovery report."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 72 + "\n")
        f.write("BF RECOVERY REPORT\n")
        f.write("=" * 72 + "\n\n")
        f.write(f"Source directory: {stats.output_dir}\n")
        f.write(f"Recovery started: {stats.started_at}\n")
        f.write(f"Recovery finished: {stats.finished_at}\n\n")

        f.write("[ SHARD INVENTORY ]\n")
        f.write(f"  Total unique shards seen:  {stats.total_shards_seen}\n")
        f.write(f"  COMPLETE (both files present):  {stats.shards_complete}\n")
        f.write(f"  PARTIAL  (.tmp file present):    {stats.shards_partial}\n")
        f.write(f"  ERRORED  (error file present):   {stats.shards_errored}\n")
        f.write(f"  BROKEN   (half-renamed):         {stats.shards_broken}\n")
        f.write(f"  UNKNOWN  (no usable files):      {stats.shards_unknown}\n\n")

        f.write("[ KEYS TRIED ]\n")
        est = " (includes partial-shard estimates)" if stats.keys_tried_estimated else ""
        f.write(f"  Total keys logged in params files: "
                f"{stats.keys_tried_total:,}{est}\n")
        f.write(f"  Keys that errored during scan:    {stats.failed_keys_total:,}\n")
        f.write(f"  Truncated params shards:          {stats.truncated_params_shards}\n\n")

        f.write("[ RESULTS RECOVERY ]\n")
        f.write(f"  Above-threshold entries recovered: {stats.entries_recovered:,}\n")
        f.write(f"  Entries dropped (truncated):       {stats.entries_dropped}\n")
        f.write(f"  Partial shards salvaged:           {stats.salvaged_partial_results}\n\n")

        f.write("[ SCAN COVERAGE ]\n")
        f.write(f"  Modes observed ({len(stats.modes_seen)}): "
                f"{', '.join(stats.modes_seen) or '(none)'}\n")
        f.write(f"  PRNGs observed ({len(stats.prngs_seen)}): "
                f"{', '.join(stats.prngs_seen) or '(none)'}\n\n")

        if stats.top_hits_by_mode:
            f.write("[ TOP HIT PER MODE ]\n")
            for mode, mh in sorted(stats.top_hits_by_mode.items(),
                                    key=lambda kv: -kv[1]):
                f.write(f"  {mode:<22s}  max_hits = {mh}\n")
            f.write("\n")

        if stats.top_entries:
            f.write("[ TOP 25 ENTRIES ]\n")
            for i, (mh, block) in enumerate(stats.top_entries, 1):
                # First line of block is the header
                first = block.split("\n", 1)[0]
                f.write(f"  {i:>3d}. {first}\n")
            f.write("\n")

        # ----- Errored shard details -----
        errored = [sh for sh in inv.values() if sh.state == "ERRORED"]
        if errored:
            f.write("=" * 72 + "\n")
            f.write(f"ERRORED SHARDS  ({len(errored)})\n")
            f.write("=" * 72 + "\n\n")
            for sh in sorted(errored, key=lambda s: s.shard_id):
                f.write(f"--- {sh.shard_id} ---\n")
                # First few lines of the error text
                lines = sh.error_text.splitlines()[:15]
                for ln in lines:
                    f.write(f"  {ln}\n")
                if len(sh.error_text.splitlines()) > 15:
                    f.write(f"  ... ({len(sh.error_text.splitlines()) - 15} "
                            f"more lines in error file)\n")
                f.write("\n")

        # ----- Partial shard list (no full body, just file presence) -----
        partial = [sh for sh in inv.values() if sh.state == "PARTIAL"]
        if partial:
            f.write("=" * 72 + "\n")
            f.write(f"PARTIAL SHARDS  ({len(partial)})\n")
            f.write("=" * 72 + "\n")
            f.write("These had .tmp files (interrupted mid-write). "
                    "Re-run the runner with --resume to retry them.\n\n")
            for sh in sorted(partial, key=lambda s: s.shard_id)[:50]:
                tags = []
                if sh.has_params_tmp: tags.append("params.tmp")
                if sh.has_results_tmp: tags.append("results.tmp")
                f.write(f"  {sh.shard_id}    [{', '.join(tags)}]\n")
            if len(partial) > 50:
                f.write(f"  ... ({len(partial) - 50} more)\n")
            f.write("\n")


# ---------------------------------------------------------------------------
# Optional HTML output (only if eyestat_html_report is on path)
# ---------------------------------------------------------------------------

def maybe_generate_html(aggregated_txt: Path, html_path: Path) -> bool:
    """Try to generate an HTML report. Returns True on success.

    Imports eyestat_html_report at call time so this script remains usable when
    that module is broken or missing.
    """
    try:
        # Local import — keeps the rest of eyestat_recover usable if this fails
        sys.path.insert(0, str(Path(__file__).parent))
        import eyestat_html_report as H  # type: ignore
        entries, metadata = H.parse_results_file(aggregated_txt)
        if not entries:
            print(f"  ! HTML generation skipped: 0 entries to render",
                  file=sys.stderr)
            return False
        doc = H.build_html(entries, metadata)
        html_path.write_text(doc, encoding="utf-8")
        return True
    except ImportError as e:
        print(f"  ! HTML generation skipped: eyestat_html_report.py not "
              f"importable ({e})", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  ! HTML generation failed: {type(e).__name__}: {e}",
              file=sys.stderr)
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output-dir", default="eyestat_results",
                   help="Directory the runner wrote shards into "
                        "(default: ./eyestat_results)")
    p.add_argument("--aggregate-to", default=None,
                   help="Where to write aggregated outputs (default: "
                        "same as --output-dir)")
    p.add_argument("--salvage-partial", action="store_true",
                   help="Also try to read .tmp shards (mid-write interrupts). "
                        "Default: only COMPLETE shards are aggregated.")
    p.add_argument("--html", action="store_true",
                   help="Also generate aggregated_report.html via eyestat_html_report.py")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-step progress prints")
    args = p.parse_args(argv)

    verbose = not args.quiet
    out_dir = Path(args.output_dir)
    agg_to = Path(args.aggregate_to) if args.aggregate_to else out_dir

    if not out_dir.exists():
        print(f"ERROR: --output-dir {out_dir} does not exist", file=sys.stderr)
        return 2
    if not out_dir.is_dir():
        print(f"ERROR: --output-dir {out_dir} is not a directory",
              file=sys.stderr)
        return 2

    print(f"[recover] eyestat_recover starting on {out_dir}")
    try:
        stats = aggregate(out_dir, agg_to, args.salvage_partial, verbose)
    except Exception as e:
        print(f"FATAL: recovery aborted: {type(e).__name__}: {e}",
              file=sys.stderr)
        traceback.print_exc()
        return 2

    # ---- Summary banner ----
    print()
    print("=" * 64)
    print("  RECOVERY SUMMARY")
    print("=" * 64)
    print(f"  shards seen:        {stats.total_shards_seen}")
    print(f"     complete:        {stats.shards_complete}")
    print(f"     partial:         {stats.shards_partial}"
          + (f"  ({stats.salvaged_partial_results} salvaged)"
             if args.salvage_partial else "  (use --salvage-partial to recover)"))
    print(f"     errored:         {stats.shards_errored}")
    print(f"     broken:          {stats.shards_broken}")
    print(f"  keys tried (total): {stats.keys_tried_total:,}"
          + (" *" if stats.keys_tried_estimated else ""))
    print(f"  failed keys:        {stats.failed_keys_total:,}")
    print(f"  truncated params:   {stats.truncated_params_shards}")
    print(f"  entries recovered:  {stats.entries_recovered:,}")
    if stats.top_entries:
        top_mh = stats.top_entries[0][0]
        print(f"  highest max_hits:   {top_mh}")
    print("=" * 64)
    print(f"  aggregated_results.txt:  {agg_to / 'aggregated_results.txt'}")
    print(f"  recovery_report.txt:     {agg_to / 'recovery_report.txt'}")

    # ---- Optional HTML ----
    if args.html:
        html_path = agg_to / "aggregated_report.html"
        if maybe_generate_html(agg_to / "aggregated_results.txt", html_path):
            print(f"  aggregated_report.html:  {html_path}")

    print()

    # ---- Exit code ----
    if stats.entries_recovered == 0 and stats.shards_complete == 0:
        print("[recover] nothing was recovered. The output dir contained no "
              "usable shards.", file=sys.stderr)
        return 2
    if (stats.shards_errored > 0 or stats.shards_broken > 0
            or stats.shards_partial > 0 or stats.failed_keys_total > 0
            or stats.truncated_params_shards > 0):
        print("[recover] completed with warnings — see recovery_report.txt")
        return 1
    print("[recover] completed cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
