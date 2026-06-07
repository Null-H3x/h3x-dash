#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_migrate_scans.py — move flat-layout scan directories to the new
temp/ + results/ subdirectory structure.

Before (flat layout):
    results_pm_v0_ctak_right_filtered/
    ├── params_ctak_right_park_miller_v0_0000000000_0001000000.tsv.gz
    ├── params_ctak_right_park_miller_v0_0001000000_0002000000.tsv.gz
    ├── ...
    ├── results_ctak_right_park_miller_v0_0000000000_0001000000.txt
    ├── ...
    └── run.log

After (new layout):
    results_pm_v0_ctak_right_filtered/
    ├── temp/
    │   ├── params_*.tsv.gz       (moved)
    │   ├── results_*.txt          (moved)
    │   └── *.tmp                  (if any)
    ├── results/                   (created empty, ready for HTML + merge)
    └── run.log                    (left in place at root)

The script is idempotent — running it on an already-migrated directory is
a no-op. It uses os.replace() (atomic rename) for the moves; aborts on any
unexpected condition without partial-state damage.

Usage:
    ./eyestat_migrate_scans.py results_pm_v0_ctak_right_filtered/ \\
                               results_pm_v1_ctak_right_filtered/

    # Or migrate every flat-layout scan under a parent dir at once:
    ./eyestat_migrate_scans.py --auto ~/Desktop/Noita/eyestat/

    # Dry-run (preview only, no file moves):
    ./eyestat_migrate_scans.py --dry-run results_pm_v0_ctak_right_filtered/
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Shard files we know how to relocate. The runner emits exactly these prefixes.
SHARD_PATTERNS = (
    re.compile(r"^params_.+\.tsv\.gz(?:\.tmp)?$"),
    re.compile(r"^results_.+\.txt(?:\.tmp)?$"),
    re.compile(r"^error_.+\.txt$"),
    re.compile(r"^failed_keys_.+\.txt$"),
)


def is_shard_file(name: str) -> bool:
    return any(p.match(name) for p in SHARD_PATTERNS)


def already_migrated(scan_dir: Path) -> bool:
    """A scan dir is 'migrated' if temp/ exists AND no shard files sit at the root."""
    temp = scan_dir / "temp"
    if not temp.is_dir():
        return False
    stragglers = [f for f in scan_dir.iterdir()
                  if f.is_file() and is_shard_file(f.name)]
    return not stragglers


def looks_like_scan_dir(p: Path) -> bool:
    """Heuristic: directory is a scan dir if it contains shard files
    directly (flat layout) OR a temp/ subdir with shard files (new layout)."""
    if not p.is_dir():
        return False
    for f in p.iterdir():
        if f.is_file() and is_shard_file(f.name):
            return True
    temp = p / "temp"
    if temp.is_dir():
        for f in temp.iterdir():
            if f.is_file() and is_shard_file(f.name):
                return True
    return False


def migrate(scan_dir: Path, dry_run: bool = False) -> tuple[int, int]:
    """Migrate one scan directory. Returns (files_moved, files_skipped)."""
    scan_dir = scan_dir.resolve()
    if not scan_dir.is_dir():
        print(f"  ! skipping {scan_dir}: not a directory")
        return 0, 0

    if already_migrated(scan_dir):
        print(f"  · {scan_dir.name}: already migrated, nothing to do")
        return 0, 0

    temp_dir    = scan_dir / "temp"
    results_dir = scan_dir / "results"

    # Collect shard files at the root
    shard_files = [f for f in scan_dir.iterdir()
                   if f.is_file() and is_shard_file(f.name)]

    if not shard_files:
        print(f"  · {scan_dir.name}: no shard files found, skipping")
        return 0, 0

    print(f"  → {scan_dir.name}: migrating {len(shard_files):,} shard files")

    if dry_run:
        for f in shard_files[:5]:
            print(f"      would move: {f.name}  →  temp/{f.name}")
        if len(shard_files) > 5:
            print(f"      ... and {len(shard_files) - 5:,} more")
        return 0, len(shard_files)

    # Create the new layout subdirs
    temp_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    moved = 0
    skipped = 0
    for f in shard_files:
        dest = temp_dir / f.name
        if dest.exists():
            print(f"      ! conflict, leaving in place: {f.name}")
            skipped += 1
            continue
        try:
            os.replace(str(f), str(dest))
            moved += 1
        except OSError as e:
            print(f"      ! move failed for {f.name}: {e}")
            skipped += 1

    print(f"      moved {moved:,}, skipped {skipped:,}")
    return moved, skipped


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*",
                   help="One or more scan directories to migrate.")
    p.add_argument("--auto", metavar="PARENT_DIR",
                   help="Scan PARENT_DIR for any subdirectory that looks "
                        "like a scan dir and migrate it.")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen without moving any files.")
    args = p.parse_args()

    targets: list[Path] = []
    if args.auto:
        parent = Path(args.auto).resolve()
        if not parent.is_dir():
            print(f"! --auto target not a directory: {parent}", file=sys.stderr)
            return 1
        for child in sorted(parent.iterdir()):
            if looks_like_scan_dir(child):
                targets.append(child)
        if not targets:
            print(f"! no scan dirs found under {parent}")
            return 0
        print(f"[auto] found {len(targets)} scan directory(ies) under {parent}:")
        for t in targets:
            print(f"  · {t.name}")
        print()

    targets.extend(Path(p).resolve() for p in args.paths)
    if not targets:
        p.print_help()
        return 1

    if args.dry_run:
        print("[dry-run mode — no files will be moved]\n")

    total_moved = 0
    total_skipped = 0
    for t in targets:
        m, s = migrate(t, dry_run=args.dry_run)
        total_moved += m
        total_skipped += s

    print()
    print(f"[done] migrated {total_moved:,} files across {len(targets)} dir(s)"
          f"{', skipped ' + format(total_skipped, ',') if total_skipped else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
