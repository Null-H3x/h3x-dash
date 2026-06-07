#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_migrate.py — rename eyestat_* → eyestat_* throughout the project.

USAGE
=====
    cd ~/Desktop/Noita/bf_project
    python3 eyestat_migrate.py --dry-run     # preview only
    python3 eyestat_migrate.py               # actually apply

WHAT THIS DOES
==============
Phase 1: rename 12 eyestat_*.py files to eyestat_*.py
    eyestat_runner.py          → eyestat_runner.py
    eyestat_gpu.py             → eyestat_gpu.py
    eyestat_gpu_runner.py      → eyestat_gpu_runner.py
    eyestat_gpu_probe.py       → eyestat_gpu_probe.py
    eyestat_gpu_validate.py    → eyestat_gpu_validate.py
    eyestat_html_report.py     → eyestat_html_report.py
    eyestat_kernels.py         → eyestat_kernels.py
    eyestat_preflight.py       → eyestat_preflight.py
    eyestat_prngs.py           → eyestat_prngs.py
    eyestat_recover.py         → eyestat_recover.py
    eyestat_scoring.py         → eyestat_scoring.py
    eyestat_selftest.py        → eyestat_selftest.py

Phase 2: update internal references in all .py, .md, .sh files
    - import statements:           import eyestat_kernels → import eyestat_kernels
    - module attribute access:     eyestat_runner.score_X → eyestat_runner.score_X
    - CLI usage in docstrings:     python3 eyestat_gpu_runner.py → python3 eyestat_gpu_runner.py
    - HTML banner strings:         "EyeStat Results Viewer" → "EyeStat Results Viewer"
                                   "EYESTAT // RESULTS VIEWER" → "EYESTAT // RESULTS VIEWER"
    - Log/print tag prefixes:      [eyestat_html_report] → [eyestat_html_report]

Phase 3: compile-check every renamed Python file to catch syntax errors

WHAT THIS DOES NOT TOUCH
========================
  - data files (.txt, .json, .gz, results/, test_results/, agg/, anything under .git/)
  - shard filenames produced by ShardWriter — those use mode_prng_seedstart_seedend,
    no bf_ prefix, so no compatibility issue. Existing completed shards remain valid.
  - prose-level "brute force" mentions in docstrings — those describe the search
    method (which is still exhaustive enumeration), not the tool name. If you want
    those rewritten too, that's a separate prose pass.

SAFETY
======
  - Uses `git mv` if a .git directory is detected, preserving git history.
  - --dry-run shows exactly what would change without touching anything.
  - Word-boundary regex (\\b) — won't accidentally rewrite unrelated identifiers
    containing 'bf_' as a substring (none exist in the codebase, but defensive).
  - Idempotent — running twice is a no-op the second time.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------- #

FILE_RENAMES = {
    "eyestat_runner.py":         "eyestat_runner.py",
    "eyestat_gpu.py":            "eyestat_gpu.py",
    "eyestat_gpu_probe.py":      "eyestat_gpu_probe.py",
    "eyestat_gpu_runner.py":     "eyestat_gpu_runner.py",
    "eyestat_gpu_validate.py":   "eyestat_gpu_validate.py",
    "eyestat_html_report.py":    "eyestat_html_report.py",
    "eyestat_kernels.py":        "eyestat_kernels.py",
    "eyestat_preflight.py":      "eyestat_preflight.py",
    "eyestat_prngs.py":          "eyestat_prngs.py",
    "eyestat_recover.py":        "eyestat_recover.py",
    "eyestat_scoring.py":        "eyestat_scoring.py",
    "eyestat_selftest.py":       "eyestat_selftest.py",
}

# Module-name substitutions. Word-boundary protected so we don't accidentally
# rewrite anything that happens to contain 'eyestat_runner' as a substring.
# Order: most-specific first (eyestat_gpu_runner before eyestat_gpu) is fine because
# word boundaries make these non-overlapping, but listing them this way
# makes the intent obvious to anyone reading.
MODULE_SUBS = [
    (r"\bbf_gpu_runner\b",   "eyestat_gpu_runner"),
    (r"\bbf_gpu_probe\b",    "eyestat_gpu_probe"),
    (r"\bbf_gpu_validate\b", "eyestat_gpu_validate"),
    (r"\bbf_gpu\b",          "eyestat_gpu"),
    (r"\bbf_html_report\b",  "eyestat_html_report"),
    (r"\bbf_kernels\b",      "eyestat_kernels"),
    (r"\bbf_preflight\b",    "eyestat_preflight"),
    (r"\bbf_prngs\b",        "eyestat_prngs"),
    (r"\bbf_recover\b",      "eyestat_recover"),
    (r"\bbf_runner\b",       "eyestat_runner"),
    (r"\bbf_scoring\b",      "eyestat_scoring"),
    (r"\bbf_selftest\b",     "eyestat_selftest"),
]

# Display-string substitutions — header text in the HTML report
DISPLAY_SUBS = [
    (r"EyeStat Results Viewer",    "EyeStat Results Viewer"),
    (r"EYESTAT // RESULTS VIEWER", "EYESTAT // RESULTS VIEWER"),
]

# Other identifier substitutions:
#   - eyestat_results: output-dir defaults + downloaded CSV filename
#   - eyestat_*       : docstring references to "the eyestat_* modules"
# Note: deliberately NOT touching `bf_project` (the user's filesystem directory
# name — user's choice to rename) or `bf_min` (a local variable in the Hungarian
# selftest where 'bf' stands for the algorithm-sense 'brute force' used as a
# ground-truth comparison).
OTHER_SUBS = [
    (r"\bbf_results_filtered\b", "eyestat_results_filtered"),
    (r"\bbf_results\b",          "eyestat_results"),
    (r"\bbf_\*",                 "eyestat_*"),
]

ALL_SUBS = [(re.compile(p), r) for p, r in MODULE_SUBS + DISPLAY_SUBS + OTHER_SUBS]

# Only process these extensions for text rewrites. Data files (.txt, .json,
# .gz, .csv) and binary files stay untouched, even if they happen to live in
# the project tree.
PROCESS_EXTS = {".py", ".md", ".sh"}

# Don't descend into these directories — they're either VCS, build artifacts,
# Python caches, virtual envs, or run-output directories that may contain
# user data we don't want to touch.
SKIP_DIR_NAMES = {".git", "__pycache__", ".venv", "venv", "node_modules"}
# Directory NAME prefixes to skip (matches anything starting with these)
SKIP_DIR_PREFIXES = ("results_", "test_results", "agg_", "agg", "shard_")


# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #

def _is_skip_dir(p: Path) -> bool:
    name = p.name
    if name in SKIP_DIR_NAMES:
        return True
    for pre in SKIP_DIR_PREFIXES:
        if name.startswith(pre):
            return True
    return False


def _walk_files(root: Path):
    """Yield processable files, skipping the directories listed above."""
    for child in sorted(root.iterdir()):
        if child.is_dir():
            if _is_skip_dir(child):
                continue
            yield from _walk_files(child)
        elif child.is_file() and child.suffix in PROCESS_EXTS:
            yield child


def _git_available(root: Path) -> bool:
    if not (root / ".git").is_dir():
        return False
    try:
        subprocess.run(["git", "--version"], cwd=root,
                       capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _rename(old: Path, new: Path, use_git: bool, dry: bool) -> None:
    if dry:
        return
    if use_git:
        subprocess.run(["git", "mv", str(old), str(new)],
                       cwd=old.parent, check=True)
    else:
        old.rename(new)


# --------------------------------------------------------------------- #
# Phase implementations
# --------------------------------------------------------------------- #

def phase_rename(root: Path, use_git: bool, dry: bool) -> int:
    """Rename eyestat_*.py → eyestat_*.py. Returns count of files renamed."""
    print("--- Phase 1: file renames ---")
    n = 0
    for old_name, new_name in FILE_RENAMES.items():
        old_p = root / old_name
        new_p = root / new_name
        if new_p.exists():
            print(f"  skip:    {new_name} already exists")
            continue
        if not old_p.exists():
            print(f"  missing: {old_name} (not in project)")
            continue
        print(f"  rename:  {old_name:25s} → {new_name}")
        _rename(old_p, new_p, use_git, dry)
        n += 1
    print(f"  ({n} renamed)\n")
    return n


def phase_textsubs(root: Path, dry: bool) -> tuple[int, int]:
    """Apply text substitutions. Returns (files_modified, total_subs)."""
    print("--- Phase 2: text substitutions ---")
    files_modified = 0
    total_subs = 0
    for fp in _walk_files(root):
        try:
            src = fp.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        new_src = src
        file_subs = 0
        for pat, rep in ALL_SUBS:
            new_src, n = pat.subn(rep, new_src)
            file_subs += n
        if file_subs == 0:
            continue
        print(f"  {fp.relative_to(root)}: {file_subs} subs")
        if not dry:
            fp.write_text(new_src, encoding="utf-8")
        files_modified += 1
        total_subs += file_subs
    print(f"  ({files_modified} files, {total_subs} total substitutions)\n")
    return files_modified, total_subs


def phase_verify(root: Path) -> int:
    """py_compile every renamed Python file. Returns number of failures."""
    print("--- Phase 3: syntax verification ---")
    failures = 0
    for new_name in FILE_RENAMES.values():
        target = root / new_name
        if not target.exists():
            continue
        r = subprocess.run([sys.executable, "-m", "py_compile", str(target)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"  OK   {new_name}")
        else:
            print(f"  FAIL {new_name}: {r.stderr.strip()}")
            failures += 1
    print(f"  ({failures} failures)\n")
    return failures


# --------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="Preview without modifying anything.")
    ap.add_argument("--no-git", action="store_true",
                    help="Use plain os.rename even if .git is present.")
    ap.add_argument("--root", default=".",
                    help="Project root (default: current directory).")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"ERROR: {root} is not a directory", file=sys.stderr)
        return 2

    use_git = (not args.no_git) and _git_available(root)

    print("=" * 60)
    print("EyeStat migration")
    print("=" * 60)
    print(f"Root: {root}")
    print(f"Mode: {'DRY-RUN (no changes)' if args.dry_run else 'APPLYING'}")
    print(f"VCS:  {'git mv' if use_git else 'plain rename'}")
    print()

    n_renamed = phase_rename(root, use_git, args.dry_run)
    n_files, n_subs = phase_textsubs(root, args.dry_run)

    if args.dry_run:
        print("=" * 60)
        print(f"Dry-run summary: would rename {n_renamed} files and "
              f"make {n_subs} text substitutions across {n_files} files.")
        print("Re-run without --dry-run to apply.")
        print("=" * 60)
        return 0

    failures = phase_verify(root)

    print("=" * 60)
    if failures == 0:
        print(f"DONE — renamed {n_renamed} files, "
              f"applied {n_subs} substitutions across {n_files} files.")
        print("All renamed Python files compile cleanly.")
        if use_git:
            print("\nNext steps:")
            print("  git status            # review the diff")
            print("  git diff --stat       # summary")
            print("  git commit -m 'Rename eyestat_* modules to eyestat_*'")
    else:
        print(f"PARTIAL — {failures} renamed files failed py_compile.")
        print("Review the FAIL lines above and fix manually.")
    print("=" * 60)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
