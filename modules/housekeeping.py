"""
housekeeping.py — Fresh-start artifact purge.

Across the rapid download → extract → run loop, stale state from previous runs
bleeds into a new session in two ways:

  1. Persisted files — scan results (scans/), ops logs (logs/), generated
     reports (reports/), and especially the MSF validation verdicts
     (loot/msf_validation.json) that the Validate/Exploit tabs render.
  2. msfrpcd sessions/jobs — if msfrpcd survives an h3x-dash restart, old
     sessions keep showing in the Shell panel.

purge_run_artifacts() handles (1). The h3x-dash.py --fresh flow calls it at
startup (before the engines load, so they come up empty) and separately resets
msfrpcd / kills lingering sessions for (2).

By default the purge clears run artifacts but PRESERVES earned loot
(credentials.json) and the CVE-intel cache (cve_intel.json) — re-downloading
intel is wasteful and captured creds are results, not noise. --fresh-all
(include_creds + include_intel) wipes those too for a total clean slate.

Pure filesystem logic — fully unit-testable (audit_housekeeping.py).
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

# Loot files that are run state (safe to drop on --fresh) vs. earned results.
_VALIDATION_FILE = 'msf_validation.json'   # always cleared on --fresh
_CREDS_FILE      = 'credentials.json'      # kept unless include_creds
_INTEL_FILE      = 'cve_intel.json'        # kept unless include_intel (it's a cache)


def _clear_dir_contents(d: Path, errors: list[str]) -> int:
    """Delete everything *inside* d, keeping d itself. Returns items removed."""
    if not d or not d.is_dir():
        return 0
    removed = 0
    for child in d.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
            removed += 1
        except OSError as exc:
            errors.append(f'{child}: {exc}')
    return removed


def purge_run_artifacts(*,
                        scans_dir: Path,
                        reports_dir: Path,
                        loot_dir: Path,
                        log_dir: Path,
                        include_creds: bool = False,
                        include_intel: bool = False) -> dict[str, Any]:
    """
    Clear previous-run artifacts. Returns a summary:
      {removed: [...], kept: [...], errors: [...]}

    - scans/, reports/, logs/   → contents cleared (dirs kept)
    - loot/msf_validation.json  → removed (stale verdicts)
    - loot/credentials.json     → removed only if include_creds
    - loot/cve_intel.json       → removed only if include_intel
    """
    removed: list[str] = []
    kept:    list[str] = []
    errors:  list[str] = []

    for label, d in (('scans', scans_dir),
                     ('reports', reports_dir),
                     ('logs', log_dir)):
        if d and Path(d).is_dir():
            n = _clear_dir_contents(Path(d), errors)
            if n:
                removed.append(f'{label}/ ({n} item{"s" if n != 1 else ""})')

    loot = Path(loot_dir) if loot_dir else None
    if loot and loot.is_dir():
        val = loot / _VALIDATION_FILE
        if val.exists():
            try:
                val.unlink()
                removed.append(f'loot/{_VALIDATION_FILE} (validation verdicts)')
            except OSError as exc:
                errors.append(f'{val}: {exc}')

        creds = loot / _CREDS_FILE
        if creds.exists():
            if include_creds:
                try:
                    creds.unlink()
                    removed.append(f'loot/{_CREDS_FILE}')
                except OSError as exc:
                    errors.append(f'{creds}: {exc}')
            else:
                kept.append(f'loot/{_CREDS_FILE} (use --fresh-all to wipe)')

        intel = loot / _INTEL_FILE
        if intel.exists():
            if include_intel:
                try:
                    intel.unlink()
                    removed.append(f'loot/{_INTEL_FILE}')
                except OSError as exc:
                    errors.append(f'{intel}: {exc}')
            else:
                kept.append(f'loot/{_INTEL_FILE} (cache — use --fresh-all to wipe)')

    return {'removed': removed, 'kept': kept, 'errors': errors}


def purge_from_config(config, *, include_creds: bool = False,
                      include_intel: bool = False) -> dict[str, Any]:
    """Convenience wrapper that pulls the standard dirs off H3xConfig."""
    return purge_run_artifacts(
        scans_dir   = config.NMAP_DIR,
        reports_dir = config.REPORT_DIR,
        loot_dir    = config.LOOT_DIR,
        log_dir     = config.LOG_DIR,
        include_creds = include_creds,
        include_intel = include_intel,
    )


def format_summary(summary: dict[str, Any]) -> str:
    """Human-readable one-block summary for the startup log."""
    lines = ['[H3x-Dash] --fresh: purging previous-run artifacts']
    for r in summary.get('removed', []):
        lines.append(f'    removed  {r}')
    for k in summary.get('kept', []):
        lines.append(f'    kept     {k}')
    for e in summary.get('errors', []):
        lines.append(f'    ERROR    {e}')
    if not summary.get('removed'):
        lines.append('    (nothing to remove — already clean)')
    return '\n'.join(lines)
