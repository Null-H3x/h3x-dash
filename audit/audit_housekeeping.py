#!/usr/bin/env python3
"""Offline audit — fresh-start artifact purge (--fresh / --fresh-all)."""
import sys
import tempfile
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.housekeeping import purge_run_artifacts, format_summary


def _scaffold():
    """Build a temp artifact tree mimicking a used install."""
    root = Path(tempfile.mkdtemp())
    scans   = root / 'scans';   scans.mkdir()
    reports = root / 'reports'; reports.mkdir()
    loot    = root / 'loot';    loot.mkdir()
    logs    = root / 'logs';    logs.mkdir()
    # scan artifacts (incl. a subdir to test recursive clear)
    (scans / 'host_10.0.0.5.xml').write_text('<nmaprun/>')
    (scans / 'sub').mkdir(); (scans / 'sub' / 'extra.txt').write_text('x')
    (reports / 'report1.html').write_text('<html/>')
    (logs / 'exploit').mkdir(); (logs / 'exploit' / 'run1.json').write_text('{}')
    (loot / 'msf_validation.json').write_text('{"10.0.0.5::mod": {}}')
    (loot / 'credentials.json').write_text('[{"u":"root"}]')
    (loot / 'cve_intel.json').write_text('{"kev": []}')
    return root, scans, reports, loot, logs


# ── 1. Default --fresh clears run state, keeps creds + intel ──────────────────
root, scans, reports, loot, logs = _scaffold()
summary = purge_run_artifacts(scans_dir=scans, reports_dir=reports,
                              loot_dir=loot, log_dir=logs)

cleared_ok = (
    not any(scans.iterdir()) and
    not any(reports.iterdir()) and
    not any(logs.iterdir()) and
    not (loot / 'msf_validation.json').exists()
)
preserved_ok = (
    (loot / 'credentials.json').exists() and
    (loot / 'cve_intel.json').exists()
)
if cleared_ok:
    ok('--fresh clears scans/, reports/, logs/, and loot/msf_validation.json')
else:
    fail('--fresh did not clear all run artifacts')
if preserved_ok:
    ok('--fresh PRESERVES loot/credentials.json + loot/cve_intel.json by default')
else:
    fail('--fresh wrongly deleted creds/intel')

# dirs themselves survive (engines re-use them)
if scans.is_dir() and reports.is_dir() and logs.is_dir():
    ok('--fresh keeps the directories themselves (only contents cleared)')
else:
    fail('--fresh removed directories that should persist')

# ── 2. --fresh-all also wipes creds + intel ───────────────────────────────────
root2, scans2, reports2, loot2, logs2 = _scaffold()
purge_run_artifacts(scans_dir=scans2, reports_dir=reports2, loot_dir=loot2,
                    log_dir=logs2, include_creds=True, include_intel=True)
if not (loot2 / 'credentials.json').exists() and not (loot2 / 'cve_intel.json').exists():
    ok('--fresh-all wipes credentials.json + cve_intel.json')
else:
    fail('--fresh-all did not wipe creds/intel')

# ── 3. Recursive clear (subdirs inside scans/logs) ────────────────────────────
if not (scans / 'sub').exists():
    ok('Nested subdirectories inside artifact dirs are removed recursively')
else:
    fail('Nested subdir survived purge')

# ── 4. Summary reports what happened ──────────────────────────────────────────
if any('msf_validation.json' in r for r in summary['removed']) and \
   any('credentials.json' in k for k in summary['kept']):
    ok('Summary lists removed verdicts + kept creds')
else:
    fail(f'Summary incomplete: {summary}')

text = format_summary(summary)
if 'purging previous-run artifacts' in text and 'removed' in text:
    ok('format_summary renders a readable startup block')
else:
    fail('format_summary output malformed')

# ── 5. Idempotent / safe on already-clean tree ────────────────────────────────
empty = Path(tempfile.mkdtemp())
for sub in ('scans', 'reports', 'loot', 'logs'):
    (empty / sub).mkdir()
s2 = purge_run_artifacts(scans_dir=empty/'scans', reports_dir=empty/'reports',
                         loot_dir=empty/'loot', log_dir=empty/'logs')
if not s2['removed'] and not s2['errors']:
    ok('Purge on an already-clean tree is a safe no-op')
else:
    fail(f'Purge on clean tree not a no-op: {s2}')

# ── 6. Missing dirs handled gracefully ────────────────────────────────────────
gone = Path(tempfile.mkdtemp()) / 'does_not_exist'
s3 = purge_run_artifacts(scans_dir=gone, reports_dir=gone, loot_dir=gone, log_dir=gone)
if not s3['errors']:
    ok('Missing directories handled gracefully (no errors)')
else:
    fail(f'Missing dirs raised errors: {s3}')

# ── 7. h3x-dash.py wiring: flags, early purge, msfrpcd reset, session kill ────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
checks = {
    "'--fresh'":            'parses --fresh flag',
    "'--fresh-all'":        'parses --fresh-all flag',
    'purge_from_config':    'calls the purge at startup',
    'kill_all_sessions':    'kills lingering MSF sessions on fresh start',
    'msf_daemon_stop':      'restarts msfrpcd for a clean session table',
}
missing = [desc for needle, desc in checks.items() if needle not in app_src]
if not missing:
    ok('h3x-dash.py wires --fresh: flags + file purge + msfrpcd reset + session kill')
else:
    fail(f'h3x-dash.py --fresh wiring missing: {missing}')

# purge must run before engines instantiate (empty engines on boot)
purge_idx = app_src.find('purge_from_config')
engine_idx = app_src.find('scan_engine  = NmapEngine()')
if purge_idx != -1 and engine_idx != -1 and purge_idx < engine_idx:
    ok('Fresh purge runs BEFORE engines instantiate (no stale state loaded)')
else:
    fail('Fresh purge not ordered before engine instantiation')

# usage banner documents the flags
if '--fresh' in app_src.split('Usage:')[1].split('"""')[0]:
    ok('Usage banner documents --fresh / --fresh-all')
else:
    fail('Usage banner missing --fresh documentation')

# ── 8. Version present (semver-shaped) ────────────────────────────────────────
import re as _re
from config import H3xConfig
if _re.match(r'^\d+\.\d+\.\d+(\.\d+)?$', H3xConfig.VERSION):
    ok(f'VERSION is version-shaped ({H3xConfig.VERSION})')
else:
    fail(f'VERSION not version-shaped: {H3xConfig.VERSION}')

print()
print('═' * 72)
print(f' HOUSEKEEPING AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
