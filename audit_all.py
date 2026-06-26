#!/usr/bin/env python3
"""
audit_all.py — Run every offline paranoia audit in one pass.

Covers internal consistency (audit_*.py) plus validate_chain.py --offline.
Does NOT require msfrpcd. For live MSF catalog verification:

    msfrpcd -P msfrpc -S -f
    python3 validate_chain.py

USAGE
    python3 audit_all.py
    python3 audit_all.py --quick    # skip slow audit_msf_runner.py
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ordered roughly fastest → slowest; msf_runner mocks console polling timers.
AUDITS = [
    'audit_scan.py',
    'audit_classifier.py',
    'audit_chain.py',
    'audit_cve_intel.py',
    'audit_evasion.py',
    'audit_extensions.py',
    'audit_ops_log.py',
    'audit_exploit.py',
    'audit_shell.py',
    'audit_validate.py',
    'audit_enum.py',
    'audit_install.py',
    'audit_msf_runner.py',
]


def _run(script: str) -> tuple[int, str]:
    path = ROOT / script
    if not path.exists():
        return 127, f'missing: {script}'
    proc = subprocess.run(
        [sys.executable, str(path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    out = (proc.stdout or '') + (proc.stderr or '')
    return proc.returncode, out


def _summary_line(output: str) -> str:
    for line in output.splitlines():
        if 'AUDIT' in line and ('FAIL' in line or 'OK' in line):
            return line.strip()
    return '(no summary line)'


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--quick', action='store_true',
                   help='Skip audit_msf_runner.py (~90-120s)')
    args = p.parse_args()

    scripts = [s for s in AUDITS
               if not (args.quick and s == 'audit_msf_runner.py')]

    print('═' * 72)
    print(' H3X-DASH PARANOIA AUDIT — FULL SUITE')
    print('═' * 72)
    print()

    results: list[tuple[str, int, str]] = []
    for script in scripts:
        print(f'[*] {script} ...', flush=True)
        rc, out = _run(script)
        results.append((script, rc, out))
        mark = 'OK' if rc == 0 else 'FAIL'
        print(f'    [{mark}] {_summary_line(out)}')

    print()
    print('[*] validate_chain.py --offline ...', flush=True)
    vc = subprocess.run(
        [sys.executable, 'validate_chain.py', '--offline'],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    vc_mark = 'OK' if vc.returncode == 0 else 'FAIL'
    print(f'    [{vc_mark}] exit={vc.returncode}')

    failed = [name for name, rc, _ in results if rc != 0]
    if vc.returncode != 0:
        failed.append('validate_chain.py --offline')

    print()
    print('═' * 72)
    passed = len(scripts) + (0 if vc.returncode != 0 else 1) - len(failed)
    total  = len(scripts) + 1
    print(f' PARANOIA SUITE — {len(failed)} FAIL · {passed} OK · {total} checks')
    print('═' * 72)

    if failed:
        print('\nFAILED:')
        for name, rc, out in results:
            if rc != 0:
                print(f'\n── {name} (exit {rc}) ──')
                tail = '\n'.join(out.splitlines()[-25:])
                print(tail)
        if vc.returncode != 0:
            print('\n── validate_chain.py --offline ──')
            print((vc.stdout or '') + (vc.stderr or ''))
        return 1

    print('\nAll offline paranoia audits passed.')
    if args.quick:
        print('(audit_msf_runner.py skipped — run without --quick for full coverage)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
