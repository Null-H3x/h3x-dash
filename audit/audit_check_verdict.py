#!/usr/bin/env python3
"""Offline audit — CheckCode-aware verdict parsing (real MSF check phrasings)."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.check_verdict import parse_check_verdict

# ── Real-world MSF check console samples (lowercased internally) ──────────────
CASES = [
    # (label, console_text, expected_code, expected_verdict)
    ('EternalBlue vulnerable',
     '[*] 10.0.0.5:445 - Using auxiliary/scanner/smb/smb_ms17_010\n'
     '[+] 10.0.0.5:445 - Host is likely VULNERABLE to MS17-010!\n'
     '[*] Scanned 1 of 1 hosts',
     'VULNERABLE', 'VULNERABLE'),

    ('Explicit target is vulnerable',
     '[+] 10.0.0.5:445 - The target is vulnerable.',
     'VULNERABLE', 'VULNERABLE'),

    ('Appears vulnerable (version match)',
     '[+] 10.0.0.5:6667 - The target appears to be vulnerable.',
     'APPEARS', 'VULNERABLE'),

    ('vsftpd no check method',
     '[*] 10.0.0.5:21 - This module does not support check.',
     'UNSUPPORTED', 'NO_CHECK'),

    ('Samba usermap no check',
     'This module does not support check.',
     'UNSUPPORTED', 'NO_CHECK'),

    ('Detected but not validated',
     '[*] 10.0.0.5:3632 - The service is running, but could not be validated.',
     'DETECTED', 'DETECTED'),

    ('Safe / not exploitable',
     '[-] 10.0.0.5:445 - The target is not exploitable.',
     'SAFE', 'NOT_VULNERABLE'),

    ('Safe / not vulnerable wording',
     '[-] 10.0.0.5:445 - The target is not vulnerable.',
     'SAFE', 'NOT_VULNERABLE'),

    ('Cannot reliably check',
     '[*] 10.0.0.5 - Cannot reliably check exploitability.',
     'UNKNOWN', 'UNKNOWN'),

    ('Connection refused',
     '[-] 10.0.0.5:445 - Connection refused',
     'UNREACHABLE', 'ERROR'),

    ('Empty output',
     '',
     'UNKNOWN', 'UNKNOWN'),
]

for label, text, exp_code, exp_verdict in CASES:
    r = parse_check_verdict(text)
    if r['code'] == exp_code and r['verdict'] == exp_verdict:
        ok(f'{label} → {exp_code}/{exp_verdict}')
    else:
        fail(f'{label}: got {r["code"]}/{r["verdict"]}, expected {exp_code}/{exp_verdict}')

# ── Critical guard: "not vulnerable" must NEVER read as VULNERABLE ────────────
r = parse_check_verdict('[-] The target is not vulnerable.')
if r['verdict'] == 'NOT_VULNERABLE':
    ok('"not vulnerable" never misreads as VULNERABLE (negation guard)')
else:
    fail(f'Negation guard failed: {r}')

# ── "does not support check" never reads as a vuln verdict ────────────────────
r = parse_check_verdict('[*] This module does not support check. vulnerable? n/a')
if r['code'] == 'UNSUPPORTED':
    fail_check = False
    ok('"does not support check" wins over stray "vulnerable" token')
else:
    fail(f'Unsupported precedence failed: {r}')

# ── Engine transport error folds into ERROR ───────────────────────────────────
r = parse_check_verdict('', engine_status='error', engine_message='msfrpcd malformed')
if r['verdict'] == 'ERROR' and 'malformed' in r['detail']:
    ok('engine status=error → ERROR verdict with message preserved')
else:
    fail(f'engine error fold failed: {r}')

# ── Detail carries the real MSF source line where useful ──────────────────────
r = parse_check_verdict('[*] 10.0.0.5:3632 - The service is running, but could not be validated.')
if 'service is running' in r['detail'].lower():
    ok('DETECTED detail surfaces the real MSF source line')
else:
    fail(f'DETECTED detail missing source line: {r}')

# ── Engine integration: run_exploit returns check_code in check mode ──────────
import inspect
from modules.msf_engine import MsfEngine
src = inspect.getsource(MsfEngine._run_exploit_inner)
if 'parse_check_verdict' in src and "'check_code'" in src:
    ok('msf_engine wires parse_check_verdict + returns check_code')
else:
    fail('msf_engine does not wire the CheckCode parser')

# ── Validator maps check_code → verdict (incl. NO_CHECK, DETECTED) ────────────
from modules.msf_validator import (MsfValidator, VULNERABLE, NOT_VULNERABLE,
                                    DETECTED, NO_CHECK, UNKNOWN, ERROR)
M = MsfValidator._verdict_from_result
checks = [
    ({'status': 'launched', 'check_code': 'VULNERABLE'}, VULNERABLE),
    ({'status': 'launched', 'check_code': 'APPEARS'},     VULNERABLE),
    ({'status': 'launched', 'check_code': 'DETECTED'},    DETECTED),
    ({'status': 'launched', 'check_code': 'UNSUPPORTED'}, NO_CHECK),
    ({'status': 'launched', 'check_code': 'SAFE'},        NOT_VULNERABLE),
    ({'status': 'launched', 'check_code': 'UNREACHABLE'}, ERROR),
    ({'status': 'launched', 'check_code': 'UNKNOWN'},     UNKNOWN),
    # legacy fallback (no check_code)
    ({'status': 'launched', 'check_vulnerable': True},    VULNERABLE),
    ({'status': 'launched', 'check_safe': True},          NOT_VULNERABLE),
    ({'status': 'error', 'message': 'boom'},              ERROR),
]
bad = [(c, M(c)['verdict'], exp) for c, exp in checks if M(c)['verdict'] != exp]
if not bad:
    ok('validator maps every check_code (and legacy flags) to correct verdict')
else:
    fail(f'validator verdict mapping wrong: {bad}')

# ── UI renders the new verdicts ───────────────────────────────────────────────
val_html = Path('templates/validate.html').read_text(encoding='utf-8')
if 'NO_CHECK' in val_html and 'DETECTED' in val_html:
    ok('validate.html renders DETECTED + NO_CHECK verdict styles')
else:
    fail('validate.html missing new verdict styles')

exploit_html = Path('templates/exploit.html').read_text(encoding='utf-8')
if 'NO_CHECK' in exploit_html and 'DETECTED' in exploit_html:
    ok('exploit.html badge map includes DETECTED + NO_CHECK')
else:
    fail('exploit.html badge map missing new verdicts')

print()
print('═' * 72)
print(f' CHECK-VERDICT AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
