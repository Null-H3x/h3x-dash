#!/usr/bin/env python3
"""Offline audit — callback path verifier + exploit UI wiring."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.callback_verify import verify_callback

# Reverse payload — LHOST required
rev = verify_callback(
    rhost='10.0.0.50', rport=3632, lhost='', lport=4444,
    payload='cmd/unix/reverse_perl',
)
if not rev['ready'] and any(c['id'] == 'lhost_set' and not c['ok'] for c in rev['checks']):
    ok('reverse mode fails when LHOST missing')
else:
    fail(f'reverse verify should fail without LHOST: {rev}')

rev2 = verify_callback(
    rhost='10.0.0.50', rport=3632, lhost='192.168.56.1', lport=4444,
    payload='cmd/unix/reverse_perl',
)
if rev2.get('is_bind') is False and rev2.get('checks'):
    ok('reverse_perl detected as non-bind payload')
else:
    fail(f'reverse_perl bind detection wrong: {rev2}')

# Bind payload — skips LHOST critical checks
bind = verify_callback(
    rhost='10.0.0.50', rport=3632, lhost='', lport=4444,
    payload='cmd/unix/bind_perl',
)
if bind.get('is_bind') and bind.get('bind_connect_cmd') == 'nc -v 10.0.0.50 4444':
    ok('bind_perl returns connect helper command')
else:
    fail(f'bind verify helper wrong: {bind}')

crit_bind = {c['id'] for c in bind['checks'] if c['id'] in {'lhost_set', 'route', 'lport_free'}}
if not crit_bind:
    ok('bind mode does not require LHOST/route/LPORT-free checks')
else:
    fail(f'bind mode should not critical-check reverse path: {crit_bind}')

# Exploit page anchors
exploit_html = Path('templates/exploit.html').read_text(encoding='utf-8')
anchors = [
    'callback-verify',
    'callback-panel',
    'payload-mode',
    'bind-helper',
    'recent-logs-panel',
    'runCallbackVerify',
    'loadRecentLogs',
]
missing = [a for a in anchors if a not in exploit_html]
if missing:
    fail(f'exploit.html missing UI anchors: {missing}')
else:
    ok('exploit.html wires callback verify, bind mode, and recent logs')

# Flask route registration (source scan)
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
for route in ('/api/network/callback-verify', '/api/ops/logs/exploit'):
    if route in app_src:
        ok(f'h3x-dash.py registers {route}')
    else:
        fail(f'h3x-dash.py missing route {route}')

print()
print('═' * 72)
print(f' CALLBACK AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
