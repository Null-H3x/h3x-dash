#!/usr/bin/env python3
"""Offline audit — profile-driven shell handoff resolution + wiring."""
import inspect
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.handoff import (
    resolve_profile, confirm_output_is_alive, HANDOFF_PROFILES,
)

# ── 1. Profile catalog integrity ──────────────────────────────────────────────
REQUIRED_KEYS = {'id', 'label', 'session_expected', 'confirm_cmds',
                 'harden_cmds', 'recon_cmds', 'background', 'auto_harden',
                 'notes'}
for pid, prof in HANDOFF_PROFILES.items():
    missing = REQUIRED_KEYS - set(prof)
    if missing:
        fail(f'profile {pid} missing keys: {missing}')
    if prof.get('id') != pid:
        fail(f'profile {pid} id mismatch: {prof.get("id")}')
if not FAIL:
    ok(f'All {len(HANDOFF_PROFILES)} handoff profiles have required keys')

# ── 2. distcc reverse cmd shell → linux_cmd_reverse, no migrate ───────────────
p = resolve_profile('exploit/unix/misc/distcc_exec',
                    'cmd/unix/reverse_perl', 'shell')
if p['id'] == 'linux_cmd_reverse' and not any('migrate' in c for c in p['harden_cmds']):
    ok('distcc reverse cmd shell → linux_cmd_reverse (no migrate)')
else:
    fail(f'distcc resolution wrong: {p["id"]}, harden={p["harden_cmds"]}')

# ── 3. vsftpd interact backdoor → linux_cmd_interact ──────────────────────────
p = resolve_profile('exploit/unix/ftp/vsftpd_234_backdoor',
                    'cmd/unix/interact', 'shell')
if p['id'] == 'linux_cmd_interact':
    ok('vsftpd interact backdoor → linux_cmd_interact')
else:
    fail(f'vsftpd resolution wrong: {p["id"]}')

# vsftpd recognized even before session type known (payload=interact, stype empty)
p = resolve_profile('exploit/unix/ftp/vsftpd_234_backdoor',
                    'cmd/unix/interact', '')
if p['id'] == 'linux_cmd_interact':
    ok('vsftpd interact resolves even with unknown session type')
else:
    fail(f'vsftpd early resolution wrong: {p["id"]}')

# ── 4. bind payload → linux_cmd_bind ──────────────────────────────────────────
p = resolve_profile('exploit/unix/misc/distcc_exec',
                    'cmd/unix/bind_perl', 'shell')
if p['id'] == 'linux_cmd_bind':
    ok('bind cmd payload → linux_cmd_bind')
else:
    fail(f'bind resolution wrong: {p["id"]}')

# ── 5. ghostcat auxiliary → no_session ────────────────────────────────────────
p = resolve_profile('auxiliary/admin/http/tomcat_ghostcat', None, '')
if p['id'] == 'no_session' and p['session_expected'] is False:
    ok('tomcat_ghostcat (auxiliary) → no_session, session_expected=False')
else:
    fail(f'ghostcat resolution wrong: {p["id"]}, expected={p["session_expected"]}')

# module_type=auxiliary also forces no_session even with odd module name
p = resolve_profile('exploit/multi/handler', None, 'meterpreter',
                    module_type='auxiliary')
if p['id'] == 'no_session':
    ok('module_type=auxiliary forces no_session regardless of session type')
else:
    fail(f'module_type aux override failed: {p["id"]}')

# ── 6. EternalBlue meterpreter → fragile profile w/ migrate+background ─────────
p = resolve_profile('exploit/windows/smb/ms17_010_eternalblue',
                    'windows/x64/meterpreter/reverse_tcp', 'meterpreter')
if (p['id'] == 'windows_meterpreter_fragile'
        and any('migrate' in c for c in p['harden_cmds'])
        and 'background' in p['harden_cmds']
        and p['skip_migrate_if_launch_migrated'] is True):
    ok('EternalBlue meterpreter → fragile profile (migrate+background, skip-aware)')
else:
    fail(f'EternalBlue resolution wrong: {p}')

# ── 7. Generic meterpreter (non-fragile) → windows_meterpreter ────────────────
p = resolve_profile('exploit/multi/misc/java_rmi_server',
                    'java/meterpreter/reverse_tcp', 'meterpreter')
if p['id'] == 'windows_meterpreter' and 'background' in p['harden_cmds']:
    ok('Non-fragile meterpreter → windows_meterpreter (background only)')
else:
    fail(f'Generic meterpreter resolution wrong: {p["id"]}')

# ── 8. PowerShell session → windows_powershell, no migrate ────────────────────
p = resolve_profile('exploit/windows/http/whatever', None, 'powershell')
if p['id'] == 'windows_powershell' and not p['harden_cmds']:
    ok('PowerShell session → windows_powershell (no migrate)')
else:
    fail(f'PowerShell resolution wrong: {p["id"]}')

# ── 9. Unknown → generic fallback ─────────────────────────────────────────────
p = resolve_profile(None, None, None)
if p['id'] == 'generic':
    ok('Unknown module/payload/type → generic fallback')
else:
    fail(f'Fallback wrong: {p["id"]}')

# resolved_from annotation present
if 'resolved_from' in p and set(p['resolved_from']) == {'module', 'payload', 'session_type'}:
    ok('resolve_profile annotates resolved_from for UI explainability')
else:
    fail('resolve_profile missing resolved_from annotation')

# ── 10. confirm_output_is_alive logic ─────────────────────────────────────────
rev = resolve_profile('exploit/unix/misc/distcc_exec', 'cmd/unix/reverse_perl', 'shell')
if confirm_output_is_alive(rev, 'uid=0(root) gid=0(root)'):
    ok('confirm_output_is_alive: real id output → alive')
else:
    fail('confirm_output_is_alive rejected valid id output')

if not confirm_output_is_alive(rev, ''):
    ok('confirm_output_is_alive: empty output → not alive')
else:
    fail('confirm_output_is_alive accepted empty output')

if not confirm_output_is_alive(rev, 'Session ID (3) does not exist'):
    ok('confirm_output_is_alive: dead-session signal → not alive')
else:
    fail('confirm_output_is_alive accepted dead-session signal')

gen = resolve_profile(None, None, None)
if confirm_output_is_alive(gen, 'H3X_HANDOFF_OK') and not confirm_output_is_alive(gen, 'random'):
    ok('generic profile requires echo sentinel to confirm liveness')
else:
    fail('generic sentinel confirmation logic wrong')

# ── 11. Resolution priority — aux beats meterpreter ───────────────────────────
p = resolve_profile('auxiliary/scanner/smb/smb_ms17_010', None, 'meterpreter')
if p['id'] == 'no_session':
    ok('Auxiliary module beats meterpreter session type in priority')
else:
    fail(f'Priority wrong — aux should win: {p["id"]}')

# ── 12. MsfEngine wiring ──────────────────────────────────────────────────────
from modules.msf_engine import MsfEngine
for meth in ('resolve_session_handoff', 'confirm_session'):
    if hasattr(MsfEngine, meth):
        ok(f'MsfEngine.{meth}() present')
    else:
        fail(f'MsfEngine missing {meth}()')

# origin records payload now
src = inspect.getsource(MsfEngine._remember_session_origin)
if "'payload'" in src:
    ok('_remember_session_origin records payload for later handoff resolution')
else:
    fail('_remember_session_origin does not record payload')

# ── 13. API routes + frontend wiring ──────────────────────────────────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
for route in ('/api/msf/session/<sid>/handoff', '/api/msf/session/<sid>/confirm'):
    if route in app_src:
        ok(f'route {route} registered')
    else:
        fail(f'missing route {route}')

shell_js = Path('templates/partials/shell_script.html').read_text(encoding='utf-8')
for anchor in ('fetchHandoffProfile', 'confirmSession', '_cmdShellHandoff',
               '_meterpreterHandoff', 'session_expected'):
    if anchor in shell_js:
        ok(f'shell_script.html wires {anchor}')
    else:
        fail(f'shell_script.html missing {anchor}')

print()
print('═' * 72)
print(f' HANDOFF AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
