#!/usr/bin/env python3
"""Offline audit — module-aware launch profiles + launcher wiring."""
import inspect
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.launch_profiles import resolve_launch_profile, _BASE

REQUIRED = set(_BASE) | {'module'}

# ── 1. vsftpd → interact, no callback, no LHOST/LPORT, single-shot, RPORT 21 ──
p = resolve_launch_profile('exploit/unix/ftp/vsftpd_234_backdoor')
checks = {
    'force_rport': 21, 'payload_mode': 'interact', 'needs_callback': False,
    'uses_lhost': False, 'uses_lport': False, 'single_shot': True,
    'default_payload': 'cmd/unix/interact', 'automigrate': False,
}
bad = {k: p.get(k) for k, v in checks.items() if p.get(k) != v}
if not bad:
    ok('vsftpd_234_backdoor: interact, no callback, no LHOST/LPORT, single-shot, RPORT 21')
else:
    fail(f'vsftpd profile wrong: {bad}')

# ── 2. distcc → reverse_perl, callback, RPORT 3632 ────────────────────────────
p = resolve_launch_profile('exploit/unix/misc/distcc_exec')
if (p['force_rport'] == 3632 and p['payload_mode'] == 'reverse'
        and p['needs_callback'] is True
        and p['default_payload'] == 'cmd/unix/reverse_perl'):
    ok('distcc_exec: reverse_perl + callback + RPORT 3632')
else:
    fail(f'distcc profile wrong: {p}')

# ── 3. ms17_010 → meterpreter, RPORT 445, automigrate ON ──────────────────────
p = resolve_launch_profile('exploit/windows/smb/ms17_010_eternalblue')
if (p['force_rport'] == 445 and p['payload_mode'] == 'meterpreter'
        and p['automigrate'] is True and p['needs_callback'] is True):
    ok('ms17_010: meterpreter, RPORT 445, automigrate ON')
else:
    fail(f'ms17_010 profile wrong: {p}')

# ── 4. UnrealIRCd / usermap / java_rmi ports ──────────────────────────────────
cases = {
    'exploit/unix/irc/unreal_ircd_3281_backdoor': (6667, 'reverse'),
    'exploit/multi/samba/usermap_script':          (139, 'reverse'),
    'exploit/multi/misc/java_rmi_server':           (1099, 'meterpreter'),
}
bad = []
for mod, (rport, mode) in cases.items():
    p = resolve_launch_profile(mod)
    if p['force_rport'] != rport or p['payload_mode'] != mode:
        bad.append((mod, p['force_rport'], p['payload_mode']))
if not bad:
    ok('UnrealIRCd/usermap/java_rmi resolve to correct ports + payload modes')
else:
    fail(f'MT2 module profiles wrong: {bad}')

# ── 5. Web modules require TARGETURI ──────────────────────────────────────────
pj = resolve_launch_profile('exploit/multi/http/jenkins_script_console')
pd = resolve_launch_profile('exploit/unix/webapp/drupal_drupalgeddon2')
if 'TARGETURI' in pj['requires'] and 'TARGETURI' in pd['requires']:
    ok('Jenkins + Drupalgeddon profiles flag TARGETURI as required')
else:
    fail(f'web profiles missing TARGETURI requirement: jenkins={pj["requires"]}, drupal={pd["requires"]}')

# ── 6. Unknown module → safe generic default (callback ON) ────────────────────
p = resolve_launch_profile('exploit/windows/something/unknown_mod')
if (p['id'] == 'generic' and p['needs_callback'] is True
        and p['force_rport'] is None and p['payload_mode'] == 'auto'):
    ok('Unknown module → generic profile (callback ON, no RPORT force) — safe default')
else:
    fail(f'generic fallback wrong: {p}')

# ── 7. Every profile is well-formed ───────────────────────────────────────────
sample_mods = [
    'exploit/unix/ftp/vsftpd_234_backdoor', 'exploit/unix/misc/distcc_exec',
    'exploit/windows/smb/ms17_010_eternalblue', 'x/y/z',
]
malformed = []
for m in sample_mods:
    p = resolve_launch_profile(m)
    missing = REQUIRED - set(p)
    if missing:
        malformed.append((m, missing))
if not malformed:
    ok('All resolved profiles contain the full field set')
else:
    fail(f'profiles missing fields: {malformed}')

# ── 8. Engine integration: RPORT auto-correct + LHOST strip use the profile ───
from modules.msf_engine import MsfEngine, _CURATED_DEFAULT_PAYLOADS
src = inspect.getsource(MsfEngine._run_exploit_inner)
if 'resolve_launch_profile' in src and "uses_lhost" in src:
    ok('msf_engine uses launch profile for RPORT auto-correct + LHOST/LPORT strip')
else:
    fail('msf_engine not wired to launch_profiles')

# vsftpd must NOT be in the curated map — interact payloads are left blank so
# the module's own default is used (MSF rejects an explicitly-set interact
# payload). The interact handling lives in the payload-tailoring block instead.
if 'exploit/unix/ftp/vsftpd_234_backdoor' not in _CURATED_DEFAULT_PAYLOADS:
    ok('vsftpd NOT force-set as curated payload (interact → module default, blank)')
else:
    fail('vsftpd still in curated defaults — explicit interact payload will be rejected')

if "_leave_payload_default" in src and "payload_mode') == 'interact'" in src:
    ok('Engine leaves PAYLOAD blank for interact modules (vsftpd fix)')
else:
    fail('Engine missing interact-payload tailoring')

# ── 9. API + frontend wiring ──────────────────────────────────────────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
if '/api/msf/launch-profile' in app_src:
    ok('launch-profile API route registered')
else:
    fail('launch-profile route missing')

exploit_html = Path('templates/exploit.html').read_text(encoding='utf-8')
for anchor in ('applyLaunchProfile', 'onModuleChange', '_launchProfile',
               'needs_callback', 'launch-profile-note'):
    if anchor in exploit_html:
        ok(f'exploit.html wires {anchor}')
    else:
        fail(f'exploit.html missing {anchor}')

# Callback gate must consult needs_callback (not gate interact modules)
if '_needsCallback' in exploit_html and '_launchProfile.needs_callback' in exploit_html:
    ok('Callback gate skipped for modules with needs_callback=false (interact safe)')
else:
    fail('Callback gate not conditioned on launch profile')

# Misleading "MT2: reverse_perl" static placeholder removed
if 'MT2: reverse_perl' not in exploit_html:
    ok('Misleading "MT2: reverse_perl" placeholder removed')
else:
    fail('Stale "MT2: reverse_perl" placeholder still present')

# ── 10. Version present + startup banner ──────────────────────────────────────
import re as _re
from config import H3xConfig
if _re.match(r'^\d+\.\d+\.\d+(\.\d+)?$', H3xConfig.VERSION):
    ok(f'VERSION is version-shaped ({H3xConfig.VERSION})')
else:
    fail(f'VERSION not version-shaped: {H3xConfig.VERSION}')

if 'starting —' in app_src and 'H3xConfig.VERSION' in app_src:
    ok('Startup banner prints running version')
else:
    fail('Startup version banner missing')

print()
print('═' * 72)
print(f' LAUNCH-PROFILE AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
