#!/usr/bin/env python3
"""Offline audit — Phase 2 resolver + information-gained feedback loop."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.exploit_resolver import (
    resolve_plan, analyze_outcome, merge_insights,
    MODE_REVERSE, MODE_BIND, MODE_INTERACT, MODE_DEFAULT, MODE_NONE,
    SIG_PAYLOAD_INCOMPAT, SIG_UNKNOWN_OPTION, SIG_REVERSE_NO_SESSION,
    SIG_SESSION_DIED, SIG_WRONG_TARGET, SIG_SINGLE_SHOT, SIG_NOT_VULNERABLE,
    SIG_SUCCESS, SIG_MISSING_REQUIRED,
)

WIN_CAPS = {
    'available': True, 'rank': 'excellent',
    'options': {'RHOSTS': {'required': True}, 'RPORT': {'required': True, 'default': 445}},
    'required': ['RHOSTS'], 'payloads_parseable': True,
    'compatible_payloads': ['windows/x64/meterpreter/reverse_tcp',
                            'windows/x64/shell/bind_tcp'],
    'targets': [{'index': 0, 'name': 'Automatic'}, {'index': 1, 'name': 'Windows 7 x64'}],
    'default_rport': 445, 'has_builtin_payload': False, 'notes': [],
}
NIX_CAPS = {
    'available': True, 'rank': 'excellent',
    'options': {'RHOSTS': {'required': True}, 'RPORT': {'required': True, 'default': 3632}},
    'required': ['RHOSTS'], 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/reverse_perl', 'cmd/unix/bind_perl',
                            'cmd/unix/bind_netcat', 'cmd/unix/generic'],
    'targets': [], 'default_rport': 3632, 'has_builtin_payload': False, 'notes': [],
}
INTERACT_CAPS = {
    'available': True, 'rank': 'excellent',
    'options': {'RHOSTS': {'required': True}, 'RPORT': {'required': True, 'default': 21}},
    'required': ['RHOSTS'], 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/interact'],
    'targets': [], 'default_rport': 21, 'has_builtin_payload': True, 'notes': [],
}

# ── 1. Windows meterpreter, routable → reverse + meterpreter + matched target ──
env = {'rhost': '10.0.0.5', 'os_family': 'windows', 'arch': 'x64',
       'lhost': '10.0.0.1', 'lhost_routable': True, 'lport_free': True}
p = resolve_plan(WIN_CAPS, env)
if (p['connection_mode'] == MODE_REVERSE
        and 'meterpreter' in (p['payload'] or '')
        and p['options'].get('RPORT') == 445
        and p['options'].get('LHOST') == '10.0.0.1'):
    ok('Windows + routable LHOST → reverse meterpreter, RPORT 445, LHOST set')
else:
    fail(f'Windows reverse plan wrong: {p}')

# ── 2. LHOST not routable → bind mode + bind payload ──────────────────────────
env2 = {'rhost': '10.0.0.5', 'os_family': 'linux', 'lhost': '10.0.0.1',
        'lhost_routable': False}
p = resolve_plan(NIX_CAPS, env2)
if p['connection_mode'] == MODE_BIND and 'bind' in (p['payload'] or ''):
    ok('LHOST not routable → bind mode + bind payload (lab-adaptive)')
else:
    fail(f'Bind fallback wrong: {p}')

# ── 3. Interact module → mode interact, PAYLOAD blank ─────────────────────────
p = resolve_plan(INTERACT_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux'},
                 policy={'payload_mode': 'interact'})
if p['connection_mode'] == MODE_INTERACT and p['payload'] is None:
    ok('Interact module → mode interact, PAYLOAD left blank (module default)')
else:
    fail(f'Interact plan wrong: {p}')

# ── 4. Auxiliary module → no session ──────────────────────────────────────────
p = resolve_plan({'available': True, 'options': {}}, {'rhost': '1.2.3.4'},
                 policy={'module_type': 'auxiliary'})
if p['connection_mode'] == MODE_NONE and p['payload'] is None:
    ok('Auxiliary module → no-session plan (no payload)')
else:
    fail(f'Aux plan wrong: {p}')

# ── 5. A required option with NO default that we CAN'T derive still surfaces ──
# (TARGETURI is now auto-filled to "/" by enrichment, so use a non-derivable one.)
caps_req = {**NIX_CAPS, 'required': ['RHOSTS', 'APIKEY'],
    'options': {**NIX_CAPS['options'], 'APIKEY': {'required': True, 'default': None}}}
p = resolve_plan(caps_req, {'rhost': '10.0.0.5', 'os_family': 'linux',
                            'lhost': '10.0.0.1', 'lhost_routable': True})
if 'APIKEY' in p['information_needed']:
    ok('Required option with no default and no derivable source surfaces (APIKEY)')
else:
    fail(f'Missing-required not surfaced: {p}')

# ── 6. Undeclared option is skipped (only sets what the module supports) ──────
# RPORT default from caps wins; an unsupported extra would be dropped. Verify
# LHOST (core, payload-level) is still allowed even though not in base options.
p = resolve_plan(NIX_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux',
                            'lhost': '10.0.0.1', 'lhost_routable': True})
if 'LHOST' in p['options']:
    ok('Core payload-level options (LHOST) allowed even if absent from base options')
else:
    fail(f'LHOST wrongly skipped: {p}')

# ── 7. analyze_outcome signal detection ───────────────────────────────────────
rev_plan = {'connection_mode': MODE_REVERSE, 'payload': 'cmd/unix/reverse_perl', 'target_index': 0}

def has_sig(insights, sig):
    return any(i['signal'] == sig for i in insights)

# payload incompatible
ins = analyze_outcome(rev_plan, {'console_output': 'The value specified for payload is not valid.'})
if has_sig(ins, SIG_PAYLOAD_INCOMPAT) and merge_insights(ins)['exclude_payloads'] == ['cmd/unix/reverse_perl']:
    ok('analyze: payload-not-valid → incompatible insight excludes that payload')
else:
    fail(f'payload incompat detection wrong: {ins}')

# unknown datastore option
ins = analyze_outcome(rev_plan, {'console_output': '[!] Unknown datastore option: ExitOnSession.'})
if has_sig(ins, SIG_UNKNOWN_OPTION) and 'ExitOnSession' in merge_insights(ins)['exclude_options']:
    ok('analyze: unknown datastore option → excludes that option next time')
else:
    fail(f'unknown option detection wrong: {ins}')

# reverse never came back
ins = analyze_outcome(rev_plan, {'exploit_failed': True,
    'console_output': 'Exploit completed, but no session was created.'})
if has_sig(ins, SIG_REVERSE_NO_SESSION) and merge_insights(ins)['prefer_mode'] == MODE_BIND:
    ok('analyze: reverse no-session → re-arm prefer bind')
else:
    fail(f'reverse no-session detection wrong: {ins}')

# reverse opened then died
ins = analyze_outcome(rev_plan, {'session_reported': True, 'session_confirmed': False,
    'console_output': 'Meterpreter session 1 opened ... session 1 closed.'})
if has_sig(ins, SIG_SESSION_DIED) and merge_insights(ins)['escalate_migrate']:
    ok('analyze: reverse opened-then-died → escalate migrate + prefer bind')
else:
    fail(f'session-died detection wrong: {ins}')

# wrong target (vuln but no session)
ins = analyze_outcome(rev_plan, {'exploit_failed': True,
    'console_output': 'The target is vulnerable. Exploit completed, but no session was created.'})
if has_sig(ins, SIG_WRONG_TARGET) and merge_insights(ins)['try_target_index'] == 1:
    ok('analyze: vulnerable-but-no-session → re-arm next target index')
else:
    fail(f'wrong-target detection wrong: {ins}')

# single-shot bind consumed
ins = analyze_outcome({'connection_mode': MODE_INTERACT, 'payload': None, 'target_index': 0},
    {'console_output': 'The port used by the backdoor bind listener is already open (6200).'})
if has_sig(ins, SIG_SINGLE_SHOT) and merge_insights(ins)['retrigger']:
    ok('analyze: single-shot bind already open → re-arm re-trigger')
else:
    fail(f'single-shot detection wrong: {ins}')

# not vulnerable → stop
ins = analyze_outcome(rev_plan, {'check_code': 'SAFE',
    'console_output': 'The target is not exploitable.'})
if has_sig(ins, SIG_NOT_VULNERABLE) and merge_insights(ins)['stop']:
    ok('analyze: SAFE verdict → stop (no retry will help)')
else:
    fail(f'not-vulnerable detection wrong: {ins}')

# success → no rearm
ins = analyze_outcome(rev_plan, {'session_confirmed': True})
if has_sig(ins, SIG_SUCCESS) and len(ins) == 1:
    ok('analyze: success → single success insight, nothing to re-arm')
else:
    fail(f'success detection wrong: {ins}')

# ── 8. THE FEEDBACK LOOP — failure re-arms the next plan ──────────────────────
# Step 1: reverse attempt fails to call back.
plan1 = resolve_plan(NIX_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux',
                                'lhost': '10.0.0.1', 'lhost_routable': True})
out1  = {'exploit_failed': True,
         'console_output': 'Exploit completed, but no session was created.'}
ins1  = analyze_outcome(plan1, out1)

# Step 2: resolver consumes the insight → switches to bind WITHOUT env change.
plan2 = resolve_plan(NIX_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux',
                                'lhost': '10.0.0.1', 'lhost_routable': True},
                     prior_insights=ins1)
if plan2['connection_mode'] == MODE_BIND and plan2['applied_insights']:
    ok('FEEDBACK 1: reverse-fail insight re-arms next plan to BIND (mode flipped)')
else:
    fail(f'feedback step 2 did not flip to bind: {plan2}')

# Step 3: the bind payload is rejected → exclude it, pick another compatible.
out2  = {'console_output': 'cmd/unix/bind_perl is not a compatible payload.'}
ins2  = analyze_outcome(plan2, out2)
combined = ins1 + ins2
plan3 = resolve_plan(NIX_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux',
                                'lhost': '10.0.0.1', 'lhost_routable': True},
                     prior_insights=combined)
if (plan3['connection_mode'] == MODE_BIND
        and plan3['payload'] != 'cmd/unix/bind_perl'):
    ok('FEEDBACK 2: rejected payload excluded — next plan selects a different one')
else:
    fail(f'feedback step 3 did not exclude rejected payload: {plan3}')

# Step 4: a SAFE verdict halts the chain entirely.
ins_safe = analyze_outcome(plan1, {'check_code': 'SAFE'})
plan4 = resolve_plan(NIX_CAPS, {'rhost': '10.0.0.5'}, prior_insights=ins_safe)
if plan4['stop'] and plan4['connection_mode'] == MODE_NONE:
    ok('FEEDBACK 3: SAFE verdict halts the chain (resolver returns stop)')
else:
    fail(f'feedback stop did not halt: {plan4}')

# ── 9. Engine + UI wiring ─────────────────────────────────────────────────────
from modules.msf_engine import MsfEngine
import inspect
for meth in ('recommend_plan', 'get_run_insights', '_record_run_outcome',
             'module_capabilities'):
    if hasattr(MsfEngine, meth):
        ok(f'MsfEngine.{meth}() present')
    else:
        fail(f'MsfEngine missing {meth}()')

inner_src  = inspect.getsource(MsfEngine._run_exploit_inner)
record_src = inspect.getsource(MsfEngine._record_run_outcome)
if '_record_run_outcome' in inner_src and 'information_gained' in record_src \
        and 'analyze_outcome' in record_src:
    ok('run_exploit records outcome → analyze_outcome → information_gained')
else:
    fail('run_exploit does not attach information_gained via analyze_outcome')

app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
if '/api/msf/resolve-plan' in app_src:
    ok('resolve-plan API route registered')
else:
    fail('resolve-plan route missing')

html = Path('templates/exploit.html').read_text(encoding='utf-8')
for anchor in ('recommendConfig', 'renderInfoGain', 'rearmFromInsights',
               'information_gained', 'applyRecommendation', 'infogain-panel'):
    if anchor in html:
        ok(f'exploit.html wires {anchor}')
    else:
        fail(f'exploit.html missing {anchor}')

# ── 11. Required-but-DEFAULTED options must NOT block (vsftpd SSLVersion bug) ─
caps_defaulted = {
    'available': True, 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/interact'],
    'targets': [], 'default_rport': 21, 'has_builtin_payload': True,
    'options': {
        'RHOSTS':        {'required': True,  'default': None},
        'RPORT':         {'required': True,  'default': 21},
        'SSLVersion':    {'required': True,  'default': 'Auto'},     # advanced, has default
        'ConnectTimeout':{'required': True,  'default': 10},         # advanced, has default
    },
    'required': ['RHOSTS', 'RPORT', 'SSLVersion', 'ConnectTimeout'],
    'notes': [],
}
p = resolve_plan(caps_defaulted, {'rhost': '10.0.0.5', 'os_family': 'linux'},
                 policy={'payload_mode': 'interact'})
if 'SSLVersion' not in p['information_needed'] and 'ConnectTimeout' not in p['information_needed']:
    ok('Required options WITH defaults (SSLVersion/ConnectTimeout) are NOT flagged as needed')
else:
    fail(f'defaulted options wrongly flagged: {p["information_needed"]}')

# Live wrinkle: pymetasploit3 reports these as required with NO default surfaced.
# The framework-option allowlist + 'advanced' flag must STILL skip them.
caps_nodefault = {
    'available': True, 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/interact'],
    'targets': [], 'default_rport': 21, 'has_builtin_payload': True,
    'options': {
        'RHOSTS':         {'required': True, 'default': None},
        'SSLVersion':     {'required': True, 'default': None},   # no default surfaced
        'ConnectTimeout': {'required': True, 'default': None},   # no default surfaced
        'WfsDelay':       {'required': True, 'default': None, 'advanced': True},
    },
    'required': ['RHOSTS', 'SSLVersion', 'ConnectTimeout', 'WfsDelay'],
    'notes': [],
}
p = resolve_plan(caps_nodefault, {'rhost': '10.0.0.5', 'os_family': 'linux'},
                 policy={'payload_mode': 'interact'})
blocked = set(p['information_needed'])
if not ({'SSLVersion', 'ConnectTimeout', 'WfsDelay'} & blocked):
    ok('Framework options reported required WITHOUT a default are still skipped '
       '(allowlist + advanced flag) — fixes the live SSLVersion/ConnectTimeout block')
else:
    fail(f'framework options still blocking with no surfaced default: {blocked}')

# Truly-required, NO-default option still surfaces.
caps_needpass = {
    'available': True, 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/reverse_perl'],
    'targets': [], 'default_rport': 22, 'has_builtin_payload': False,
    'options': {'RHOSTS': {'required': True, 'default': None},
                'PASSWORD': {'required': True, 'default': None}},
    'required': ['RHOSTS', 'PASSWORD'], 'notes': [],
}
p = resolve_plan(caps_needpass, {'rhost': '10.0.0.5', 'os_family': 'linux',
                                 'lhost': '10.0.0.1', 'lhost_routable': True})
if 'PASSWORD' in p['information_needed']:
    ok('Required option with NO default and no derivable value still surfaces (PASSWORD)')
else:
    fail(f'no-default required option not surfaced: {p}')

# ── 12. Silent enrichment: creds auto-fill USERNAME/PASSWORD when declared ────
p = resolve_plan(caps_needpass,
                 {'rhost': '10.0.0.5', 'os_family': 'linux',
                  'lhost': '10.0.0.1', 'lhost_routable': True,
                  'creds': {'username': 'root', 'password': 'toor'}})
if p['options'].get('PASSWORD') == 'toor' and 'PASSWORD' not in p['information_needed']:
    ok('Captured creds auto-fill declared PASSWORD → no longer needs operator input')
else:
    fail(f'cred enrichment failed: opts={p["options"]}, need={p["information_needed"]}')

# ── 13. TARGETURI auto-filled (web_path or "/") when the module declares it ───
caps_web = {
    'available': True, 'payloads_parseable': True,
    'compatible_payloads': ['cmd/unix/reverse_perl'],
    'targets': [], 'default_rport': 8080, 'has_builtin_payload': False,
    'options': {'RHOSTS': {'required': True, 'default': None},
                'TARGETURI': {'required': True, 'default': None}},
    'required': ['RHOSTS', 'TARGETURI'], 'notes': [],
}
p = resolve_plan(caps_web, {'rhost': '10.0.0.5', 'os_family': 'linux',
                            'lhost': '10.0.0.1', 'lhost_routable': True,
                            'web_path': '/jenkins/'})
if p['options'].get('TARGETURI') == '/jenkins/' and 'TARGETURI' not in p['information_needed']:
    ok('Enum web path auto-fills TARGETURI (no per-CVE table)')
else:
    fail(f'TARGETURI enrichment failed: opts={p["options"]}, need={p["information_needed"]}')

p2 = resolve_plan(caps_web, {'rhost': '10.0.0.5', 'os_family': 'linux',
                             'lhost': '10.0.0.1', 'lhost_routable': True})
if p2['options'].get('TARGETURI') == '/':
    ok('TARGETURI defaults to "/" when no enum path is known')
else:
    fail(f'TARGETURI default fallback wrong: {p2["options"]}')

# ── 14. Enrichment only sets DECLARED options (never invents undeclared ones) ─
p = resolve_plan(caps_needpass,
                 {'rhost': '10.0.0.5', 'os_family': 'linux',
                  'lhost': '10.0.0.1', 'lhost_routable': True,
                  'creds': {'username': 'root', 'password': 'toor'},
                  'web_path': '/x/'})
if 'TARGETURI' not in p['options']:   # this module doesn't declare TARGETURI
    ok('Enrichment never sets options the module does not declare')
else:
    fail(f'enrichment invented an undeclared option: {p["options"]}')

# ── 15. OS-compatibility guard (high-confidence) ──────────────────────────────
from modules.exploit_resolver import os_incompatible, module_platform
if (module_platform('exploit/windows/smb/ms17_010_eternalblue') == 'windows'
        and module_platform('exploit/unix/ftp/vsftpd_234_backdoor') == 'linux'
        and module_platform('exploit/multi/misc/java_rmi_server') is None):
    ok('module_platform derives platform from the module path (None for multi)')
else:
    fail('module_platform derivation wrong')

# Windows module vs 100% Linux host → incompatible (halt, don't waste attempts)
if os_incompatible('exploit/windows/smb/ms17_010_eternalblue', 'linux', 100):
    ok('Windows module on 100%-confidence Linux host → incompatible')
else:
    fail('OS-incompat guard missed windows-on-linux at high confidence')

# Low confidence must NOT veto.
if not os_incompatible('exploit/windows/smb/ms17_010_eternalblue', 'linux', 40):
    ok('Low classification confidence never vetoes a module (no false block)')
else:
    fail('low-confidence wrongly vetoed')

# Cross-platform module never incompatible.
if not os_incompatible('exploit/multi/misc/java_rmi_server', 'linux', 100):
    ok('Cross-platform (multi/) module never flagged incompatible')
else:
    fail('multi module wrongly flagged incompatible')

# resolve_plan halts on an incompatible module instead of planning a doomed run.
p = resolve_plan(WIN_CAPS, {'rhost': '10.0.0.5', 'os_family': 'linux',
                            'os_confidence': 100,
                            'module': 'exploit/windows/smb/ms17_010_eternalblue'})
if p.get('stop') and p.get('incompatible'):
    ok('resolve_plan halts (incompatible) for an OS-mismatched module at high confidence')
else:
    fail(f'resolve_plan did not halt on incompatible module: {p}')

print()
print('═' * 72)
print(f' RESOLVER AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
