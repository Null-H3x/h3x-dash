#!/usr/bin/env python3
"""Offline audit — Phase 1 MSF capability introspection (parsing + cache)."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.msf_capabilities import (
    parse_capabilities, get_module_capabilities, CapabilityCache,
)


# ── Mock pymetasploit3 module objects ─────────────────────────────────────────
class GoodMod:
    rank = 'excellent'
    options = {
        'RHOSTS': {'required': True, 'default': None, 'type': 'address'},
        'RPORT':  {'required': True, 'default': 445, 'type': 'port'},
        'SMBUser': {'required': False, 'default': None, 'type': 'string'},
    }
    required = ['RHOSTS', 'RPORT']
    payloads = ['windows/x64/meterpreter/reverse_tcp',
                'windows/x64/shell/reverse_tcp']
    targets = ['Automatic Target', 'Windows 7 x64']


class QuirkMod:
    """Module whose .payloads raises — the pymetasploit3 compatible_payloads quirk."""
    rank = 'great'
    options = {'RHOSTS': {'required': True}, 'RPORT': {'required': True, 'default': 21}}
    required = ['RHOSTS']
    targets = ['Automatic']
    @property
    def payloads(self):
        raise TypeError("'NoneType' object is not subscriptable")


class InteractMod:
    rank = 'excellent'
    options = {'RHOSTS': {'required': True}, 'RPORT': {'required': True, 'default': 21}}
    required = ['RHOSTS']
    payloads = ['cmd/unix/interact']
    targets = ['Automatic']


# ── 1. Good module parses fully ───────────────────────────────────────────────
c = parse_capabilities('exploit/windows/smb/ms17_010_eternalblue', GoodMod())
if (c['available'] and c['default_rport'] == 445
        and 'windows/x64/meterpreter/reverse_tcp' in c['compatible_payloads']
        and c['payloads_parseable'] and len(c['targets']) == 2
        and 'RHOSTS' in c['required']):
    ok('Good module: options, default RPORT, payloads, targets, required all parsed')
else:
    fail(f'Good module parse wrong: {c}')

# ── 2. Quirk module degrades gracefully (no raise, empty payloads) ────────────
c = parse_capabilities('exploit/unix/ftp/proftpd', QuirkMod())
if (c['available'] and c['compatible_payloads'] == []
        and c['payloads_parseable'] is False and c['default_rport'] == 21
        and c['notes']):
    ok('Quirk module: payloads degrade to [] + payloads_parseable=False, no raise')
else:
    fail(f'Quirk module did not degrade gracefully: {c}')

# ── 3. Interact module flagged has_builtin_payload ────────────────────────────
c = parse_capabilities('exploit/unix/ftp/vsftpd_234_backdoor', InteractMod())
if c['has_builtin_payload'] is True:
    ok('Interact-only module flagged has_builtin_payload (resolver leaves PAYLOAD blank)')
else:
    fail(f'has_builtin_payload not set for interact module: {c}')

# ── 4. None module → available False, never raises ────────────────────────────
c = parse_capabilities('exploit/x/y', None)
if c['available'] is False and c['options'] == {} and c['notes']:
    ok('Missing module → available=False with a helpful note (no raise)')
else:
    fail(f'None module handling wrong: {c}')

# ── 5. Cache stores + returns ─────────────────────────────────────────────────
cache = CapabilityCache()
cache.put('m', {'available': True, 'x': 1})
if cache.get('m') == {'available': True, 'x': 1} and cache.get('nope') is None:
    ok('CapabilityCache stores and returns by module name')
else:
    fail('CapabilityCache broken')

# ── 6. get_module_capabilities with a mock client (+ caching) ─────────────────
class MockModules:
    def __init__(self): self.calls = 0
    def use(self, t, n):
        self.calls += 1
        return GoodMod()
class MockClient:
    def __init__(self): self.modules = MockModules()

mc = MockClient()
import modules.msf_capabilities as capmod
capmod._cache.clear()
r1 = get_module_capabilities(mc, 'exploit/windows/smb/ms17_010_eternalblue')
r2 = get_module_capabilities(mc, 'exploit/windows/smb/ms17_010_eternalblue')
if r1['available'] and mc.modules.calls == 1:
    ok('get_module_capabilities caches — second call does not re-hit RPC')
else:
    fail(f'Caching failed: calls={mc.modules.calls}')

# ── 7. No client → graceful unavailable ───────────────────────────────────────
r = get_module_capabilities(None, 'exploit/x/y')
if r['available'] is False:
    ok('No client → available=False (never raises)')
else:
    fail('No-client handling wrong')

# ── 8. App wiring ─────────────────────────────────────────────────────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
if '/api/msf/capabilities' in app_src:
    ok('Capabilities API route registered')
else:
    fail('Capabilities route missing')

from modules.msf_engine import MsfEngine
if hasattr(MsfEngine, 'module_capabilities'):
    ok('MsfEngine.module_capabilities() present')
else:
    fail('MsfEngine missing module_capabilities()')

print()
print('═' * 72)
print(f' CAPABILITIES AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
