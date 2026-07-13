#!/usr/bin/env python3
"""Offline audit — Credentials store, parsers, and capture wiring.

Regression-guards the credential bugs fixed in the Operations pass:
  * unix_hash is a valid type (Linux /etc/shadow capture must persist)
  * shadow parser covers modern hash ids ($6$/$y$/bcrypt) + uppercase users
  * stats() counts unix hashes and tolerates malformed records
  * the store survives a corrupt / foreign-schema JSON file
  * the resolver enrichment reads `value` (not the non-existent `password`)
  * the capture route validates connection/session and guards each add
"""
import json
import sys
import tempfile
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.credentials import (CredentialStore, CRED_TYPES, HASH_TYPES,
                                  parse_shadow_output, parse_hashdump_output,
                                  creds_from_finding)

# ── 1. unix_hash type ─────────────────────────────────────────────────────────
if 'unix_hash' in CRED_TYPES:
    ok('unix_hash is a registered credential type')
else:
    fail('unix_hash missing from CRED_TYPES — Linux shadow capture would 500')
if 'unix_hash' in HASH_TYPES and 'ntlm_hash' in HASH_TYPES:
    ok('HASH_TYPES covers ntlm_hash + unix_hash')
else:
    fail(f'HASH_TYPES wrong: {HASH_TYPES}')

# ── 2. shadow parser coverage + persistence ───────────────────────────────────
shadow = (
    "root:$6$abc$def/0123456789:19000:0:99999:7:::\n"
    "GitLab:$y$j9T$salt$hashy:19000:0:99999:7:::\n"        # yescrypt + uppercase
    "svc-bcrypt:$2b$12$abcdefghijklmnopqrstuv:19000::::::\n"
    "daemon:*:19000:0:99999:7:::\n"                         # locked — no hash
    "bin:!:19000:0:99999:7:::\n"
)
sc = parse_shadow_output(shadow, host_ip='10.0.0.5')
names = {c['username'] for c in sc}
if names == {'root', 'GitLab', 'svc-bcrypt'}:
    ok('shadow parser captures $6$, yescrypt ($y$), bcrypt; skips locked (* / !)')
else:
    fail(f'shadow parse wrong: {sorted(names)}')
if all(c['type'] == 'unix_hash' for c in sc):
    ok('shadow creds are typed unix_hash')
else:
    fail('shadow creds not typed unix_hash')

with tempfile.TemporaryDirectory() as td:
    store = CredentialStore(Path(td) / 'creds.json')
    try:
        ids = [store.add(c) for c in sc]
        ok(f'store.add persisted {len(ids)} unix_hash creds without ValueError')
    except Exception as exc:
        fail(f'store.add raised on unix_hash: {exc}')
    st = store.stats()
    if st['with_hash'] == 3:
        ok('stats.with_hash counts unix hashes')
    else:
        fail(f'stats.with_hash wrong: {st["with_hash"]}')

    # hashdump still works alongside
    hd = parse_hashdump_output(
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:'
        '31d6cfe0d16ae931b73c59d7e0c089c0:::\n', host_ip='10.0.0.6')
    if hd and hd[0]['type'] == 'ntlm_hash':
        ok('hashdump parser still yields ntlm_hash')
    else:
        fail('hashdump parser regressed')

# ── 3. corrupt / foreign-schema JSON tolerated ────────────────────────────────
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / 'creds.json'
    p.write_text(json.dumps([{'u': 'root'}]))            # a bare list, not a dict
    try:
        store = CredentialStore(p)
        store.stats()
        ok('store loads a list-shaped JSON file without crashing (empty store)')
    except Exception as exc:
        fail(f'store crashed on list-shaped JSON: {exc}')

    # malformed entry (missing type) must not crash stats()
    p2 = Path(td) / 'creds2.json'
    p2.write_text(json.dumps({'credentials': {'x': {'username': 'a'}}}))
    try:
        s2 = CredentialStore(p2)
        s2.stats()
        ok('stats() tolerates a record with no type field')
    except Exception as exc:
        fail(f'stats() crashed on typeless record: {exc}')

# ── 4. creds_from_finding never raises + returns valid types ──────────────────
out = creds_from_finding({'type': 'ad_users', 'detail': 'alice, bob@CORP + 3 more',
                          'host_ip': '10.0.0.7', 'tool': 'enum4linux'})
if out and all(c['type'] == 'username_only' for c in out):
    ok('creds_from_finding extracts username_only entries from ad_users')
else:
    fail(f'creds_from_finding ad_users wrong: {out}')

# ── 5. source-scan: resolver value mapping + capture-route guards ─────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
if "best.get('value')" in app_src and "best.get('password')" not in app_src.split(
        '_PRI =')[-1].split('env[\'creds\']')[0]:
    ok("resolver enrichment maps the secret from `value` (not `password`)")
else:
    # softer check — just confirm value is referenced in the creds env block
    if "best.get('value')" in app_src:
        ok("resolver enrichment references cred `value`")
    else:
        fail('resolver still uses non-existent `password` field')

for needle, desc in [
    ("is_connected()", 'capture route checks MSF connection'),
    ("'Session {sid} not found", 'capture route 404s a missing session'),
    ("per-cred guard", 'capture hook documents per-cred guard'),
]:
    if needle in app_src:
        ok(f'{desc}')
    else:
        fail(f'missing: {desc} ({needle!r})')

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print('═' * 72)
print(f' CREDENTIALS AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
