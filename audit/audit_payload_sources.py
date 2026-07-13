#!/usr/bin/env python3
"""Offline audit — vetted GitHub payload sources + the access-update pull.

Exercises every code path that does NOT require network: allowlist shape and
enforcement, URL validation (defence-in-depth), git-tree → payload parsing,
synced-payload merge into the library, manager persistence, and the Flask/UI
wiring. No request is ever made — the parser is fed a mock tree.
"""
import json
import sys
import tempfile
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules import implant_engine
from modules import payload_sources as ps
from modules.payload_sources import (
    VETTED_SOURCES, SOURCE_ORDER, is_vetted,
    _assert_allowed_url, _derive_payloads_from_tree, _extract_description,
    PayloadSourceManager,
)
from modules.implant_engine import PRODUCTS

REQUIRED_KEYS = {'id', 'label', 'org', 'repo', 'branch', 'library_path',
                 'products', 'lang', 'attack', 'cm', 'callback', 'homepage'}

# ── 1. Allowlist shape ────────────────────────────────────────────────────────
if set(SOURCE_ORDER) == set(VETTED_SOURCES):
    ok('SOURCE_ORDER covers every vetted source exactly')
else:
    fail(f'SOURCE_ORDER / VETTED_SOURCES mismatch: '
         f'{set(SOURCE_ORDER) ^ set(VETTED_SOURCES)}')

for sid, src in VETTED_SOURCES.items():
    missing = REQUIRED_KEYS - set(src)
    if missing:
        fail(f'{sid}: missing keys {missing}')
        continue
    if src['id'] != sid:
        fail(f'{sid}: id field {src["id"]!r} != key')
    bad_prods = [p for p in src['products'] if p not in PRODUCTS]
    if bad_prods:
        fail(f'{sid}: products not in PRODUCTS: {bad_prods}')
    if src['callback'] != 'none':
        fail(f'{sid}: synced payloads must default callback=none, got {src["callback"]!r}')
if not FAIL:
    ok('every vetted source has a valid shape, products, and callback=none')

if all(is_vetted(s) for s in SOURCE_ORDER) and not is_vetted('attacker/evil-repo'):
    ok('is_vetted accepts allowlisted ids and rejects unknown ones')
else:
    fail('is_vetted allowlist behaviour wrong')

# ── 1b. New Hak5 devices wired in ─────────────────────────────────────────────
from modules.implant_engine import PRODUCT_ORDER, list_payloads as _lp
NEW_PAYLOAD = ['packetsquirrel', 'keycroc', 'signalowl', 'omg-cable']
NEW_SPECTRUM = ['screencrab', 'plunderbug', 'wificoconut']
miss = [p for p in NEW_PAYLOAD + NEW_SPECTRUM if p not in PRODUCTS]
if not miss:
    ok('all new Hak5 device products are registered in PRODUCTS')
else:
    fail(f'missing new products: {miss}')
if all(PRODUCTS.get(p, {}).get('class') == 'payload' for p in NEW_PAYLOAD):
    ok('Packet Squirrel / Key Croc / Signal Owl / O.MG Cable are payload-class')
else:
    fail('a new payload device has the wrong class')
if all(PRODUCTS.get(p, {}).get('class') == 'spectrum' for p in NEW_SPECTRUM):
    ok('Screen Crab / Plunder Bug / WiFi Coconut are spectrum-class')
else:
    fail('a new capture device has the wrong class')
if all(p in PRODUCT_ORDER for p in NEW_PAYLOAD + NEW_SPECTRUM):
    ok('new devices appear in PRODUCT_ORDER')
else:
    fail('a new device is missing from PRODUCT_ORDER')
# O.MG Cable shares the existing O.MG payload library
if any('omg-cable' in p['products'] for p in _lp('omg-cable')):
    ok('O.MG Cable inherits the O.MG payload set')
else:
    fail('O.MG Cable has no compatible payloads (not added to _OMG)')
# Each new payload device has a backing vetted source
for pid, sid in [('packetsquirrel', 'hak5-packetsquirrel'),
                 ('keycroc', 'hak5-keycroc'), ('signalowl', 'hak5-signalowl')]:
    src = VETTED_SOURCES.get(sid, {})
    if src.get('products') == [pid]:
        ok(f'{pid} has a vetted source ({sid})')
    else:
        fail(f'{pid} missing/incorrect vetted source {sid}: {src.get("products")}')

# ── 1c. Version bump ──────────────────────────────────────────────────────────
cfg = Path('config.py').read_text(encoding='utf-8')
if "VERSION = '0.9.90.70'" in cfg:
    ok('config.py VERSION bumped to 0.9.90.70')
else:
    fail('config.py VERSION not set to 0.9.90.70')

# ── 1d. Access functional fixes (connectivity / arming / deploying) ───────────
import tempfile as _tf
from modules.implant_engine import ImplantRegistry, validate_connect

# New payload devices are armable offline (built-in stub payloads exist).
for pid in ('packetsquirrel', 'keycroc', 'signalowl'):
    if _lp(pid):
        ok(f'{pid} has built-in payload(s) — armable offline before GitHub sync')
    else:
        fail(f'{pid} has no built-in payloads — ARM would be empty on an air-gapped range')

# validate_connect: USB → manual (neutral), bad port → clean fail (no crash).
usb_v = validate_connect({'product_id': 'ducky', 'transport': 'usb', 'host': '', 'port': None})
if usb_v.get('status') == 'manual':
    ok('validate_connect reports USB devices as "manual" (neutral, not offline)')
else:
    fail(f'USB validate status wrong: {usb_v.get("status")}')
bad_v = validate_connect({'product_id': 'bunny', 'transport': 'ssh',
                          'host': '10.0.0.1', 'port': 'not-a-number'})
if bad_v.get('status') == 'fail' and 'invalid port' in bad_v.get('detail', ''):
    ok('validate_connect returns a clean fail on a malformed port (no 500)')
else:
    fail(f'bad-port validate not handled cleanly: {bad_v}')

# arm() clears stale deploy state (re-arm must not keep a DEPLOYED badge).
with _tf.TemporaryDirectory() as _td:
    reg = ImplantRegistry(Path(_td) / 'implants.json')
    inst = reg.add_instance('bunny')
    reg.arm(inst['id'], 'quickcreds.txt', callback='creds')
    reg.mark_deployed(inst['id'], target='lab', ack=True)
    if reg.get(inst['id'])['deployed']:
        # re-arm should reset deployed
        reg.arm(inst['id'], 'exfil-docs.txt', callback='loot')
        if not reg.get(inst['id'])['deployed']:
            ok('re-arming an instance clears stale deployed state')
        else:
            fail('re-arm left deployed=True (stale DEPLOYED badge)')
    else:
        fail('mark_deployed did not set deployed (test setup issue)')

# Source-scan: callback landed uses integer port compare; api-connect gated.
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
if "rsplit(':', 1)" in app_src and "tport == lport_int" in app_src:
    ok('callback "landed" detection compares tunnel port as an integer')
else:
    fail('callback landed still uses fragile suffix matching')
if "'status':  'unreachable'" in app_src or "'status': 'unreachable'" in app_src:
    ok('Pineapple api-connect gates success on a reachable probe')
else:
    fail('Pineapple api-connect may still report success unconditionally')

# payload.js preserves the Arm-tab selection across tab switches.
pjs = Path('static/payload.js').read_text(encoding='utf-8')
if 'SEL.inst && insts.some' in pjs and 'SEL.payload && pays.some' in pjs:
    ok('payload.js restores the Arm-tab instance + payload selection on revisit')
else:
    fail('Arm-tab selection not preserved — Deploy could target the wrong device')

# ── 2. URL validation (defence-in-depth) ──────────────────────────────────────
src = VETTED_SOURCES['hak5-ducky']
good = f"https://api.github.com/repos/{src['org']}/{src['repo']}/git/trees/master?recursive=1"
try:
    _assert_allowed_url(good, src)
    ok('valid api.github.com URL for the vetted repo is accepted')
except Exception as e:
    fail(f'valid URL rejected: {e}')

bad_urls = [
    'https://evil.example.com/repos/hak5/usbrubberducky-payloads/git/trees/master',
    'http://api.github.com/repos/hak5/usbrubberducky-payloads/git/trees/master',
    'https://api.github.com/repos/attacker/malware/git/trees/master',
    'https://api.github.com.evil.com/repos/hak5/usbrubberducky-payloads/x',
]
rejected = 0
for u in bad_urls:
    try:
        _assert_allowed_url(u, src)
    except ValueError:
        rejected += 1
if rejected == len(bad_urls):
    ok('non-GitHub host, http scheme, wrong repo, and look-alike host all rejected')
else:
    fail(f'_assert_allowed_url failed to reject {len(bad_urls) - rejected} hostile URL(s)')

# ── 3. Tree → payload parsing ─────────────────────────────────────────────────
mock_tree = [
    {'type': 'tree', 'path': 'payloads'},
    {'type': 'tree', 'path': 'payloads/library'},
    {'type': 'tree', 'path': 'payloads/library/exfiltration'},
    {'type': 'blob', 'path': 'payloads/library/exfiltration/Browser-Creds/payload.txt'},
    {'type': 'blob', 'path': 'payloads/library/exfiltration/Browser-Creds/README.md'},
    {'type': 'blob', 'path': 'payloads/library/remote-access/Reverse-Shell/payload.txt'},
    {'type': 'blob', 'path': 'payloads/library/README.md'},
    {'type': 'blob', 'path': 'payloads/library/Quick-Hello.txt'},
    {'type': 'blob', 'path': 'payloads/library/LICENSE.txt'},
    {'type': 'blob', 'path': 'outside/library/Ignored/payload.txt'},
]
parsed = _derive_payloads_from_tree(mock_tree, src)
names = {p['name'] for p in parsed}
expected = {'Browser-Creds', 'Reverse-Shell', 'Quick-Hello'}
if names == expected:
    ok(f'tree parse derived exactly {sorted(expected)} (folder names + flat .txt)')
else:
    fail(f'tree parse wrong: got {sorted(names)}, expected {sorted(expected)}')

if all(p['callback'] == 'none' and p['vetted'] and p['source'] == 'hak5-ducky'
       and p['url'].startswith('https://github.com/hak5/usbrubberducky-payloads/blob/')
       for p in parsed):
    ok('parsed payloads carry callback=none, vetted flag, source id, and a repo URL')
else:
    fail('parsed payload metadata incomplete')

# doc_path: a sibling README is preferred; otherwise the payload file itself.
bc = next((p for p in parsed if p['name'] == 'Browser-Creds'), {})
rs = next((p for p in parsed if p['name'] == 'Reverse-Shell'), {})
if bc.get('doc_path') == 'payloads/library/exfiltration/Browser-Creds/README.md':
    ok('doc_path prefers a sibling README.md when present')
else:
    fail(f'doc_path README preference wrong: {bc.get("doc_path")}')
if rs.get('doc_path') == 'payloads/library/remote-access/Reverse-Shell/payload.txt':
    ok('doc_path falls back to the payload file when no README')
else:
    fail(f'doc_path fallback wrong: {rs.get("doc_path")}')

# Cap is enforced
big_tree = [{'type': 'blob', 'path': f'payloads/library/cat/P{i}/payload.txt'}
            for i in range(ps.PER_SOURCE_LIMIT + 50)]
if len(_derive_payloads_from_tree(big_tree, src)) == ps.PER_SOURCE_LIMIT:
    ok(f'parser caps results at PER_SOURCE_LIMIT ({ps.PER_SOURCE_LIMIT})')
else:
    fail('PER_SOURCE_LIMIT cap not enforced')

# Flat match-mode (LAN Turtle modules: depth-1 files, no payload.txt wrapper)
turtle = VETTED_SOURCES['hak5-turtle']
flat_tree = [
    {'type': 'blob', 'path': 'modules/autossh'},
    {'type': 'blob', 'path': 'modules/dns-spoof'},
    {'type': 'blob', 'path': 'modules/module_list'},   # skipped meta file
    {'type': 'blob', 'path': 'README.md'},             # outside library_path
    {'type': 'blob', 'path': 'modules/sub/deep'},       # too deep for flat mode
]
flat_names = {p['name'] for p in _derive_payloads_from_tree(flat_tree, turtle)}
if flat_names == {'autossh', 'dns-spoof'}:
    ok("flat match-mode derives depth-1 modules and skips meta/deep entries")
else:
    fail(f'flat match-mode wrong: {sorted(flat_names)}')

# ── 3b. Description extraction (no network) ───────────────────────────────────
ducky_script = (
    "REM Title: Exfiltrate Browser Creds\n"
    "REM Author: jane.doe\n"
    "REM Description: Dumps saved browser credentials and exfils over SMB.\n"
    "DELAY 1000\nGUI r\n")
d1 = _extract_description(ducky_script, 'payloads/library/x/payload.txt')
if (d1['title'] == 'Exfiltrate Browser Creds' and d1['author'] == 'jane.doe'
        and 'exfils over SMB' in d1['description']):
    ok('payload-script REM Title/Author/Description headers parsed')
else:
    fail(f'script header extraction wrong: {d1}')

md = ("# QuickCreds\n\n"
      "![badge](https://img.shields.io/x)\n\n"
      "Grabs NetNTLMv2 hashes from a locked host using Responder.\n\n"
      "## Usage\nmore text\n")
d2 = _extract_description(md, 'payloads/library/x/README.md')
if d2['title'] == 'QuickCreds' and d2['description'].startswith('Grabs NetNTLMv2'):
    ok('markdown README title + first real paragraph parsed (badges skipped)')
else:
    fail(f'markdown extraction wrong: {d2}')

long_desc = _extract_description('REM Description: ' + ('x' * 4000), 'p.txt')['description']
if len(long_desc) <= 901 and long_desc.endswith('…'):
    ok('description is truncated to a sane length')
else:
    fail(f'description truncation wrong: len={len(long_desc)}')

# ── 4. Synced-payload merge into the library ──────────────────────────────────
implant_engine.set_synced_payloads([])  # clean slate
builtin_total = len(implant_engine.list_payloads())

n = implant_engine.set_synced_payloads([
    {'name': 'unit-test-pull', 'products': ['ducky'], 'lang': 'DuckyScript'},
    {'name': 'bad-no-product', 'products': ['not-a-real-product']},
    {'name': 'quickcreds.txt', 'products': ['bunny']},   # collides with a built-in
])
if n == 2:
    ok('set_synced_payloads dropped the payload with no valid product')
else:
    fail(f'set_synced_payloads kept {n}, expected 2 (one dropped)')

lib = implant_engine.list_payloads()
qc = [p for p in lib if p['name'] == 'quickcreds.txt']
if len(qc) == 1 and not qc[0].get('vetted'):
    ok('built-in payload wins a name collision with a synced one')
else:
    fail('name-collision precedence wrong (built-in should win)')

if any(p['name'] == 'unit-test-pull' and p.get('vetted') for p in lib):
    ok('synced payload surfaces in list_payloads with vetted flag')
else:
    fail('synced payload missing from list_payloads')

ducky_lib = implant_engine.list_payloads('ducky')
if any(p['name'] == 'unit-test-pull' for p in ducky_lib):
    ok('synced payload is filterable by product (ducky)')
else:
    fail('synced payload not filterable by product')

implant_engine.set_synced_payloads([])  # restore

# ── 5. Manager: persistence + non-vetted rejection (no network) ───────────────
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / 'payload_sources.json'
    # Pre-seed a cache file the manager should load + push to the engine on init.
    p.write_text(json.dumps({
        'sources': {'hak5-ducky': {'status': 'ok', 'count': 1,
                                   'last_synced': '2026-01-01T00:00:00+00:00'}},
        'payloads': [{'name': 'cached-pull', 'products': ['ducky'], 'lang': 'DuckyScript',
                      'callback': 'none', 'vetted': True, 'source': 'hak5-ducky'}],
    }))
    mgr = PayloadSourceManager(p)
    if any(x['name'] == 'cached-pull' for x in implant_engine.synced_payloads()):
        ok('manager loads cached payloads and registers them with the engine on init')
    else:
        fail('manager did not push cached payloads to the engine')

    srcs = mgr.sources()
    if len(srcs) == len(VETTED_SOURCES) and {s['id'] for s in srcs} == set(VETTED_SOURCES):
        ok('manager.sources() returns the full decorated vetted catalog')
    else:
        fail('manager.sources() shape wrong')
    ducky_state = next((s for s in srcs if s['id'] == 'hak5-ducky'), {})
    if ducky_state.get('status') == 'ok' and ducky_state.get('count') == 1:
        ok('manager.sources() merges persisted per-source sync state')
    else:
        fail(f'manager.sources() did not surface cached state: {ducky_state}')

    rej = mgr.update('attacker/evil-repo')
    if rej.get('status') == 'rejected':
        ok('manager.update refuses a non-vetted source_id (allowlist enforced)')
    else:
        fail(f'manager.update should reject non-vetted id, got: {rej.get("status")}')

    # describe(): allowlist + known-path enforcement (no network on these paths)
    drej = mgr.describe('attacker/evil-repo', 'whatever')
    if drej.get('status') == 'rejected':
        ok('manager.describe refuses a non-vetted source_id')
    else:
        fail(f'manager.describe should reject non-vetted id, got: {drej.get("status")}')
    dnf = mgr.describe('hak5-ducky', 'some/unknown/path/not/in/synced/set')
    if dnf.get('status') == 'not_found':
        ok('manager.describe refuses a path not in the synced set (no blind fetch)')
    else:
        fail(f'manager.describe should 404 unknown path, got: {dnf.get("status")}')

    st = mgr.stats()
    if {'sources', 'synced_payloads', 'builtin_payloads', 'total_payloads'} <= set(st):
        ok('manager.stats() reports source + payload counts')
    else:
        fail(f'manager.stats() shape wrong: {st}')

implant_engine.set_synced_payloads([])  # restore global engine state

# ── 6. Flask + UI wiring (source scan) ────────────────────────────────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
for route in ('/api/implants/sources', '/api/implants/sources/update',
              '/api/implants/sources/describe'):
    if route in app_src:
        ok(f'h3x-dash.py registers {route}')
    else:
        fail(f'h3x-dash.py missing route {route}')
if 'PayloadSourceManager' in app_src and 'payload_sources' in app_src:
    ok('h3x-dash.py instantiates the PayloadSourceManager')
else:
    fail('h3x-dash.py does not instantiate PayloadSourceManager')

html = Path('templates/payload.html').read_text(encoding='utf-8')
for anchor in ('view-p-lib', 'updateAllSources', 'src-tbody', 'syn-groups',
               'lib-group', 'lib-sort', 'lib-product'):
    if anchor in html:
        ok(f'payload.html has LIBRARY anchor {anchor}')
    else:
        fail(f'payload.html missing anchor {anchor}')

js = Path('static/payload.js').read_text(encoding='utf-8')
for fn in ('loadSources', 'updateSource', 'updateAllSources', 'renderSyncedPayloads',
           'libToggleGroup', 'libToggleDesc', 'libExpandAll', 'descHtml'):
    if fn in js:
        ok(f'payload.js defines {fn}')
    else:
        fail(f'payload.js missing {fn}')

sjs = Path('static/spectrum.js').read_text(encoding='utf-8')
for fn in ('connectSpectrumDevice', 'fillSpProduct', 'sValidate'):
    if fn in sjs:
        ok(f'spectrum.js defines {fn} (generic add for capture devices)')
    else:
        fail(f'spectrum.js missing {fn}')

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print('═' * 72)
print(f' PAYLOAD-SOURCES AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
