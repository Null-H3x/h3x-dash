#!/usr/bin/env python3
"""
audit_extensions.py — Consistency checks for plugin system, credential store,
                       and MITRE mapping. Run after touching any of:
                         modules/plugin_system.py
                         modules/credentials.py
                         modules/mitre_mapping.py
                         plugins/*.py
"""
import sys, tempfile
from pathlib import Path
import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

from modules import plugin_system, credentials, mitre_mapping, enum_engine

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

# ── Plugin system ─────────────────────────────────────────────────────────────
plugins = plugin_system.load_plugins()
errors  = plugin_system.load_errors()

if not plugins and not errors:
    ok("Plugin system loaded cleanly (no plugins, no errors)")
elif plugins:
    ok(f"Plugin system loaded {len(plugins)} plugin(s): {sorted(plugins.keys())}")
if errors:
    for e in errors:
        fail(f"plugin load error in {e['plugin']}: {e['error']}")

# Validate the example plugin if present
if 'well_known' in plugins:
    p = plugins['well_known']
    if p.tier != mitre_mapping.SEVERITY_CVSS_ESTIMATE and p.tier in (1, 2, 3):
        ok(f"well_known plugin tier={p.tier}, ports={p.ports}, services={p.services}")
    if not callable(getattr(p, 'run', None)):
        fail("well_known plugin run() not callable")

# After registration, verify dispatch tables saw the plugin
registered = plugin_system.register_with_enum_engine(enum_engine)
ok(f"register_with_enum_engine returned {registered}")
for tid in plugins:
    if tid not in enum_engine.TOOL_LABELS:
        fail(f"plugin {tid!r} missing from TOOL_LABELS after registration")
    if tid not in enum_engine.TOOL_TIERS:
        fail(f"plugin {tid!r} missing from TOOL_TIERS after registration")
    if not hasattr(enum_engine.EnumEngine, f'_run_{tid}'):
        fail(f"plugin {tid!r} runner not bound as EnumEngine._run_{tid}")
if plugins and not FAIL:
    ok(f"All {len(plugins)} plugins wired into TOOL_LABELS / TOOL_TIERS / EnumEngine")

# ── Credential store ──────────────────────────────────────────────────────────
with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tf:
    tmp_path = Path(tf.name)
try:
    store = credentials.CredentialStore(tmp_path)

    # Add → get round-trip
    cid = store.add({
        'type': 'password', 'username': 'admin',
        'value': 'hunter2', 'host_ip': '10.0.0.5', 'source_tool': 'audit',
    })
    got = store.get(cid)
    if got and got['username'] == 'admin' and got['value'] == 'hunter2':
        ok("CredentialStore add → get round-trip works")
    else:
        fail(f"CredentialStore round-trip failed: {got}")

    # Dedup
    cid2 = store.add({
        'type': 'password', 'username': 'admin',
        'value': 'hunter2', 'host_ip': '10.0.0.5', 'source_tool': 'audit',
    })
    if cid == cid2:
        ok("CredentialStore deduplicates identical creds (same id returned)")
    else:
        fail(f"CredentialStore failed dedup: cid={cid} cid2={cid2}")

    # Verification flow
    if store.mark_verified(cid, True) and store.get(cid)['verified']:
        ok("CredentialStore verification flow works")
    else:
        fail("CredentialStore mark_verified failed")

    # Bad type rejection
    try:
        store.add({'type': 'invalid_type'})
        fail("CredentialStore accepted invalid cred type (should have raised)")
    except ValueError:
        ok("CredentialStore rejects unknown cred types with ValueError")

    # Persistence
    store2 = credentials.CredentialStore(tmp_path)
    if store2.get(cid):
        ok("CredentialStore persists to disk and reloads correctly")
    else:
        fail("CredentialStore did not persist across instances")

    # creds_from_finding extractor — explicit creds list
    f1 = {
        'tool': 'kerbrute', 'host_ip': '10.0.0.5', 'port': 88,
        'creds': [{'type': 'ntlm_hash', 'username': 'svc_sql',
                   'value': 'abcd:efgh'}],
    }
    extracted = credentials.creds_from_finding(f1)
    if extracted and extracted[0]['type'] == 'ntlm_hash':
        ok("creds_from_finding extracts explicit creds list")
    else:
        fail(f"creds_from_finding explicit extraction failed: {extracted}")

    # creds_from_finding — ad_users heuristic
    f2 = {
        'tool': 'kerbrute', 'type': 'ad_users', 'host_ip': '10.0.0.5',
        'port': 88,
        'detail': 'alice, bob, carol + 7 more',
    }
    extracted = credentials.creds_from_finding(f2)
    if len(extracted) == 3 and extracted[0]['type'] == 'username_only':
        ok("creds_from_finding extracts usernames from ad_users findings")
    else:
        fail(f"creds_from_finding ad_users extraction failed: {extracted}")

    # Stats
    s = store.stats()
    if s['total'] >= 1 and s['by_type']['password'] >= 1:
        ok(f"CredentialStore.stats() reports {s['total']} total, "
           f"{s['by_type']['password']} password(s)")
    else:
        fail(f"CredentialStore.stats() unexpected: {s}")
finally:
    tmp_path.unlink(missing_ok=True)
    tmp_path.with_suffix('.tmp').unlink(missing_ok=True)

# ── MITRE / CVSS ──────────────────────────────────────────────────────────────
cov = mitre_mapping.coverage_stats()
if cov['modules_mapped'] >= 50 and cov['cves_with_cvss'] >= 30:
    ok(f"MITRE coverage: {cov['modules_mapped']} modules, "
       f"{cov['cves_with_cvss']} CVEs, {cov['techniques_labeled']} techniques")
else:
    fail(f"MITRE coverage thin: {cov}")

# Sample annotations
samples = [
    ({'tool': 'foo', 'msf_module': 'exploit/windows/smb/ms17_010_eternalblue',
      'cve': 'CVE-2017-0144', 'severity': 'HIGH'},
     'T1210', 8.1),
    ({'tool': 'foo', 'msf_module': 'auxiliary/admin/dcerpc/cve_2020_1472_zerologon',
      'cve': 'CVE-2020-1472', 'severity': 'CRITICAL'},
     'T1003.006', 10.0),
    ({'tool': 'foo', 'type': 'ad_users', 'severity': 'HIGH'},
     'T1087.002', 7.5),  # type-based, severity-based CVSS
    ({'tool': 'foo', 'type': 'unknown_type', 'severity': 'LOW'},
     None, 3.5),         # no technique, severity-based CVSS
]
all_ok = True
for finding, expect_tech, expect_score in samples:
    ann = mitre_mapping.annotate_finding(finding)
    if expect_tech and expect_tech not in ann['attack_techniques']:
        fail(f"annotate_finding missing technique {expect_tech} on {finding}")
        all_ok = False
    if abs(ann['cvss_score'] - expect_score) > 0.1:
        fail(f"annotate_finding wrong CVSS for {finding}: "
             f"got {ann['cvss_score']}, expected {expect_score}")
        all_ok = False
if all_ok:
    ok("annotate_finding correctly attributes techniques + CVSS in all samples")

# attack_matrix
matrix = mitre_mapping.attack_matrix(
    [s[0] for s in samples])
if 'T1210' in matrix and 'unmapped' in matrix:
    ok("attack_matrix groups findings by technique + handles unmapped bucket")
else:
    fail(f"attack_matrix output unexpected: keys={list(matrix.keys())}")

# Sanity: every module path in cve_chain has either an attack mapping OR is documented
from modules.cve_chain import CVE_MAP
unmapped_modules = []
for key, entries in CVE_MAP.items():
    for e in entries:
        mod = e[1]
        if mod and mod not in mitre_mapping.MODULE_ATTACK_MAP:
            unmapped_modules.append(mod)
unmapped_unique = sorted(set(unmapped_modules))
if len(unmapped_unique) <= 25:
    ok(f"MITRE coverage of chain modules: "
       f"{len(set(m[1] for entries in CVE_MAP.values() for m in entries if m[1])) - len(unmapped_unique)} "
       f"mapped, {len(unmapped_unique)} unmapped")
else:
    fail(f"MITRE coverage thin against chain — {len(unmapped_unique)} unmapped modules")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "═" * 72)
print(f" EXTENSIONS AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:")
    [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
[print(f"  ✓ {m}") for m in OK]
sys.exit(1 if FAIL else 0)
