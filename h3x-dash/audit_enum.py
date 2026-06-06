#!/usr/bin/env python3
"""Paranoia audit for enum tool wiring — runners ↔ labels ↔ tiers ↔ dispatch."""
import sys; sys.path.insert(0, '.')
from modules.enum_engine import (
    EnumEngine, TOOL_LABELS, TOOL_TIERS, PORT_TOOLS, SERVICE_TOOLS,
    TOOL_AVAILABILITY_CATEGORIES,
    TIER_RECON, TIER_STANDARD, TIER_DEEP,
)

FAIL, OK = [], []
def fail(m): FAIL.append(m)
def ok(m):   OK.append(m)

# Helpers
methods = {m for m in dir(EnumEngine)
           if m.startswith('_run_') and m not in ('_run_cmd', '_run')}
labeled = set(TOOL_LABELS.keys())
api_tools = set(EnumEngine.available_tools().keys())

# ── 1. Every TOOL_LABELS entry has a backing _run_<id> method ─────────────────
for tid in labeled:
    if f'_run_{tid}' not in methods:
        fail(f"label '{tid}' has no EnumEngine._run_{tid}() method")
without_label = {m[5:] for m in methods} - labeled
for tid in without_label:
    fail(f"runner _run_{tid} has no TOOL_LABELS entry — won't show in UI")
if not FAIL:
    ok(f"All {len(labeled)} labels have backing runner methods (and vice-versa)")

# ── 2. Every TOOL_TIERS entry is labeled ──────────────────────────────────────
unlabeled_tier = set(TOOL_TIERS) - labeled
if unlabeled_tier:
    fail(f"TOOL_TIERS entries with no label: {unlabeled_tier}")
else:
    ok(f"All {len(TOOL_TIERS)} tier-mapped tools have labels")

# ── 3. Every tool referenced in PORT_TOOLS / SERVICE_TOOLS is wired ───────────
refs = set()
for v in PORT_TOOLS.values():    refs.update(v)
for v in SERVICE_TOOLS.values(): refs.update(v)
orphans = refs - labeled
if orphans:
    fail(f"PORT/SERVICE_TOOLS reference unlabeled tools: {orphans}")
no_tier = refs - set(TOOL_TIERS)
if no_tier:
    fail(f"PORT/SERVICE_TOOLS reference untiered tools (default Tier 2): {no_tier}")
if not orphans and not no_tier:
    ok(f"All {len(refs)} port/service-referenced tools fully wired")

# ── 4. available_tools() coverage ─────────────────────────────────────────────
not_in_api = labeled - api_tools
# Runner IDs that legitimately have no single binary to check:
#   - Composite runners that delegate to OTHER already-tracked tools
#     (snmp_check → onesixtyone+snmpwalk; ssh_audit → ssh-audit binary;
#      ldap_enum → ldapsearch; rdp_check → nmap NSE; gobuster_ssl → gobuster)
#   - Pure-Python socket / protocol probes (ftp_anon, vnc_check, redis_check,
#     elastic_check, mongo_check, smtp_enum)
#   - Aliases for binaries tracked under their canonical name
#     (smbnull→smbclient; rpcnull→rpcclient; testssl→testssl.sh;
#      enum4linux→enum4linux-ng)
COMPOSITE_OR_ALIAS = {
    'ftp_anon', 'vnc_check', 'redis_check', 'elastic_check', 'mongo_check',
    'smtp_enum', 'snmp_check', 'ldap_enum', 'ssh_audit', 'rdp_check',
    'gobuster_ssl', 'smbnull', 'rpcnull', 'testssl', 'enum4linux',
}
real_gaps = not_in_api - COMPOSITE_OR_ALIAS
if real_gaps:
    fail(f"labels with no available_tools() check: {real_gaps}")
else:
    ok(f"available_tools() covers every dispatchable tool "
       f"(plus {len(COMPOSITE_OR_ALIAS)} composite runners noted)")

# ── 4b. Tool Availability UI categories cover every binary key ────────────────
cat_keys = {k for _, tools in TOOL_AVAILABILITY_CATEGORIES for k, _ in tools}
missing_cat = api_tools - cat_keys
extra_cat   = cat_keys - api_tools
if missing_cat:
    fail(f"TOOL_AVAILABILITY_CATEGORIES missing keys: {sorted(missing_cat)}")
if extra_cat:
    fail(f"TOOL_AVAILABILITY_CATEGORIES unknown keys: {sorted(extra_cat)}")
layout = EnumEngine.tool_availability_layout()
if not layout or not all(c.get('tools') for c in layout):
    fail("tool_availability_layout() returned empty categories")
else:
    ok(f"Tool Availability UI covers all {len(api_tools)} binary keys "
       f"in {len(layout)} categories")

# ── 5. Dispatch sim — Windows AD host & Linux web host ────────────────────────
def candidates_for(ports: list[int]) -> set[str]:
    fired = set()
    for p in ports:
        fired.update(PORT_TOOLS.get(p, []))
    return fired

def dispatch_for(ports: list[int], tier: int = TIER_STANDARD) -> set[str]:
    return {t for t in candidates_for(ports)
            if TOOL_TIERS.get(t, TIER_STANDARD) <= tier}

ad_fired   = candidates_for([21, 22, 53, 80, 88, 139, 389, 443, 445, 3389])
linux_fired = candidates_for([21, 22, 80, 443, 3306, 5432, 6379])
new_tools = {'wafw00f','sslscan','smbnull','rpcnull','wpscan','droopescan',
             'ffuf','kerbrute','ldapdomaindump','dnsenum'}

ad_hits    = sorted(ad_fired   & new_tools)
linux_hits = sorted(linux_fired & new_tools)
if len(ad_hits) >= 8:
    ok(f"Windows AD host fires {len(ad_hits)}/{len(new_tools)} new tools: {ad_hits}")
else:
    fail(f"AD host should fire ≥8 new tools, got {len(ad_hits)}: {ad_hits}")
if len(linux_hits) >= 4:
    ok(f"Linux web host fires {len(linux_hits)} new tools: {linux_hits}")
else:
    fail(f"Linux web host should fire ≥4 new tools, got {len(linux_hits)}")

# ── 5b. Tier discipline — web port 80 / TLS 443 ───────────────────────────────
recon_80 = dispatch_for([80], TIER_RECON)
want_recon_80 = {'httpx', 'wafw00f', 'whatweb'}
if recon_80 != want_recon_80:
    fail(f"Recon tier on :80 should be {want_recon_80}, got {recon_80}")
else:
    ok("Recon :80 fires httpx + wafw00f + whatweb only")

std_80 = dispatch_for([80], TIER_STANDARD)
if not {'nikto', 'gobuster'}.issubset(std_80):
    fail(f"Standard :80 missing nikto/gobuster: {std_80}")
if std_80 & {'nuclei', 'feroxbuster', 'wpscan'}:
    fail(f"Standard :80 should not fire deep tools: {std_80 & {'nuclei','feroxbuster','wpscan'}}")
else:
    ok("Standard :80 adds nikto/gobuster without deep CMS/fuzz tools")

recon_443 = dispatch_for([443], TIER_RECON)
if not {'httpx', 'sslscan'}.issubset(recon_443):
    fail(f"Recon :443 should include httpx + sslscan, got {recon_443}")
if 'sslyze' in recon_443 or 'testssl' in recon_443:
    fail(f"Recon :443 should not run sslyze/testssl: {recon_443}")
else:
    ok("Recon :443 triages HTTP + fast TLS (sslscan) only")

deep_443 = dispatch_for([443], TIER_DEEP)
if not {'testssl', 'nuclei'}.issubset(deep_443):
    fail(f"Deep :443 missing testssl/nuclei: {deep_443}")
else:
    ok("Deep :443 enables testssl + nuclei")

# ── 6. Tier distribution sanity ───────────────────────────────────────────────
by_tier = {1: [], 2: [], 3: []}
for tid, t in TOOL_TIERS.items():
    if tid in new_tools:
        by_tier.setdefault(t, []).append(tid)
print("\nTier placement of new tools:")
print(f"  Tier 1 (Recon)    : {sorted(by_tier.get(1, []))}")
print(f"  Tier 2 (Standard) : {sorted(by_tier.get(2, []))}")
print(f"  Tier 3 (Deep)     : {sorted(by_tier.get(3, []))}")

# ── 7. _run_cmd kills the whole process tree (grandchild-pipe hang fix) ───────
# Reproduce the exact enum4linux-ng hang: a process that spawns a child which
# inherits stdout and outlives the parent. Without process-group kill, the
# read loop blocks forever on the inherited pipe. With it, the timeout kills
# the whole group and _run_cmd returns promptly.
import time as _time
import tempfile as _tf
import os as _os

# A parent shell that spawns a backgrounded child sleeping 60s while holding
# stdout, then the parent itself sleeps. If we only kill the parent, the child
# keeps the pipe open. Process-group kill takes out both.
hang_script = (
    'sleep 60 & '          # backgrounded child inherits stdout, sleeps 60s
    'echo started; '       # emit one line so we know it ran
    'sleep 60'             # parent also sleeps
)

eng = EnumEngine.__new__(EnumEngine)   # bare instance, no full init needed
emitted = []
start = _time.time()
rc, lines = eng._run_cmd(['/bin/sh', '-c', hang_script],
                          emit=lambda l: emitted.append(l),
                          timeout=3)
elapsed = _time.time() - start

if elapsed < 10 and rc == -1:
    ok(f"_run_cmd process-group kill works — hung command (parent+child both "
       f"holding stdout) terminated in {elapsed:.1f}s, not 60s+")
else:
    fail(f"_run_cmd didn't kill process tree promptly: elapsed={elapsed:.1f}s, "
         f"rc={rc} (expected <10s and rc=-1)")

# Verify start_new_session is actually used (the mechanism that enables killpg)
import inspect as _inspect
src = _inspect.getsource(EnumEngine._run_cmd)
if 'start_new_session=True' in src and 'killpg' in src:
    ok("_run_cmd uses start_new_session + killpg (grandchildren reachable)")
else:
    fail("_run_cmd missing process-group mechanism (start_new_session/killpg)")

# Verify enum4linux-ng invocation carries the -t connection timeout
e4l_src = _inspect.getsource(EnumEngine._run_enum4linux)
if "'-t'" in e4l_src:
    ok("enum4linux-ng invocation includes -t connection timeout (fail-fast)")
else:
    fail("enum4linux-ng missing -t connection timeout — will hang on slow RPC")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "═" * 72)
print(f" ENUM WIRING AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:"); [print(f"  ✓ {m}") for m in OK]
sys.exit(1 if FAIL else 0)
