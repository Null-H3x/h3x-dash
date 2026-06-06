#!/usr/bin/env python3
"""Static audit for Scan-tab web modes and Layer-7 wiring."""
import sys
sys.path.insert(0, '.')

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.nmap_engine import (
    NmapEngine, PORT_PROFILES, SCAN_MODES, PORT_PROFILE_DESC,
)

# ── 1. Web port profile exists ────────────────────────────────────────────────
if 'web' not in PORT_PROFILES:
    fail("PORT_PROFILES missing 'web' profile")
else:
    ports = PORT_PROFILES['web']
    if isinstance(ports, tuple):
        ports = ''.join(ports)
    for p in ('80', '443', '8080'):
        if p not in str(ports):
            fail(f"web port profile missing {p}: {ports}")
    ok(f"web port profile present: {ports}")

# ── 2. Scan modes exposed to UI ───────────────────────────────────────────────
expected_modes = {'network', 'web', 'web_only'}
if set(SCAN_MODES) != expected_modes:
    fail(f"SCAN_MODES mismatch: {set(SCAN_MODES)} vs {expected_modes}")
else:
    ok(f"SCAN_MODES covers {len(SCAN_MODES)} modes")

# ── 3. Layer-7 helpers on NmapEngine ────────────────────────────────────────
for meth in ('_expand_web_targets', '_attach_web_records', '_run_web_only'):
    if not hasattr(NmapEngine, meth):
        fail(f"NmapEngine missing {meth}")
if not FAIL:
    ok("NmapEngine Layer-7 helpers present")

# ── 4. Target expansion behaviour ─────────────────────────────────────────────
expanded = NmapEngine._expand_web_targets('10.0.0.5')
if not expanded or not any(e.startswith('10.0.0.5:') for e in expanded):
    fail(f"bare IP should expand to host:port list, got {expanded[:3]}")
else:
    ok(f"bare IP expands to {len(expanded)} web endpoints")

url_exp = NmapEngine._expand_web_targets('https://lab.local/')
if url_exp != ['https://lab.local/']:
    fail(f"URL should pass through unchanged: {url_exp}")
else:
    ok("explicit URL targets pass through unchanged")

# ── 5. UI blurbs for port profiles ───────────────────────────────────────────
if not PORT_PROFILE_DESC.get('web'):
    fail("PORT_PROFILE_DESC missing web blurb")
else:
    ok("PORT_PROFILE_DESC documents web profile")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" SCAN WIRING AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:")
    for m in FAIL: print(f"  ✗ {m}")
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
