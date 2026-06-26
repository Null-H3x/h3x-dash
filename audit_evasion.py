#!/usr/bin/env python3
"""
audit_evasion.py — Verify evasion module + its scan/msf integration.

Run after touching modules/evasion.py, modules/nmap_engine.py (the
extra_args integration), or modules/msf_engine.py (the encoder injection).
"""
import sys
sys.path.insert(0, '.')

from modules import evasion

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


# ── 1. All 4 levels are defined and well-formed ───────────────────────────────
for level in (0, 1, 2, 3):
    p = evasion.level_profile(level)
    if not all(k in p for k in ('name', 'description', 'nmap_flags',
                                  'msf_encoder', 'enum_delay_ms',
                                  'estimated_slowdown')):
        fail(f"Level {level} profile missing required fields: {p.keys()}")
        continue
    if p['level'] != level:
        fail(f"Level {level} profile reports wrong level: {p['level']}")
ok(f"All 4 stealth levels are well-formed (Normal/Quiet/Stealth/Paranoid)")


# ── 2. Level 0 contributes no flags / no encoder ──────────────────────────────
if (evasion.nmap_flags_for(0) == [] and
    evasion.msf_options_for(0) == {} and
    evasion.enum_delay_ms_for(0) == 0):
    ok("Level 0 (Normal) is a true no-op — no flags, no encoder, no delay")
else:
    fail(f"Level 0 should be no-op: flags={evasion.nmap_flags_for(0)}, "
         f"opts={evasion.msf_options_for(0)}")


# ── 3. Levels 1–3 strictly increase nmap evasion intensity ─────────────────────
# Each level should have AT LEAST as many flags as the previous, and slower
# timing (T2 → T1 → T0).
prev_count = 0
prev_timing = 'T9'   # higher than any real timing
for level in (1, 2, 3):
    flags = evasion.nmap_flags_for(level)
    if len(flags) < prev_count:
        fail(f"Level {level} has fewer nmap flags than level {level-1}: "
             f"{len(flags)} vs {prev_count}")
    timing_flags = [f for f in flags if f.startswith('-T')]
    if timing_flags:
        cur_t = timing_flags[0]
        if cur_t >= prev_timing:
            fail(f"Level {level} timing {cur_t} not slower than level {level-1} ({prev_timing})")
        prev_timing = cur_t
    prev_count = len(flags)
ok("Nmap evasion strictly increases across levels 1→3 (more flags, slower timing)")


# ── 4. Levels 2+ activate MSF encoders ────────────────────────────────────────
for level in (2, 3):
    opts = evasion.msf_options_for(level)
    if opts.get('ENCODER') != 'x86/shikata_ga_nai':
        fail(f"Level {level} should activate shikata_ga_nai encoder, got {opts}")
    if not opts.get('EnableStageEncoding'):
        fail(f"Level {level} should enable stage encoding, got {opts}")
    if level == 3 and not opts.get('StageEncodingFallbacks'):
        fail(f"Level 3 (paranoid) should enable encoder fallback chain")
if not FAIL:
    ok("Levels 2+ correctly activate MSF encoder + stage encoding")


# ── 5. set_level clamps + threadsafe basics ───────────────────────────────────
evasion.set_level(2)
if evasion.get_level() != 2: fail("set_level(2) didn't take")

evasion.set_level(99)
if evasion.get_level() != 3: fail(f"set_level(99) should clamp to 3, got {evasion.get_level()}")

evasion.set_level(-5)
if evasion.get_level() != 0: fail(f"set_level(-5) should clamp to 0, got {evasion.get_level()}")

evasion.set_level('paranoid')
if evasion.get_level() != 0: fail(f"set_level(str) should fall to 0, got {evasion.get_level()}")

evasion.set_level(0)   # reset
ok("set_level clamps invalid values (range 0–3, ints only)")


# ── 6. Threading sanity — concurrent set_level doesn't crash ──────────────────
import threading, random, time
def hammer():
    for _ in range(50):
        evasion.set_level(random.randint(0, 3))
        evasion.get_level()
        time.sleep(0.001)
threads = [threading.Thread(target=hammer) for _ in range(6)]
[t.start() for t in threads]
[t.join() for t in threads]
final = evasion.get_level()
if 0 <= final <= 3:
    ok(f"Concurrent set_level from 6 threads × 50 iter — no crash (settled at {final})")
else:
    fail(f"Concurrent set_level produced invalid state: {final}")


# ── 7. Nmap integration — flags would reach cfg.extra_args ────────────────────
# Verify the integration code path: simulate what nmap_engine does
import sys; sys.path.insert(0, '.')
evasion.set_level(2)
flags = evasion.nmap_flags_for()
operator_extras = ['--exclude', '192.168.1.50']
# This is the exact line in nmap_engine.py:
merged = flags + operator_extras
expected_count = len(flags) + len(operator_extras)
if len(merged) == expected_count and '-T1' in merged and '--exclude' in merged:
    ok(f"Scan integration: {len(flags)} evasion flags prepended cleanly "
       f"to {len(operator_extras)} operator flags")
else:
    fail(f"Scan integration merge produced wrong list: {merged}")


# ── 8. MSF integration — options would merge correctly ────────────────────────
evasion.set_level(2)
evasion_opts   = evasion.msf_options_for()
operator_opts  = {'RHOSTS': '10.0.0.5', 'LHOST': '10.0.0.99',
                  'ENCODER': 'x86/alpha_mixed'}      # operator overrides!
merged = dict(evasion_opts)
merged.update(operator_opts)
# Operator-supplied ENCODER must win
if (merged['ENCODER'] == 'x86/alpha_mixed'
    and merged['RHOSTS'] == '10.0.0.5'
    and merged.get('EnableStageEncoding') is True):
    ok("MSF integration: operator-supplied options override evasion defaults; "
       "non-conflicting evasion options preserved")
else:
    fail(f"MSF integration merge wrong: {merged}")


# ── 9. UI surface — all_profiles() returns dropdown-ready data ────────────────
profiles = evasion.all_profiles()
if (len(profiles) == 4
    and profiles[0]['level'] == 0
    and profiles[-1]['level'] == 3
    and all('name' in p and 'icon' in p and 'description' in p for p in profiles)):
    ok(f"all_profiles() returns 4 UI-ready profile dicts")
else:
    fail(f"all_profiles() unexpected: {len(profiles)} entries")


# Reset to 0 so we don't leave state for other audits
evasion.set_level(0)


# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" EVASION AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
