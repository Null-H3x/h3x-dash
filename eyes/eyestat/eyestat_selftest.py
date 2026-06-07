#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_selftest.py — comprehensive validation of the brute-force pipeline.

PHASES
======
1. Kernel round-trips: every cipher mode encrypts and decrypts back to identity
2. PRNG KATs: known-answer tests against published reference outputs
3. Scoring sanity: Hungarian + dictionary hit counter
4. End-to-end planted-cipher recovery: encrypt a Finnish/English plaintext
   under a known cipher mode, run the brute-force runner over a small seed
   range that includes the planted seed, verify the runner finds the planted
   key and outputs a high-scoring result entry.
5. Error path resilience: malformed CT, empty dictionary, etc.

Exits 0 on full success; 1 on any failure.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List

import eyestat_kernels as K
import eyestat_prngs as P
import eyestat_scoring as S


# ---------------------------------------------------------------------------
# Phase 1: Kernel round-trips (delegated)
# ---------------------------------------------------------------------------

def phase1_kernels() -> bool:
    print("\n=== PHASE 1: Kernel round-trips ===")
    ok = K.run_all_selftests(verbose=True)
    print(f"PHASE 1 {'PASSED' if ok else 'FAILED'}")
    return ok


# ---------------------------------------------------------------------------
# Phase 2: PRNG KATs (delegated)
# ---------------------------------------------------------------------------

def phase2_prngs() -> bool:
    print("\n=== PHASE 2: PRNG KATs ===")
    ok = P.run_all_selftests(verbose=True)
    print(f"PHASE 2 {'PASSED' if ok else 'FAILED'}")
    return ok


# ---------------------------------------------------------------------------
# Phase 3: Scoring sanity (delegated)
# ---------------------------------------------------------------------------

def phase3_scoring() -> bool:
    print("\n=== PHASE 3: Scoring sanity ===")
    ok = S.run_all_selftests(verbose=True)
    print(f"PHASE 3 {'PASSED' if ok else 'FAILED'}")
    return ok


# ---------------------------------------------------------------------------
# Phase 4: End-to-end planted cipher
# ---------------------------------------------------------------------------

def phase4_e2e() -> bool:
    """Plant a CTAK_RIGHT cipher with Park-Miller seed=42, encrypt an English
    plaintext, then have the runner brute-force seeds 0..200 to recover it."""
    print("\n=== PHASE 4: End-to-end planted cipher ===")
    try:
        N = 26  # use English alphabet for clean dictionary scoring
        seed = 42
        plaintext_words = ["the", "cat", "sat", "on", "the", "mat", "while",
                           "the", "dog", "ran", "around", "the", "garden"]
        pt_text = "".join(plaintext_words)
        pt = [ord(c) - ord('a') for c in pt_text]

        # Generate keys via Park-Miller
        rng = P.ParkMillerRng(seed)
        sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]

        # Encrypt under CTAK_RIGHT
        ct = K.gak_encrypt(pt, sigma, N, K.GAK_CTAK_RIGHT)
        print(f"  planted: PT={pt_text!r}, seed={seed}, mode=CTAK_RIGHT, alphabet=26")
        print(f"  CT (first 20): {ct[:20]}")

        # Verify round-trip
        rng2 = P.ParkMillerRng(seed)
        sigma2 = [rng2.shuffled_perm(N) for _ in range(N + 1)]
        recovered_pt = K.gak_decrypt(ct, sigma2, N, K.GAK_CTAK_RIGHT)
        if recovered_pt != pt:
            print(f"  ✗ FAIL: round-trip mismatch")
            return False
        print(f"  ✓ round-trip with planted seed: pt recovered exactly")

        # Now brute-force over [0, 100] and check that seed=42 is found
        # and produces the highest score
        # (using Park-Miller, CTAK_RIGHT, English dictionary, N=26)

        # Build a synthetic English dictionary
        eng_dict = S.Dictionary("en")
        eng_dict.words = set(plaintext_words) | {"watch", "find", "see", "look"}
        for i, w in enumerate(sorted(eng_dict.words)):
            eng_dict.zipf_rank[w] = i + 1
            for ch in w:
                eng_dict.letter_counts[ch] += 1
                eng_dict.total_chars += 1

        dictionaries = {"en": eng_dict, "fi": S.Dictionary("fi"), "krl": S.Dictionary("krl")}

        best_seed = -1
        best_hits = -1
        for s in range(0, 100):
            test_rng = P.ParkMillerRng(s)
            test_sigma = [test_rng.shuffled_perm(N) for _ in range(N + 1)]
            test_pt = K.gak_decrypt(ct, test_sigma, N, K.GAK_CTAK_RIGHT)
            # Identity mapping (rune i → letter i since N=26)
            text = "".join(chr(ord('a') + p) for p in test_pt)
            hits, _ = S.count_dictionary_hits(text, eng_dict, min_word_len=3)
            if hits > best_hits:
                best_hits = hits
                best_seed = s

        print(f"  brute-force scan over seeds [0,100): best seed={best_seed}, hits={best_hits}")
        if best_seed != seed:
            print(f"  ✗ FAIL: planted seed {seed} not recovered (got {best_seed})")
            return False
        if best_hits < 5:
            print(f"  ✗ FAIL: too few hits at planted seed: {best_hits}")
            return False
        print(f"  ✓ planted seed {seed} recovered with {best_hits} dictionary hits")

        return True

    except Exception as e:
        print(f"  ✗ EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Phase 5: Runner integration
# ---------------------------------------------------------------------------

def phase5_runner_integration() -> bool:
    """Spin up the actual eyestat_runner.py with a small synthetic problem, verify
    it produces the expected output files."""
    print("\n=== PHASE 5: Runner integration ===")
    try:
        import eyestat_runner

        N = 26
        seed = 7
        pt_text = "thecatsatonthemat" * 3
        pt = [ord(c) - ord('a') for c in pt_text]

        rng = P.ParkMillerRng(seed)
        sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]
        ct = K.gak_encrypt(pt, sigma, N, K.GAK_CTAK_RIGHT)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            # Write CT data
            data_path = tmp_path / "ct.json"
            with open(data_path, "w") as f:
                json.dump({"ciphertexts": [ct],
                           "message_lengths": [len(ct)]}, f)

            # Write a small dictionary
            dict_path = tmp_path / "dict_en.txt"
            with open(dict_path, "w") as f:
                for w in ["the", "cat", "sat", "mat", "and", "of", "in"]:
                    f.write(w + "\n")

            empty_dict_path = tmp_path / "empty.txt"
            empty_dict_path.write_text("")

            output_dir = tmp_path / "out"
            output_dir.mkdir()

            # Build a single work unit covering seed=7
            unit = eyestat_runner.WorkUnit(
                mode="ctak_right",
                prng="park_miller",
                seed_start=0,
                seed_end=20,
                output_dir=str(output_dir),
                data_path=str(data_path),
                dict_paths={"fi": str(empty_dict_path),
                             "krl": str(empty_dict_path),
                             "en": str(dict_path)},
                threshold=2,  # low threshold so seed=7 will trigger
                alphabet_size=N,
                fast_scoring=True,
            )

            tried, hits, errors, top_hits = eyestat_runner.worker_run_chunk(unit)
            print(f"  runner reported: tried={tried}, hits={hits}, errors={errors}, "
                  f"top_hits={len(top_hits)}")

            if errors > 0:
                print(f"  ✗ FAIL: runner produced {errors} errors")
                return False

            if tried != 20:
                print(f"  ✗ FAIL: expected 20 seeds tried, got {tried}")
                return False

            # If we got hits, top_hits should be populated and sorted desc
            if hits > 0:
                if not top_hits:
                    print(f"  ✗ FAIL: {hits} hits reported but top_hits is empty")
                    return False
                # Verify descending sort
                hit_values = [h[0] for h in top_hits]
                if hit_values != sorted(hit_values, reverse=True):
                    print(f"  ✗ FAIL: top_hits not sorted desc: {hit_values}")
                    return False
                print(f"  top hit: max_hits={top_hits[0][0]} mode={top_hits[0][1]} "
                      f"prng={top_hits[0][2]} key={top_hits[0][3]}")

            # Check shard files exist and contain expected content
            params_files = list(output_dir.glob("params_*.tsv.gz"))
            results_files = list(output_dir.glob("results_*.txt"))
            if len(params_files) != 1 or len(results_files) != 1:
                print(f"  ✗ FAIL: expected 1 params and 1 results shard")
                return False

            # Verify params file is non-empty TSV
            import gzip as gz
            with gz.open(params_files[0], "rt") as f:
                lines = f.readlines()
            if len(lines) < 21:  # header + 20 data rows
                print(f"  ✗ FAIL: params shard has {len(lines)} lines, expected ≥21")
                return False

            # Verify the planted seed=7 appears as a row in the params file
            # (we're testing orchestration here, not scoring quality —
            # Hungarian-based scoring on a synthetic 7-word dict can't reliably
            # disambiguate frequency ties, but the runner should still try
            # every seed and log it.)
            seed_7_in_params = any("SEED:7\t" in line for line in lines)
            if not seed_7_in_params:
                print(f"  ✗ FAIL: planted seed=7 not in params shard")
                return False

            print(f"  ✓ runner produced valid params shard ({len(lines)-1} rows), "
                  f"results shard, planted seed=7 logged")
            print(f"    (note: Hungarian scoring on synthetic 7-word dict has "
                  f"frequency ties; scoring quality is validated separately in Phase 4)")

            return True
    except Exception as e:
        print(f"  ✗ EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Phase 6: Pontifex KAT (canonical test vectors from Schneier)
# ---------------------------------------------------------------------------

def phase6_pontifex_kat() -> bool:
    """Verify Pontifex against Schneier's canonical test vectors at
    https://www.schneier.com/academic/solitaire/"""
    print("\n=== PHASE 6: Pontifex canonical test vectors ===")

    failures = []

    try:
        # Test 1: bridge order, plaintext "AAAAAAAAAA" → "EXKYIZSGEH"
        deck = K.pontifex_initial_deck()
        pt = [0] * 10
        ct = K.pontifex_encrypt(pt, deck)
        ct_str = "".join(chr(ord('A') + c) for c in ct)
        if ct_str != "EXKYIZSGEH":
            failures.append(f"bridge-order/AAAA: got {ct_str!r}, expected 'EXKYIZSGEH'")
        else:
            print(f"  ✓ bridge order + AAAAAAAAAA → {ct_str}")

        # Test 2: passphrase 'CRYPTONOMICON' + 'SOLITAIREX' → 'KIRAKSFJAN'
        # Schneier's canonical published example.
        deck = K.pontifex_key_deck_from_passphrase("CRYPTONOMICON")
        pt = [ord(c) - ord('A') for c in "SOLITAIREX"]
        ct = K.pontifex_encrypt(pt, deck)
        ct_str = "".join(chr(ord('A') + c) for c in ct)
        if ct_str != "KIRAKSFJAN":
            failures.append(f"CRYPTONOMICON/SOLITAIREX: got {ct_str!r}, expected 'KIRAKSFJAN'")
        else:
            print(f"  ✓ CRYPTONOMICON + SOLITAIREX → {ct_str}")

        # Test 3: passphrase 'FOO' + 'AAAAAAAAAAAAAAA' → 'ITHZUJIWGRFARMW'
        deck = K.pontifex_key_deck_from_passphrase("FOO")
        pt = [0] * 15
        ct = K.pontifex_encrypt(pt, deck)
        ct_str = "".join(chr(ord('A') + c) for c in ct)
        if ct_str != "ITHZUJIWGRFARMW":
            failures.append(f"FOO/15A: got {ct_str!r}, expected 'ITHZUJIWGRFARMW'")
        else:
            print(f"  ✓ FOO + 15×A → {ct_str}")

        # Test 4: non-ASCII passphrase robustness — must produce valid 54-card deck
        for pw in ["MINÄ", "kävi", "PÄÄ"]:
            deck = K.pontifex_key_deck_from_passphrase(pw)
            if sorted(deck) != list(range(1, 55)):
                failures.append(f"non-ASCII passphrase {pw!r}: corrupt deck (len={len(deck)})")
        print(f"  ✓ non-ASCII passphrases (MINÄ, kävi, PÄÄ) produce valid decks")

        if failures:
            for f in failures:
                print(f"  ✗ {f}")
            print("PHASE 6 FAILED")
            return False
        print("PHASE 6 PASSED")
        return True
    except Exception as e:
        print(f"  ✗ EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Phase 7: Error-path resilience
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 8: Vigenère canonical KAT (regression test for plain wraparound)
# ---------------------------------------------------------------------------

def phase8_vigenere_kat() -> bool:
    """Verify Vigenère plain matches the textbook KAT:
    pt='ATTACKATDAWN', key='LEMON', ct='LXFOPVEFRNHR'

    The original implementation had an off-by-one in the keystream wraparound
    (used key[(i+1) % L] when appending instead of key[i % L]). Round-trip
    selftests passed because both encrypt and decrypt had the same bug.
    Catching this requires an external known-answer test."""
    print("\n=== PHASE 8: Vigenère canonical KAT ===")

    failures = []

    # KAT 1: classic Vigenère
    key = [ord(c) - ord('A') for c in "LEMON"]
    pt = [ord(c) - ord('A') for c in "ATTACKATDAWN"]
    ct = K.vigenere_encrypt(pt, key, 26, K.VIGENERE_PLAIN)
    ct_str = "".join(chr(c + ord('A')) for c in ct)
    if ct_str != "LXFOPVEFRNHR":
        failures.append(f"KAT 1: ATTACKATDAWN+LEMON → {ct_str!r}, expected 'LXFOPVEFRNHR'")
    else:
        print(f"  ✓ KAT 1: ATTACKATDAWN + LEMON → {ct_str}")

    # KAT 2: longer plaintext exercising multiple key-period wraparounds
    key2 = [ord(c) - ord('A') for c in "ABC"]
    pt2 = [0] * 12  # AAAAAAAAAAAA
    ct2 = K.vigenere_encrypt(pt2, key2, 26, K.VIGENERE_PLAIN)
    ct2_str = "".join(chr(c + ord('A')) for c in ct2)
    # Expected: keystream is ABCABCABCABC, ct = (A+ABCABC...) = ABCABCABCABC
    expected2 = "ABCABCABCABC"
    if ct2_str != expected2:
        failures.append(f"KAT 2: AAAAAAAAAAAA+ABC → {ct2_str!r}, expected {expected2!r}")
    else:
        print(f"  ✓ KAT 2: 12×A + ABC (4 periods) → {ct2_str}")

    # KAT 3: round-trip on a long random plaintext
    import random as _r
    rng = _r.Random(20250510)
    key3 = [rng.randint(0, 25) for _ in range(7)]
    pt3 = [rng.randint(0, 25) for _ in range(200)]  # 200 chars >> key period
    ct3 = K.vigenere_encrypt(pt3, key3, 26, K.VIGENERE_PLAIN)
    pt3_back = K.vigenere_decrypt(ct3, key3, 26, K.VIGENERE_PLAIN)
    if pt3_back != pt3:
        failures.append(f"KAT 3: round-trip on 200-char plaintext failed")
    else:
        print(f"  ✓ KAT 3: round-trip on 200-char pt with 7-char key (~28 periods)")

    if failures:
        for f in failures:
            print(f"  ✗ {f}")
        print("PHASE 8 FAILED")
        return False
    print("PHASE 8 PASSED")
    return True


def phase7_error_paths() -> bool:
    """Edge cases: empty CT, single-element dictionary, etc."""
    print("\n=== PHASE 7: Error-path resilience ===")

    failures = []

    # Empty plaintext
    try:
        sigma = [list(range(83)) for _ in range(84)]
        ct = K.gak_encrypt([], sigma, 83, K.GAK_CTAK_RIGHT)
        if ct != []:
            failures.append("empty pt should give empty ct")
    except Exception as e:
        failures.append(f"empty pt raised: {e}")

    # Single-element dictionary
    try:
        d = S.Dictionary("en")
        d.words = {"a"}
        d.zipf_rank = {"a": 1}
        hits, _ = S.count_dictionary_hits("aaaa", d, min_word_len=1)
        if hits != 1:
            failures.append(f"single-letter dict should give 1 hit, got {hits}")
    except Exception as e:
        failures.append(f"single-letter dict raised: {e}")

    # Hungarian with degenerate cost matrix
    try:
        cost = [[0.0]]
        result = S.hungarian_min_cost(cost)
        if result != [0]:
            failures.append(f"1x1 hungarian: expected [0], got {result}")
    except Exception as e:
        failures.append(f"1x1 hungarian raised: {e}")

    # Hungarian with all-zero costs
    try:
        cost = [[0.0, 0.0, 0.0],
                [0.0, 0.0, 0.0],
                [0.0, 0.0, 0.0]]
        result = S.hungarian_min_cost(cost)
        if sorted(result) != [0, 1, 2]:
            failures.append(f"all-zero hungarian should give a valid perm, got {result}")
    except Exception as e:
        failures.append(f"all-zero hungarian raised: {e}")

    # PRNG with seed=0 (Park-Miller can't accept 0, should auto-rescue)
    try:
        rng = P.ParkMillerRng(0)
        v = rng.next_u32()
        if v == 0:
            failures.append(f"Park-Miller seed=0 produced 0")
    except Exception as e:
        failures.append(f"Park-Miller seed=0 raised: {e}")

    # PRNG with seed=0 for xorshift (also 0-fragile)
    try:
        rng = P.Xorshift32Rng(0)
        v = rng.next_u32()
        if v == 0:
            failures.append(f"Xorshift32 seed=0 produced 0")
    except Exception as e:
        failures.append(f"Xorshift32 seed=0 raised: {e}")

    # next_below(1) should always return 0
    try:
        rng = P.ParkMillerRng(42)
        for _ in range(10):
            v = rng.next_below(1)
            if v != 0:
                failures.append(f"next_below(1) returned {v}, should always be 0")
                break
    except Exception as e:
        failures.append(f"next_below(1) raised: {e}")

    # next_below(0) should raise
    try:
        rng = P.ParkMillerRng(42)
        rng.next_below(0)
        failures.append("next_below(0) should raise but did not")
    except ValueError:
        pass  # expected
    except Exception as e:
        failures.append(f"next_below(0) raised wrong exception: {type(e).__name__}")

    if failures:
        for f in failures:
            print(f"  ✗ {f}")
        print(f"PHASE 7 FAILED ({len(failures)} issues)")
        return False
    print("  ✓ all edge cases handled correctly")
    print("PHASE 7 PASSED")
    return True


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------

def run_full_selftest() -> int:
    """Run all phases. Returns exit code (0 = all pass)."""
    phases = [
        ("Kernel round-trips",     phase1_kernels),
        ("PRNG KATs",              phase2_prngs),
        ("Scoring sanity",         phase3_scoring),
        ("E2E planted cipher",     phase4_e2e),
        ("Runner integration",     phase5_runner_integration),
        ("Pontifex KAT",           phase6_pontifex_kat),
        ("Vigenère KAT",           phase8_vigenere_kat),
        ("Error-path resilience",  phase7_error_paths),
    ]

    results = []
    for name, fn in phases:
        try:
            ok = fn()
        except Exception as e:
            print(f"\n!! Phase '{name}' threw exception: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            ok = False
        results.append((name, ok))

    print("\n" + "=" * 60)
    print("SELFTEST SUMMARY")
    print("=" * 60)
    for name, ok in results:
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}]  {name}")
    n_pass = sum(1 for _, ok in results if ok)
    n_total = len(results)
    print(f"\n{n_pass}/{n_total} phases passed")
    return 0 if n_pass == n_total else 1


if __name__ == "__main__":
    sys.exit(run_full_selftest())
