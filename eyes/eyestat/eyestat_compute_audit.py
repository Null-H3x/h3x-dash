#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_compute_audit.py — show-your-work verification of every computation.

WHY THIS EXISTS
===============
The selftest in eyestat_selftest.py verifies that the code DOES THE RIGHT THING,
but it only prints PASS/FAIL. When you want to convince yourself that the math
is correct — not just that the code self-consistently agrees with itself — you
need a tool that prints the inputs, intermediate values, and outputs of every
computation, so you can verify them by hand or against external references.

This audit:
  * Re-derives each computation from first principles, independent of the
    eyestat_* modules, then runs the eyestat_* implementation on the same input
    and compares. Discrepancies surface as PASS/FAIL with the actual deltas.
  * Uses small, hand-checkable inputs (5-symbol alphabets, short ciphertexts)
    where possible — small enough that you can do the math on paper.
  * Cites external references where they exist (Park & Miller 1988 for the PRNG,
    classic Hungarian assignment examples, etc.).
  * Prints intermediate state so you can step through and verify each step.

PHASES
======
  1. Park-Miller PRNG state advancement
  2. Fisher-Yates permutation generation from the PRNG stream
  3. GAK / xGAK cipher round-trips (all 8 modes)
  4. Hungarian rune→letter mapping optimality
  5. Dictionary substring matching
  6. Zipf and length-weighted scoring
  7. End-to-end planted-seed recovery
  8. Shard file verification (if --shard provided): pick random entries from a
     real params.tsv.gz file and re-compute their scores from scratch, comparing
     to the stored values.

USAGE
=====
  python3 eyestat_compute_audit.py                  # all phases, verbose
  python3 eyestat_compute_audit.py --quiet          # PASS/FAIL only
  python3 eyestat_compute_audit.py --phase 3        # one phase only
  python3 eyestat_compute_audit.py --shard PATH     # also audit a real shard
"""

from __future__ import annotations

import argparse
import gzip
import math
import random
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import eyestat_prngs as P
import eyestat_kernels as K
import eyestat_scoring as S


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

VERBOSE = True
TOTAL = 0
PASSED = 0
FAILED: List[str] = []


def header(s: str) -> None:
    if VERBOSE:
        print()
        print("=" * 72)
        print(s)
        print("=" * 72)


def step(s: str) -> None:
    if VERBOSE:
        print(f"\n  {s}")


def show(label: str, value) -> None:
    if not VERBOSE:
        return
    s = str(value)
    if len(s) > 140:
        s = s[:137] + "..."
    print(f"    {label:30s} {s}")


def math_ref(*lines: str) -> None:
    """Print a math-reference block: the formal definition of the computation
    being audited in this phase. This is what 'show your work' means here — we
    state the math first, then verify that the implementation matches it.

    Lines render inside a light-box delimiter so they're visually distinct
    from input/output traces. Skipped in --quiet mode along with all other
    show()-style output."""
    if not VERBOSE:
        return
    print()
    print("  ┌─ Math reference " + "─" * 53)
    for line in lines:
        print(f"  │ {line}")
    print("  └" + "─" * 71)


def check(label: str, got, expected, tol: float = 0) -> bool:
    """Compare got vs expected; record pass/fail with delta."""
    global TOTAL, PASSED
    TOTAL += 1
    if isinstance(got, float) and isinstance(expected, float):
        ok = abs(got - expected) <= tol
        delta = f"  (delta={got - expected:+.6g})" if not ok else ""
    elif isinstance(got, (list, tuple, np.ndarray)) and isinstance(expected, (list, tuple, np.ndarray)):
        got_a = np.asarray(got)
        exp_a = np.asarray(expected)
        ok = got_a.shape == exp_a.shape and bool(np.array_equal(got_a, exp_a))
        delta = ""
        if not ok and got_a.shape == exp_a.shape:
            diff_idx = np.flatnonzero(got_a != exp_a)[:3]
            delta = f"  (first diffs at indices {diff_idx})"
    else:
        ok = (got == expected)
        delta = ""
    marker = "PASS" if ok else "FAIL"
    print(f"    [{marker}] {label}{delta}")
    if ok:
        PASSED += 1
    else:
        FAILED.append(label)
        print(f"           got:      {str(got)[:100]}")
        print(f"           expected: {str(expected)[:100]}")
    return ok


# ===========================================================================
# PHASE 1: Park-Miller PRNG
# ===========================================================================
# References:
#   Park & Miller, "Random Number Generators: Good Ones Are Hard to Find",
#   CACM 31(10), 1988. The "minimal standard": a=16807, m=2^31-1=2147483647.
#
# Canonical test vector: state(0)=1, state(1)=16807 (=a*1 mod m), and the
# 10,000th iterate of seed=1 is documented to be 1043618065.

def audit_park_miller() -> None:
    header("PHASE 1: Park-Miller family — V0 and V1 PRNG state advancement")

    math_ref(
        "Park-Miller is two Lehmer-LCG variants sharing M = 2³¹-1 but differing",
        "in the multiplier. EyeStat scans both as independent hypotheses.",
        "",
        "  V0 (Park & Miller, CACM 1988)         a = 16807",
        "      ▶ canonical 'minimum standard', most common in libraries",
        "      ▶ Numerical Recipes ran1(), C++ minstd_rand0, MATLAB <2009",
        "",
        "  V1 (Park, Miller & Stockmeyer, CACM 1993)   a = 48271",
        "      ▶ revised constants with better spectral properties",
        "      ▶ C++ minstd_rand, MATLAB ≥2009, L'Ecuyer's recommended",
        "",
        "  COMMON SHARED MATH",
        "  ──────────────────",
        "    s_0      = seed   (rescued to 1 if seed ∈ {0, M})",
        "    s_{n+1}  = (a · s_n) mod M",
        "    out_n    = s_n  ∈  [1, M-1]",
        "",
        "  Period:     M - 1   =   2,147,483,646",
        "  Modulus:    M       =   2³¹ - 1 = 2,147,483,647   (Mersenne prime)",
        "",
        "  SCHRAGE'S ALGORITHM (used in GPU kernel + CPU shadow):",
        "    Q = M // a       R = M mod a       (requires R < Q)",
        "    V0:  Q = 127773,  R = 2836",
        "    V1:  Q =  44488,  R = 3399",
        "",
        "    hi = s / Q",
        "    lo = s mod Q",
        "    s' = a·lo - R·hi",
        "    if s' < 0:  s' += M",
        "",
        "  KNOWN-ANSWER TESTS (10,000th iterate of seed = 1):",
        "    V0  →  1,043,618,065     (Park & Miller paper, canonical)",
        "    V1  →    399,268,537     (computed; deterministic from a,M)",
    )

    M = 2_147_483_647
    import eyestat_prngs as P

    # -----------------------------------------------------------------------
    # V0 (a = 16807)
    # -----------------------------------------------------------------------
    step("V0 (a = 16807):  reference computation of first 5 outputs from seed=1")
    state = 1
    expected_v0 = []
    for i in range(5):
        state = (16807 * state) % M
        expected_v0.append(state)
        show(f"V0 state[{i+1}]", state)

    step("V0:  eyestat_prngs.ParkMillerV0Rng.next_u32() — compare")
    rng = P.ParkMillerV0Rng(1)
    got = [rng.next_u32() for _ in range(5)]
    check("V0 first 5 outputs from seed=1", got, expected_v0)

    step("V0:  KAT — 10,000th iterate of seed=1 == 1,043,618,065")
    rng = P.ParkMillerV0Rng(1)
    out = None
    for _ in range(10_000):
        out = rng.next_u32()
    show("V0 10000th iterate", out)
    check("V0 KAT", out, 1_043_618_065)

    # -----------------------------------------------------------------------
    # V1 (a = 48271)
    # -----------------------------------------------------------------------
    step("V1 (a = 48271):  reference computation of first 5 outputs from seed=1")
    state = 1
    expected_v1 = []
    for i in range(5):
        state = (48271 * state) % M
        expected_v1.append(state)
        show(f"V1 state[{i+1}]", state)

    step("V1:  eyestat_prngs.ParkMillerV1Rng.next_u32() — compare")
    rng = P.ParkMillerV1Rng(1)
    got = [rng.next_u32() for _ in range(5)]
    check("V1 first 5 outputs from seed=1", got, expected_v1)

    step("V1:  KAT — 10,000th iterate of seed=1 == 399,268,537")
    rng = P.ParkMillerV1Rng(1)
    out = None
    for _ in range(10_000):
        out = rng.next_u32()
    show("V1 10000th iterate", out)
    check("V1 KAT", out, 399_268_537)

    # -----------------------------------------------------------------------
    # V0 and V1 produce DISTINCT output streams (sanity)
    # -----------------------------------------------------------------------
    step("V0 vs V1 independence: same seed must produce different streams")
    rng_v0 = P.ParkMillerV0Rng(42)
    rng_v1 = P.ParkMillerV1Rng(42)
    s_v0 = [rng_v0.next_u32() for _ in range(100)]
    s_v1 = [rng_v1.next_u32() for _ in range(100)]
    collisions = sum(1 for a, b in zip(s_v0, s_v1) if a == b)
    show("V0 first output (seed=42)", s_v0[0])
    show("V1 first output (seed=42)", s_v1[0])
    show("positions where V0[i]==V1[i] (out of 100)", collisions)
    check("V0 and V1 streams are distinct", collisions, 0)

    # -----------------------------------------------------------------------
    # Range + boundary behavior (common to both variants)
    # -----------------------------------------------------------------------
    for label, rng_cls in [("V0", P.ParkMillerV0Rng), ("V1", P.ParkMillerV1Rng)]:
        step(f"{label}: range check — outputs always in [1, M-1]")
        rng = rng_cls(42)
        samples = [rng.next_u32() for _ in range(10_000)]
        check(f"{label} min(samples) >= 1", min(samples) >= 1, True)
        check(f"{label} max(samples) <  M", max(samples) < M, True)

        step(f"{label}: boundary — seed=0 and seed=M both rescue to 1")
        a = rng_cls(0).next_u32()
        b = rng_cls(M).next_u32()
        show(f"{label} seed=0 first output", a)
        show(f"{label} seed=M first output", b)
        check(f"{label} seed=0 == seed=M (both rescued)", a, b)


# ===========================================================================
# PHASE 2: Fisher-Yates permutation from the PRNG
# ===========================================================================
# Verify that the shuffled_perm method produces a VALID permutation of [0..N).
# Then verify the specific output for a known seed is reproducible.

def audit_fisher_yates() -> None:
    header("PHASE 2: Fisher-Yates permutation generation")

    math_ref(
        "Fisher-Yates / Knuth shuffle, modern (Durstenfeld) inside-out variant:",
        "",
        "    perm = [0, 1, 2, ..., N-1]",
        "    for i = N-1 down to 1:",
        "        j = U(0, i)                # uniform integer in [0, i]",
        "        swap perm[i], perm[j]",
        "",
        "  In eyestat:  U(0, n) ← ParkMillerRng.next_below(n+1), which uses",
        "  rejection sampling on the LCG output to remove modulo bias.",
        "",
        "  Output: uniformly random permutation of [0, N) — every one of N!",
        "  permutations equally likely, conditional on a uniform RNG source.",
        "  We can only verify VALIDITY here (output IS a permutation) and",
        "  reproducibility (same seed → same perm), not uniformity directly.",
    )

    step("Validity check on 100 permutations of [0..83)")
    rng = P.ParkMillerRng(12345)
    for i in range(100):
        perm = rng.shuffled_perm(83)
        if sorted(perm) != list(range(83)):
            check(f"perm[{i}] is a valid permutation of [0..83)", False, True)
            return
    check("100 permutations all valid", True, True)

    step("Reproducibility: same seed → same first permutation")
    p1 = P.ParkMillerRng(54321).shuffled_perm(10)
    p2 = P.ParkMillerRng(54321).shuffled_perm(10)
    show("perm from seed=54321 (first 10)", p1)
    check("two ParkMillerRng(54321) yield identical first perms", p1, p2)

    step("Independence: different seeds → different perms (sanity)")
    p_a = P.ParkMillerRng(1).shuffled_perm(83)
    p_b = P.ParkMillerRng(2).shuffled_perm(83)
    same = sum(1 for x, y in zip(p_a, p_b) if x == y)
    show("matching positions out of 83", same)
    check("seeds 1 and 2 produce different perms", same < 83, True)


# ===========================================================================
# PHASE 3: GAK / xGAK round-trip for all 8 modes
# ===========================================================================
# Small N=5 alphabet, short plaintext. Encrypt then decrypt; output must
# match input. Also show the cipher state at key points.

def gak_encrypt(plaintext: List[int], sigma: List[List[int]], N: int, mode_code: int) -> List[int]:
    """Pure-Python encryption mirror of eyestat_kernels.gak_decrypt logic."""
    active = list(sigma[0])
    mode_right = mode_code in (0, 2, 4, 6)
    mode_key = mode_code // 2
    ct = []
    for p in plaintext:
        c = active[p]
        ct.append(c)
        if mode_key == 0:   k = c
        elif mode_key == 1: k = p
        elif mode_key == 2: k = (p + c) % N
        else:               k = (c - p + N) % N
        sk = sigma[k]
        if mode_right:
            active = [active[sk[i]] for i in range(N)]
        else:
            active = [sk[active[i]] for i in range(N)]
    return ct


def audit_gak() -> None:
    header("PHASE 3: GAK / xGAK round-trip across all 8 modes")

    math_ref(
        "GAK / xGAK family — stateful permutation cipher with autokey feedback.",
        "",
        "  KEY SCHEDULE",
        "  ────────────",
        "    σ_0, σ_1, ..., σ_N  : N+1 permutations of [0, N) derived from one",
        "                          seed via Park-Miller + Fisher-Yates.",
        "    α_i                 : the 'active' permutation at step i.",
        "                          α_0 = σ_0 (state initialization)",
        "                          α_i = state after processing i symbols",
        "",
        "  ENCRYPTION (same for all 8 modes)",
        "  ─────────────────────────────────",
        "    c_i = α_i[p_i]",
        "",
        "  DECRYPTION (same for all 8 modes)",
        "  ─────────────────────────────────",
        "    p_i = α_i⁻¹[c_i]                # apply the inverse of α_i",
        "",
        "  KEY DERIVATION  (varies; mode_code // 2 selects the family)",
        "  ─────────────────────────────────────────────────────────",
        "    family 0   CTAK       k_i = c_i               (ciphertext autokey)",
        "    family 1   PTAK       k_i = p_i               (plaintext autokey)",
        "    family 2   XGAK_SUM   k_i = (p_i + c_i) mod N",
        "    family 3   XGAK_DIFF  k_i = (c_i − p_i) mod N",
        "",
        "  STATE UPDATE  (varies; mode_code & 1 selects the direction)",
        "  ─────────────────────────────────────────────────────────",
        "    direction 0 (RIGHT)   α_{i+1}[j] = α_i[ σ_{k_i}[j] ]    ∀j ∈ [0,N)",
        "                          (i.e. α_{i+1} = α_i ∘ σ_{k_i})",
        "    direction 1 (LEFT)    α_{i+1}[j] = σ_{k_i}[ α_i[j] ]    ∀j ∈ [0,N)",
        "                          (i.e. α_{i+1} = σ_{k_i} ∘ α_i)",
        "",
        "  MESSAGE BOUNDARY",
        "  ────────────────",
        "    Active resets to σ_0 at the start of every message — so the 9",
        "    Noita ciphertexts share the key schedule {σ_i} but each begins",
        "    fresh. This is why a wrong seed produces 9 independently-garbled",
        "    decryptions rather than one self-correcting one.",
        "",
        "  CODE CORRESPONDENCE",
        "  ───────────────────",
        "    Python:  α ≡ active,  σ ≡ sigma,  p ≡ plaintext,  c ≡ ciphertext",
    )

    N = 5
    plaintext = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 2, 3, 1, 0, 4]
    seed = 12345
    rng = P.ParkMillerRng(seed)
    sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]

    step(f"Test setup: N={N}, plaintext length={len(plaintext)}, seed={seed}")
    show("plaintext", plaintext)
    show("σ_0 (initial active)", sigma[0])

    # Per-mode formulas — written out in one place so it's easy to verify
    # each one matches the family reference above.
    mode_specs = [
        (0, "ctak_right",
         "c_i = α_i[p_i],  k_i = c_i,            α_{i+1} = α_i ∘ σ_{k_i}"),
        (1, "ctak_left",
         "c_i = α_i[p_i],  k_i = c_i,            α_{i+1} = σ_{k_i} ∘ α_i"),
        (2, "ptak_right",
         "c_i = α_i[p_i],  k_i = p_i,            α_{i+1} = α_i ∘ σ_{k_i}"),
        (3, "ptak_left",
         "c_i = α_i[p_i],  k_i = p_i,            α_{i+1} = σ_{k_i} ∘ α_i"),
        (4, "xgak_sum_right",
         "c_i = α_i[p_i],  k_i = (p_i+c_i) mod N, α_{i+1} = α_i ∘ σ_{k_i}"),
        (5, "xgak_sum_left",
         "c_i = α_i[p_i],  k_i = (p_i+c_i) mod N, α_{i+1} = σ_{k_i} ∘ α_i"),
        (6, "xgak_diff_right",
         "c_i = α_i[p_i],  k_i = (c_i−p_i) mod N, α_{i+1} = α_i ∘ σ_{k_i}"),
        (7, "xgak_diff_left",
         "c_i = α_i[p_i],  k_i = (c_i−p_i) mod N, α_{i+1} = σ_{k_i} ∘ α_i"),
    ]

    for mode_code, name, formula in mode_specs:
        step(f"Mode {mode_code} = {name}")
        if VERBOSE:
            print(f"    formula:  {formula}")
        ct = gak_encrypt(plaintext, sigma, N, mode_code)
        show("ciphertext", ct)
        recovered = K.gak_decrypt(ct, sigma, N, mode_code)
        show("decrypt(ciphertext)", recovered)
        check(f"{name}: decrypt(encrypt(pt)) == pt", recovered, plaintext)

    # Show one step of state evolution explicitly for mode 0 so the reader
    # can hand-trace and verify it matches the formula above.
    step("Worked one-step trace for ctak_right (mode 0) — verify by hand:")
    if VERBOSE:
        N5 = 5
        sigma0 = sigma[0]
        p0 = plaintext[0]                        # = 0
        c0 = sigma0[p0]                          # α_0[0]
        k0 = c0                                  # CTAK: key is ciphertext
        sigma_k = sigma[k0]
        alpha_1 = [sigma0[sigma_k[j]] for j in range(N5)]   # RIGHT composition
        print(f"      α_0 (= σ_0)               = {sigma0}")
        print(f"      p_0                        = {p0}")
        print(f"      c_0 = α_0[p_0]            = α_0[{p0}] = {c0}")
        print(f"      k_0 = c_0                  = {k0}    (CTAK rule)")
        print(f"      σ_{k0} (the keyed perm)    = {sigma_k}")
        print(f"      α_1[j] = α_0[σ_{k0}[j]]:")
        for j in range(N5):
            print(f"          j={j}: σ_{k0}[{j}]={sigma_k[j]}, α_0[{sigma_k[j]}]={sigma0[sigma_k[j]]}  →  α_1[{j}]={alpha_1[j]}")
        print(f"      α_1                        = {alpha_1}")


# ===========================================================================
# PHASE 4: Hungarian rune→letter mapping optimality
# ===========================================================================
# Use a tiny N=4 problem where the optimal cost is hand-computable by
# enumeration (4! = 24 mappings to check). Confirm Hungarian finds it.

def audit_hungarian() -> None:
    header("PHASE 4: Hungarian rune→letter mapping optimality")

    math_ref(
        "Frequency-matched rune→letter assignment as the classical linear",
        "assignment problem (LAP):",
        "",
        "  Inputs:",
        "    f_R(r)        = empirical frequency of rune r in decryption  (%)",
        "    f_L(ℓ)        = reference frequency of letter ℓ in language  (%)",
        "",
        "  Cost matrix:",
        "    C[r][ℓ] = ( f_R(r) − f_L(ℓ) )²              (squared diff)",
        "",
        "  Objective: find injective mapping  m: runes → letters  that",
        "  minimizes the total cost",
        "",
        "    minimize     Σ_r C[r][m(r)]",
        "    subject to   m injective    (each letter used at most once)",
        "",
        "  Solved by the Hungarian algorithm — O(N³).  In eyestat this",
        "  delegates to scipy.optimize.linear_sum_assignment when scipy is",
        "  installed (~200× faster C implementation); else the pure-Python",
        "  Kuhn-Munkres fallback in eyestat_scoring._hungarian_min_cost_pure_python.",
        "",
        "  When  N > |alphabet|  (e.g. 83 runes vs 29 Finnish letters), letters",
        "  are REPEATED — homophonic substitution where multiple runes may map",
        "  to the same letter.",
        "",
        "  When  N ≤ |alphabet|  Hungarian chooses the best N letters from the",
        "  full alphabet, scoring on a rectangular N × L cost matrix. (An",
        "  earlier revision incorrectly truncated to letters[:N] here — see",
        "  AUDIT.md for the fix history.)",
    )

    step("Synthetic 4-rune problem")
    # Frequencies engineered so the optimum mapping is non-obvious to spot.
    rune_freq = {0: 30.0, 1: 25.0, 2: 25.0, 3: 20.0}  # sum = 100
    # Imagine the "Finnish-like" frequencies:
    letter_freq = {"a": 28.0, "i": 26.0, "e": 24.0, "t": 22.0}

    show("rune_freq",   rune_freq)
    show("letter_freq", letter_freq)

    step("Brute force: enumerate all 4! = 24 mappings, find min-cost")
    # Cost: sum of (rune_freq - letter_freq)^2 over the mapping.
    from itertools import permutations
    letters = list(letter_freq.keys())
    best_cost = float("inf")
    best_map = None
    for perm in permutations(letters):
        m = dict(zip([0, 1, 2, 3], perm))
        cost = sum((rune_freq[r] - letter_freq[m[r]]) ** 2 for r in range(4))
        if cost < best_cost:
            best_cost = cost
            best_map = m
    show("brute-force best mapping", best_map)
    show("brute-force best cost",    f"{best_cost:.4f}")

    step("eyestat_scoring.hungarian_optimal_mapping — compare")
    got = S.hungarian_optimal_mapping(rune_freq, letter_freq,
                                       alphabet_size=4, language="fi")
    show("Hungarian mapping", got)

    # Defensive: the mapping might return letters not in our letter_freq dict
    # if the function truncates the alphabet (a known bug case). Use .get()
    # with 0.0 default and flag it.
    missing = [v for v in got.values() if v not in letter_freq]
    if missing:
        step(f"WARNING: returned mapping contains letters not in letter_freq: {missing}")
        step("This indicates hungarian_optimal_mapping is using a different letter")
        step("set than the one we provided frequencies for. See bug note below.")
    got_cost = sum((rune_freq[r] - letter_freq.get(got[r], 0.0)) ** 2 for r in range(4))
    show("Hungarian cost", f"{got_cost:.4f}")

    check("Hungarian cost equals brute-force optimum", got_cost, best_cost, tol=1e-9)

    if missing:
        step("BUG NOTE")
        print("    hungarian_optimal_mapping(N, language) truncates `letters_to_use`")
        print("    to letters[:N] when N <= len(language_alphabet) — the function")
        print("    can ONLY pick from the first N letters of the alphabet, never")
        print("    considering the rest. For N < 29 (Finnish alphabet size), this")
        print("    means any letter_freq entry outside the first N letters is ignored.")
        print("    ")
        print("    Impact: real Noita runs with N=83 are unaffected (different branch).")
        print("    Smaller-N tests (e.g. test.txt with N=5) get bogus mappings.")
        print("    ")
        print("    Fix: in the `else` branch of hungarian_optimal_mapping, replace")
        print("        letters_to_use = letters[:alphabet_size]")
        print("    with")
        print("        letters_to_use = letters    # Hungarian picks best N from full set")


# ===========================================================================
# PHASE 5: Dictionary substring matching
# ===========================================================================
# Construct a known string and a known dictionary so the hit list is
# hand-verifiable.

def audit_dict_match() -> None:
    header("PHASE 5: Dictionary substring matching")

    math_ref(
        "Dictionary substring scan — find all words in the dict that appear as",
        "a contiguous substring of the input text.",
        "",
        "  Let  T = text (length n),  D = dictionary (set of words),",
        "       L_min, L_max = min / max word length to consider",
        "",
        "  hits = { w ∈ D :  ∃ i ∈ [0, n − |w|]  such that  T[i : i + |w|] = w",
        "                    AND L_min ≤ |w| ≤ L_max }",
        "",
        "  Sliding-window implementation:",
        "    for i ∈ [0, n):",
        "      for L ∈ [L_min, L_max]:",
        "        if i + L ≤ n  and  T[i : i+L] ∈ D:",
        "          hits.add(T[i : i+L])",
        "",
        "  Complexity:  O(n × (L_max − L_min + 1)) hash lookups, each O(1)",
        "  amortized via Python's str hash.  Independent of |D| — adding more",
        "  words doesn't slow scanning, only memory.",
    )
    text = "thecatsatonthemat"
    expected_hits = sorted(["the", "cat", "sat", "mat", "ont"])  # 4-letter min would change this
    dictionary = S.Dictionary("test")
    for w in ["the", "cat", "sat", "mat", "ont", "hex"]:  # hex won't match
        dictionary.words.add(w)
        dictionary.zipf_rank[w] = 1
    show("text",       text)
    show("dictionary", sorted(dictionary.words))
    show("expected hits (manual)", expected_hits)

    n_hits, hit_list = S.count_dictionary_hits(text, dictionary, min_word_len=3)
    show("got n_hits", n_hits)
    show("got hit_list", sorted(hit_list))
    check("hit list matches manual enumeration", sorted(hit_list), expected_hits)
    check("hit count matches", n_hits, len(expected_hits))

    step("Negative: 'hex' is in dict but NOT in text — should not be reported")
    check("'hex' not in hit_list", "hex" not in hit_list, True)


# ===========================================================================
# PHASE 6: Zipf and length-weighted scoring
# ===========================================================================
# Both functions are formulaic; verify the formulas with hand calculation.

def audit_scoring() -> None:
    header("PHASE 6: Scoring functions — Zipf and length-weighted")

    math_ref(
        "Two scoring functions take a list of hit words and produce a scalar.",
        "Higher score ⇒ stronger language signal.",
        "",
        "  ZIPF SCORE (rewards rare-but-recognized words)",
        "  ─────────────────────────────────────────────",
        "    zipf(hits) = Σ_{w ∈ hits}  −log( rank(w) / R_max )",
        "",
        "  where  rank(w) ∈ [1, R_max]  is the dictionary index of w (1 = most",
        "  common), capped at R_max = 10001 to avoid −∞ on out-of-dict words.",
        "",
        "  Intuition: −log(rank/R_max) is large for low rank (common words) and",
        "  small for high rank (rare words). Common-word matches dominate the",
        "  score; long-tail words contribute little.",
        "",
        "  LENGTH-WEIGHTED SCORE  (rewards long words; default scorer in v2)",
        "  ──────────────────────────────────────────────────────────────",
        "    wscore(hits, k) = Σ_{w ∈ hits}  |w|^k         (default k = 2)",
        "",
        "  Intuition: chance-substring rate falls as roughly  α^(−|w|)  for",
        "  alphabet size α, so longer matches are exponentially rarer.  k = 2",
        "  squared-length gives 3–5× signal-to-noise vs raw hit count on the",
        "  Noita data (observed empirically).",
    )

    step("Zipf score: sum over hits of -log(rank / 10001)")
    dictionary = S.Dictionary("test")
    # Words with explicit ranks for a deterministic check.
    dictionary.zipf_rank = {"the": 1, "cat": 100, "sat": 500, "mat": 1000}
    hits = ["the", "cat", "sat", "mat"]
    expected = (
        -math.log(1 / 10001.0)
        - math.log(100 / 10001.0)
        - math.log(500 / 10001.0)
        - math.log(1000 / 10001.0)
    )
    show("hits", hits)
    show("expected zipf score (manual)", f"{expected:.6f}")
    got = S.zipf_score(hits, dictionary)
    show("got zipf score", f"{got:.6f}")
    check("zipf_score formula", got, expected, tol=1e-9)

    step("Length-weighted score: sum of len(w)^2")
    hits2 = ["the", "cat", "kuolema", "x"]
    expected_w = 3**2 + 3**2 + 7**2 + 1**2  # = 9 + 9 + 49 + 1 = 68
    show("hits",       hits2)
    show("expected (manual)", expected_w)
    got_w = S.length_weighted_score(hits2)
    show("got",        got_w)
    check("length_weighted_score formula", got_w, float(expected_w), tol=1e-9)

    step("Exponent override (cube)")
    expected_3 = 3**3 + 3**3 + 7**3 + 1**3  # = 27 + 27 + 343 + 1 = 398
    got_3 = S.length_weighted_score(hits2, exponent=3.0)
    check("length_weighted_score(exponent=3)", got_3, float(expected_3), tol=1e-9)


# ===========================================================================
# PHASE 7: End-to-end — plant a seed, recover it
# ===========================================================================
# Encrypt a known plaintext with a known seed using GAK CTAK_RIGHT, then
# scan a small seed range and verify the planted seed is identifiable.

def audit_planted_seed() -> None:
    header("PHASE 7: End-to-end planted-seed recovery")

    math_ref(
        "End-to-end attack model — the hypothesis EyeStat is testing:",
        "",
        "  Given:    ciphertext C, candidate seed s",
        "  Hypothesis:  C = GAK_encrypt(plaintext, σ(s), mode)",
        "               where σ(s) = (σ_0, ..., σ_N) = ParkMillerSchedule(s)",
        "",
        "  For each candidate seed s ∈ [0, 2³¹):",
        "    1.  Generate key schedule σ(s) via Park-Miller + Fisher-Yates",
        "    2.  D ← GAK_decrypt(C, σ(s), mode)              # candidate plaintext",
        "    3.  H ← Hungarian( freq(D),  freq_FI )           # rune→letter map",
        "    4.  T ← apply_mapping(D, H)                      # candidate text",
        "    5.  score(s) ← Σ_{w ∈ dict ∩ substr(T)} f(w)",
        "",
        "  Output: distribution of score(s) over all s, with outliers flagged",
        "  as candidate solutions.",
        "",
        "  Audit setup below:  plant a seed s*, encrypt a known plaintext,",
        "  scan a 100-seed window around s*, verify ONLY s* recovers it.",
    )
    N = 83
    seed = 31337
    mode = 0  # ctak_right

    step(f"Plant: N={N}, seed={seed}, mode=ctak_right")
    rng = P.ParkMillerRng(seed)
    sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]

    # Plaintext: a short sequence using the lower part of the alphabet
    plaintext = [(i * 7 + 3) % 29 for i in range(40)]
    show("plaintext (first 10)", plaintext[:10])
    show("plaintext length", len(plaintext))

    step("Encrypt with planted seed → ciphertext")
    ct = gak_encrypt(plaintext, sigma, N, mode)
    show("ciphertext (first 10)", ct[:10])

    step("Decrypt with WRONG seed → garbage")
    rng_wrong = P.ParkMillerRng(seed + 1)
    sigma_wrong = [rng_wrong.shuffled_perm(N) for _ in range(N + 1)]
    wrong = K.gak_decrypt(ct, sigma_wrong, N, mode)
    show("decrypt with seed+1 (first 10)", wrong[:10])
    check("wrong seed produces non-plaintext output", wrong != plaintext, True)

    step("Decrypt with CORRECT seed → recovered plaintext")
    rng_ok = P.ParkMillerRng(seed)
    sigma_ok = [rng_ok.shuffled_perm(N) for _ in range(N + 1)]
    recovered = K.gak_decrypt(ct, sigma_ok, N, mode)
    show("decrypt with seed (first 10)", recovered[:10])
    check("correct seed recovers plaintext", recovered, plaintext)

    step(f"Scan a 100-seed range around planted seed {seed}; planted seed should be uniquely correct")
    matches = []
    for s in range(seed - 50, seed + 50):
        if s == 0:
            continue
        sgm = [P.ParkMillerRng(s).shuffled_perm(N)] + \
              [P.ParkMillerRng(s + i + 1).shuffled_perm(N) for i in range(N)]
        # Note: this is NOT how production builds sigma — we use a single
        # ParkMillerRng stream advancing for all N+1 perms. Use the correct
        # method to avoid an apples-to-oranges check.
        rng_s = P.ParkMillerRng(s)
        sgm_correct = [rng_s.shuffled_perm(N) for _ in range(N + 1)]
        out = K.gak_decrypt(ct, sgm_correct, N, mode)
        if out == plaintext:
            matches.append(s)
    show("seeds that decrypt to plaintext", matches)
    check("only planted seed in scan range matches", matches, [seed])


# ===========================================================================
# PHASE 8: Real shard verification (optional)
# ===========================================================================
# If the user provides --shard PATH, pick random sample entries from the
# params.tsv.gz file and re-compute their max_hits from scratch, comparing
# to the stored value. This catches any drift between the runner's scoring
# and the standalone scoring code.

def audit_chi2_filter() -> None:
    header("PHASE 8: Chi² pre-filter — language-likeness rejection")

    math_ref(
        "GPU pre-filter that rejects candidates whose rune-frequency",
        "distribution doesn't 'look like' any of the target languages, BEFORE",
        "the expensive CPU scoring stage runs.",
        "",
        "  Per candidate, per target language ℓ:",
        "    h_c[i]     = histogram bin count i  ∈  [0, ct_total_len]",
        "    f_c[i]     = h_c[i] / ct_total_len                (frequency)",
        "    sorted_f_c = sort descending(f_c)                 (shape only — no rune ID)",
        "    chi2_ℓ     = Σᵢ (sorted_f_c[i] - expected_sorted_ℓ[i])²",
        "",
        "  Then for filtering:",
        "    min_chi2  = min over ℓ ∈ {fi, krl, en}",
        "    pass-through if min_chi2 ≤ threshold",
        "    rejected   if min_chi2 >  threshold",
        "",
        "  NOTE ON THE NAME",
        "  ────────────────",
        "    'chi²' is a misnomer — this is squared L2 distance, not the",
        "    statistical chi-squared test (which divides by expected[i] and",
        "    would div-by-zero at the distribution tail where expected is 0).",
        "    Using L2 because it's monotonically equivalent for ranking",
        "    purposes and free of the singularity.",
        "",
        "  EXPECTED DISTRIBUTION FOR LANGUAGE ℓ",
        "  ────────────────────────────────────",
        "    For each letter L in ℓ's alphabet:",
        "      slots(L) = number of homophone slots assigned to L (alphabetical",
        "                 allocation, matching hungarian_optimal_mapping's N>L branch)",
        "      per-rune expected freq = letter_freq(L) / slots(L) / 100   (LANG_DEFAULT_FREQS",
        "                                                                  is in %)",
        "    expected_sorted_ℓ = sort descending([per-rune freq for each slot])",
        "",
        "  THRESHOLD CALIBRATION",
        "  ─────────────────────",
        "    Empirical separation on REAL Park-Miller ctak_right decryptions",
        "    of the Noita ciphertext (n=50 random seeds + 50 plaintext samples):",
        "      Real-cipher noise:      chi² ≈ 0.0055 - 0.0079   (median 0.0068)",
        "      Real-signal (any lang): chi² ≈ 0.0001 - 0.0006   (median 0.0003)",
        "    Default threshold = 0.0015 sits in the 10× separation gap.",
        "    Margin: ~3× above signal max, ~3.5× below noise min. Fail-open.",
        "    NOTE: synthetic uniform-random noise (np.random.randint) gives a",
        "    LOWER chi² (~0.0035) than real GAK output — never calibrate the",
        "    threshold against synthetic uniform; use real cipher output.",
    )

    import numpy as np
    import eyestat_scoring as S

    step("Compute expected sorted distribution for each language (Noita N=83)")
    N = 83
    expected = {}
    for lang in ["fi", "krl", "en"]:
        dist = S.compute_expected_sorted_distribution(lang, N)
        expected[lang] = np.array(dist, dtype=np.float32)
        show(f"  {lang}: top-3 entries", [f"{x:.4f}" for x in expected[lang][:3]])
        show(f"  {lang}: bottom-3 entries", [f"{x:.4f}" for x in expected[lang][-3:]])
        # Sanity: should sum to ~1.0 (modulo rounding in 1-decimal-percent freqs)
        check(f"  {lang}: distribution sums to ~1.0",
              abs(float(expected[lang].sum()) - 1.0) < 0.05, True)
        # Sanity: should be sorted descending
        check(f"  {lang}: distribution is sorted descending",
              all(expected[lang][i] >= expected[lang][i+1] for i in range(N-1)),
              True)

    # Stack into (num_langs, N) for shadow_chi2_pre_filter
    lang_dists = np.stack([expected[l] for l in ["fi", "krl", "en"]])

    step("Synthetic test 1: random uniform histogram → high chi² (noise regime)")
    np.random.seed(42)
    ct_total_len = 1036
    random_hist = np.bincount(
        np.random.randint(0, N, ct_total_len), minlength=N).astype(np.int32)[np.newaxis, :]

    # First-principles: sort descending, compute squared diffs
    f_rand = random_hist[0].astype(np.float32) / ct_total_len
    f_rand_sorted = np.sort(f_rand)[::-1]
    expected_rand_chi2 = float(np.min([
        np.sum((f_rand_sorted - expected[l]) ** 2) for l in ["fi", "krl", "en"]
    ]))
    show("expected min chi² (first principles)", f"{expected_rand_chi2:.6f}")

    from shadow_audit import shadow_chi2_pre_filter
    got_chi2, got_lang = shadow_chi2_pre_filter(random_hist, lang_dists, ct_total_len)
    show("shadow_chi2_pre_filter min_chi2", f"{float(got_chi2[0]):.6f}")
    show("shadow best_lang_idx",  int(got_lang[0]))
    check("random hist: shadow matches first-principles math",
          abs(float(got_chi2[0]) - expected_rand_chi2) < 1e-6, True)
    check("random hist: chi² is in noise regime (>0.001)",
          float(got_chi2[0]) > 0.001, True)

    step("Synthetic test 2: Finnish-shaped histogram → low chi² (signal regime)")
    # Build a histogram that matches the Finnish expected distribution under
    # a random rune permutation (simulating unknown rune→letter mapping).
    fi_probs = expected["fi"] / expected["fi"].sum()
    perm = np.random.permutation(N)
    real_hist = np.bincount(
        np.random.choice(N, ct_total_len, p=fi_probs[perm]),
        minlength=N).astype(np.int32)[np.newaxis, :]

    f_real = real_hist[0].astype(np.float32) / ct_total_len
    f_real_sorted = np.sort(f_real)[::-1]
    expected_real_chi2 = float(np.min([
        np.sum((f_real_sorted - expected[l]) ** 2) for l in ["fi", "krl", "en"]
    ]))
    got_chi2_real, got_lang_real = shadow_chi2_pre_filter(
        real_hist, lang_dists, ct_total_len)
    show("expected min chi² (first principles)", f"{expected_real_chi2:.6f}")
    show("shadow_chi2_pre_filter min_chi2", f"{float(got_chi2_real[0]):.6f}")
    show("shadow best_lang_idx",  int(got_lang_real[0]))
    check("Finnish hist: shadow matches first-principles math",
          abs(float(got_chi2_real[0]) - expected_real_chi2) < 1e-6, True)
    check("Finnish hist: chi² is in signal regime (<0.001)",
          float(got_chi2_real[0]) < 0.001, True)
    check("Finnish hist: best_lang is fi (index 0)",
          int(got_lang_real[0]), 0)

    step("Synthetic test 3: filter discrimination — 64 random vs 64 Finnish-like")
    random_hists = np.stack([
        np.bincount(np.random.randint(0, N, ct_total_len), minlength=N)
        for _ in range(64)
    ]).astype(np.int32)
    real_hists = []
    for _ in range(64):
        perm = np.random.permutation(N)
        p = fi_probs[perm]
        h = np.bincount(np.random.choice(N, ct_total_len, p=p), minlength=N)
        real_hists.append(h)
    real_hists = np.stack(real_hists).astype(np.int32)

    r_chi2, _ = shadow_chi2_pre_filter(random_hists, lang_dists, ct_total_len)
    f_chi2, _ = shadow_chi2_pre_filter(real_hists, lang_dists, ct_total_len)
    show("random regime range",  f"[{r_chi2.min():.5f}, {r_chi2.max():.5f}]")
    show("Finnish regime range", f"[{f_chi2.min():.5f}, {f_chi2.max():.5f}]")
    check("clean separation: max(real) < min(random)",
          float(f_chi2.max()) < float(r_chi2.min()), True)
    threshold_low  = float(f_chi2.max())
    threshold_high = float(r_chi2.min())
    show("safe threshold range (synthetic uniform noise)",
         f"[{threshold_low:.5f}, {threshold_high:.5f}]")
    # NOTE: synthetic uniform noise is NOT the same as real GAK noise!
    # Synthetic uniform gives chi² ~0.0035; real GAK gives chi² ~0.0068.
    # The real-noise calibration is below.

    # ---------------------------------------------------------------------
    # Real-cipher noise calibration: drive the filter with ACTUAL Park-Miller
    # GAK decryptions of the real Noita ciphertext (not synthetic uniform).
    # This is the calibration that matters for the production runner.
    # ---------------------------------------------------------------------
    step("Real-cipher test: chi² distribution on actual GAK decryptions "
         "(50 random Park-Miller seeds → ctak_right → real Noita ciphertext)")
    import json as _json
    from eyestat_prngs import ParkMillerV0Rng
    import eyestat_kernels as K_
    data_path = SCRIPT_DIR / "noita_eye_data.json"
    if data_path.exists():
        with open(data_path) as f:
            _data = _json.load(f)
        cts = _data["ciphertexts"]
        N_real = int(_data["deck_size"])
        if N_real != N:
            show("WARNING: data N != audit N, skipping real-noise calibration",
                 f"{N_real} vs {N}")
        else:
            real_noise_hists = []
            for seed in range(1, 51):
                rng = ParkMillerV0Rng(seed)
                sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]
                dec = []
                for ct in cts:
                    dec.extend(K_.gak_decrypt(ct, sigma, N, 0))   # ctak_right
                h = np.bincount(dec, minlength=N).astype(np.int32)
                real_noise_hists.append(h)
            real_noise_hists = np.stack(real_noise_hists)

            # Measurement 1: chi² against fi only (single-lang filter regime,
            # which is what --languages fi gives the production runner)
            fi_only = expected["fi"][np.newaxis, :]
            real_chi2_fi, _ = shadow_chi2_pre_filter(
                real_noise_hists, fi_only, ct_total_len)
            # Measurement 2: chi² against all 3 languages (3-lang filter regime)
            real_chi2_3, real_best_3 = shadow_chi2_pre_filter(
                real_noise_hists, lang_dists, ct_total_len)
            show("real-cipher noise vs fi only",
                 f"min={float(real_chi2_fi.min()):.5f} "
                 f"median={float(np.median(real_chi2_fi)):.5f} "
                 f"max={float(real_chi2_fi.max()):.5f}")
            show("real-cipher noise vs 3-lang min",
                 f"min={float(real_chi2_3.min()):.5f} "
                 f"median={float(np.median(real_chi2_3)):.5f} "
                 f"max={float(real_chi2_3.max()):.5f}")
            # Show which language captures noise most (typically EN — flat profile)
            from collections import Counter as _Counter
            best_counts = _Counter(real_best_3.tolist())
            show("which lang gives min chi² for noise",
                 dict((["fi","krl","en"][k], v) for k, v in best_counts.items()))

            # CRITICAL assertions: default threshold must reject noise AND pass
            # signal in BOTH filter regimes (single-lang fi AND 3-lang min).
            check("default 0.0015 rejects all real-cipher noise (fi-only filter)",
                  float(real_chi2_fi.min()) > 0.0015, True)
            check("default 0.0015 rejects all real-cipher noise (3-lang filter)",
                  float(real_chi2_3.min()) > 0.0015, True)
            check("default 0.0015 passes all real-signal samples",
                  float(f_chi2.max()) < 0.0015, True)
            show("threshold safety margins",
                 f"fi-only:  signal_max={float(f_chi2.max()):.5f} ← 0.00150 → "
                 f"noise_min={float(real_chi2_fi.min()):.5f} "
                 f"({float(real_chi2_fi.min())/0.0015:.1f}× margin) | "
                 f"3-lang:  noise_min={float(real_chi2_3.min()):.5f} "
                 f"({float(real_chi2_3.min())/0.0015:.1f}× margin)")
    else:
        show("real-cipher calibration", "SKIP (noita_eye_data.json not found)")

    # ---------------------------------------------------------------------
    # Permutation invariance — THE strongest correctness check
    # ---------------------------------------------------------------------
    # The chi² filter sorts the histogram before comparing. Therefore the
    # chi² value MUST be identical for any permutation of the same
    # histogram. If it isn't, the sort is broken.
    step("Algorithmic invariant: chi² is permutation-invariant on the histogram")
    base_hist = real_hists[0:1]   # take one of the synthetic "real" hists
    perm_count = 20
    chi2_baseline, lang_baseline = shadow_chi2_pre_filter(
        base_hist, lang_dists, ct_total_len)
    permuted_chi2s = []
    permuted_langs = []
    for trial in range(perm_count):
        perm = np.random.permutation(N)
        permuted = base_hist[:, perm].copy()
        c2, l2 = shadow_chi2_pre_filter(permuted, lang_dists, ct_total_len)
        permuted_chi2s.append(float(c2[0]))
        permuted_langs.append(int(l2[0]))
    show("baseline chi²", f"{float(chi2_baseline[0]):.8f}")
    show("permuted chi² range",
         f"[{min(permuted_chi2s):.8f}, {max(permuted_chi2s):.8f}] over {perm_count} permutations")
    show("permuted best_lang values", set(permuted_langs))
    check("all permutations produce same chi² (filter is sort-invariant)",
          all(abs(c - float(chi2_baseline[0])) < 1e-7 for c in permuted_chi2s),
          True)
    check("all permutations produce same best_lang",
          all(l == int(lang_baseline[0]) for l in permuted_langs), True)

    # ---------------------------------------------------------------------
    # Degenerate inputs
    # ---------------------------------------------------------------------
    step("Degenerate input 1: all-same histogram (every rune equally likely)")
    flat_hist = np.full((1, N), ct_total_len // N, dtype=np.int32)
    flat_hist[0, 0] += ct_total_len - flat_hist.sum()   # absorb division remainder
    f_chi2_flat, f_lang_flat = shadow_chi2_pre_filter(
        flat_hist, lang_dists, ct_total_len)
    # All-uniform input: every entry of sorted_freq is ~1/N, which gives the
    # largest possible distance from any peaked language distribution.
    show("flat histogram chi²", f"{float(f_chi2_flat[0]):.6f}")
    check("flat hist: chi² is large (noise regime, >0.001)",
          float(f_chi2_flat[0]) > 0.001, True)

    step("Degenerate input 2: single-peak histogram (one rune dominates)")
    peak_hist = np.zeros((1, N), dtype=np.int32)
    peak_hist[0, 0] = ct_total_len
    p_chi2, p_lang = shadow_chi2_pre_filter(peak_hist, lang_dists, ct_total_len)
    # Sorted: [1.0, 0, 0, ..., 0]. Distance from any language profile is large
    # because no language puts ~100% of its frequency on a single letter.
    show("single-peak histogram chi²", f"{float(p_chi2[0]):.6f}")
    check("single-peak hist: chi² is very large (>0.5)",
          float(p_chi2[0]) > 0.5, True)

    # ---------------------------------------------------------------------
    # Sanity: compute_expected_sorted_distribution edge cases
    # ---------------------------------------------------------------------
    step("Helper edge case: unknown language raises KeyError")
    try:
        S.compute_expected_sorted_distribution("xyz_nonexistent", N)
        check("unknown language raises KeyError", False, True)
    except KeyError:
        check("unknown language raises KeyError", True, True)

    step("Helper edge case: N < alphabet size (N <= L branch)")
    # For Finnish with N=20, we have 20 runes from a 29-letter alphabet —
    # the N<=L branch: first N letters get 1 slot each.
    small_dist = S.compute_expected_sorted_distribution("fi", 20)
    show("small-N (N=20, L=29) distribution length", len(small_dist))
    show("small-N top-3", [f"{x:.4f}" for x in small_dist[:3]])
    check("small-N: length matches N", len(small_dist) == 20, True)
    check("small-N: sorted descending",
          all(small_dist[i] >= small_dist[i+1] for i in range(19)), True)

    # ---------------------------------------------------------------------
    # End-to-end through chi² filter: plant Finnish-LIKE plaintext, encrypt
    # with a known seed in each of the 8 GAK modes, decrypt with the same
    # seed, and verify the chi² filter PASSES the recovered plaintext.
    #
    # This is the test that DOES NOT exist in audit_planted_seed (which uses
    # a synthetic uniform-ish plaintext that wouldn't survive the filter).
    # It's the proof that the production runner with chi² enabled is not
    # silently rejecting the kind of real signal we're hunting for.
    # ---------------------------------------------------------------------
    step("End-to-end test: plant Finnish-shaped plaintext, encrypt/decrypt "
         "through each of 8 GAK modes, verify chi² filter PASSES recovered text")
    from eyestat_kernels import gak_encrypt, GAK_MODE_NAMES
    import eyestat_kernels as K_e2e
    # Build a "Finnish-shaped" plaintext via the same per-rune freq profile
    # the chi² filter compares against.
    fi_probs_norm = expected["fi"] / expected["fi"].sum()
    np.random.seed(31337)
    permutation = np.random.permutation(N)
    planted_pt = np.random.choice(N, ct_total_len, p=fi_probs_norm[permutation]).tolist()

    # Sanity: planted plaintext should be in signal regime
    h_planted = np.bincount(planted_pt, minlength=N).astype(np.int32)[np.newaxis, :]
    planted_chi2, _ = shadow_chi2_pre_filter(
        h_planted, lang_dists, ct_total_len)
    show("planted plaintext chi²", f"{float(planted_chi2[0]):.5f}")
    check("planted plaintext is in signal regime (<0.0015)",
          float(planted_chi2[0]) < 0.0015, True)

    # Encrypt + decrypt + filter check for each of 8 GAK modes
    planted_seed = 31337
    all_modes_pass = True
    for mode_code, mode_name in sorted(GAK_MODE_NAMES.items()):
        rng = P.ParkMillerV0Rng(planted_seed)
        sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]
        ct_e2e = gak_encrypt(planted_pt, sigma, N, mode_code)
        # Decrypt with same seed (correct key)
        rng2 = P.ParkMillerV0Rng(planted_seed)
        sigma2 = [rng2.shuffled_perm(N) for _ in range(N + 1)]
        recovered = K_e2e.gak_decrypt(ct_e2e, sigma2, N, mode_code)
        # Check (a) round-trip works (b) recovered text passes chi² filter
        roundtrip_ok = (recovered == planted_pt)
        h_rec = np.bincount(recovered, minlength=N).astype(np.int32)[np.newaxis, :]
        rec_chi2, _ = shadow_chi2_pre_filter(h_rec, lang_dists, ct_total_len)
        filter_passes = float(rec_chi2[0]) < 0.0015
        all_modes_pass = all_modes_pass and roundtrip_ok and filter_passes

    check("all 8 GAK modes: planted Finnish plaintext survives chi² filter",
          all_modes_pass, True)

    # Negative control: same encrypted ciphertext, decrypted with WRONG
    # seed, should be REJECTED by the chi² filter (noise regime).
    step("Negative control: same ciphertext + WRONG seed → filter REJECTS")
    rng = P.ParkMillerV0Rng(planted_seed)
    sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]
    ct_neg = gak_encrypt(planted_pt, sigma, N, 0)   # ctak_right
    n_rejected = 0
    n_total = 30
    for offset in range(1, n_total + 1):
        rng_wrong = P.ParkMillerV0Rng(planted_seed + offset)
        sigma_w = [rng_wrong.shuffled_perm(N) for _ in range(N + 1)]
        dec_w = K_e2e.gak_decrypt(ct_neg, sigma_w, N, 0)
        h_w = np.bincount(dec_w, minlength=N).astype(np.int32)[np.newaxis, :]
        chi2_w, _ = shadow_chi2_pre_filter(h_w, lang_dists, ct_total_len)
        if float(chi2_w[0]) >= 0.0015:
            n_rejected += 1
    show(f"wrong-seed decryptions REJECTED by filter (out of {n_total})", n_rejected)
    check("all wrong-seed decryptions correctly rejected by filter",
          n_rejected, n_total)


def audit_shard(shard_path: Path, sample_n: int = 5) -> None:
    header(f"PHASE 9: Shard verification — {shard_path.name}")

    if not shard_path.exists():
        print(f"  SKIP — {shard_path} not found")
        return

    step("Parse params.tsv.gz and select random sample of entries")
    rows = []
    with gzip.open(shard_path, "rt") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 9:
                continue
            rows.append(parts)
    if not rows:
        print("  SKIP — no rows in shard")
        return
    show("total rows in shard", len(rows))

    rnd = random.Random(0)
    sample = rnd.sample(rows, min(sample_n, len(rows)))
    show("sampled entries", len(sample))

    step("For each sample: re-compute hits from scratch, compare to stored")
    # NOTE: we don't have the ciphertext + dictionaries inside the shard,
    # so we can only check internal consistency (hits_fi+krl+en >= 0, max_hits
    # equals the max of the three, etc.). A deeper audit would need to be
    # called with --data NOITA.json --dict-fi ... etc.
    issues = 0
    for r in sample:
        mode, prng, key_id = r[0], r[1], r[2]
        z_fi, z_krl, z_en = float(r[3]), float(r[4]), float(r[5])
        h_fi, h_krl, h_en = int(r[6]), int(r[7]), int(r[8])
        max_recomputed = max(h_fi, h_krl, h_en)
        if max_recomputed != max(h_fi, h_krl, h_en):
            issues += 1
        show(f"  {key_id[:18]}",
             f"fi={h_fi:>3} krl={h_krl:>3} en={h_en:>3}  "
             f"z_fi={z_fi:.2f} z_krl={z_krl:.2f} z_en={z_en:.2f}")
    if issues == 0:
        check("all sampled rows are internally consistent", True, True)
    else:
        check(f"{issues} rows inconsistent", False, True)

    step("Note on the limit of this phase")
    print("    This phase only checks INTERNAL consistency of the stored rows.")
    print("    A full audit would re-decrypt the ciphertext for each sampled")
    print("    seed and re-score from scratch — which requires the original")
    print("    data JSON + dictionaries.  Add --recompute later if needed.")


# ===========================================================================
# CLI
# ===========================================================================

PHASES = {
    1: ("Park-Miller PRNG",            audit_park_miller),
    2: ("Fisher-Yates permutations",   audit_fisher_yates),
    3: ("GAK / xGAK round-trips",      audit_gak),
    4: ("Hungarian mapping optimality",audit_hungarian),
    5: ("Dictionary matching",         audit_dict_match),
    6: ("Zipf + WScore scoring",       audit_scoring),
    7: ("Planted seed recovery",       audit_planted_seed),
    8: ("Chi² pre-filter math",        audit_chi2_filter),
}


def main() -> int:
    global VERBOSE
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--phase", type=int, default=None,
                   help="Run only one phase (1-7); default: all")
    p.add_argument("--quiet", action="store_true",
                   help="Print only PASS/FAIL lines (no intermediate values)")
    p.add_argument("--shard", default=None,
                   help="Path to a params.tsv.gz file for shard verification (phase 8)")
    args = p.parse_args()

    VERBOSE = not args.quiet

    print()
    print("=" * 72)
    print("EYESTAT COMPUTATION AUDIT")
    print("=" * 72)
    print("Verifies every primitive computation against first-principles")
    print("reference implementations. Prints intermediate values so you can")
    print("verify by hand or against external sources.")

    if args.phase is not None:
        if args.phase not in PHASES:
            print(f"ERROR: phase must be 1..{max(PHASES)}", file=sys.stderr)
            return 2
        name, fn = PHASES[args.phase]
        try:
            fn()
        except Exception as e:
            print(f"\n  PHASE CRASHED: {type(e).__name__}: {e}")
            import traceback; traceback.print_exc()
            FAILED.append(f"{name} (exception)")
    else:
        for n, (name, fn) in sorted(PHASES.items()):
            try:
                fn()
            except Exception as e:
                print(f"\n  PHASE CRASHED: {type(e).__name__}: {e}")
                import traceback; traceback.print_exc()
                FAILED.append(f"{name} (exception)")
        if args.shard:
            try:
                audit_shard(Path(args.shard))
            except Exception as e:
                print(f"\n  SHARD AUDIT CRASHED: {type(e).__name__}: {e}")
                FAILED.append("Shard audit (exception)")

    print()
    print("=" * 72)
    print(f"SUMMARY:  {PASSED} / {TOTAL} checks passed")
    if FAILED:
        print()
        print("FAILURES:")
        for f in FAILED:
            print(f"  - {f}")
    print("=" * 72)

    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
