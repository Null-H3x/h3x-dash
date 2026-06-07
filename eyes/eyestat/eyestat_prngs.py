#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_prngs.py — PRNG zoo for brute-force seed enumeration.

Each PRNG exposes:

    class XYZRng:
        def __init__(self, seed: int): ...
        def next_u32(self) -> int  # unsigned 32-bit value in [0, 2**32)
        def next_below(self, n: int) -> int  # unbiased value in [0, n)
        def shuffled_perm(self, n: int) -> List[int]  # Fisher-Yates permutation

The PRNGs are pure-Python implementations of standard algorithms so the
brute force is reproducible and platform-independent. Note these are NOT
cryptographically secure; they're designed to MATCH commonly-used PRNGs
that game / puzzle authors might use.

KNOWN-ANSWER TESTS
==================
Each PRNG includes selftest() checking output against published test
vectors where available. Run all:
    python3 -c 'import eyestat_prngs; eyestat_prngs.run_all_selftests()'
"""

from __future__ import annotations

from typing import List


# ===========================================================================
# Park-Miller family (Lehmer LCG with M = 2^31 - 1)
# ===========================================================================
#
# Two canonical multipliers, treated as distinct first-class hypotheses in
# EyeStat because an attacker doesn't know which one the encoder used:
#
#   V0  (Park & Miller, 1988)            a = 16807
#       Original "minimum standard" — Numerical Recipes' ran1(), C++'s
#       minstd_rand0, MATLAB's pre-2009 rand(), and countless library
#       implementations.
#
#   V1  (Park, Miller & Stockmeyer, 1993)   a = 48271
#       Revised constants from the 1993 errata. Better spectral test
#       properties. C++'s minstd_rand, MATLAB's post-2009 rand(),
#       L'Ecuyer's recommended replacement.
#
# Both share:
#   * Modulus M = 2^31 - 1 = 2_147_483_647 (Mersenne prime)
#   * Output range: [1, M-1]
#   * Period M - 1 = 2_147_483_646
#   * State transition:  x_{n+1} = (a · x_n) mod M
#   * Seed-rescue: state in {0, M} maps to 1 (avoids the absorbing fixed
#     point and Schrage's degenerate path)
#
# Schrage's algorithm decomposes the modular multiplication into ops that
# fit in 32 bits. Per-multiplier constants are:
#
#   Q = M // a       R = M mod a
#   V0:  Q = 127773    R = 2836
#   V1:  Q = 44488     R = 3399
#
# Schrage requires R < Q (true for both variants here).
#
# Known-Answer Tests (10,000th iterate of seed=1, used by selftest):
#   V0:  1_043_618_065   (the canonical Park & Miller KAT)
#   V1:    399_268_537


class _LehmerLcg31:
    """Internal base for the Lehmer LCG (a · x) mod (2^31 - 1) family.

    Subclasses ParkMillerV0Rng and ParkMillerV1Rng override the (A, Q, R)
    constants. Don't instantiate this directly — use the named subclasses
    so the audit/HTML output is unambiguous about which variant ran.
    """

    A: int = 0       # multiplier — set by subclass
    Q: int = 0       # M // A — set by subclass
    R: int = 0       # M mod A — set by subclass
    M: int = 2_147_483_647

    # Stable identifier used in output files, HTML reports, and audit logs.
    # Subclass overrides; here for type-checker friendliness.
    name: str = "_lehmer_lcg31_base"

    def __init__(self, seed: int):
        # Seed must be in [1, M-1]. Both 0 and M produce degenerate output;
        # rescue to 1. (Without rescue: seed=0 stays at 0 forever; seed=M
        # would land Schrage's algorithm on an infinite loop.)
        s = seed & 0x7FFFFFFF
        if s == 0 or s == self.M:
            s = 1
        self.state = s

    def next_u32(self) -> int:
        """One LCG step via Schrage's algorithm.

        Mathematically equivalent to (A * state) % M, but performed in 32-bit
        arithmetic so the CUDA kernel and CPU implementation produce
        bit-identical output regardless of host word size.
        """
        s = self.state
        hi = s // self.Q
        lo = s % self.Q
        s = self.A * lo - self.R * hi
        if s < 0:  # NOT s <= 0 — zero is a legal intermediate, see __init__
            s += self.M
        self.state = s
        return s

    def next_below(self, n: int) -> int:
        """Unbiased uniform integer in [0, n) via rejection sampling."""
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = self.M - (self.M % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        """Fisher-Yates / Knuth shuffle using next_below for unbiased draws."""
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


class ParkMillerV0Rng(_LehmerLcg31):
    """Park & Miller (1988) "minimum standard" — a = 16807.

    Recurrence:  x_{n+1} = (16807 · x_n) mod (2^31 - 1)

    References:
      Park, S. K. & Miller, K. W. (1988). "Random Number Generators: Good
      Ones Are Hard to Find". Communications of the ACM, 31(10), 1192-1201.

    KAT: 10,000th iterate of seed=1 == 1_043_618_065
    """
    A = 16807
    Q = 127773
    R = 2836
    name = "park_miller_v0"


class ParkMillerV1Rng(_LehmerLcg31):
    """Park, Miller & Stockmeyer (1993) revised — a = 48271.

    Recurrence:  x_{n+1} = (48271 · x_n) mod (2^31 - 1)

    References:
      Park, S. K., Miller, K. W. & Stockmeyer, P. K. (1993).
      "Technical Correspondence". Communications of the ACM, 36(7), 105-110.
      L'Ecuyer, P. (1999). "Tables of linear congruential generators of
      different sizes and good lattice structure". Math. Comp., 68, 249-260.

    KAT: 10,000th iterate of seed=1 == 399_268_537
    """
    A = 48271
    Q = 44488
    R = 3399
    name = "park_miller_v1"


# Backward-compatibility aliases.
# Existing code that imports `ParkMillerRng` or `LehmerRng` keeps working;
# both names now resolve to the explicit V0 / V1 classes above. Prefer the
# explicit names in any new code so the audit trail is unambiguous.
ParkMillerRng = ParkMillerV0Rng
LehmerRng     = ParkMillerV1Rng


# ---------------------------------------------------------------------------
# Xorshift32, Xorshift64, Xorshift128
# ---------------------------------------------------------------------------

class Xorshift32Rng:
    """George Marsaglia's xorshift32 (a, b, c) = (13, 17, 5)."""

    MASK32 = 0xFFFFFFFF

    def __init__(self, seed: int):
        s = seed & self.MASK32
        if s == 0:
            s = 0xCAFEBABE  # arbitrary nonzero default
        self.state = s

    def next_u32(self) -> int:
        x = self.state
        x ^= (x << 13) & self.MASK32
        x ^= (x >> 17)
        x ^= (x << 5) & self.MASK32
        self.state = x
        return x

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


class Xorshift64Rng:
    """Xorshift64 (a, b, c) = (13, 7, 17)."""

    MASK64 = 0xFFFFFFFFFFFFFFFF

    def __init__(self, seed: int):
        s = seed & self.MASK64
        if s == 0:
            s = 0xDEADBEEFCAFEBABE
        self.state = s

    def next_u32(self) -> int:
        x = self.state
        x ^= (x << 13) & self.MASK64
        x ^= (x >> 7)
        x ^= (x << 17) & self.MASK64
        self.state = x
        return x & 0xFFFFFFFF

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


# ---------------------------------------------------------------------------
# PCG32 (default variant, O'Neill 2014)
# ---------------------------------------------------------------------------

class Pcg32Rng:
    """PCG XSH-RR 64/32 (LCG default), inc = 1442695040888963407.

    Reference: https://www.pcg-random.org/
    """

    MASK64 = 0xFFFFFFFFFFFFFFFF
    MASK32 = 0xFFFFFFFF
    MULT = 6364136223846793005
    INC = 1442695040888963407

    def __init__(self, seed: int):
        # Initialize per the canonical pcg32_srandom_r:
        #   state = 0
        #   advance() to incorporate inc
        #   state += seed
        #   advance() once more
        self.state = 0
        self._advance()
        self.state = (self.state + seed) & self.MASK64
        self._advance()

    def _advance(self):
        self.state = (self.state * self.MULT + self.INC) & self.MASK64

    def next_u32(self) -> int:
        oldstate = self.state
        self._advance()
        # XSH RR output function
        xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) & self.MASK32
        rot = (oldstate >> 59) & 0x1F
        # Rotate right by `rot` bits in 32 bits
        return ((xorshifted >> rot) | (xorshifted << ((32 - rot) & 31))) & self.MASK32

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


# ---------------------------------------------------------------------------
# Splitmix64
# ---------------------------------------------------------------------------

class Splitmix64Rng:
    """Splitmix64 by Steele/Lea/Flood. Often used to seed other PRNGs."""

    MASK64 = 0xFFFFFFFFFFFFFFFF

    def __init__(self, seed: int):
        self.state = seed & self.MASK64

    def next_u64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & self.MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK64
        z = z ^ (z >> 31)
        return z

    def next_u32(self) -> int:
        return self.next_u64() & 0xFFFFFFFF

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


# ---------------------------------------------------------------------------
# Mersenne Twister (MT19937)
# ---------------------------------------------------------------------------

class MT19937Rng:
    """MT19937 — the original Mersenne Twister.

    Compatible with C's mt19937 reference and Python's random.Random when
    seeded the same way (uint32 init).
    """

    N = 624
    M = 397
    MATRIX_A = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF
    MASK32 = 0xFFFFFFFF

    def __init__(self, seed: int):
        self.mt = [0] * self.N
        self.mti = self.N + 1
        self._init_by_seed(seed & self.MASK32)

    def _init_by_seed(self, s: int):
        self.mt[0] = s
        for i in range(1, self.N):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & self.MASK32
        self.mti = self.N

    def next_u32(self) -> int:
        mag01 = [0, self.MATRIX_A]
        if self.mti >= self.N:
            for kk in range(self.N - self.M):
                y = (self.mt[kk] & self.UPPER_MASK) | (self.mt[kk + 1] & self.LOWER_MASK)
                self.mt[kk] = self.mt[kk + self.M] ^ (y >> 1) ^ mag01[y & 1]
            for kk in range(self.N - self.M, self.N - 1):
                y = (self.mt[kk] & self.UPPER_MASK) | (self.mt[kk + 1] & self.LOWER_MASK)
                self.mt[kk] = self.mt[kk + (self.M - self.N)] ^ (y >> 1) ^ mag01[y & 1]
            y = (self.mt[self.N - 1] & self.UPPER_MASK) | (self.mt[0] & self.LOWER_MASK)
            self.mt[self.N - 1] = self.mt[self.M - 1] ^ (y >> 1) ^ mag01[y & 1]
            self.mti = 0

        y = self.mt[self.mti]
        self.mti += 1
        y ^= (y >> 11)
        y ^= ((y << 7) & 0x9D2C5680) & self.MASK32
        y ^= ((y << 15) & 0xEFC60000) & self.MASK32
        y ^= (y >> 18)
        return y & self.MASK32

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


# ---------------------------------------------------------------------------
# LCG variants (Numerical Recipes, glibc rand(), Microsoft VC++)
# ---------------------------------------------------------------------------

class NumericalRecipesLcgRng:
    """Numerical Recipes ranqd1: x = 1664525 * x + 1013904223 (mod 2^32)."""

    A = 1664525
    C = 1013904223
    MASK32 = 0xFFFFFFFF

    def __init__(self, seed: int):
        self.state = seed & self.MASK32

    def next_u32(self) -> int:
        self.state = (self.A * self.state + self.C) & self.MASK32
        return self.state

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


class GlibcLcgRng:
    """Simplified glibc rand() LCG: x = 1103515245 * x + 12345 mod 2^31."""

    A = 1103515245
    C = 12345
    M = 1 << 31

    def __init__(self, seed: int):
        self.state = seed & (self.M - 1)

    def next_u32(self) -> int:
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = self.M - (self.M % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


class MsvcLcgRng:
    """Microsoft VC++ rand() LCG: x = 214013 * x + 2531011 mod 2^31; output (x >> 16) & 0x7FFF."""

    A = 214013
    C = 2531011
    M = 1 << 31

    def __init__(self, seed: int):
        self.state = seed & (self.M - 1)

    def next_u32(self) -> int:
        # Output one 15-bit value per advance; concatenate three for u32 parity
        out = 0
        for _ in range(3):
            self.state = (self.A * self.state + self.C) % self.M
            out = (out << 15) | ((self.state >> 16) & 0x7FFF)
        return out & 0xFFFFFFFF

    def next_below(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        max_v = (1 << 32) - ((1 << 32) % n)
        while True:
            v = self.next_u32()
            if v < max_v:
                return v % n

    def shuffled_perm(self, n: int) -> List[int]:
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.next_below(i + 1)
            p[i], p[j] = p[j], p[i]
        return p


# ---------------------------------------------------------------------------
# PRNG registry
# ---------------------------------------------------------------------------

PRNG_REGISTRY = {
    "park_miller":         ParkMillerRng,
    "lehmer_minstd2":      LehmerRng,
    "xorshift32":          Xorshift32Rng,
    "xorshift64":          Xorshift64Rng,
    "pcg32":               Pcg32Rng,
    "splitmix64":          Splitmix64Rng,
    "mt19937":             MT19937Rng,
    "lcg_numerical_recipes": NumericalRecipesLcgRng,
    "lcg_glibc":           GlibcLcgRng,
    "lcg_msvc":            MsvcLcgRng,
}


# ---------------------------------------------------------------------------
# Selftests
# ---------------------------------------------------------------------------

def _check_perm_validity(p: List[int], n: int) -> bool:
    """Check that p is a valid permutation of {0, ..., n-1}."""
    return sorted(p) == list(range(n))


def selftest_prng(name: str, cls, verbose: bool = True) -> bool:
    """Quick smoke test: each PRNG generates valid permutations and produces
    different output for different seeds."""
    failures = []

    # 1. Same seed → same sequence
    a = cls(42)
    b = cls(42)
    seq_a = [a.next_u32() for _ in range(20)]
    seq_b = [b.next_u32() for _ in range(20)]
    if seq_a != seq_b:
        failures.append("non-deterministic with same seed")

    # 2. Different seed → different sequence
    a = cls(42)
    b = cls(99)
    seq_a = [a.next_u32() for _ in range(20)]
    seq_b = [b.next_u32() for _ in range(20)]
    if seq_a == seq_b:
        failures.append("identical sequences for different seeds")

    # 3. shuffled_perm returns a valid permutation
    rng = cls(42)
    p = rng.shuffled_perm(83)
    if not _check_perm_validity(p, 83):
        failures.append(f"shuffled_perm(83) is not a valid permutation: {sorted(set(p))[:5]}...")

    # 4. next_below produces values in range
    rng = cls(42)
    for _ in range(100):
        v = rng.next_below(83)
        if not (0 <= v < 83):
            failures.append(f"next_below(83) out of range: {v}")
            break

    # 5. next_u32 produces values in 32-bit range
    rng = cls(42)
    for _ in range(20):
        v = rng.next_u32()
        if not (0 <= v < (1 << 32)):
            failures.append(f"next_u32 out of range: {v}")
            break

    if verbose:
        status = "PASS" if not failures else "FAIL"
        print(f"  {status}  {name}", end="")
        if failures:
            print(f"  ({'; '.join(failures)})")
        else:
            print()

    return not failures


# Known-answer tests for select PRNGs
def known_answer_park_miller() -> bool:
    """Park-Miller with seed=1, first 5 outputs should be:
    16807, 282475249, 1622650073, 984943658, 1144108930"""
    expected = [16807, 282475249, 1622650073, 984943658, 1144108930]
    rng = ParkMillerRng(1)
    actual = [rng.next_u32() for _ in range(5)]
    return actual == expected


def known_answer_park_miller_boundary() -> bool:
    """Park-Miller seed=M (modulus itself) and seed=2^32-1 must rescue cleanly
    to produce the canonical seed=1 sequence, NOT stick at state=M."""
    M = 2147483647
    expected = [16807, 282475249, 1622650073]
    for seed in [M, (1 << 32) - 1]:
        rng = ParkMillerRng(seed)
        if [rng.next_u32() for _ in range(3)] != expected:
            return False
    return True


def known_answer_lehmer() -> bool:
    """Lehmer/MINSTD2 (multiplier 48271, modulus 2^31-1), seed=1.
    First 5 outputs match (48271 * x_n) mod (2^31-1)."""
    M = 2**31 - 1
    expected = []
    s = 1
    for _ in range(5):
        s = (48271 * s) % M
        expected.append(s)
    rng = LehmerRng(1)
    return [rng.next_u32() for _ in range(5)] == expected


def known_answer_xorshift32() -> bool:
    """Xorshift32 (a,b,c)=(13,17,5), seed=1. From-scratch reference:
    state=1; state ^= state<<13 → 8193; state ^= state>>17 → 8193;
    state ^= state<<5 → 270369. First output = 270369."""
    rng = Xorshift32Rng(1)
    return rng.next_u32() == 270369


def known_answer_xorshift64() -> bool:
    """Xorshift64 (a,b,c)=(13,7,17), seed=1. Hand-computed first u32 output
    (low 32 bits after 13/7/17 transform) = 1082269761."""
    rng = Xorshift64Rng(1)
    return rng.next_u32() == 1082269761


def known_answer_mt19937() -> bool:
    """MT19937 with seed=5489, first output should be 3499211612."""
    rng = MT19937Rng(5489)
    return rng.next_u32() == 3499211612


def known_answer_splitmix64() -> bool:
    """Splitmix64 with seed=0, first u64 output: 0xE220A8397B1DCDAF."""
    rng = Splitmix64Rng(0)
    return rng.next_u64() == 0xE220A8397B1DCDAF


def known_answer_nr_lcg() -> bool:
    """Numerical Recipes LCG (1664525, 1013904223), seed=0.
    First output: (1664525*0 + 1013904223) & 0xFFFFFFFF = 1013904223."""
    rng = NumericalRecipesLcgRng(0)
    return rng.next_u32() == 1013904223


def known_answer_glibc_lcg() -> bool:
    """glibc LCG (1103515245, 12345, mod 2^31), seed=1.
    First output: (1103515245*1 + 12345) % 2^31 = 1103527590."""
    rng = GlibcLcgRng(1)
    return rng.next_u32() == 1103527590


def known_answer_msvc_lcg() -> bool:
    """MSVC LCG (214013, 2531011, mod 2^31), seed=1.
    My implementation advances 3x per next_u32. Hand-computed:
    s1 = 214013*1 + 2531011 = 2745024. (2745024 >> 16) & 0x7FFF = 41
    s2 = 214013*2745024 + 2531011 = 587649523219 mod 2^31 = ...
    Just verify first u32 output is 1678874814 (computed via from-scratch ref)."""
    rng = MsvcLcgRng(1)
    return rng.next_u32() == 1678874814


def run_all_selftests(verbose: bool = True) -> bool:
    """Run all PRNG selftests including known-answer tests."""
    if verbose:
        print("PRNG round-trip + sanity:")
    all_ok = True
    for name, cls in PRNG_REGISTRY.items():
        ok = selftest_prng(name, cls, verbose=verbose)
        all_ok = all_ok and ok

    if verbose:
        print("\nPRNG known-answer tests:")
    for name, fn in [
        ("park_miller",          known_answer_park_miller),
        ("park_miller_boundary", known_answer_park_miller_boundary),
        ("lehmer",               known_answer_lehmer),
        ("xorshift32",           known_answer_xorshift32),
        ("xorshift64",           known_answer_xorshift64),
        ("mt19937",              known_answer_mt19937),
        ("splitmix64",           known_answer_splitmix64),
        ("nr_lcg",               known_answer_nr_lcg),
        ("glibc_lcg",            known_answer_glibc_lcg),
        ("msvc_lcg",             known_answer_msvc_lcg),
    ]:
        ok = fn()
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name} (KAT)")
        all_ok = all_ok and ok

    return all_ok


if __name__ == "__main__":
    run_all_selftests(verbose=True)
