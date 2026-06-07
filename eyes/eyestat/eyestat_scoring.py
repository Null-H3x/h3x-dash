#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_scoring.py — dictionary scoring + rune-to-letter mapping.

PIPELINE
========
1. Load dictionaries (Finnish, Karelian, English) into trie or set structures
   for fast multi-word substring matching.
2. Compute target language letter frequencies.
3. For a given decrypted symbol sequence (in 0..N-1), generate candidate
   rune→letter mappings:
     - DEFAULT: identity (rune i → letter i if N == alphabet size, else
       (i mod alphabet_size) for direct fallback).
     - HUNGARIAN OPTIMUM: solve the assignment problem to match symbol
       frequencies in the decrypted sequence to language letter frequencies.
     - PERTURBED: top-1000 mappings by perturbing the Hungarian optimum
       with single-pair swaps.
4. For each mapping, transform the decrypted sequence to a letter string and
   count dictionary word occurrences.
5. Return the score breakdown.

HUNGARIAN ALGORITHM
===================
Pure-Python O(n³) implementation since scipy may not be available. For
n ~ 30 (alphabet size), this is ~27k ops per call — negligible.
"""

from __future__ import annotations

import gzip
import math
import random
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Fixed seed for the deterministic perturbation-order shuffle in
# perturbed_mappings. Keeping a constant seed preserves reproducibility (the
# whole pipeline is designed to be byte-deterministic) while spreading the
# explored swaps uniformly across all runes instead of only the low-index ones.
_PERTURB_SEED = 0x59455354  # "YEST"


# ---------------------------------------------------------------------------
# Language alphabet definitions
# ---------------------------------------------------------------------------

# Each language's alphabet ordered by canonical sequence. Letter frequencies
# are approximate, derived from large-corpus references.

LANG_ALPHABETS: Dict[str, str] = {
    "fi":  "abcdefghijklmnopqrstuvwxyzåäö",          # Finnish, 29 chars
    "krl": "abcdefghijklmnoprstuvyzčšžäö",           # Karelian (simplified), 28 chars
    "en":  "abcdefghijklmnopqrstuvwxyz",             # English, 26 chars
}

# Approximate letter frequencies (relative). Exact values are recomputed
# from the dictionaries themselves on load to be self-consistent.
LANG_DEFAULT_FREQS: Dict[str, Dict[str, float]] = {
    "fi":  {  # Finnish frequencies (approximate, %)
        "a": 12.2, "i": 10.6, "t": 9.8, "n": 8.7, "e": 8.0, "s": 7.8,
        "l": 5.8, "o": 5.6, "u": 5.0, "k": 4.9, "ä": 3.6, "m": 3.3,
        "r": 2.9, "v": 2.4, "j": 2.0, "h": 1.8, "y": 1.7, "p": 1.7,
        "d": 1.0, "ö": 0.5, "g": 0.4, "b": 0.3, "f": 0.2, "c": 0.1,
        "w": 0.1, "z": 0.1, "å": 0.04, "x": 0.03, "q": 0.01,
    },
    "krl": {  # Karelian — using Finnish as proxy with adjustments
        "a": 11.5, "i": 10.5, "n": 9.0, "t": 8.5, "e": 8.0, "s": 7.5,
        "l": 6.0, "o": 5.5, "u": 4.8, "k": 5.0, "ä": 3.5, "m": 3.5,
        "r": 3.0, "v": 2.5, "j": 2.0, "h": 1.8, "y": 1.5, "p": 1.5,
        "d": 0.8, "ö": 0.5, "g": 0.4, "b": 0.3, "f": 0.2, "c": 0.1,
        "z": 0.05, "č": 0.3, "š": 0.2, "ž": 0.1,
    },
    "en":  {  # English (Norvig-style)
        "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7,
        "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8,
        "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0,
        "p": 1.9, "b": 1.5, "v": 1.0, "k": 0.8, "j": 0.15, "x": 0.15,
        "q": 0.1, "z": 0.07,
    },
}


# ---------------------------------------------------------------------------
# Dictionary loading
# ---------------------------------------------------------------------------

class Dictionary:
    """Set-based dictionary with optional Zipf-rank weighting.

    Stores normalized lowercase forms; lookups should normalize inputs the
    same way before checking membership.
    """

    def __init__(self, lang: str):
        self.lang = lang
        self.words: Set[str] = set()
        self.zipf_rank: Dict[str, int] = {}
        self.total_chars = 0
        self.letter_counts: Counter = Counter()

    def load(self, path: Path) -> None:
        """Load words from a text file, one word per line. Supports .gz.

        Can be called MULTIPLE TIMES on the same Dictionary to merge wordlists
        (e.g. a base language dict + a domain-specific supplement). Words
        already present keep their original Zipf rank; new words get ranks
        appended after the existing maximum. Letter-frequency stats and
        per-word zipf_rank are accumulated only for first-seen words, so
        merging is order-sensitive for rank but not for membership."""
        next_rank = len(self.zipf_rank) + 1
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if not w or len(w) < 2:
                    continue
                # Filter out non-alphabetic chars (keep apostrophes, hyphens)
                if any(c.isdigit() for c in w):
                    continue
                if w in self.words:
                    continue
                self.words.add(w)
                self.zipf_rank[w] = next_rank
                next_rank += 1
                for ch in w:
                    if ch.isalpha():
                        self.letter_counts[ch] += 1
                        self.total_chars += 1

    def letter_frequencies(self) -> Dict[str, float]:
        """Empirical letter frequencies as percentages."""
        if self.total_chars == 0:
            return LANG_DEFAULT_FREQS.get(self.lang, {})
        return {ch: 100.0 * cnt / self.total_chars
                for ch, cnt in self.letter_counts.items()}

    def __contains__(self, word: str) -> bool:
        return word in self.words

    def __len__(self) -> int:
        return len(self.words)


# ---------------------------------------------------------------------------
# Hungarian algorithm (rectangular)
# ---------------------------------------------------------------------------

INF = float("inf")


try:
    from scipy.optimize import linear_sum_assignment as _scipy_lsa
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False


def compute_expected_sorted_distribution(language: str, N: int) -> List[float]:
    """Compute the expected per-rune frequency distribution under the
    homophonic substitution hypothesis, sorted descending.

    For an alphabet of size L < N, each letter is assigned ceil(N/L) or
    floor(N/L) homophone slots (alphabetical allocation, matching
    hungarian_optimal_mapping's N>L branch). Each slot's expected frequency
    is the letter's overall frequency divided by that letter's slot count —
    intuitively, a letter that appears 12% of the time spread across 3
    homophones gives each homophone ~4%.

    The returned list is the SHAPE of the expected per-rune frequency
    distribution — sorted descending, with no rune-identity information. This
    is what gets compared against the candidate's sorted rune histogram in
    the chi² pre-filter, since the candidate's specific rune→letter
    assignment is unknown (Hungarian solves that downstream).

    Returns: list of N floats summing approximately to 1.0 (modulo rounding
    in LANG_DEFAULT_FREQS, which uses 1-decimal percentages).
    """
    if language not in LANG_ALPHABETS:
        raise KeyError(f"Unknown language {language!r}; "
                       f"valid: {sorted(LANG_ALPHABETS)}")
    letters = LANG_ALPHABETS[language]
    L = len(letters)
    letter_freqs = LANG_DEFAULT_FREQS.get(language, {})

    if N <= L:
        # Fewer runes than letters. The downstream Hungarian step is free to
        # assign these N runes to ANY N of the L letters (it uses the full
        # rectangular N×L cost matrix, NOT just the alphabetically-first N).
        # A language-like decryption therefore lands on the most frequent
        # letters, so the candidate-agnostic expected SHAPE is the N
        # highest-frequency letters. Using letters[:N] (alphabetical) injected
        # rare letters like 'q'/'x'/'z' into the expected tail and
        # mis-calibrated the chi² pre-filter for any run with N <= L.
        ranked = sorted(letters, key=lambda l: letter_freqs.get(l, 0.0),
                        reverse=True)
        used_letters = ranked[:N]
        slots: Dict[str, int] = {l: 1 for l in used_letters}
    else:
        # Homophonic: extended_letters[:N] gives the slot-by-slot layout
        n_repeats = (N + L - 1) // L
        extended = list(letters) * n_repeats
        used_letters = extended[:N]
        slots = {}
        for l in used_letters:
            slots[l] = slots.get(l, 0) + 1

    # Per-rune expected frequency under perfect homophonic spreading.
    # LANG_DEFAULT_FREQS is in percentages, so /100.
    per_rune = [
        letter_freqs.get(l, 0.0) / slots[l] / 100.0
        for l in used_letters
    ]
    per_rune.sort(reverse=True)
    return per_rune


def hungarian_min_cost(cost: List[List[float]]) -> List[int]:
    """Solve the assignment problem: find col_for_row[i] minimizing
    sum(cost[i][col_for_row[i]]).

    Delegates to scipy.optimize.linear_sum_assignment (C implementation,
    ~200× faster) when scipy is installed; falls back to the pure-Python
    Kuhn-Munkres recipe below otherwise.

    Both paths return the same encoding: a list of length n_rows where
    result[i] is the column assigned to row i, or -1 if row i is unassigned
    (which can happen when n_rows > n_cols, i.e., more rows than columns).

    Install scipy on Ubuntu via:
        sudo apt-get install python3-scipy
    """
    if _HAS_SCIPY:
        n_rows = len(cost)
        # scipy returns paired (row_ind, col_ind) arrays of length min(rows, cols).
        # We need to splat this into a length-n_rows array with -1 for unassigned.
        row_ind, col_ind = _scipy_lsa(cost)
        col_for_row = [-1] * n_rows
        for r, c in zip(row_ind, col_ind):
            col_for_row[int(r)] = int(c)
        return col_for_row
    return _hungarian_min_cost_pure_python(cost)


def _hungarian_min_cost_pure_python(cost: List[List[float]]) -> List[int]:
    """Pure Python O(n³) Kuhn-Munkres fallback. Used only when scipy is
    not installed. Same return contract as hungarian_min_cost.

    cost is rectangular: len(cost) rows × len(cost[0]) cols, with rows ≤ cols.
    """
    n_rows = len(cost)
    n_cols = len(cost[0])
    if n_rows > n_cols:
        # Transpose, solve, then unmap
        transposed = [[cost[r][c] for r in range(n_rows)] for c in range(n_cols)]
        row_for_col = _hungarian_min_cost_pure_python(transposed)
        col_for_row = [-1] * n_rows
        for c, r in enumerate(row_for_col):
            if r >= 0:
                col_for_row[r] = c
        return col_for_row

    # Pad to square if rows < cols
    n = n_cols
    padded = [[cost[r][c] if r < n_rows else 0.0 for c in range(n)] for r in range(n)]

    # Standard O(n³) Kuhn-Munkres on square matrix
    u = [0.0] * (n + 1)
    v = [0.0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)

    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [INF] * (n + 1)
        used = [False] * (n + 1)

        while True:
            used[j0] = True
            i0 = p[j0]
            delta = INF
            j1 = 0
            for j in range(1, n + 1):
                if not used[j]:
                    cur = padded[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j] = cur
                        way[j] = j0
                    if minv[j] < delta:
                        delta = minv[j]
                        j1 = j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break

        while j0 != 0:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1

    col_for_row = [0] * n
    for j in range(1, n + 1):
        if p[j] > 0:
            col_for_row[p[j] - 1] = j - 1

    return col_for_row[:n_rows]


# ---------------------------------------------------------------------------
# Rune→letter mapping generation
# ---------------------------------------------------------------------------

def hungarian_optimal_mapping(rune_freq: Dict[int, float],
                              letter_freq: Dict[str, float],
                              alphabet_size: int,
                              language: str) -> Dict[int, str]:
    """Compute the Hungarian-optimum rune→letter mapping.

    rune_freq:   {rune_index: percent_frequency in decrypted output}
    letter_freq: {letter: percent_frequency in language}
    alphabet_size: number of distinct runes (e.g., 83)
    language: which language's alphabet to map to

    Cost matrix entry [r][l] = (rune_freq[r] - letter_freq[l])^2.
    Solving min-cost assignment gives the most-frequency-consistent mapping.

    For alphabet_size > len(language_alphabet), runes beyond the alphabet
    map by direct index modulo alphabet length.
    """
    lang_alphabet = LANG_ALPHABETS[language]
    L = len(lang_alphabet)

    runes_sorted = list(range(alphabet_size))
    letters = list(lang_alphabet)

    # Build cost matrix: rows = runes (alphabet_size), cols = letters (L).
    # Pad letters by repeating if alphabet_size > L (homophonic mapping).
    if alphabet_size > L:
        # Repeat letters to make square-ish; each letter gets extra "slots"
        n_repeats = (alphabet_size + L - 1) // L
        extended_letters = []
        for rep in range(n_repeats):
            extended_letters.extend(letters)
        letters_to_use = extended_letters[:alphabet_size]
    else:
        # Hungarian should pick the BEST N letters from the full alphabet,
        # not just the first N. scipy.optimize.linear_sum_assignment handles
        # rectangular N × L cost matrices correctly.
        letters_to_use = letters

    # Build cost matrix
    cost = []
    for r in runes_sorted:
        row = []
        rf = rune_freq.get(r, 0.0)
        for l in letters_to_use:
            lf = letter_freq.get(l, 0.0)
            row.append((rf - lf) ** 2)
        cost.append(row)

    col_for_row = hungarian_min_cost(cost)
    return {r: letters_to_use[col_for_row[r]] for r in runes_sorted}


def perturbed_mappings(base: Dict[int, str], n_perturbations: int) -> List[Dict[int, str]]:
    """Generate `n_perturbations` distinct mappings by single-pair swaps from
    the base mapping. Returns base + perturbed; total = 1 + n_perturbations."""
    runes = sorted(base.keys())
    n = len(runes)
    seen: Set[Tuple[Tuple[int, str], ...]] = set()

    def to_key(m: Dict[int, str]) -> Tuple[Tuple[int, str], ...]:
        return tuple(sorted(m.items()))

    out: List[Dict[int, str]] = [dict(base)]
    seen.add(to_key(base))

    # Generate single-swap perturbations. Iterate the candidate pairs in a
    # deterministically-shuffled order so the explored neighborhood is spread
    # uniformly across ALL runes. The previous lexicographic order only ever
    # swapped the lowest-indexed runes — for an 83-rune alphabet every one of
    # the first ~1000 pairs involves runes 0..16, leaving high-index runes
    # (and therefore most high-frequency-letter assignments) completely
    # unexplored. Fixed seed keeps the search reproducible.
    pairs = list(combinations(runes, 2))
    random.Random(_PERTURB_SEED).shuffle(pairs)
    for r1, r2 in pairs:
        if len(out) >= n_perturbations + 1:
            break
        m = dict(base)
        m[r1], m[r2] = m[r2], m[r1]
        k = to_key(m)
        if k not in seen:
            seen.add(k)
            out.append(m)

    # If we need more, do double swaps (4-perms)
    if len(out) < n_perturbations + 1:
        for r1, r2, r3, r4 in combinations(runes, 4):
            if len(out) >= n_perturbations + 1:
                break
            m = dict(base)
            m[r1], m[r2] = m[r2], m[r1]
            m[r3], m[r4] = m[r4], m[r3]
            k = to_key(m)
            if k not in seen:
                seen.add(k)
                out.append(m)

    return out[:n_perturbations + 1]


# ---------------------------------------------------------------------------
# Decryption-output scoring
# ---------------------------------------------------------------------------

def apply_mapping(symbols: List[int], mapping: Dict[int, str]) -> str:
    """Convert a sequence of rune indices to a letter string."""
    return "".join(mapping.get(s, "?") for s in symbols)


def count_dictionary_hits(text: str, dictionary: Dictionary,
                          min_word_len: int = 4,
                          max_word_len: int = 20) -> Tuple[int, List[str]]:
    """Count distinct dictionary word occurrences in `text` (substring match).

    Uses a sliding-window over text, checking every substring of length
    [min_word_len, max_word_len] against the dictionary. Returns
    (count, list_of_hits_unique).

    NOTE: min_word_len defaults to 4 because 3-letter words (especially in
    Finnish, where many common particles like 'aie', 'ali', 'apu' are 3
    letters) match random text by chance — the noise floor in a 9000-char
    random string is ~30 hits at min_word_len=3, dropping to ~5-10 at
    min_word_len=4 and ~1-2 at min_word_len=5. Tune via the runner CLI.
    """
    n = len(text)
    hits: List[str] = []
    seen: Set[str] = set()
    for i in range(n):
        for L in range(min_word_len, max_word_len + 1):
            if i + L > n:
                break
            w = text[i:i + L]
            if w in dictionary and w not in seen:
                hits.append(w)
                seen.add(w)
    return len(hits), hits


def zipf_score(hits: List[str], dictionary: Dictionary) -> float:
    """Score = sum over hits of -log(rank). Rare words contribute less,
    common words contribute more. Cap rank at 10000 to avoid -inf."""
    score = 0.0
    for w in hits:
        rank = dictionary.zipf_rank.get(w, 10000)
        rank = min(rank, 10000)
        score += -math.log(max(1, rank) / 10001.0)
    return score


def length_weighted_score(hits: List[str], exponent: float = 2.0) -> float:
    """Score = sum of len(w)**exponent across the hit list.

    Rationale: chance substring matches in random text are dominated by short
    words (4-letter matches in a 1036-char string mapped to common letters
    happen ~10 times by chance). Longer matches are exponentially rarer:
    a 7-letter match is ~1000x less likely than a 4-letter match.

    Raising raw count (which weighs everything equally) to length-weighted
    summation typically gives 3-5x better signal-to-noise vs the noise floor
    for natural language plaintexts.

    Defaults to exponent=2 (squared length). At min_word_len=4 the per-hit
    contributions are: 4-letter→16, 5→25, 6→36, 7→49, 10→100.

    Pure scoring function; takes a unique-or-not list, callers should pass the
    de-duplicated set if they want hits counted once."""
    return float(sum(len(w) ** exponent for w in hits))


# ---------------------------------------------------------------------------
# End-to-end scoring helper
# ---------------------------------------------------------------------------

def score_decryption(decrypted_symbols: List[int],
                     alphabet_size: int,
                     dictionaries: Dict[str, Dictionary],
                     n_mappings: int = 1000) -> Dict[str, dict]:
    """For each language dictionary, find the best rune→letter mapping and
    score the decryption.

    Returns: {language: {"hits": int, "zipf_score": float,
                          "best_mapping": dict, "decrypted_text": str}}
    """
    # Empirical rune frequency in the decrypted output
    rune_counts = Counter(decrypted_symbols)
    total = sum(rune_counts.values())
    if total == 0:
        rune_freq = {r: 0.0 for r in range(alphabet_size)}
    else:
        rune_freq = {r: 100.0 * rune_counts.get(r, 0) / total
                     for r in range(alphabet_size)}

    results: Dict[str, dict] = {}
    for lang, dictionary in dictionaries.items():
        letter_freq = dictionary.letter_frequencies()
        if not letter_freq:
            letter_freq = LANG_DEFAULT_FREQS[lang]

        # Hungarian optimum
        opt_mapping = hungarian_optimal_mapping(rune_freq, letter_freq,
                                                 alphabet_size, lang)
        # Top-N mappings via perturbation
        candidate_mappings = perturbed_mappings(opt_mapping, n_mappings - 1)

        best = {"hits": 0, "zipf_score": 0.0, "best_mapping": None,
                "decrypted_text": ""}
        for m in candidate_mappings:
            text = apply_mapping(decrypted_symbols, m)
            hits, hit_list = count_dictionary_hits(text, dictionary)
            if hits > best["hits"]:
                z = zipf_score(hit_list, dictionary)
                best = {"hits": hits, "zipf_score": z, "best_mapping": m,
                        "decrypted_text": text, "hit_words": hit_list}
        results[lang] = best
    return results


# ---------------------------------------------------------------------------
# Selftests
# ---------------------------------------------------------------------------

def selftest_hungarian() -> bool:
    """Hungarian KATs: small KAT, larger KATs with known optima, rectangular
    cases, and random vs brute-force cross-validation."""
    # 3x3 KAT
    cost = [[4, 1, 3], [2, 0, 5], [3, 2, 2]]
    result = hungarian_min_cost(cost)
    if sum(cost[r][result[r]] for r in range(3)) != 5 or len(set(result)) != 3:
        return False

    # 5x5 diagonal-cheap (optimum = 1+2+3+4+5 = 15)
    cost = [[1 if i == j else 9 for j in range(5)] for i in range(5)]
    cost = [[c if c == 9 else (i + 1) for j, c in enumerate(row)]
            for i, row in enumerate(cost)]
    # Actually simpler: diagonal contains 1..5
    cost = [[(i+1) if i == j else 9 for j in range(5)] for i in range(5)]
    result = hungarian_min_cost(cost)
    if sum(cost[r][result[r]] for r in range(5)) != 15:
        return False

    # 4x4 anti-diagonal (optimum = 4)
    cost = [[1 if i + j == 3 else 9 for j in range(4)] for i in range(4)]
    result = hungarian_min_cost(cost)
    if sum(cost[r][result[r]] for r in range(4)) != 4:
        return False

    # 2x4 rectangular (more cols than rows, optimum = 3)
    cost = [[5, 1, 8, 9], [3, 7, 2, 6]]
    result = hungarian_min_cost(cost)
    if sum(cost[r][result[r]] for r in range(2)) != 3:
        return False

    # 4x2 rectangular (more rows than cols, optimum = 2 with 2 unassigned rows)
    cost = [[1, 9], [9, 1], [3, 5], [7, 7]]
    result = hungarian_min_cost(cost)
    # Two rows must have -1 (unassigned), the other two should pick (col 0, col 1)
    assigned = [r for r, c in enumerate(result) if c >= 0]
    if len(assigned) != 2:
        return False

    # Random 6x6 vs brute-force
    import random as _r
    rng = _r.Random(20250510)
    cost = [[rng.uniform(0, 100) for _ in range(6)] for _ in range(6)]
    result = hungarian_min_cost(cost)
    hung_total = sum(cost[r][result[r]] for r in range(6))
    # Brute-force min over all 6! = 720 permutations
    from itertools import permutations
    bf_min = min(sum(cost[i][p[i]] for i in range(6)) for p in permutations(range(6)))
    if abs(hung_total - bf_min) > 1e-9:
        return False

    return True


def selftest_perturbation() -> bool:
    """Verify perturbed_mappings generates distinct valid mappings."""
    base = {i: chr(ord('a') + i) for i in range(5)}
    perts = perturbed_mappings(base, 5)
    if len(perts) != 6:
        return False
    if perts[0] != base:
        return False
    seen = set()
    for m in perts:
        # Each must be a valid permutation
        vals = list(m.values())
        if sorted(vals) != sorted(base.values()):
            return False
        seen.add(tuple(sorted(m.items())))
    return len(seen) == len(perts)


def selftest_dictionary_hits() -> bool:
    """Synthetic dictionary; check substring matching."""
    d = Dictionary("en")
    d.words = {"the", "cat", "sat", "mat", "ate"}
    d.zipf_rank = {w: i for i, w in enumerate(d.words)}
    text = "thecatsatonthemat"
    # Test data uses 3-letter words intentionally to exercise the matcher;
    # production default min_word_len=4 is for noise-floor reasons.
    n_hits, hits = count_dictionary_hits(text, d, min_word_len=3)
    expected = {"the", "cat", "sat", "mat"}
    return set(hits) == expected


def run_all_selftests(verbose: bool = True) -> bool:
    if verbose:
        print("Scoring module selftests:")
    tests = [
        ("hungarian_min_cost",  selftest_hungarian()),
        ("perturbed_mappings",  selftest_perturbation()),
        ("dictionary_hits",     selftest_dictionary_hits()),
    ]
    all_ok = True
    for name, ok in tests:
        if verbose:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        all_ok = all_ok and ok
    return all_ok


if __name__ == "__main__":
    run_all_selftests(verbose=True)
