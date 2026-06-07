# EyeStat — Statistical Cryptanalysis Pipeline

**Goal:** Recover plaintext from 9 in-game "eye message" ciphertexts in Noita (Finnish indie game). Cipher family, PRNG, and key are all unknown — we brute-force the joint hypothesis space.

Looking for review from coders, mathematicians, and cryptographers — both on the workflow correctness and on what hypotheses might be missing.

---

## Inputs

**Verified ciphertext** (from `noita_eye_data.json`, deobfuscated from game assets):
```
9 messages,  1036 total symbols,  N = 83 distinct runes
```

**Reference distributions** for scoring (built from canonical letter frequencies):
- Finnish: 29-letter alphabet (a-z + å, ä, ö)
- Karelian: 28-letter alphabet (simplified)
- English: 26-letter alphabet

Each maps to an 83-rune homophonic frequency profile (e.g. Finnish 'a' at 12.2% gets 3 homophone slots, each ~4.07%).

---

## Hypothesis Grid

For each (mode, PRNG, seed) tuple, test:
```
ciphertext = GAK_encrypt(plaintext, σ(seed), mode)
```

**Cipher modes** — 19 modes across 7 families:
- GAK family (8 modes): ctak_right, ctak_left, ptak_right, ptak_left, xgak_sum_r/l, xgak_diff_r/l
- KAK family (2), CFB (2), OFB (1), Vigenère (3), Pontifex, Mirdek, Card Chameleon

**PRNG families** — 10 generators:
- Park-Miller V0 (a=16807, 1988)
- Park-Miller V1 (a=48271, 1993 revision)
- Xorshift32, Xorshift64, PCG32, Splitmix64, MT19937
- Numerical Recipes LCG, glibc LCG, MSVC LCG

Total grid: **190 (mode, PRNG) hypothesis pairs**. Each Park-Miller PRNG has 2³¹ − 2 ≈ 2.15B valid seeds; sweeping one pair takes ~2 hours on an RTX 5080.

---

## Per-Candidate Pipeline (GPU then CPU)

### 1. PRNG state generation (GPU CUDA kernel)
Park-Miller Lehmer LCG with Schrage's algorithm in 32-bit math:
```
state_0       = seed (rescued to 1 if ∈ {0, M})
state_{n+1}   = (A · state_n) mod M
M             = 2^31 - 1   (Mersenne prime)
A             = 16807 (V0) or 48271 (V1)
```

Known-Answer Tests (10,000th iterate of seed=1):
- V0: `1,043,618,065` (matches canonical Park & Miller 1988 paper)
- V1: `399,268,537` (computed; deterministic given a, M)

### 2. Permutation schedule (GPU CUDA)
84 permutations of {0..82} via Fisher-Yates with rejection-sampling `next_below(n)` for unbiased uniform draws.

### 3. GAK decryption (GPU CUDA)
Maintains an `active` permutation that evolves per symbol. For `ctak_right`:
```
p_i      = active_inv[c_i]              (decrypt one rune)
active   = active ∘ σ[c_i]              (update with ciphertext feedback)
```
Output: 1036-rune candidate decryption.

### 4. Histogram (GPU CUDA)
83-bin frequency histogram of the candidate output. Block-per-candidate, atomic shared-memory accumulation.

### 5. Chi² shape filter (GPU CUDA) — Phase 1.5
This is the throughput-critical optimization. **Rejects candidates whose rune-frequency distribution SHAPE doesn't match any natural language.**
```
f_c[i]       = histogram[i] / 1036                     (frequencies)
sorted_f_c   = sort descending(f_c)                     (shape, no rune identity)
chi²_ℓ       = Σᵢ (sorted_f_c[i] - expected_sorted_ℓ[i])²
min_chi²     = min over ℓ ∈ {fi, krl, en}
PASS if min_chi² < threshold (default 0.0015)
```

**Note:** "chi²" is a misnomer here — it's squared L2 distance, not the statistical chi-squared (which would divide by expected[i] and have div-by-zero at the distribution tail). L2 is monotonically equivalent for ranking and free of the singularity.

**Empirical calibration** (50 random Park-Miller seeds against real Noita ct):
```
Real-cipher noise chi²:   range  0.00552 - 0.00792   (median 0.00677)
Real-signal chi²:         range  0.00011 - 0.00051   (median 0.00021)
Default threshold 0.0015 sits in the 10× gap. ~3.7× safety margin from noise.
```

**Permutation invariance** is the key correctness property: the filter sorts before comparing, so chi² is unchanged under any permutation of the histogram bins. Verified via 20 random permutations → bit-identical chi².

### 6. Hungarian assignment (CPU pool, survivors only)
Globally optimal rune → letter mapping:
```
cost[i][j]    = |observed_freq[i] - expected_freq[j]|²
col_for_row[i] = argmin assignment over linear_sum_assignment
```
Via scipy's `linear_sum_assignment` (C implementation of Hungarian / Jonker-Volgenant). Returns the rune → letter map.

### 7. Dictionary scan + scoring (CPU pool)
For each language:
- `apply_mapping(decrypted, rune→letter)` → 1036-character text string
- `hits[lang]` = count of dictionary words found as substrings
- `zipf_score[lang]` = Σ -log(rank(w) / 10001) over hit words (rewards common-word density)
- `length_weighted_score[lang]` = Σ |w|² over hit words

If `max(hits[fi], hits[krl], hits[en]) >= threshold` (default 13): write entry to `results.txt`.

---

## Output Files

Per shard (1M-seed range), two files:
```
params_{mode}_{prng}_{seed_start}_{seed_end}.tsv.gz
  → row per chi²-survivor: seed, hits_fi, hits_krl, hits_en, zipf scores

results_{mode}_{prng}_{seed_start}_{seed_end}.txt
  → entry per qualifying candidate: full plaintext attempt, scores per lang
```

Atomic write via `tmp → final` rename so crashed/interrupted shards leave no half-written final files. Resume on relaunch skips completed shards.

After full sweep: HTML report aggregating top hits, threshold distributions, and per-shard summaries.

---

## Validation Layer — "Show Your Work"

**57-check compute audit** (`./eyestat_compute_audit.py`):
```
Phase 1:  Park-Miller V0/V1 state advancement (KATs against published refs)
Phase 2:  Fisher-Yates shuffle (uniformity, bijection over n!)
Phase 3:  GAK encrypt/decrypt round-trip identity (all 8 modes)
Phase 4:  Hungarian assignment vs scipy reference
Phase 5:  Dictionary substring matching
Phase 6:  Scoring functions (Zipf, length-weighted)
Phase 7:  Planted-seed end-to-end recovery
Phase 8:  Chi² filter math + permutation invariance + threshold calibration
          (includes empirical noise/signal separation across all 8 GAK modes)
```

**Shadow audit** (`./shadow_audit.py`): every CUDA kernel has a bit-exact NumPy reference. Validated GPU vs shadow on:
- All 8 GAK modes × both Park-Miller variants × 27 edge-case seeds × 9 real ciphertexts
- 256 real Noita decryptions through histogram + chi² kernels
- Permutation invariance + degenerate-input regression tests

**End-to-end test:** plant Finnish-shaped plaintext → encrypt with known seed in each of 8 modes → decrypt → verify chi² filter PASSES recovered text → verify wrong-seed decryptions are REJECTED. 30/30 negative-control rejections per mode.

---

## Throughput

```
Pre-filter baseline:  ~10,000 seeds/sec   (CPU-bound on dict scan)
With chi² pre-filter: ~272,000 seeds/sec  (GPU-bound, ~26× speedup)
Per (mode, PRNG):     ~2.2 hours
Full 8 GAK × 2 PRNG:  ~35 hours
Full hypothesis grid: ~7 days continuous
```

Hardware: AMD Threadripper 9970X + NVIDIA RTX 5080 (Ubuntu 24.04).

---

## What I'm Looking For

- **Cryptographers**: are there cipher families I'm missing? Is the GAK hypothesis well-founded for an indie game puzzle?
- **Mathematicians**: is the L2-on-sorted-distributions filter sound? Better statistic for this regime?
- **Coders**: workflow gaps, bugs, edge cases not covered by the 57-check audit?

Source coming soon to `github.com/Null-H3x/` — pending one more sweep result.
