# Noita Eye Messages — Convergence Review & Code Audit

**Scope.** Review of the three lines of effort in `Null-H3x/Noita-Eyesieve`
— **EyeStat** (GPU statistical seed-scan), **EyeSieve** (structural hypothesis
sweep), and **eye-cipher-workbench.html** (interactive workbench) — to (1) map
their capabilities, (2) find where the efforts converge, and (3) audit all code
for mathematical and code-level soundness, with bugfixes.

**Corpus under analysis (shared by all three).** 9 messages
(E1,W1,E2,W2,E3,W3,E4,W4,E5), 1036 symbols, alphabet `deck_size = 83` (prime),
converted from base-5 trigrams. Measured properties that drive everything below:

- **IoC ≈ 0.012** (flat, ≈ uniform `1/83`). No monoalphabetic signal → the
  cipher is **polyalphabetic / keystream**, or a transposition of high-entropy
  source. This is *why* EyeStat hunts a PRNG keystream.
- **Position 1 = 66, position 2 = 5 are universal** across all 9 messages;
  position 0 is a per-message `sigma0`. A fixed 2-symbol header = a built-in crib.
- **Strong shared-prefix "depth" structure**: messages agree column-by-column
  far above chance (e.g. `(E1−W1) mod 83 == 0` at 44% of positions).

---

## Part 1 — Capability map

### EyeStat — GPU statistical seed-scan (`eyestat.zip`, ~14k LoC)

Brute-forces a `(cipher mode × PRNG × seed)` grid; for each seed it decrypts on
the GPU, applies a cheap shape filter, and dictionary-scores the survivors.

| Layer | What it does |
|---|---|
| **PRNGs** (`eyestat_prngs.py`) | 10 generators: Park-Miller V0 (a=16807) / V1 (a=48271) via Schrage, Xorshift32/64, PCG32, Splitmix64, MT19937, NR/glibc/MSVC LCGs. All carry published **KATs**. |
| **Ciphers** (`eyestat_kernels.py`) | 8 GAK/xGAK perm-advance modes, KAK, CFB (mod/sub), OFB, Vigenère (plain/PT-auto/CT-auto), Pontifex/Solitaire, Card Chameleon, Mirdek. |
| **Shape filter** | Sorted-histogram **L2 distance** ("chi²") vs per-language expected shape; rejects ~99.9% on-GPU before any CPU work (10k→272k seeds/s). |
| **Scoring** (`eyestat_scoring.py`) | Hungarian-optimal rune→letter mapping (scipy or pure-Python Kuhn-Munkres) + perturbed neighbors; dictionary substring hits (fi/krl/en) + Zipf/length-weighted score. |
| **Orchestration** | Queue runner, live status TUI, HTML reports, crash recovery, resume. |
| **Validation** | `eyestat_compute_audit.py` (57 checks), `eyestat_selftest.py` (8 phases incl. **Schneier Pontifex KAT** & **Vigenère KAT**), `shadow_audit.py` (bit-exact CPU mirror of every GPU kernel). |

### EyeSieve — structural hypothesis sweep (`eyesieve-v1.0.1.tar.gz`, ~10.5k LoC)

Sweeps `(input-pair × merge-op × key-derivation × cipher)` through a cheap sieve
cascade, then dictionary-scores survivors. Key model is corpus-internal
("**E5 is the key**", Theory 1; transformations of E5, Theory 2) — *not* a PRNG.

| Layer | What it does |
|---|---|
| **Ciphers** (`eyesieve_ciphers.py`) | 12: XOR-stream, Vigenère, Beaufort, Variant-Beaufort, Vigenère/Beaufort autokey, Affine, keyword-substitution, columnar transposition (k=3,4,5,7). |
| **Merge ops** (`eyesieve_sources.py`) | 83: concat, cyclic/truncated add-sub-xor, interleave, index-driven, header/payload split. |
| **Key derivation** (`eyesieve_keyderiv.py`) | Theory 1 Identity; Theory 2 SelfMerge/CrossMerge/ConstantMerge (56 default derivations). |
| **Sieve** (`eyesieve_sieve.py`) | 4 cheap stages: length, alphabet-closure, **IoC band-pass (0.03–0.20)**, symbol-distribution. |
| **Enumerator** | Theory 1 = 7,968 hypotheses; Theory 2 = 446,208; union = 454,176. |
| **Scoring** | **Delegates to `eyestat_scoring.score_decryption`** (shared backend). |
| **Runners / validation** | Single + multiprocess (checkpoint/resume), 218 selftests, preflight. |

### eye-cipher-workbench.html — interactive workbench (~1.1k LoC, single file)

A chainable, manual decryption pipeline plus automated scanners and structural
diagnostics — the human-in-the-loop counterpart to the two batch tools.

| Layer | What it does |
|---|---|
| **Pipeline ops** (`applyOp`) | add/sub (Vigenère), mul, affine, beaufort, xor, sub-table, progressive 4A, two-alphabet 4B, primitive-root, LFSR, chain-addition, autokey, dynamic-substitution, Hill, fractionate, reverse, rotate, railfence, columnar, decimate, atbash, delta, cumsum. |
| **Auto key-scanners** | shift, affine, beaufort, xor, primroot, progression, quad-progression, fractionate-sweep, coset — **ranked by IoC**, click-to-apply onto the pipeline. |
| **Structural diagnostics** | **Friedman** (per-coset IoC by period), **Kasiski** (repeated n-grams), **Δ-isomorph** (constraint-5.2 progressive-alphabet signature). |
| **Scoring/telemetry** | IoC, English letter-frequency match, glyph-frequency histogram, live chips. |

---

## Part 2 — Convergence of efforts

The three tools attack the **same corpus** from three complementary angles:

```
                       ┌───────────────────────────┐
                       │      noita_eye_data.json    │  ← single shared corpus
                       └─────────────┬───────────────┘
        keystream =  PRNG(seed)      │      keystream / key = f(corpus)
                ┌────────────────────┼────────────────────┐
                ▼                    ▼                     ▼
           ┌─────────┐         ┌──────────┐         ┌──────────────┐
           │ EyeStat │         │ EyeSieve │         │  Workbench   │
           │ GPU scan│         │structural│         │ interactive  │
           └────┬────┘         └────┬─────┘         └──────┬───────┘
                │  decrypt → score   │                     │  human triage
                └──────────┬─────────┴─────────────────────┘
                           ▼
                 eyestat_scoring.score_decryption   ← shared scoring backend
```

### Where they already converge
1. **Corpus**: all three consume the same 9 messages (EyeStat/EyeSieve via
   `noita_eye_data.json`; the workbench via an embedded `DATA` blob).
2. **Scoring**: EyeSieve already calls EyeStat's `score_decryption` — one
   Hungarian + dictionary backend, two consumers.

### Where they *should* converge (high-value dedup)
These are duplicated implementations of identical math that should live in one
shared library so a fix/validation in one place covers all three:

| Concern | EyeStat | EyeSieve | Workbench | Action |
|---|---|---|---|---|
| **Corpus loader** | `noita_eye_data.json` | `eyesieve_corpus.py` | embedded `DATA` | one JSON, workbench fetches/builds from it (no literal copy that can drift) |
| **Index of Coincidence** | — | `compute_ic` | `ioc()` | identical formula in 2 places → one tested impl |
| **Modular stream ciphers** (`(c±k) mod 83`, Beaufort, autokey) | kernels | `eyesieve_ciphers` | `applyOp` | one canonical `decrypt(op, vals, params, N)` + shared KAT vectors |
| **English letter freqs** | `LANG_DEFAULT_FREQS['en']` | (via EyeStat) | `ENG[]` | single frequency table |
| **Cheap statistical filters** (IoC / distribution) | shape filter | sieve stages | scanners | reuse sieve as a GPU/JS pre-filter |

### The structural finding that ties them together (and the gap)
The corpus's flat IoC + 44% pairwise agreement says the decisive battleground is
the **keystream**, and that the 9 messages are likely **in depth** (sharing a
keystream). None of the three currently runs an **N-way depth / crib-drag**
attack — EyeStat hunts the keystream *source* (PRNG seed), EyeSieve assumes the
key *is the corpus*, and the workbench analyzes one message at a time. A
keystream-recovery layer that *differences the messages to cancel the unknown
keystream* is the natural convergence point and the most promising unexplored
direction (see Part 5).

### Recommended converged architecture
```
noita-eye-core/                 ← new shared package
├── corpus.py / corpus.json     ← single source of truth (all tools import)
├── cipher_ops.py               ← canonical modular ciphers + KAT vectors
├── stats.py                    ← IoC, χ²/L2, Friedman, Kasiski, Δ-isomorph
├── scoring.py                  ← the existing eyestat_scoring (Hungarian+dict)
└── depth.py   (NEW)            ← N-way depth / crib-drag keystream recovery
```
EyeStat, EyeSieve, and the workbench (via a small WASM/JS build of
`cipher_ops`+`stats`) become thin front-ends over this core.

---

## Part 3 — Audit findings

**Baseline before changes (all green):** EyeStat 57/57 compute-audit, 8/8
selftest, shadow audit bit-exact; EyeSieve 218/218 selftests. The default,
production paths are mathematically sound and well-tested. Notably, EyeStat's
PRNG KATs check out (Park-Miller 10,000th iterate = 1,043,618,065), the Pontifex
KAT is Schneier's real `AAAAAAAAAA → EXKYIZSGEH` vector, and there is an explicit
Vigenère KAT guarding a *previously-fixed* keystream off-by-one. The findings
below are therefore concentrated in the less-tested edges.

Severity: **[M]** = math correctness, **[R]** = robustness/code, **[D]** =
design/quality, **[N]** = noted (not changed).

### EyeStat
- **[M] `compute_expected_sorted_distribution`, `N ≤ L` branch** — the chi²
  pre-filter built its expected shape from the **alphabetically-first N
  letters** (`letters[:N]`), while the Hungarian mapper picks the **best N of
  L**. For any run with alphabet ≤ language size this injected rare letters
  (q/x/z) into the expected tail and mis-calibrated the filter. **Fixed**: use
  the N **highest-frequency** letters. (Dormant for Noita where N=83 > L, but a
  real latent bug.) *Validated: 57/57 still green; the audit's "small-N" top-3
  is unchanged because a/i/t are top by frequency anyway.*
- **[D] `perturbed_mappings` explored a biased neighborhood** — single-pair
  swaps were taken in lexicographic order, so the first ~1000 candidates only
  ever swapped runes 0–16; high-index runes (and thus most high-frequency-letter
  assignments) were never explored. This directly weakens the make-or-break
  scoring step. **Fixed**: iterate the swap candidates in a *deterministically
  shuffled* order (fixed seed → still reproducible) so coverage is uniform
  across all runes.
- **[N] Card Chameleon & Mirdek** are documented "best-effort" implementations
  with **symmetric round-trip selftests only** (no canonical KAT). They are
  correct *inverse pairs* (round-trip passes) but their absolute keystreams are
  unverified against any published spec. Tier-4/future ciphers; left as-is but
  flagged — do not trust a hit from these without a KAT first.

### EyeSieve
- **[R] HTML run-report funnel dropped the `length` stage** —
  `eyesieve_run_report.py` summed kills for only `[alphabet_closure, ic,
  distribution]`, so length-stage kills were invisible and the survivor bar
  could disagree with `killed_by_stage`. **Fixed**: include `length` and append
  any other telemetry stages so custom cascades never silently lose rows.
  Selftest expectation updated 6→7 funnel rows.
- **[R] Silent dropping of unknown Theory-2 config names** —
  `_select_combine_ops` / `_select_permutations` skipped names not found in the
  enumeration, so a typo'd op/permutation name shrank the sweep with no error
  (the run "completed" while skipping whole derivation families). **Fixed**:
  raise `KeyDerivError` listing the unknown name(s) + valid options. Added 2
  selftests. *Validated: 220/220 green.*
- **[N] Coverage gap**: `HeaderPayload(preserve_header="b")` is implemented but
  never enumerated (only `None`/`"a"`). Adding it doubles the header/payload
  family. Left as a deliberate-scope decision to flag, not silently change.

### eye-cipher-workbench.html
- **[M] Kasiski used a global GCD of *all* pooled distances** — mixing distances
  from unrelated repeats (incl. chance 3-grams) collapses the GCD to 1–2 and
  yields false "no period" / misleading hints. **Fixed**: proper Kasiski
  **divisibility tally** (for each candidate period, count how many repeat
  distances it divides) + per-n-gram GCD shown on each row. This is the standard
  factor-analysis form and is robust to chance repeats.
- **[M] Friedman summary was dominated by `k=1`** — at period 1 the single coset
  *is* the whole text, so its mean IoC always equals the baseline and won the
  "strongest period" pick on flat ciphertext (reporting a spurious period of 1).
  **Fixed**: exclude `k=1` from the best-period selection and report the chosen
  period's **lift over the k=1 baseline**.
- **[M] IoC reference `english≈0.0667` shown for the 83-symbol alphabet** — that
  benchmark is the IoC of 26-letter English and is only meaningful in A–Z mode.
  Shown against mod-83 decrypts it biases interpretation. **Fixed**: show a
  mode-appropriate target (`natural-lang ≈ 0.0667·26/N` off the 26-letter mode);
  applied to both the input readout and the Friedman summary.
- **[R] Scanner panel mislabeled "scored vs. English letter frequency"** while
  the scanners actually rank by IoC. **Fixed**: relabel to "candidates ranked by
  index of coincidence (IoC)".
- **[N] Other noted, not changed**: XOR scanner ranks by byte-space IoC (not
  comparable to mod-83 scans); progression scanners never sweep `start`; Hill
  leaves a trailing partial block unchanged; `parseInput` silently drops
  out-of-range trigram values (display already warns via the "out of range"
  chip). See the workbench audit notes for line-level detail.

---

## Part 4 — Bugfixes (patches) & validation

Because the cloud agent's token is scoped to `h3x-dash` (push to
`Noita-Eyesieve` returns 403), the fixes are delivered as **validated patches**
under `patches/`. Each was generated against the pristine archive contents and
**dry-run-applied cleanly**.

| Patch | Targets | Apply from |
|---|---|---|
| `patches/01-eyesieve.patch` | `eyesieve_keyderiv.py`, `eyesieve_run_report.py`, `eyesieve_selftest.py` | the extracted `eyesieve/` dir (root of the tarball) |
| `patches/02-eyestat.patch` | `eyestat_scoring.py` | the extracted `eyestat/` dir |
| `patches/03-workbench.patch` | `eye-cipher-workbench.html` | the repo root |

```bash
# EyeSieve (from the dir containing eyesieve_*.py)
patch -p1 < 01-eyesieve.patch
# EyeStat (from the dir containing eyestat_*.py)
patch -p1 < 02-eyestat.patch
# Workbench (from the repo root)
patch -p1 < 03-workbench.patch
```

**Post-fix validation (all green):**
- EyeStat: `eyestat_scoring.py` selftests PASS · `eyestat_compute_audit.py`
  **57/57** · `eyestat_selftest.py` **8/8** · `shadow_audit.py` bit-exact.
- EyeSieve: `eyesieve_selftest.py` **220/220** (was 218; +2 new tests).
- Workbench: JS parses cleanly (Node syntax check); corrected Friedman/Kasiski
  verified to identify the right period on a synthetic period-5 cipher.

---

## Part 5 — Recommendations / "more to do"

1. **Build the depth/crib-drag layer (`depth.py`).** The 44% E1/W1 agreement and
   the universal `66,5` crib make N-way depth recovery the highest-probability
   path to first plaintext, and it needs no GPU. This is the missing convergence
   piece all three tools can feed and consume.
2. **Add a calibrated null model / significance threshold to the seed-scan.**
   Across 2³² seeds the best dictionary score *by chance* is high; without a
   shuffled-corpus null distribution + multiple-testing correction, a real hit is
   indistinguishable from noise. This is the make-or-break for trusting an
   EyeStat result. (`perturbed_mappings` is now less biased, which helps the
   per-candidate score quality feeding this.)
3. **Use Noita's *actual* worldgen PRNG.** If the eyes were generated in-engine,
   only the exact algorithm reproduces the keystream. Confirm/add it to the PRNG
   zoo (it currently ships generic LCG/xorshift/PCG/MT families).
4. **Recover the base-5 trigram substructure.** All tools treat runes as opaque
   0–82; decomposing each rune into its `(d1,d2,d3)` base-5 digits unlocks
   per-digit IoC and **Trifid/fractionation on the real coordinates** — a cipher
   family that fits the glyph structure and that none of the tools run on the
   true digits.
5. **Extract `eyesieve/` and `eyestat/` as tracked source folders** in the repo
   (currently only the archives are committed) so future fixes are reviewable as
   diffs rather than binary archive swaps.
