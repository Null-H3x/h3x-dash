# Brute-Force Tool — Audit & Sanity Check Summary (v1.4)

**Build:** v1.4 (post fourth paranoid audit)
**Files:** `eyestat_kernels.py`, `eyestat_prngs.py`, `eyestat_scoring.py`, `eyestat_runner.py`, `eyestat_selftest.py`
**Total LoC:** ~3200 lines of Python (stdlib only)
**Selftest status:** 8/8 phases passing; 10 PRNG KATs (was 3); 6 Hungarian KATs (was 1); atomic shard writes; UTF-8 explicit everywhere

---

## Selftest coverage

| Phase | Tests | Status |
|-------|-------|--------|
| 1 | Kernel round-trips: 19 cipher modes | PASS |
| 2 | PRNG smoke + KATs: 10 PRNGs, 10 known-answer tests including Park-Miller boundary | PASS |
| 3 | Scoring sanity: Hungarian (6 KATs incl. random vs brute-force), perturbation, dictionary matching | PASS |
| 4 | E2E planted cipher: encrypt under CTAK_RIGHT seed=42, scan finds it | PASS |
| 5 | Runner integration: orchestrator runs cleanly, well-formed shards | PASS |
| 6 | Pontifex KAT: bridge-order + CRYPTONOMICON/SOLITAIREX + FOO + non-ASCII robustness | PASS |
| 7 | Error-path resilience: empty PT, edge cases, seed=0 across PRNGs | PASS |
| 8 | Vigenère KAT: ATTACKATDAWN+LEMON→LXFOPVEFRNHR, period wraparound | PASS |

External validation also run (recorded here, not in selftest):
- σ-key generation matches `noita_prng_brute.py` byte-for-byte (84/84 perms identical for 7 different Park-Miller seeds incl. boundary M-1)
- Hand-traced GAK CTAK_LEFT/RIGHT and PTAK_RIGHT match cipher kernel output
- Vigenère PT-autokey and CT-autokey match canonical hand-computed values (`QUEENLY` + `ATTACKATDAWN`)
- All 10 PRNGs cross-validated against from-scratch reference implementations
- E2E recovery on real-data-shaped CT (9 messages × 1036 chars, planted at seed=12345): planted ranks #1 with 57 fi-hits vs runner-up 37
- Multiprocessing determinism: 6 shards across 2 runs (4 workers, chunksize 10) byte-identical via zcmp
- 9-mode × 3-PRNG × 3-chunk smoke test on real Noita CT: 63 shards, 630 keys, 0 errors

---

## Bugs found and fixed (cumulative)

### From initial audit
1. **Pontifex output value off-by-one** [CRITICAL] — Schneier 1-indexed letters; my code did `(card-1) % 26` instead of `card % 26`.
2. **Dictionary noise floor at min_word_len=3** [CRITICAL] — 3-letter Finnish particles match by chance; 194/200 random keys exceeded threshold=13. Default raised to 4.
3. **Repeated rune-frequency computation in card path** [PERFORMANCE] — hoisted outside loop.

### From triple-check audit
4. **Vigenère plain off-by-one** [CRITICAL] — keystream wraparound used `key[(i+1) % L]` instead of `key[i % L]`. Round-trip masked the bug; canonical KAT caught it. **Without this fix, Vigenère brute force would never recover the puzzle's key.**
5. **Pontifex non-ASCII passphrase corruption** [CRITICAL] — non-ASCII chars (Finnish ä/ö/å) made deck length grow each character. After 4 chars of "minä" deck has ~58 cards. **Without this fix, every Finnish-passphrase test in Pontifex would have crashed or produced garbage.**
6. **Worker error handling** [ROBUSTNESS] — wrapped worker_run_chunk in outer try/except.
7. **Result text truncation** [USER SPEC] — removed 500-char text limit and 30-word hit_words cap.
8. **CT symbol range check** [DEFENSIVE] — worker validates CT symbols vs alphabet_size.
9. **Phase 5 test design** [TEST] — relaxed to validate orchestration only.

### From paranoid pass (this v1.2 build)
10. **Park-Miller seed=M boundary** [CRITICAL] — for seed value equal to the modulus M=2^31-1 (or seed=2^32-1 which masks to M), Schrage's algorithm correctly computes `(A*M) mod M = 0`, but the rescue `if s <= 0: s += M` incorrectly turns this into M, creating an **infinite loop at state=M producing M every call** instead of canonical state=0 (degenerate). Two fixes: reject `s == M` in `__init__` (not in valid range [1, M-1]); change rescue from `s <= 0` to `s < 0` (s==0 only happens for invalid input, not valid x in [1, M-1] where Schrage's result is in [-r·hmax, A·(q-1)] and only the negative case needs the +M wrap). **Without this fix, ~2 seed values out of every 2^32 would have produced sticky-state output that doesn't match canonical Park-Miller, potentially missing the puzzle's seed if they happened to use one of these.** Phase 2 KAT added for regression prevention.

11. **Lehmer/MINSTD2 seed=M boundary** [SAME ISSUE] — same fix applied. State=M with direct mod arithmetic produces 0, then sticks at 0 (degenerate, all-zero output). Now rescues to seed=1.

### From second paranoid pass (this v1.3 build)
12. **Partial-shard data loss on setup errors** [DATA INTEGRITY] — previously, a worker that failed during setup (bad CT path, malformed dict, OOM during dict load) would leave a partial header-only shard file on disk. The resume existence check would then incorrectly skip the chunk on subsequent runs. **Fixed via atomic shard writes:** workers now write to `.tmp` paths during processing and rename to final names only on successful completion. On setup error, only the `error_*.txt` file remains (no partial shard). Resume correctly retries the chunk.

13. **SIGKILL leaves stale partial shards** [DATA INTEGRITY] — same problem as #12 but caused by SIGKILL/Ctrl-C/pool.terminate during the shard write. Atomic writes also fix this case: stale `.tmp` files are cleaned up at the start of each worker run, then the chunk is retried from scratch.

14. **Per-seed errors silently lost on resume** [OBSERVABILITY] — when individual seeds error mid-chunk, the surrounding seeds complete normally and the shard is renamed to final, so resume skips the chunk. The failed seeds were previously logged only to stderr (often lost in long batch jobs). **Fix:** per-shard `failed_keys_*.txt` log records each errored seed with its exception type and message. User can identify lost keys for manual retry.

### From fourth paranoid pass (this v1.4 build)
15. **Cross-platform encoding inconsistency** [PORTABILITY] — shard files are written as UTF-8 (explicit) but were read with platform-default encoding via `open(shard)`. On Linux this happens to be UTF-8 so it worked, but on macOS or Windows the read would use a different codec and Finnish text (åäö) in the merged output would be mojibake or raise UnicodeDecodeError. Fixed by adding `encoding="utf-8"` to all 5 file opens that lacked it (`merge_results` shard reader, `merge_results` final writer, error_*.txt writer, CT data reader, failed_keys_*.txt writer).

16. **`--selftest` flag required `--data`** [USABILITY] — argparse marked `--data` as required, so `python3 eyestat_runner.py --selftest` failed with "the following arguments are required: --data" before reaching the selftest short-circuit. Made `--data` optional with `default=None`, validated in `main()` only when not running selftest.

### KATs added in this pass (regression prevention)
- All 10 PRNGs now have hand-verified KATs (was 3/10).
- 6 Hungarian KATs including 5x5 diagonal, 4x4 anti-diagonal, rectangular 2x4 and 4x2, and random 6x6 cross-validated against brute-force.
- Park-Miller boundary KAT: seed=M and seed=2^32-1 must rescue to canonical seed=1 sequence.
- Phase 6 upgraded with Pontifex CRYPTONOMICON+SOLITAIREX→KIRAKSFJAN (Schneier's published example), FOO→ITHZUJIWGRFARMW, and non-ASCII passphrase robustness.

---

## Verifications performed in v1.2 paranoid pass

These either caught new bugs or confirmed correctness of paths previously trusted by reasoning alone.

### Cipher kernels — hand-traced examples

CTAK_RIGHT, CTAK_LEFT, PTAK_RIGHT all produce expected output for a hand-computed N=3 example with σ[0]=[1,2,0], σ[1]=identity, σ[2]=[2,1,0], pt=[0,1,2]. Verifies LEFT vs RIGHT semantics are distinct and correct.

### Vigenère autokey canonical KATs

- **PT-autokey** with primer "QUEENLY", pt "ATTACKATDAWN" → `QNXEPVYTWTWP` (hand-computed)
- **CT-autokey** with primer "QUEENLY", pt "ATTACKATDAWN" → `QNXEPVYJQXAC` (hand-computed)

Both match cipher kernel output. Round-trips also pass.

### PRNG cross-validation (from-scratch reference)

All 10 PRNGs produce sequences identical to from-scratch reference implementations:
- Park-Miller (seed=1): `[16807, 282475249, 1622650073, 984943658, 1144108930]` ✓
- Park-Miller seed=M: rescues to seed=1, produces canonical sequence ✓
- Lehmer (seed=1): `[48271, 182605794, 1291394886, 1914720637, 2078669041]` ✓
- Xorshift32 (seed=1): first 5 = `[270369, 67634689, 2647435461, 307599695, 2398689233]` ✓
- Xorshift64 (seed=1): first 5 = `[1082269761, 201397313, 1854285353, 1432191013, 2421789285]` ✓
- MT19937 (seed=5489): first u32 = 3499211612 (canonical) ✓
- Splitmix64 (seed=0): first u64 = 0xE220A8397B1DCDAF (canonical) ✓
- Numerical Recipes LCG, glibc LCG, MSVC LCG: match reference ✓

### Hungarian — random matrices vs brute-force

For 6×6 and 7×7 random cost matrices, Hungarian finds the same minimum as brute-force enumeration over all 6! and 7! permutations. Confirms correctness on non-trivial sizes.

### σ-key generation determinism across PRNG fix

Verified that the Park-Miller `seed=M` fix didn't change output for any normal seed. All 7 test seeds (1, 2, 42, 12345, 99999, 1000000, 2147483646=M-1) produce 84 σ keys byte-identical to from-scratch reference Fisher-Yates.

### Verifications added in v1.3 second paranoid pass

These either caught new robustness bugs or confirmed correctness of paths previously trusted by reasoning alone.

- **MT19937 against canonical Matsumoto-Nishimura reference**: `MT19937(seed=5489)` first 5 outputs match `[3499211612, 581869302, 3890346734, 3586334585, 545404204]` from the original C reference at `mt19937ar.c`. (Python's stdlib `random` doesn't match because Python applies a hash to the seed before init; not a bug — different convention.)

- **PCG32 statistical sanity**: determinism (same seed twice → identical), avalanche (different seeds → no shared outputs in first 5), uniform high-bit (~50% in 1000 outputs), uniform mod-10 distribution (all buckets within 957-1032 of expected 1000).

- **Hungarian on rectangular & edge matrices**: cross-validated against brute-force enumeration for 2×5, 3×7, 4×10 (wide), 5×2, 7×3, 10×4 (tall — exercises the transpose+recurse codepath), 1×1 (degenerate), 5×5 all-equal cost (Hungarian still produces a valid permutation). All match brute-force optimum.

- **CFB and OFB algebra walkthrough**: hand-traced encrypt/decrypt for both CFB_MOD (`c = sigma[prev] + p`), CFB_SUB (`c = sigma[(prev+p) mod N]`), and OFB (`c = (p + ks) mod N` with `ks = sigma[ks]` advance). Round-trips verify, prev-update semantics correct.

- **Atomic-write fix verified end-to-end**:
  - Setup error (missing CT file): only error_*.txt remains, no partial shard, resume retries correctly (20/20 seeds processed).
  - SIGKILL simulation (planted stale .tmp files): cleaned up automatically, chunk retried from scratch.
  - Mid-chunk per-seed error: shard completes normally with successful seeds, failed seed logged to failed_keys_*.txt, resume correctly skips (no infinite retry).
  - Multiprocessing: 9 modes × 3 PRNGs (or card-only) × 2 chunks = 42 shards across 4 workers, 0 errors, 0 stale .tmp files.

### Verifications added in v1.4 fourth paranoid pass

- **`count_dictionary_hits` substring boundaries**: 8 boundary tests pass — word at text start, word at text end, overlapping substrings (`scatomb` → all 4 of `scat/cat/atom/tomb`), text shorter than min_word_len, empty text, single-char text, dedup of repeated words, max_word_len truncation. No off-by-one.

- **Hungarian extreme inputs**: negative costs (mixed signs), all-negative costs, very large costs (~1e9), very small fractional costs (~1e-9). All match brute-force optimum exactly. Implementation has no positivity assumption.

- **`gen_passphrases` determinism**: same Python session yields identical first-1000 passphrases across two calls. Cross-process determinism follows because dictionary words are loaded from file in deterministic order then `sorted()`.

- **CT edge cases**: empty message in middle of CT (`[[1,2,3], [], [4,5,6]]`), `seed_start == seed_end` (no work), 1-symbol CT, all-9-messages-identical. All pass with 0 errors.

- **CLI edge cases**: `--workers 0` falls into serial mode (the `if args.workers <= 1` branch), `--workers 1` runs serially, invalid mode/PRNG names produce clear error messages with the available options listed, `--selftest` works standalone (post-fix #16).

- **End-to-end smoke covering all 6 cipher families** (CTAK GAK, xGAK, KAK, CFB, OFB, Vigenère, Pontifex, Card Chameleon, Mirdek) × 3 PRNGs × 30 seeds × 4 workers = 630 keys, 63 shards, 0 errors, 0 stale .tmp.

---

## Design choices documented

### A. Card cipher rune→letter pre-mapping uses naive frequency-rank pairing
For 83→26 reduction. Documented as best-effort.

### B. PRNG seed=0 and seed=M auto-rescue
Park-Miller, Lehmer, Xorshift32, Xorshift64 cannot accept boundary values cleanly. Rescues:
- Park-Miller, Lehmer: seed=0 OR seed=M → seed=1
- Xorshift32: seed=0 → 0xCAFEBABE
- Xorshift64: seed=0 → 0xDEADBEEFCAFEBABE

For 32-bit seed space, seeds 0, M, 2^31, and 2^32-1 alias to other valid seeds. ~4 aliased values out of 2^32 = negligible coverage loss.

### C. MsvcLcgRng `next_u32()` advances state 3× per call
Microsoft `rand()` is 15-bit native; my `next_u32` concatenates three advances. **CAVEAT:** This is one specific interpretation. If the puzzle author used canonical 15-bit MSVC `rand()` with single-advance shuffling, my MsvcLcgRng tests a different sequence. The 32-bit-concat hypothesis is what's tested; canonical 15-bit usage is a separate hypothesis not currently tested.

### D. Mirdek and Card Chameleon are best-effort
Round-trips pass; no canonical KATs widely published.

### E. Scoring uses Hungarian-optimum mapping by default
Fast path. Slow path (`--full-scoring`) runs 1000-mapping perturbation search.

### F. Resume granularity is shard-level, with atomic writes
Workers write shard files to `.tmp` paths and rename to final names on successful completion. This makes resume robust to setup errors, SIGKILL during write, and pool.terminate(). Stale `.tmp` files from prior crashes are cleaned up at the start of each worker run. Per-seed errors (which complete the shard but lose individual keys) are logged to `failed_keys_*.txt` for manual investigation.

### G. Vigenère key length defaults to 8
Hardcoded; edit `gen_keys_vigenere` for variations.

### H. KAK key0 and CFB/OFB IV are PRNG-derived
Tests one specific PRNG-derived value per seed; not all N possible values per (sigma, advance) pair.

---

## Performance (real-data smoke test)

| Mode family | Throughput | Notes |
|-------------|------------|-------|
| GAK/xGAK + Park-Miller (single worker) | ~6 keys/sec | Hungarian-bound |
| 9 modes × 3 PRNGs (4 workers) | ~6 keys/sec aggregate | parallel scaling not great in pure Python |
| Card cipher + passphrase (single worker) | ~26 keys/sec | smaller alphabet |

**Bottleneck:** Pure-Python Hungarian on 83×83 padded matrix. Optimization paths:
- `scipy.optimize.linear_sum_assignment` (~100× faster)
- L1 distance pre-filter (skip Hungarian for distant rune/letter freq distributions)
- PyPy execution (~5-10× free speedup)

---

## Files inventory

| File | Lines | Purpose |
|------|-------|---------|
| `eyestat_kernels.py` | ~810 | 19 cipher mode kernels with round-trip tests |
| `eyestat_prngs.py` | ~660 | 10 PRNGs with 10 KATs |
| `eyestat_scoring.py` | ~510 | Hungarian (6 KATs), dictionary loading, scoring |
| `eyestat_runner.py` | ~740 | CLI, work-unit dispatch, multiprocessing |
| `eyestat_selftest.py` | ~525 | 8-phase comprehensive validation |
| **Total** | **~3245** | |

---

## How to run

```bash
# Selftest (~10 sec, 8 phases including all KATs)
python3 eyestat_selftest.py

# Production scan
python3 eyestat_runner.py \
    --data noita_eye_data.json \
    --dict-fi extra_words_fi.txt \
    --dict-krl extra_words_krl.txt \
    --dict-en noita_wordlist.txt \
    --modes ctak_right,xgak_diff_right,xgak_sum_right,kak_right \
    --prngs park_miller,mt19937,xorshift32,pcg32 \
    --seed-start 0 --seed-end 1000000 \
    --workers 64 \
    --output-dir results_v1 \
    --threshold 13 \
    --min-word-len 4

# Card cipher scan
python3 eyestat_runner.py \
    --data noita_eye_data.json \
    --dict-fi extra_words_fi.txt \
    --dict-krl extra_words_krl.txt \
    --dict-en noita_wordlist.txt \
    --modes pontifex,card_chameleon,mirdek \
    --seed-start 0 --seed-end 700000 \
    --workers 64 \
    --output-dir results_card_v1 \
    --threshold 13
```

Outputs:
- `params_{shard_id}.tsv.gz` — every key tried with hits/zipf scores per language
- `results_{shard_id}.txt` — keys ≥ threshold hits with FULL decrypted text
- `error_{shard_id}.txt` — workers that failed, with full traceback
- `bruteforce_results.txt` — merged final ranked output, sorted by max_hits desc
