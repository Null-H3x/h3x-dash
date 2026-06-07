# EyeStat

**Statistical cryptanalysis pipeline for Noita's "eye messages" puzzle.**

GPU-accelerated brute-force search over a structured hypothesis space of
(cipher mode, PRNG, seed) tuples. For each candidate seed, decrypts the
ciphertext, applies a chi² shape filter on the GPU, and scores survivors
against natural-language dictionaries on the CPU.

---

## What problem is this solving?

Noita contains 9 in-game "eye messages" totaling 1036 symbols drawn from
an alphabet of 83 distinct runes. The cipher family, PRNG, and key are
all unknown. EyeStat sweeps the joint hypothesis space and ranks
candidates by how language-like the decrypted output is.

```
     ┌───────────────────────────────────────────────────────────────┐
     │  Hypothesis Grid                                              │
     │     19 cipher modes × 10 PRNG families = 190 (mode,prng) pairs│
     │     Each pair has ~2.15B candidate seeds                      │
     │     Per-pair sweep: ~2.2 hours on RTX 5080 with chi² filter   │
     │     Full grid: ~7 days continuous compute                     │
     └───────────────────────────────────────────────────────────────┘
```

Output for each sweep: per-shard params + results files, a merged
deliverable, and an auto-generated HTML report.

---

## Quickstart (fresh Ubuntu 24.04 + NVIDIA GPU)

```bash
# 1. Extract project
unzip eyestat.zip
cd eyestat

# 2. Install — autodetects GPU, sets up venv, installs CuPy + CUDA-aware deps
chmod +x install.sh run.sh
./install.sh

# If installer says "REBOOT REQUIRED" (new Nvidia driver), reboot then re-run.

# 3. Update shebangs to your venv path (one-time; default targets user h3x)
sed -i "s|#!/home/h3x/.venvs/eyestat/bin/python3|#!$HOME/.venvs/eyestat/bin/python3|" *.py
chmod +x *.py *.sh

# 4. Sanity check — should be all green
./eyestat_compute_audit.py          # 57/57 checks
./eyestat_selftest.py                # 8/8 phases
./shadow_audit.py                    # CPU-shadow vs GPU bit-exact match

# 5. Launch the comprehensive sweep (Tier 1: 16 sweeps, ~35 hours)
./eyestat_queue.py --tier 1

# 6. In another terminal — live status display
./eyestat_status.py scans/
```

That's it. The queue runs sequentially, drops HTML reports into each
scan's `results/` directory, and skips combos that are already complete
if you re-launch.

---

## How it works (per-candidate pipeline)

For each candidate seed `s`:

| Stage | Where | Description |
|---|---|---|
| 1. PRNG state generation | GPU | Park-Miller LCG via Schrage's algorithm |
| 2. Fisher-Yates permutation schedule | GPU | 84 permutations of {0..82} |
| 3. GAK decryption | GPU | Produces 1036-rune candidate text |
| 4. Histogram (83 bins) | GPU | Frequency count via atomic shared memory |
| 5. **Chi² shape filter** | **GPU** | **Rejects ~100% noise without CPU touch** |
| 6. Hungarian rune→letter mapping | CPU | scipy linear_sum_assignment (survivors only) |
| 7. Dictionary substring scan + score | CPU | Per-language hits and Zipf-weighted score |
| 8. Threshold check + write | CPU | Writes to params/results if max_hits ≥ threshold |

Steps 5 and 6 are the critical innovation. The chi² filter rejects
~99.9% of candidates on the GPU before any CPU work happens. Empirically
this moves throughput from 10k seeds/sec (CPU-bound) to 272k seeds/sec
(GPU-bound).

---

## The chi² filter (Phase 1.5)

Computes squared L2 distance between the sorted candidate-frequency
vector and the sorted expected-frequency vector for each reference
language. Takes the minimum across languages. Passes if `min(chi²) <
threshold`.

```
f_c[i]       = histogram[i] / 1036
sorted_f_c   = sort descending(f_c)
chi²_ℓ       = Σᵢ (sorted_f_c[i] - expected_sorted_ℓ[i])²
min_chi²     = min over ℓ ∈ {fi, krl, en}
```

**"Chi²" is a misnomer.** True Pearson χ² divides by `expected[i]` which
goes to zero at the distribution tail and produces div-by-zero. We use
L2, which is monotonically equivalent for ranking and free of that
singularity.

**Empirical calibration** against real Noita ciphertext (50-seed sample
per mode):

```
Real-language signal chi²:    range  0.00011 - 0.00051   (median 0.00021)
Real-cipher noise chi²:       range  0.00552 - 0.00792   (median 0.00677)
Default threshold 0.0015 sits in the 10× gap.  ~3.7× safety margin.
```

**Permutation invariance** is the correctness property: the filter
sorts before comparing, so chi² is unchanged under any permutation of
the histogram bins. Verified across 20 random permutations → bit-
identical chi² each time.

---

## Directory layout

```
~/Desktop/Noita/eyestat/
├── eyestat_*.py                     ← all tools live at project root
├── install.sh, run.sh
├── requirements*.txt
├── README.md, CHANGELOG.md, AUDIT.md, WORKFLOW.md
├── noita_eye_data.json              ← input ciphertext
├── *_wordlist.txt, extra_words_*.txt← dictionaries
│
└── scans/                           ← all sweep output lives here
    ├── ctak_right_pm_v0/            ← one folder per (mode, prng) combo
    │   ├── run.log                  ← runner output (auto line-buffered)
    │   ├── temp/                    ← per-shard params + results
    │   │   ├── params_*.tsv.gz
    │   │   └── results_*.txt
    │   └── results/                 ← post-run deliverables
    │       └── ctak_right_park_miller_v0_report.html
    ├── ctak_right_pm_v1/
    │   └── ...
    └── queue.log                    ← master queue session log
```

**Scan dir naming convention**: `<mode>_<prng_short>` where `prng_short`
is from a built-in abbreviation table (`pm_v0`, `pm_v1`, `xs32`, `pcg`,
`mt`, ...). The queue runner uses this convention automatically.

---

## Tools

### Core pipeline

| Tool | Purpose |
|---|---|
| `eyestat_runner.py` | CPU baseline orchestrator (no GPU required) |
| `eyestat_gpu_runner.py` | GPU-accelerated runner for GAK family — recommended |
| `eyestat_gpu.py` | CUDA kernel host code |
| `eyestat_kernels.py` | Cipher kernels (8 GAK modes) |
| `eyestat_prngs.py` | PRNG zoo (Park-Miller V0/V1, Xorshift, PCG, MT19937, ...) |
| `eyestat_scoring.py` | Dictionary scoring + Hungarian assignment |

### Orchestration

| Tool | Purpose |
|---|---|
| `eyestat_queue.py` | Sequential queue across multiple (mode, prng) combos |
| `eyestat_status.py` | Live status display (auto-follows queue) |
| `eyestat_migrate_scans.py` | Migrate legacy flat-layout scans to new structure |

### Reporting

| Tool | Purpose |
|---|---|
| `eyestat_html_report.py` | Build self-contained HTML viewer (auto-runs at end of each sweep) |
| `eyestat_recover.py` | Inventory + salvage shards from crashed runs |

### Validation

| Tool | Purpose |
|---|---|
| `eyestat_compute_audit.py` | 57 checks across 8 phases (PRNG, FY, GAK, Hungarian, scoring, planted-seed, chi²) |
| `eyestat_selftest.py` | 8-phase end-to-end pipeline test |
| `shadow_audit.py` | Bit-exact CPU NumPy mirror of every GPU kernel |
| `eyestat_gpu_validate.py` | GPU vs CPU spot check (50 seeds) |
| `eyestat_gpu_probe.py` | GPU capability + throughput benchmark |
| `eyestat_preflight.py` | Pre-flight check before launching a sweep |

---

## CLI reference (the runner)

```bash
./eyestat_gpu_runner.py \
    --mode ctak_right                # cipher mode (see eyestat_kernels.py)
    --prng park_miller_v0            # PRNG family
    --seed-start 0                   # inclusive
    --seed-end 2147483646            # exclusive
    --workers 64                     # CPU pool for scoring survivors
    --languages fi                   # comma-separated; default "fi,krl,en"
    --dict-en noita_wordlist.txt     # English dictionary path
    --output-dir scans/ctak_right_pm_v0/
    --threshold 13                   # min hits to write to results.txt
    --chi2-threshold 0.0015          # chi² filter threshold; "off" to disable
    --gpu-utilization 1.0            # 1.0 = full GPU; lower for thermal headroom
    --merge                          # produce results/bruteforce_results.txt
    --no-html                        # skip auto-HTML at end of run
```

The runner is idempotent — re-running with the same args resumes where
it left off (skips already-`.final` shards).

---

## The queue runner

For multi-sweep campaigns, use `eyestat_queue.py` instead of launching
the GPU runner directly:

```bash
# Preset tier (8 GAK modes × 2 Park-Miller variants = 16 sweeps)
./eyestat_queue.py --tier 1

# Or explicit
./eyestat_queue.py \
    --modes ctak_left,ptak_right,ptak_left \
    --prngs park_miller_v0,park_miller_v1 \
    --threshold 13

# Preview without launching
./eyestat_queue.py --tier 1 --dry-run

# Force re-running combos that are already complete
./eyestat_queue.py --tier 1 --force
```

The queue:
- Runs scans sequentially, one at a time, full GPU per scan.
- Skips combos whose `scans/<short_name>/results/*_report.html` already
  exists.
- Master log appended to `scans/queue.log` across invocations.
- Per-scan log written to `scans/<short_name>/run.log` (line-buffered).
- Single Ctrl-C: finishes current scan, then exits cleanly.
- Double Ctrl-C: forwards SIGINT to the runner so it can clean up.
- Idempotent — re-run with same args to resume.

---

## Live status display

```bash
# Auto-follows whichever scan the queue is currently running
./eyestat_status.py scans/

# Or pin to one specific scan
./eyestat_status.py scans/ctak_left_pm_v0/

# Or a specific run.log
./eyestat_status.py scans/ctak_left_pm_v0/run.log
```

Output (refreshes every 5 seconds, static in-place update):

```
▶ ctak_left_pm_v0

ETA:  2.0 hr
      7.71% complete

hits  = 0
rate  = 272,500/s

shard 165/2,148
keys  164.66M/2.15B

GPU: 72°C  Util: 96%
CPU: 58°C  Util: 4%

chi2: reject 100.0%   min 0.00498
```

Color-coded temperatures (green < 75°C, yellow 75-83°C, red ≥ 84°C).
Read-only — has zero effect on the running scan.

CPU temp detection works on both `/sys/class/hwmon/hwmon*/` (k10temp,
zenpower, coretemp) and `/sys/class/thermal/thermal_zone*/`. Tested on
AMD Threadripper Zen 5 (k10temp).

---

## Validation layer

EyeStat ships with three layers of verification:

### `eyestat_compute_audit.py` — 57 checks across 8 phases
Show-your-work verification of every individual computation:

```
Phase 1:  Park-Miller V0/V1 state advancement (KATs vs published refs)
Phase 2:  Fisher-Yates shuffle (uniformity, bijection over n!)
Phase 3:  GAK encrypt/decrypt round-trip identity (all 8 modes)
Phase 4:  Hungarian assignment vs scipy reference
Phase 5:  Dictionary substring matching
Phase 6:  Scoring functions (Zipf, length-weighted)
Phase 7:  Planted-seed end-to-end recovery
Phase 8:  Chi² filter math, permutation invariance, threshold calibration
```

Park-Miller KATs (10,000th iterate of seed=1):
- V0 (a=16807): **1,043,618,065** (matches Park & Miller 1988 paper)
- V1 (a=48271): **399,268,537**

### `eyestat_selftest.py` — 8-phase pipeline test
End-to-end run with planted plaintext through every stage. Catches
integration errors that unit tests miss.

### `shadow_audit.py` — bit-exact GPU↔CPU equivalence
Every CUDA kernel has a NumPy reference. The shadow audit verifies
bit-exact equivalence on:
- All 8 GAK modes × both Park-Miller variants
- 27 edge-case seeds + 9 real Noita ciphertexts
- 256 real Noita decryptions through histogram + chi² kernels
- Permutation invariance + degenerate-input regression

Run all three after any change to GPU kernels:

```bash
./eyestat_compute_audit.py && ./eyestat_selftest.py && ./shadow_audit.py
```

Total runtime: ~60 seconds. They must all be green before launching a
multi-hour sweep.

---

## Performance

Hardware: AMD Threadripper 9970X + NVIDIA RTX 5080, Ubuntu 24.04.

```
Pre-filter baseline:           ~10,000 seeds/sec   (CPU-bound on dict scan)
With chi² filter:              ~272,000 seeds/sec  (GPU-bound, ~26× speedup)
Per (mode, PRNG) sweep:        ~2.2 hours
Tier 1 (8 GAK × V0+V1):        ~35 hours
Full hypothesis grid:          ~7 days continuous
```

Compare to the unfiltered baseline: same total work, ~5 months.
Phase 1.5 is what makes the broader search tractable.

---

## Hypothesis status

| Tier | Description | Status |
|---|---|---|
| 1 | GAK family × Park-Miller V0/V1, 8-cuts (default per-message reset) | run with `--tier 1` |
| 2 | Same as 1, but `--treat-as-single` (0-cuts, continuous stream) | future (requires `--treat-as-single` impl) |
| 3 | GAK family × other PRNGs (Xorshift, PCG, MT19937, ...) | future |
| 4 | Non-GAK cipher families (KAK, CFB, OFB, Vigenère, Pontifex, Mirdek) | requires new kernels |

See `WORKFLOW.md` for the full mathematical pipeline + cryptanalytic
context, and `CHANGELOG.md` for incremental improvements.

---

## License

MIT (see LICENSE)
