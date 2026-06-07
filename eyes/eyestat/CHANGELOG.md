# Changelog

Recent additions to the EyeStat pipeline that aren't yet reflected in the
main `README.md`.

---

## Phase 1.5 — Chi² Pre-Filter (GPU)

A new shape-distance filter runs on the GPU between decryption and CPU
scoring. It rejects candidates whose rune-frequency distribution doesn't
match any of the reference languages (fi/krl/en) without paying for the
expensive Hungarian + dictionary scan.

```
Pre-filter baseline:    ~10,000 seeds/sec   (CPU-bound on dict scan)
With chi² pre-filter:   ~272,000 seeds/sec  (GPU-bound, ~26× speedup)
Per (mode, PRNG):       ~2.2 hours
```

**Math:** the filter computes squared L2 distance between the sorted
candidate-frequency vector and the sorted expected-frequency vector for
each language, then takes the minimum. "Chi²" is a misnomer (true Pearson
χ² divides by expected[i], which would singularity at the distribution
tail). L2 is monotonically equivalent for ranking and free of that bug.

**Flags** (on `eyestat_gpu_runner.py`):
- `--chi2-threshold 0.0015` — default. Empirically calibrated; signal sits
  at chi² ≈ 0.0001-0.0005, noise at 0.0055-0.0079, threshold mid-gap.
- `--chi2-threshold off` — disable the filter (back to ~10k/s, but every
  candidate gets scored). Useful for sanity checks.

The filter is validated by the shadow audit (`shadow_audit.py`) and the
compute audit (`eyestat_compute_audit.py`, phase 8). Empirical
calibration runs against real Noita ciphertext across all 8 GAK modes
verify a 3-4× safety margin from the noise floor.

---

## Scans Directory Hygiene

Outputs reorganized to keep per-shard chatter separate from final
deliverables:

```
scans/
├── ctak_right_v0/
│   ├── temp/                       ← per-shard params_*.tsv.gz + results_*.txt
│   ├── results/                    ← merged + HTML report
│   └── run.log
├── ctak_right_v1/
│   └── ...
```

**Migration script** for existing flat-layout scans:
```bash
./eyestat_migrate_scans.py scans/ctak_right_v0/
./eyestat_migrate_scans.py --auto ~/Desktop/Noita/eyestat/   # find all
./eyestat_migrate_scans.py --dry-run scans/ctak_right_v0/    # preview
```

Layout-aware tools: `eyestat_html_report.py` and `eyestat_recover.py`
auto-detect both flat and new layouts.

---

## Auto-Generated HTML Reports

Every scan now drops a self-contained HTML report into
`<output-dir>/results/{mode}_{prng}_report.html` at end of run. No CLI
flags needed. Failure is non-fatal — the scan exits cleanly even if HTML
generation hits an error.

**Filename convention:**
```
scans/ctak_right_v0/results/ctak_right_park_miller_v0_report.html
```

Multiple scans can land HTML into the same `results/` dir without
collision. Each report has a **SCAN CONFIGURATION** banner surfacing
mode / PRNG / seed range / hits / chi² threshold etc., even when entries
are empty.

**Opt-out:** `--no-html` flag on the runner.

---

## Live Status Tool

`eyestat_status.py` — read-only status display that polls `run.log` + GPU
+ CPU and renders a static vertical block updated every 5 seconds.

```
ETA:  2.2 hr
      3.71% complete

hits  = 0
rate  = 272,500/s

shard 85/2,148
keys  84.98M/2.15B

GPU: 72°C  Util: 96%
CPU: 58°C  Util: 4%

chi2: reject 100.0%   min 0.00521
```

```bash
./eyestat_status.py scans/ctak_right_v0/run.log
./eyestat_status.py scans/ctak_right_v0/run.log --refresh 3
```

CPU temperature reading covers both `/sys/class/hwmon/hwmon*/` (k10temp,
zenpower, coretemp) and the older `/sys/class/thermal/thermal_zone*/`
path. Works on Threadripper / Intel / Zen-anything.

Run it in a separate tmux pane while your sweep runs in another. No
impact on the production run — only reads `run.log` and `/proc`, `/sys`.

---

## Rate Display Honesty

Fixed a bug where the rate column went haywire after a resume (showed
22M/s at shard 80 because elapsed time started before the [skip] phase).
Now rate/ETA are computed against a session baseline captured at the
first non-skipped shard, so the displayed rate matches reality from the
first progress line onward.

---

## Shebang + Permissions

Every executable script has an absolute-path shebang
(`#!/home/h3x/.venvs/eyestat/bin/python3`) so they can be invoked
directly (`./eyestat_compute_audit.py`) without venv activation.

If you're not the original user `h3x`, either:
1. Update the shebang path in each `.py` file to your venv, OR
2. Invoke explicitly: `~/.venvs/eyestat/bin/python3 eyestat_gpu_runner.py ...`

After unzipping into a fresh tree:
```bash
chmod +x *.py *.sh
```

---

## Validation Status

After all the changes:
- **57/57** compute audit checks pass (`./eyestat_compute_audit.py`)
- **8/8** selftest phases pass (`./eyestat_selftest.py`)
- **Shadow audit** passes across V0+V1 PRNGs and all 8 GAK modes against
  real Noita ciphertext (`./shadow_audit.py`)

Always run these after any code change. They take <60 seconds combined.

---

## Quick Reference — Common Commands

```bash
# Sanity check after pulling in updates
./eyestat_compute_audit.py
./eyestat_selftest.py

# Launch a sweep (with chi² filter + auto-HTML)
mkdir -p scans/ctak_right_v0
./eyestat_gpu_runner.py \
    --mode ctak_right --prng park_miller_v0 \
    --seed-start 0 --seed-end 2147483646 \
    --workers 64 --languages fi \
    --dict-en noita_wordlist.txt \
    --output-dir scans/ctak_right_v0/ \
    --gpu-utilization 1.0 \
    --threshold 13 \
    2>&1 | tee scans/ctak_right_v0/run.log

# In another pane: live status
./eyestat_status.py scans/ctak_right_v0/run.log

# Generate HTML for a completed scan (auto-runs at end of sweep too)
./eyestat_html_report.py \
    --scan-dir scans/ctak_right_v0/ \
    --output   scans/ctak_right_v0/results/report.html

# Migrate old flat-layout scan dirs to the new structure
./eyestat_migrate_scans.py --auto ~/Desktop/Noita/eyestat/

# Recovery (handles crashed shards, .tmp salvage, etc.)
./eyestat_recover.py --output-dir scans/ctak_right_v0/ --html
```
