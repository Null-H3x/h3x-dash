# SETUP — Fresh EyeStat Directory from Scratch

A complete walkthrough for getting EyeStat running in a clean directory on a
machine with NVIDIA GPU + Ubuntu 24.04. Estimated time: 20-30 minutes
including the installer and validation, then ~35 hours of unattended
compute for the Tier 1 sweep.

---

## Prerequisites

```
Hardware:   x86_64 CPU + NVIDIA GPU (RTX 30-series or newer)
OS:         Ubuntu 24.04 (other Debian-derived distros should work)
Disk:       ~5 GB for the project + venv + scan outputs
Network:    Required for installer (pulls packages from apt + pypi)
Sudo:       Required ONLY for the installer (driver + CUDA install)
```

If you don't have a GPU, EyeStat still works — `install.sh --no-gpu`
falls back to the CPU runner. But you'd be looking at ~5 months for the
Tier 1 sweep instead of ~35 hours.

---

## Step 1 — Extract the project

```bash
# Choose where you want the project to live
cd ~/Desktop                       # or anywhere you like

# Unzip — preserves the eyestat/ wrapper folder
unzip eyestat.zip
cd eyestat

# Restore execute bits (some unzip tools strip them)
chmod +x *.py *.sh
```

Expected layout after extraction:

```
eyestat/
├── README.md, SETUP.md, CHANGELOG.md, AUDIT.md, WORKFLOW.md
├── install.sh, run.sh, requirements*.txt
├── eyestat_*.py                  (20 Python tools)
├── noita_eye_data.json           (input ciphertext)
├── *_wordlist.txt, extra_words_*.txt  (dictionaries)
```

---

## Step 2 — Run the installer

```bash
./install.sh
```

The installer:
1. Detects your GPU (or skips with `--no-gpu` flag)
2. Installs Nvidia driver if missing (may require reboot)
3. Installs CUDA toolkit
4. Creates a venv at `~/.venvs/eyestat/`
5. Installs Python deps from `requirements.txt` + `requirements-gpu.txt`
6. Runs a quick GPU probe to verify CuPy works

If you see `REBOOT REQUIRED` at the end, reboot and re-run `./install.sh`
to complete CUDA setup.

Alternate install modes:

```bash
./install.sh --no-gpu          # CPU-only path (skip Nvidia driver + CuPy)
./install.sh --no-cuda         # keep existing CUDA, only install Python deps
./install.sh --skip-validate   # skip end-of-install selftest/preflight
./install.sh --help            # all options
```

---

## Step 3 — Fix shebangs for YOUR username

Every `.py` file ships with a shebang line targeting `user h3x`. Update
this to your actual home directory so you can invoke scripts directly
(`./eyestat_gpu_runner.py ...`):

```bash
# One-shot fix — sed replaces the default username with your $HOME path
sed -i "s|#!/home/h3x/.venvs/eyestat/bin/python3|#!$HOME/.venvs/eyestat/bin/python3|" *.py

# Re-mark executable
chmod +x *.py *.sh

# Verify a sample
head -1 eyestat_gpu_runner.py
# Should print: #!/home/YOUR_USERNAME/.venvs/eyestat/bin/python3
```

If your venv lives somewhere other than `~/.venvs/eyestat/`, adjust the
`sed` command accordingly. Or skip this step entirely and always invoke
explicitly: `~/.venvs/eyestat/bin/python3 eyestat_gpu_runner.py ...`

---

## Step 4 — Run the validation triad

These three commands together take about 60 seconds and verify the
entire computation graph is correct before you launch a multi-hour
sweep. **Do not skip this.**

```bash
./eyestat_compute_audit.py       # Expected: 57/57 checks passed
./eyestat_selftest.py             # Expected: 8/8 phases passed
./shadow_audit.py                 # Expected: ALL ALGORITHMS CORRECT
```

If any of these fail, do not proceed. Paste the failure output and we
debug. The most common cause of failure on a fresh install is missing
Python packages (selftest will report `ModuleNotFoundError`) or a
broken CuPy install (shadow_audit will fail GPU↔CPU equivalence). Both
get caught instantly by the triad.

---

## Step 5 — Smoke-test the runner (optional but recommended)

Before launching the 2-hour V0/ctak_right sweep, do a 30-second tiny
run to verify the GPU pipeline end-to-end:

```bash
mkdir -p scans/_smoketest
./eyestat_gpu_runner.py \
    --mode ctak_right --prng park_miller_v0 \
    --seed-start 0 --seed-end 100000 \
    --workers 8 --languages fi \
    --dict-en noita_wordlist.txt \
    --output-dir scans/_smoketest/ \
    --threshold 13 \
    --chi2-threshold 0.0015 \
    2>&1 | tee scans/_smoketest/run.log
```

Expected output:
- Startup banner showing PRNG variant + chi² threshold
- `[validate] PASS — 50/50 match` (GPU vs CPU sanity check)
- A few `[progress]` lines showing rate around 250-280k/s
- `[done] Tried 100,000 keys in ~0.4s`
- `[html] Wrote report: scans/_smoketest/results/ctak_right_park_miller_v0_report.html`

Open the HTML to verify the report layout:

```bash
xdg-open scans/_smoketest/results/ctak_right_park_miller_v0_report.html
```

If everything looks good, clean up the smoketest dir and you're ready to
launch:

```bash
rm -rf scans/_smoketest
```

---

## Step 6 — Launch the Tier 1 comprehensive sweep

```bash
./eyestat_queue.py --tier 1
```

This kicks off all 16 (mode, PRNG) combinations of the GAK family ×
Park-Miller V0/V1. The queue:
- Shows a plan upfront — what will run, what will skip
- Runs sweeps sequentially, full GPU per sweep
- Writes each scan's output to `scans/<mode>_<prng_short>/`
- Auto-generates an HTML report at end of each sweep
- Total estimated time: ~35 hours at 272k seeds/sec

Estimated completion: queue will print an ETA upfront. At 272k/s, each
sweep takes ~2h11m. The full Tier 1 runs to ~35h05m.

If you want to preview the queue without launching:

```bash
./eyestat_queue.py --tier 1 --dry-run
```

---

## Step 7 — Monitor in another terminal

Open a second terminal and start the live status display:

```bash
cd ~/Desktop/eyestat
./eyestat_status.py scans/
```

This shows a static vertical block that refreshes every 5 seconds and
auto-follows whichever scan the queue is currently running:

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

When the queue moves from `ctak_left_pm_v0` to `ctak_left_pm_v1`, the
header at the top automatically updates.

---

## Step 8 — When the queue finishes

After ~35 hours, the queue exits with a summary line in the queue
terminal. Each scan's directory now contains:

```
scans/ctak_left_pm_v0/
├── run.log                                    # full runner output
├── temp/                                      # per-shard files
│   ├── params_*.tsv.gz                        (2,148 shards)
│   └── results_*.txt                          (2,148 shards)
└── results/
    └── ctak_left_park_miller_v0_report.html   # the deliverable
```

Open each HTML report to see the scan summary:

```bash
ls scans/*/results/*.html
# Open any of them in a browser:
xdg-open scans/ctak_left_pm_v0/results/ctak_left_park_miller_v0_report.html
```

If any scan produced hits (max_hits ≥ 13), they'd show up as table rows
in the report. If all 16 scans came back with zero hits — that's
informative too. The Tier 1 hypothesis (GAK × Park-Miller × 8-cuts) is
ruled out, and you'd move to Tier 2 (which requires the
`--treat-as-single` flag to be implemented).

---

## Common issues

### "Permission denied" running ./eyestat_*.py
You need `chmod +x` after extraction:
```bash
chmod +x *.py *.sh
```

### "No module named 'cupy'"
You're not in the venv. Either:
1. Activate it: `source ~/.venvs/eyestat/bin/activate`
2. Or fix shebangs (see Step 3) and invoke as `./eyestat_*.py`
3. Or invoke explicitly: `~/.venvs/eyestat/bin/python3 eyestat_*.py`

### "Permission denied" with sudo
Don't use sudo. EyeStat reads/writes only inside your home directory.
Sudo strips your `$PATH` for security and can't find `./eyestat_*.py`.

### Status tool shows "waiting for first progress line" forever
The runner hasn't emitted progress yet (normal for the first 30-60s of
a fresh run). If it's been 90+ seconds, check `tail -20 scans/*/run.log`
for the most recent scan — there should be `[progress]` lines.

### GPU temp climbing toward 84°C+
Throttle by adding `--gpu-utilization 0.85` to the queue. Or run
`sudo nvidia-smi -pl 300` to cap power at 300W.

### Want to stop the queue gracefully
Single Ctrl-C: finishes current scan, then exits. Double Ctrl-C:
interrupts the current scan immediately. The queue is idempotent — just
re-run `./eyestat_queue.py --tier 1` to resume.

### Want to test specific (mode, prng) combinations only
Use the queue's explicit form:
```bash
./eyestat_queue.py \
    --modes ctak_left,ptak_right \
    --prngs park_miller_v0 \
    --dry-run                # preview, drop --dry-run to actually launch
```

---

## What's NOT in this setup

Things you'd want for production but aren't strictly required:
- Backup of `scans/` directory (the output files)
- Remote monitoring (SSH + tmux/screen for headless operation)
- Automated re-run on failure
- A Tier 2+ sweep flag — coming soon

For headless/remote operation, wrap the queue in `nohup` or run inside
`screen`/`tmux`:

```bash
# nohup style (lowest dependency)
nohup ./eyestat_queue.py --tier 1 > scans/queue_session.log 2>&1 &
disown

# Check on progress later
./eyestat_status.py scans/
tail -f scans/queue.log
```

---

## Summary

```
Step 1 — unzip + chmod +x
Step 2 — ./install.sh (may need reboot)
Step 3 — fix shebangs to your username
Step 4 — run the validation triad (60s)
Step 5 — smoke-test the runner (30s)
Step 6 — ./eyestat_queue.py --tier 1
Step 7 — ./eyestat_status.py scans/ in another terminal
Step 8 — read the HTML reports
```

Setup is a one-time cost. Once installed, future sweeps are just:

```bash
./eyestat_queue.py --tier 1
./eyestat_status.py scans/
```
