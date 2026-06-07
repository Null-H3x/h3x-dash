#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_gpu_runner.py — GPU-accelerated brute-force runner.

Wraps eyestat_gpu.GpuBatchRunner with a multiprocessing CPU pool for scoring,
producing output shards in the exact format eyestat_runner.py uses — so the
existing eyestat_recover.py and eyestat_html_report.py tools work unchanged on
GPU-runner output.

CURRENT SCOPE (v1)
==================
  PRNG:           park_miller only
  Cipher family:  GAK / xGAK (8 modes: ctak/ptak/xgak_sum/xgak_diff × right/left)

For other PRNGs (mt19937, pcg32, etc.) or cipher families (KAK, CFB, OFB,
Vigenère, Pontifex, Mirdek, Card Chameleon), use eyestat_runner.py until those
GPU kernels are added to eyestat_gpu.py.

PIPELINE
========
  for each batch of batch_size seeds:
      GPU:  generate decrypted texts (run_batch)
      CPU pool (N workers):
          Hungarian rune→letter mapping per language
          Apply mapping → letter string
          Dictionary substring matching
          Zipf scoring
      Main thread:
          Write params row for every key
          If max_hits >= threshold, write full result entry
          Update progress

USAGE
=====
    source ~/.venvs/eyestat/bin/activate
    cd ~/eyestat
    python3 eyestat_gpu_runner.py \\
        --mode ctak_right \\
        --seed-start 0 --seed-end 1000000 \\
        --batch-size 65536 --workers 32 \\
        --output-dir gpu_results/

OUTPUT
======
Same format as eyestat_runner.py — drop into eyestat_html_report.py or eyestat_recover.py:

    gpu_results/
      params_ctak_right_park_miller_0000000000_0000010000.tsv.gz
      results_ctak_right_park_miller_0000000000_0000010000.txt
      params_ctak_right_park_miller_0000010000_0000020000.tsv.gz
      results_ctak_right_park_miller_0000010000_0000020000.txt
      ...
      bruteforce_results.txt          # merged results (optional, --merge)
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import multiprocessing as mp
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

# Park-Miller M; max meaningful seed boundary. Seeds outside [0, M] would be
# bit-masked to 0x7FFFFFFF and silently re-scan the same space, so we cap.
PARK_MILLER_M = 2_147_483_647

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import eyestat_scoring as S

# CuPy/eyestat_gpu imports are deferred until run_gpu_brute_force() so this module
# can be imported for testing the CPU-side scoring + shard-writing helpers
# even on systems without a GPU.
_GPU_IMPORT_ERROR = None
try:
    from eyestat_gpu import GpuBatchRunner, MODE_CODE, MODE_NAME
except ImportError as _e:
    GpuBatchRunner = None
    # Fallback MODE_CODE so CLI choices can still be enumerated
    MODE_CODE = {
        "ctak_right": 0, "ctak_left": 1, "ptak_right": 2, "ptak_left": 3,
        "xgak_sum_right": 4, "xgak_sum_left": 5,
        "xgak_diff_right": 6, "xgak_diff_left": 7,
    }
    MODE_NAME = {v: k for k, v in MODE_CODE.items()}
    _GPU_IMPORT_ERROR = _e


# =============================================================================
# Constants matching eyestat_runner.py
# =============================================================================

VALID_LANGS = ("fi", "krl", "en")
TOP_HITS_PER_SHARD = 5  # mirror eyestat_runner


# =============================================================================
# Per-key scoring — mirror of eyestat_runner.score_decryption_fast()
# Inlined here to avoid importing eyestat_runner (which pulls in heavy modules).
# Keep in sync with the original if it changes.
# =============================================================================

def _score_decryption_fast(symbols, N, dictionaries, min_word_len=4):
    """Hungarian optimum mapping per language; no perturbations."""
    rune_counts = Counter(symbols)
    total = sum(rune_counts.values())
    if total == 0:
        return {lang: {"hits": 0, "zipf_score": 0.0,
                       "decrypted_text": "", "hit_words": []}
                for lang in dictionaries}

    rune_freq = {r: 100.0 * rune_counts.get(r, 0) / total for r in range(N)}

    results = {}
    for lang, dictionary in dictionaries.items():
        if len(dictionary) == 0:
            results[lang] = {"hits": 0, "zipf_score": 0.0,
                             "decrypted_text": "", "hit_words": []}
            continue
        letter_freq = dictionary.letter_frequencies()
        if not letter_freq:
            letter_freq = S.LANG_DEFAULT_FREQS[lang]
        mapping = S.hungarian_optimal_mapping(rune_freq, letter_freq, N, lang)
        text = S.apply_mapping(symbols, mapping)
        hits, hit_list = S.count_dictionary_hits(
            text, dictionary, min_word_len=min_word_len)
        z = S.zipf_score(hit_list, dictionary) if hits else 0.0
        results[lang] = {"hits": hits, "zipf_score": z,
                         "decrypted_text": text, "hit_words": hit_list}
    return results


def _write_result_entry(f, mode, prng, key_id, per_lang, max_hits):
    """Same format as eyestat_runner.write_result_entry."""
    f.write(f"=== mode={mode} prng={prng} key={key_id} max_hits={max_hits} ===\n")
    for lang, val in per_lang.items():
        hits = val["hits"]
        z = val["zipf_score"]
        text = val.get("decrypted_text", "")
        hit_list = val.get("hit_words", [])
        f.write(f"  [{lang}] hits={hits} zipf_score={z:.2f}\n")
        sorted_hits = sorted(set(hit_list), key=lambda w: (-len(w), w))
        f.write(f"  hit_words ({len(sorted_hits)}): {', '.join(sorted_hits)}\n")
        f.write(f"  text: {text}\n")
    f.write("\n")
    f.flush()


# =============================================================================
# Multiprocessing worker setup
# =============================================================================

# Globals populated by worker initializer (avoids pickling dictionaries
# on every chunk).
_WORKER_DICTS = None
_WORKER_N = None
_WORKER_LANGUAGES = None
_WORKER_MIN_WORD_LEN = None
_WORKER_CT_TOTAL_LEN = None


def _worker_init(dict_paths, languages, N, min_word_len, ct_total_len):
    """Pool initializer — load dictionaries once per worker."""
    global _WORKER_DICTS, _WORKER_N, _WORKER_LANGUAGES
    global _WORKER_MIN_WORD_LEN, _WORKER_CT_TOTAL_LEN
    _WORKER_N = N
    _WORKER_LANGUAGES = languages
    _WORKER_MIN_WORD_LEN = min_word_len
    _WORKER_CT_TOTAL_LEN = ct_total_len

    _WORKER_DICTS = {}
    for lang in languages:
        d = S.Dictionary(lang)
        # dict_paths[lang] may be a single path or '+'-separated list of paths
        # (e.g. "extra_words_fi.txt+noita_wordlist.txt"). Files are merged into
        # one Dictionary; first-seen words determine zipf rank ordering.
        raw = str(dict_paths[lang])
        for sub in raw.split("+"):
            sub = sub.strip()
            if not sub:
                continue
            p = Path(sub)
            if p.exists():
                d.load(p)
        _WORKER_DICTS[lang] = d


def _score_chunk(args):
    """Score a chunk of decrypted keys.

    Args:
        seeds:   np.ndarray (uint32) — the seeds for these keys
        decs:    np.ndarray (uint8) — shape (n_keys, ct_total_len)

    Returns:
        list of (seed, max_hits, results_dict)
    """
    seeds, decs = args
    out = []
    for i in range(len(seeds)):
        symbols = decs[i].tolist()
        results = _score_decryption_fast(
            symbols, _WORKER_N, _WORKER_DICTS, _WORKER_MIN_WORD_LEN)
        hits = {lang: results.get(lang, {}).get("hits", 0)
                for lang in _WORKER_LANGUAGES}
        max_hits = max(hits.values()) if hits else 0
        out.append((int(seeds[i]), max_hits, results))
    return out


# =============================================================================
# Shard writer — format matches eyestat_runner.py exactly
# =============================================================================

class ShardWriter:
    """Writes one (mode, prng, seed_start, seed_end) shard pair."""

    @staticmethod
    def shard_paths(output_dir, mode, prng, seed_start, seed_end):
        """Compute the final + tmp paths for a shard without side effects.
        Use this for resume checks before constructing the writer.

        Layout (since the 'scans hygiene' refactor):
            <output_dir>/temp/    — per-shard params + results files
            <output_dir>/results/ — aggregated/HTML output (written later)

        Backward compat: if <output_dir>/temp/ doesn't exist but a legacy
        flat-layout shard does exist directly under <output_dir>/, return
        the legacy path so resume keeps working on pre-refactor scans.
        """
        output_dir = Path(output_dir)
        shard_id = f"{mode}_{prng}_{seed_start:010d}_{seed_end:010d}"
        temp_dir = output_dir / "temp"
        # Legacy flat-layout check (only matters for resume on old scan dirs)
        legacy_final = output_dir / f"params_{shard_id}.tsv.gz"
        if legacy_final.exists() and not temp_dir.exists():
            base = output_dir
        else:
            base = temp_dir
        return {
            "shard_id": shard_id,
            "params_final":  base / f"params_{shard_id}.tsv.gz",
            "results_final": base / f"results_{shard_id}.txt",
            "params_tmp":    base / f"params_{shard_id}.tsv.gz.tmp",
            "results_tmp":   base / f"results_{shard_id}.txt.tmp",
        }

    def __init__(self, output_dir, mode, prng, seed_start, seed_end,
                 languages, threshold):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # Create the new layout subdirs eagerly so downstream tools
        # (HTML report, merge step) can rely on them existing.
        (self.output_dir / "temp").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "results").mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.prng = prng
        self.seed_start = seed_start
        self.seed_end = seed_end
        self.languages = languages
        self.threshold = threshold

        paths = self.shard_paths(self.output_dir, mode, prng, seed_start, seed_end)
        self.shard_id = paths["shard_id"]
        self.params_tmp    = paths["params_tmp"]
        self.results_tmp   = paths["results_tmp"]
        self.params_final  = paths["params_final"]
        self.results_final = paths["results_final"]

        # Clean up stale .tmp files from prior crashed runs (matches eyestat_runner)
        for p in (self.params_tmp, self.results_tmp):
            if p.exists():
                try: p.unlink()
                except OSError: pass

        self.params_f = gzip.open(self.params_tmp, "wt", encoding="utf-8")
        self.results_f = open(self.results_tmp, "w", encoding="utf-8")

        self.n_tried = 0   # ALL candidates attempted in this shard, including
                           # those rejected by the GPU chi² filter before scoring
        self.n_scored = 0  # candidates that reached CPU scoring (passed filter
                           # if enabled; equals n_tried when filter is off)
        self.n_hits = 0
        self.top_hits: List[Tuple[int, str, str, str]] = []  # (max_hits, mode, prng, key_id)

    def note_filtered(self, n: int) -> None:
        """Record that n candidates were attempted but rejected by the chi²
        pre-filter before reaching CPU scoring. Bumps n_tried only (not
        n_scored or n_hits) so that downstream rate / throughput metrics
        reflect the actual GPU sweep size."""
        if n < 0:
            raise ValueError(f"note_filtered: n must be >= 0, got {n}")
        self.n_tried += n

    def write_key(self, seed, max_hits, results):
        """Write one key's result. Always writes to params; conditionally to results."""
        hits = {lang: results.get(lang, {}).get("hits", 0) for lang in VALID_LANGS}
        zs   = {lang: results.get(lang, {}).get("zipf_score", 0.0) for lang in VALID_LANGS}
        key_id = f"SEED:{seed}"
        self.params_f.write(
            f"{self.mode}\t{self.prng}\t{key_id}\t"
            f"{zs['fi']:.2f}\t{zs['krl']:.2f}\t{zs['en']:.2f}\t"
            f"{hits['fi']}\t{hits['krl']}\t{hits['en']}\n")

        if max_hits >= self.threshold:
            self.n_hits += 1
            # Restrict to selected languages in the entry
            per_lang = {lang: results[lang] for lang in self.languages
                        if lang in results}
            _write_result_entry(self.results_f, self.mode, self.prng,
                                key_id, per_lang, max_hits)
            # Top-hits tracking
            self.top_hits.append((max_hits, self.mode, self.prng, key_id))
            self.top_hits.sort(key=lambda t: t[0], reverse=True)
            self.top_hits = self.top_hits[:TOP_HITS_PER_SHARD]

        self.n_scored += 1
        self.n_tried += 1   # incremented for scored candidates; note_filtered()
                            # bumps it for chi²-rejected ones separately

    def close(self):
        """Atomic finalize: tmp → final."""
        self.params_f.close()
        self.results_f.close()
        try:
            os.replace(self.params_tmp, self.params_final)
            os.replace(self.results_tmp, self.results_final)
        except OSError as e:
            print(f"WARN: failed to rename shard: {e}", file=sys.stderr)

    def abandon(self):
        """Close file handles WITHOUT atomic-rename. Use on interrupt/error
        so a partial shard stays as .tmp for eyestat_recover.py to salvage instead
        of getting promoted to a final-looking file with truncated data."""
        try: self.params_f.close()
        except Exception: pass
        try: self.results_f.close()
        except Exception: pass


# =============================================================================
# GPU monitoring + thermal safety
# =============================================================================

def get_gpu_stats() -> Optional[Tuple[int, int, int, int]]:
    """Query the GPU via nvidia-smi. Returns (temp_c, util_pct, mem_used_mb,
    power_w) or None if nvidia-smi isn't available / fails.

    Cheap (~30-50ms). Safe to call once per progress tick."""
    try:
        r = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=temperature.gpu,utilization.gpu,memory.used,power.draw",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2)
        if r.returncode != 0:
            return None
        parts = [p.strip() for p in r.stdout.strip().split(",")]
        # power.draw can be "[N/A]" on some cards
        try:
            power = int(float(parts[3]))
        except (ValueError, IndexError):
            power = 0
        return (int(float(parts[0])), int(float(parts[1])),
                int(float(parts[2])), power)
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None


def get_gpu_power_limit() -> Optional[Tuple[int, int]]:
    """Returns (current_limit_w, max_limit_w) or None."""
    try:
        r = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=power.limit,power.max_limit",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2)
        if r.returncode != 0:
            return None
        parts = [p.strip() for p in r.stdout.strip().split(",")]
        return (int(float(parts[0])), int(float(parts[1])))
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
        return None


def format_gpu_stats(stats: Tuple[int, int, int, int],
                     temp_warn: int = 0) -> str:
    """Format stats as a single-line string for progress output."""
    temp, util, mem, power = stats
    temp_str = f"{temp}°C"
    if temp_warn and temp >= temp_warn:
        temp_str = f"\033[91m{temp}°C ⚠\033[0m"  # red + warn
    return (f"GPU: {temp_str} util={util}% mem={mem}MB"
            + (f" {power}W" if power > 0 else ""))


# =============================================================================
# Main orchestrator
# =============================================================================

def run_gpu_brute_force(args):
    """Top-level orchestration. Returns exit code."""
    # ---- Verify GPU stack is available ----
    if _GPU_IMPORT_ERROR is not None:
        print(f"ERROR: GPU stack not importable: {_GPU_IMPORT_ERROR}", file=sys.stderr)
        print("  Activate venv first:  source ~/.venvs/eyestat/bin/activate",
              file=sys.stderr)
        return 2

    # ---- Load data ----
    data_path = Path(args.data)
    if not data_path.is_absolute():
        data_path = SCRIPT_DIR / data_path
    try:
        with open(data_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: data file not found: {data_path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: data file is not valid JSON: {e}", file=sys.stderr)
        return 2
    # Validate required keys before reaching into them — KeyError tracebacks
    # are not user-friendly.
    missing = [k for k in ("ciphertexts", "deck_size") if k not in data]
    if missing:
        print(f"ERROR: data file {data_path.name} is missing required keys: "
              f"{missing}. Expected schema: "
              f"{{'ciphertexts': [[...], [...]], 'deck_size': N}}",
              file=sys.stderr)
        return 2
    if not isinstance(data["ciphertexts"], list) or not data["ciphertexts"]:
        print(f"ERROR: data['ciphertexts'] must be a non-empty list of lists",
              file=sys.stderr)
        return 2

    ciphertexts = [list(ct) for ct in data["ciphertexts"]]
    N = int(data["deck_size"])
    num_msgs = len(ciphertexts)
    ct_total_len = sum(len(ct) for ct in ciphertexts)
    print(f"[data] {num_msgs} messages, N={N}, "
          f"{ct_total_len} total symbols, file={data_path.name}")

    # ---- Validate constraints ----
    # Normalize backward-compat alias and validate against supported variants
    SUPPORTED_PRNGS = {"park_miller_v0", "park_miller_v1"}
    if args.prng == "park_miller":
        args.prng = "park_miller_v0"   # legacy CLI alias
    if args.prng not in SUPPORTED_PRNGS:
        print(f"ERROR: GPU runner only supports Park-Miller variants "
              f"{sorted(SUPPORTED_PRNGS)}, got --prng {args.prng}",
              file=sys.stderr)
        return 2

    if args.mode not in MODE_CODE:
        print(f"ERROR: GPU runner v1 only supports GAK family modes "
              f"{sorted(MODE_CODE)}, got --mode {args.mode}", file=sys.stderr)
        return 2

    languages = [l for l in args.languages.split(",") if l]
    for lang in languages:
        if lang not in VALID_LANGS:
            print(f"ERROR: --languages: unknown lang '{lang}'", file=sys.stderr)
            return 2

    # Worker count must be positive. argparse type=int accepts 0 and negatives,
    # and Pool(processes=0) is a confusing ValueError.
    if args.workers < 1:
        print(f"ERROR: --workers must be >= 1, got {args.workers}",
              file=sys.stderr)
        return 2

    # Clamp throttle to a sane range. 0.1 ≈ 90% sleep is the practical floor;
    # below that the runner makes near-zero progress. Above 1.0 means no
    # throttling at all. isfinite check rejects NaN/Inf — argparse type=float
    # accepts both, and NaN comparisons silently return False, slipping past
    # naive range checks and crashing time.sleep(NaN) mid-run.
    if (not math.isfinite(args.gpu_utilization)
            or args.gpu_utilization < 0.1 or args.gpu_utilization > 1.0):
        print(f"ERROR: --gpu-utilization must be a finite value in [0.1, 1.0], "
              f"got {args.gpu_utilization}", file=sys.stderr)
        return 2

    # Range sanity. Empty/inverted ranges would otherwise write spurious
    # empty shard files (a real footgun if you typo'd start/end).
    if args.seed_end <= args.seed_start:
        print(f"ERROR: --seed-end ({args.seed_end}) must be > --seed-start "
              f"({args.seed_start})", file=sys.stderr)
        return 2
    if args.seed_start < 0:
        print(f"ERROR: --seed-start ({args.seed_start}) must be >= 0",
              file=sys.stderr)
        return 2
    # Park-Miller's valid seed space is [0, M] where M = 2^31 - 1. Seeds above
    # M get bit-masked to 0x7FFFFFFF and re-scan the same low-half of the space
    # silently — you'd waste days re-scanning seeds you already covered.
    if args.seed_end > PARK_MILLER_M:
        print(f"ERROR: --seed-end ({args.seed_end:,}) exceeds Park-Miller's "
              f"seed space (max {PARK_MILLER_M:,} = 2^31 - 1). Seeds above this "
              f"would silently re-scan low seeds via uint32 masking.",
              file=sys.stderr)
        return 2

    # Shard alignment. If shard_size < batch_size, every shard pads the GPU
    # batch with seeds it then throws away — wastes (batch_size - shard_size)
    # of GPU work per shard. Not a correctness issue, just inefficiency.
    if args.shard_size < args.batch_size:
        wasted_pct = (args.batch_size - args.shard_size) * 100.0 / args.batch_size
        print(f"WARN: --shard-size ({args.shard_size:,}) < --batch-size "
              f"({args.batch_size:,}): each shard pads GPU work by "
              f"~{wasted_pct:.0f}%. Consider raising --shard-size to a "
              f"multiple of --batch-size for better throughput.",
              file=sys.stderr)

    dict_paths = {
        "fi":  args.dict_fi  if args.dict_fi  else str(SCRIPT_DIR / "extra_words_fi.txt"),
        "krl": args.dict_krl if args.dict_krl else str(SCRIPT_DIR / "extra_words_krl.txt"),
        "en":  args.dict_en  if args.dict_en  else str(SCRIPT_DIR / "noita_wordlist.txt"),
    }
    # Each dict path may be a single file or '+'-separated list of files
    # (e.g. "extra_words_fi.txt+noita_wordlist.txt"); validate each piece.
    for lang in languages:
        raw = dict_paths[lang]
        missing = [s.strip() for s in raw.split("+")
                   if s.strip() and not Path(s.strip()).exists()]
        if missing:
            print(f"WARN: dict file(s) for {lang} not found: {missing}",
                  file=sys.stderr)
        components = [s.strip() for s in raw.split("+") if s.strip()]
        if len(components) > 1:
            print(f"[dict] {lang}: merging {len(components)} files: "
                  f"{', '.join(Path(c).name for c in components)}")

    # ---- Initialize GPU ----
    print(f"[gpu] Initializing GpuBatchRunner "
          f"(mode={args.mode}, batch_size={args.batch_size})...")
    gpu = GpuBatchRunner(
        mode_code=MODE_CODE[args.mode],
        N=N,
        ciphertexts=ciphertexts,
        batch_size=args.batch_size,
        prng_version=args.prng,
    )
    print(f"[gpu] Compiled kernels target = {gpu.arch_used}")
    print(f"[gpu] PRNG variant            = {args.prng}  "
          f"(A={gpu._prng_A}, Q={gpu._prng_Q}, R={gpu._prng_R})")
    print(f"[gpu] GPU memory: perms = "
          f"{args.batch_size * gpu.num_perms * N / 1024**2:.0f} MB, "
          f"decrypted = "
          f"{args.batch_size * gpu.ct_total_len / 1024**2:.0f} MB")

    # =========================================================================
    # chi² pre-filter setup
    # =========================================================================
    # The filter rejects candidates whose rune-frequency shape doesn't look
    # like any of the active target languages. Done on GPU between decryption
    # and CPU scoring. See math reference in eyestat_compute_audit.py Phase 8
    # and the chi2_pre_filter kernel docstring in eyestat_gpu.py.
    if args.chi2_threshold.lower() in ("off", "none", "inf"):
        chi2_threshold = math.inf
        chi2_filter_enabled = False
        print(f"[chi2] Pre-filter DISABLED — all candidates go to CPU pool")
    else:
        try:
            chi2_threshold = float(args.chi2_threshold)
        except ValueError:
            print(f"ERROR: --chi2-threshold must be a finite number or 'off', "
                  f"got {args.chi2_threshold!r}", file=sys.stderr)
            return 2
        if not math.isfinite(chi2_threshold) or chi2_threshold < 0:
            print(f"ERROR: --chi2-threshold must be in [0, inf), got "
                  f"{chi2_threshold}", file=sys.stderr)
            return 2
        chi2_filter_enabled = True

    # Build reference distributions for each active language.
    # Each is the per-rune expected frequency shape under homophonic mapping,
    # sorted descending. See eyestat_scoring.compute_expected_sorted_distribution.
    lang_dists_gpu = None
    if chi2_filter_enabled:
        # Deferred CuPy import — matches the pattern used for GpuBatchRunner
        # above. Imported here only if chi² is enabled so the runner module
        # remains importable on CPU-only systems for testing.
        try:
            import cupy as cp
        except ImportError as e:
            print(f"ERROR: chi² filter requires CuPy but import failed: {e}\n"
                  f"       Pass --chi2-threshold off to disable the filter.",
                  file=sys.stderr)
            return 2

        from eyestat_scoring import compute_expected_sorted_distribution
        try:
            expected = np.stack([
                np.array(compute_expected_sorted_distribution(l, N),
                         dtype=np.float32)
                for l in languages
            ])
        except KeyError as e:
            print(f"ERROR: cannot compute expected distribution for language: {e}",
                  file=sys.stderr)
            return 2
        lang_dists_gpu = cp.asarray(expected)
        print(f"[chi2] Pre-filter ENABLED — threshold = {chi2_threshold}")
        print(f"[chi2] Reference distributions: {languages}  "
              f"(shape (n_langs, N) = {lang_dists_gpu.shape})")
        for i, l in enumerate(languages):
            top3 = expected[i, :3].tolist()
            print(f"[chi2]   {l}: top-3 expected freqs = "
                  f"[{top3[0]:.4f}, {top3[1]:.4f}, {top3[2]:.4f}]")

    # Filter statistics — tracked across all batches in this run.
    chi2_n_total = 0       # total candidates seen by the filter
    chi2_n_rejected = 0    # candidates filtered out before CPU scoring
    chi2_min_seen = math.inf   # smallest chi² observed (closest to plaintext shape)

    # Initial GPU health snapshot + advisories
    initial = get_gpu_stats()
    if initial is not None:
        print(f"[gpu] {format_gpu_stats(initial, args.temp_warn)}")
        plimit = get_gpu_power_limit()
        if plimit is not None:
            cur, mx = plimit
            print(f"[gpu] Power limit: {cur} W / {mx} W max"
                  + (" (capped)" if cur < mx else ""))
            if cur >= mx and args.gpu_utilization >= 1.0:
                print(f"[gpu] TIP: for thermal safety on long runs, consider")
                print(f"      EITHER  sudo nvidia-smi -pl {int(mx * 0.85)}  (hardware power cap, persists)")
                print(f"      OR pass --gpu-utilization 0.80  (duty-cycle throttle in this run)")
    else:
        print(f"[gpu] (nvidia-smi unavailable — temperature monitoring disabled)")

    if args.gpu_utilization < 1.0:
        print(f"[throttle] GPU duty cycle: {args.gpu_utilization*100:.0f}%  "
              f"(sleep {(1-args.gpu_utilization)/args.gpu_utilization*100:.0f}% of work time per batch)")
    if args.temp_warn > 0:
        print(f"[throttle] Temperature warning threshold: {args.temp_warn}°C")

    # ---- Optional GPU sanity check ----
    if not args.skip_validate:
        print(f"[validate] Cross-validating GPU vs CPU on 50 seeds...")
        if not gpu.validate_against_cpu(n_test=50, verbose=True):
            print(f"  CROSS-VALIDATION FAILED — aborting.")
            return 2

    # ---- Initialize CPU worker pool ----
    print(f"[pool] Starting {args.workers} CPU scoring workers...")
    # 'fork' on Linux shares parent memory pages (copy-on-write) — fast init
    ctx = mp.get_context("fork")
    pool = ctx.Pool(
        processes=args.workers,
        initializer=_worker_init,
        initargs=(dict_paths, languages, N, args.min_word_len, ct_total_len),
    )

    # ---- Main batch loop ----
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    total_keys = args.seed_end - args.seed_start
    n_shards = max(1, (total_keys + args.shard_size - 1) // args.shard_size)
    print(f"[run] mode={args.mode} prng={args.prng}  "
          f"seeds=[{args.seed_start}, {args.seed_end}) = {total_keys:,} keys")
    print(f"      shard_size={args.shard_size} → {n_shards} shards")
    print(f"      batch_size={args.batch_size}, workers={args.workers}")
    print()

    t_start = time.time()
    last_print = t_start
    grand_tried = 0
    grand_hits = 0
    skipped_shards = 0
    all_top_hits = []
    shard_writer = None  # references the currently-active writer for clean abort

    # Session-rate tracking. When resuming a partial run, the [skip] phase
    # quickly bumps grand_tried by the size of every completed shard, BUT the
    # "rate" display would be misleading if we divided that by elapsed time
    # (which started before any real work happened). So we capture a baseline
    # at the FIRST real (non-skipped) shard and compute rate/ETA against that.
    session_started = False
    session_baseline_seeds = 0   # = grand_tried at start of first real shard

    try:
        for shard_idx in range(n_shards):
            shard_start = args.seed_start + shard_idx * args.shard_size
            shard_end = min(shard_start + args.shard_size, args.seed_end)

            # Resume check: skip BEFORE opening any .tmp files. Critical —
            # previous version constructed ShardWriter (opening empty .tmp
            # files) and then called close(), which atomic-renamed the empty
            # tmp over the existing complete final, destroying data.
            paths = ShardWriter.shard_paths(
                output_dir, args.mode, args.prng, shard_start, shard_end)
            if paths["params_final"].exists() and paths["results_final"].exists():
                print(f"  [skip] shard {shard_idx+1}/{n_shards} "
                      f"({shard_start}-{shard_end}) already complete")
                skipped_shards += 1
                # Account for the skipped shard in grand_tried so that
                # progress / rate / ETA / final summary lines reflect TOTAL
                # sweep coverage, not just keys done in this resumed session.
                # We can't recover the exact n_tried (the shard might have
                # had filtering), but the shard's seed range is the right
                # accounting unit: any seed in [shard_start, shard_end) is
                # accounted for as "swept" by the previous run.
                grand_tried += (shard_end - shard_start)
                continue

            shard_writer = ShardWriter(
                output_dir, args.mode, args.prng, shard_start, shard_end,
                languages, args.threshold)

            # First non-skipped shard: capture timing baselines so rate/ETA
            # reflect work done in THIS session, not work inherited from
            # previously-completed shards. Without this, the rate display
            # is wildly inflated right after a resume (skip phase counts
            # zero seconds but adds millions of seeds to grand_tried).
            if not session_started:
                session_started = True
                session_baseline_seeds = grand_tried
                t_start = time.time()
                last_print = t_start
                if skipped_shards > 0:
                    print(f"  [session] First new shard begins. "
                          f"Skipped {skipped_shards:,} prior shards = "
                          f"{session_baseline_seeds:,} seeds. "
                          f"Rate/ETA from here.")

            # Loop over batches within this shard
            #
            # PIPELINE OVERVIEW
            # =================
            # The naïve loop is fully sequential per batch: GPU produces, then
            # CPU pool scores (with GPU idle), then main thread writes all
            # results (with workers and GPU both idle). That gives the
            # characteristic stop-and-go power/clock oscillation on both the
            # CPU and GPU — exactly what `nvidia-smi` + `htop` show.
            #
            # This implementation overlaps three things:
            #
            # 1. GPU producing batch N+1 happens WHILE pool workers score batch N.
            #    `gpu.run_batch()` blocks the main thread for ~220 ms, but during
            #    that time the pool workers are already busy with the previous
            #    batch's chunks — they were submitted via imap_unordered, which
            #    returns immediately and lets workers process in the background.
            #
            # 2. `pool.imap_unordered` returns results as workers finish their
            #    chunks. The main thread writes each chunk's results to the
            #    ShardWriter immediately, instead of waiting for all chunks then
            #    bulk-writing 65 k entries.
            #
            # 3. Writes interleave with scoring: the disk-bound `write_key` calls
            #    happen on the main thread while workers continue scoring slower
            #    chunks. With ~50 µs per write × ~65 k entries (~3 s), and ~24 s
            #    of CPU scoring per batch, the writes are completely hidden.
            #
            # Net effect (predicted, calibrate with timing):
            #   GPU oscillation should disappear (constant ~70-80 % util during
            #   the CPU-bound regime).  CPU workers should show flat 95-100 %
            #   load with no idle troughs between batches.  Effective
            #   throughput up by 15-25 %.

            def _launch_batch(seed_start):
                """Run one GPU batch starting at `seed_start`.

                Returns (seeds, decrypted, n_tried, n_survivors):
                  seeds       : np.ndarray (n_survivors,) uint32 — survivor seeds
                  decrypted   : np.ndarray (n_survivors, ct_total_len) uint8
                  n_tried     : int — total seeds advanced (for `cur += n_tried`)
                  n_survivors : int — candidates that passed the chi² filter and
                                will be sent to the CPU pool. Always <= n_tried.

                When chi²-filtering is disabled, n_survivors == n_tried and the
                first two return values are the full batch.
                """
                n_tried = min(args.batch_size, shard_end - seed_start)
                # Decrypt — same as before
                if n_tried == args.batch_size:
                    dec = gpu.run_batch(seed_start=seed_start)
                    sds = np.arange(seed_start, seed_start + n_tried,
                                    dtype=np.uint32)
                else:
                    sds_full = np.arange(seed_start,
                                          seed_start + args.batch_size,
                                          dtype=np.uint32)
                    dec_full = gpu.run_batch_seeds(sds_full)
                    sds = sds_full[:n_tried]
                    dec = dec_full[:n_tried]

                if not chi2_filter_enabled:
                    return sds, dec, n_tried, n_tried

                # GPU chi² filter — runs on the FULL batch_size of decryptions
                # the kernels just produced, then we slice to [:n_tried] for
                # the partial-tail case.
                hist_gpu = gpu.compute_histograms(return_numpy=False)
                min_chi2_gpu, _best_lang_gpu = gpu.compute_chi2(
                    hist_gpu, lang_dists_gpu, return_numpy=False)
                min_chi2_host = cp.asnumpy(min_chi2_gpu)[:n_tried]

                # Filter to survivors
                mask = min_chi2_host < chi2_threshold
                survivor_idx = np.flatnonzero(mask)
                n_survivors = int(survivor_idx.size)

                # Update run-wide filter statistics
                nonlocal chi2_n_total, chi2_n_rejected, chi2_min_seen
                chi2_n_total    += n_tried
                chi2_n_rejected += (n_tried - n_survivors)
                batch_min = float(min_chi2_host.min()) if n_tried > 0 else math.inf
                if batch_min < chi2_min_seen:
                    chi2_min_seen = batch_min

                # Tell the active shard writer about candidates we discarded
                # at the GPU stage so its n_tried counter (used by grand_tried,
                # per-shard summary, and final rate calc) reflects the actual
                # sweep size — not just the survivor count.
                if shard_writer is not None and n_tried > n_survivors:
                    shard_writer.note_filtered(n_tried - n_survivors)

                if n_survivors == 0:
                    # Nothing to score — return empty arrays of the right shape
                    return (sds[:0], dec[:0], n_tried, 0)
                return (sds[survivor_idx], dec[survivor_idx], n_tried, n_survivors)

            def _build_chunks(sds, dec, n_actual):
                """Slice a batch into per-worker chunks. 4 chunks/worker keeps
                load-balance tight (slowest chunk doesn't dominate)."""
                chunk_n = max(1, n_actual // (args.workers * 4))
                out = []
                for c0 in range(0, n_actual, chunk_n):
                    c1 = min(c0 + chunk_n, n_actual)
                    out.append((sds[c0:c1], dec[c0:c1]))
                return out

            shard_keys_done = 0
            cur = shard_start
            high_temp_seen = 0  # track peak for the run summary

            # ---- Prime the pipeline: first batch ----
            # n_tried = candidates the GPU advanced through (drives cur)
            # n_scored = candidates that survived the chi² filter (sent to pool)
            seeds_curr, dec_curr, n_tried_curr, n_scored_curr = _launch_batch(cur)
            cur += n_tried_curr
            pending = pool.imap_unordered(_score_chunk,
                                           _build_chunks(seeds_curr,
                                                          dec_curr, n_scored_curr))

            # ---- Pipelined steady state ----
            while cur < shard_end:
                batch_t0 = time.time()

                # Launch GPU for the NEXT batch while pool workers are still
                # crunching the CURRENT batch in the background. This is the
                # heart of the pipeline overlap.
                seeds_next, dec_next, n_tried_next, n_scored_next = _launch_batch(cur)
                cur += n_tried_next

                # Drain results from the current (in-flight) batch. Most chunks
                # have already completed during the GPU launch above; this loop
                # consumes whatever's ready and waits for the last few.
                # Workers stay busy on slower chunks while writes interleave.
                for chunk_results in pending:
                    for seed, max_hits, results in chunk_results:
                        shard_writer.write_key(seed, max_hits, results)

                # Submit the next batch's chunks. The main thread keeps moving;
                # workers immediately start scoring while we go around the loop.
                pending = pool.imap_unordered(_score_chunk,
                                               _build_chunks(seeds_next,
                                                              dec_next,
                                                              n_scored_next))

                # Advance shard counter by what the GPU tried, not what the
                # filter let through — chi²-rejected candidates still count as
                # "swept" because we won't revisit those seeds.
                shard_keys_done += n_tried_curr
                # Roll the "current" pointers forward. Reassigning frees the
                # previous batch's arrays — without this, seeds_curr/dec_curr
                # from the PRIME would stay alive for the whole shard (~65 MB
                # per shard of needlessly retained main-process memory).
                seeds_curr, dec_curr = seeds_next, dec_next
                n_tried_curr, n_scored_curr = n_tried_next, n_scored_next

                batch_elapsed = time.time() - batch_t0

                # Duty-cycle throttle: sleep proportional to work time so the
                # GPU spends (1-util) fraction of total time idle. With the
                # pipeline, this also throttles the CPU side naturally because
                # we delay the next GPU launch.
                #
                # NOTE: under CPU-bound regimes (very large dictionaries, very
                # slow scoring) the GPU is already idle most of the time and
                # this sleep is largely a no-op — that's fine, the user-set
                # util cap is an UPPER bound, not a target.
                if args.gpu_utilization < 1.0:
                    sleep_t = batch_elapsed * (1.0 - args.gpu_utilization) / args.gpu_utilization
                    if sleep_t > 0:
                        time.sleep(sleep_t)

                # Progress
                now = time.time()
                if now - last_print >= args.progress_interval:
                    elapsed = now - t_start
                    cur_total = grand_tried + shard_keys_done
                    # Rate is computed only over THIS session's work — the
                    # numerator subtracts whatever was bumped during the skip
                    # phase. Otherwise the rate display is wildly off on resume.
                    session_seeds_done = cur_total - session_baseline_seeds
                    rate = session_seeds_done / max(elapsed, 0.01)
                    remaining = (total_keys - cur_total) / max(rate, 1)
                    line = (f"  [progress] shard {shard_idx+1}/{n_shards}, "
                            f"keys={cur_total:,}/{total_keys:,}, "
                            f"hits={grand_hits + shard_writer.n_hits:,}, "
                            f"rate={rate:,.0f}/s, "
                            f"ETA={remaining/60:.1f}min")
                    # Chi² filter stats — reject rate is the throughput multiplier
                    if chi2_filter_enabled and chi2_n_total > 0:
                        reject_pct = 100.0 * chi2_n_rejected / chi2_n_total
                        line += (f"  |  chi2 reject={reject_pct:.1f}% "
                                 f"min={chi2_min_seen:.5f}")
                    # Append GPU stats if available
                    stats = get_gpu_stats()
                    if stats is not None:
                        temp = stats[0]
                        if temp > high_temp_seen:
                            high_temp_seen = temp
                        line += f"  |  {format_gpu_stats(stats, args.temp_warn)}"
                    print(line)
                    last_print = now

            # End of shard — drain the last batch's pending iterator. The
            # pipeline has one batch "in flight" at all times; we exit the
            # while loop after submitting it, so we still need to consume it.
            for chunk_results in pending:
                for seed, max_hits, results in chunk_results:
                    shard_writer.write_key(seed, max_hits, results)
            shard_keys_done += n_tried_curr

            shard_writer.close()
            grand_tried += shard_writer.n_tried
            grand_hits += shard_writer.n_hits
            all_top_hits.extend(shard_writer.top_hits)
            all_top_hits.sort(key=lambda t: t[0], reverse=True)
            all_top_hits = all_top_hits[:20]

            elapsed = time.time() - t_start
            # Cumulative rate over this SESSION (excludes seeds inherited
            # from skipped shards) so the number is meaningful on resume.
            session_seeds_done = grand_tried - session_baseline_seeds
            rate = session_seeds_done / max(elapsed, 0.01)
            print(f"  [shard {shard_idx+1}/{n_shards}] "
                  f"keys={shard_writer.n_tried:,}, "
                  f"hits={shard_writer.n_hits:,}, "
                  f"cumulative rate={rate:,.0f}/s")
            shard_writer = None   # only clear AFTER all reads — for the abort handler

    except KeyboardInterrupt:
        print("\n[abort] Caught Ctrl-C; closing pool + flushing in-flight shard...")
        if shard_writer is not None:
            # Don't atomic-rename — leave .tmp files for eyestat_recover.py to salvage.
            shard_writer.abandon()
        pool.terminate()
        pool.join()
        return 130
    except Exception as e:
        # Non-Ctrl-C failures: disk full, CUDA OOM, BrokenProcessPool, etc.
        # Same handling — abandon the in-flight shard (don't promote to final),
        # then re-raise so the traceback is visible. The .tmp files will be
        # explicitly flushed (rather than relying on GC after the traceback
        # propagates) so eyestat_recover can salvage what was written.
        print(f"\n[abort] Unexpected error mid-run: {type(e).__name__}: {e}",
              file=sys.stderr)
        if shard_writer is not None:
            shard_writer.abandon()
        pool.terminate()
        pool.join()
        raise
    finally:
        # If we got here normally, pool.terminate wasn't called and we just
        # close. If we got here via KeyboardInterrupt or other exception,
        # the pool is already terminated+joined and close()/join() are
        # safe no-ops.
        try:
            pool.close()
            pool.join()
        except Exception:
            pass

    # ---- Summary ----
    elapsed = time.time() - t_start
    session_seeds = grand_tried - session_baseline_seeds
    print()
    if skipped_shards > 0:
        # Resume run — distinguish "session" from "total swept"
        print(f"[done] Session: tried {session_seeds:,} new keys in {elapsed:.1f}s "
              f"({session_seeds/max(elapsed,0.01):,.0f}/s)")
        print(f"[done] Skipped {skipped_shards:,} previously-completed shards "
              f"({session_baseline_seeds:,} seeds)")
        print(f"[done] Total swept across all sessions: {grand_tried:,} of "
              f"{total_keys:,}")
    else:
        # Fresh run — session == total
        print(f"[done] Tried {grand_tried:,} keys in {elapsed:.1f}s "
              f"({grand_tried/max(elapsed,0.01):,.0f}/s)")
    print(f"[done] Found {grand_hits:,} keys above threshold={args.threshold}")
    final_stats = get_gpu_stats()
    if final_stats is not None:
        print(f"[done] Final GPU: {format_gpu_stats(final_stats, args.temp_warn)}")
    if all_top_hits:
        print(f"\n[top hits]")
        for max_hits, mode, prng, key_id in all_top_hits[:10]:
            print(f"  {max_hits:>4d}  {mode:<18s}  {prng:<15s}  {key_id}")

    # ---- Optional merge ----
    if args.merge:
        # New layout: write merged file to <output_dir>/results/.
        # Source shards live in <output_dir>/temp/ (or legacy flat layout).
        results_dir = output_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        merged_path = results_dir / "bruteforce_results.txt"
        # Find shards in temp/ first (new layout), fall back to flat layout
        temp_dir = output_dir / "temp"
        if temp_dir.exists():
            shard_paths = sorted(temp_dir.glob("results_*.txt"))
        else:
            shard_paths = sorted(output_dir.glob("results_*.txt"))
        print(f"\n[merge] Aggregating {len(shard_paths)} shards into {merged_path}...")
        with open(merged_path, "w", encoding="utf-8") as out:
            for results_file in shard_paths:
                with open(results_file, "r", encoding="utf-8") as f:
                    out.write(f.read())
        print(f"[merge] Wrote {merged_path.stat().st_size:,} bytes")

    # ---- Auto HTML report ----
    # Unless explicitly disabled via --no-html, generate a self-contained
    # HTML report for this scan and drop it into <output_dir>/results/.
    # Failure here is non-fatal: the scan already succeeded, the report is
    # a nicety. We log any error and return normally.
    if not args.no_html:
        results_dir = output_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        # Filename embeds (mode, prng) so multiple scans in the same parent
        # tree never collide. Example: ctak_right_park_miller_v0_report.html
        html_name = f"{args.mode}_{args.prng}_report.html"
        html_path = results_dir / html_name
        try:
            import eyestat_html_report as H   # deferred import — keeps cold-start fast
            entries, scan_meta = H.scan_directory(output_dir)
            # Enrich metadata with this run's actual parameters
            scan_meta.update({
                "mode": args.mode,
                "prng": args.prng,
                "seed_start": args.seed_start,
                "seed_end": args.seed_end,
                "languages": args.languages,
                "threshold": args.threshold,
                "chi2_threshold": getattr(args, "chi2_threshold", None),
                "total_seeds_tried": grand_tried,
                "total_hits": grand_hits,
                "shards_scanned": len(list((output_dir / "temp").glob("results_*.txt")))
                                  if (output_dir / "temp").exists()
                                  else len(list(output_dir.glob("results_*.txt"))),
            })
            doc = H.build_html(entries, scan_meta)
            html_path.write_text(doc, encoding="utf-8")
            print(f"\n[html] Wrote report: {html_path}")
            print(f"[html] Open with: xdg-open {html_path}")
        except ImportError as e:
            # eyestat_html_report not on path — log and skip
            print(f"\n[html] Skipped: eyestat_html_report module not found "
                  f"({e}). To enable, ensure eyestat_html_report.py is in "
                  f"the same directory.", file=sys.stderr)
        except Exception as e:
            # Anything else (parse error, write permission, etc.) — log and skip
            print(f"\n[html] Skipped due to error: {type(e).__name__}: {e}",
                  file=sys.stderr)

    return 0


# =============================================================================
# CLI
# =============================================================================

def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Data
    p.add_argument("--data", default="noita_eye_data.json",
                   help="Ciphertext data file (default: noita_eye_data.json)")
    p.add_argument("--dict-fi", default="",
                   help="Finnish dictionary file. Use '+' to merge multiple "
                        "files: 'extra_words_fi.txt+noita_wordlist.txt'. "
                        "Default: extra_words_fi.txt")
    p.add_argument("--dict-krl", default="",
                   help="Karelian dictionary file. Same '+'-merge syntax as "
                        "--dict-fi. Default: extra_words_krl.txt")
    p.add_argument("--dict-en", default="",
                   help="English dictionary file. Same '+'-merge syntax as "
                        "--dict-fi. Default: noita_wordlist.txt")

    # What to scan
    p.add_argument("--mode", default="ctak_right", choices=list(MODE_CODE.keys()),
                   help="GAK cipher mode (default: ctak_right)")
    p.add_argument("--prng", default="park_miller_v0",
                   choices=["park_miller_v0", "park_miller_v1", "park_miller"],
                   help="PRNG variant. park_miller_v0 (a=16807, the original "
                        "1988 'minimum standard') or park_miller_v1 (a=48271, "
                        "the 1993 revised constants). `park_miller` is a "
                        "backward-compatible alias for park_miller_v0.")
    p.add_argument("--languages", default="fi,krl,en",
                   help="Languages to score against (comma-separated). "
                        "Default: fi,krl,en")

    p.add_argument("--seed-start", type=int, default=0,
                   help="First seed (inclusive)")
    p.add_argument("--seed-end", type=int, default=10000,
                   help="Last seed + 1 (exclusive)")

    # Knobs
    p.add_argument("--batch-size", type=int, default=65536,
                   help="Seeds per GPU batch (default: 65536)")
    p.add_argument("--shard-size", type=int, default=1_000_000,
                   help="Seeds per output shard file (default: 1,000,000 ≈ "
                        "16 batches of 65536). Should be >= --batch-size for "
                        "efficient GPU use.")
    p.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 2),
                   help=f"CPU scoring workers (default: cpu_count - 2)")
    p.add_argument("--threshold", type=int, default=13,
                   help="Min max_hits to include in results.txt (default: 13)")
    p.add_argument("--chi2-threshold", default="0.0015",
                   help="GPU chi² pre-filter threshold. Candidates whose "
                        "min(chi²) across active languages exceeds the threshold "
                        "are rejected at the GPU stage and never sent to the CPU "
                        "pool. Default 0.0015 — empirically calibrated for clean "
                        "separation between noise (mean ~0.0035) and real "
                        "language signal (mean ~0.0002). Pass 'off', 'none', or "
                        "'inf' to disable the filter (everything goes to CPU).")
    p.add_argument("--min-word-len", type=int, default=4,
                   help="Min word length for dict matching (default: 4)")
    p.add_argument("--progress-interval", type=float, default=5.0,
                   help="Seconds between progress lines (default: 5)")

    # Thermal safety
    p.add_argument("--gpu-utilization", type=float, default=1.0,
                   help="GPU duty-cycle target: 1.0=full speed, 0.8=80%% "
                        "(sleep ~25%% of work time per batch). Reduces "
                        "sustained thermal load on multi-hour runs. "
                        "Default: 1.0")
    p.add_argument("--temp-warn", type=int, default=83,
                   help="Print a warning when GPU temp >= this °C "
                        "(0=disable). Default: 83")

    # Misc
    p.add_argument("--output-dir", default="gpu_results",
                   help="Where to write shards (default: gpu_results/)")
    p.add_argument("--skip-validate", action="store_true",
                   help="Skip the 50-seed CPU vs GPU sanity check at start")
    p.add_argument("--merge", action="store_true",
                   help="Concatenate all results_*.txt into "
                        "bruteforce_results.txt at end")
    p.add_argument("--no-html", action="store_true",
                   help="Skip auto-generating the HTML report at end of run "
                        "(report is generated into <output-dir>/results/ by "
                        "default).")

    args = p.parse_args()
    return run_gpu_brute_force(args)


if __name__ == "__main__":
    sys.exit(main())
