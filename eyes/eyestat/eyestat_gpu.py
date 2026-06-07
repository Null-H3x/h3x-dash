#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_gpu.py — GPU pipeline for the brute-force runner: park_miller + GAK family.

This module provides batched GPU execution of the inner loop:

    seed → park_miller PRNG → 84 permutations → GAK decryption → decrypted texts

What lives on the GPU here:
  - park_miller PRNG state advancement (validated byte-for-byte in eyestat_gpu_validate.py)
  - Fisher-Yates generation of 84 permutations (sigma[0..N]) per seed
  - GAK/xGAK decryption (all 8 modes) of all 9 Noita messages in one launch

What stays on the CPU (handled elsewhere — eyestat_runner.py orchestrates):
  - Hungarian rune→letter mapping (scipy.optimize.linear_sum_assignment)
  - Dictionary substring matching (Aho-Corasick / set lookup)
  - File I/O, work-unit scheduling, progress monitoring, recovery

Supports all 8 GAK family modes via a single kernel parameterized by mode_code:
  0  GAK_CTAK_RIGHT    1  GAK_CTAK_LEFT
  2  GAK_PTAK_RIGHT    3  GAK_PTAK_LEFT
  4  XGAK_SUM_RIGHT    5  XGAK_SUM_LEFT
  6  XGAK_DIFF_RIGHT   7  XGAK_DIFF_LEFT

Only park_miller PRNG is supported for v1. Add more PRNGs by extending
CUDA_SOURCE with new __device__ functions and wiring them in the kernel.

USAGE — high-level
==================

    from eyestat_gpu import GpuBatchRunner

    runner = GpuBatchRunner(
        mode_code=0,                        # GAK_CTAK_RIGHT
        N=83,                                # alphabet size
        ciphertexts=[ct1_list, ct2_list...], # the 9 Noita messages
        batch_size=65536,
    )

    # Generate decrypted texts for seeds [seed_start, seed_start + batch_size)
    decrypted = runner.run_batch(seed_start=0)
    # decrypted is np.ndarray, shape (batch_size, total_ct_len), dtype uint8

    # Verify against CPU implementation
    assert runner.validate_against_cpu(n_test=100)

USAGE — standalone validation + benchmark
==========================================

    python3 eyestat_gpu.py                       # default: 1000 seed validation + benchmark
    python3 eyestat_gpu.py --batch-size 131072   # bigger batches
    python3 eyestat_gpu.py --mode xgak_diff_right --n-test 500
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

try:
    import cupy as cp
except ImportError:
    cp = None  # Deferred: raise a clear error only when a GPU path is actually used.


def _require_cupy():
    """Raise a clear ImportError when a GPU code path is entered without CuPy.

    This lets `import eyestat_gpu` succeed on machines without a GPU so the
    runner can be import-tested and CPU-only helpers exercised. The original
    sys.exit(1) here bypassed the runner's try/except ImportError, which was
    the design intent recorded in eyestat_gpu_runner.py.
    """
    if cp is None:
        raise ImportError(
            "CuPy is required for this operation. Install with:\n"
            "  source ~/.venvs/eyestat/bin/activate\n"
            "  pip install --pre 'cupy-cuda13x[ctk]'"
        )

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from eyestat_prngs import ParkMillerRng, ParkMillerV0Rng, ParkMillerV1Rng
import eyestat_kernels as K


def _gen_keys_gak_xgak_cpu(prng_cls, seed: int, N: int) -> List[List[int]]:
    """CPU reference for the 84-perm GAK key schedule.

    Inlined here (rather than imported from eyestat_runner) so eyestat_gpu.py doesn't
    drag in the runner's heavy dependencies (multiprocessing, CLI, etc.).
    Matches gen_keys_gak_xgak() in eyestat_runner.py — the PRNG state is shared
    across all N+1 shuffled_perm calls.
    """
    rng = prng_cls(seed)
    return [rng.shuffled_perm(N) for _ in range(N + 1)]


# =============================================================================
# Mode codes — kept in sync with eyestat_kernels.py
# =============================================================================

MODE_CODE = {
    "ctak_right":      0,
    "ctak_left":       1,
    "ptak_right":      2,
    "ptak_left":       3,
    "xgak_sum_right":  4,
    "xgak_sum_left":   5,
    "xgak_diff_right": 6,
    "xgak_diff_left":  7,
}
MODE_NAME = {v: k for k, v in MODE_CODE.items()}
RIGHT_MODES = {0, 2, 4, 6}  # used for in-kernel composition direction


# =============================================================================
# CUDA SOURCE
# =============================================================================

CUDA_SOURCE = r"""
// ===========================================================================
// park_miller_next() — Schrage's algorithm parameterized on (A, Q, R)
//
// MUST match eyestat_prngs._LehmerLcg31.next_u32() bit-for-bit. Schrage's
// constants are (Q, R) = (M // A, M mod A), and the same formula handles
// both Park-Miller V0 (A=16807) and V1 (A=48271) without recompilation —
// the caller passes whichever pair matches the hypothesis being tested.
// ===========================================================================
extern "C" __device__ unsigned int park_miller_next(
    unsigned int s,
    int A,
    int Q,
    int R
) {
    const int M = 2147483647;
    int hi = (int)s / Q;
    int lo = (int)s - hi * Q;
    int t = A * lo - R * hi;
    if (t < 0) t += M;
    return (unsigned int)t;
}

// ===========================================================================
// gak_generate_keys
// Per thread: read one seed, write 84 permutations (N+1 perms × N bytes each)
// to perms[idx * (N+1) * N : ...]. PRNG state is preserved across all 84
// perm generations, matching gen_keys_gak_xgak() in eyestat_runner.py.
// ===========================================================================
extern "C" __global__ void gak_generate_keys(
    const unsigned int* seeds_in,    // [batch_size]
    unsigned char* perms_out,         // [batch_size, num_perms, N]
    int batch_size,
    int N,
    int num_perms,
    int prng_A,                       // Park-Miller multiplier (16807 for V0, 48271 for V1)
    int prng_Q,                       // Schrage's Q = M // A
    int prng_R                        // Schrage's R = M mod A
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;

    const unsigned int M = 2147483647u;

    unsigned int s = seeds_in[idx] & 0x7FFFFFFFu;
    if (s == 0u || s == M) s = 1u;

    for (int k = 0; k < num_perms; k++) {
        unsigned char* perm = perms_out
            + ((size_t)idx * (size_t)num_perms + (size_t)k) * (size_t)N;

        // Identity init
        for (int i = 0; i < N; i++) perm[i] = (unsigned char)i;

        // Fisher-Yates with rejection-sampling next_below
        for (int i = N - 1; i > 0; i--) {
            unsigned int bound = (unsigned int)(i + 1);
            unsigned int max_v = M - (M % bound);
            unsigned int v;
            do {
                s = park_miller_next(s, prng_A, prng_Q, prng_R);
                v = s;
            } while (v >= max_v);
            unsigned int j = v % bound;

            unsigned char tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
    }
}

// ===========================================================================
// gak_decrypt_batch
//
// Per thread: read this thread's 84 perms; for each of the num_msgs
// ciphertext messages, decrypt under the specified mode. Output is the
// concatenated decrypted text of length ct_total_len.
//
// We hold active[] and active_inv[] in thread-local arrays of size N=83.
// These typically spill to local memory (off-chip but L1-cached), which is
// fine — the dominant cost is the per-symbol active recomputation, not
// memory bandwidth.
//
// Mode logic matches gak_decrypt() in eyestat_kernels.py exactly:
//   p = active_inv[c]                  (always)
//   k = c | p | (p+c) mod N | (c-p) mod N    (per mode)
//   RIGHT: active'[i] = active[sigma_k[i]]
//   LEFT:  active'[i] = sigma_k[active[i]]
//   active_inv'[active'[i]] = i        (recompute inverse)
// ===========================================================================
extern "C" __global__ void gak_decrypt_batch(
    const unsigned char* perms,           // [batch, num_perms, N]
    const unsigned char* ciphertext,       // [ct_total_len]
    const int* msg_offsets,                // [num_msgs+1] start indices
    int num_msgs,
    int ct_total_len,
    unsigned char* decrypted,             // [batch, ct_total_len]
    int batch_size,
    int N,
    int num_perms,                         // typically N+1; passed explicitly for robustness
    int mode_code
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;

    const unsigned char* my_perms = perms
        + (size_t)idx * (size_t)num_perms * (size_t)N;
    unsigned char* my_dec = decrypted + (size_t)idx * (size_t)ct_total_len;

    // We assume N <= 256 (uint8 perms). 83 fits well.
    unsigned char active[256];
    unsigned char active_inv[256];
    unsigned char new_active[256];

    // Cache mode comparisons to avoid repeated branching
    bool mode_right = (mode_code == 0 || mode_code == 2
                       || mode_code == 4 || mode_code == 6);
    int mode_key_type = mode_code / 2;  // 0=ctak, 1=ptak, 2=xgak_sum, 3=xgak_diff

    for (int m = 0; m < num_msgs; m++) {
        int ct_start = msg_offsets[m];
        int ct_end   = msg_offsets[m + 1];

        // Reset active = sigma[0]; compute active_inv from it
        for (int i = 0; i < N; i++) active[i] = my_perms[i];
        for (int i = 0; i < N; i++) active_inv[active[i]] = (unsigned char)i;

        // Decrypt each symbol in this message
        for (int pos = ct_start; pos < ct_end; pos++) {
            unsigned char c = ciphertext[pos];
            unsigned char p = active_inv[c];
            my_dec[pos] = p;

            // Compute k based on mode
            int k;
            if (mode_key_type == 0)       k = (int)c;                       // ctak
            else if (mode_key_type == 1)  k = (int)p;                       // ptak
            else if (mode_key_type == 2)  k = ((int)p + (int)c) % N;        // xgak_sum
            else                          k = ((int)c - (int)p + N) % N;    // xgak_diff

            const unsigned char* sigma_k = my_perms + (size_t)k * (size_t)N;

            // Update active
            if (mode_right) {
                // active'[i] = active[sigma_k[i]]
                for (int i = 0; i < N; i++) {
                    new_active[i] = active[sigma_k[i]];
                }
            } else {
                // active'[i] = sigma_k[active[i]]
                for (int i = 0; i < N; i++) {
                    new_active[i] = sigma_k[active[i]];
                }
            }

            // Commit + recompute inverse
            for (int i = 0; i < N; i++) active[i] = new_active[i];
            for (int i = 0; i < N; i++) active_inv[active[i]] = (unsigned char)i;
        }
    }
}

// =============================================================================
// rune_histogram — per-candidate frequency analysis on GPU
// =============================================================================
//
// For each candidate (one CUDA block), compute the N-bin histogram of its
// decrypted output. Threads within the block cooperatively scan the candidate's
// rune array, atomic-add into a shared-memory histogram, then write the final
// bin counts back to global memory.
//
// Why block-per-candidate (not thread-per-candidate):
//   * A 1036-rune scan is too much serial work per thread for the thread-per-
//     candidate pattern used elsewhere in this file.
//   * Shared-memory histograms are an order of magnitude faster than global
//     atomicAdds for hot bins (e.g. high-frequency runes like the cipher's
//     equivalent of 'a' in Finnish plaintext).
//   * Per-block shared memory cost is tiny: N * sizeof(int) = 332 bytes for
//     N=83, well within any modern device's per-SM shared memory budget.
//
// Inputs:
//   decrypted     : [batch_size, ct_total_len] uint8 — output of gak_decrypt_batch
//   ct_total_len  : scalar — total decryption length (1036 for Noita)
//   batch_size    : scalar — number of candidates
//   N             : scalar — alphabet size (83 for Noita)
// Outputs:
//   histograms    : [batch_size, N] int32 — bin counts; row sums equal ct_total_len
//
// Launch params (set by host code):
//   grid  = (batch_size,)
//   block = (256,)
//   shared = N * sizeof(int) bytes
extern "C" __global__ void rune_histogram(
    const unsigned char* decrypted,    // [batch, ct_total_len]
    int ct_total_len,
    int batch_size,
    int N,
    int* histograms                     // [batch, N]
) {
    int cand = blockIdx.x;
    if (cand >= batch_size) return;

    extern __shared__ int hist[];       // [N]

    // 1. Zero the shared-memory histogram
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        hist[i] = 0;
    }
    __syncthreads();

    // 2. Cooperative scan: each thread covers a strided slice of the candidate
    const unsigned char* my_dec = decrypted + (size_t)cand * (size_t)ct_total_len;
    for (int pos = threadIdx.x; pos < ct_total_len; pos += blockDim.x) {
        unsigned char r = my_dec[pos];
        if (r < N) atomicAdd(&hist[r], 1);
    }
    __syncthreads();

    // 3. Write histogram back to global memory
    int* my_hist = histograms + (size_t)cand * (size_t)N;
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        my_hist[i] = hist[i];
    }
}

// =============================================================================
// chi2_pre_filter — language-likeness rejection filter
// =============================================================================
//
// For each candidate, compute the squared-L2 distance between its sorted
// rune-frequency distribution and each language's expected sorted
// distribution. Emit (min_chi2, best_lang_idx) per candidate.
//
// Math (per candidate, per language ℓ):
//   f_c[i]      = histogram[i] / ct_total_len           (frequencies)
//   sorted_f_c  = sort descending(f_c)                  (shape only — no identity)
//   chi2_ℓ      = Σᵢ (sorted_f_c[i] - expected_sorted_ℓ[i])²
//   min_chi2    = min over ℓ
//
// NOTE: "chi2" is a misnomer here — this is squared L2 distance, not the
// statistical chi-squared (which would divide by expected[i] and have
// div-by-zero issues at the distribution tail). Using L2 because it's
// monotonically equivalent for ranking purposes and free of the singularity.
//
// The "expected_sorted" distribution for each language is precomputed on
// CPU via eyestat_scoring.compute_expected_sorted_distribution() and
// uploaded to GPU once at startup.
//
// Sorting strategy: parallel rank-based sort. Each thread (tid < N) handles
// one bin position. It counts how many OTHER bins have higher frequency
// (with tie-breaking by index) — that count IS its rank in the descending
// sort. Write to sorted_freq[rank]. O(N²) work / O(1) wall-clock per thread
// since all N threads run concurrently. For N=83 this is ~83 ops per
// thread, microseconds total.
//
// Inputs:
//   histograms      : [batch_size, N]               int32 from rune_histogram
//   lang_dists      : [num_langs, N]                float32 sorted desc expected
//   batch_size      : scalar
//   N               : alphabet size (83 for Noita)
//   num_langs       : 1, 2, or 3 typically
//   ct_total_len    : scalar — normalization divisor (1036 for Noita)
//
// Outputs:
//   min_chi2_out    : [batch_size]                  float32 — the rejection statistic
//   best_lang_out   : [batch_size]                  int32   — argmin lang index
//
// Launch params:
//   grid  = (batch_size,)
//   block = (max(N, 32),)                            we use up to N threads
//   shared = (N + num_langs) * sizeof(float) bytes
extern "C" __global__ void chi2_pre_filter(
    const int* histograms,           // [batch, N]
    const float* lang_dists,         // [num_langs, N]
    int batch_size,
    int N,
    int num_langs,
    int ct_total_len,
    float* min_chi2_out,             // [batch]
    int* best_lang_out               // [batch]
) {
    int cand = blockIdx.x;
    if (cand >= batch_size) return;
    int tid = threadIdx.x;

    extern __shared__ float chi2_shmem[];
    // Layout: sorted_freq[0..N-1], then chi2_per_lang[0..num_langs-1]
    float* sorted_freq    = chi2_shmem;
    float* chi2_per_lang  = chi2_shmem + N;

    // STEP 1: Parallel rank-based sort.
    // Each thread tid < N computes its own rank by counting other bins
    // with strictly larger values (and lower-index ties to break the tie
    // deterministically). Then writes its frequency to sorted_freq[rank].
    if (tid < N) {
        int my_count = histograms[cand * N + tid];
        int rank = 0;
        for (int i = 0; i < N; i++) {
            int other_count = histograms[cand * N + i];
            if (other_count > my_count) {
                rank++;
            } else if (other_count == my_count && i < tid) {
                rank++;
            }
        }
        float my_freq = (float)my_count / (float)ct_total_len;
        sorted_freq[rank] = my_freq;
    }
    __syncthreads();

    // STEP 2: For each language, compute chi2 = Σ (sorted_f - expected)²
    // Parallel reduction across N entries per language.
    for (int lang = 0; lang < num_langs; lang++) {
        if (tid == 0) chi2_per_lang[lang] = 0.0f;
        __syncthreads();

        float partial = 0.0f;
        for (int i = tid; i < N; i += blockDim.x) {
            float diff = sorted_freq[i] - lang_dists[lang * N + i];
            partial += diff * diff;
        }
        atomicAdd(&chi2_per_lang[lang], partial);
        __syncthreads();
    }

    // STEP 3: argmin across languages — thread 0 only.
    if (tid == 0) {
        float min_v = chi2_per_lang[0];
        int best = 0;
        for (int l = 1; l < num_langs; l++) {
            if (chi2_per_lang[l] < min_v) {
                min_v = chi2_per_lang[l];
                best = l;
            }
        }
        min_chi2_out[cand] = min_v;
        best_lang_out[cand] = best;
    }
}
"""


# =============================================================================
# Compilation helper
# =============================================================================

def compile_module(cuda_source: str = CUDA_SOURCE) -> Tuple["cp.RawModule", str]:
    """Compile the RawModule targeting the current device's compute capability.
    Returns (module, arch_used)."""
    _require_cupy()
    cap = cp.cuda.Device().compute_capability  # e.g. "120"

    # CuPy 13.4+ auto-detects the device arch and passes -arch to NVRTC itself.
    # Passing --gpu-architecture explicitly causes:
    #   "nvrtc: error: --gpu-architecture (-arch) defined more than once"
    # Try the no-options (auto) path first; fall back to explicit for older CuPy
    # or unusual devices where auto-detect picks the wrong arch.
    try:
        module = cp.RawModule(code=cuda_source)
        _ = module.get_function("gak_generate_keys")
        _ = module.get_function("gak_decrypt_batch")
        return module, f"compute_{cap}"
    except Exception:
        pass  # Fall back to explicit-arch path below

    candidates = [f"compute_{cap}", "compute_90", "compute_86"]
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    last_err = None
    for arch in candidates:
        try:
            options = (f"--gpu-architecture={arch}",)
            module = cp.RawModule(code=cuda_source, options=options)
            # Force compilation by resolving both kernels
            _ = module.get_function("gak_generate_keys")
            _ = module.get_function("gak_decrypt_batch")
            return module, arch
        except Exception as e:
            last_err = e
            continue
    raise last_err if last_err else RuntimeError("no arch compiled")


# =============================================================================
# GpuBatchRunner — main entry point
# =============================================================================

class GpuBatchRunner:
    """Batched GPU execution of GAK-family decryption for the bf project.

    Lifecycle:
        runner = GpuBatchRunner(mode_code=0, N=83, ciphertexts=[...], batch_size=65536)
        for seed_start in range(0, big_number, 65536):
            decrypted = runner.run_batch(seed_start)
            # Hand off `decrypted` (numpy array) to CPU scoring pool

    The GpuBatchRunner reuses GPU buffers across calls — only seeds vary per
    batch. Per-batch memory cost: ~512 MB at batch_size=65536 for N=83 and
    1036-character total ciphertext.
    """

    # Schrage constants for each supported Park-Miller variant.
    # The kernel takes (A, Q, R) per-launch — no recompilation needed.
    PRNG_VARIANTS = {
        "park_miller_v0": (16807, 127773, 2836),    # Park & Miller, 1988
        "park_miller_v1": (48271,  44488, 3399),    # Park, Miller & Stockmeyer, 1993
    }

    def __init__(self, mode_code: int, N: int,
                 ciphertexts: List[List[int]],
                 batch_size: int = 65536,
                 threads_per_block: int = 256,
                 prng_version: str = "park_miller_v0"):
        _require_cupy()
        if mode_code not in MODE_NAME:
            raise ValueError(f"Unknown mode_code {mode_code}; valid: {sorted(MODE_NAME)}")
        if prng_version not in self.PRNG_VARIANTS:
            raise ValueError(
                f"Unknown prng_version {prng_version!r}; "
                f"valid: {sorted(self.PRNG_VARIANTS)}")
        if N > 256:
            raise ValueError(f"N={N} exceeds uint8 perm capacity (256). "
                             "Increase the active[]/active_inv[] kernel array sizes.")
        if N < 2:
            raise ValueError(f"N={N} must be >= 2")
        if not ciphertexts:
            raise ValueError("ciphertexts must be a non-empty list of lists")
        if any(len(ct) == 0 for ct in ciphertexts):
            raise ValueError("each ciphertext message must be non-empty")

        # Stash PRNG constants — passed to gak_generate_keys on every launch
        self.prng_version = prng_version
        self._prng_A, self._prng_Q, self._prng_R = self.PRNG_VARIANTS[prng_version]
        if batch_size < 1:
            raise ValueError(f"batch_size={batch_size} must be >= 1")
        if threads_per_block < 1 or threads_per_block > 1024:
            raise ValueError(f"threads_per_block={threads_per_block} out of range [1, 1024]")

        self.mode_code = mode_code
        self.N = N
        self.batch_size = batch_size
        self.threads_per_block = threads_per_block
        self.num_perms = N + 1
        self.ciphertexts = [list(ct) for ct in ciphertexts]
        self.num_msgs = len(ciphertexts)

        # Flatten ciphertexts + build offsets
        flat = []
        offsets = [0]
        for ct in self.ciphertexts:
            flat.extend(ct)
            offsets.append(len(flat))
        self.ct_total_len = offsets[-1]
        self._ct_host = np.array(flat, dtype=np.uint8)
        self._offsets_host = np.array(offsets, dtype=np.int32)

        # Validate ciphertext symbols are in [0, N)
        if self._ct_host.max() >= N:
            raise ValueError(f"ciphertext symbol {self._ct_host.max()} >= N={N}")

        # Compile
        self.module, self.arch_used = compile_module()
        self._kernel_keys    = self.module.get_function("gak_generate_keys")
        self._kernel_decrypt = self.module.get_function("gak_decrypt_batch")
        self._kernel_histogram = self.module.get_function("rune_histogram")
        self._kernel_chi2      = self.module.get_function("chi2_pre_filter")

        # Allocate persistent GPU buffers
        self._d_seeds = cp.zeros(batch_size, dtype=cp.uint32)
        self._d_perms = cp.zeros(
            (batch_size, self.num_perms, N), dtype=cp.uint8)
        self._d_ct = cp.asarray(self._ct_host)
        self._d_offsets = cp.asarray(self._offsets_host)
        self._d_dec = cp.zeros(
            (batch_size, self.ct_total_len), dtype=cp.uint8)

    def run_batch(self, seed_start: int) -> np.ndarray:
        """Generate decrypted texts for seeds [seed_start, seed_start + batch_size).

        Returns numpy ndarray of shape (batch_size, ct_total_len), dtype uint8.
        """
        # Fill seeds on host, copy to device
        seeds = np.arange(seed_start, seed_start + self.batch_size,
                          dtype=np.uint32)
        self._d_seeds.set(seeds)

        # Launch key-generation kernel
        blocks = (self.batch_size + self.threads_per_block - 1) // self.threads_per_block
        self._kernel_keys(
            (blocks,), (self.threads_per_block,),
            (self._d_seeds, self._d_perms,
             self.batch_size, self.N, self.num_perms,
             self._prng_A, self._prng_Q, self._prng_R))

        # Launch decryption kernel
        self._kernel_decrypt(
            (blocks,), (self.threads_per_block,),
            (self._d_perms, self._d_ct, self._d_offsets,
             self.num_msgs, self.ct_total_len,
             self._d_dec,
             self.batch_size, self.N, self.num_perms, self.mode_code))

        # Sync + retrieve result
        cp.cuda.Stream.null.synchronize()
        return cp.asnumpy(self._d_dec)

    def run_batch_seeds(self, seeds: np.ndarray) -> np.ndarray:
        """Same as run_batch but with caller-specified seeds (for validation).
        seeds must have shape (batch_size,) dtype uint32."""
        if seeds.shape != (self.batch_size,):
            raise ValueError(f"seeds must be ({self.batch_size},), got {seeds.shape}")
        self._d_seeds.set(seeds.astype(np.uint32))
        blocks = (self.batch_size + self.threads_per_block - 1) // self.threads_per_block
        self._kernel_keys(
            (blocks,), (self.threads_per_block,),
            (self._d_seeds, self._d_perms,
             self.batch_size, self.N, self.num_perms,
             self._prng_A, self._prng_Q, self._prng_R))
        self._kernel_decrypt(
            (blocks,), (self.threads_per_block,),
            (self._d_perms, self._d_ct, self._d_offsets,
             self.num_msgs, self.ct_total_len,
             self._d_dec,
             self.batch_size, self.N, self.num_perms, self.mode_code))
        cp.cuda.Stream.null.synchronize()
        return cp.asnumpy(self._d_dec)

    def compute_histograms(self, return_numpy: bool = True):
        """Compute per-candidate rune-frequency histograms on the GPU.

        Reads from the runner's internal `_d_dec` buffer, which is populated by
        the most recent call to `run_batch()` / `run_batch_seeds()`. So the
        typical use is:

            runner.run_batch(seed_start)
            hist = runner.compute_histograms()        # shape (batch_size, N)

        Each row sums to ct_total_len (1036 for Noita). Use the histogram for:
          * Frequency-shape analysis (chi-squared vs language profile)
          * Approximate rank-order rune→letter mapping (cheaper than Hungarian)
          * Pre-filtering candidates before expensive CPU scoring

        Args:
            return_numpy: if True (default), copy the result to host and return
                          np.ndarray. If False, return the cupy ndarray for
                          subsequent on-device work (avoids host round-trip).

        Returns:
            (batch_size, N) int32 array of bin counts.
        """
        _require_cupy()
        histograms = cp.zeros((self.batch_size, self.N), dtype=cp.int32)
        threads = 256
        # One block per candidate; shared-memory histogram of N int32 bins
        self._kernel_histogram(
            (self.batch_size,), (threads,),
            (self._d_dec, self.ct_total_len, self.batch_size, self.N, histograms),
            shared_mem=self.N * 4
        )
        if return_numpy:
            cp.cuda.Stream.null.synchronize()
            return cp.asnumpy(histograms)
        return histograms

    def compute_chi2(self, histograms_gpu, lang_dists_gpu,
                     return_numpy: bool = True):
        """Compute per-candidate chi² (squared-L2) language-shape distances.

        Takes histograms (output of compute_histograms with return_numpy=False)
        and a (num_langs, N) float32 array of precomputed sorted expected
        distributions per language. Returns (min_chi2, best_lang_idx) — the
        minimum chi² across languages and which language achieved that minimum.

        See eyestat_scoring.compute_expected_sorted_distribution() for how
        the expected distributions are precomputed on CPU and uploaded.

        Args:
            histograms_gpu: cupy int32 array of shape (batch_size, N), the
                            histograms from compute_histograms(return_numpy=False).
            lang_dists_gpu: cupy float32 array of shape (num_langs, N), the
                            sorted-descending expected per-rune frequencies for
                            each candidate language.
            return_numpy: True → copy results to host; False → keep on GPU
                          (useful when chaining to further on-device filtering).

        Returns:
            (min_chi2, best_lang_idx) — both shape (batch_size,)
            min_chi2: float32 — squared-L2 distance to closest language profile
            best_lang_idx: int32 — index into lang_dists_gpu of that closest lang
        """
        _require_cupy()
        num_langs = int(lang_dists_gpu.shape[0])
        if num_langs <= 0:
            raise ValueError(
                f"lang_dists_gpu must have at least one language; "
                f"got shape {lang_dists_gpu.shape}")
        if lang_dists_gpu.shape != (num_langs, self.N):
            raise ValueError(
                f"lang_dists_gpu shape {lang_dists_gpu.shape} != "
                f"({num_langs}, {self.N})")
        if histograms_gpu.shape != (self.batch_size, self.N):
            raise ValueError(
                f"histograms_gpu shape {histograms_gpu.shape} != "
                f"({self.batch_size}, {self.N})")
        if lang_dists_gpu.dtype != cp.float32:
            raise ValueError(
                f"lang_dists_gpu dtype must be float32, got {lang_dists_gpu.dtype}")
        if histograms_gpu.dtype != cp.int32:
            raise ValueError(
                f"histograms_gpu dtype must be int32, got {histograms_gpu.dtype}")

        min_chi2     = cp.zeros(self.batch_size, dtype=cp.float32)
        best_lang    = cp.zeros(self.batch_size, dtype=cp.int32)

        # Need at least N threads for the parallel rank-based sort. Round up
        # to the next multiple of 32 (the CUDA warp size) so we don't end up
        # with a partially-active final warp — small performance win, and
        # makes the chi² reduction loop cleaner since all warps are aligned.
        threads = ((self.N + 31) // 32) * 32   # for N=83 → 96
        # Shared mem: sorted_freq[N] + chi2_per_lang[num_langs] floats
        shared_mem_bytes = (self.N + num_langs) * 4

        self._kernel_chi2(
            (self.batch_size,), (threads,),
            (histograms_gpu, lang_dists_gpu,
             self.batch_size, self.N, num_langs, self.ct_total_len,
             min_chi2, best_lang),
            shared_mem=shared_mem_bytes
        )
        if return_numpy:
            cp.cuda.Stream.null.synchronize()
            return cp.asnumpy(min_chi2), cp.asnumpy(best_lang)
        return min_chi2, best_lang

    def validate_against_cpu(self, n_test: int = 100,
                              seed_offset: int = 0,
                              verbose: bool = True) -> bool:
        """Run n_test seeds on both GPU and CPU, byte-compare decrypted output.
        Returns True if all match, False otherwise."""
        if n_test > self.batch_size:
            raise ValueError(f"n_test={n_test} > batch_size={self.batch_size}")

        # Generate a mix of seeds including edge cases:
        # - 0 and M=2147483647 exercise the seed rescue path (both rescue to 1)
        # - 1 is the smallest valid seed
        # - M-1=2147483646 is the largest valid seed
        # - 16807 is the Park-Miller multiplier A (output of seed=1)
        rng = np.random.default_rng(seed_offset + 42)
        edge_seeds = np.array([0, 1, 2, 16807, 12345,
                                2147483646, 2147483647], dtype=np.uint32)
        random_seeds = rng.integers(
            1, 2_147_483_646,
            size=max(0, n_test - len(edge_seeds)), dtype=np.uint32)
        seeds = np.concatenate([edge_seeds, random_seeds])[:n_test]

        # Pad to batch_size (extra entries get random seeds; we'll only check first n_test)
        if len(seeds) < self.batch_size:
            pad = rng.integers(
                1, 2_147_483_646,
                size=self.batch_size - len(seeds), dtype=np.uint32)
            full_seeds = np.concatenate([seeds, pad])
        else:
            full_seeds = seeds

        gpu_dec = self.run_batch_seeds(full_seeds)

        # CPU reference for first n_test
        # Pick the CPU PRNG class matching this runner's GPU configuration so
        # validate_against_cpu actually validates the SAME hypothesis. Mismatch
        # here would compare V0 GPU output against V1 CPU reference and produce
        # spurious failures.
        cpu_prng_cls = {
            "park_miller_v0": ParkMillerV0Rng,
            "park_miller_v1": ParkMillerV1Rng,
        }[self.prng_version]

        mismatches = []
        for i in range(n_test):
            seed = int(seeds[i])
            sigma = _gen_keys_gak_xgak_cpu(cpu_prng_cls, seed, self.N)
            # Concatenate all decryptions for this seed
            cpu_dec_full = np.empty(self.ct_total_len, dtype=np.uint8)
            for m, ct in enumerate(self.ciphertexts):
                pt = K.gak_decrypt(ct, sigma, self.N, self.mode_code)
                start = self._offsets_host[m]
                end = self._offsets_host[m + 1]
                cpu_dec_full[start:end] = np.array(pt, dtype=np.uint8)

            if not np.array_equal(cpu_dec_full, gpu_dec[i]):
                # Find first divergence
                diff = np.where(cpu_dec_full != gpu_dec[i])[0]
                first = int(diff[0])
                # Which message?
                msg_idx = 0
                while msg_idx + 1 < len(self._offsets_host) \
                        and self._offsets_host[msg_idx + 1] <= first:
                    msg_idx += 1
                pos_in_msg = first - int(self._offsets_host[msg_idx])
                mismatches.append({
                    "test_idx": i,
                    "seed": seed,
                    "first_diff_pos": first,
                    "msg_idx": msg_idx,
                    "pos_in_msg": pos_in_msg,
                    "gpu_value": int(gpu_dec[i, first]),
                    "cpu_value": int(cpu_dec_full[first]),
                })
                if not verbose or len(mismatches) >= 3:
                    break

        if not mismatches:
            if verbose:
                print(f"  [PASS] validate_against_cpu: {n_test}/{n_test} match "
                      f"(mode={MODE_NAME[self.mode_code]}, "
                      f"total bytes compared = {n_test * self.ct_total_len:,})")
            return True
        else:
            if verbose:
                print(f"  [FAIL] validate_against_cpu: {len(mismatches)} mismatch(es)")
                for m in mismatches:
                    print(f"        seed={m['seed']:>10d}  msg={m['msg_idx']}  "
                          f"pos={m['pos_in_msg']:>4d}  "
                          f"gpu={m['gpu_value']:>3d}  cpu={m['cpu_value']:>3d}")
            return False


# =============================================================================
# Standalone validation + benchmark
# =============================================================================

def _load_default_data():
    """Load noita_eye_data.json from script dir."""
    import json
    data_path = SCRIPT_DIR / "noita_eye_data.json"
    if not data_path.exists():
        raise FileNotFoundError(f"{data_path} not found")
    with open(data_path) as f:
        data = json.load(f)
    return data["ciphertexts"], int(data["deck_size"])


def benchmark(runner: GpuBatchRunner, iterations: int = 20) -> dict:
    """Time a series of batches; return throughput stats."""
    # Warm-up
    runner.run_batch(0)
    cp.cuda.Stream.null.synchronize()

    t0 = time.time()
    for i in range(iterations):
        runner.run_batch(seed_start=i * runner.batch_size + 1)
    cp.cuda.Stream.null.synchronize()
    dt = time.time() - t0

    total_keys = iterations * runner.batch_size
    return {
        "iterations": iterations,
        "batch_size": runner.batch_size,
        "total_keys": total_keys,
        "elapsed_s": dt,
        "keys_per_sec": total_keys / dt,
        "ms_per_batch": dt / iterations * 1000,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", default="ctak_right",
                   choices=list(MODE_CODE.keys()),
                   help="GAK mode to use (default: ctak_right)")
    p.add_argument("--batch-size", type=int, default=65536,
                   help="Seeds per GPU batch (default: 65536)")
    p.add_argument("--n-test", type=int, default=200,
                   help="Seeds to byte-validate against CPU (default: 200)")
    p.add_argument("--bench-iters", type=int, default=20,
                   help="Batches to time in benchmark (default: 20)")
    p.add_argument("--skip-benchmark", action="store_true")
    args = p.parse_args()

    # --help and argparse failures have already exited above; only now do we
    # need CuPy to actually run the benchmark.
    _require_cupy()

    print()
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║  eyestat_gpu.py — STANDALONE VALIDATION + BENCHMARK                    ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")

    # Device info
    dev = cp.cuda.Device()
    name = cp.cuda.runtime.getDeviceProperties(0)['name'].decode()
    free, total = cp.cuda.runtime.memGetInfo()
    print(f"\n[Device]  {name}  sm_{dev.compute_capability}  "
          f"{free // (1024**2):,} / {total // (1024**2):,} MB free")
    print(f"[CuPy]    version {cp.__version__}")

    # Load data
    print(f"\n[Data]    Loading noita_eye_data.json...")
    ciphertexts, N = _load_default_data()
    total_ct = sum(len(c) for c in ciphertexts)
    print(f"          {len(ciphertexts)} messages, N={N}, {total_ct} total symbols")

    # Construct runner
    print(f"\n[Init]    mode={args.mode} ({MODE_CODE[args.mode]}), "
          f"batch_size={args.batch_size}")
    runner = GpuBatchRunner(
        mode_code=MODE_CODE[args.mode],
        N=N,
        ciphertexts=ciphertexts,
        batch_size=args.batch_size,
    )
    print(f"          compiled kernels target = {runner.arch_used}")
    perm_bytes = args.batch_size * runner.num_perms * N
    dec_bytes  = args.batch_size * runner.ct_total_len
    print(f"          GPU memory: perms = {perm_bytes / 1024**2:.0f} MB, "
          f"decrypted = {dec_bytes / 1024**2:.0f} MB")

    # ----- Validation: per-mode -----
    print(f"\n[Validate] Cross-validating {args.n_test} seeds vs CPU "
          f"(mode={args.mode})...")
    if not runner.validate_against_cpu(n_test=args.n_test):
        print("\n  Validation FAILED. Send the [FAIL] line above.")
        return 1

    # ----- Validation: all modes (smaller sample) -----
    print(f"\n[Validate] Spot-checking all 8 GAK modes (20 seeds each)...")
    n_spot = 20
    all_ok = True
    for mode_name, mode_code in MODE_CODE.items():
        if mode_name == args.mode:
            continue  # already validated above with larger sample
        try:
            r2 = GpuBatchRunner(
                mode_code=mode_code, N=N,
                ciphertexts=ciphertexts,
                batch_size=max(n_spot, 256))  # min batch
            if r2.validate_against_cpu(n_test=n_spot, verbose=False):
                print(f"  [PASS] {mode_name:<18s}  ({n_spot} seeds match)")
            else:
                # Re-run verbose to surface the diff
                print(f"  [FAIL] {mode_name:<18s}")
                r2.validate_against_cpu(n_test=n_spot, verbose=True)
                all_ok = False
            del r2
        except Exception as e:
            print(f"  [FAIL] {mode_name}: {type(e).__name__}: {e}")
            all_ok = False
    if not all_ok:
        print("\n  At least one mode failed cross-validation.")
        return 1

    # ----- Benchmark -----
    if not args.skip_benchmark:
        print(f"\n[Benchmark] {args.bench_iters} batches × {args.batch_size} seeds, "
              f"mode={args.mode}...")
        stats = benchmark(runner, iterations=args.bench_iters)
        print(f"  Elapsed:        {stats['elapsed_s']:.2f} s for "
              f"{stats['total_keys']:,} keys")
        print(f"  Throughput:     {stats['keys_per_sec']:>15,.0f} keys/sec "
              f"(GPU-only, no CPU scoring)")
        print(f"  Latency:        {stats['ms_per_batch']:.2f} ms per batch of "
              f"{stats['batch_size']:,}")
        # Park-Miller full sweep projection
        pm_sweep_s = 2_147_483_646 / stats['keys_per_sec']
        print(f"\n  Park-Miller full sweep (2.15B seeds), "
              f"GPU-only: {pm_sweep_s/3600:.1f} hours")
        print(f"  Real end-to-end will be slower — CPU scoring (scipy Hungarian +")
        print(f"  dict matching) becomes the bottleneck. Expect ~2-5x slowdown")
        print(f"  unless CPU scoring is parallelized across 32+ threads.")

    print(f"\n[Summary] ALL VALIDATIONS PASSED. Ready for eyestat_runner.py integration.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
