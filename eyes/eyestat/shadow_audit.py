#!/home/h3x/.venvs/eyestat/bin/python3
"""Shadow simulation of eyestat_gpu.py's CUDA kernels — runs on CPU for audit."""
import json, sys, random
from pathlib import Path

# Look for eyestat_prngs / eyestat_kernels / data in the same dir as this script
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from eyestat_prngs import ParkMillerRng, ParkMillerV0Rng, ParkMillerV1Rng
import eyestat_kernels as K

M_CONST = 2147483647

# Schrage's algorithm constants for each Park-Miller variant. Mirror of
# eyestat_prngs.ParkMillerV{0,1}Rng (A, Q, R). Used by validate() to test
# both variants against their respective GPU kernel invocations.
PRNG_VARIANTS = {
    "park_miller_v0": (16807, 127773, 2836),    # Park & Miller, 1988
    "park_miller_v1": (48271,  44488, 3399),    # Park, Miller & Stockmeyer, 1993
}


def shadow_park_miller_next(s, A=16807, Q=127773, R=2836):
    """Mirror of CUDA park_miller_next() under the parameterized (A, Q, R).

    Defaults to V0 for backward compatibility with older shadow callers.
    Pass V1's (48271, 44488, 3399) to exercise the revised multiplier.
    """
    hi = s // Q                  # CUDA: (int)s / Q (truncating div)
    lo = s - hi * Q              # CUDA: (int)s - hi * Q
    t = A * lo - R * hi
    if t < 0:
        t += M_CONST
    return t & 0xFFFFFFFF


def shadow_gak_generate_keys(seed, N, num_perms, prng_version="park_miller_v0"):
    """Mirror of CUDA gak_generate_keys kernel for one seed.

    Accepts a prng_version string selecting the Schrage constants used to
    advance the PRNG. Falls back to V0 when not specified so legacy callers
    behave identically to the original implementation.
    """
    if prng_version not in PRNG_VARIANTS:
        raise ValueError(f"Unknown prng_version {prng_version!r}; "
                         f"valid: {sorted(PRNG_VARIANTS)}")
    A, Q, R = PRNG_VARIANTS[prng_version]

    s = seed & 0x7FFFFFFF
    if s == 0 or s == M_CONST:
        s = 1

    perms = []
    for _k in range(num_perms):
        perm = list(range(N))
        for i in range(N - 1, 0, -1):
            bound = i + 1
            max_v = M_CONST - (M_CONST % bound)
            while True:
                s = shadow_park_miller_next(s, A, Q, R)
                v = s
                if v < max_v:
                    break
            j = v % bound
            perm[i], perm[j] = perm[j], perm[i]
        perms.append(perm)
    return perms


def shadow_gak_decrypt(seed, ciphertext, N, mode_code, num_perms,
                       prng_version="park_miller_v0"):
    """Mirror of CUDA gak_decrypt_batch kernel for one seed × one message."""
    perms = shadow_gak_generate_keys(seed, N, num_perms, prng_version)

    mode_right = mode_code in (0, 2, 4, 6)
    mode_key_type = mode_code // 2

    # Initialize active = sigma[0]
    active = list(perms[0])
    active_inv = [0] * N
    for i, v in enumerate(active):
        active_inv[v] = i

    decrypted = []
    for c in ciphertext:
        p = active_inv[c]
        decrypted.append(p)

        if mode_key_type == 0:
            k = c
        elif mode_key_type == 1:
            k = p
        elif mode_key_type == 2:
            k = (p + c) % N
        else:
            k = (c - p + N) % N

        sigma_k = perms[k]

        if mode_right:
            new_active = [active[sigma_k[i]] for i in range(N)]
        else:
            new_active = [sigma_k[active[i]] for i in range(N)]

        active = new_active
        for i, v in enumerate(active):
            active_inv[v] = i

    return decrypted


def shadow_rune_histogram(decrypted, N=83):
    """Mirror of the CUDA rune_histogram kernel in pure Python / numpy.

    For each candidate, count occurrences of each rune value in [0, N).
    Values >= N are silently dropped (matches the GPU `if (r < N)` guard).

    Args:
        decrypted: shape (batch_size, ct_total_len), dtype uint8.
                   Accepts list-of-lists or numpy array.
        N: alphabet size (default 83 for Noita).

    Returns:
        numpy int32 array of shape (batch_size, N) where row i is the rune
        histogram of candidate i. Each row sums to (number of values < N in
        that candidate's decryption).
    """
    import numpy as np

    if not isinstance(decrypted, np.ndarray):
        decrypted = np.asarray(decrypted, dtype=np.uint8)
    if decrypted.ndim == 1:
        decrypted = decrypted[np.newaxis, :]

    batch_size = decrypted.shape[0]
    histograms = np.zeros((batch_size, N), dtype=np.int32)
    for i in range(batch_size):
        # np.bincount is the canonical CPU equivalent of a histogram kernel
        counts = np.bincount(decrypted[i], minlength=N)
        # Drop any out-of-range bins (matches GPU guard)
        histograms[i, :] = counts[:N]
    return histograms


def shadow_chi2_pre_filter(histograms, lang_dists, ct_total_len):
    """Mirror of the CUDA chi2_pre_filter kernel in pure NumPy.

    For each candidate, computes the squared-L2 distance between its sorted
    rune-frequency distribution and each language's expected sorted
    distribution; emits (min_chi2, best_lang_idx) per candidate.

    See math reference in eyestat_gpu.py's chi2_pre_filter CUDA kernel and
    in eyestat_compute_audit.py Phase 8.

    Args:
        histograms: shape (batch_size, N), int32 — rune histograms
        lang_dists: shape (num_langs, N), float32 — sorted desc expected
                    distributions per language
        ct_total_len: int — total decryption length (sum of each histogram row)

    Returns:
        min_chi2: shape (batch_size,) float32
        best_lang_idx: shape (batch_size,) int32
    """
    import numpy as np

    histograms = np.asarray(histograms, dtype=np.int32)
    lang_dists = np.asarray(lang_dists, dtype=np.float32)
    if histograms.ndim != 2:
        raise ValueError(f"histograms must be 2D, got {histograms.shape}")
    if lang_dists.ndim != 2:
        raise ValueError(f"lang_dists must be 2D, got {lang_dists.shape}")
    batch_size, N = histograms.shape
    num_langs, N2 = lang_dists.shape
    if N != N2:
        raise ValueError(f"shape mismatch: histograms N={N} vs lang_dists N={N2}")

    # Normalize to frequencies, sort descending per candidate
    freqs = histograms.astype(np.float32) / float(ct_total_len)
    sorted_freqs = -np.sort(-freqs, axis=1)   # descending = sort ascending of negated

    # For each language, compute Σ (sorted_freqs - lang_dist)² per candidate
    # diff shape: (batch_size, num_langs, N)
    diff = sorted_freqs[:, np.newaxis, :] - lang_dists[np.newaxis, :, :]
    chi2_per_lang = (diff * diff).sum(axis=2)   # shape (batch_size, num_langs)

    min_chi2     = chi2_per_lang.min(axis=1).astype(np.float32)
    best_lang_idx = chi2_per_lang.argmin(axis=1).astype(np.int32)
    return min_chi2, best_lang_idx


# =========================================================================
# Validation: shadow simulator vs eyestat_kernels.gak_decrypt on real data
# =========================================================================

def validate():
    # Load real Noita data
    with open(SCRIPT_DIR / "noita_eye_data.json") as f:
        data = json.load(f)
    ciphertexts = data["ciphertexts"]
    N = int(data["deck_size"])
    num_perms = N + 1

    MODES = {
        "ctak_right": 0, "ctak_left": 1,
        "ptak_right": 2, "ptak_left": 3,
        "xgak_sum_right": 4, "xgak_sum_left": 5,
        "xgak_diff_right": 6, "xgak_diff_left": 7,
    }

    # Test seeds including edge cases
    test_seeds = [
        0,            # rescue
        1,            # smallest valid
        2,            # small
        12345,        # arbitrary
        16807,        # park_miller A
        2147483646,   # M - 1
        2147483647,   # M (rescue)
    ]
    # Plus random
    rng = random.Random(42)
    test_seeds.extend([rng.randint(1, 2_147_483_646) for _ in range(20)])

    all_pass = True
    # Two PRNG variants treated as independent hypotheses — each gets its own
    # full validation pass. Failure in one doesn't short-circuit the other.
    for prng_label, prng_cls in [
        ("park_miller_v0", ParkMillerV0Rng),
        ("park_miller_v1", ParkMillerV1Rng),
    ]:
        print(f"\n--- PRNG: {prng_label} ---")
        for mode_name, mode_code in MODES.items():
            mode_pass = True
            for seed in test_seeds:
                # Shadow GPU simulation for all 9 messages
                shadow_dec = []
                for ct in ciphertexts:
                    shadow_dec.extend(
                        shadow_gak_decrypt(seed, ct, N, mode_code, num_perms,
                                           prng_version=prng_label))

                # CPU reference: 84 perms with shared PRNG state, using the
                # explicit V0 / V1 class corresponding to this validation pass
                cpu_rng = prng_cls(seed)
                sigma = [cpu_rng.shuffled_perm(N) for _ in range(N + 1)]
                cpu_dec = []
                for ct in ciphertexts:
                    cpu_dec.extend(K.gak_decrypt(ct, sigma, N, mode_code))

                if shadow_dec != cpu_dec:
                    # Find first divergence
                    first_diff = next(
                        (i for i, (a, b) in enumerate(zip(shadow_dec, cpu_dec))
                         if a != b), -1)
                    print(f"  FAIL  prng={prng_label}  mode={mode_name:18s}  "
                          f"seed={seed:>11d}  first_diff_pos={first_diff}  "
                          f"shadow={shadow_dec[first_diff] if first_diff >= 0 else 'len'}  "
                          f"cpu={cpu_dec[first_diff] if first_diff >= 0 else 'len'}")
                    all_pass = False
                    mode_pass = False

            print(f"  {'PASS' if mode_pass else 'FAIL'}  {mode_name:18s}  "
                  f"{len(test_seeds)} seeds × {sum(len(c) for c in ciphertexts)} bytes")

    # Phase B: shadow_rune_histogram vs np.bincount (the canonical reference).
    # This validates the CPU SHADOW; the GPU kernel itself is validated by
    # validate_histogram_gpu() below, which requires CuPy.
    import numpy as np
    print()
    print("Histogram shadow vs np.bincount (CPU↔CPU reference check):")
    rng_np = np.random.default_rng(42)
    for case_name, dec in [
        ("uniform random",      rng_np.integers(0, N, size=(50, 1036), dtype=np.uint8)),
        ("skewed (mostly 0-9)", rng_np.integers(0, 10, size=(50, 1036), dtype=np.uint8)),
        ("all same rune",       np.full((10, 1036), 42, dtype=np.uint8)),
        ("real ctak_right=12345",
            np.asarray([d for d in [shadow_gak_decrypt(12345, ct, N, 0, num_perms)
                                    for ct in ciphertexts]], dtype=object)),
    ]:
        # Handle the ragged real-decryption case
        if case_name.startswith("real"):
            flat = []
            for ct_dec in dec:
                flat.extend(ct_dec)
            arr = np.asarray([flat], dtype=np.uint8)
        else:
            arr = dec
        shadow_h = shadow_rune_histogram(arr, N=N)
        ref_h = np.zeros_like(shadow_h)
        for i in range(arr.shape[0]):
            ref_h[i, :] = np.bincount(arr[i], minlength=N)[:N]
        ok = np.array_equal(shadow_h, ref_h)
        # Sanity: row sums should equal row length
        sum_ok = all(shadow_h[i].sum() == arr[i].size for i in range(arr.shape[0]))
        marker = "PASS" if (ok and sum_ok) else "FAIL"
        print(f"  {marker}  histogram shadow  {case_name}")
        if not (ok and sum_ok):
            all_pass = False

    return all_pass


def validate_histogram_gpu(verbose: bool = True) -> bool:
    """End-to-end histogram validation: GPU kernel vs shadow vs np.bincount.

    Requires CuPy and a CUDA device. Runs a planted batch of synthetic
    decryptions through `GpuBatchRunner.compute_histograms()` and asserts the
    GPU output is bit-exact identical to the CPU shadow. Useful for catching
    GPU memory-bandwidth bugs, shared-memory race conditions, and ECC-related
    transient errors on long-running sweeps.

    Returns True if GPU == shadow == bincount on every test case.
    """
    try:
        import cupy as cp
        import numpy as np
    except ImportError:
        if verbose:
            print("  SKIP — CuPy not available; cannot validate the GPU kernel.")
            print("        shadow_rune_histogram is still validated above against np.bincount.")
        return True

    # Load real Noita data so we have a realistic ciphertext to decrypt against
    with open(SCRIPT_DIR / "noita_eye_data.json") as f:
        data = json.load(f)
    ciphertexts = data["ciphertexts"]
    N = int(data["deck_size"])

    # Import here to keep the rest of the file CuPy-free at module load time
    from eyestat_gpu import GpuBatchRunner

    batch_size = 256       # small enough to be fast, big enough to stress atomics

    # Run validation twice — once per PRNG variant. The histogram itself
    # doesn't depend on the multiplier, but exercising both variants confirms
    # the parameterized gak_generate_keys kernel produces consistent
    # decryptions in both modes, AND that those decryptions feed correctly
    # into the histogram kernel for either upstream PRNG choice.
    all_ok = True
    for prng_label in ("park_miller_v0", "park_miller_v1"):
        runner = GpuBatchRunner(
            mode_code=0, N=N, ciphertexts=ciphertexts,
            batch_size=batch_size, threads_per_block=256,
            prng_version=prng_label,
        )

        if verbose:
            print()
            print(f"GPU histogram kernel — prng={prng_label}, batch_size={batch_size}:")

        # Run a batch starting from seed=1
        decrypted = runner.run_batch(seed_start=1)
        gpu_hist  = runner.compute_histograms()
        shadow_h  = shadow_rune_histogram(decrypted, N=N)

        ok = np.array_equal(gpu_hist, shadow_h)
        if ok:
            ct_total_len = decrypted.shape[1]
            sums_ok = bool(np.all(gpu_hist.sum(axis=1) == ct_total_len))
            nonneg  = bool(np.all(gpu_hist >= 0))
            ok = sums_ok and nonneg

        if verbose:
            if ok:
                print(f"  PASS  bit-exact identical on {batch_size} candidates × {N} bins")
            else:
                n_diff_rows = int(np.sum(np.any(gpu_hist != shadow_h, axis=1)))
                print(f"  FAIL  {n_diff_rows}/{batch_size} candidates differ")
                for i in range(batch_size):
                    if not np.array_equal(gpu_hist[i], shadow_h[i]):
                        diffs = np.flatnonzero(gpu_hist[i] != shadow_h[i])[:5]
                        print(f"        candidate {i}: first diff bins {diffs.tolist()}")
                        print(f"          gpu   : {gpu_hist[i, diffs].tolist()}")
                        print(f"          shadow: {shadow_h[i, diffs].tolist()}")
                        break
        all_ok = all_ok and ok

    return all_ok


def validate_chi2_gpu(verbose: bool = True) -> bool:
    """End-to-end chi² pre-filter validation: GPU kernel vs shadow.

    Builds expected sorted distributions per language on CPU, uploads to GPU,
    runs a batch of real Noita decryptions through compute_chi2(), and
    compares against shadow_chi2_pre_filter run on the same histograms.

    Also performs three sanity checks on the chi² values themselves:
      1. Random rune output → high chi² (in the noise regime)
      2. Real-language-shaped output → low chi² (in the signal regime)
      3. Separation between the two regimes is large enough for a meaningful
         threshold to exist
    """
    try:
        import cupy as cp
        import numpy as np
    except ImportError:
        if verbose:
            print("  SKIP — CuPy not available; cannot validate chi² GPU kernel.")
            print("        shadow_chi2_pre_filter is still validated against its math.")
        return True

    with open(SCRIPT_DIR / "noita_eye_data.json") as f:
        data = json.load(f)
    ciphertexts = data["ciphertexts"]
    N = int(data["deck_size"])

    from eyestat_gpu import GpuBatchRunner
    from eyestat_scoring import compute_expected_sorted_distribution

    # Precompute the sorted expected distributions per language and upload to GPU
    langs = ["fi", "krl", "en"]
    expected_per_lang = np.stack([
        np.array(compute_expected_sorted_distribution(l, N), dtype=np.float32)
        for l in langs
    ])   # shape (3, N)
    lang_dists_gpu = cp.asarray(expected_per_lang)

    batch_size = 256
    runner = GpuBatchRunner(
        mode_code=0, N=N, ciphertexts=ciphertexts,
        batch_size=batch_size, threads_per_block=256,
        prng_version="park_miller_v0",
    )

    if verbose:
        print()
        print(f"GPU chi² pre-filter — batch_size={batch_size}, num_langs={len(langs)}:")

    # ---- Phase 1: bit-exact GPU vs shadow on real Noita decryptions ----
    runner.run_batch(seed_start=1)
    hist_gpu = runner.compute_histograms(return_numpy=False)
    hist_host = cp.asnumpy(hist_gpu)

    gpu_min, gpu_best = runner.compute_chi2(hist_gpu, lang_dists_gpu)
    shadow_min, shadow_best = shadow_chi2_pre_filter(
        hist_host, expected_per_lang, ct_total_len=runner.ct_total_len)

    # Floating-point chi² won't be bit-exact across implementations because
    # atomicAdd ordering varies between launches. Compare with a tight tol.
    chi2_close = np.allclose(gpu_min, shadow_min, rtol=1e-4, atol=1e-7)
    best_match = np.array_equal(gpu_best, shadow_best)
    if chi2_close and best_match:
        if verbose:
            print(f"  PASS  GPU chi² vs shadow on {batch_size} candidates "
                  f"(max delta = {float(np.max(np.abs(gpu_min - shadow_min))):.2e})")
    else:
        if verbose:
            print(f"  FAIL  GPU chi² disagrees with shadow")
            if not chi2_close:
                idx = int(np.argmax(np.abs(gpu_min - shadow_min)))
                print(f"        max delta at idx {idx}: "
                      f"gpu={gpu_min[idx]:.6f} shadow={shadow_min[idx]:.6f}")
            if not best_match:
                idx = int(np.argmax(gpu_best != shadow_best))
                print(f"        best_lang differs at idx {idx}: "
                      f"gpu={gpu_best[idx]} shadow={shadow_best[idx]}")
        return False

    # ---- Phase 2: chi² values themselves are in the expected regime ----
    # Real decryptions from random seeds should produce chi² in the noise
    # regime (mean ~0.003). We don't know which seed gives the plaintext,
    # but we can at least verify the values are in a sensible range.
    if verbose:
        print(f"  chi² stats over {batch_size} real-Noita decryptions "
              f"(seeds 1..{batch_size}):")
        print(f"    min={float(gpu_min.min()):.5f}  median="
              f"{float(np.median(gpu_min)):.5f}  max={float(gpu_min.max()):.5f}")

    # ---- Phase 3: synthetic regime separation ----
    # Confirm the filter actually separates "looks like language" from
    # "looks like noise" on synthetic inputs.
    np.random.seed(42)
    # Random histograms (uniform noise)
    random_hists = np.stack([
        np.bincount(np.random.randint(0, N, runner.ct_total_len), minlength=N)
        for _ in range(64)
    ]).astype(np.int32)
    # "Real Finnish-shaped" histograms (sampled from the expected distribution
    # under a random rune→letter permutation, simulating an unknown mapping)
    real_hists = []
    fi_probs = expected_per_lang[0] / expected_per_lang[0].sum()
    for _ in range(64):
        perm = np.random.permutation(N)
        p = fi_probs[perm]
        h = np.bincount(np.random.choice(N, runner.ct_total_len, p=p), minlength=N)
        real_hists.append(h)
    real_hists = np.stack(real_hists).astype(np.int32)

    random_min, _ = shadow_chi2_pre_filter(random_hists, expected_per_lang,
                                            ct_total_len=runner.ct_total_len)
    real_min, _   = shadow_chi2_pre_filter(real_hists,   expected_per_lang,
                                            ct_total_len=runner.ct_total_len)

    separation_ok = real_min.max() < random_min.min()
    if verbose:
        print(f"  Synthetic separation test (64 random + 64 real samples):")
        print(f"    random regime chi²:  min={random_min.min():.5f} "
              f"median={np.median(random_min):.5f}")
        print(f"    real   regime chi²:  max={real_min.max():.5f} "
              f"median={np.median(real_min):.5f}")
        if separation_ok:
            print(f"    PASS — clean separation, threshold somewhere in "
                  f"[{real_min.max():.5f}, {random_min.min():.5f}]")
        else:
            print(f"    FAIL — regimes overlap, no clean threshold exists")
    return separation_ok


if __name__ == "__main__":
    print("Shadow simulator (GPU kernel logic in Python) vs eyestat_kernels.gak_decrypt")
    print(f"Data: real Noita ciphertexts, all 8 GAK modes, edge-case + random seeds\n")
    ok = validate()
    # Phase C: real GPU vs shadow (no-op if CuPy isn't installed)
    print()
    print("=" * 70)
    print("GPU kernel validation (requires CuPy + CUDA device):")
    ok_hist = validate_histogram_gpu(verbose=True)
    ok_chi2 = validate_chi2_gpu(verbose=True)
    ok = ok and ok_hist and ok_chi2
    print(f"\n{'='*70}")
    print("ALL ALGORITHMS CORRECT" if ok else "ALGORITHM DISCREPANCY DETECTED")
    sys.exit(0 if ok else 1)
