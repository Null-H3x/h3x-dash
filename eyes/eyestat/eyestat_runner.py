#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_runner.py — brute-force orchestrator.

Runs every (cipher_mode × prng × seed-or-passphrase × language) combination
against the Noita ciphertext. Logs all attempts to a TSV; logs decryptions
that score ≥ threshold dictionary hits to a ranked results file.

USAGE
=====
    python3 eyestat_runner.py \
        --data noita_eye_data.json \
        --dict-fi  extra_words_fi.txt \
        --dict-krl extra_words_krl.txt \
        --dict-en  noita_wordlist.txt \
        --modes all --prngs all \
        --seed-start 0 --seed-end 65536 \
        --workers 8 \
        --output-dir results/ \
        --threshold 13

OUTPUTS
=======
    {output_dir}/bruteforce_params.tsv.gz   — every (mode, prng, seed) tried
    {output_dir}/bruteforce_results.txt     — decryptions with hits ≥ threshold,
                                              rank-ordered by total score

CHECKPOINTING
=============
Each worker writes its own shard files; on resume, completed shards are
detected and skipped. Use --resume to pick up from a partial run.

LIVE PROGRESS MONITORING
========================
By default, a background monitor thread prints a status line every 5 seconds
showing elapsed time, keys tried, throughput (smoothed over a 30s rolling
window), error count, shards complete, ETA, and the top-N highest-hit keys
seen so far. On a TTY the panel updates in place via ANSI cursor controls;
in log files / CI, each update appends a fresh block.

Flags:
    --progress-interval N    Seconds between updates (default 5, 0 = disable)
    --progress-top-n K       How many top hits to show in panel (default 5, 0 = none)
    --no-color               Disable ANSI styling
"""

from __future__ import annotations

import argparse
import gzip
import itertools
import json
import multiprocessing as mp
import os
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import eyestat_kernels as K
import eyestat_prngs as P
import eyestat_scoring as S


# ---------------------------------------------------------------------------
# Cipher-mode configs
# ---------------------------------------------------------------------------

# Mode families: how each mode's key is generated and how the cipher operates
MODE_FAMILY_GAK_XGAK = "gak_xgak"      # PRNG → 84 perms in S_N
MODE_FAMILY_KAK      = "kak"           # PRNG → 84 perms + advance perm + key0
MODE_FAMILY_CFB      = "cfb"           # PRNG → single perm + IV
MODE_FAMILY_OFB      = "ofb"           # PRNG → single perm + IV
MODE_FAMILY_VIGENERE = "vigenere"      # PRNG → key sequence
MODE_FAMILY_CARD     = "card"          # passphrase → deck

MODE_REGISTRY: Dict[str, dict] = {
    # GAK / xGAK family
    "ctak_right":      {"family": MODE_FAMILY_GAK_XGAK, "code": K.GAK_CTAK_RIGHT},
    "ctak_left":       {"family": MODE_FAMILY_GAK_XGAK, "code": K.GAK_CTAK_LEFT},
    "ptak_right":      {"family": MODE_FAMILY_GAK_XGAK, "code": K.GAK_PTAK_RIGHT},
    "ptak_left":       {"family": MODE_FAMILY_GAK_XGAK, "code": K.GAK_PTAK_LEFT},
    "xgak_sum_right":  {"family": MODE_FAMILY_GAK_XGAK, "code": K.XGAK_SUM_RIGHT},
    "xgak_sum_left":   {"family": MODE_FAMILY_GAK_XGAK, "code": K.XGAK_SUM_LEFT},
    "xgak_diff_right": {"family": MODE_FAMILY_GAK_XGAK, "code": K.XGAK_DIFF_RIGHT},
    "xgak_diff_left":  {"family": MODE_FAMILY_GAK_XGAK, "code": K.XGAK_DIFF_LEFT},
    # KAK
    "kak_right":       {"family": MODE_FAMILY_KAK, "code": K.KAK_RIGHT},
    "kak_left":        {"family": MODE_FAMILY_KAK, "code": K.KAK_LEFT},
    # CFB
    "cfb_mod":         {"family": MODE_FAMILY_CFB, "code": K.CFB_MOD},
    "cfb_sub":         {"family": MODE_FAMILY_CFB, "code": K.CFB_SUB},
    # OFB
    "ofb":             {"family": MODE_FAMILY_OFB, "code": K.OFB},
    # Vigenère
    "vigenere_plain":     {"family": MODE_FAMILY_VIGENERE, "code": K.VIGENERE_PLAIN},
    "vigenere_pt_auto":   {"family": MODE_FAMILY_VIGENERE, "code": K.VIGENERE_PT_AUTO},
    "vigenere_ct_auto":   {"family": MODE_FAMILY_VIGENERE, "code": K.VIGENERE_CT_AUTO},
    # Card ciphers (alphabet_size = native, not 83)
    "pontifex":        {"family": MODE_FAMILY_CARD, "code": K.PONTIFEX,
                        "alphabet": K.PONTIFEX_ALPHABET, "deck_size": K.PONTIFEX_DECK_SIZE},
    "card_chameleon":  {"family": MODE_FAMILY_CARD, "code": K.CARD_CHAMELEON,
                        "alphabet": K.CC_DECK_SIZE, "deck_size": K.CC_DECK_SIZE},
    "mirdek":          {"family": MODE_FAMILY_CARD, "code": K.MIRDEK,
                        "alphabet": K.MIRDEK_ALPHABET, "deck_size": K.MIRDEK_DECK_SIZE},
}

ALL_MODES = list(MODE_REGISTRY.keys())
ALL_PRNGS = list(P.PRNG_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Key generation per mode family
# ---------------------------------------------------------------------------

def gen_keys_gak_xgak(prng_cls, seed: int, N: int) -> List[List[int]]:
    """Generate sigma[0..N], N+1 permutations in S_N."""
    rng = prng_cls(seed)
    return [rng.shuffled_perm(N) for _ in range(N + 1)]


def gen_keys_kak(prng_cls, seed: int, N: int) -> Tuple[List[List[int]], List[int], int]:
    """Generate sigma[0..N], an advance perm, and an initial key value."""
    rng = prng_cls(seed)
    sigma = [rng.shuffled_perm(N) for _ in range(N + 1)]
    advance = rng.shuffled_perm(N)
    key0 = rng.next_below(N)
    return sigma, advance, key0


def gen_keys_cfb(prng_cls, seed: int, N: int) -> Tuple[List[int], int]:
    """Generate single perm + IV."""
    rng = prng_cls(seed)
    sigma = rng.shuffled_perm(N)
    iv = rng.next_below(N)
    return sigma, iv


def gen_keys_ofb(prng_cls, seed: int, N: int) -> Tuple[List[int], int]:
    return gen_keys_cfb(prng_cls, seed, N)  # same structure


def gen_keys_vigenere(prng_cls, seed: int, N: int, key_len: int = 8) -> List[int]:
    """Generate key sequence."""
    rng = prng_cls(seed)
    return [rng.next_below(N) for _ in range(key_len)]


def gen_passphrases(dictionaries: Dict[str, S.Dictionary],
                    max_length_brute: int = 4,
                    cap: int = 700_000) -> Iterator[str]:
    """Yield passphrases: null + dictionary words + length-1-to-4 brute strings.
    Caps total at `cap`."""
    yielded = 0
    yield ""
    yielded += 1
    if yielded >= cap:
        return

    # Dictionary words
    for lang, d in dictionaries.items():
        for w in sorted(d.words):
            if w and w.isalpha():
                yield w
                yielded += 1
                if yielded >= cap:
                    return

    # Length-1-to-N brute over A-Z
    for L in range(1, max_length_brute + 1):
        for combo in itertools.product("abcdefghijklmnopqrstuvwxyz", repeat=L):
            yield "".join(combo)
            yielded += 1
            if yielded >= cap:
                return


# ---------------------------------------------------------------------------
# Decryption per cipher family
# ---------------------------------------------------------------------------

def decrypt_one_msg(ct: List[int], mode_name: str, key_state, N: int) -> List[int]:
    """Dispatch decryption to the appropriate kernel."""
    cfg = MODE_REGISTRY[mode_name]
    family = cfg["family"]
    code = cfg["code"]

    if family == MODE_FAMILY_GAK_XGAK:
        sigma = key_state
        return K.gak_decrypt(ct, sigma, N, code)

    elif family == MODE_FAMILY_KAK:
        sigma, advance, key0 = key_state
        return K.kak_decrypt(ct, sigma, advance, key0, N, code)

    elif family == MODE_FAMILY_CFB:
        sigma, iv = key_state
        return K.cfb_decrypt(ct, sigma, iv, N, code)

    elif family == MODE_FAMILY_OFB:
        sigma, iv = key_state
        return K.ofb_decrypt(ct, sigma, iv, N)

    elif family == MODE_FAMILY_VIGENERE:
        key = key_state
        return K.vigenere_decrypt(ct, key, N, code)

    elif family == MODE_FAMILY_CARD:
        deck = key_state
        if code == K.PONTIFEX:
            return K.pontifex_decrypt(ct, deck)
        elif code == K.CARD_CHAMELEON:
            return K.card_chameleon_decrypt(ct, deck)
        elif code == K.MIRDEK:
            return K.mirdek_decrypt(ct, deck)

    raise ValueError(f"Unknown mode/family: {mode_name}/{family}")


# ---------------------------------------------------------------------------
# Per-cipher alphabet handling
# ---------------------------------------------------------------------------

def map_runes_to_card_alphabet(rune_seq: List[int], rune_freq: Dict[int, float],
                                language: str, target_size: int) -> List[int]:
    """For card-cipher modes that operate on a smaller alphabet (26),
    map 83-rune ciphertext down to that alphabet using Hungarian-frequency
    matching against the language."""
    lang_alphabet = S.LANG_ALPHABETS[language][:target_size]
    letter_freq_dict = S.LANG_DEFAULT_FREQS[language]
    letter_freq = {ch: letter_freq_dict.get(ch, 0.0) for ch in lang_alphabet}

    # Build cost matrix: rows = runes, cols = letters
    n_runes = max(rune_seq) + 1 if rune_seq else 0
    n_runes = max(n_runes, target_size)
    rune_to_letter_idx: Dict[int, int] = {}

    # Simple frequency-rank matching: sort runes by descending freq, sort
    # letters by descending freq, pair them up
    runes_by_freq = sorted(range(n_runes), key=lambda r: -rune_freq.get(r, 0.0))
    letters_by_freq = sorted(range(target_size),
                              key=lambda l: -letter_freq.get(lang_alphabet[l], 0.0))
    for rank, rune in enumerate(runes_by_freq):
        rune_to_letter_idx[rune] = letters_by_freq[rank % target_size]

    return [rune_to_letter_idx.get(r, 0) for r in rune_seq]


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

@dataclass
class WorkUnit:
    """A chunk of work assigned to one process."""
    mode: str
    prng: str  # for card modes, this is the language for passphrase source
    seed_start: int
    seed_end: int
    output_dir: str
    data_path: str
    dict_paths: Dict[str, str]
    threshold: int
    alphabet_size: int  # for the ciphertext (e.g., 83)
    fast_scoring: bool
    min_word_len: int = 4


def worker_run_chunk(unit: WorkUnit) -> Tuple[int, int, int, List[Tuple[int, str, str, str]]]:
    """Process one work unit. Returns (n_tried, n_above_threshold, n_errors, top_hits).

    top_hits is a list of (max_hits, mode, prng, key_id) tuples for every key
    that crossed --threshold in this shard, capped at TOP_HITS_PER_SHARD entries
    (highest max_hits kept). Empty list if nothing crossed threshold. The main
    process aggregates these for live progress monitoring.

    Wrapped in an outer try/except so any worker exception (bad CT file,
    malformed dictionary, kernel crash, etc.) gets logged to a per-shard
    error file and returns a (0, 0, 1, []) tuple — preserving the multiprocessing
    pool from being poisoned by a single bad work unit.

    Atomic writes: shard files are written to .tmp paths first and renamed
    only on successful completion. On exception (or SIGKILL), .tmp files
    remain but final-name files don't exist — so the resume existence check
    correctly identifies the chunk as incomplete and retries it."""
    shard_id = f"{unit.mode}_{unit.prng}_{unit.seed_start:010d}_{unit.seed_end:010d}"
    out_dir = Path(unit.output_dir)
    params_path = out_dir / f"params_{shard_id}.tsv.gz"
    results_path = out_dir / f"results_{shard_id}.txt"
    params_tmp = out_dir / f"params_{shard_id}.tsv.gz.tmp"
    results_tmp = out_dir / f"results_{shard_id}.txt.tmp"

    # Resume check: if final shard files exist, skip
    if params_path.exists() and results_path.exists():
        return (0, 0, 0, [])

    # Clean up stale .tmp files from prior crashes
    for p in (params_tmp, results_tmp):
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass

    try:
        result = _worker_run_chunk_inner(unit, shard_id, params_tmp, results_tmp)
        # Atomic rename on success
        params_tmp.replace(params_path)
        results_tmp.replace(results_path)
        return result
    except Exception as outer_e:
        # Pool-safe: log to error file, clean up partials, return error count
        try:
            err_path = out_dir / f"error_{shard_id}.txt"
            with open(err_path, "w", encoding="utf-8") as ef:
                import traceback
                ef.write(f"Worker fatal error in {shard_id}\n")
                ef.write(f"Exception: {type(outer_e).__name__}: {outer_e}\n\n")
                ef.write(traceback.format_exc())
            # Clean up partial .tmp files so resume retries this chunk
            for p in (params_tmp, results_tmp):
                if p.exists():
                    try:
                        p.unlink()
                    except OSError:
                        pass
        except Exception:
            pass  # if we can't even write the error file, give up silently
        return (0, 0, 1, [])


# Cap on how many above-threshold hits each shard can bubble up to the
# monitor thread. Keeps memory bounded for pathologically permissive thresholds.
TOP_HITS_PER_SHARD = 10


def _worker_run_chunk_inner(unit: WorkUnit, shard_id: str,
                            params_path: Path, results_path: Path) -> Tuple[int, int, int, List[Tuple[int, str, str, str]]]:
    """Core worker logic; wrapped by worker_run_chunk for pool-safe errors.
    params_path and results_path are .tmp paths during processing; the outer
    wrapper renames them to final names on successful return."""
    # Load CT
    with open(unit.data_path, encoding="utf-8") as f:
        data = json.load(f)
    ciphertexts = [list(c) for c in data["ciphertexts"]]

    # Sanity-check CT against alphabet_size
    for msg_idx, ct in enumerate(ciphertexts):
        if any(c < 0 or c >= unit.alphabet_size for c in ct):
            raise ValueError(
                f"CT msg {msg_idx} contains symbols outside [0, {unit.alphabet_size})")

    # Load dictionaries
    dictionaries: Dict[str, S.Dictionary] = {}
    for lang, path in unit.dict_paths.items():
        d = S.Dictionary(lang)
        if Path(path).exists():
            d.load(Path(path))
        dictionaries[lang] = d

    cfg = MODE_REGISTRY[unit.mode]
    family = cfg["family"]

    n_tried = 0
    n_hits = 0
    n_errors = 0
    failed_keys: List[str] = []  # for per-seed error logging
    # Top above-threshold hits to bubble up to the monitor thread.
    # Each entry: (max_hits, mode, prng, key_id). Sorted desc on return.
    top_hits: List[Tuple[int, str, str, str]] = []

    params_f = gzip.open(params_path, "wt", encoding="utf-8")
    results_f = open(results_path, "w", encoding="utf-8")
    params_f.write("mode\tprng\tseed\tscore_fi\tscore_krl\tscore_en\thits_fi\thits_krl\thits_en\n")

    try:
        if family == MODE_FAMILY_CARD:
            # Iterate passphrases instead of seeds
            target_alphabet = cfg["alphabet"]
            passphrases_iter = gen_passphrases(dictionaries)

            # Pre-compute rune frequencies and per-language pre-decryption
            # mappings ONCE per work unit (they depend only on CT, not on key).
            rune_counts = Counter()
            for ct in ciphertexts:
                rune_counts.update(ct)
            total_runes = sum(rune_counts.values())
            rune_freq = {r: 100.0 * rune_counts.get(r, 0) / max(total_runes, 1)
                         for r in range(unit.alphabet_size)}

            # Map ciphertexts to card alphabet ONCE per language (also CT-only)
            ct_in_card_alpha: Dict[str, List[List[int]]] = {}
            for lang in dictionaries:
                ct_in_card_alpha[lang] = [
                    map_runes_to_card_alphabet(ct, rune_freq, lang, target_alphabet)
                    for ct in ciphertexts
                ]

            # Cache language alphabet strings once
            lang_alpha_cache = {lang: S.LANG_ALPHABETS[lang][:target_alphabet]
                                for lang in dictionaries}

            # seed_start/seed_end define the slice
            for idx, passphrase in enumerate(passphrases_iter):
                if idx < unit.seed_start:
                    continue
                if idx >= unit.seed_end:
                    break

                # Generate deck from passphrase
                if cfg["code"] == K.PONTIFEX:
                    deck = K.pontifex_key_deck_from_passphrase(passphrase)
                elif cfg["code"] == K.CARD_CHAMELEON:
                    deck = K.card_chameleon_key_deck_from_passphrase(passphrase)
                elif cfg["code"] == K.MIRDEK:
                    deck = K.mirdek_key_deck_from_passphrase(passphrase)
                else:
                    deck = list(range(cfg["deck_size"]))

                # Score per language using the pre-built CT-in-card-alphabet
                best_per_lang = {}
                for lang in dictionaries:
                    decrypted_letters: List[List[int]] = []
                    for ct_letters in ct_in_card_alpha[lang]:
                        try:
                            pt = decrypt_one_msg(ct_letters, unit.mode, deck,
                                                 target_alphabet)
                            decrypted_letters.append(pt)
                        except Exception as e:
                            n_errors += 1
                            decrypted_letters.append([])

                    # Score: concat all decrypted msgs, count dictionary hits
                    lang_alpha = lang_alpha_cache[lang]
                    parts = []
                    for letters in decrypted_letters:
                        parts.append("".join(lang_alpha[l] if 0 <= l < len(lang_alpha)
                                              else "?" for l in letters))
                    text = "".join(parts)
                    hits, hit_list = S.count_dictionary_hits(
                        text, dictionaries[lang], min_word_len=unit.min_word_len)
                    z = S.zipf_score(hit_list, dictionaries[lang]) if hits else 0.0
                    best_per_lang[lang] = (hits, z, text, hit_list)

                # Log
                hits_fi = best_per_lang.get("fi", (0, 0, "", []))[0]
                hits_krl = best_per_lang.get("krl", (0, 0, "", []))[0]
                hits_en = best_per_lang.get("en", (0, 0, "", []))[0]
                z_fi = best_per_lang.get("fi", (0, 0, "", []))[1]
                z_krl = best_per_lang.get("krl", (0, 0, "", []))[1]
                z_en = best_per_lang.get("en", (0, 0, "", []))[1]

                key_id = f"PHRASE:{passphrase[:200]}" if passphrase else "NULL"
                params_f.write(f"{unit.mode}\t{unit.prng}\t{key_id}\t"
                               f"{z_fi:.2f}\t{z_krl:.2f}\t{z_en:.2f}\t"
                               f"{hits_fi}\t{hits_krl}\t{hits_en}\n")

                max_hits = max(hits_fi, hits_krl, hits_en)
                if max_hits >= unit.threshold:
                    n_hits += 1
                    write_result_entry(results_f, unit.mode, unit.prng, key_id,
                                       best_per_lang, max_hits)
                    _push_top_hit(top_hits, max_hits, unit.mode, unit.prng, key_id)

                n_tried += 1

        else:
            # PRNG-keyed mode
            prng_cls = P.PRNG_REGISTRY[unit.prng]

            # Pre-compute rune frequencies (constant per CT)
            rune_counts = Counter()
            for ct in ciphertexts:
                rune_counts.update(ct)
            total = sum(rune_counts.values())
            rune_freq = {r: 100.0 * rune_counts.get(r, 0) / max(total, 1)
                         for r in range(unit.alphabet_size)}

            for seed in range(unit.seed_start, unit.seed_end):
                try:
                    # Generate keys for this seed
                    if family == MODE_FAMILY_GAK_XGAK:
                        sigma = gen_keys_gak_xgak(prng_cls, seed, unit.alphabet_size)
                        key_state = sigma
                    elif family == MODE_FAMILY_KAK:
                        key_state = gen_keys_kak(prng_cls, seed, unit.alphabet_size)
                    elif family == MODE_FAMILY_CFB:
                        key_state = gen_keys_cfb(prng_cls, seed, unit.alphabet_size)
                    elif family == MODE_FAMILY_OFB:
                        key_state = gen_keys_ofb(prng_cls, seed, unit.alphabet_size)
                    elif family == MODE_FAMILY_VIGENERE:
                        key_state = gen_keys_vigenere(prng_cls, seed, unit.alphabet_size)

                    # Decrypt all msgs
                    decrypted_msgs = []
                    for ct in ciphertexts:
                        pt = decrypt_one_msg(ct, unit.mode, key_state, unit.alphabet_size)
                        decrypted_msgs.append(pt)

                    # Score: per-language scoring with empirical mapping per decryption
                    if unit.fast_scoring:
                        # Fast path: use Hungarian optimum once per (decryption, lang)
                        all_symbols = []
                        for msg in decrypted_msgs:
                            all_symbols.extend(msg)
                        results = score_decryption_fast(all_symbols, unit.alphabet_size,
                                                          dictionaries,
                                                          min_word_len=unit.min_word_len)
                    else:
                        # Slow path: full perturbation search
                        all_symbols = []
                        for msg in decrypted_msgs:
                            all_symbols.extend(msg)
                        results = S.score_decryption(all_symbols, unit.alphabet_size,
                                                       dictionaries, n_mappings=1000)

                    hits_fi = results.get("fi", {}).get("hits", 0)
                    hits_krl = results.get("krl", {}).get("hits", 0)
                    hits_en = results.get("en", {}).get("hits", 0)
                    z_fi = results.get("fi", {}).get("zipf_score", 0.0)
                    z_krl = results.get("krl", {}).get("zipf_score", 0.0)
                    z_en = results.get("en", {}).get("zipf_score", 0.0)

                    key_id = f"SEED:{seed}"
                    params_f.write(f"{unit.mode}\t{unit.prng}\t{key_id}\t"
                                   f"{z_fi:.2f}\t{z_krl:.2f}\t{z_en:.2f}\t"
                                   f"{hits_fi}\t{hits_krl}\t{hits_en}\n")

                    max_hits = max(hits_fi, hits_krl, hits_en)
                    if max_hits >= unit.threshold:
                        n_hits += 1
                        formatted = {lang: (results[lang].get("hits", 0),
                                            results[lang].get("zipf_score", 0.0),
                                            results[lang].get("decrypted_text", ""),
                                            results[lang].get("hit_words", []))
                                     for lang in dictionaries}
                        write_result_entry(results_f, unit.mode, unit.prng, key_id,
                                           formatted, max_hits)
                        _push_top_hit(top_hits, max_hits, unit.mode, unit.prng, key_id)

                    n_tried += 1

                except Exception as e:
                    n_errors += 1
                    failed_keys.append(f"SEED:{seed} {type(e).__name__}: {e}")
                    if n_errors < 5:
                        print(f"[{unit.mode}/{unit.prng}/{seed}] error: {e}",
                              file=sys.stderr)

    finally:
        params_f.close()
        results_f.close()

    # If any per-seed errors occurred, log them to a per-shard errors file
    # so the user knows which keys were lost (seed ranges are NOT retried on
    # resume — even partial-success shards are considered complete)
    if failed_keys:
        try:
            err_log = Path(unit.output_dir) / f"failed_keys_{shard_id}.txt"
            with open(err_log, "w", encoding="utf-8") as ef:
                ef.write(f"# Keys that errored during {shard_id} ({len(failed_keys)} total)\n")
                for line in failed_keys:
                    ef.write(line + "\n")
        except Exception:
            pass

    # Sort top hits desc by max_hits; pre-capped to TOP_HITS_PER_SHARD
    top_hits.sort(key=lambda h: -h[0])
    return (n_tried, n_hits, n_errors, top_hits)


def _push_top_hit(top_hits: List[Tuple[int, str, str, str]],
                  max_hits: int, mode: str, prng: str, key_id: str) -> None:
    """Append to a bounded top-K list (highest max_hits kept).

    O(K) per insertion; K is small (TOP_HITS_PER_SHARD=10) so this is fine."""
    if len(top_hits) < TOP_HITS_PER_SHARD:
        top_hits.append((max_hits, mode, prng, key_id))
        return
    # At capacity — evict the lowest entry if the new one beats it
    min_idx = min(range(len(top_hits)), key=lambda i: top_hits[i][0])
    if max_hits > top_hits[min_idx][0]:
        top_hits[min_idx] = (max_hits, mode, prng, key_id)


def score_decryption_fast(symbols: List[int], N: int,
                          dictionaries: Dict[str, S.Dictionary],
                          min_word_len: int = 4) -> Dict[str, dict]:
    """Fast scoring: Hungarian optimum mapping per language, no perturbations."""
    rune_counts = Counter(symbols)
    total = sum(rune_counts.values())
    if total == 0:
        return {lang: {"hits": 0, "zipf_score": 0.0, "decrypted_text": "", "hit_words": []}
                for lang in dictionaries}

    rune_freq = {r: 100.0 * rune_counts.get(r, 0) / total for r in range(N)}

    results: Dict[str, dict] = {}
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
        hits, hit_list = S.count_dictionary_hits(text, dictionary, min_word_len=min_word_len)
        z = S.zipf_score(hit_list, dictionary) if hits else 0.0
        results[lang] = {"hits": hits, "zipf_score": z,
                          "decrypted_text": text, "hit_words": hit_list,
                          "best_mapping": mapping}
    return results


def write_result_entry(f, mode: str, prng: str, key_id: str,
                       per_lang: dict, max_hits: int) -> None:
    """Write one ranked result entry. Full plaintext included — per user spec
    'producing readable plain text, even if the results are massive'."""
    f.write(f"=== mode={mode} prng={prng} key={key_id} max_hits={max_hits} ===\n")
    for lang, val in per_lang.items():
        if isinstance(val, tuple):
            hits, z, text, hit_list = val
        else:
            hits = val["hits"]
            z = val["zipf_score"]
            text = val.get("decrypted_text", "")
            hit_list = val.get("hit_words", [])
        f.write(f"  [{lang}] hits={hits} zipf_score={z:.2f}\n")
        # Sort hits by length descending then alphabetically — longer matches
        # are stronger signal and easier to scan
        sorted_hits = sorted(set(hit_list), key=lambda w: (-len(w), w))
        f.write(f"  hit_words ({len(sorted_hits)}): {', '.join(sorted_hits)}\n")
        f.write(f"  text: {text}\n")
    f.write("\n")
    f.flush()


# ---------------------------------------------------------------------------
# Live progress monitoring
# ---------------------------------------------------------------------------

@dataclass
class ProgressState:
    """Thread-safe progress tracker shared between main thread and monitor.

    The main thread calls update() as pool.imap_unordered yields results;
    the monitor thread reads the snapshot fields under self._lock every
    --progress-interval seconds and prints a status line.
    """
    n_tried: int
    n_hits: int
    n_errors: int
    completed_units: int
    total_units: int
    est_total_keys: int
    top_hits: List[Tuple[int, str, str, str]]  # (max_hits, mode, prng, key_id)
    t0: float
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Capacity for the global top-hits list (across the entire run)
    GLOBAL_TOP_CAP: int = 50

    def update(self, n_tried: int, n_hits: int, n_errors: int,
               top: List[Tuple[int, str, str, str]]) -> None:
        with self._lock:
            self.n_tried += n_tried
            self.n_hits += n_hits
            self.n_errors += n_errors
            self.completed_units += 1
            # Merge shard's top hits, keep best GLOBAL_TOP_CAP overall
            self.top_hits.extend(top)
            if len(self.top_hits) > self.GLOBAL_TOP_CAP:
                self.top_hits.sort(key=lambda h: -h[0])
                del self.top_hits[self.GLOBAL_TOP_CAP:]

    def snapshot(self) -> Tuple[int, int, int, int, int, List[Tuple[int, str, str, str]]]:
        """Return a consistent point-in-time copy of the counters + top hits."""
        with self._lock:
            top = sorted(self.top_hits, key=lambda h: -h[0])
            return (self.n_tried, self.n_hits, self.n_errors,
                    self.completed_units, self.total_units, list(top))


def _fmt_duration(seconds: float) -> str:
    """Format a duration as a compact H:MM:SS or Dd HH:MM string."""
    if seconds < 0 or seconds != seconds:  # negative or NaN
        return "--:--:--"
    seconds = int(seconds)
    if seconds < 3600:
        return f"{seconds // 60:02d}:{seconds % 60:02d}"
    if seconds < 86400:
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h:d}:{m:02d}:{s:02d}"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return f"{d}d {h:02d}:{m:02d}"


def _fmt_count(n: int) -> str:
    """Compact thousands-separator formatting for large counts."""
    return f"{n:,}"


class ProgressMonitor:
    """Background thread that prints a status line every interval seconds.

    Reads ProgressState atomically via snapshot(); never blocks the main
    thread's update() path. Uses a clean overwrite-and-flush approach so
    the terminal isn't flooded with status lines: each interval prints
    the status + top-N hits panel with ANSI cursor controls when on a TTY,
    or plain newlines when not.
    """

    def __init__(self, state: ProgressState, interval: float, top_n: int,
                 use_color: bool):
        self.state = state
        self.interval = interval
        self.top_n = top_n
        self.use_color = use_color
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                         name="bf-progress-monitor")
        # Rolling window of (timestamp, total_tried) samples for smoothed
        # rate calculation. Using ~30s window (worth of samples at any interval)
        # gives stable ETA even when shards complete sporadically.
        self._samples: List[Tuple[float, int]] = [(state.t0, 0)]
        self._window_seconds = max(30.0, interval * 6)
        self._lines_printed = 0  # for cursor-up clearing on TTY

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(self.interval + 1.0, 2.0))

    def _run(self) -> None:
        # Wait one interval before the first print so we have a rate sample
        while not self._stop.wait(self.interval):
            self.print_status(final=False)

    def _rolling_rate(self, now: float, tried: int) -> float:
        """Return keys/sec averaged over the rolling window."""
        # Append this sample
        self._samples.append((now, tried))
        # Drop samples older than window_seconds (keep at least 2 for delta)
        cutoff = now - self._window_seconds
        while len(self._samples) > 2 and self._samples[0][0] < cutoff:
            self._samples.pop(0)
        t_old, tried_old = self._samples[0]
        dt = now - t_old
        if dt <= 0:
            return 0.0
        return (tried - tried_old) / dt

    def print_status(self, final: bool = False) -> None:
        tried, hits, errors, done, total, top = self.state.snapshot()
        now = time.time()
        elapsed = now - self.state.t0
        # Smoothed rolling rate (replaces single-sample recent rate)
        rate_recent = self._rolling_rate(now, tried)
        # Cumulative average throughput (for end-of-run summary clarity)
        rate_avg = tried / max(elapsed, 0.001)

        # Progress fraction — use whichever signal is more reliable.
        # est_total_keys assumes all units run to completion; if units are
        # being skipped (resume), completed_units/total is more accurate.
        if self.state.est_total_keys > 0:
            frac_keys = min(tried / self.state.est_total_keys, 1.0)
        else:
            frac_keys = 0.0
        frac_units = done / max(total, 1)
        frac = max(frac_keys, frac_units)

        # ETA: use whichever rate is more positive and informative.
        # Early in the run, recent rate may be 0 (no shard done yet) — fall
        # back to avg. After warmup, rolling rate is more responsive.
        rate_for_eta = rate_recent if rate_recent > 0 else rate_avg
        if rate_for_eta > 0 and self.state.est_total_keys > tried:
            remaining_keys = self.state.est_total_keys - tried
            eta_seconds = remaining_keys / rate_for_eta
        else:
            eta_seconds = 0.0 if (final or frac >= 1.0) else -1.0

        # Build status string. ANSI styling when on TTY.
        def c(code: str, s: str) -> str:
            return f"\033[{code}m{s}\033[0m" if self.use_color else s

        elapsed_str = _fmt_duration(elapsed)
        eta_str = _fmt_duration(eta_seconds) if eta_seconds >= 0 else "calculating…"
        pct_str = f"{frac*100:5.2f}%"
        # Show rolling rate; if it's zero (no progress in window), show ─/s
        rate_str = f"{rate_recent:,.0f}/s" if rate_recent > 0 else "─/s"

        status = (
            f"[ {c('96', elapsed_str)} ] "
            f"keys {c('92', _fmt_count(tried))}"
            f"/{c('90', _fmt_count(self.state.est_total_keys))} ({pct_str})  "
            f"│  rate {c('93', rate_str)} "
            f"({c('90', f'avg {rate_avg:,.0f}/s')})  "
            f"│  hits {c('92' if hits else '90', _fmt_count(hits))}  "
            f"err {c('91' if errors else '90', _fmt_count(errors))}  "
            f"│  shards {done}/{total}  │  ETA {c('96', eta_str)}"
        )

        # Build top hits panel
        panel_lines: List[str] = []
        if self.top_n > 0 and top:
            panel_lines.append(c("1", "  top hits  ─────────────────────────────────────────────────────────────"))
            for h, mode, prng, key_id in top[:self.top_n]:
                # Truncate key_id for readability
                kid = key_id if len(key_id) <= 40 else key_id[:37] + "..."
                panel_lines.append(
                    f"    {c('92', f'{h:>3d}')}  "
                    f"{c('96', f'{mode:<18s}')}  "
                    f"{c('93', f'{prng:<22s}')}  "
                    f"{kid}"
                )

        # Print: on a TTY, overwrite the previous block; otherwise just emit a
        # fresh block prefixed with a separator so logs stay scannable.
        if self.use_color and not final:
            # Move cursor up to overwrite previous status block
            if self._lines_printed > 0:
                sys.stdout.write(f"\033[{self._lines_printed}A")
            # Clear each line as we print
            sys.stdout.write("\033[K" + status + "\n")
            for line in panel_lines:
                sys.stdout.write("\033[K" + line + "\n")
            sys.stdout.flush()
            self._lines_printed = 1 + len(panel_lines)
        else:
            # Plain output for non-TTY (log files, CI). Print fresh block.
            print(status)
            for line in panel_lines:
                print(line)
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--data", default=None, help="CT data JSON (required unless --selftest)")
    p.add_argument("--dict-fi",  default="extra_words_fi.txt")
    p.add_argument("--dict-krl", default="extra_words_krl.txt")
    p.add_argument("--dict-en",  default="noita_wordlist.txt")
    p.add_argument("--languages", default="fi,krl,en",
                   help="Comma-separated languages to score against (default: all three). "
                        "Use 'fi' alone to run a Finnish-only scan, etc. Valid: fi,krl,en")
    p.add_argument("--modes", default="all",
                   help="Comma-separated mode names or 'all'")
    p.add_argument("--prngs", default="park_miller,mt19937,xorshift32,pcg32",
                   help="Comma-separated PRNG names or 'all'")
    p.add_argument("--seed-start", type=int, default=0)
    p.add_argument("--seed-end",   type=int, default=10000,
                   help="Number of seeds to try (default 10k for testing)")
    p.add_argument("--workers",    type=int, default=mp.cpu_count())
    p.add_argument("--chunk-size", type=int, default=1000,
                   help="Seeds per work unit chunk")
    p.add_argument("--output-dir", default="eyestat_results")
    p.add_argument("--threshold",  type=int, default=13,
                   help="Min hits in any language for a result entry")
    p.add_argument("--min-word-len", type=int, default=4,
                   help="Minimum word length for dictionary matching "
                        "(3 = noisy on long text, 4 = balanced, 5 = strict signal)")
    p.add_argument("--alphabet-size", type=int, default=83,
                   help="Ciphertext alphabet size (83 for Noita runes)")
    p.add_argument("--fast-scoring", action="store_true", default=True,
                   help="Use fast Hungarian-only scoring (no perturbations)")
    p.add_argument("--full-scoring", dest="fast_scoring", action="store_false",
                   help="Use full Hungarian + 1000 perturbations per call")
    p.add_argument("--progress-interval", type=float, default=5.0,
                   help="Seconds between live progress updates "
                        "(0 = disable monitor thread, only end-of-run summary)")
    p.add_argument("--progress-top-n", type=int, default=5,
                   help="How many top hits to show in each progress update "
                        "(0 = no top-hits panel, just status line)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color in progress output")
    p.add_argument("--selftest", action="store_true",
                   help="Run end-to-end selftest and exit")
    return p.parse_args()


def main():
    args = parse_args()
    if args.selftest:
        from eyestat_selftest import run_full_selftest
        run_full_selftest()
        return

    if args.data is None:
        print("ERROR: --data is required unless --selftest is given", file=sys.stderr)
        sys.exit(1)

    # Resolve modes
    if args.modes == "all":
        modes = ALL_MODES
    else:
        modes = args.modes.split(",")

    # Resolve PRNGs
    if args.prngs == "all":
        prngs = ALL_PRNGS
    else:
        prngs = args.prngs.split(",")

    # Resolve languages — subset of {fi, krl, en} the run will score against.
    # The runner always processes the same plaintext per key; this just selects
    # which dictionaries to load and score. Reducing the language set is a
    # ~30-50% speedup per key (Hungarian mapping is per-language).
    VALID_LANGS = ("fi", "krl", "en")
    languages = [L.strip() for L in args.languages.split(",") if L.strip()]
    for L in languages:
        if L not in VALID_LANGS:
            print(f"ERROR: unknown language '{L}'. Valid: {','.join(VALID_LANGS)}",
                  file=sys.stderr)
            sys.exit(1)
    if not languages:
        print(f"ERROR: --languages must specify at least one of {VALID_LANGS}",
              file=sys.stderr)
        sys.exit(1)
    # Build the per-language path map from selected languages only.
    # Languages not selected are not loaded by workers — saves both startup
    # time (no dictionary load) and per-key time (no Hungarian + hit count).
    lang_path_map_full = {
        "fi": args.dict_fi, "krl": args.dict_krl, "en": args.dict_en,
    }
    selected_dict_paths = {L: lang_path_map_full[L] for L in languages}

    # Validate
    for m in modes:
        if m not in MODE_REGISTRY:
            print(f"ERROR: unknown mode '{m}'. Available: {ALL_MODES}", file=sys.stderr)
            sys.exit(1)
    for prng in prngs:
        if prng not in P.PRNG_REGISTRY:
            print(f"ERROR: unknown PRNG '{prng}'. Available: {ALL_PRNGS}", file=sys.stderr)
            sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # Build work units
    units: List[WorkUnit] = []
    for mode in modes:
        cfg = MODE_REGISTRY[mode]
        if cfg["family"] == MODE_FAMILY_CARD:
            # Card modes use passphrases, not PRNG seeds
            for start in range(args.seed_start, args.seed_end, args.chunk_size):
                end = min(start + args.chunk_size, args.seed_end)
                units.append(WorkUnit(
                    mode=mode, prng="passphrase",
                    seed_start=start, seed_end=end,
                    output_dir=args.output_dir,
                    data_path=args.data,
                    dict_paths=selected_dict_paths,
                    threshold=args.threshold,
                    alphabet_size=args.alphabet_size,
                    fast_scoring=args.fast_scoring,
                    min_word_len=args.min_word_len,
                ))
        else:
            for prng in prngs:
                for start in range(args.seed_start, args.seed_end, args.chunk_size):
                    end = min(start + args.chunk_size, args.seed_end)
                    units.append(WorkUnit(
                        mode=mode, prng=prng,
                        seed_start=start, seed_end=end,
                        output_dir=args.output_dir,
                        data_path=args.data,
                        dict_paths=selected_dict_paths,
                        threshold=args.threshold,
                        alphabet_size=args.alphabet_size,
                        fast_scoring=args.fast_scoring,
                        min_word_len=args.min_word_len,
                    ))

    print(f"[runner] {len(units)} work units, {args.workers} workers")
    print(f"[runner] modes: {modes}")
    print(f"[runner] PRNGs: {prngs}")
    print(f"[runner] languages: {languages}")
    print(f"[runner] seeds [{args.seed_start}, {args.seed_end}) per (mode, prng)")
    print(f"[runner] output: {args.output_dir}/")

    # Estimate total keys across all units for ETA calculation. We can't know
    # exactly how many keys card-mode shards will try without enumerating
    # passphrases, so use seed_end-seed_start as a proxy (consistent with
    # how seed ranges are sized for card modes in main).
    est_total_keys = sum(u.seed_end - u.seed_start for u in units)

    t0 = time.time()

    # ---- Shared state for monitor thread ----
    progress_state = ProgressState(
        n_tried=0, n_hits=0, n_errors=0,
        completed_units=0, total_units=len(units),
        est_total_keys=est_total_keys,
        top_hits=[],
        t0=t0,
    )

    # Start monitor thread (no-op if interval <= 0)
    monitor = None
    if args.progress_interval > 0:
        monitor = ProgressMonitor(
            state=progress_state,
            interval=args.progress_interval,
            top_n=args.progress_top_n,
            use_color=(not args.no_color) and sys.stdout.isatty(),
        )
        monitor.start()

    try:
        if args.workers <= 1:
            # Serial mode (useful for debugging)
            for u in units:
                t, h, e, top = worker_run_chunk(u)
                progress_state.update(t, h, e, top)
        else:
            with mp.Pool(processes=args.workers) as pool:
                for t, h, e, top in pool.imap_unordered(worker_run_chunk, units, chunksize=1):
                    progress_state.update(t, h, e, top)
    finally:
        if monitor is not None:
            monitor.stop()
            # Final flush after shutdown so the last status line reflects
            # actual completion, not a stale snapshot
            monitor.print_status(final=True)

    n_tried = progress_state.n_tried
    n_hits = progress_state.n_hits
    n_errors = progress_state.n_errors

    elapsed = time.time() - t0
    print(f"\n[runner] done in {elapsed:.1f}s")
    print(f"[runner] {n_tried} keys tried, {n_hits} above threshold, {n_errors} errors")
    print(f"[runner] throughput: {n_tried/max(elapsed, 0.001):.0f} keys/sec")
    print(f"[runner] outputs in {args.output_dir}/")

    # Optional: merge shards into final ranked file
    merge_results(args.output_dir, args.threshold)


def merge_results(output_dir: str, threshold: int) -> None:
    """Merge per-shard results files into a final ranked results.txt.

    Sorts entries by max_hits descending; ties broken by zipf_score sum.
    """
    output_path = Path(output_dir)
    shard_paths = sorted(output_path.glob("results_*.txt"))
    if not shard_paths:
        print("[runner] no result shards to merge")
        return

    # Read all entries
    entries: List[Tuple[int, str]] = []
    for shard in shard_paths:
        with open(shard, encoding="utf-8") as f:
            current = []
            current_hits = 0
            for line in f:
                if line.startswith("=== "):
                    if current:
                        entries.append((current_hits, "".join(current)))
                    current = [line]
                    # Parse max_hits from header
                    try:
                        # ... max_hits=N ===
                        idx = line.find("max_hits=")
                        if idx >= 0:
                            current_hits = int(line[idx+9:].split()[0])
                    except (ValueError, IndexError):
                        current_hits = 0
                else:
                    current.append(line)
            if current:
                entries.append((current_hits, "".join(current)))

    entries.sort(key=lambda e: -e[0])
    final_path = output_path / "bruteforce_results.txt"
    with open(final_path, "w", encoding="utf-8") as f:
        f.write(f"# Brute-force results (threshold ≥ {threshold} hits, ranked)\n")
        f.write(f"# {len(entries)} total entries\n\n")
        for hits, text in entries:
            f.write(text)
    print(f"[runner] merged {len(entries)} entries → {final_path}")


if __name__ == "__main__":
    main()
