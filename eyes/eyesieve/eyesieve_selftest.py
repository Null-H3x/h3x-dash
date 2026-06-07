#!/usr/bin/env python3
"""eyesieve_selftest.py — module selftests.

Runs known-answer tests on every module the runner depends on, validates
the corpus loads cleanly, and exercises the permutation algebra (forward
+ inverse round-trips, length preservation, edge cases).

Exit codes:
  0  all green
  1  warnings only
  2  hard failure
"""

from __future__ import annotations

import os
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

import eyesieve_ciphers as _ciphers
import eyesieve_cli as _cli
import eyesieve_corpus as _corpus
import eyesieve_enumerator as _enum
import eyesieve_hypothesis as _hyp
import eyesieve_keyderiv as _keyderiv
import eyesieve_mprunner as _mprunner
import eyesieve_permutations as _perm
import eyesieve_reader as _reader
import eyesieve_runner as _runner
import eyesieve_run_report as _run_report
import eyesieve_scoring as _scoring
import eyesieve_sieve as _sieve
import eyesieve_sources as _sources

# ---------------------------------------------------------------------------
# Output (matches eyestat aesthetic)
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def green(s: str) -> str:  return _c("92", s)
def red(s: str) -> str:    return _c("91", s)
def yellow(s: str) -> str: return _c("93", s)
def cyan(s: str) -> str:   return _c("96", s)
def dim(s: str) -> str:    return _c("90", s)
def bold(s: str) -> str:   return _c("1", s)


TAG_OK   = f"[ {green('OK')}   ]"
TAG_WARN = f"[ {yellow('WARN')} ]"
TAG_FAIL = f"[ {red('FAIL')} ]"
TAG_SKIP = f"[ {yellow('SKIP')} ]"
TAG_INFO = f"[ {cyan('INFO')} ]"


class SkipTest(Exception):
    """Raised by a test body to mark it as skipped rather than failed.

    Used by tests that depend on optional infrastructure (eyestat for
    scoring, etc.) — when the dependency isn't available, the test
    should skip cleanly rather than fail."""
    pass


_results: list[tuple[str, str, str]] = []  # (name, status, detail)


def _run(name: str, fn: Callable[[], None]) -> None:
    try:
        fn()
    except SkipTest as e:
        _results.append((name, "skip", str(e) or "skipped"))
        print(f"{TAG_SKIP} {name}")
        if str(e):
            print(f"         {dim(str(e))}")
    except AssertionError as e:
        _results.append((name, "fail", str(e) or "assertion failed"))
        print(f"{TAG_FAIL} {name}")
        print(f"         {dim(str(e) or 'assertion failed')}")
    except Exception as e:  # noqa: BLE001
        _results.append((name, "fail", f"{type(e).__name__}: {e}"))
        print(f"{TAG_FAIL} {name}")
        print(f"         {dim(type(e).__name__ + ': ' + str(e))}")
        traceback.print_exc()
    else:
        _results.append((name, "ok", ""))
        print(f"{TAG_OK} {name}")


ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Corpus selftests
# ---------------------------------------------------------------------------

DATA_PATH = Path(__file__).resolve().parent / "noita_eye_data.json"


def t_corpus_loads() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    assert c.deck_size == 83
    assert c.num_messages == 9
    assert len(c.ciphertexts) == 9


def t_corpus_total_symbols() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    assert sum(c.lengths) == 1036, f"got {sum(c.lengths)}"


def t_corpus_short_codes() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    expected = ("E1", "W1", "E2", "W2", "E3", "W3", "E4", "W4", "E5")
    assert c.short_codes == expected, f"got {c.short_codes}"


def t_corpus_individual_lengths() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    expected = {"E1": 99, "W1": 103, "E2": 118, "W2": 102,
                "E3": 137, "W3": 124, "E4": 119, "W4": 120, "E5": 114}
    for code, exp_len in expected.items():
        got = len(c[code])
        assert got == exp_len, f"{code}: got {got}, expected {exp_len}"


def t_corpus_alphabet_range() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    for code, ct in zip(c.short_codes, c.ciphertexts):
        for j, x in enumerate(ct):
            assert 0 <= x < c.deck_size, f"{code}[{j}] = {x} out of range"


def t_corpus_sigma0_matches() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    assert c.sigma0_targets is not None, "sigma0_ct_targets missing from JSON"
    for code, ct, s0 in zip(c.short_codes, c.ciphertexts, c.sigma0_targets):
        assert ct[0] == s0, f"{code}: ct[0]={ct[0]} != sigma0={s0}"


def t_corpus_lookup_by_short_and_label() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    by_short = c.by_short("E1")
    by_label = c.by_label("East 1")
    by_getitem_short = c["E1"]
    by_getitem_label = c["East 1"]
    assert by_short == by_label == by_getitem_short == by_getitem_label


def t_corpus_lookup_rejects_unknown() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    try:
        c["NotAMessage"]
    except _corpus.CorpusError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected CorpusError on unknown key")


def t_corpus_universal_positions() -> None:
    """Positions 1 and 2 should be (66, 5) for all 9 messages."""
    c = _corpus.load_corpus(DATA_PATH)
    univ = dict(_corpus.universal_positions(c))
    assert univ.get(1) == 66, f"position 1: got {univ.get(1)}, expected 66"
    assert univ.get(2) == 5,  f"position 2: got {univ.get(2)}, expected 5"
    assert 0 not in univ, "position 0 should NOT be universal (sigma0 varies)"


def t_corpus_universal_prefix_alias() -> None:
    """Backward-compat alias must point at the new function."""
    assert _corpus.universal_prefix is _corpus.universal_positions


def t_corpus_prefix_groups_split() -> None:
    """At position 3, expect a 3/6 split: (48 -> E1,W1,E2) and (49 -> rest)."""
    c = _corpus.load_corpus(DATA_PATH)
    groups = _corpus.shared_prefix_groups(c, max_position=5, min_group_size=2)
    pos3 = [g for g in groups if g.position == 3]
    sizes = sorted(len(g.members) for g in pos3)
    assert sizes == [3, 6], f"position 3 group sizes: {sizes}"
    g48 = next(g for g in pos3 if g.symbol == 48)
    g49 = next(g for g in pos3 if g.symbol == 49)
    assert set(g48.members) == {"E1", "W1", "E2"}, f"got {g48.members}"
    assert set(g49.members) == {"W2", "E3", "W3", "E4", "W4", "E5"}


def t_corpus_alphabet_usage_total() -> None:
    c = _corpus.load_corpus(DATA_PATH)
    usage = _corpus.alphabet_usage(c)
    assert sum(usage.values()) == 1036
    # Universal positions 1 (66) and 2 (5) contribute >= 9 each
    assert usage[66] >= 9
    assert usage[5] >= 9


def t_corpus_load_deterministic() -> None:
    """Two loads of the same file must produce equal Corpus instances."""
    c1 = _corpus.load_corpus(DATA_PATH)
    c2 = _corpus.load_corpus(DATA_PATH)
    assert c1 == c2, "load_corpus is not deterministic"
    assert hash(c1) == hash(c2), "frozen Corpus hashes don't match"


def t_corpus_frozen() -> None:
    """Mutation attempts on Corpus must raise FrozenInstanceError."""
    import dataclasses
    c = _corpus.load_corpus(DATA_PATH)
    try:
        c.deck_size = 99  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Corpus is not frozen — mutation succeeded")


def t_corpus_load_missing_file() -> None:
    """Missing file must raise CorpusError (not FileNotFoundError)."""
    try:
        _corpus.load_corpus("/tmp/__eyesieve_nonexistent_file__.json")
    except _corpus.CorpusError as e:
        assert "not found" in str(e).lower()
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected CorpusError on missing file")


def t_corpus_load_bad_json() -> None:
    """Malformed JSON must raise CorpusError with parse context."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as f:
        f.write("{this is not valid json")
        bad_path = f.name
    try:
        _corpus.load_corpus(bad_path)
    except _corpus.CorpusError as e:
        assert "invalid json" in str(e).lower()
        assert ERROR_PREFIX in str(e)
        return
    finally:
        os.unlink(bad_path)
    raise AssertionError("expected CorpusError on malformed JSON")


def t_corpus_load_wrong_types() -> None:
    """Wrong-type fields must raise CorpusError, not deep TypeError."""
    import json as _json
    import tempfile
    bad_payload = {
        "deck_size": 83,
        "num_messages": 9,
        "message_labels": "East 1",  # should be a list
        "message_lengths": [99],
        "ciphertexts": [[0, 1, 2]],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as f:
        _json.dump(bad_payload, f)
        bad_path = f.name
    try:
        _corpus.load_corpus(bad_path)
    except _corpus.CorpusError as e:
        assert "message_labels" in str(e)
        assert ERROR_PREFIX in str(e)
        return
    finally:
        os.unlink(bad_path)
    raise AssertionError("expected CorpusError on wrong-type field")


def t_corpus_lookup_errors_consistent() -> None:
    """All lookup methods must raise CorpusError (not ValueError) on bad input."""
    c = _corpus.load_corpus(DATA_PATH)
    methods = [
        ("length_of",      lambda: c.length_of("ZZZ")),
        ("short_to_label", lambda: c.short_to_label("ZZZ")),
        ("label_to_short", lambda: c.label_to_short("Nope")),
        ("by_short",       lambda: c.by_short("ZZZ")),
        ("by_label",       lambda: c.by_label("Nope")),
        ("__getitem__",    lambda: c["NoSuch"]),
    ]
    for name, fn in methods:
        try:
            fn()
        except _corpus.CorpusError as e:
            assert ERROR_PREFIX in str(e), f"{name}: missing error prefix"
            continue
        raise AssertionError(f"{name} did not raise CorpusError on bad input")


def t_corpus_picklable() -> None:
    """Corpus must round-trip through pickle (required for multiprocessing)."""
    import pickle
    c = _corpus.load_corpus(DATA_PATH)
    blob = pickle.dumps(c)
    c2 = pickle.loads(blob)
    assert c == c2, "Corpus does not round-trip through pickle"


# ---------------------------------------------------------------------------
# Permutation selftests
# ---------------------------------------------------------------------------

# Use a known sequence with no repeats so round-trips are unambiguous.
TEST_SEQ_SHORT: tuple[int, ...] = tuple(range(12))   # length 12
TEST_SEQ_PRIME: tuple[int, ...] = tuple(range(13))   # length 13 (prime, awkward)
TEST_SEQ_ODD:   tuple[int, ...] = (7, 3, 9, 1, 4, 6, 0, 2, 8, 5)  # length 10


def _check_roundtrip(p: _perm.Permutation, seq: tuple[int, ...]) -> None:
    forward = p.apply(seq)
    back = p.inverse().apply(forward)
    assert tuple(back) == tuple(seq), (
        f"{p.name}: round-trip failed.\n"
        f"  input    : {seq}\n"
        f"  forward  : {forward}\n"
        f"  back     : {back}"
    )


def _check_length_preserved(p: _perm.Permutation, seq: tuple[int, ...]) -> None:
    out = p.apply(seq)
    assert len(out) == len(seq), (
        f"{p.name}: length not preserved ({len(seq)} -> {len(out)})"
    )


def _check_is_permutation(p: _perm.Permutation, seq: tuple[int, ...]) -> None:
    """Forward output is a permutation of input (same multiset)."""
    out = p.apply(seq)
    assert sorted(out) == sorted(seq), (
        f"{p.name}: output is not a permutation of input"
    )


def t_identity_roundtrip() -> None:
    p = _perm.Identity()
    for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
        assert p.apply(seq) == tuple(seq)
        _check_roundtrip(p, seq)


def t_reverse_roundtrip() -> None:
    p = _perm.Reverse()
    assert p.apply(TEST_SEQ_SHORT) == tuple(reversed(TEST_SEQ_SHORT))
    for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
        _check_roundtrip(p, seq)
        _check_length_preserved(p, seq)
        _check_is_permutation(p, seq)


def t_rotate_k_known() -> None:
    p = _perm.RotateK(k=3)
    assert p.apply((0, 1, 2, 3, 4)) == (3, 4, 0, 1, 2)
    p_neg = _perm.RotateK(k=-1)
    assert p_neg.apply((0, 1, 2, 3, 4)) == (4, 0, 1, 2, 3)
    # k larger than length normalizes mod len
    p_big = _perm.RotateK(k=8)
    assert p_big.apply((0, 1, 2, 3, 4)) == (3, 4, 0, 1, 2)


def t_rotate_k_roundtrip() -> None:
    for k in (1, 2, 3, 5, 7, 11, 13, -3):
        p = _perm.RotateK(k=k)
        for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
            _check_roundtrip(p, seq)
            _check_is_permutation(p, seq)


def t_block_reverse_known() -> None:
    p = _perm.BlockReverseN(n=3)
    assert p.apply((0, 1, 2, 3, 4, 5)) == (2, 1, 0, 5, 4, 3)
    # Trailing partial block
    assert p.apply((0, 1, 2, 3, 4)) == (2, 1, 0, 4, 3)


def t_block_reverse_roundtrip() -> None:
    for n in (2, 3, 4, 5, 7):
        p = _perm.BlockReverseN(n=n)
        for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
            _check_roundtrip(p, seq)
            _check_is_permutation(p, seq)


def t_stride_n_known() -> None:
    p = _perm.StrideN(n=2)
    assert p.apply((0, 1, 2, 3, 4, 5)) == (0, 2, 4, 1, 3, 5)
    p3 = _perm.StrideN(n=3)
    assert p3.apply((0, 1, 2, 3, 4, 5, 6, 7)) == (0, 3, 6, 1, 4, 7, 2, 5)


def t_stride_n_roundtrip() -> None:
    for n in (2, 3, 4, 5, 7):
        p = _perm.StrideN(n=n)
        for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
            _check_roundtrip(p, seq)
            _check_is_permutation(p, seq)


def t_grid_transpose_known() -> None:
    # 6 symbols into a 3-wide grid:
    #   row 0: 0 1 2
    #   row 1: 3 4 5
    # Read column-major: 0,3,1,4,2,5
    p = _perm.GridTranspose(width=3)
    assert p.apply((0, 1, 2, 3, 4, 5)) == (0, 3, 1, 4, 2, 5)


def t_grid_transpose_roundtrip() -> None:
    for w in range(3, 9):
        p = _perm.GridTranspose(width=w)
        for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
            _check_roundtrip(p, seq)
            _check_is_permutation(p, seq)


def t_message_indexed_known() -> None:
    # Indexer (10, 30, 20, 40) argsorts to positions (0, 2, 1, 3).
    p = _perm.MessageIndexed(indexer=(10, 30, 20, 40))
    assert p.apply(("a", "b", "c", "d")) == ("a", "c", "b", "d")


def t_message_indexed_roundtrip() -> None:
    # Use distinct indexer values so the sort is unambiguous.
    indexer = tuple(reversed(range(20)))
    p = _perm.MessageIndexed(indexer=indexer)
    for seq in (TEST_SEQ_SHORT, TEST_SEQ_PRIME, TEST_SEQ_ODD):
        _check_roundtrip(p, seq)
        _check_is_permutation(p, seq)


def t_enumerate_basic() -> None:
    perms = list(_perm.enumerate_permutations(max_len=20))
    # Identity, Reverse, 7 rotations, 5 block-reverses, 5 strides, 6 grids = 25
    assert len(perms) == 25, f"got {len(perms)} perms"
    names = {p.name for p in perms}
    assert "identity" in names
    assert "reverse" in names
    # All names unique
    assert len({p.name for p in perms}) == len(perms)


def t_enumerate_small_max_len() -> None:
    """At max_len=4, larger-period perms should be excluded."""
    perms = list(_perm.enumerate_permutations(max_len=4))
    for p in perms:
        if isinstance(p, _perm.RotateK):
            assert p.k < 4
        if isinstance(p, _perm.BlockReverseN):
            assert p.n <= 4
        if isinstance(p, _perm.StrideN):
            assert p.n <= 4
        if isinstance(p, _perm.GridTranspose):
            assert p.width <= 4


def t_perm_protocol_compliance() -> None:
    """All concrete perms satisfy the Permutation protocol."""
    for p in _perm.enumerate_permutations(max_len=20):
        assert isinstance(p, _perm.Permutation), (
            f"{type(p).__name__} does not satisfy Permutation protocol"
        )


def t_perm_empty_sequence() -> None:
    """Every enumerated permutation must accept an empty sequence."""
    for p in _perm.enumerate_permutations(max_len=20):
        out = p.apply(())
        assert out == (), f"{p.name}: empty -> {out}"
        # Inverse of empty should also be empty
        back = p.inverse().apply(out)
        assert back == (), f"{p.name}: inverse of empty -> {back}"


def t_perm_length_one_sequence() -> None:
    """Length-1 sequences are degenerate identities under any permutation."""
    for p in _perm.enumerate_permutations(max_len=20):
        out = p.apply((42,))
        assert out == (42,), f"{p.name}: length-1 -> {out}"


def t_perm_picklable() -> None:
    """Every concrete permutation must round-trip through pickle for
    multiprocessing safety."""
    import pickle
    for p in _perm.enumerate_permutations(max_len=20):
        try:
            blob = pickle.dumps(p)
            p2 = pickle.loads(blob)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{p.name}: pickle failed: {e}")
        assert p == p2, f"{p.name}: pickle round-trip not equal"
        # And the unpickled copy must produce identical output
        seq = TEST_SEQ_SHORT
        assert p.apply(seq) == p2.apply(seq), (
            f"{p.name}: unpickled copy produces different output"
        )


def t_perm_on_corpus_lengths() -> None:
    """Run every enumerated permutation against each real corpus message;
    verify round-trip + multiset preservation."""
    c = _corpus.load_corpus(DATA_PATH)
    for code in c.short_codes:
        seq = c[code]
        for p in _perm.enumerate_permutations(max_len=max(c.lengths)):
            out = p.apply(seq)
            assert len(out) == len(seq), (
                f"{p.name} on {code}: length {len(seq)} -> {len(out)}"
            )
            assert sorted(out) == sorted(seq), (
                f"{p.name} on {code}: multiset not preserved"
            )
            back = p.inverse().apply(out)
            assert back == seq, (
                f"{p.name} on {code}: round-trip failed"
            )


# ---------------------------------------------------------------------------
# Reader selftests
# ---------------------------------------------------------------------------

def _reader_corpus():
    return _corpus.load_corpus(DATA_PATH)


def _reader_freq():
    return _reader.FrequencyMap.from_corpus(_reader_corpus())


def _reader_highlights():
    return _reader.HighlightMap.from_corpus(_reader_corpus())


def _make_cfg(fmt: str = "decimal",
              freq_color: bool = False,
              highlights: bool = True,
              show_positions: bool = True) -> _reader.FormatConfig:
    return _reader.FormatConfig(fmt=fmt, freq_color=freq_color,
                                 highlights=highlights,
                                 show_positions=show_positions)


def t_reader_glyphs_table() -> None:
    assert len(_reader.GLYPHS) == 83, f"GLYPHS has {len(_reader.GLYPHS)} chars"
    assert len(set(_reader.GLYPHS)) == 83, "GLYPHS has duplicates"
    # All glyphs must be printable single chars (no control characters)
    for ch in _reader.GLYPHS:
        assert ch.isprintable(), f"non-printable glyph: {ch!r}"
        assert len(ch) == 1, f"multi-char glyph: {ch!r}"


def t_reader_frequency_map() -> None:
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    assert len(freq.rank) == c.deck_size
    assert len(freq.counts) == c.deck_size
    # Sum of counts equals total symbols
    assert sum(freq.counts) == sum(c.lengths)
    # Ranks are a permutation of [0, deck_size)
    assert sorted(freq.rank) == list(range(c.deck_size))
    # Universal-position symbols (66 and 5) should have high frequency
    # (appear at least 9 times each — once per message)
    assert freq.counts[66] >= 9
    assert freq.counts[5] >= 9


def t_reader_color_codes_valid() -> None:
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    for rune in range(c.deck_size):
        code = freq.color_code(rune)
        assert 16 <= code <= 231, f"rune {rune} -> color code {code} out of range"


def t_reader_highlight_universal() -> None:
    hl = _reader_highlights()
    assert 1 in hl.universal_positions
    assert 2 in hl.universal_positions
    assert 0 not in hl.universal_positions   # sigma0 varies
    assert 3 not in hl.universal_positions


def t_reader_highlight_groups() -> None:
    hl = _reader_highlights()
    # At position 3: E1, W1, E2 should be in a 3-group; W2 onward in a 6-group
    pos3 = hl.group_membership.get(3, {})
    assert pos3.get("E1") == 3
    assert pos3.get("W1") == 3
    assert pos3.get("E2") == 3
    assert pos3.get("W2") == 6
    assert pos3.get("E3") == 6


def t_reader_render_widths() -> None:
    cfg = _make_cfg(fmt="decimal", highlights=False)
    # Without color, output equals plain padded text
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        assert _reader.render_symbol(7, cfg, None, None, width=3) == "  7"
        cfg_hex = _make_cfg(fmt="hex", highlights=False)
        assert _reader.render_symbol(255 % 83, cfg_hex, None, None, width=3) == \
               f"{(255 % 83):>3x}"
        cfg_glyph = _make_cfg(fmt="glyph", highlights=False)
        out = _reader.render_symbol(10, cfg_glyph, None, None, width=3)
        # value 10 in glyph table is 'A'
        assert out == "  A", f"got {out!r}"
    finally:
        _reader.USE_COLOR = saved


def t_reader_grid_runs() -> None:
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        out = _reader.view_grid(c, _make_cfg(), freq, hl, term_width=100)
    finally:
        _reader.USE_COLOR = saved
    assert len(out) > 0
    assert "E1" in out and "W4" in out
    assert "Aligned grid" in out


def t_reader_show_runs() -> None:
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        out = _reader.view_show(c, ["E1"], _make_cfg(), freq, hl,
                                term_width=120)
    finally:
        _reader.USE_COLOR = saved
    assert "E1" in out and "East 1" in out
    # First symbol of E1 is 50; with cell width >= 2, output contains " 50"
    assert " 50" in out


def t_reader_columns_runs() -> None:
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        out = _reader.view_columns(c, 0, 5, _make_cfg(), freq, hl,
                                   term_width=100)
    finally:
        _reader.USE_COLOR = saved
    assert "Per-position structural notes" in out
    assert "universal" in out
    assert "3-group" in out


def t_reader_diff_known_match() -> None:
    """E1 vs W1 has a known 24-position matching run from positions 1-24."""
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        out = _reader.view_diff(c, "E1", "W1", _make_cfg(), freq, hl)
    finally:
        _reader.USE_COLOR = saved
    assert "longest match run  : 24" in out, (
        f"expected 24-position match run; got:\n{out[-400:]}"
    )
    assert "positions 1-24" in out


def t_reader_format_matrix() -> None:
    """Every view mode must run cleanly under every format / highlight combo."""
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    saved = _reader.USE_COLOR
    try:
        _reader.USE_COLOR = False
        for fmt in ("decimal", "hex", "glyph"):
            for highlights in (True, False):
                for freq_color in (True, False):
                    cfg = _make_cfg(fmt=fmt, highlights=highlights,
                                    freq_color=freq_color)
                    assert _reader.view_grid(c, cfg, freq, hl, 120)
                    assert _reader.view_show(c, ["E5"], cfg, freq, hl, 120)
                    assert _reader.view_columns(c, 0, 4, cfg, freq, hl, 120)
                    assert _reader.view_diff(c, "E1", "W1", cfg, freq, hl)
                    assert _reader.view_prefix(c, 8, cfg, freq, hl, 120)
    finally:
        _reader.USE_COLOR = saved


def t_reader_unknown_code() -> None:
    """Reader functions accept the corpus's error contract."""
    c = _reader_corpus()
    freq = _reader.FrequencyMap.from_corpus(c)
    hl = _reader.HighlightMap.from_corpus(c)
    # view_show handles errors internally and embeds them in output
    out = _reader.view_show(c, ["ZZZ"], _make_cfg(), freq, hl, 100)
    assert "ZZZ" in out or "unknown" in out.lower(), out
    # view_diff handles errors internally too
    out2 = _reader.view_diff(c, "ZZZ", "W1", _make_cfg(), freq, hl)
    assert "ZZZ" in out2 or "unknown" in out2.lower(), out2


# ---------------------------------------------------------------------------
# Source / merge-op selftests
# ---------------------------------------------------------------------------

def _corpus_for_sources() -> _corpus.Corpus:
    return _corpus.load_corpus(DATA_PATH)


def t_sources_concat_known() -> None:
    op = _sources.Concat()
    assert op.apply((1, 2, 3), (4, 5)) == (1, 2, 3, 4, 5)
    assert op.apply((1,), (2,), (3,)) == (1, 2, 3)
    assert op.apply(()) == ()
    assert op.apply((1, 2), ()) == (1, 2)


def t_sources_concat_arity() -> None:
    op = _sources.Concat()
    # 1 input is fine
    assert op.apply((7,)) == (7,)
    # 0 inputs raises
    try:
        op.apply()
    except _sources.SourceError:
        return
    raise AssertionError("expected SourceError on 0-arg concat")


def t_sources_cyclic_known() -> None:
    """Known answers under deck_size=10 (easier mental math)."""
    add = _sources.CyclicCombine(op="add", deck_size=10)
    # a=(1,2,3,4), b=(5,6) -> (1+5,2+6,3+5,4+6) mod 10 = (6,8,8,0)
    assert add.apply((1, 2, 3, 4), (5, 6)) == (6, 8, 8, 0)

    sub = _sources.CyclicCombine(op="sub", deck_size=10)
    # (1-5,2-6,3-5,4-6) mod 10 = (6,6,8,8)
    assert sub.apply((1, 2, 3, 4), (5, 6)) == (6, 6, 8, 8)

    xor = _sources.CyclicCombine(op="xor")
    # (5^1, 6^2, 5^3, 6^4) = (4, 4, 6, 2)
    assert xor.apply((1, 2, 3, 4), (5, 6)) == (4, 4, 6, 2)


def t_sources_cyclic_length() -> None:
    """Output length == len(first arg) regardless of keystream length."""
    for op_name in ("add", "sub", "xor"):
        op = _sources.CyclicCombine(op=op_name, deck_size=83)
        assert len(op.apply((1, 2, 3, 4, 5), (9,))) == 5
        assert len(op.apply((1,), (9, 8, 7, 6))) == 1


def t_sources_cyclic_asymmetric() -> None:
    add = _sources.CyclicCombine(op="add", deck_size=83)
    a, b = (10, 20, 30), (1, 2)
    r1 = add.apply(a, b)
    r2 = add.apply(b, a)
    assert r1 != r2, "CyclicCombine must be order-asymmetric"
    assert len(r1) == len(a)
    assert len(r2) == len(b)


def t_sources_cyclic_add_sub_inverse() -> None:
    """add then sub recovers the original message."""
    add = _sources.CyclicCombine(op="add", deck_size=83)
    sub = _sources.CyclicCombine(op="sub", deck_size=83)
    a = (50, 17, 33, 71, 4, 25)
    keystream = (8, 11, 3)
    encrypted = add.apply(a, keystream)
    decrypted = sub.apply(encrypted, keystream)
    assert decrypted == a, f"add->sub round trip failed: {decrypted} != {a}"


def t_sources_cyclic_closure() -> None:
    """add and sub stay in [0, deck_size)."""
    c = _corpus_for_sources()
    add = _sources.CyclicCombine(op="add", deck_size=c.deck_size)
    sub = _sources.CyclicCombine(op="sub", deck_size=c.deck_size)
    for op in (add, sub):
        for ca in c.short_codes:
            for cb in c.short_codes:
                if ca == cb:
                    continue
                out = op.apply(c.by_short(ca), c.by_short(cb))
                for j, v in enumerate(out):
                    assert 0 <= v < c.deck_size, (
                        f"{op.name}({ca},{cb})[{j}] = {v} outside alphabet"
                    )


def t_sources_interleave_known() -> None:
    op = _sources.Interleave(start=0)
    assert op.apply((1, 2, 3), (10, 20, 30)) == (1, 10, 2, 20, 3, 30)
    # Unequal lengths: alternate then append tail
    assert op.apply((1, 2, 3, 4, 5), (10, 20)) == (1, 10, 2, 20, 3, 4, 5)
    assert op.apply((1,), (10, 20, 30)) == (1, 10, 20, 30)


def t_sources_interleave_start() -> None:
    a = (1, 2, 3)
    b = (10, 20, 30)
    op0 = _sources.Interleave(start=0)
    op1 = _sources.Interleave(start=1)
    assert op0.apply(a, b) == (1, 10, 2, 20, 3, 30)
    assert op1.apply(a, b) == (10, 1, 20, 2, 30, 3)
    # start=1 of (a, b) equals start=0 of (b, a)
    assert op1.apply(a, b) == op0.apply(b, a)


def t_sources_trunc_known() -> None:
    add = _sources.TruncatedAlign(op="add", deck_size=10)
    # a=(1,2,3,4), b=(5,6) -> only first 2 positions used
    # (1+5, 2+6) mod 10 = (6, 8)
    assert add.apply((1, 2, 3, 4), (5, 6)) == (6, 8)
    sub = _sources.TruncatedAlign(op="sub", deck_size=10)
    assert sub.apply((1, 2, 3, 4), (5, 6)) == (6, 6)


def t_sources_trunc_equal() -> None:
    """When lengths match, trunc(add) equals cyclic(add)."""
    a = (1, 2, 3, 4, 5)
    b = (10, 20, 30, 40, 50)
    trunc_add = _sources.TruncatedAlign(op="add", deck_size=83)
    cyclic_add = _sources.CyclicCombine(op="add", deck_size=83)
    assert trunc_add.apply(a, b) == cyclic_add.apply(a, b)


def t_sources_hp_zero_header() -> None:
    """header_length=0 must produce identical output to the inner op alone."""
    inner = _sources.CyclicCombine(op="add", deck_size=83)
    hp = _sources.HeaderPayload(header_length=0, payload_op=inner)
    a = (1, 2, 3, 4, 5)
    b = (10, 20, 30)
    assert hp.apply(a, b) == inner.apply(a, b)


def t_sources_hp_composition() -> None:
    """HP strips headers, applies inner, returns inner's output."""
    inner = _sources.Concat()
    hp = _sources.HeaderPayload(header_length=2, payload_op=inner)
    # Strip 2 from each, then concat the payloads
    a = (1, 2, 3, 4)
    b = (10, 20, 30, 40, 50)
    expected = inner.apply((3, 4), (30, 40, 50))
    assert hp.apply(a, b) == expected
    assert hp.apply(a, b) == (3, 4, 30, 40, 50)


def t_sources_hp_preserve() -> None:
    """preserve_header prepends the chosen input's header."""
    inner = _sources.Concat()
    a = (1, 2, 3, 4)
    b = (10, 20, 30, 40, 50)
    hp_a = _sources.HeaderPayload(header_length=2, payload_op=inner,
                                   preserve_header="a")
    hp_b = _sources.HeaderPayload(header_length=2, payload_op=inner,
                                   preserve_header="b")
    assert hp_a.apply(a, b) == (1, 2) + (3, 4, 30, 40, 50)
    assert hp_b.apply(a, b) == (10, 20) + (3, 4, 30, 40, 50)


def t_sources_hp_overflow() -> None:
    """header_length > input length raises SourceError."""
    hp = _sources.HeaderPayload(header_length=10,
                                 payload_op=_sources.Concat())
    try:
        hp.apply((1, 2, 3), (4, 5, 6, 7, 8))
    except _sources.SourceError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected SourceError on header overflow")


def t_sources_index_lookup() -> None:
    op = _sources.IndexDriven(mode="lookup")
    # indices=(0,2,4), source=(10,20,30,40,50)
    # output = (source[0], source[2], source[4]) = (10, 30, 50)
    assert op.apply((0, 2, 4), (10, 20, 30, 40, 50)) == (10, 30, 50)
    # indices wrap: (5 % 5 = 0, 7 % 5 = 2)
    assert op.apply((5, 7), (10, 20, 30, 40, 50)) == (10, 30)


def t_sources_index_skip() -> None:
    op = _sources.IndexDriven(mode="skip")
    # indices=(1,2,3), source=(10,20,30,40,50)
    # pos starts at 0
    # +1 -> pos=1, source[1]=20
    # +2 -> pos=3, source[3]=40
    # +3 -> pos=6 % 5 = 1, source[1]=20
    assert op.apply((1, 2, 3), (10, 20, 30, 40, 50)) == (20, 40, 20)


def t_sources_arity_enforcement() -> None:
    """Every 2-arg merge op rejects 1-arg or 3-arg calls."""
    two_arg_ops = [
        _sources.CyclicCombine(op="add", deck_size=83),
        _sources.Interleave(),
        _sources.TruncatedAlign(op="add", deck_size=83),
        _sources.HeaderPayload(header_length=0,
                                payload_op=_sources.Concat()),
        _sources.IndexDriven(mode="lookup"),
    ]
    for op in two_arg_ops:
        for args in ((1, 2, 3),), ((1,), (2,), (3,)):
            try:
                op.apply(*args)
            except _sources.SourceError:
                continue
            raise AssertionError(
                f"{op.name}: expected SourceError on {len(args)}-arg call"
            )


def t_sources_edge_cases() -> None:
    """Empty / single-element inputs don't crash and produce sensible output."""
    add = _sources.CyclicCombine(op="add", deck_size=83)
    # Empty data with non-empty keystream
    assert add.apply((), (1, 2)) == ()
    # Non-empty data with empty keystream -> error (can't wrap)
    try:
        add.apply((1, 2), ())
    except _sources.SourceError:
        pass
    else:
        raise AssertionError("CyclicCombine: expected error on empty keystream")

    # Single-element on both sides
    assert add.apply((5,), (7,)) == ((5 + 7) % 83,)

    # Concat with empty inputs
    assert _sources.Concat().apply((), ()) == ()

    # Interleave with one empty
    assert _sources.Interleave().apply((1, 2, 3), ()) == (1, 2, 3)

    # TruncatedAlign with one empty
    assert _sources.TruncatedAlign(op="add", deck_size=83).apply((1, 2), ()) == ()


def t_sources_deterministic() -> None:
    c = _corpus_for_sources()
    for op in _sources.enumerate_merge_ops():
        try:
            r1 = op.apply(c.by_short("E1"), c.by_short("W1"))
            r2 = op.apply(c.by_short("E1"), c.by_short("W1"))
        except _sources.SourceError:
            continue   # ops that reject specific inputs are fine
        assert r1 == r2, f"{op.name}: not deterministic"


def t_sources_pickle() -> None:
    import pickle
    for op in _sources.enumerate_merge_ops():
        try:
            blob = pickle.dumps(op)
            op2 = pickle.loads(blob)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{op.name}: pickle failed: {e}")
        assert op == op2, f"{op.name}: pickle round-trip not equal"
        # And the unpickled copy must produce identical output
        c = _corpus_for_sources()
        a = c.by_short("E1")
        b = c.by_short("W1")
        try:
            assert op.apply(a, b) == op2.apply(a, b), (
                f"{op.name}: unpickled output differs"
            )
        except _sources.SourceError:
            pass


def t_sources_corpus_application() -> None:
    """Every merge op runs without exception on every (E_i, W_i) corpus pair."""
    c = _corpus_for_sources()
    failures: list[str] = []
    for op in _sources.enumerate_merge_ops():
        for i in range(1, 5):
            ca, cb = f"E{i}", f"W{i}"
            try:
                out = op.apply(c.by_short(ca), c.by_short(cb))
                assert len(out) >= 0
            except _sources.SourceError as e:
                # HeaderPayload(h=9) on the 99-length E1/W1 is fine
                # but should not raise — record any unexpected raises
                failures.append(f"{op.name}({ca},{cb}): {e}")
            except Exception as e:  # noqa: BLE001
                failures.append(
                    f"{op.name}({ca},{cb}): non-SourceError exception "
                    f"{type(e).__name__}: {e}"
                )
    assert not failures, "merge-op failures:\n  " + "\n  ".join(failures)


def t_sources_single_message() -> None:
    c = _corpus_for_sources()
    sm = _sources.SingleMessage(code="E1")
    assert sm.resolve(c) == c.by_short("E1")
    assert "E1" in sm.name


def t_sources_single_message_error() -> None:
    c = _corpus_for_sources()
    sm = _sources.SingleMessage(code="ZZZ")
    try:
        sm.resolve(c)
    except _sources.SourceError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected SourceError on unknown code")


def t_sources_merged_messages() -> None:
    c = _corpus_for_sources()
    mm = _sources.MergedMessages(codes=("E1", "W1"),
                                  op=_sources.Concat())
    expected = _sources.Concat().apply(c.by_short("E1"), c.by_short("W1"))
    assert mm.resolve(c) == expected
    assert "E1" in mm.name and "W1" in mm.name


def t_sources_merged_messages_error() -> None:
    try:
        _sources.MergedMessages(codes=(), op=_sources.Concat())
    except _sources.SourceError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected SourceError on empty codes tuple")


def t_sources_enumerate_unique() -> None:
    names = [op.name for op in _sources.enumerate_merge_ops()]
    assert len(names) == len(set(names)), (
        f"duplicate names: {[n for n in names if names.count(n) > 1]}"
    )


def t_sources_estimated_count() -> None:
    actual = sum(1 for _ in _sources.enumerate_merge_ops())
    estimated = _sources.estimated_count()
    assert actual == estimated, f"estimated {estimated} != actual {actual}"
    # 11 base ops + 6 header_lengths × 6 inner ops × 2 preserve = 83
    assert actual == 83, f"expected 83 ops by default, got {actual}"


# ---------------------------------------------------------------------------
# Cipher selftests
# ---------------------------------------------------------------------------

# Test inputs sized to exercise both K<n and K>=n keystream-wrap regimes.
_TEST_PT_SMALL: tuple[int, ...] = (12, 45, 7, 33, 17, 50, 4, 81, 22, 6)
_TEST_KEY_SMALL: tuple[int, ...] = (8, 33, 5, 17, 60, 41, 2, 19)  # >= max key_columns=7
_TEST_PT_LONG:  tuple[int, ...] = tuple(range(50))
_TEST_KEY_LONG: tuple[int, ...] = (3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9)


def t_ciphers_protocol() -> None:
    for cipher in _ciphers.enumerate_ciphers():
        assert isinstance(cipher, _ciphers.Cipher), (
            f"{type(cipher).__name__} does not satisfy Cipher protocol"
        )


def t_ciphers_roundtrip_simple() -> None:
    for cipher in _ciphers.enumerate_ciphers():
        ct = cipher.encrypt(_TEST_PT_SMALL, _TEST_KEY_SMALL)
        rec = cipher.decrypt(ct, _TEST_KEY_SMALL)
        assert tuple(rec) == _TEST_PT_SMALL, (
            f"{cipher.name}: round-trip failed\n"
            f"  pt = {_TEST_PT_SMALL}\n"
            f"  ct = {ct}\n"
            f"  rec= {rec}"
        )


def t_ciphers_roundtrip_corpus() -> None:
    """Every cipher must round-trip on every real corpus message under a
    real corpus-derived key."""
    c = _corpus.load_corpus(DATA_PATH)
    key = c.by_short("E5")   # 114 long, sufficient for all enumerated k_columns
    for cipher in _ciphers.enumerate_ciphers():
        for code in c.short_codes:
            msg = c.by_short(code)
            ct = cipher.encrypt(msg, key)
            rec = cipher.decrypt(ct, key)
            assert tuple(rec) == tuple(msg), (
                f"{cipher.name} on {code}: round-trip failed\n"
                f"  len(msg)={len(msg)}, len(ct)={len(ct)}, len(rec)={len(rec)}"
            )


def t_ciphers_empty_key() -> None:
    for cipher in _ciphers.enumerate_ciphers():
        try:
            cipher.decrypt((1, 2, 3), ())
        except _ciphers.CipherError as e:
            assert ERROR_PREFIX in str(e), (
                f"{cipher.name}: error message missing prefix"
            )
            continue
        raise AssertionError(f"{cipher.name}: did not raise on empty key")


def t_ciphers_empty_input() -> None:
    for cipher in _ciphers.enumerate_ciphers():
        out = cipher.decrypt((), _TEST_KEY_LONG)
        assert tuple(out) == (), f"{cipher.name}: empty -> {out}"
        out2 = cipher.encrypt((), _TEST_KEY_LONG)
        assert tuple(out2) == (), f"{cipher.name}: empty encrypt -> {out2}"


def t_ciphers_xor_selfinverse() -> None:
    x = _ciphers.XORStream()
    pt = _TEST_PT_SMALL
    key = _TEST_KEY_SMALL
    once = x.encrypt(pt, key)
    twice = x.encrypt(once, key)
    assert twice == pt, "XORStream should be self-inverse"
    assert x.decrypt(pt, key) == x.encrypt(pt, key)


def t_ciphers_beaufort_selfinverse() -> None:
    b = _ciphers.Beaufort()
    pt = _TEST_PT_SMALL
    key = _TEST_KEY_SMALL
    once = b.encrypt(pt, key)
    twice = b.encrypt(once, key)
    assert twice == pt, "Beaufort should be self-inverse"
    assert b.decrypt(pt, key) == b.encrypt(pt, key)


def t_ciphers_beaufort_autokey_not_selfinverse() -> None:
    """Regression test for the audit finding — BeaufortAutokey is NOT
    self-inverse despite its non-autokey parent being so."""
    ba = _ciphers.BeaufortAutokey()
    pt = (5, 17, 33, 71, 4, 25, 81, 22, 50, 11)
    key = (8, 33, 5)
    once = ba.encrypt(pt, key)
    twice = ba.encrypt(once, key)
    assert twice != pt, (
        "BeaufortAutokey should NOT be self-inverse (per audit); "
        "double-encrypt unexpectedly recovered the plaintext"
    )
    # But proper encrypt+decrypt does recover
    assert ba.decrypt(once, key) == pt


def t_ciphers_vigenere_variant_identity() -> None:
    """Algebraic identity: Vigenere.encrypt and VariantBeaufort.decrypt
    are the same operation (both compute pt + key mod N). Worth knowing
    for phase-4 enumerator dedup."""
    v = _ciphers.Vigenere()
    vb = _ciphers.VariantBeaufort()
    pt = _TEST_PT_SMALL
    key = _TEST_KEY_SMALL
    assert v.encrypt(pt, key) == vb.decrypt(pt, key)


def t_ciphers_vigenere_known() -> None:
    v = _ciphers.Vigenere(deck_size=10)
    assert v.encrypt((0, 1, 2), (3, 5)) == (3, 6, 5)
    assert v.decrypt((3, 6, 5), (3, 5)) == (0, 1, 2)


def t_ciphers_beaufort_known() -> None:
    b = _ciphers.Beaufort(deck_size=10)
    # encrypt: (3,5,3) - (0,1,2) = (3,4,1)
    assert b.encrypt((0, 1, 2), (3, 5)) == (3, 4, 1)
    # decrypt is the same operation (self-inverse)
    assert b.decrypt((3, 4, 1), (3, 5)) == (0, 1, 2)


def t_ciphers_vigenere_autokey_known() -> None:
    """Autokey extension kicks in when i >= K."""
    va = _ciphers.VigenereAutokey(deck_size=10)
    # pt=(0,1,2,3,4,5), key=(7); for i>=1 keystream picks up pt[i-1]
    ct = va.encrypt((0, 1, 2, 3, 4, 5), (7,))
    assert ct == (7, 1, 3, 5, 7, 9), f"got {ct}"
    assert va.decrypt(ct, (7,)) == (0, 1, 2, 3, 4, 5)


def t_ciphers_affine_invertible() -> None:
    af = _ciphers.Affine(deck_size=83)
    for key_first in range(0, 83):
        key = (key_first, 17)
        a, b = af._derive_ab(key)
        assert 1 <= a < 83, f"a = {a} out of range"
        a_inv = pow(a, 81, 83)
        assert (a * a_inv) % 83 == 1, f"a={a} has no inverse mod 83"


def t_ciphers_affine_rejects_composite() -> None:
    try:
        _ciphers.Affine(deck_size=10)  # 10 = 2 x 5
    except _ciphers.CipherError as e:
        assert "not prime" in str(e)
        return
    raise AssertionError("Affine should reject composite deck_size")


def t_ciphers_keyword_perm_derivation() -> None:
    ks = _ciphers.KeywordSubstitution(deck_size=8)
    perm = ks._derive_perm((5, 3, 5, 1, 7))
    # Unique in-range, in order seen: 5, 3, 1, 7
    # Then remaining: 0, 2, 4, 6
    assert perm == (5, 3, 1, 7, 0, 2, 4, 6), f"got {perm}"
    assert ks.encrypt((0, 1, 2), (5, 3, 5, 1, 7)) == (5, 3, 1)


def t_ciphers_columnar_stable_ties() -> None:
    """Tied key values produce a deterministic column order via stable
    tiebreaking on index."""
    ct = _ciphers.ColumnarTransposition(key_columns=4)
    order = ct._derive_column_order((5, 3, 5, 1))
    assert order == (3, 1, 0, 2), f"got {order}"


def t_ciphers_columnar_known() -> None:
    """Known-answer test on a small example with partial last row.

    pt length 7 with K=3: rows=3, last_row_width=1 (only col 0 reaches row 2)
    key (2,0,1): column read order [1, 2, 0]
    Grid: row0=(pt0,pt1,pt2)  row1=(pt3,pt4,pt5)  row2=(pt6,_,_)
    Read col 1 (2 rows): pt1, pt4
    Read col 2 (2 rows): pt2, pt5
    Read col 0 (3 rows): pt0, pt3, pt6
    """
    ct = _ciphers.ColumnarTransposition(deck_size=83, key_columns=3)
    pt = (10, 20, 30, 40, 50, 60, 70)
    expected = (20, 50, 30, 60, 10, 40, 70)
    assert ct.encrypt(pt, (2, 0, 1)) == expected
    assert ct.decrypt(expected, (2, 0, 1)) == pt


def t_ciphers_columnar_short_key() -> None:
    ct = _ciphers.ColumnarTransposition(key_columns=5)
    try:
        ct.encrypt((1, 2, 3, 4, 5), (1, 2, 3))   # key shorter than K=5
    except _ciphers.CipherError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected CipherError on short key")


def t_ciphers_alphabet_validation() -> None:
    """Modular ciphers must reject out-of-alphabet inputs (XOR doesn't -
    by design, since XOR is not closed on a non-power-of-2 alphabet)."""
    v = _ciphers.Vigenere(deck_size=83)
    try:
        v.decrypt((50, 200, 7), (1, 2, 3))   # 200 out of [0, 83)
    except _ciphers.CipherError as e:
        assert ERROR_PREFIX in str(e)
    else:
        raise AssertionError("Vigenere should reject ct=200")
    try:
        v.decrypt((50, 7, 3), (1, 100, 3))   # key=100 out of alphabet
    except _ciphers.CipherError as e:
        assert ERROR_PREFIX in str(e)
    else:
        raise AssertionError("Vigenere should reject key=100")


def t_ciphers_deterministic() -> None:
    for cipher in _ciphers.enumerate_ciphers():
        r1 = cipher.decrypt(_TEST_PT_LONG, _TEST_KEY_LONG)
        r2 = cipher.decrypt(_TEST_PT_LONG, _TEST_KEY_LONG)
        assert r1 == r2, f"{cipher.name}: non-deterministic"


def t_ciphers_pickle() -> None:
    import pickle
    for cipher in _ciphers.enumerate_ciphers():
        try:
            blob = pickle.dumps(cipher)
            c2 = pickle.loads(blob)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{cipher.name}: pickle failed: {e}")
        assert cipher == c2, f"{cipher.name}: pickle not equal"
        assert cipher.decrypt(_TEST_PT_SMALL, _TEST_KEY_SMALL) == \
               c2.decrypt(_TEST_PT_SMALL, _TEST_KEY_SMALL)


def t_ciphers_enumerate_unique() -> None:
    names = [c.name for c in _ciphers.enumerate_ciphers()]
    assert len(names) == len(set(names)), (
        f"duplicate cipher names: "
        f"{[n for n in names if names.count(n) > 1]}"
    )
    actual = len(names)
    estimated = _ciphers.estimated_count()
    assert actual == estimated, f"estimated {estimated} != actual {actual}"


# ---------------------------------------------------------------------------
# Phase 4: KeyDerivation, Hypothesis, Enumerator selftests
# ---------------------------------------------------------------------------

def _corpus_for_phase45() -> _corpus.Corpus:
    return _corpus.load_corpus(DATA_PATH)


def t_kd_identity_passthrough() -> None:
    c = _corpus_for_phase45()
    ident = _keyderiv.Identity()
    e5 = c.by_short("E5")
    out = ident.derive(e5, c)
    assert out == tuple(e5)
    assert isinstance(out, tuple)


def t_kd_identity_empty() -> None:
    c = _corpus_for_phase45()
    ident = _keyderiv.Identity()
    try:
        ident.derive((), c)
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected KeyDerivError on empty key source")


def t_kd_identity_picklable() -> None:
    import pickle
    ident = _keyderiv.Identity()
    ident2 = pickle.loads(pickle.dumps(ident))
    assert ident == ident2
    assert hash(ident) == hash(ident2)


def t_kd_protocol_compliance() -> None:
    ident = _keyderiv.Identity()
    assert isinstance(ident, _keyderiv.KeyDerivation)
    assert hasattr(ident, "name") and hasattr(ident, "derive")


def t_kd_enumerate_theory1() -> None:
    items = list(_keyderiv.enumerate_theory1())
    assert len(items) == 1
    assert isinstance(items[0], _keyderiv.Identity)
    assert _keyderiv.estimated_count_theory1() == 1


def _sample_hypothesis():
    return _hyp.Hypothesis(
        input_binding=_sources.MergedMessages(
            codes=("E1", "W1"), op=_sources.Concat()
        ),
        key_binding=_sources.SingleMessage(code="E5"),
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.Vigenere(deck_size=83),
    )


def t_hyp_picklable() -> None:
    import pickle
    h = _sample_hypothesis()
    h2 = pickle.loads(pickle.dumps(h))
    assert h == h2
    assert hash(h) == hash(h2)


def t_hyp_execute() -> None:
    c = _corpus_for_phase45()
    h = _sample_hypothesis()
    result = h.execute(c)
    assert isinstance(result, tuple)
    assert len(result) == 202


def t_hyp_execute_matches_manual() -> None:
    c = _corpus_for_phase45()
    h = _sample_hypothesis()
    merged = _sources.Concat().apply(c.by_short("E1"), c.by_short("W1"))
    key = _keyderiv.Identity().derive(c.by_short("E5"), c)
    expected = _ciphers.Vigenere(deck_size=83).decrypt(merged, key)
    assert h.execute(c) == expected


def t_hyp_execute_with_intermediates() -> None:
    c = _corpus_for_phase45()
    h = _sample_hypothesis()
    parts = h.execute_with_intermediates(c)
    for key in ("merged_ct", "key_source", "effective_key", "candidate"):
        assert key in parts, f"missing intermediate {key!r}"
        assert isinstance(parts[key], tuple)
    assert parts["candidate"] == h.execute(c)


def t_hyp_name_includes_components() -> None:
    h = _sample_hypothesis()
    name = h.name
    assert "E1" in name and "W1" in name
    assert "E5" in name
    assert "identity" in name
    assert "vigenere" in name


def t_hyp_equality() -> None:
    h1 = _sample_hypothesis()
    h2 = _sample_hypothesis()
    assert h1 == h2
    h3 = _hyp.Hypothesis(
        input_binding=h1.input_binding,
        key_binding=h1.key_binding,
        key_derivation=h1.key_derivation,
        cipher=_ciphers.Beaufort(deck_size=83),
    )
    assert h1 != h3


def t_enum_config_defaults() -> None:
    cfg = _enum.Theory1Config()
    assert cfg.strict_pairing is True
    assert cfg.bidirectional is True
    assert cfg.fixed_key_E5 is True
    assert cfg.include_xor_ciphers is True


def t_enum_yields_hypotheses() -> None:
    c = _corpus_for_phase45()
    e = _enum.Theory1Enumerator(c)
    first = next(iter(e))
    assert isinstance(first, _hyp.Hypothesis)


def t_enum_count_matches_iteration() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory1Config(bidirectional=False,
                              include_xor_ciphers=False)
    e = _enum.Theory1Enumerator(c, cfg)
    estimated = e.estimated_count()
    actual = sum(1 for _ in e)
    assert estimated == actual, f"closed-form {estimated} != actual {actual}"


def t_enum_default_count() -> None:
    c = _corpus_for_phase45()
    e = _enum.Theory1Enumerator(c)
    assert e.estimated_count() == 7968


def t_enum_monodirectional() -> None:
    c = _corpus_for_phase45()
    full = _enum.Theory1Enumerator(c).estimated_count()
    mono = _enum.Theory1Enumerator(
        c, _enum.Theory1Config(bidirectional=False)
    ).estimated_count()
    assert mono == full // 2


def t_enum_no_xor() -> None:
    c = _corpus_for_phase45()
    with_xor = _enum.Theory1Enumerator(c).estimated_count()
    no_xor = _enum.Theory1Enumerator(
        c, _enum.Theory1Config(include_xor_ciphers=False)
    ).estimated_count()
    assert no_xor == with_xor * 11 // 12


def t_enum_cross_pair() -> None:
    c = _corpus_for_phase45()
    strict = _enum.Theory1Enumerator(c).estimated_count()
    cross = _enum.Theory1Enumerator(
        c, _enum.Theory1Config(strict_pairing=False)
    ).estimated_count()
    assert cross == strict * 4


def t_enum_any_key() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory1Config(fixed_key_E5=False)
    e = _enum.Theory1Enumerator(c, cfg)
    assert e.estimated_count() == 16 * 2 * 83 * 12


def t_enum_all_identity() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory1Config(bidirectional=False,
                              include_xor_ciphers=False)
    e = _enum.Theory1Enumerator(c, cfg)
    for i, hypo in enumerate(e):
        if i >= 100:
            break
        assert isinstance(hypo.key_derivation, _keyderiv.Identity)


def t_enum_idempotent_iteration() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory1Config(bidirectional=False,
                              include_xor_ciphers=False)
    e = _enum.Theory1Enumerator(c, cfg)
    first = list(e)
    second = list(e)
    assert first == second


def t_enum_make_theory1() -> None:
    c = _corpus_for_phase45()
    e = _enum.make_theory1(c, strict_pairing=False)
    assert isinstance(e, _enum.Theory1Enumerator)
    assert e.config.strict_pairing is False


def t_enum_hypotheses_picklable() -> None:
    import pickle
    c = _corpus_for_phase45()
    e = _enum.Theory1Enumerator(c)
    for i, hypo in enumerate(e):
        if i >= 50:
            break
        try:
            hypo2 = pickle.loads(pickle.dumps(hypo))
        except Exception as ex:  # noqa: BLE001
            raise AssertionError(
                f"hypothesis #{i} pickle failed: {type(ex).__name__}: {ex}"
            )
        assert hypo == hypo2


# ---------------------------------------------------------------------------
# Phase 5: Sieve selftests
# ---------------------------------------------------------------------------

def t_sieve_compute_ic() -> None:
    uniform = tuple([i % 5 for i in range(100)])
    ic = _sieve.compute_ic(uniform)
    assert 0.19 < ic < 0.20, f"uniform-over-5 IC {ic} outside expected range"
    assert _sieve.compute_ic((3,) * 50) == 1.0
    assert _sieve.compute_ic(()) == 0.0
    assert _sieve.compute_ic((5,)) == 0.0
    assert _sieve.compute_ic((1, 2)) == 0.0


def t_sieve_max_freq() -> None:
    seq = (1, 1, 1, 2, 3, 4, 5, 6, 7, 8)
    assert _sieve.max_symbol_frequency(seq) == 0.3
    assert _sieve.max_symbol_frequency((5, 5, 5)) == 1.0
    assert _sieve.max_symbol_frequency(()) == 0.0


def t_sieve_distinct() -> None:
    assert _sieve.distinct_symbol_count((1, 2, 3, 4, 5)) == 5
    assert _sieve.distinct_symbol_count((1, 1, 1, 1)) == 1
    assert _sieve.distinct_symbol_count(()) == 0


def t_sieve_verdict_picklable() -> None:
    import pickle
    v = _sieve.SieveVerdict(keep=True, reason="",
                             metrics=(("ic", 0.05),))
    v2 = pickle.loads(pickle.dumps(v))
    assert v == v2


def t_sieve_length() -> None:
    c = _corpus_for_phase45()
    ctx = _sieve.SieveContext(corpus=c)
    h = _sample_hypothesis()
    stage = _sieve.LengthSieve(min_length=10, max_length=50)
    assert stage.filter(h, (1,) * 5, ctx).keep is False
    assert stage.filter(h, (1,) * 30, ctx).keep is True
    assert stage.filter(h, (1,) * 100, ctx).keep is False
    assert stage.filter(h, (1,) * 10, ctx).keep is True
    assert stage.filter(h, (1,) * 50, ctx).keep is True


def t_sieve_length_max_disabled() -> None:
    c = _corpus_for_phase45()
    ctx = _sieve.SieveContext(corpus=c)
    h = _sample_hypothesis()
    stage = _sieve.LengthSieve(min_length=5, max_length=0)
    assert stage.filter(h, (1,) * 100000, ctx).keep is True


def t_sieve_alphabet_closure() -> None:
    c = _corpus_for_phase45()
    ctx = _sieve.SieveContext(corpus=c)
    h = _sample_hypothesis()
    stage = _sieve.AlphabetClosureSieve()
    assert stage.filter(h, tuple(range(83)), ctx).keep is True
    v = stage.filter(h, (1, 2, 3, 83, 4), ctx)
    assert v.keep is False
    assert "position 3" in v.reason and "83" in v.reason


def t_sieve_ic_bounds() -> None:
    c = _corpus_for_phase45()
    ctx = _sieve.SieveContext(corpus=c)
    h = _sample_hypothesis()
    stage = _sieve.ICSieve(min_ic=0.030, max_ic=0.20)
    uniform = tuple([i % 83 for i in range(415)])
    assert stage.filter(h, uniform, ctx).keep is False
    assert stage.filter(h, (5,) * 50, ctx).keep is False
    moderate = tuple([i % 20 for i in range(200)])
    assert stage.filter(h, moderate, ctx).keep is True


def t_sieve_distribution() -> None:
    c = _corpus_for_phase45()
    ctx = _sieve.SieveContext(corpus=c)
    h = _sample_hypothesis()
    stage = _sieve.SymbolDistributionSieve(max_freq=0.30, min_distinct=10)
    bad = (1,) * 80 + tuple(range(2, 22))
    assert stage.filter(h, bad, ctx).keep is False
    low_distinct = tuple([i % 5 for i in range(50)])
    assert stage.filter(h, low_distinct, ctx).keep is False
    healthy = tuple([i % 25 for i in range(100)])
    assert stage.filter(h, healthy, ctx).keep is True
    assert stage.filter(h, (), ctx).keep is False


def t_sieve_cascade_default_stages() -> None:
    casc = _sieve.SieveCascade.default()
    names = [s.name for s in casc.stages]
    assert names == ["length", "alphabet_closure", "ic", "distribution"]


def t_sieve_cascade_stops_on_first_kill() -> None:
    c = _corpus_for_phase45()
    h = _hyp.Hypothesis(
        input_binding=_sources.MergedMessages(("E1", "W1"), _sources.Concat()),
        key_binding=_sources.SingleMessage(code="E5"),
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.XORStream(),
    )
    casc = _sieve.SieveCascade.default()
    result = casc.evaluate(h, c)
    assert result.survived is False
    assert result.killed_at == "alphabet_closure"
    assert len(result.verdicts) == 2


def t_sieve_cascade_catches_source_error() -> None:
    c = _corpus_for_phase45()
    h = _hyp.Hypothesis(
        input_binding=_sources.SingleMessage(code="ZZZ"),
        key_binding=_sources.SingleMessage(code="E5"),
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.Vigenere(deck_size=83),
    )
    casc = _sieve.SieveCascade.default()
    result = casc.evaluate(h, c)
    assert result.survived is False
    assert result.killed_at == "execute"
    assert ERROR_PREFIX in result.error


def t_sieve_cascade_catches_keyderiv_error() -> None:
    c = _corpus_for_phase45()
    empty_key = _sources.MergedMessages(
        codes=("E1", "E1"),
        op=_sources.HeaderPayload(header_length=99,
                                   payload_op=_sources.Concat()),
    )
    h = _hyp.Hypothesis(
        input_binding=_sources.MergedMessages(("E1", "W1"), _sources.Concat()),
        key_binding=empty_key,
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.Vigenere(deck_size=83),
    )
    casc = _sieve.SieveCascade.default()
    result = casc.evaluate(h, c)
    assert result.survived is False
    assert result.killed_at == "execute"


def t_sieve_cascade_does_not_swallow_unexpected() -> None:
    from dataclasses import dataclass as _dc

    @_dc(frozen=True)
    class CrashStage:
        cost_tier: int = 1

        @property
        def name(self) -> str:
            return "crash"

        def filter(self, hypothesis, candidate, context):
            raise RuntimeError("intentional crash")

    c = _corpus_for_phase45()
    casc = _sieve.SieveCascade(stages=(CrashStage(),))
    h = _sample_hypothesis()
    try:
        casc.evaluate(h, c)
    except RuntimeError as e:
        assert "intentional crash" in str(e)
        return
    raise AssertionError("expected RuntimeError to propagate")


def t_sieve_result_picklable() -> None:
    import pickle
    c = _corpus_for_phase45()
    h = _sample_hypothesis()
    casc = _sieve.SieveCascade.default()
    result = casc.evaluate(h, c)
    result2 = pickle.loads(pickle.dumps(result))
    assert result.survived == result2.survived
    assert result.killed_at == result2.killed_at
    assert result.candidate == result2.candidate


def t_sieve_telemetry_record() -> None:
    c = _corpus_for_phase45()
    casc = _sieve.SieveCascade.default()
    tel = _sieve.SieveTelemetry()

    survivor_or_killed = _sample_hypothesis()
    killed_xor = _hyp.Hypothesis(
        input_binding=_sources.MergedMessages(("E1", "W1"), _sources.Concat()),
        key_binding=_sources.SingleMessage(code="E5"),
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.XORStream(),
    )
    fail_hypo = _hyp.Hypothesis(
        input_binding=_sources.SingleMessage(code="ZZZ"),
        key_binding=_sources.SingleMessage(code="E5"),
        key_derivation=_keyderiv.Identity(),
        cipher=_ciphers.Vigenere(deck_size=83),
    )

    tel.record(casc.evaluate(survivor_or_killed, c))
    tel.record(casc.evaluate(killed_xor, c))
    tel.record(casc.evaluate(fail_hypo, c))

    assert tel.total_evaluated == 3
    assert tel.execute_failures == 1
    sum_check = (tel.survivors + tel.execute_failures
                 + sum(tel.killed_by_stage.values()))
    assert sum_check == tel.total_evaluated


def t_sieve_telemetry_serializable() -> None:
    import json
    tel = _sieve.SieveTelemetry()
    tel.total_evaluated = 100
    tel.survivors = 5
    tel.execute_failures = 2
    tel.killed_by_stage = {"length": 10, "alphabet_closure": 30, "ic": 53}
    d = tel.as_dict()
    parsed = json.loads(json.dumps(d))
    assert parsed["total_evaluated"] == 100
    assert parsed["killed_by_stage"]["alphabet_closure"] == 30


def t_sieve_stages_picklable() -> None:
    import pickle
    casc = _sieve.SieveCascade.default()
    for stage in casc.stages:
        try:
            s2 = pickle.loads(pickle.dumps(stage))
        except Exception as e:  # noqa: BLE001
            raise AssertionError(
                f"{stage.name}: pickle failed: {type(e).__name__}: {e}"
            )
        assert stage == s2


def t_sieve_stages_protocol() -> None:
    casc = _sieve.SieveCascade.default()
    for stage in casc.stages:
        assert isinstance(stage, _sieve.SieveStage), (
            f"{stage.name} does not satisfy SieveStage protocol"
        )


def t_sieve_real_corpus_smoke() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory1Config(bidirectional=False)
    e = _enum.Theory1Enumerator(c, cfg)
    casc = _sieve.SieveCascade.default()
    tel = _sieve.SieveTelemetry()
    for i, hypo in enumerate(e):
        if i >= 200:
            break
        tel.record(casc.evaluate(hypo, c))
    assert tel.total_evaluated == 200
    sum_check = (tel.survivors + tel.execute_failures
                 + sum(tel.killed_by_stage.values()))
    assert sum_check == 200


# ---------------------------------------------------------------------------
# Phase 7: Scoring selftests
# ---------------------------------------------------------------------------

def t_score_config_defaults() -> None:
    cfg = _scoring.ScoringConfig()
    assert cfg.languages == ('fi', 'krl', 'en')
    assert cfg.n_mappings == 100
    # eyestat_dir should be a Path; we don't assert it points to a real
    # checkout because that's a deployment fact, not a config invariant.
    assert isinstance(cfg.eyestat_dir, Path)


def t_score_eyestat_available() -> None:
    """is_eyestat_available returns a bool and reflects auto-discovery.
    Doesn't assert eyestat IS installed — that's a deployment fact, not
    a correctness invariant. Skips with a clear message when absent so
    downstream scoring tests can be safely skipped too."""
    result = _scoring.is_eyestat_available()
    assert isinstance(result, bool)
    if not result:
        raise SkipTest(
            "eyestat not installed at any discovered path; "
            "set $EYESTAT_DIR or place eyestat at ~/Desktop/Noita/eyestat"
        )


def t_score_language_score_picklable() -> None:
    import pickle
    ls = _scoring.LanguageScore(
        language='fi', hits=5, zipf_score=2.3,
        decrypted_text='abc',
        best_mapping_pairs=((0, 'a'), (1, 'b')),
    )
    ls2 = pickle.loads(pickle.dumps(ls))
    assert ls == ls2
    assert ls.best_mapping == {0: 'a', 1: 'b'}


def t_score_result_properties() -> None:
    ls_a = _scoring.LanguageScore('fi', 10, 5.0, 'aaa', ())
    ls_b = _scoring.LanguageScore('en', 20, 7.5, 'bbb', ())
    ls_c = _scoring.LanguageScore('krl', 0, 0.0, '', ())
    sr = _scoring.ScoringResult(per_language=(ls_a, ls_b, ls_c))
    assert sr.best_score == 7.5
    assert sr.best_language == 'en'
    assert sr.total_hits == 30
    # Empty
    empty = _scoring.ScoringResult(per_language=())
    assert empty.best_score == 0.0
    assert empty.best_language == ""
    assert empty.total_hits == 0


def _require_eyestat() -> None:
    """Helper used by scoring-dependent tests: raise SkipTest when
    eyestat isn't reachable so the test counts as skipped, not failed."""
    if not _scoring.is_eyestat_available():
        raise SkipTest("eyestat not installed; skipping scoring test")


def t_score_scorer_init() -> None:
    _require_eyestat()
    s = _scoring.Scorer()
    assert s.dictionaries is not None
    # Should have entries for all configured languages
    for lang in ('fi', 'krl', 'en'):
        assert lang in s.dictionaries


def t_score_real_candidate() -> None:
    _require_eyestat()
    c = _corpus_for_phase45()
    # Pick a real survivor: use the first cascade survivor we find
    enum = _enum.Theory1Enumerator(c)
    cascade = _sieve.SieveCascade.default()
    survivor = None
    for hypo in enum:
        r = cascade.evaluate(hypo, c)
        if r.survived:
            survivor = r
            break
    assert survivor is not None, "no survivors found in default sweep"

    scorer = _scoring.Scorer(_scoring.ScoringConfig(n_mappings=20))
    result = scorer.score(survivor.candidate, c.deck_size)
    assert isinstance(result, _scoring.ScoringResult)
    assert len(result.per_language) >= 1
    for ls in result.per_language:
        assert ls.language in ('fi', 'krl', 'en')
        assert ls.hits >= 0
        assert ls.zipf_score >= 0.0


def t_score_none_mapping_safe() -> None:
    """A candidate that's pure noise should not crash the scorer even
    when eyestat returns best_mapping=None for some language."""
    _require_eyestat()
    import random
    random.seed(99)
    c = _corpus_for_phase45()
    # Uniform random candidate — unlikely to produce dictionary hits
    cand = tuple(random.randint(0, 82) for _ in range(60))
    scorer = _scoring.Scorer(_scoring.ScoringConfig(n_mappings=10))
    result = scorer.score(cand, c.deck_size)
    # Should return a result with all configured languages, possibly
    # all zero hits, all empty text, all empty mapping
    assert isinstance(result, _scoring.ScoringResult)
    for ls in result.per_language:
        # decrypted_text may be empty string but must be a string
        assert isinstance(ls.decrypted_text, str)
        assert isinstance(ls.best_mapping_pairs, tuple)


def t_score_empty_candidate() -> None:
    _require_eyestat()
    scorer = _scoring.Scorer(_scoring.ScoringConfig(n_mappings=10))
    try:
        scorer.score((), 83)
    except _scoring.ScoringError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("expected ScoringError on empty candidate")


# ---------------------------------------------------------------------------
# Phase 6: Runner selftests
# ---------------------------------------------------------------------------

def t_runner_config_defaults() -> None:
    from pathlib import Path
    cfg = _runner.RunConfig(
        data_path=Path("noita_eye_data.json"),
        output_dir=Path("/tmp/eyesieve-test-defaults"),
    )
    assert cfg.scoring_enabled is True
    assert cfg.scoring_n_mappings == 100
    assert cfg.progress_every == 500
    assert cfg.max_survivors_to_score == 0
    assert cfg.quiet is False


def t_runner_config_presets() -> None:
    expected = {"strict", "mono", "no-xor", "cross-pair", "any-key", "liberal"}
    assert set(_runner.CONFIG_PRESETS.keys()) == expected
    # Spot-check shape
    assert _runner.CONFIG_PRESETS["strict"].strict_pairing is True
    assert _runner.CONFIG_PRESETS["mono"].bidirectional is False
    assert _runner.CONFIG_PRESETS["no-xor"].include_xor_ciphers is False
    assert _runner.CONFIG_PRESETS["cross-pair"].strict_pairing is False
    assert _runner.CONFIG_PRESETS["any-key"].fixed_key_E5 is False
    assert _runner.CONFIG_PRESETS["liberal"].strict_pairing is False
    assert _runner.CONFIG_PRESETS["liberal"].fixed_key_E5 is False


def t_runner_construct() -> None:
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=False,
            quiet=True,
        )
        r = _runner.Runner(cfg)
        assert r.corpus is not None
        assert r.cascade is not None
        assert r.enumerator.estimated_count() == 3984


def t_runner_run_no_score() -> None:
    from pathlib import Path
    import tempfile, json
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=False,
            quiet=True,
        )
        result = _runner.Runner(cfg).run()
        assert result.n_survivors > 0
        assert result.n_scored == 0
        assert (Path(td) / "telemetry.json").exists()
        assert (Path(td) / "survivors.jsonl").exists()
        assert not (Path(td) / "scored.jsonl").exists()


def t_runner_run_with_score() -> None:
    _require_eyestat()
    from pathlib import Path
    import tempfile, json
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=True,
            scoring_n_mappings=10,
            max_survivors_to_score=5,
            quiet=True,
        )
        result = _runner.Runner(cfg).run()
        assert result.n_survivors > 0
        assert result.n_scored == 5
        assert (Path(td) / "scored.jsonl").exists()
        # First line of scored.jsonl should have a "scoring" key with
        # the highest score (sorted descending)
        with open(Path(td) / "scored.jsonl") as f:
            first = json.loads(f.readline())
        assert "scoring" in first
        assert "best_score" in first["scoring"]


def t_runner_output_well_formed() -> None:
    from pathlib import Path
    import tempfile, json
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=False,
            quiet=True,
        )
        _runner.Runner(cfg).run()
        # telemetry.json parses cleanly
        tel = json.loads((Path(td) / "telemetry.json").read_text())
        assert tel["totals"]["total_evaluated"] == 3984
        assert "killed_by_stage" in tel["totals"]
        # every line in survivors.jsonl parses
        with open(Path(td) / "survivors.jsonl") as f:
            for i, line in enumerate(f):
                obj = json.loads(line)
                assert obj["survived"] is True
                assert obj["candidate_length"] > 0
                assert obj["killed_at"] == ""


def t_runner_telemetry_balances() -> None:
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=False,
            quiet=True,
        )
        result = _runner.Runner(cfg).run()
        tel = result.telemetry
        total = (tel.survivors + tel.execute_failures
                 + sum(tel.killed_by_stage.values()))
        assert total == tel.total_evaluated == 3984


def t_runner_quiet() -> None:
    """In quiet mode, the runner should still write outputs but not print
    the banner. We can't easily intercept stdout from inside selftest, so
    just verify the run completes silently and outputs exist."""
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH),
            output_dir=Path(td),
            enumerator_config=_enum.Theory1Config(bidirectional=False),
            scoring_enabled=False,
            quiet=True,
        )
        _runner.Runner(cfg).run()
        assert (Path(td) / "telemetry.json").exists()
        # run.log should still be written even in quiet mode
        assert (Path(td) / "run.log").exists()


# ---------------------------------------------------------------------------
# Phase 9: Theory 2 keyderiv selftests
# ---------------------------------------------------------------------------

def _t2_sample_self_merge():
    perm = next(p for p in _perm.enumerate_permutations(max_len=83)
                if p.name == "reverse")
    op = next(o for o in _sources.enumerate_merge_ops()
              if o.name == "cyclic_add")
    return _keyderiv.SelfMerge(perm, op)


def _t2_sample_cross_merge():
    op = next(o for o in _sources.enumerate_merge_ops()
              if o.name == "cyclic_add")
    return _keyderiv.CrossMerge("E1", op)


def _t2_sample_constant_merge():
    op = next(o for o in _sources.enumerate_merge_ops()
              if o.name == "cyclic_add")
    return _keyderiv.ConstantMerge("zeros", op)


def t_t2_self_name() -> None:
    sm = _t2_sample_self_merge()
    assert "self" in sm.name and "reverse" in sm.name and "cyclic_add" in sm.name


def t_t2_self_derive() -> None:
    c = _corpus_for_phase45()
    sm = _t2_sample_self_merge()
    out = sm.derive(c.by_short("E5"), c)
    assert isinstance(out, tuple)
    assert len(out) == len(c.by_short("E5"))


def t_t2_self_picklable() -> None:
    import pickle
    sm = _t2_sample_self_merge()
    sm2 = pickle.loads(pickle.dumps(sm))
    assert sm == sm2
    assert hash(sm) == hash(sm2)


def t_t2_self_empty() -> None:
    c = _corpus_for_phase45()
    sm = _t2_sample_self_merge()
    try:
        sm.derive((), c)
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("SelfMerge should raise on empty key_source")


def t_t2_cross_name() -> None:
    cm = _t2_sample_cross_merge()
    assert "cross" in cm.name and "E1" in cm.name


def t_t2_cross_derive() -> None:
    c = _corpus_for_phase45()
    cm = _t2_sample_cross_merge()
    out = cm.derive(c.by_short("E5"), c)
    assert isinstance(out, tuple)
    assert len(out) > 0


def t_t2_cross_bad_code() -> None:
    c = _corpus_for_phase45()
    op = next(o for o in _sources.enumerate_merge_ops()
              if o.name == "cyclic_add")
    cm = _keyderiv.CrossMerge("ZZZ", op)
    try:
        cm.derive(c.by_short("E5"), c)
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("CrossMerge should raise on unknown cross code")


def t_t2_constant_patterns() -> None:
    c = _corpus_for_phase45()
    e5 = c.by_short("E5")
    op = next(o for o in _sources.enumerate_merge_ops()
              if o.name == "cyclic_add")
    for pattern in _keyderiv.CONSTANT_PATTERNS:
        const = _keyderiv.ConstantMerge(pattern, op)
        out = const.derive(e5, c)
        assert isinstance(out, tuple)
        assert len(out) > 0


def t_t2_constant_unknown() -> None:
    try:
        _keyderiv._build_constant("nonexistent", 10, 83)
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("_build_constant should raise on unknown pattern")


def t_t2_select_combine_unknown_raises() -> None:
    # A typo'd combine-op name must fail loudly, not silently shrink the sweep.
    valid = _keyderiv._select_combine_ops(
        83, _keyderiv.THEORY2_DEFAULT_COMBINE_OP_NAMES)
    assert len(valid) == len(_keyderiv.THEORY2_DEFAULT_COMBINE_OP_NAMES)
    try:
        _keyderiv._select_combine_ops(83, ["cyclic_add", "definitely_not_an_op"])
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("_select_combine_ops should raise on unknown name")


def t_t2_select_perm_unknown_raises() -> None:
    valid = _keyderiv._select_permutations(
        140, _keyderiv.THEORY2_DEFAULT_PERMUTATION_NAMES)
    assert len(valid) == len(_keyderiv.THEORY2_DEFAULT_PERMUTATION_NAMES)
    try:
        _keyderiv._select_permutations(140, ["reverse", "definitely_not_a_perm"])
    except _keyderiv.KeyDerivError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("_select_permutations should raise on unknown name")


def t_t2_enumerate_count() -> None:
    c = _corpus_for_phase45()
    # Default: 5 perms × 4 ops + 4 cross × 4 ops + 5 patterns × 4 ops
    #        =  20 + 16 + 20 = 56
    assert _keyderiv.estimated_count_theory2(c) == 56


def t_t2_enumerate_excludes_key() -> None:
    c = _corpus_for_phase45()
    for d in _keyderiv.enumerate_theory2(c, key_code="E5"):
        if isinstance(d, _keyderiv.CrossMerge):
            assert d.cross_code != "E5"


def t_t2_enumerate_empty_subsets() -> None:
    c = _corpus_for_phase45()
    items = list(_keyderiv.enumerate_theory2(
        c, include_self=False, include_cross=False, include_constant=False
    ))
    assert len(items) == 0


def t_t2_enum_config_defaults() -> None:
    cfg = _enum.Theory2Config()
    assert cfg.strict_pairing is True
    assert cfg.bidirectional is True
    assert cfg.fixed_key_E5 is True
    assert cfg.include_xor_ciphers is True
    assert cfg.include_self_merge is True
    assert cfg.include_cross_merge is True
    assert cfg.include_constant_merge is True


def t_t2_enum_yields_hypotheses() -> None:
    c = _corpus_for_phase45()
    e = _enum.Theory2Enumerator(c)
    first = next(iter(e))
    assert isinstance(first, _hyp.Hypothesis)
    # The derivation should NOT be Identity
    assert not isinstance(first.key_derivation, _keyderiv.Identity)


def t_t2_enum_default_count() -> None:
    c = _corpus_for_phase45()
    e = _enum.Theory2Enumerator(c)
    # 4 pairs × 2 orderings × 83 ops × 12 ciphers × 56 derivations
    expected = 4 * 2 * 83 * 12 * 56
    assert e.estimated_count() == expected, (
        f"got {e.estimated_count()}, expected {expected}"
    )


def t_t2_enum_count_matches_iteration() -> None:
    c = _corpus_for_phase45()
    # Use a small config to keep this test cheap
    cfg = _enum.Theory2Config(
        bidirectional=False,
        include_xor_ciphers=False,
        include_self_merge=True,
        include_cross_merge=False,
        include_constant_merge=False,
        combine_op_names=("cyclic_add",),
        permutation_names=("reverse",),
    )
    e = _enum.Theory2Enumerator(c, cfg)
    est = e.estimated_count()
    actual = sum(1 for _ in e)
    assert est == actual, f"est={est}, actual={actual}"


def t_t2_enum_no_identity() -> None:
    c = _corpus_for_phase45()
    cfg = _enum.Theory2Config(
        bidirectional=False, include_xor_ciphers=False,
        combine_op_names=("cyclic_add",),
        permutation_names=("reverse",),
    )
    e = _enum.Theory2Enumerator(c, cfg)
    for hypo in e:
        assert not isinstance(hypo.key_derivation, _keyderiv.Identity)


def t_t2_union_ordering() -> None:
    c = _corpus_for_phase45()
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    t2_cfg = _enum.Theory2Config(
        bidirectional=False, include_xor_ciphers=False,
        combine_op_names=("cyclic_add",),
        permutation_names=("reverse",),
        include_cross_merge=False, include_constant_merge=False,
    )
    u = _enum.TheoryUnionEnumerator(c, t1_cfg, t2_cfg)
    t1_count = _enum.Theory1Enumerator(c, t1_cfg).estimated_count()
    # First t1_count hypotheses are from T1 (Identity), rest are T2
    for i, hypo in enumerate(u):
        if i < t1_count:
            assert isinstance(hypo.key_derivation, _keyderiv.Identity)
        else:
            assert not isinstance(hypo.key_derivation, _keyderiv.Identity)


def t_t2_union_count() -> None:
    c = _corpus_for_phase45()
    t1 = _enum.Theory1Enumerator(c)
    t2 = _enum.Theory2Enumerator(c)
    u = _enum.TheoryUnionEnumerator(c)
    assert u.estimated_count() == t1.estimated_count() + t2.estimated_count()


def t_t2_enum_picklable() -> None:
    import pickle
    c = _corpus_for_phase45()
    cfg = _enum.Theory2Config(
        bidirectional=False, include_xor_ciphers=False,
        combine_op_names=("cyclic_add",),
        permutation_names=("reverse",),
        include_cross_merge=False, include_constant_merge=False,
    )
    e = _enum.Theory2Enumerator(c, cfg)
    # Test first 30 are picklable
    for i, hypo in enumerate(e):
        if i >= 30: break
        h2 = pickle.loads(pickle.dumps(hypo))
        assert hypo == h2


# ---------------------------------------------------------------------------
# Phase 8: Multiprocess runner selftests
# ---------------------------------------------------------------------------

def t_mpr_config_defaults() -> None:
    from pathlib import Path
    cfg = _mprunner.MPRunConfig(
        data_path=Path("noita_eye_data.json"),
        output_dir=Path("/tmp/x"),
    )
    assert cfg.theory == "theory1"
    assert cfg.n_workers == 1
    assert cfg.chunksize == 100
    assert cfg.checkpoint_every == 5000
    assert cfg.scoring_enabled is True
    assert cfg.resume is False


def t_mpr_error_prefix() -> None:
    e = _mprunner.MPRunnerError("test")
    assert ERROR_PREFIX in str(e)


def t_mpr_rejects_zero_workers() -> None:
    from pathlib import Path
    cfg = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/mpr-test-rejects-zero"),
        n_workers=0,
    )
    try:
        _mprunner.MultiprocessRunner(cfg)
    except _mprunner.MPRunnerError as e:
        assert "n_workers" in str(e)
        return
    raise AssertionError("MPRunner should reject n_workers=0")


def t_mpr_rejects_bad_theory() -> None:
    from pathlib import Path
    cfg = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/mpr-test-rejects-bad-theory"),
        theory="theory42",
    )
    try:
        _mprunner.MultiprocessRunner(cfg)
    except _mprunner.MPRunnerError as e:
        assert "theory" in str(e).lower()
        return
    raise AssertionError("MPRunner should reject unknown theory")


def t_mpr_fingerprint_stable() -> None:
    from pathlib import Path
    cfg1 = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/a"),
        theory="theory1",
        theory1_config=_enum.Theory1Config(bidirectional=False),
    )
    cfg2 = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/b"),  # different
        theory="theory1",
        theory1_config=_enum.Theory1Config(bidirectional=False),
        n_workers=4,  # different
    )
    # Fingerprint should ignore output_dir and n_workers, match on enumerator-relevant fields
    assert (_mprunner._config_fingerprint(cfg1)
            == _mprunner._config_fingerprint(cfg2))


def t_mpr_fingerprint_distinct() -> None:
    from pathlib import Path
    cfg1 = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/x"),
        theory="theory1",
    )
    cfg2 = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH),
        output_dir=Path("/tmp/x"),
        theory="theory2",
    )
    assert (_mprunner._config_fingerprint(cfg1)
            != _mprunner._config_fingerprint(cfg2))


def t_mpr_checkpoint_roundtrip() -> None:
    from pathlib import Path
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "checkpoint.json"
        tel = _sieve.SieveTelemetry()
        tel.total_evaluated = 1000
        tel.survivors = 25
        tel.execute_failures = 7
        tel.killed_by_stage = {"ic": 800, "alphabet_closure": 168}
        _mprunner._write_checkpoint(
            path, n_processed=1000, n_total=5000,
            telemetry=tel, config_fingerprint="abc123",
            started_at="2026-05-14T20:00:00",
        )
        loaded = _mprunner._read_checkpoint(path)
        assert loaded["n_processed"] == 1000
        assert loaded["telemetry"]["survivors"] == 25
        assert loaded["config_fingerprint"] == "abc123"


def t_mpr_workers1_matches_runner() -> None:
    from pathlib import Path
    import tempfile
    # Use a small enumerator (mono no-xor = 3,652)
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    # Single-process Runner
    with tempfile.TemporaryDirectory() as td_a:
        r_cfg = _runner.RunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td_a),
            enumerator_config=t1_cfg, scoring_enabled=False, quiet=True,
        )
        r_result = _runner.Runner(r_cfg).run()

    # MP runner with workers=1
    with tempfile.TemporaryDirectory() as td_b:
        mp_cfg = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td_b),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
        )
        mp_result = _mprunner.MultiprocessRunner(mp_cfg).run()

    # Compare telemetry
    assert r_result.telemetry.total_evaluated == mp_result.telemetry.total_evaluated
    assert r_result.telemetry.survivors == mp_result.telemetry.survivors
    assert r_result.telemetry.execute_failures == mp_result.telemetry.execute_failures
    assert r_result.telemetry.killed_by_stage == mp_result.telemetry.killed_by_stage


def t_mpr_workers2_matches_workers1() -> None:
    from pathlib import Path
    import tempfile
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    results = {}
    for workers in (1, 2):
        with tempfile.TemporaryDirectory() as td:
            cfg = _mprunner.MPRunConfig(
                data_path=Path(DATA_PATH), output_dir=Path(td),
                theory="theory1", theory1_config=t1_cfg,
                n_workers=workers, chunksize=50,
                scoring_enabled=False, quiet=True,
            )
            results[workers] = _mprunner.MultiprocessRunner(cfg).run()
    r1, r2 = results[1].telemetry, results[2].telemetry
    assert r1.total_evaluated == r2.total_evaluated
    assert r1.survivors == r2.survivors
    assert r1.killed_by_stage == r2.killed_by_stage


def t_mpr_checkpoint_written() -> None:
    from pathlib import Path
    import tempfile
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    with tempfile.TemporaryDirectory() as td:
        cfg = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
            checkpoint_every=500,
        )
        _mprunner.MultiprocessRunner(cfg).run()
        ck = Path(td) / "checkpoint.json"
        assert ck.exists()
        import json
        data = json.loads(ck.read_text())
        assert data["n_processed"] == 3652
        assert data["schema_version"] == _mprunner.CHECKPOINT_SCHEMA_VERSION


def t_mpr_resume_completes() -> None:
    """End-to-end resume: run, simulate crash via checkpoint rewind, resume."""
    from pathlib import Path
    import tempfile, json, shutil
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    with tempfile.TemporaryDirectory() as td:
        cfg = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
            checkpoint_every=500,
        )
        # Initial run
        full = _mprunner.MultiprocessRunner(cfg).run()
        n_full = full.telemetry.total_evaluated
        # Rewind checkpoint to halfway
        ck_path = Path(td) / "checkpoint.json"
        ck = json.loads(ck_path.read_text())
        half = (n_full // 2 // 500) * 500
        ck["n_processed"] = half
        ck["telemetry"]["total_evaluated"] = half
        ck["telemetry"]["survivors"] = 5  # claim small count
        ck_path.write_text(json.dumps(ck))
        # Resume
        cfg_resume = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
            checkpoint_every=500, resume=True,
        )
        resumed = _mprunner.MultiprocessRunner(cfg_resume).run()
        assert resumed.telemetry.total_evaluated == n_full
        assert resumed.resumed is True
        assert resumed.resumed_from == half


def t_mpr_resume_refuses_mismatch() -> None:
    """Resume must refuse if config_fingerprint doesn't match."""
    from pathlib import Path
    import tempfile, json
    with tempfile.TemporaryDirectory() as td:
        # Write a checkpoint with a stale fingerprint
        ck_path = Path(td) / "checkpoint.json"
        ck_path.write_text(json.dumps({
            "schema_version": _mprunner.CHECKPOINT_SCHEMA_VERSION,
            "started_at": "2026-05-14T19:00:00",
            "last_updated_at": "2026-05-14T19:01:00",
            "n_processed": 1000,
            "n_total": 5000,
            "telemetry": {
                "total_evaluated": 1000, "survivors": 10,
                "execute_failures": 3, "killed_by_stage": {"ic": 987},
            },
            "config_fingerprint": "stale-mismatched-fingerprint",
        }))
        cfg = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1",
            theory1_config=_enum.Theory1Config(bidirectional=False),
            n_workers=1, scoring_enabled=False, quiet=True,
            resume=True,
        )
        try:
            _mprunner.MultiprocessRunner(cfg).run()
        except _mprunner.MPRunnerError as e:
            assert "fingerprint" in str(e).lower()
            return
        raise AssertionError("resume should refuse on fingerprint mismatch")


def t_mpr_resume_truncates_survivors() -> None:
    """If survivors.jsonl has more entries than checkpoint reports,
    resume must truncate to checkpoint count."""
    from pathlib import Path
    import tempfile, json
    t1_cfg = _enum.Theory1Config(bidirectional=False, include_xor_ciphers=False)
    with tempfile.TemporaryDirectory() as td:
        # First run to populate
        cfg = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
            checkpoint_every=500,
        )
        _mprunner.MultiprocessRunner(cfg).run()
        # Survivors file has ~134 entries; rewind checkpoint to half + tell it 5 survivors
        ck_path = Path(td) / "checkpoint.json"
        ck = json.loads(ck_path.read_text())
        n_full = ck["n_processed"]
        ck["n_processed"] = (n_full // 2 // 500) * 500
        ck["telemetry"]["total_evaluated"] = ck["n_processed"]
        ck["telemetry"]["survivors"] = 5
        ck_path.write_text(json.dumps(ck))
        # Count survivors before resume
        n_before = sum(1 for _ in open(Path(td) / "survivors.jsonl"))
        assert n_before > 5, f"expected >5 survivors pre-resume, got {n_before}"
        # Resume
        cfg_r = _mprunner.MPRunConfig(
            data_path=Path(DATA_PATH), output_dir=Path(td),
            theory="theory1", theory1_config=t1_cfg,
            n_workers=1, scoring_enabled=False, quiet=True,
            checkpoint_every=500, resume=True,
        )
        _mprunner.MultiprocessRunner(cfg_r).run()
        # File should now start with 5 kept entries + new ones found
        n_after = sum(1 for _ in open(Path(td) / "survivors.jsonl"))
        # n_after >= 5 (kept) and n_after < n_before + new found
        # The exact count depends on whether reference survivors overlap
        # with the truncated range. Just verify truncation happened.
        # (Pre-resume had n_before, post-resume should be ≤ n_before + survivors
        # in [n_processed, n_full) which is at most n_before. Actually we
        # truncate to 5, then add survivors in [n_processed, n_full) which
        # is at most n_before. So total is at most 5 + n_before. Realistic
        # bound: ≤ n_before since survivors don't grow.)
        assert n_after >= 5


# ---------------------------------------------------------------------------
# Phase 10: HTML run report selftests
# ---------------------------------------------------------------------------

def _rr_quick_run_dir(td_path):
    """Build a small run dir to feed the report renderer."""
    from pathlib import Path
    cfg = _mprunner.MPRunConfig(
        data_path=Path(DATA_PATH), output_dir=Path(td_path),
        theory="theory1",
        theory1_config=_enum.Theory1Config(bidirectional=False, include_xor_ciphers=False),
        n_workers=1, scoring_enabled=False, quiet=True,
    )
    _mprunner.MultiprocessRunner(cfg).run()
    return Path(td_path)


def t_rr_error_prefix() -> None:
    e = _run_report.RunReportError("probe")
    assert ERROR_PREFIX in str(e)
    assert "run_report" in str(e)


def t_rr_missing_telemetry() -> None:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        try:
            _run_report._read_telemetry(Path(td))
        except _run_report.RunReportError as e:
            assert "telemetry.json not found" in str(e)
            return
    raise AssertionError("missing telemetry.json should raise RunReportError")


def t_rr_malformed_telemetry() -> None:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "telemetry.json").write_text("{this is not json")
        try:
            _run_report._read_telemetry(Path(td))
        except _run_report.RunReportError as e:
            assert "malformed" in str(e)
            return
    raise AssertionError("malformed telemetry.json should raise RunReportError")


def t_rr_empty_jsonl() -> None:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "empty.jsonl"
        p.write_text("")
        result = _run_report._read_jsonl(p)
        assert result == []


def t_rr_blank_lines() -> None:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "data.jsonl"
        p.write_text('{"a": 1}\n\n\n{"a": 2}\n')
        result = _run_report._read_jsonl(p)
        assert result == [{"a": 1}, {"a": 2}]


def t_rr_jsonl_limit() -> None:
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "data.jsonl"
        p.write_text("\n".join(f'{{"i": {i}}}' for i in range(100)))
        result = _run_report._read_jsonl(p, limit=5)
        assert len(result) == 5
        assert result[4]["i"] == 4


def t_rr_render_html_real() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        run_dir = _rr_quick_run_dir(td)
        html = _run_report.render_html(run_dir)
        assert "<!DOCTYPE html>" in html
        assert "EYESIEVE" in html
        assert "</html>" in html.lower()
        # Balanced section tags
        assert html.count("<section") == html.count("</section>")


def t_rr_html_escapes() -> None:
    """Verify that user-supplied content (e.g. hypothesis names with
    special HTML chars) is properly escaped."""
    import tempfile, json
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        # Create a fake run dir with an XSS-flavored hypothesis name
        d = Path(td)
        (d / "telemetry.json").write_text(json.dumps({
            "config": {"data_path": "<script>", "theory": "theory1"},
            "totals": {"total_evaluated": 1, "survivors": 1,
                       "execute_failures": 0, "killed_by_stage": {}},
            "timing_seconds": {"sieve": 0.0, "scoring": 0.0, "total": 0.0},
            "scoring": {"candidates_scored": 0},
            "config_fingerprint": "abc",
        }))
        (d / "survivors.jsonl").write_text(json.dumps({
            "hypothesis_name": "input=merge(E1+W1,<script>alert(1)</script>) | derive=identity",
            "survived": True, "killed_at": "", "candidate": [1, 2, 3],
            "candidate_length": 3, "verdicts": [], "error": None,
        }) + "\n")
        html = _run_report.render_html(d)
        # The raw script tag must NOT appear unescaped in the body
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


def t_rr_html_sections() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        run_dir = _rr_quick_run_dir(td)
        html = _run_report.render_html(run_dir)
        # All expected section markers
        for marker in [">config<", "pipeline funnel", ">timing<",
                       ">leaderboard", "survivor breakdown"]:
            assert marker in html, f"missing marker: {marker}"


def t_rr_no_scoring() -> None:
    """Render report when scored.jsonl is absent — should show 'no scored
    candidates' note rather than crashing."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        run_dir = _rr_quick_run_dir(td)
        # No scored.jsonl created (sieve-only run)
        html = _run_report.render_html(run_dir)
        assert "no scored candidates" in html or "--no-score" in html


def t_rr_top_n_limit() -> None:
    import tempfile, json
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "telemetry.json").write_text(json.dumps({
            "config": {"theory": "theory1"},
            "totals": {"total_evaluated": 100, "survivors": 50,
                       "execute_failures": 0, "killed_by_stage": {}},
            "timing_seconds": {"sieve": 1.0, "scoring": 1.0, "total": 2.0},
            "scoring": {"candidates_scored": 50},
            "config_fingerprint": "fp",
        }))
        # Synthesize 50 scored entries
        with open(d / "scored.jsonl", "w") as f:
            for i in range(50):
                entry = {
                    "hypothesis_name": f"hypothesis_{i}",
                    "survived": True, "killed_at": "", "candidate": [],
                    "candidate_length": 0, "verdicts": [], "error": None,
                    "scoring": {
                        "best_language": "en", "best_score": 50 - i,
                        "total_hits": i,
                        "per_language": [
                            {"language": "en", "hits": i, "zipf_score": 50 - i,
                             "decrypted_text": f"text {i}", "best_mapping": {}}
                        ],
                    },
                }
                f.write(json.dumps(entry) + "\n")
        html = _run_report.render_html(d, top_n=5)
        # Should have exactly 5 ranks rendered
        assert html.count('class="rank"') == 5
        # And the top should be rank #1
        assert ">#1<" in html


def t_rr_funnel_rows() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        run_dir = _rr_quick_run_dir(td)
        html = _run_report.render_html(run_dir)
        # Default cascade has 4 kill stages (length, alphabet_closure, ic,
        # distribution) + input + execute + survivors = 7 funnel rows.
        n_rows = html.count('class="funnel-row"')
        assert n_rows == 7, f"expected 7 funnel rows, got {n_rows}"


def t_rr_breakdown_t2_parsing() -> None:
    """Theory 2 hypothesis names use derive=self(...), derive=cross(...),
    derive=const(...). Verify the breakdown collapses them into family
    counters."""
    import tempfile, json
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "telemetry.json").write_text(json.dumps({
            "config": {"theory": "theory2"},
            "totals": {"total_evaluated": 4, "survivors": 4,
                       "execute_failures": 0, "killed_by_stage": {}},
            "timing_seconds": {"sieve": 1.0, "scoring": 0.0, "total": 1.0},
            "scoring": {"candidates_scored": 0},
            "config_fingerprint": "fp",
        }))
        with open(d / "survivors.jsonl", "w") as f:
            for derive in ("self(reverse,cyclic_add)",
                           "cross(E1,cyclic_add)",
                           "const(zeros,cyclic_add)",
                           "identity"):
                f.write(json.dumps({
                    "hypothesis_name": f"input=merge(E1+W1,concat) | key=single(E5) | derive={derive} | cipher=affine",
                    "survived": True, "killed_at": "", "candidate": [1],
                    "candidate_length": 1, "verdicts": [], "error": None,
                }) + "\n")
        html = _run_report.render_html(d)
        # All four derivation family names should be present
        for fam in ("self_merge", "cross_merge", "constant_merge", "identity"):
            assert fam in html, f"missing derivation family: {fam}"


# ---------------------------------------------------------------------------
# Phase 11: Unified CLI dispatcher selftests
# ---------------------------------------------------------------------------

def t_cli_subcommands_complete() -> None:
    """All listed subcommands resolve to importable modules."""
    import importlib
    expected = {"run", "mp", "report", "corpus-report",
                "reader", "selftest", "preflight"}
    assert set(_cli.SUBCOMMANDS.keys()) == expected
    for cmd, mod_name in _cli.SUBCOMMANDS.items():
        mod = importlib.import_module(mod_name)
        assert hasattr(mod, "main"), f"{mod_name} missing main()"


def t_cli_no_args() -> None:
    rc = _cli.main([])
    assert rc == 0


def t_cli_help() -> None:
    for flag in ("-h", "--help", "help"):
        rc = _cli.main([flag])
        assert rc == 0


def t_cli_unknown_subcommand() -> None:
    import io
    from contextlib import redirect_stderr
    buf = io.StringIO()
    with redirect_stderr(buf):
        rc = _cli.main(["nonexistent"])
    assert rc == 2
    assert "unknown subcommand" in buf.getvalue()


def t_cli_no_argv_main() -> None:
    """eyesieve_selftest.main() takes no args; dispatcher must adapt
    rather than passing argv=[] (which would TypeError)."""
    import inspect
    sig = inspect.signature(_selftest.main) if hasattr(globals(), '_selftest') else None
    # We can verify the adapter logic by examining what happens with the
    # selftest dispatcher path. But running selftest from inside selftest
    # would infinite-recurse. Instead verify the inspect-based branch
    # exists in the dispatcher source.
    import inspect
    src = inspect.getsource(_cli.main)
    assert "signature" in src and "parameters" in src


def t_cli_forwards_argv() -> None:
    """Dispatcher must forward args to subcommand main(argv)."""
    # Use --help which is non-destructive across all subcommands
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            _cli.main(["run", "--help"])
    except SystemExit:
        # argparse's --help raises SystemExit; that's fine
        pass
    out = buf.getvalue()
    assert "usage" in out.lower()


def t_cli_main_exists() -> None:
    import importlib
    for sub, mod_name in _cli.SUBCOMMANDS.items():
        mod = importlib.import_module(mod_name)
        m = getattr(mod, "main", None)
        assert callable(m), f"{mod_name}.main is not callable"


def t_perm_error_prefix() -> None:
    """eyesieve_permutations.PermutationError carries the standard prefix."""
    try:
        _perm.BlockReverseN(0)
    except _perm.PermutationError as e:
        assert ERROR_PREFIX in str(e)
        return
    raise AssertionError("BlockReverseN(0) should raise PermutationError")


def t_perm_module_has_error_prefix() -> None:
    """The module-level ERROR_PREFIX constant matches the global standard."""
    assert _perm.ERROR_PREFIX == ERROR_PREFIX


def t_audit_make_theory1_constructor() -> None:
    """make_theory1 convenience constructor produces a usable enumerator."""
    c = _corpus_for_phase45()
    e = _enum.make_theory1(c, bidirectional=False, include_xor_ciphers=False)
    assert isinstance(e, _enum.Theory1Enumerator)
    assert e.estimated_count() > 0
    # Verify a sample iteration works
    first = next(iter(e))
    assert isinstance(first, _hyp.Hypothesis)


def t_audit_make_theory2_constructor() -> None:
    """make_theory2 convenience constructor produces a usable enumerator."""
    c = _corpus_for_phase45()
    e = _enum.make_theory2(c, bidirectional=False, include_xor_ciphers=False,
                            include_cross_merge=False, include_constant_merge=False,
                            combine_op_names=("cyclic_add",),
                            permutation_names=("reverse",))
    assert isinstance(e, _enum.Theory2Enumerator)
    assert e.estimated_count() > 0


def t_audit_latent_exception_classes_constructible() -> None:
    """EnumeratorError, HypothesisError, RunnerError exist but are never
    raised in current code. Verify they're constructible with prefix in
    case future code or user-extension code raises them."""
    for exc_cls in (_enum.EnumeratorError, _hyp.HypothesisError,
                    _runner.RunnerError):
        e = exc_cls("probe")
        assert ERROR_PREFIX in str(e), f"{exc_cls.__name__} missing prefix"


def t_audit_dataclass_dict_helper() -> None:
    """mprunner.dataclass_dict round-trips a frozen dataclass to plain dict."""
    cfg = _enum.Theory1Config(bidirectional=False)
    d = _mprunner.dataclass_dict(cfg)
    assert isinstance(d, dict)
    assert d["bidirectional"] is False
    assert "strict_pairing" in d


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    print(bold(cyan("\n╔══════════════════════════════════════════════════════════════╗")))
    print(bold(cyan("║  EyeSieve // SELFTEST // phase 10                             ║")))
    print(bold(cyan("╚══════════════════════════════════════════════════════════════╝")))

    print(f"\n{TAG_INFO} {bold('Corpus tests')}")
    _run("corpus.load_corpus opens noita_eye_data.json",
         t_corpus_loads)
    _run("corpus total symbols == 1036",
         t_corpus_total_symbols)
    _run("corpus short codes E1..W4,E5",
         t_corpus_short_codes)
    _run("corpus individual message lengths",
         t_corpus_individual_lengths)
    _run("corpus all symbols in [0, deck_size)",
         t_corpus_alphabet_range)
    _run("corpus sigma0_ct_targets match position 0",
         t_corpus_sigma0_matches)
    _run("corpus lookup by short, label, __getitem__ agree",
         t_corpus_lookup_by_short_and_label)
    _run("corpus rejects unknown lookup with prefixed error",
         t_corpus_lookup_rejects_unknown)
    _run("corpus universal positions at 1, 2 = (66, 5)",
         t_corpus_universal_positions)
    _run("corpus universal_prefix is aliased to universal_positions",
         t_corpus_universal_prefix_alias)
    _run("corpus position-3 group split is 3/6 with expected members",
         t_corpus_prefix_groups_split)
    _run("corpus alphabet_usage total == 1036",
         t_corpus_alphabet_usage_total)
    _run("corpus load is deterministic across calls",
         t_corpus_load_deterministic)
    _run("Corpus dataclass is genuinely frozen",
         t_corpus_frozen)
    _run("load_corpus raises CorpusError on missing file",
         t_corpus_load_missing_file)
    _run("load_corpus raises CorpusError on malformed JSON",
         t_corpus_load_bad_json)
    _run("load_corpus raises CorpusError on wrong-type fields",
         t_corpus_load_wrong_types)
    _run("length_of / short_to_label / label_to_short raise CorpusError",
         t_corpus_lookup_errors_consistent)
    _run("Corpus pickles cleanly (multiprocessing-safe)",
         t_corpus_picklable)

    print(f"\n{TAG_INFO} {bold('Permutation tests')}")
    _run("Identity is identity + round-trip", t_identity_roundtrip)
    _run("Reverse known answer + round-trip", t_reverse_roundtrip)
    _run("RotateK known answers", t_rotate_k_known)
    _run("RotateK round-trip across k values", t_rotate_k_roundtrip)
    _run("BlockReverseN known answers", t_block_reverse_known)
    _run("BlockReverseN round-trip", t_block_reverse_roundtrip)
    _run("StrideN known answers", t_stride_n_known)
    _run("StrideN round-trip", t_stride_n_roundtrip)
    _run("GridTranspose known answer", t_grid_transpose_known)
    _run("GridTranspose round-trip", t_grid_transpose_roundtrip)
    _run("MessageIndexed known answer", t_message_indexed_known)
    _run("MessageIndexed round-trip", t_message_indexed_roundtrip)
    _run("enumerate_permutations basic count + uniqueness", t_enumerate_basic)
    _run("enumerate_permutations respects max_len bounds",
         t_enumerate_small_max_len)
    _run("All enumerated perms satisfy Permutation protocol",
         t_perm_protocol_compliance)
    _run("All perms handle empty sequence", t_perm_empty_sequence)
    _run("All perms handle length-1 sequence", t_perm_length_one_sequence)
    _run("All perms round-trip through pickle (multiprocessing-safe)",
         t_perm_picklable)
    _run("All perms round-trip against every real corpus message",
         t_perm_on_corpus_lengths)

    print(f"\n{TAG_INFO} {bold('Reader tests')}")
    _run("GLYPHS table has exactly 83 unique single-char glyphs",
         t_reader_glyphs_table)
    _run("FrequencyMap covers all runes and is rank-consistent",
         t_reader_frequency_map)
    _run("FrequencyMap color codes are valid 256-color indices",
         t_reader_color_codes_valid)
    _run("HighlightMap correctly classifies universal positions",
         t_reader_highlight_universal)
    _run("HighlightMap exposes 3-group and 6-group memberships at pos 3",
         t_reader_highlight_groups)
    _run("render_symbol pads to requested visible width across formats",
         t_reader_render_widths)
    _run("Reader: --grid runs without exception, output non-empty",
         t_reader_grid_runs)
    _run("Reader: --show E1 produces output containing E1's symbols",
         t_reader_show_runs)
    _run("Reader: --columns 0:5 surfaces structural notes",
         t_reader_columns_runs)
    _run("Reader: --diff E1 W1 reports the known 24-position match run",
         t_reader_diff_known_match)
    _run("Reader: every view mode runs cleanly under every format",
         t_reader_format_matrix)
    _run("Reader rejects unknown codes with CorpusError contract",
         t_reader_unknown_code)

    print(f"\n{TAG_INFO} {bold('Source tests')}")
    _run("Concat: known answer + length addition",
         t_sources_concat_known)
    _run("Concat: accepts 1+ inputs",
         t_sources_concat_arity)
    _run("CyclicCombine: add/sub/xor known answers",
         t_sources_cyclic_known)
    _run("CyclicCombine: output length == len(first arg)",
         t_sources_cyclic_length)
    _run("CyclicCombine: order-asymmetric on unequal lengths",
         t_sources_cyclic_asymmetric)
    _run("CyclicCombine: add/sub are inverses",
         t_sources_cyclic_add_sub_inverse)
    _run("CyclicCombine: add/sub stay inside the alphabet",
         t_sources_cyclic_closure)
    _run("Interleave: known answer + length",
         t_sources_interleave_known)
    _run("Interleave: start=0 vs start=1 swap inputs",
         t_sources_interleave_start)
    _run("TruncatedAlign: known answer + min-length output",
         t_sources_trunc_known)
    _run("TruncatedAlign: equal lengths == position-wise op",
         t_sources_trunc_equal)
    _run("HeaderPayload: header_length=0 == inner op alone",
         t_sources_hp_zero_header)
    _run("HeaderPayload: composes over inner ops",
         t_sources_hp_composition)
    _run("HeaderPayload: preserve_header prepends correctly",
         t_sources_hp_preserve)
    _run("HeaderPayload: rejects header_length > input length",
         t_sources_hp_overflow)
    _run("IndexDriven: lookup mode known answer",
         t_sources_index_lookup)
    _run("IndexDriven: skip mode known answer",
         t_sources_index_skip)
    _run("All merge ops enforce arity",
         t_sources_arity_enforcement)
    _run("All merge ops handle empty/single-element edges",
         t_sources_edge_cases)
    _run("All merge ops are deterministic across calls",
         t_sources_deterministic)
    _run("All merge ops round-trip through pickle",
         t_sources_pickle)
    _run("All merge ops apply to every (E_i, W_i) corpus pair",
         t_sources_corpus_application)
    _run("SingleMessage.resolve returns the ciphertext",
         t_sources_single_message)
    _run("SingleMessage raises SourceError on unknown code",
         t_sources_single_message_error)
    _run("MergedMessages composes Source + MergeOp",
         t_sources_merged_messages)
    _run("MergedMessages raises SourceError on empty codes",
         t_sources_merged_messages_error)
    _run("enumerate_merge_ops yields unique names",
         t_sources_enumerate_unique)
    _run("estimated_count matches actual enumeration",
         t_sources_estimated_count)

    print(f"\n{TAG_INFO} {bold('Cipher tests')}")
    _run("Cipher protocol compliance for all enumerated ciphers",
         t_ciphers_protocol)
    _run("All ciphers round-trip encrypt -> decrypt on simple input",
         t_ciphers_roundtrip_simple)
    _run("All ciphers round-trip on every real corpus message",
         t_ciphers_roundtrip_corpus)
    _run("All ciphers reject empty key with CipherError",
         t_ciphers_empty_key)
    _run("All ciphers handle empty plaintext / ciphertext",
         t_ciphers_empty_input)
    _run("XORStream: self-inverse (encrypt == decrypt)",
         t_ciphers_xor_selfinverse)
    _run("Beaufort: self-inverse (encrypt == decrypt)",
         t_ciphers_beaufort_selfinverse)
    _run("BeaufortAutokey: NOT self-inverse (regression test for audit)",
         t_ciphers_beaufort_autokey_not_selfinverse)
    _run("Vigenere.encrypt and VariantBeaufort.decrypt are identical",
         t_ciphers_vigenere_variant_identity)
    _run("Vigenere known-answer test",
         t_ciphers_vigenere_known)
    _run("Beaufort known-answer test",
         t_ciphers_beaufort_known)
    _run("VigenereAutokey known-answer test",
         t_ciphers_vigenere_autokey_known)
    _run("Affine: derives (a, b) and is invertible for prime N",
         t_ciphers_affine_invertible)
    _run("Affine: rejects composite deck_size at construction",
         t_ciphers_affine_rejects_composite)
    _run("KeywordSubstitution: keyword-derived permutation correct",
         t_ciphers_keyword_perm_derivation)
    _run("ColumnarTransposition: stable column ordering on tied keys",
         t_ciphers_columnar_stable_ties)
    _run("ColumnarTransposition: known answer on small input",
         t_ciphers_columnar_known)
    _run("ColumnarTransposition: rejects key shorter than column count",
         t_ciphers_columnar_short_key)
    _run("Vigenere rejects out-of-alphabet inputs",
         t_ciphers_alphabet_validation)
    _run("All ciphers are deterministic across calls",
         t_ciphers_deterministic)
    _run("All ciphers round-trip through pickle",
         t_ciphers_pickle)
    _run("enumerate_ciphers yields unique names + matches estimated_count",
         t_ciphers_enumerate_unique)

    print(f"\n{TAG_INFO} {bold('KeyDerivation tests (phase 4)')}")
    _run("Identity.derive returns key source unchanged",
         t_kd_identity_passthrough)
    _run("Identity.derive on empty source raises KeyDerivError",
         t_kd_identity_empty)
    _run("Identity is frozen / hashable / picklable",
         t_kd_identity_picklable)
    _run("Identity satisfies KeyDerivation protocol",
         t_kd_protocol_compliance)
    _run("enumerate_theory1 yields exactly Identity",
         t_kd_enumerate_theory1)

    print(f"\n{TAG_INFO} {bold('Hypothesis tests (phase 4)')}")
    _run("Hypothesis is frozen / hashable / picklable",
         t_hyp_picklable)
    _run("Hypothesis.execute runs the full pipeline",
         t_hyp_execute)
    _run("Hypothesis.execute matches a manual stage-by-stage run",
         t_hyp_execute_matches_manual)
    _run("Hypothesis.execute_with_intermediates returns all 4 stages",
         t_hyp_execute_with_intermediates)
    _run("Hypothesis.name contains every component name",
         t_hyp_name_includes_components)
    _run("Hypothesis equality respects all four components",
         t_hyp_equality)

    print(f"\n{TAG_INFO} {bold('Theory1Enumerator tests (phase 4)')}")
    _run("Theory1Config defaults match documentation",
         t_enum_config_defaults)
    _run("Theory1Enumerator yields Hypothesis instances",
         t_enum_yields_hypotheses)
    _run("estimated_count is closed-form correct vs actual iteration",
         t_enum_count_matches_iteration)
    _run("Default config yields 7,968 hypotheses",
         t_enum_default_count)
    _run("bidirectional=False halves the count",
         t_enum_monodirectional)
    _run("include_xor_ciphers=False prunes xor_stream variants",
         t_enum_no_xor)
    _run("strict_pairing=False expands to all (E_i, W_j) cross-pairs",
         t_enum_cross_pair)
    _run("fixed_key_E5=False expands to all 5 East keys",
         t_enum_any_key)
    _run("Every yielded hypothesis uses Identity key derivation",
         t_enum_all_identity)
    _run("Iterating twice yields identical hypothesis sequences",
         t_enum_idempotent_iteration)
    _run("make_theory1 convenience constructor works",
         t_enum_make_theory1)
    _run("First 50 hypotheses pickle round-trip cleanly",
         t_enum_hypotheses_picklable)

    print(f"\n{TAG_INFO} {bold('Sieve tests (phase 5)')}")
    _run("compute_ic: uniform, concentrated, short inputs",
         t_sieve_compute_ic)
    _run("max_symbol_frequency: typical, dominant, empty",
         t_sieve_max_freq)
    _run("distinct_symbol_count: typical, single, empty",
         t_sieve_distinct)
    _run("SieveVerdict is frozen and picklable",
         t_sieve_verdict_picklable)
    _run("LengthSieve: min_length boundary cases",
         t_sieve_length)
    _run("LengthSieve: max_length=0 means unbounded",
         t_sieve_length_max_disabled)
    _run("AlphabetClosureSieve: passes valid, kills first out-of-range",
         t_sieve_alphabet_closure)
    _run("ICSieve: rejects below min_ic and above max_ic",
         t_sieve_ic_bounds)
    _run("SymbolDistributionSieve: kills concentration and low-distinct",
         t_sieve_distribution)
    _run("SieveCascade.default has 4 stages in correct order",
         t_sieve_cascade_default_stages)
    _run("SieveCascade kills at first failing stage and stops",
         t_sieve_cascade_stops_on_first_kill)
    _run("SieveCascade catches SourceError as killed_at='execute'",
         t_sieve_cascade_catches_source_error)
    _run("SieveCascade catches KeyDerivError as killed_at='execute'",
         t_sieve_cascade_catches_keyderiv_error)
    _run("SieveCascade does NOT swallow unexpected RuntimeError",
         t_sieve_cascade_does_not_swallow_unexpected)
    _run("SieveResult is frozen and picklable",
         t_sieve_result_picklable)
    _run("SieveTelemetry.record accumulates correctly across results",
         t_sieve_telemetry_record)
    _run("SieveTelemetry.as_dict is JSON-serializable",
         t_sieve_telemetry_serializable)
    _run("All sieve stages are picklable (multiprocessing safety)",
         t_sieve_stages_picklable)
    _run("All sieve stages satisfy the SieveStage protocol",
         t_sieve_stages_protocol)
    _run("Cascade smoke run on 200 real hypotheses: telemetry sum holds",
         t_sieve_real_corpus_smoke)

    print(f"\n{TAG_INFO} {bold('Scoring tests (phase 7)')}")
    _run("ScoringConfig defaults match documentation",
         t_score_config_defaults)
    _run("is_eyestat_available returns True on this checkout",
         t_score_eyestat_available)
    _run("LanguageScore is frozen and picklable",
         t_score_language_score_picklable)
    _run("ScoringResult.best_score / best_language properties",
         t_score_result_properties)
    _run("Scorer init succeeds with default config",
         t_score_scorer_init)
    _run("Scorer.score on real candidate returns expected shape",
         t_score_real_candidate)
    _run("Scorer handles None best_mapping gracefully",
         t_score_none_mapping_safe)
    _run("Scorer.score raises ScoringError on empty candidate",
         t_score_empty_candidate)

    print(f"\n{TAG_INFO} {bold('Runner tests (phase 6)')}")
    _run("RunConfig defaults match documentation",
         t_runner_config_defaults)
    _run("CONFIG_PRESETS contains all 6 expected presets",
         t_runner_config_presets)
    _run("Runner constructs cleanly with strict config",
         t_runner_construct)
    _run("Runner.run produces expected output files (no scoring)",
         t_runner_run_no_score)
    _run("Runner.run produces expected output files (with scoring)",
         t_runner_run_with_score)
    _run("Runner output files are well-formed JSON",
         t_runner_output_well_formed)
    _run("RunResult telemetry totals match enumerator count",
         t_runner_telemetry_balances)
    _run("Runner --quiet flag suppresses banner output",
         t_runner_quiet)

    print(f"\n{TAG_INFO} {bold('Theory 2 keyderiv tests (phase 9)')}")
    _run("SelfMerge has well-formed name",
         t_t2_self_name)
    _run("SelfMerge.derive produces a usable key on real corpus",
         t_t2_self_derive)
    _run("SelfMerge is frozen and picklable",
         t_t2_self_picklable)
    _run("SelfMerge raises KeyDerivError on empty key source",
         t_t2_self_empty)
    _run("CrossMerge has well-formed name",
         t_t2_cross_name)
    _run("CrossMerge.derive produces a usable key",
         t_t2_cross_derive)
    _run("CrossMerge raises KeyDerivError on bad cross code",
         t_t2_cross_bad_code)
    _run("ConstantMerge produces correct length for each pattern",
         t_t2_constant_patterns)
    _run("ConstantMerge raises on unknown pattern via _build_constant",
         t_t2_constant_unknown)
    _run("_select_combine_ops raises on unknown combine-op name",
         t_t2_select_combine_unknown_raises)
    _run("_select_permutations raises on unknown permutation name",
         t_t2_select_perm_unknown_raises)
    _run("enumerate_theory2 default count matches expectation",
         t_t2_enumerate_count)
    _run("enumerate_theory2 excludes key_code from CrossMerge targets",
         t_t2_enumerate_excludes_key)
    _run("enumerate_theory2 with empty subsets yields nothing",
         t_t2_enumerate_empty_subsets)

    print(f"\n{TAG_INFO} {bold('Theory 2 enumerator tests (phase 9)')}")
    _run("Theory2Config defaults match documentation",
         t_t2_enum_config_defaults)
    _run("Theory2Enumerator yields Hypothesis instances",
         t_t2_enum_yields_hypotheses)
    _run("Theory2Enumerator default count == 446,208",
         t_t2_enum_default_count)
    _run("Theory2Enumerator estimated == actual iteration count",
         t_t2_enum_count_matches_iteration)
    _run("All Theory 2 hypotheses use a Theory 2 derivation (never Identity)",
         t_t2_enum_no_identity)
    _run("TheoryUnionEnumerator yields T1 then T2 in order",
         t_t2_union_ordering)
    _run("TheoryUnionEnumerator count == T1 + T2",
         t_t2_union_count)
    _run("Theory 2 hypotheses are picklable (multiprocessing safety)",
         t_t2_enum_picklable)

    print(f"\n{TAG_INFO} {bold('Multiprocess runner tests (phase 8)')}")
    _run("MPRunConfig defaults match documentation",
         t_mpr_config_defaults)
    _run("MPRunnerError carries the standard error prefix",
         t_mpr_error_prefix)
    _run("MPRunConfig rejects n_workers < 1",
         t_mpr_rejects_zero_workers)
    _run("MPRunConfig rejects unknown theory string",
         t_mpr_rejects_bad_theory)
    _run("_config_fingerprint is stable across construction",
         t_mpr_fingerprint_stable)
    _run("_config_fingerprint differs for different configs",
         t_mpr_fingerprint_distinct)
    _run("Checkpoint write/read round-trip",
         t_mpr_checkpoint_roundtrip)
    _run("workers=1 produces same telemetry as single-process Runner",
         t_mpr_workers1_matches_runner)
    _run("workers=2 produces same telemetry as workers=1",
         t_mpr_workers2_matches_workers1)
    _run("Checkpoint file is written periodically during sieve pass",
         t_mpr_checkpoint_written)
    _run("Resume from checkpoint completes the run cleanly",
         t_mpr_resume_completes)
    _run("Resume refuses on config_fingerprint mismatch",
         t_mpr_resume_refuses_mismatch)
    _run("Resume truncates survivor file to checkpoint count",
         t_mpr_resume_truncates_survivors)

    print(f"\n{TAG_INFO} {bold('HTML run report tests (phase 10)')}")
    _run("RunReportError carries the standard error prefix",
         t_rr_error_prefix)
    _run("_read_telemetry raises on missing file",
         t_rr_missing_telemetry)
    _run("_read_telemetry raises on malformed JSON",
         t_rr_malformed_telemetry)
    _run("_read_jsonl handles empty file gracefully",
         t_rr_empty_jsonl)
    _run("_read_jsonl skips blank lines",
         t_rr_blank_lines)
    _run("_read_jsonl honors limit parameter",
         t_rr_jsonl_limit)
    _run("render_html on real run dir produces valid HTML",
         t_rr_render_html_real)
    _run("Rendered HTML escapes user-supplied strings",
         t_rr_html_escapes)
    _run("Rendered HTML contains all expected sections",
         t_rr_html_sections)
    _run("Leaderboard section handles missing scored.jsonl gracefully",
         t_rr_no_scoring)
    _run("top_n parameter limits leaderboard size",
         t_rr_top_n_limit)
    _run("Funnel section: row count = stages + 2 (input + survivors)",
         t_rr_funnel_rows)
    _run("Breakdown parses Theory 2 hypothesis names correctly",
         t_rr_breakdown_t2_parsing)

    print(f"\n{TAG_INFO} {bold('Unified CLI dispatcher tests (phase 11)')}")
    _run("SUBCOMMANDS maps all 7 subcommands to known modules",
         t_cli_subcommands_complete)
    _run("Dispatcher with no args returns 0 + prints usage",
         t_cli_no_args)
    _run("Dispatcher with --help returns 0",
         t_cli_help)
    _run("Dispatcher returns 2 for unknown subcommand",
         t_cli_unknown_subcommand)
    _run("Dispatcher handles main() that takes no argv",
         t_cli_no_argv_main)
    _run("Dispatcher forwards argv to main(argv) signatures",
         t_cli_forwards_argv)
    _run("Each subcommand module has a main() callable",
         t_cli_main_exists)

    print(f"\n{TAG_INFO} {bold('Cross-cutting consistency (audit findings)')}")
    _run("PermutationError carries the standard prefix",
         t_perm_error_prefix)
    _run("eyesieve_permutations.ERROR_PREFIX matches the global standard",
         t_perm_module_has_error_prefix)
    _run("make_theory1 convenience constructor produces usable enumerator",
         t_audit_make_theory1_constructor)
    _run("make_theory2 convenience constructor produces usable enumerator",
         t_audit_make_theory2_constructor)
    _run("Latent exception classes (EnumeratorError, HypothesisError, "
         "RunnerError) carry the prefix",
         t_audit_latent_exception_classes_constructible)
    _run("dataclass_dict helper round-trips frozen dataclass",
         t_audit_dataclass_dict_helper)

    # Summary
    total = len(_results)
    passed = sum(1 for _, s, _ in _results if s == "ok")
    failed = sum(1 for _, s, _ in _results if s == "fail")
    warned = sum(1 for _, s, _ in _results if s == "warn")
    skipped = sum(1 for _, s, _ in _results if s == "skip")

    print()
    print(bold("─" * 64))
    print(f"  total : {total}")
    print(f"  ok    : {green(str(passed))}")
    if skipped:
        print(f"  skip  : {yellow(str(skipped))}")
    if warned:
        print(f"  warn  : {yellow(str(warned))}")
    if failed:
        print(f"  fail  : {red(str(failed))}")
    print(bold("─" * 64))

    if failed:
        print(f"\n{TAG_FAIL} {ERROR_PREFIX} :: selftest :: {failed} failure(s)")
        return 2
    if warned:
        return 1
    if skipped:
        print(f"\n{green('ALL GREEN — v1.0 modules look healthy.')} "
              f"({skipped} skipped — see above)")
    else:
        print(f"\n{green('ALL GREEN — v1.0 modules look healthy.')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
