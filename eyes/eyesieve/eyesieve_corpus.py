#!/usr/bin/env python3
"""eyesieve_corpus.py — load and validate the Noita eye-message corpus.

The corpus is the same noita_eye_data.json file consumed by EyeStat. This
module provides:

  - Corpus dataclass  : typed, immutable access to ciphertexts/labels/lengths
  - load_corpus(path) : reads and validates the JSON
  - validate_corpus() : strict integrity checks (9 messages, 1036 symbols,
                        83-rune alphabet, all symbols in [0, 82], sigma0
                        consistency)
  - Prefix analysis   : shared_prefix_groups() surfaces the cross-message
                        shared-position structure (positions 1-2 are
                        universally (66, 5); positions 3-4 split into two
                        groups). The sieve and dashboard consume this.

ERROR HANDLING
==============
All integrity failures raise CorpusError prefixed with the project's
standard error code (XD-MBYG04K-URS3LF) so failures are greppable in logs.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

EXPECTED_NUM_MESSAGES = 9
EXPECTED_TOTAL_SYMBOLS = 1036
EXPECTED_DECK_SIZE = 83

# Canonical short codes derived from the "East N" / "West N" labels in the
# JSON. Internal code uses short codes; UI/reporting uses full labels.
_SHORT_CODE_MAP: dict[str, str] = {
    "East 1": "E1", "West 1": "W1",
    "East 2": "E2", "West 2": "W2",
    "East 3": "E3", "West 3": "W3",
    "East 4": "E4", "West 4": "W4",
    "East 5": "E5",
}


class CorpusError(Exception):
    """Raised on any corpus integrity failure."""

    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: corpus :: {msg}")


@dataclass(frozen=True)
class Corpus:
    """The 9-message Noita eye-message corpus.

    All ciphertexts are stored as tuples of ints in ``[0, deck_size)``.
    The dataclass is frozen so corpus instances are hashable and safe to
    share across multiprocessing workers.
    """

    deck_size: int                          # alphabet size, == 83
    num_messages: int                       # == 9
    labels: tuple[str, ...]                 # ("East 1", "West 1", ...)
    short_codes: tuple[str, ...]            # ("E1", "W1", ...)
    ciphertexts: tuple[tuple[int, ...], ...]
    lengths: tuple[int, ...]
    sigma0_targets: tuple[int, ...] | None  # position-0 of each ciphertext

    # -----------------------------------------------------------------------
    # Lookup
    # -----------------------------------------------------------------------

    def by_short(self, code: str) -> tuple[int, ...]:
        """Return ciphertext for a short code like 'E1'."""
        try:
            idx = self.short_codes.index(code)
        except ValueError:
            raise CorpusError(
                f"unknown short code {code!r}; valid: {list(self.short_codes)}"
            )
        return self.ciphertexts[idx]

    def by_label(self, label: str) -> tuple[int, ...]:
        """Return ciphertext for a full label like 'East 1'."""
        try:
            idx = self.labels.index(label)
        except ValueError:
            raise CorpusError(
                f"unknown label {label!r}; valid: {list(self.labels)}"
            )
        return self.ciphertexts[idx]

    def __getitem__(self, key: str) -> tuple[int, ...]:
        """Convenience: ``corpus['E1']`` or ``corpus['East 1']``."""
        if key in self.short_codes:
            return self.by_short(key)
        if key in self.labels:
            return self.by_label(key)
        raise CorpusError(f"unknown corpus key {key!r}")

    def short_to_label(self, code: str) -> str:
        try:
            idx = self.short_codes.index(code)
        except ValueError:
            raise CorpusError(
                f"unknown short code {code!r}; valid: {list(self.short_codes)}"
            )
        return self.labels[idx]

    def label_to_short(self, label: str) -> str:
        try:
            idx = self.labels.index(label)
        except ValueError:
            raise CorpusError(
                f"unknown label {label!r}; valid: {list(self.labels)}"
            )
        return self.short_codes[idx]

    # -----------------------------------------------------------------------
    # Structural accessors
    # -----------------------------------------------------------------------

    def east_codes(self) -> tuple[str, ...]:
        return tuple(c for c in self.short_codes if c.startswith("E"))

    def west_codes(self) -> tuple[str, ...]:
        return tuple(c for c in self.short_codes if c.startswith("W"))

    def length_of(self, code: str) -> int:
        try:
            idx = self.short_codes.index(code)
        except ValueError:
            raise CorpusError(
                f"unknown short code {code!r}; valid: {list(self.short_codes)}"
            )
        return self.lengths[idx]


# ---------------------------------------------------------------------------
# Loading + validation
# ---------------------------------------------------------------------------

def load_corpus(path: Path | str) -> Corpus:
    """Load and validate the corpus from a JSON file. Raises CorpusError
    on any failure — missing file, malformed JSON, wrong types, or
    integrity-check violations."""
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise CorpusError(f"data file not found: {p}")
    except PermissionError as e:
        raise CorpusError(f"cannot read data file {p}: {e}")
    except json.JSONDecodeError as e:
        raise CorpusError(f"invalid JSON in {p}: {e}")
    except OSError as e:
        raise CorpusError(f"OS error reading {p}: {e}")

    if not isinstance(raw, dict):
        raise CorpusError(
            f"top-level JSON must be an object, got {type(raw).__name__}"
        )

    required = ["deck_size", "num_messages", "message_labels",
                "message_lengths", "ciphertexts"]
    missing = [k for k in required if k not in raw]
    if missing:
        raise CorpusError(f"missing required keys: {missing}")

    # Type-strict parsing — surface any wrong-type field with a clear message
    # instead of a cryptic ValueError/TypeError from deep inside a comprehension.
    try:
        labels_raw = raw["message_labels"]
        if not isinstance(labels_raw, list):
            raise CorpusError(
                f"message_labels must be a list, got {type(labels_raw).__name__}"
            )
        labels = tuple(str(x) for x in labels_raw)

        short_codes: list[str] = []
        for lbl in labels:
            if lbl not in _SHORT_CODE_MAP:
                raise CorpusError(
                    f"unknown message label {lbl!r}; expected one of "
                    f"{list(_SHORT_CODE_MAP)}"
                )
            short_codes.append(_SHORT_CODE_MAP[lbl])

        cts_raw = raw["ciphertexts"]
        if not isinstance(cts_raw, list):
            raise CorpusError(
                f"ciphertexts must be a list, got {type(cts_raw).__name__}"
            )
        cts_list: list[tuple[int, ...]] = []
        for i, ct in enumerate(cts_raw):
            if not isinstance(ct, list):
                raise CorpusError(
                    f"ciphertexts[{i}] must be a list, "
                    f"got {type(ct).__name__}"
                )
            try:
                cts_list.append(tuple(int(x) for x in ct))
            except (TypeError, ValueError) as e:
                raise CorpusError(
                    f"ciphertexts[{i}] contains non-integer value: {e}"
                )
        cts = tuple(cts_list)

        lengths_raw = raw["message_lengths"]
        if not isinstance(lengths_raw, list):
            raise CorpusError(
                f"message_lengths must be a list, got {type(lengths_raw).__name__}"
            )
        try:
            lengths = tuple(int(x) for x in lengths_raw)
        except (TypeError, ValueError) as e:
            raise CorpusError(f"message_lengths contains non-integer: {e}")

        sigma0: tuple[int, ...] | None = None
        if "sigma0_ct_targets" in raw:
            s_raw = raw["sigma0_ct_targets"]
            if not isinstance(s_raw, list):
                raise CorpusError(
                    f"sigma0_ct_targets must be a list, got {type(s_raw).__name__}"
                )
            try:
                sigma0 = tuple(int(x) for x in s_raw)
            except (TypeError, ValueError) as e:
                raise CorpusError(f"sigma0_ct_targets contains non-integer: {e}")

        deck_size_raw = raw["deck_size"]
        if not isinstance(deck_size_raw, int) or isinstance(deck_size_raw, bool):
            raise CorpusError(
                f"deck_size must be an int, got {type(deck_size_raw).__name__}"
            )

        num_messages_raw = raw["num_messages"]
        if not isinstance(num_messages_raw, int) or isinstance(num_messages_raw, bool):
            raise CorpusError(
                f"num_messages must be an int, got {type(num_messages_raw).__name__}"
            )
    except CorpusError:
        raise
    except Exception as e:  # noqa: BLE001 — last-resort safety net
        raise CorpusError(f"parse error: {type(e).__name__}: {e}")

    corpus = Corpus(
        deck_size=deck_size_raw,
        num_messages=num_messages_raw,
        labels=labels,
        short_codes=tuple(short_codes),
        ciphertexts=cts,
        lengths=lengths,
        sigma0_targets=sigma0,
    )
    validate_corpus(corpus)
    return corpus


def validate_corpus(c: Corpus) -> None:
    """Strict integrity check. Raises CorpusError on any drift."""
    if c.deck_size != EXPECTED_DECK_SIZE:
        raise CorpusError(
            f"deck_size mismatch: got {c.deck_size}, expected {EXPECTED_DECK_SIZE}"
        )
    if c.num_messages != EXPECTED_NUM_MESSAGES:
        raise CorpusError(
            f"num_messages mismatch: got {c.num_messages}, "
            f"expected {EXPECTED_NUM_MESSAGES}"
        )
    if len(c.ciphertexts) != EXPECTED_NUM_MESSAGES:
        raise CorpusError(
            f"ciphertexts count: got {len(c.ciphertexts)}, "
            f"expected {EXPECTED_NUM_MESSAGES}"
        )
    if len(c.lengths) != EXPECTED_NUM_MESSAGES:
        raise CorpusError(
            f"lengths count: got {len(c.lengths)}, "
            f"expected {EXPECTED_NUM_MESSAGES}"
        )
    if len(c.labels) != EXPECTED_NUM_MESSAGES:
        raise CorpusError(
            f"labels count: got {len(c.labels)}, expected {EXPECTED_NUM_MESSAGES}"
        )
    if len(c.short_codes) != EXPECTED_NUM_MESSAGES:
        raise CorpusError(
            f"short_codes count: got {len(c.short_codes)}, "
            f"expected {EXPECTED_NUM_MESSAGES}"
        )

    # Each ciphertext length matches stated length
    for label, ct, stated_len in zip(c.labels, c.ciphertexts, c.lengths):
        if len(ct) != stated_len:
            raise CorpusError(
                f"{label}: ciphertext length {len(ct)} != stated {stated_len}"
            )

    # Total symbols
    total = sum(c.lengths)
    if total != EXPECTED_TOTAL_SYMBOLS:
        raise CorpusError(
            f"total symbols: got {total}, expected {EXPECTED_TOTAL_SYMBOLS}"
        )

    # All symbols in [0, deck_size)
    for label, ct in zip(c.labels, c.ciphertexts):
        for j, x in enumerate(ct):
            if not (0 <= x < c.deck_size):
                raise CorpusError(
                    f"{label}[{j}] = {x} out of range [0, {c.deck_size})"
                )

    # sigma0 consistency
    if c.sigma0_targets is not None:
        if len(c.sigma0_targets) != EXPECTED_NUM_MESSAGES:
            raise CorpusError(
                f"sigma0_targets count: got {len(c.sigma0_targets)}, "
                f"expected {EXPECTED_NUM_MESSAGES}"
            )
        for i, (label, ct, s0) in enumerate(zip(c.labels, c.ciphertexts,
                                                c.sigma0_targets)):
            if ct[0] != s0:
                raise CorpusError(
                    f"{label}: sigma0 mismatch — position 0 is {ct[0]}, "
                    f"sigma0_targets[{i}] is {s0}"
                )

    # Short codes match expected canonical mapping
    for label, sc in zip(c.labels, c.short_codes):
        expected = _SHORT_CODE_MAP.get(label)
        if expected != sc:
            raise CorpusError(
                f"short code mismatch: {label!r} -> {sc!r}, expected {expected!r}"
            )


# ---------------------------------------------------------------------------
# Structural analysis
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PrefixGroup:
    """A set of messages sharing identical symbols at a position."""
    position: int           # column index (0-based)
    symbol: int             # the shared symbol value
    members: tuple[str, ...]  # short codes of messages in the group


def shared_prefix_groups(c: Corpus,
                         max_position: int = 16,
                         min_group_size: int = 2,
                         ) -> list[PrefixGroup]:
    """Scan positions ``0 .. max_position-1`` (exclusive upper bound, clamped
    to the shortest message length) and group messages by shared symbol at
    each position.

    A position with all 9 messages agreeing produces one group of size 9.
    A position that splits 3/6 produces two groups (sizes 3 and 6).
    Groups smaller than ``min_group_size`` are dropped from the output.

    Output is sorted by (position ascending, group size descending, symbol
    ascending).
    """
    groups: list[PrefixGroup] = []
    scan_upper = min(max_position, min(c.lengths))
    for pos in range(scan_upper):
        by_symbol: dict[int, list[str]] = {}
        for code, ct in zip(c.short_codes, c.ciphertexts):
            if pos < len(ct):
                by_symbol.setdefault(ct[pos], []).append(code)
        for sym, members in by_symbol.items():
            if len(members) >= min_group_size:
                groups.append(PrefixGroup(
                    position=pos, symbol=sym, members=tuple(members)
                ))
    groups.sort(key=lambda g: (g.position, -len(g.members), g.symbol))
    return groups


def universal_positions(c: Corpus) -> tuple[tuple[int, int], ...]:
    """Return ``((position, symbol), ...)`` for every column where ALL 9
    messages share the same symbol.

    This intentionally scans the full min-length range — not just the
    leading prefix — because the framework needs to know about any
    universal column (mid-message or otherwise), not only contiguous
    header runs. For this corpus, the result is ``((1, 66), (2, 5))``.
    """
    out: list[tuple[int, int]] = []
    min_len = min(c.lengths)
    for pos in range(min_len):
        symbols = {ct[pos] for ct in c.ciphertexts}
        if len(symbols) == 1:
            out.append((pos, next(iter(symbols))))
    return tuple(out)


# Backward-compatibility alias for any external caller using the older
# name. New code should call universal_positions().
universal_prefix = universal_positions


def alphabet_usage(c: Corpus) -> Counter[int]:
    """Count occurrences of each rune across all 9 ciphertexts."""
    counter: Counter[int] = Counter()
    for ct in c.ciphertexts:
        counter.update(ct)
    return counter


# ---------------------------------------------------------------------------
# CLI: print a summary when invoked directly
# ---------------------------------------------------------------------------

def _format_summary(c: Corpus) -> str:
    lines = [
        "EyeSieve corpus summary",
        "=" * 56,
        f"deck_size      : {c.deck_size}",
        f"num_messages   : {c.num_messages}",
        f"total symbols  : {sum(c.lengths)}",
        "",
        "Messages:",
    ]
    for code, label, length in zip(c.short_codes, c.labels, c.lengths):
        lines.append(f"  {code}  ({label:<7})  length={length:>3}")
    lines.append("")
    lines.append("Universal-prefix positions (all 9 messages agree):")
    for pos, sym in universal_positions(c):
        lines.append(f"  position {pos:>2}: symbol = {sym}")
    lines.append("")
    lines.append("Prefix groups (size >= 2, first 6 positions):")
    for g in shared_prefix_groups(c, max_position=6, min_group_size=2):
        if len(g.members) == c.num_messages:
            continue  # already shown above
        lines.append(
            f"  pos {g.position:>2}  sym {g.symbol:>3}  size {len(g.members)}  "
            f"members: {', '.join(g.members)}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Summarize an eyesieve corpus.")
    p.add_argument("--data", default="noita_eye_data.json",
                   help="Path to noita_eye_data.json (default: %(default)s)")
    args = p.parse_args(argv)
    try:
        corpus = load_corpus(args.data)
    except CorpusError as e:
        print(str(e))
        return 2
    print(_format_summary(corpus))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
