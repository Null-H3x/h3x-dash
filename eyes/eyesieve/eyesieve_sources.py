#!/usr/bin/env python3
"""eyesieve_sources.py — slot bindings and merge operations.

This module makes Theory 1's central question mechanical. Where the corpus
module gave us data and the permutations module gave us key-shuffle
families, this one provides the answer to *"what does merging two
messages this way actually produce?"*

CONCEPTS
========
Each input slot in a Hypothesis is filled by a ``Source``. A source is
either a ``SingleMessage`` (pull one ciphertext by its short code) or a
``MergedMessages`` (pull N ciphertexts and combine them via a
``MergeOp``).

MERGE OPERATIONS
================
Six families covering Theory 1's design space:

  Concat              a ‖ b  (or 3+ inputs in declaration order)
  CyclicCombine(op)   longer message combined with shorter as keystream
                      via op ∈ {add, sub, xor} mod deck_size
  Interleave(start)   alternate symbols a[0],b[0],a[1],b[1],...
                      (start=1 flips which input goes first)
  TruncatedAlign(op)  position-wise combine over min-length prefix only;
                      the longer message's tail is discarded
  HeaderPayload(h,op) strip ``h`` leading positions from each input,
                      then apply an inner MergeOp to the payloads;
                      optionally preserve one input's header on the front
  IndexDriven(mode)   first input drives positional / skip choices;
                      second input supplies symbols. Mode ``lookup``
                      uses indices as direct positions; ``skip`` walks
                      the source by indices[i] steps each.

HEADERPAYLOAD GETS SPECIAL ATTENTION
====================================
Phase 1 surfaced strong structural prefixes — positions 1-2 universal,
3-5 split 3/6, 6-9 split 3/4. HeaderPayload encodes the hypothesis that
this prefix is a header (framing, IV, MAC, decoy) layered on top of a
real payload starting deeper into each message. Default sweep header
lengths cover the structurally significant boundaries: 0, 1, 2, 3, 5, 9.

ENUMERATION
===========
``enumerate_merge_ops()`` yields the default sweep (~80 merge variants
calibrated for the corpus). The phase-4 enumerator will combine these
with partition choices, ciphers, and rune mappings.

ERROR CONTRACT
==============
All failures raise ``SourceError`` with the project's standard error-code
prefix ``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, Sequence, runtime_checkable

import eyesieve_corpus as ec

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

RuneSeq = tuple[int, ...]
DEFAULT_DECK_SIZE = 83


class SourceError(Exception):
    """Raised on any source / merge-op contract violation."""

    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: sources :: {msg}")


# ===========================================================================
# MergeOp protocol
# ===========================================================================

@runtime_checkable
class MergeOp(Protocol):
    """Structural protocol — concrete merge ops don't inherit, only expose
    ``name`` and ``apply()``."""
    name: str

    def apply(self, *msgs: Sequence[int]) -> RuneSeq: ...


# ===========================================================================
# Concrete merge operations
# ===========================================================================

@dataclass(frozen=True)
class Concat:
    """Concatenate inputs in declaration order. Accepts 1+ inputs.

    Output length == sum of input lengths.
    """

    name: str = "concat"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) < 1:
            raise SourceError(
                f"concat requires at least 1 input, got {len(msgs)}"
            )
        out: list[int] = []
        for m in msgs:
            out.extend(m)
        return tuple(out)


@dataclass(frozen=True)
class CyclicCombine:
    """Stream-cipher-style combine: FIRST input is the message data,
    SECOND input is treated as a cyclic keystream.

    For each position i in the first input:
        op="add":  result[i] = (a[i] + b[i % len(b)]) mod deck_size
        op="sub":  result[i] = (a[i] - b[i % len(b)]) mod deck_size
        op="xor":  result[i] = a[i] XOR b[i % len(b)]

    This is asymmetric in argument order — ``apply(E1, W1)`` and
    ``apply(W1, E1)`` produce different results. The enumerator generates
    both orderings as distinct hypotheses.

    Note: ``xor`` is not closed on a non-power-of-2 alphabet (deck_size=83),
    so most XOR results will fail the alphabet-closure sieve stage in
    phase 5. Included for completeness — the framework should test what it
    claims to test.

    Output length == len(first input).
    """

    op: str                              # "add" | "sub" | "xor"
    deck_size: int = DEFAULT_DECK_SIZE

    def __post_init__(self) -> None:
        if self.op not in ("add", "sub", "xor"):
            raise SourceError(f"CyclicCombine: unknown op {self.op!r}")
        if self.deck_size < 2:
            raise SourceError(
                f"CyclicCombine: deck_size must be >= 2, got {self.deck_size}"
            )

    @property
    def name(self) -> str:
        return f"cyclic_{self.op}"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) != 2:
            raise SourceError(
                f"cyclic_{self.op} requires 2 inputs, got {len(msgs)}"
            )
        a, b = msgs
        if len(a) == 0:
            return ()
        if len(b) == 0:
            raise SourceError(
                f"cyclic_{self.op}: keystream (second input) is empty"
            )
        n_key = len(b)
        if self.op == "add":
            return tuple((a[i] + b[i % n_key]) % self.deck_size
                         for i in range(len(a)))
        if self.op == "sub":
            return tuple((a[i] - b[i % n_key]) % self.deck_size
                         for i in range(len(a)))
        # xor
        return tuple(a[i] ^ b[i % n_key] for i in range(len(a)))


@dataclass(frozen=True)
class Interleave:
    """Alternate symbols from each input, A first by default.

    start=0:  a[0], b[0], a[1], b[1], a[2], b[2], ...
    start=1:  b[0], a[0], b[1], a[1], ...

    When inputs differ in length, alternation continues until the shorter
    input is exhausted, then the longer's tail is appended.

    Output length == |a| + |b|.
    """

    start: int = 0

    def __post_init__(self) -> None:
        if self.start not in (0, 1):
            raise SourceError(
                f"Interleave: start must be 0 or 1, got {self.start}"
            )

    @property
    def name(self) -> str:
        return f"interleave(start={self.start})"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) != 2:
            raise SourceError(
                f"interleave requires 2 inputs, got {len(msgs)}"
            )
        a, b = msgs
        if self.start == 1:
            a, b = b, a
        out: list[int] = []
        n = max(len(a), len(b))
        for i in range(n):
            if i < len(a):
                out.append(a[i])
            if i < len(b):
                out.append(b[i])
        return tuple(out)


@dataclass(frozen=True)
class TruncatedAlign:
    """Position-wise combine over the shared min-length prefix.

    The longer input's tail is discarded entirely.

        op="add": result[i] = (a[i] + b[i]) mod deck_size  for i in [0, n)
        op="sub": result[i] = (a[i] - b[i]) mod deck_size  for i in [0, n)
        op="xor": result[i] = a[i] XOR b[i]                for i in [0, n)

    where n = min(|a|, |b|).

    Same XOR caveat as ``CyclicCombine``: XOR on the 83-symbol alphabet
    will mostly produce out-of-range values and fail alphabet closure.

    Output length == min(|a|, |b|).
    """

    op: str
    deck_size: int = DEFAULT_DECK_SIZE

    def __post_init__(self) -> None:
        if self.op not in ("add", "sub", "xor"):
            raise SourceError(f"TruncatedAlign: unknown op {self.op!r}")
        if self.deck_size < 2:
            raise SourceError(
                f"TruncatedAlign: deck_size must be >= 2, got {self.deck_size}"
            )

    @property
    def name(self) -> str:
        return f"trunc_{self.op}"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) != 2:
            raise SourceError(
                f"trunc_{self.op} requires 2 inputs, got {len(msgs)}"
            )
        a, b = msgs
        n = min(len(a), len(b))
        if self.op == "add":
            return tuple((a[i] + b[i]) % self.deck_size for i in range(n))
        if self.op == "sub":
            return tuple((a[i] - b[i]) % self.deck_size for i in range(n))
        return tuple(a[i] ^ b[i] for i in range(n))


@dataclass(frozen=True)
class HeaderPayload:
    """Strip a structural header from each input, then apply an inner merge
    op to the remaining payloads.

    Designed around the phase-1 structural finding: positions 1-2 are
    universal, 3-5 split 3/6, 6-9 split 3/4. ``HeaderPayload`` encodes the
    hypothesis that this prefix is a header (framing, IV, decoy) and the
    real payload starts deeper into each message.

    Fields:
      header_length     — number of leading positions to strip from each input
      payload_op        — a MergeOp applied to the stripped payloads
      preserve_header   — if "a" or "b", prepend that input's header to the
                          merged payload; if None, header is discarded

    Output length depends on the inner op:
      preserve_header=None:  ``len(payload_op.apply(a[h:], b[h:]))``
      preserve_header="a":   ``h + len(payload_op.apply(a[h:], b[h:]))``
      preserve_header="b":   ``h + len(payload_op.apply(a[h:], b[h:]))``
    """

    header_length: int
    payload_op: MergeOp
    preserve_header: str | None = None

    def __post_init__(self) -> None:
        if self.header_length < 0:
            raise SourceError(
                f"HeaderPayload: header_length must be >= 0, "
                f"got {self.header_length}"
            )
        if self.preserve_header not in (None, "a", "b"):
            raise SourceError(
                f"HeaderPayload: preserve_header must be None, 'a', or 'b'; "
                f"got {self.preserve_header!r}"
            )

    @property
    def name(self) -> str:
        ph = "" if self.preserve_header is None else f",keep={self.preserve_header}"
        return f"hp(h={self.header_length},{self.payload_op.name}{ph})"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) != 2:
            raise SourceError(
                f"HeaderPayload requires 2 inputs, got {len(msgs)}"
            )
        a, b = msgs
        h = self.header_length
        if h > len(a) or h > len(b):
            raise SourceError(
                f"HeaderPayload: header_length {h} exceeds at least one input "
                f"(input lengths {len(a)}, {len(b)})"
            )
        a_payload = a[h:]
        b_payload = b[h:]
        payload_result = self.payload_op.apply(a_payload, b_payload)
        if self.preserve_header is None:
            return tuple(payload_result)
        if self.preserve_header == "a":
            return tuple(a[:h]) + tuple(payload_result)
        # "b"
        return tuple(b[:h]) + tuple(payload_result)


@dataclass(frozen=True)
class IndexDriven:
    """One input drives positional / skip choices; the other supplies symbols.

    First arg ``indices`` provides position numbers or skip counts; second
    arg ``source`` provides the symbol pool to read from.

    Modes:
      "lookup"  — output[i] = source[indices[i] % len(source)]
                  (indices used as direct positions, wrapped mod length)
      "skip"    — walk source by indices[i] steps each, emit successive
                  positions:
                      pos = 0
                      for v in indices:
                          pos = (pos + v) % len(source)
                          output.append(source[pos])

    Output length == len(indices).
    """

    mode: str    # "lookup" | "skip"

    def __post_init__(self) -> None:
        if self.mode not in ("lookup", "skip"):
            raise SourceError(
                f"IndexDriven: mode must be 'lookup' or 'skip', "
                f"got {self.mode!r}"
            )

    @property
    def name(self) -> str:
        return f"index_{self.mode}"

    def apply(self, *msgs: Sequence[int]) -> RuneSeq:
        if len(msgs) != 2:
            raise SourceError(
                f"IndexDriven requires 2 inputs, got {len(msgs)}"
            )
        indices, source = msgs
        if len(source) == 0:
            return ()
        n = len(source)
        if self.mode == "lookup":
            return tuple(source[indices[i] % n] for i in range(len(indices)))
        # skip
        out: list[int] = []
        pos = 0
        for v in indices:
            pos = (pos + v) % n
            out.append(source[pos])
        return tuple(out)


# ===========================================================================
# Source protocol and concrete sources
# ===========================================================================

@runtime_checkable
class Source(Protocol):
    """A way to fill an input slot in a Hypothesis.

    Concrete implementations resolve themselves against a corpus to produce
    a rune sequence.
    """
    name: str

    def resolve(self, corpus: ec.Corpus) -> RuneSeq: ...


@dataclass(frozen=True)
class SingleMessage:
    """Slot filled by one ciphertext, identified by short code."""
    code: str

    @property
    def name(self) -> str:
        return f"single({self.code})"

    def resolve(self, corpus: ec.Corpus) -> RuneSeq:
        try:
            return corpus.by_short(self.code)
        except ec.CorpusError as e:
            raise SourceError(
                f"SingleMessage.resolve: {self.code!r}: {e}"
            )


@dataclass(frozen=True)
class MergedMessages:
    """Slot filled by combining N ciphertexts via a MergeOp.

    The order of ``codes`` matters — most merge ops are asymmetric. For
    example, ``MergedMessages(("E1","W1"), Concat())`` is not the same as
    ``MergedMessages(("W1","E1"), Concat())``.
    """
    codes: tuple[str, ...]
    op: MergeOp

    def __post_init__(self) -> None:
        if len(self.codes) < 1:
            raise SourceError(
                "MergedMessages: at least 1 code required"
            )

    @property
    def name(self) -> str:
        return f"merge({'+'.join(self.codes)},{self.op.name})"

    def resolve(self, corpus: ec.Corpus) -> RuneSeq:
        try:
            msgs = [corpus.by_short(c) for c in self.codes]
        except ec.CorpusError as e:
            raise SourceError(f"MergedMessages.resolve: {e}")
        return self.op.apply(*msgs)


# ===========================================================================
# Enumeration helpers
# ===========================================================================

# Default header lengths align with the phase-1 structural findings:
#   0 = no strip (baseline)
#   1 = strip sigma0 only (the position-0 variable)
#   2 = strip through position-1 universal (66)
#   3 = strip through both universal positions (66, 5)
#   5 = strip through the 3/6 split region end (pos 5 last 3-vs-6)
#   9 = strip through the 3/4 split region end
DEFAULT_HEADER_LENGTHS: tuple[int, ...] = (0, 1, 2, 3, 5, 9)


def enumerate_base_merge_ops(
    deck_size: int = DEFAULT_DECK_SIZE,
) -> Iterator[MergeOp]:
    """Yield the non-composite merge ops (everything except HeaderPayload)."""
    yield Concat()
    for op in ("add", "sub", "xor"):
        yield CyclicCombine(op=op, deck_size=deck_size)
    yield Interleave(start=0)
    yield Interleave(start=1)
    for op in ("add", "sub", "xor"):
        yield TruncatedAlign(op=op, deck_size=deck_size)
    yield IndexDriven(mode="lookup")
    yield IndexDriven(mode="skip")


def enumerate_merge_ops(
    deck_size: int = DEFAULT_DECK_SIZE,
    include_header_payload: bool = True,
    header_lengths: Sequence[int] = DEFAULT_HEADER_LENGTHS,
    inner_op_filter: Sequence[str] | None = None,
) -> Iterator[MergeOp]:
    """Yield the full default sweep of merge operations.

    Calibrated against the EyeSieve corpus:
    - Base ops cover the standard merge families
    - HeaderPayload variants sweep ``header_lengths`` × inner ops × {None, "a"}
      preserve-header values

    ``inner_op_filter`` (optional) restricts which inner ops are used for the
    HeaderPayload composition. Defaults to a sensible subset that avoids
    nested HeaderPayloads (no recursion at this layer).
    """
    yield from enumerate_base_merge_ops(deck_size=deck_size)

    if not include_header_payload:
        return

    # Inner ops for HeaderPayload composition — explicitly NOT including
    # IndexDriven or another HeaderPayload (nesting handled later if needed).
    default_inner_names = (
        "concat", "cyclic_add", "cyclic_sub",
        "trunc_add", "trunc_sub", "interleave(start=0)",
    )
    selected_names = (
        tuple(inner_op_filter) if inner_op_filter else default_inner_names
    )

    inner_pool: list[MergeOp] = []
    for op in enumerate_base_merge_ops(deck_size=deck_size):
        if op.name in selected_names:
            inner_pool.append(op)

    for h in header_lengths:
        for inner in inner_pool:
            yield HeaderPayload(header_length=h, payload_op=inner)
            yield HeaderPayload(header_length=h, payload_op=inner,
                                preserve_header="a")


def estimated_count(
    deck_size: int = DEFAULT_DECK_SIZE,
    include_header_payload: bool = True,
    header_lengths: Sequence[int] = DEFAULT_HEADER_LENGTHS,
) -> int:
    """Total merge-op count yielded by ``enumerate_merge_ops`` for given bounds."""
    return sum(1 for _ in enumerate_merge_ops(
        deck_size=deck_size,
        include_header_payload=include_header_payload,
        header_lengths=header_lengths,
    ))
