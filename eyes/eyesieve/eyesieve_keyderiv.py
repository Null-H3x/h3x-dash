"""eyesieve_keyderiv.py — key-derivation protocol and implementations.

The KeyDerivation stage transforms a key source (typically E5) into the
effective key passed to the cipher's decrypt method.

THEORY 1
========
``Identity`` — use the key source unchanged. E5 IS the literal key.

THEORY 2 (phase 9)
==================
- ``SelfMerge``      — E5 combined with a permutation of itself
- ``CrossMerge``     — E5 combined with another corpus message
- ``ConstantMerge``  — E5 combined with a position-derived constant pattern

All Theory 2 derivations are parametric over a combine operation
(MergeOp from eyesieve_sources), so the same merge algebra used for
input-binding composition is reused here.

ERROR CONTRACT
==============
All failures raise ``KeyDerivError`` with the standard prefix
``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterator, Protocol, Sequence, runtime_checkable

import eyesieve_corpus as ec
import eyesieve_permutations as ep
import eyesieve_sources as es

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
RuneSeq = tuple[int, ...]


class KeyDerivError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: keyderiv :: {msg}")


@runtime_checkable
class KeyDerivation(Protocol):
    name: str
    def derive(self, key_source: Sequence[int], corpus: ec.Corpus) -> RuneSeq: ...


# ============================================================================
# Theory 1
# ============================================================================

@dataclass(frozen=True)
class Identity:
    """Theory 1: use the key source unchanged."""

    @property
    def name(self) -> str:
        return "identity"

    def derive(self, key_source, corpus):
        if len(key_source) == 0:
            raise KeyDerivError("identity: empty key source")
        return tuple(key_source)


# ============================================================================
# Theory 2 — SelfMerge
# ============================================================================

@dataclass(frozen=True)
class SelfMerge:
    """Theory 2: derive key by combining key_source with a permutation
    of itself.

    ``perm.apply(key_source)`` produces a transformed version of the source;
    ``combine_op.apply(key_source, transformed)`` merges them position-wise
    (or however the merge op chooses).
    """
    permutation: ep.Permutation
    combine_op: es.MergeOp

    @property
    def name(self) -> str:
        return f"self({self.permutation.name},{self.combine_op.name})"

    def derive(self, key_source, corpus):
        if len(key_source) == 0:
            raise KeyDerivError("self_merge: empty key source")
        try:
            permuted = self.permutation.apply(key_source)
        except Exception as e:
            raise KeyDerivError(
                f"self_merge: permutation {self.permutation.name} raised "
                f"{type(e).__name__}: {e}"
            )
        try:
            return self.combine_op.apply(key_source, permuted)
        except es.SourceError as e:
            # Surface as KeyDerivError (typed sieve-caught error)
            raise KeyDerivError(
                f"self_merge: combine_op {self.combine_op.name} failed: {e}"
            )


# ============================================================================
# Theory 2 — CrossMerge
# ============================================================================

@dataclass(frozen=True)
class CrossMerge:
    """Theory 2: derive key by combining key_source with another corpus
    message (e.g., combine E5 with E1)."""
    cross_code: str
    combine_op: es.MergeOp

    @property
    def name(self) -> str:
        return f"cross({self.cross_code},{self.combine_op.name})"

    def derive(self, key_source, corpus):
        if len(key_source) == 0:
            raise KeyDerivError("cross_merge: empty key source")
        try:
            cross = corpus.by_short(self.cross_code)
        except (KeyError, ec.CorpusError) as e:
            raise KeyDerivError(
                f"cross_merge: unknown cross source {self.cross_code!r}: {e}"
            )
        if len(cross) == 0:
            raise KeyDerivError(
                f"cross_merge: empty cross source {self.cross_code!r}"
            )
        try:
            return self.combine_op.apply(key_source, cross)
        except es.SourceError as e:
            raise KeyDerivError(
                f"cross_merge: combine_op {self.combine_op.name} failed: {e}"
            )


# ============================================================================
# Theory 2 — ConstantMerge
# ============================================================================

# Supported constant pattern names — extending this requires adding a
# corresponding generator in _build_constant() below.
CONSTANT_PATTERNS: tuple[str, ...] = (
    "zeros", "ones", "counter", "reverse_counter", "deck_modulo",
)


def _build_constant(pattern: str, length: int, deck_size: int) -> RuneSeq:
    if pattern == "zeros":
        return (0,) * length
    if pattern == "ones":
        return (1,) * length
    if pattern == "counter":
        return tuple(i % deck_size for i in range(length))
    if pattern == "reverse_counter":
        return tuple((deck_size - 1 - i) % deck_size for i in range(length))
    if pattern == "deck_modulo":
        # A non-trivial stride pattern that hits many values without trivial
        # repetition. Uses a stride coprime to deck_size when possible.
        stride = max(1, deck_size // 3 + 1)
        return tuple((i * stride) % deck_size for i in range(length))
    raise KeyDerivError(f"unknown constant pattern: {pattern!r}")


@dataclass(frozen=True)
class ConstantMerge:
    """Theory 2: derive key by combining key_source with a position-derived
    constant pattern (zeros / ones / counter / reverse_counter / deck_modulo)."""
    pattern: str
    combine_op: es.MergeOp

    @property
    def name(self) -> str:
        return f"const({self.pattern},{self.combine_op.name})"

    def derive(self, key_source, corpus):
        if len(key_source) == 0:
            raise KeyDerivError("constant_merge: empty key source")
        constant = _build_constant(self.pattern, len(key_source), corpus.deck_size)
        try:
            return self.combine_op.apply(key_source, constant)
        except es.SourceError as e:
            raise KeyDerivError(
                f"constant_merge: combine_op {self.combine_op.name} failed: {e}"
            )


# ============================================================================
# Enumeration helpers
# ============================================================================

def enumerate_theory1() -> Iterator[KeyDerivation]:
    yield Identity()


def estimated_count_theory1() -> int:
    return sum(1 for _ in enumerate_theory1())


# Curated subsets for Theory 2 enumeration. Full-cartesian over all 25
# permutations × 83 combine ops would yield 2,075 SelfMerge derivations —
# multiplied by Theory 1's 7,968 hypothesis space, that's ~16M total
# hypotheses. We instead curate small subsets and let users opt in to
# broader sweeps via Theory2Config.

# Combine ops used by default in Theory 2. These are the modular,
# alphabet-closed merges most likely to produce usable keys.
THEORY2_DEFAULT_COMBINE_OP_NAMES: tuple[str, ...] = (
    "cyclic_add",
    "cyclic_sub",
    "trunc_add",
    "trunc_sub",
)

# Permutations used by default in SelfMerge. These represent distinct
# structural transformations of E5 — reversing, rotating, striding,
# block-reshaping.
THEORY2_DEFAULT_PERMUTATION_NAMES: tuple[str, ...] = (
    "reverse",
    "rotate_k(1)",
    "rotate_k(7)",
    "stride_n(2)",
    "block_reverse_n(3)",
)


def _select_combine_ops(deck_size: int, names: Sequence[str]) -> list:
    """Pull MergeOp instances by name from the sources enumeration.

    Raises KeyDerivError on an unknown name rather than silently dropping it —
    a typo in a config previously produced a smaller-than-intended sweep with
    no warning, so the run looked complete while skipping whole derivations.
    """
    by_name = {op.name: op for op in es.enumerate_merge_ops(deck_size=deck_size)}
    unknown = [n for n in names if n not in by_name]
    if unknown:
        raise KeyDerivError(
            f"unknown combine op name(s) {unknown!r}; "
            f"valid: {sorted(by_name)}"
        )
    return [by_name[n] for n in names]


def _select_permutations(max_len: int, names: Sequence[str]) -> list:
    """Pull Permutation instances by name. Raises KeyDerivError on an unknown
    name (see _select_combine_ops for the silent-drop hazard this prevents)."""
    by_name = {p.name: p for p in ep.enumerate_permutations(max_len=max_len)}
    unknown = [n for n in names if n not in by_name]
    if unknown:
        raise KeyDerivError(
            f"unknown permutation name(s) {unknown!r}; "
            f"valid: {sorted(by_name)}"
        )
    return [by_name[n] for n in names]


def enumerate_theory2(
    corpus: ec.Corpus,
    key_code: str = "E5",
    combine_op_names: Sequence[str] | None = None,
    permutation_names: Sequence[str] | None = None,
    include_self: bool = True,
    include_cross: bool = True,
    include_constant: bool = True,
) -> Iterator[KeyDerivation]:
    """Yield Theory 2 key derivations.

    The order is: SelfMerge → CrossMerge → ConstantMerge. Identity (the
    Theory 1 baseline) is NOT included — pair this with enumerate_theory1
    via itertools.chain if a union over both theories is desired.

    ``combine_op_names`` defaults to THEORY2_DEFAULT_COMBINE_OP_NAMES.
    ``permutation_names`` defaults to THEORY2_DEFAULT_PERMUTATION_NAMES.
    """
    combine_names = combine_op_names or THEORY2_DEFAULT_COMBINE_OP_NAMES
    perm_names = permutation_names or THEORY2_DEFAULT_PERMUTATION_NAMES

    combine_ops = _select_combine_ops(corpus.deck_size, combine_names)
    perms = _select_permutations(corpus.deck_size, perm_names)

    if include_self:
        for perm in perms:
            for op in combine_ops:
                yield SelfMerge(permutation=perm, combine_op=op)

    if include_cross:
        for cross_code in corpus.east_codes():
            if cross_code == key_code:
                continue
            for op in combine_ops:
                yield CrossMerge(cross_code=cross_code, combine_op=op)

    if include_constant:
        for pattern in CONSTANT_PATTERNS:
            for op in combine_ops:
                yield ConstantMerge(pattern=pattern, combine_op=op)


def estimated_count_theory2(
    corpus: ec.Corpus,
    key_code: str = "E5",
    combine_op_names: Sequence[str] | None = None,
    permutation_names: Sequence[str] | None = None,
    include_self: bool = True,
    include_cross: bool = True,
    include_constant: bool = True,
) -> int:
    return sum(1 for _ in enumerate_theory2(
        corpus, key_code, combine_op_names, permutation_names,
        include_self, include_cross, include_constant
    ))
