#!/usr/bin/env python3
"""eyesieve_permutations.py — parametric permutation families.

Used by Theory 2 key derivation when the effective key is a "shuffled"
version of the key-source message. Enumerating arbitrary 83-symbol
permutations is astronomical (83! >> 10^124), so we restrict to a small
family of structured permutations that cover the cryptographically
interesting cases.

PROTOCOL
========
Every permutation type implements:

    name : str                              # stable identifier for telemetry
    .apply(seq: Sequence[int]) -> tuple    # length-preserving reorder
    .inverse() -> Permutation              # such that p.inverse().apply(p.apply(x)) == x

All implementations are frozen dataclasses — hashable, picklable,
deterministically reproducible across process boundaries.

FAMILIES
========
  Identity            no shuffle (Theory 1 case, also placeholder in Theory 2)
  Reverse             reverse the sequence
  RotateK(k)          rotate left by k positions (k normalized mod len)
  BlockReverseN(n)    reverse each contiguous block of n
  StrideN(n)          read every n'th starting at offset 0, then 1, ..., n-1
  GridTranspose(w)    write w-wide row-major, read column-major
  MessageIndexed(idx) permute by argsort of an external index sequence
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, Sequence, runtime_checkable

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
RuneSeq = tuple[int, ...]


class PermutationError(Exception):
    """Raised on invalid permutation parameters or apply-time mismatches."""
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: permutations :: {msg}")


@runtime_checkable
class Permutation(Protocol):
    """Structural protocol — concrete classes don't need to inherit, only
    to expose ``name`` and ``apply()``/``inverse()``."""
    name: str

    def apply(self, seq: Sequence[int]) -> RuneSeq: ...
    def inverse(self) -> "Permutation": ...


# ---------------------------------------------------------------------------
# Concrete permutations
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    name: str = "identity"

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        return tuple(seq)

    def inverse(self) -> "Identity":
        return self


@dataclass(frozen=True)
class Reverse:
    name: str = "reverse"

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        return tuple(reversed(seq))

    def inverse(self) -> "Reverse":
        return self  # reverse is self-inverse


@dataclass(frozen=True)
class RotateK:
    """Rotate left by k positions. ``k`` is normalized mod len at apply time."""
    k: int

    @property
    def name(self) -> str:
        return f"rotate_k({self.k})"

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        n = len(seq)
        if n == 0:
            return tuple()
        k = self.k % n
        return tuple(seq[k:]) + tuple(seq[:k])

    def inverse(self) -> "RotateK":
        return RotateK(k=-self.k)


@dataclass(frozen=True)
class BlockReverseN:
    """Reverse each contiguous block of size n. Trailing block may be short."""
    n: int

    @property
    def name(self) -> str:
        return f"block_reverse_n({self.n})"

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise PermutationError(f"BlockReverseN: n must be > 0, got {self.n}")

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        out: list[int] = []
        n = self.n
        for i in range(0, len(seq), n):
            block = list(seq[i:i + n])
            block.reverse()
            out.extend(block)
        return tuple(out)

    def inverse(self) -> "BlockReverseN":
        return self  # self-inverse on block-aligned input


@dataclass(frozen=True)
class StrideN:
    """Stride read: emit positions [0, n, 2n, ...], then [1, n+1, ...], etc.

    Equivalent to a transposition: write seq row-wise into an n-row grid,
    read column-major. For a length-L input this is a deterministic
    permutation of L symbols regardless of whether L is divisible by n.
    """
    n: int

    @property
    def name(self) -> str:
        return f"stride_n({self.n})"

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise PermutationError(f"StrideN: n must be > 0, got {self.n}")

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        out: list[int] = []
        for offset in range(self.n):
            out.extend(seq[offset::self.n])
        return tuple(out)

    def inverse(self) -> "_InversePermutation":
        # The inverse depends on input length; we encode the forward perm
        # vector and let the inverse class invert it at apply time.
        return _InversePermutation(forward=self)


@dataclass(frozen=True)
class GridTranspose:
    """Write row-major into a w-wide grid, read column-major. Last row
    may be short; symbols in incomplete column tails are simply skipped
    (so output length == input length)."""
    width: int

    @property
    def name(self) -> str:
        return f"grid_transpose(w={self.width})"

    def __post_init__(self) -> None:
        if self.width <= 0:
            raise PermutationError(f"GridTranspose: width must be > 0, got {self.width}")

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        rows = (len(seq) + self.width - 1) // self.width
        out: list[int] = []
        for col in range(self.width):
            for row in range(rows):
                idx = row * self.width + col
                if idx < len(seq):
                    out.append(seq[idx])
        return tuple(out)

    def inverse(self) -> "_InversePermutation":
        return _InversePermutation(forward=self)


@dataclass(frozen=True)
class MessageIndexed:
    """Permutation driven by an external index sequence (typically another
    message). Indices are argsorted (stable); seq is reordered to match.

    If ``len(indexer) < len(seq)``, raises at apply time. If longer, only
    the first ``len(seq)`` entries are used.
    """
    indexer: tuple[int, ...]

    @property
    def name(self) -> str:
        return f"message_indexed(len={len(self.indexer)})"

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        if len(self.indexer) < len(seq):
            raise PermutationError(
                f"MessageIndexed: indexer length {len(self.indexer)} < "
                f"seq length {len(seq)}"
            )
        order = sorted(range(len(seq)),
                       key=lambda i: (self.indexer[i], i))
        return tuple(seq[i] for i in order)

    def inverse(self) -> "_InversePermutation":
        return _InversePermutation(forward=self)


@dataclass(frozen=True)
class _InversePermutation:
    """Internal helper: invert any forward permutation by computing and
    applying its index vector. Computed lazily per input length."""
    forward: Permutation

    @property
    def name(self) -> str:
        return f"inverse({self.forward.name})"

    def apply(self, seq: Sequence[int]) -> RuneSeq:
        n = len(seq)
        # Compute the forward permutation's effect on indices [0..n)
        index_input = tuple(range(n))
        forward_indices = self.forward.apply(index_input)
        # forward_indices[j] = i means "position j of output comes from
        # position i of input". To invert: place seq[j] at position
        # forward_indices[j] of the output.
        out = [0] * n
        for j, src in enumerate(forward_indices):
            out[src] = seq[j]
        return tuple(out)

    def inverse(self) -> Permutation:
        return self.forward


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def enumerate_permutations(
    max_len: int,
    include_message_indexed: bool = False,
    indexers: Sequence[tuple[int, ...]] | None = None,
) -> Iterator[Permutation]:
    """Yield every parametric permutation worth testing for a given max length.

    Bounds are conservative — small k/n only — because larger values are
    structurally equivalent to combinations of smaller ones in most cases
    and produce diminishing signal.
    """
    yield Identity()
    yield Reverse()

    # Rotations: small primes pick up most interesting structure.
    for k in (1, 2, 3, 5, 7, 11, 13):
        if k < max_len:
            yield RotateK(k=k)

    # Block reversal
    for n in (2, 3, 4, 5, 7):
        if n <= max_len:
            yield BlockReverseN(n=n)

    # Stride
    for n in (2, 3, 4, 5, 7):
        if n <= max_len:
            yield StrideN(n=n)

    # Grid transposition
    for w in range(3, 9):
        if w <= max_len:
            yield GridTranspose(width=w)

    if include_message_indexed and indexers:
        for idx in indexers:
            yield MessageIndexed(indexer=tuple(idx))


def estimated_count(max_len: int, n_indexers: int = 0) -> int:
    """Number of permutations that ``enumerate_permutations`` yields under
    the given bounds. Useful for sizing the hypothesis space ahead of time."""
    dummy_indexers: tuple[tuple[int, ...], ...] | None = None
    if n_indexers > 0:
        dummy_indexers = tuple(tuple(range(max_len)) for _ in range(n_indexers))
    return sum(1 for _ in enumerate_permutations(
        max_len,
        include_message_indexed=(n_indexers > 0),
        indexers=dummy_indexers,
    ))
