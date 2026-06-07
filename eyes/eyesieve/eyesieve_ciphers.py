#!/usr/bin/env python3
"""eyesieve_ciphers.py — cipher decryption operations.

Phase 3 of the EyeSieve pipeline. Each cipher exposes ``encrypt`` and
``decrypt`` methods over rune sequences. The framework primarily uses
``decrypt`` — given a ciphertext and a key, recover candidate plaintext.
``encrypt`` exists so every cipher can be validated via encrypt-then-
decrypt round-trip tests.

CIPHER FAMILIES
===============
Stream / classical-modular:
  XORStream          ct[i] = pt[i] XOR key[i % K]                 (self-inverse)
  Vigenere           ct[i] = (pt[i] + key[i % K]) mod N
  Beaufort           ct[i] = (key[i % K] - pt[i]) mod N           (self-inverse)
  VariantBeaufort    ct[i] = (pt[i] - key[i % K]) mod N

Autokey (key extends with plaintext after exhaustion):
  VigenereAutokey    Vigenère with k_eff[i>=K] = pt[i-K]
  BeaufortAutokey    Beaufort with k_eff[i>=K] = pt[i-K]

Other classical:
  Affine             ct[i] = (a * pt[i] + b) mod N; (a, b) derived from key
  KeywordSubstitution    monoalphabetic; key derives a permutation by the
                         classical keyword-first method
  ColumnarTransposition  columnar transposition with key-driven column order

Vigenere vs CyclicCombine(add)
==============================
Both perform additive modular combine. Vigenere is a *cipher* (its decrypt
SUBTRACTS the key), while CyclicCombine(op="add") is a *merge* (combining
two ciphertexts produces a third ciphertext-like artifact). The math is
identical; the semantic role is different.

XOR + 83-symbol alphabet
========================
XOR is not closed on a non-power-of-2 alphabet (deck_size=83). XOR-decrypt
outputs frequently fall outside [0, 82]; the alphabet-closure sieve stage
in phase 5 will kill those hypotheses. Included for completeness.

ERROR CONTRACT
==============
All failures raise ``CipherError`` with the standard error-code prefix
``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, Sequence, runtime_checkable

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

RuneSeq = tuple[int, ...]
DEFAULT_DECK_SIZE = 83


class CipherError(Exception):
    """Raised on any cipher contract violation."""

    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: ciphers :: {msg}")


# ===========================================================================
# Cipher protocol
# ===========================================================================

@runtime_checkable
class Cipher(Protocol):
    """Structural protocol — concrete ciphers don't inherit, only expose
    ``name``, ``encrypt``, and ``decrypt``."""
    name: str

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq: ...
    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq: ...


# ---------------------------------------------------------------------------
# Shared validators
# ---------------------------------------------------------------------------

def _require_nonempty_key(name: str, key: Sequence[int]) -> None:
    if len(key) == 0:
        raise CipherError(f"{name}: key must be non-empty")


def _require_in_alphabet(name: str, label: str,
                          seq: Sequence[int], deck_size: int) -> None:
    for j, v in enumerate(seq):
        if not (0 <= v < deck_size):
            raise CipherError(
                f"{name}: {label}[{j}] = {v} out of alphabet [0, {deck_size})"
            )


# ===========================================================================
# XOR stream cipher
# ===========================================================================

@dataclass(frozen=True)
class XORStream:
    """ct[i] = pt[i] XOR key[i % K]. Self-inverse (encrypt == decrypt).

    Note: XOR is not closed on a non-power-of-2 alphabet. Most XOR outputs
    on the 83-symbol corpus will fall outside [0, 82] and be killed by
    the alphabet-closure sieve in phase 5. Included for completeness.

    XOR does not validate alphabet-closure of inputs or outputs — XOR
    operates on raw integers, and the framework deliberately allows
    out-of-alphabet outputs here so the sieve can detect them downstream.
    """

    name: str = "xor_stream"

    def _apply(self, seq: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        n_key = len(key)
        return tuple(seq[i] ^ key[i % n_key] for i in range(len(seq)))

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        return self._apply(plaintext, key)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        return self._apply(ciphertext, key)


# ===========================================================================
# Vigenère and Beaufort families
# ===========================================================================

@dataclass(frozen=True)
class Vigenere:
    """Classical Vigenère.

        encrypt: ct[i] = (pt[i] + key[i % K]) mod N
        decrypt: pt[i] = (ct[i] - key[i % K]) mod N
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "vigenere"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"Vigenere: deck_size must be >= 2, got {self.deck_size}"
            )

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        n = len(key)
        return tuple((plaintext[i] + key[i % n]) % self.deck_size
                     for i in range(len(plaintext)))

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        n = len(key)
        return tuple((ciphertext[i] - key[i % n]) % self.deck_size
                     for i in range(len(ciphertext)))


@dataclass(frozen=True)
class Beaufort:
    """Classical Beaufort. Self-inverse.

        encrypt: ct[i] = (key[i % K] - pt[i]) mod N
        decrypt: pt[i] = (key[i % K] - ct[i]) mod N
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "beaufort"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"Beaufort: deck_size must be >= 2, got {self.deck_size}"
            )

    def _apply(self, seq: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "data", seq, self.deck_size)
        n = len(key)
        return tuple((key[i % n] - seq[i]) % self.deck_size
                     for i in range(len(seq)))

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        return self._apply(plaintext, key)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        return self._apply(ciphertext, key)


@dataclass(frozen=True)
class VariantBeaufort:
    """Variant Beaufort (a.k.a. German variant).

        encrypt: ct[i] = (pt[i] - key[i % K]) mod N
        decrypt: pt[i] = (ct[i] + key[i % K]) mod N
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "variant_beaufort"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"VariantBeaufort: deck_size must be >= 2, got {self.deck_size}"
            )

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        n = len(key)
        return tuple((plaintext[i] - key[i % n]) % self.deck_size
                     for i in range(len(plaintext)))

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        n = len(key)
        return tuple((ciphertext[i] + key[i % n]) % self.deck_size
                     for i in range(len(ciphertext)))


# ===========================================================================
# Autokey variants
# ===========================================================================

@dataclass(frozen=True)
class VigenereAutokey:
    """Vigenère autokey: after the seed key is exhausted, the recovered
    plaintext extends the effective key.

        encrypt: ct[i] = (pt[i] + k_i) mod N   where
                 k_i = key[i]      if i < K
                 k_i = pt[i - K]   if i >= K

        decrypt: pt[i] = (ct[i] - k_i) mod N   (recursive: k_i for i>=K
                                                depends on pt[i-K])
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "vigenere_autokey"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"VigenereAutokey: deck_size must be >= 2, got {self.deck_size}"
            )

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        K = len(key)
        ct: list[int] = []
        for i, p in enumerate(plaintext):
            k = key[i] if i < K else plaintext[i - K]
            ct.append((p + k) % self.deck_size)
        return tuple(ct)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        K = len(key)
        pt: list[int] = []
        for i, c in enumerate(ciphertext):
            k = key[i] if i < K else pt[i - K]
            pt.append((c - k) % self.deck_size)
        return tuple(pt)


@dataclass(frozen=True)
class BeaufortAutokey:
    """Beaufort autokey (plaintext-extending).

    Unlike non-autokey Beaufort (which IS self-inverse), the autokey
    variant is NOT self-inverse: ``encrypt(encrypt(pt, k), k) != pt`` in
    general. The reason: ``encrypt`` extends the keystream with the
    plaintext supplied as input, whereas ``decrypt`` extends it with the
    plaintext as it's being recovered. These are different sources, so
    applying ``encrypt`` twice does not recover the original.

    The encrypt/decrypt pair IS a proper inverse pair —
    ``decrypt(encrypt(pt, k), k) == pt`` — which is what the round-trip
    selftest verifies.

        encrypt: ct[i] = (k_i - pt[i]) mod N
                 where k_i = key[i] for i < K, else pt[i - K]

        decrypt: pt[i] = (k_i - ct[i]) mod N
                 where k_i = key[i] for i < K, else recovered_pt[i - K]
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "beaufort_autokey"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"BeaufortAutokey: deck_size must be >= 2, got {self.deck_size}"
            )

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        K = len(key)
        ct: list[int] = []
        for i, p in enumerate(plaintext):
            k = key[i] if i < K else plaintext[i - K]
            ct.append((k - p) % self.deck_size)
        return tuple(ct)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        K = len(key)
        pt: list[int] = []
        for i, c in enumerate(ciphertext):
            k = key[i] if i < K else pt[i - K]
            pt.append((k - c) % self.deck_size)
        return tuple(pt)


# ===========================================================================
# Affine cipher
# ===========================================================================

@dataclass(frozen=True)
class Affine:
    """Affine cipher with key-derived (a, b).

        encrypt: ct[i] = (a * pt[i] + b) mod N
        decrypt: pt[i] = (a^-1 * (ct[i] - b)) mod N

        a = (key[0] mod (N - 1)) + 1   ensures a in [1, N-1]
        b = key[1] mod N               if K >= 2, else 0

    Requires N to be prime (so any a in [1, N-1] is invertible). N = 83 is
    prime; framework will raise if a non-prime deck_size is supplied.
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "affine"

    def __post_init__(self) -> None:
        if self.deck_size < 3:
            raise CipherError(
                f"Affine: deck_size must be >= 3, got {self.deck_size}"
            )
        n = self.deck_size
        for d in range(2, int(n ** 0.5) + 1):
            if n % d == 0:
                raise CipherError(
                    f"Affine: deck_size {n} is not prime (divisible by {d}); "
                    f"affine cipher requires prime alphabet for guaranteed "
                    f"invertibility"
                )

    def _derive_ab(self, key: Sequence[int]) -> tuple[int, int]:
        _require_nonempty_key(self.name, key)
        _require_in_alphabet(self.name, "key", key, self.deck_size)
        n = self.deck_size
        a = (key[0] % (n - 1)) + 1
        b = (key[1] % n) if len(key) >= 2 else 0
        return a, b

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        a, b = self._derive_ab(key)
        n = self.deck_size
        return tuple((a * p + b) % n for p in plaintext)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        a, b = self._derive_ab(key)
        n = self.deck_size
        # Modular inverse via Fermat's little theorem (n is prime)
        a_inv = pow(a, n - 2, n)
        return tuple((a_inv * (c - b)) % n for c in ciphertext)


# ===========================================================================
# Keyword substitution
# ===========================================================================

@dataclass(frozen=True)
class KeywordSubstitution:
    """Monoalphabetic substitution; the key derives a permutation of
    [0, deck_size) via the classical keyword method:

      1. Walk the key left-to-right, collecting unique in-range rune values
         in order of first appearance.
      2. Append the remaining [0, N) values in numerical order.
      3. The result is the encryption permutation: ct[i] = perm[pt[i]].

    Decryption applies the inverse permutation.
    """
    deck_size: int = DEFAULT_DECK_SIZE

    @property
    def name(self) -> str:
        return "keyword_substitution"

    def __post_init__(self) -> None:
        if self.deck_size < 2:
            raise CipherError(
                f"KeywordSubstitution: deck_size must be >= 2, "
                f"got {self.deck_size}"
            )

    def _derive_perm(self, key: Sequence[int]) -> RuneSeq:
        _require_nonempty_key(self.name, key)
        seen: set[int] = set()
        perm: list[int] = []
        for v in key:
            if 0 <= v < self.deck_size and v not in seen:
                perm.append(v)
                seen.add(v)
        for v in range(self.deck_size):
            if v not in seen:
                perm.append(v)
        if len(perm) != self.deck_size:
            raise CipherError(
                f"{self.name}: derived perm has length {len(perm)}, "
                f"expected {self.deck_size}"
            )
        return tuple(perm)

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_in_alphabet(self.name, "plaintext", plaintext, self.deck_size)
        perm = self._derive_perm(key)
        return tuple(perm[p] for p in plaintext)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        _require_in_alphabet(self.name, "ciphertext", ciphertext, self.deck_size)
        perm = self._derive_perm(key)
        inv_perm = [0] * self.deck_size
        for i, v in enumerate(perm):
            inv_perm[v] = i
        return tuple(inv_perm[c] for c in ciphertext)


# ===========================================================================
# Columnar transposition
# ===========================================================================

@dataclass(frozen=True)
class ColumnarTransposition:
    """Columnar transposition cipher with key-derived column order.

    The first ``key_columns`` values of the key define a column order:
    sort the column indices by their key values (stable on ties).

    Encryption:
      1. Write plaintext row-major into a grid with ``key_columns`` columns.
      2. Read columns in the sorted-key order; concatenate.

    Decryption is the inverse: distribute ciphertext characters back into
    columns in the same order, then read row-major.

    The last row may be partial; column lengths are derived from total
    length and column count.
    """
    deck_size: int = DEFAULT_DECK_SIZE
    key_columns: int = 5

    @property
    def name(self) -> str:
        return f"columnar_transposition(k={self.key_columns})"

    def __post_init__(self) -> None:
        if self.key_columns < 2:
            raise CipherError(
                f"ColumnarTransposition: key_columns must be >= 2, "
                f"got {self.key_columns}"
            )
        if self.deck_size < 2:
            raise CipherError(
                f"ColumnarTransposition: deck_size must be >= 2, "
                f"got {self.deck_size}"
            )

    def _derive_column_order(self, key: Sequence[int]) -> tuple[int, ...]:
        K = self.key_columns
        if len(key) < K:
            raise CipherError(
                f"{self.name}: key length {len(key)} < required column count {K}"
            )
        return tuple(sorted(range(K), key=lambda i: (key[i], i)))

    def encrypt(self, plaintext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        K = self.key_columns
        order = self._derive_column_order(key)
        n = len(plaintext)
        if n == 0:
            return ()
        rows = (n + K - 1) // K
        # Last row may be partial. Columns [0, last_row_width) get `rows`
        # positions; columns [last_row_width, K) get `rows - 1`.
        last_row_width = n - K * (rows - 1)
        out: list[int] = []
        for col in order:
            col_rows = rows if col < last_row_width else rows - 1
            for r in range(col_rows):
                idx = r * K + col
                out.append(plaintext[idx])
        return tuple(out)

    def decrypt(self, ciphertext: Sequence[int], key: Sequence[int]) -> RuneSeq:
        K = self.key_columns
        order = self._derive_column_order(key)
        n = len(ciphertext)
        if n == 0:
            return ()
        rows = (n + K - 1) // K
        last_row_width = n - K * (rows - 1)
        # Refill columns in the same order they were read during encryption
        col_data: list[list[int]] = [[] for _ in range(K)]
        pos = 0
        for col in order:
            col_rows = rows if col < last_row_width else rows - 1
            col_data[col] = list(ciphertext[pos:pos + col_rows])
            pos += col_rows
        out: list[int] = []
        for r in range(rows):
            for c in range(K):
                if r < len(col_data[c]):
                    out.append(col_data[c][r])
        return tuple(out)


# ===========================================================================
# Enumeration
# ===========================================================================

def enumerate_ciphers(deck_size: int = DEFAULT_DECK_SIZE) -> Iterator[Cipher]:
    """Yield the default sweep of ciphers worth testing.

    For ColumnarTransposition, sweeps a few small column counts.
    """
    yield XORStream()
    yield Vigenere(deck_size=deck_size)
    yield Beaufort(deck_size=deck_size)
    yield VariantBeaufort(deck_size=deck_size)
    yield VigenereAutokey(deck_size=deck_size)
    yield BeaufortAutokey(deck_size=deck_size)
    yield Affine(deck_size=deck_size)
    yield KeywordSubstitution(deck_size=deck_size)
    for k in (3, 4, 5, 7):
        yield ColumnarTransposition(deck_size=deck_size, key_columns=k)


def estimated_count(deck_size: int = DEFAULT_DECK_SIZE) -> int:
    return sum(1 for _ in enumerate_ciphers(deck_size=deck_size))
