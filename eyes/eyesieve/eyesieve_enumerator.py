"""eyesieve_enumerator.py — hypothesis enumerators.

THEORY 1 (Theory1Enumerator)
============================
Ben's stated theory: four east-west paired messages with E5 as the
decryption key, used as-is. Key derivation: Identity only.
Default size: 7,968 hypotheses.

THEORY 2 (Theory2Enumerator, phase 9)
=====================================
E5 transformed (not used as-is). Key derivation iterates over
SelfMerge / CrossMerge / ConstantMerge variants.
Default size: 7,968 × 56 = 446,208 hypotheses.
"""

from __future__ import annotations
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Sequence

import eyesieve_ciphers as eci
import eyesieve_corpus as ec
import eyesieve_hypothesis as eh
import eyesieve_keyderiv as ekd
import eyesieve_sources as es

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"


class EnumeratorError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: enumerator :: {msg}")


# ============================================================================
# Theory 1
# ============================================================================

@dataclass(frozen=True)
class Theory1Config:
    strict_pairing: bool = True
    bidirectional: bool = True
    fixed_key_E5: bool = True
    include_xor_ciphers: bool = True


class Theory1Enumerator:
    """Theory 1 hypothesis enumerator (Identity key derivation only)."""

    def __init__(self, corpus, config=None):
        self.corpus = corpus
        self.config = config or Theory1Config()

    def __iter__(self):
        deck = self.corpus.deck_size
        ciphers = self._ciphers(deck)
        merge_ops = list(es.enumerate_merge_ops(deck_size=deck))
        derivation = ekd.Identity()
        for key_code in self._key_candidates():
            available_east = self._available_east(key_code)
            for east_code, west_code in self._pairs(available_east):
                for first, second in self._orderings(east_code, west_code):
                    for op in merge_ops:
                        ib = es.MergedMessages(codes=(first, second), op=op)
                        for cipher in ciphers:
                            yield eh.Hypothesis(
                                input_binding=ib,
                                key_binding=es.SingleMessage(code=key_code),
                                key_derivation=derivation,
                                cipher=cipher,
                            )

    def _ciphers(self, deck):
        ciphers = list(eci.enumerate_ciphers(deck_size=deck))
        if not self.config.include_xor_ciphers:
            ciphers = [c for c in ciphers if c.name != "xor_stream"]
        return ciphers

    def _key_candidates(self):
        if self.config.fixed_key_E5:
            return ("E5",)
        return self.corpus.east_codes()

    def _available_east(self, key_code):
        return tuple(c for c in self.corpus.east_codes() if c != key_code)

    def _pairs(self, available_east):
        west = self.corpus.west_codes()
        if self.config.strict_pairing:
            # CORPUS ASSUMPTION: codes are "E<idx>"/"W<idx>" where the
            # suffix defines the same-index pair relation.
            west_by_index = {w[1:]: w for w in west}
            pairs = []
            for e in available_east:
                idx = e[1:]
                if idx in west_by_index:
                    pairs.append((e, west_by_index[idx]))
            return tuple(pairs)
        return tuple((e, w) for e in available_east for w in west)

    def _orderings(self, east_code, west_code):
        if self.config.bidirectional:
            return ((east_code, west_code), (west_code, east_code))
        return ((east_code, west_code),)

    def estimated_count(self):
        deck = self.corpus.deck_size
        n_ciphers = len(self._ciphers(deck))
        n_merge_ops = sum(1 for _ in es.enumerate_merge_ops(deck_size=deck))
        n_orderings = 2 if self.config.bidirectional else 1
        total = 0
        for key_code in self._key_candidates():
            available_east = self._available_east(key_code)
            n_pairs = len(self._pairs(available_east))
            total += n_pairs * n_orderings * n_merge_ops * n_ciphers
        return total


def make_theory1(corpus, **kwargs):
    return Theory1Enumerator(corpus=corpus, config=Theory1Config(**kwargs))


# ============================================================================
# Theory 2 (phase 9)
# ============================================================================

@dataclass(frozen=True)
class Theory2Config:
    """Configuration for Theory 2 enumeration.

    The first four knobs (strict_pairing, bidirectional, fixed_key_E5,
    include_xor_ciphers) match Theory1Config and control the same
    dimensions of the search space. The remaining knobs are Theory 2
    specific:

      include_self_merge      — SelfMerge derivations (E5 ⊕ permuted(E5))
      include_cross_merge     — CrossMerge derivations (E5 ⊕ E_i for i≠key)
      include_constant_merge  — ConstantMerge derivations (E5 ⊕ pattern)
      combine_op_names        — which MergeOp names to test as the combiner
      permutation_names       — which Permutation names to test in SelfMerge
    """
    strict_pairing: bool = True
    bidirectional: bool = True
    fixed_key_E5: bool = True
    include_xor_ciphers: bool = True
    include_self_merge: bool = True
    include_cross_merge: bool = True
    include_constant_merge: bool = True
    combine_op_names: tuple[str, ...] = ekd.THEORY2_DEFAULT_COMBINE_OP_NAMES
    permutation_names: tuple[str, ...] = ekd.THEORY2_DEFAULT_PERMUTATION_NAMES


class Theory2Enumerator:
    """Theory 2 hypothesis enumerator (SelfMerge / CrossMerge / ConstantMerge
    key derivations). Identity derivation is NOT included to avoid
    duplication with Theory 1 — chain Theory1Enumerator + Theory2Enumerator
    via itertools.chain for a union sweep.
    """

    def __init__(self, corpus, config=None):
        self.corpus = corpus
        self.config = config or Theory2Config()

    def __iter__(self):
        deck = self.corpus.deck_size
        ciphers = self._ciphers(deck)
        merge_ops = list(es.enumerate_merge_ops(deck_size=deck))
        for key_code in self._key_candidates():
            # Cross-merge derivations exclude the current key_code, so we
            # re-enumerate per key_code. SelfMerge and ConstantMerge are
            # key-code-independent but pulled through the same call for
            # simplicity.
            derivations = list(ekd.enumerate_theory2(
                self.corpus,
                key_code=key_code,
                combine_op_names=self.config.combine_op_names,
                permutation_names=self.config.permutation_names,
                include_self=self.config.include_self_merge,
                include_cross=self.config.include_cross_merge,
                include_constant=self.config.include_constant_merge,
            ))
            available_east = self._available_east(key_code)
            for east_code, west_code in self._pairs(available_east):
                for first, second in self._orderings(east_code, west_code):
                    for op in merge_ops:
                        ib = es.MergedMessages(codes=(first, second), op=op)
                        for derivation in derivations:
                            for cipher in ciphers:
                                yield eh.Hypothesis(
                                    input_binding=ib,
                                    key_binding=es.SingleMessage(code=key_code),
                                    key_derivation=derivation,
                                    cipher=cipher,
                                )

    # Same skeleton helpers as Theory1Enumerator. Duplicating for clarity
    # rather than extracting a base class — the two enumerators may diverge
    # further as Theory 2 evolves.

    def _ciphers(self, deck):
        ciphers = list(eci.enumerate_ciphers(deck_size=deck))
        if not self.config.include_xor_ciphers:
            ciphers = [c for c in ciphers if c.name != "xor_stream"]
        return ciphers

    def _key_candidates(self):
        if self.config.fixed_key_E5:
            return ("E5",)
        return self.corpus.east_codes()

    def _available_east(self, key_code):
        return tuple(c for c in self.corpus.east_codes() if c != key_code)

    def _pairs(self, available_east):
        west = self.corpus.west_codes()
        if self.config.strict_pairing:
            west_by_index = {w[1:]: w for w in west}
            pairs = []
            for e in available_east:
                idx = e[1:]
                if idx in west_by_index:
                    pairs.append((e, west_by_index[idx]))
            return tuple(pairs)
        return tuple((e, w) for e in available_east for w in west)

    def _orderings(self, east_code, west_code):
        if self.config.bidirectional:
            return ((east_code, west_code), (west_code, east_code))
        return ((east_code, west_code),)

    def estimated_count(self):
        deck = self.corpus.deck_size
        n_ciphers = len(self._ciphers(deck))
        n_merge_ops = sum(1 for _ in es.enumerate_merge_ops(deck_size=deck))
        n_orderings = 2 if self.config.bidirectional else 1
        total = 0
        for key_code in self._key_candidates():
            n_derivations = ekd.estimated_count_theory2(
                self.corpus,
                key_code=key_code,
                combine_op_names=self.config.combine_op_names,
                permutation_names=self.config.permutation_names,
                include_self=self.config.include_self_merge,
                include_cross=self.config.include_cross_merge,
                include_constant=self.config.include_constant_merge,
            )
            available_east = self._available_east(key_code)
            n_pairs = len(self._pairs(available_east))
            total += n_pairs * n_orderings * n_merge_ops * n_ciphers * n_derivations
        return total


def make_theory2(corpus, **kwargs):
    return Theory2Enumerator(corpus=corpus, config=Theory2Config(**kwargs))


# ============================================================================
# Union enumerator: Theory 1 + Theory 2
# ============================================================================

class TheoryUnionEnumerator:
    """Yields hypotheses from Theory 1 first, then Theory 2.

    Useful for end-to-end runs that want to sweep both theories without
    explicit itertools.chain in user code. The order is Theory 1 → Theory 2,
    so Theory 1 hypotheses always appear before Theory 2 ones — preserving
    deterministic ordering for checkpointing.
    """

    def __init__(self, corpus,
                 theory1_config: Theory1Config | None = None,
                 theory2_config: Theory2Config | None = None):
        self.corpus = corpus
        self._t1 = Theory1Enumerator(corpus, theory1_config)
        self._t2 = Theory2Enumerator(corpus, theory2_config)

    def __iter__(self):
        yield from self._t1
        yield from self._t2

    def estimated_count(self):
        return self._t1.estimated_count() + self._t2.estimated_count()
