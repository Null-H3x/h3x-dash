"""eyesieve_sieve.py — sieve cascade with cheap filter stages.

Phase 5 stages (in order):
  1. LengthSieve              — candidate length within reasonable bounds
  2. AlphabetClosureSieve     — every output value in [0, deck_size)
  3. ICSieve                  — index of coincidence in natural-language range
  4. SymbolDistributionSieve  — no single symbol dominates the output

The cascade catches typed pipeline errors (SourceError, KeyDerivError,
CipherError) and records them as killed_at="execute". Unexpected
exceptions propagate — they're framework bugs, not data conditions.
"""

from __future__ import annotations
from collections import Counter
from dataclasses import dataclass, field
from typing import Protocol, Sequence, runtime_checkable

import eyesieve_ciphers as eci
import eyesieve_corpus as ec
import eyesieve_hypothesis as eh
import eyesieve_keyderiv as ekd
import eyesieve_sources as es

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
RuneSeq = tuple[int, ...]


class SieveError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: sieve :: {msg}")


# ---------- Statistics helpers ----------

def compute_ic(seq: Sequence[int]) -> float:
    """Raw index of coincidence. 0.0 if len < 2. Uniform over n: 1/n."""
    n = len(seq)
    if n < 2:
        return 0.0
    counts = Counter(seq)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def max_symbol_frequency(seq: Sequence[int]) -> float:
    if not seq:
        return 0.0
    return max(Counter(seq).values()) / len(seq)


def distinct_symbol_count(seq: Sequence[int]) -> int:
    return len(set(seq))


# ---------- Per-stage verdict ----------

@dataclass(frozen=True)
class SieveVerdict:
    keep: bool
    reason: str
    metrics: tuple[tuple[str, float], ...] = ()


@runtime_checkable
class SieveStage(Protocol):
    name: str
    # cost_tier is INFORMATIONAL — it describes how expensive the stage is
    # relative to siblings. The cascade runs stages in the order they appear
    # in `SieveCascade.stages`, not sorted by cost_tier. Cascade builders
    # are responsible for declaring cheap stages first.
    cost_tier: int
    def filter(self, hypothesis: eh.Hypothesis, candidate: RuneSeq,
               context: "SieveContext") -> SieveVerdict: ...


@dataclass(frozen=True)
class SieveContext:
    corpus: ec.Corpus


# ---------- Stages ----------

@dataclass(frozen=True)
class LengthSieve:
    min_length: int = 20
    max_length: int = 0
    cost_tier: int = 1

    @property
    def name(self) -> str:
        return "length"

    def filter(self, hypothesis, candidate, context):
        n = len(candidate)
        metrics = (("length", float(n)),)
        if n < self.min_length:
            return SieveVerdict(False, f"length {n} < min {self.min_length}", metrics)
        if self.max_length > 0 and n > self.max_length:
            return SieveVerdict(False, f"length {n} > max {self.max_length}", metrics)
        return SieveVerdict(True, "", metrics)


@dataclass(frozen=True)
class AlphabetClosureSieve:
    cost_tier: int = 1

    @property
    def name(self) -> str:
        return "alphabet_closure"

    def filter(self, hypothesis, candidate, context):
        deck = context.corpus.deck_size
        for j, v in enumerate(candidate):
            if not (0 <= v < deck):
                return SieveVerdict(
                    False,
                    f"value {v} at position {j} outside [0, {deck})",
                    (("first_out_of_range_position", float(j)),
                     ("first_out_of_range_value", float(v))),
                )
        return SieveVerdict(True, "", ())


@dataclass(frozen=True)
class ICSieve:
    min_ic: float = 0.030
    max_ic: float = 0.20
    cost_tier: int = 2

    @property
    def name(self) -> str:
        return "ic"

    def filter(self, hypothesis, candidate, context):
        ic = compute_ic(candidate)
        metrics = (("ic", ic),)
        if ic < self.min_ic:
            return SieveVerdict(False, f"IC {ic:.4f} < min {self.min_ic}", metrics)
        if ic > self.max_ic:
            return SieveVerdict(False, f"IC {ic:.4f} > max {self.max_ic}", metrics)
        return SieveVerdict(True, "", metrics)


@dataclass(frozen=True)
class SymbolDistributionSieve:
    max_freq: float = 0.30
    min_distinct: int = 10
    cost_tier: int = 2

    @property
    def name(self) -> str:
        return "distribution"

    def filter(self, hypothesis, candidate, context):
        if not candidate:
            return SieveVerdict(False, "empty candidate", ())
        freq = max_symbol_frequency(candidate)
        distinct = distinct_symbol_count(candidate)
        metrics = (("max_freq", freq), ("distinct", float(distinct)))
        if freq > self.max_freq:
            return SieveVerdict(
                False,
                f"max-symbol frequency {freq:.3f} > {self.max_freq}",
                metrics,
            )
        if distinct < self.min_distinct:
            return SieveVerdict(
                False,
                f"distinct {distinct} < min {self.min_distinct}",
                metrics,
            )
        return SieveVerdict(True, "", metrics)


# ---------- Cascade ----------

@dataclass(frozen=True)
class SieveResult:
    hypothesis: eh.Hypothesis
    survived: bool
    killed_at: str
    candidate: RuneSeq | None
    verdicts: tuple[tuple[str, SieveVerdict], ...]
    error: str = ""


@dataclass
class SieveTelemetry:
    total_evaluated: int = 0
    execute_failures: int = 0
    survivors: int = 0
    killed_by_stage: dict[str, int] = field(default_factory=dict)
    error_samples: list[str] = field(default_factory=list)
    max_error_samples: int = 50

    def record(self, result: SieveResult) -> None:
        self.total_evaluated += 1
        if result.killed_at == "execute":
            self.execute_failures += 1
            if len(self.error_samples) < self.max_error_samples:
                self.error_samples.append(result.error)
        elif result.survived:
            self.survivors += 1
        else:
            self.killed_by_stage[result.killed_at] = (
                self.killed_by_stage.get(result.killed_at, 0) + 1
            )

    def as_dict(self) -> dict:
        return {
            "total_evaluated": self.total_evaluated,
            "survivors": self.survivors,
            "execute_failures": self.execute_failures,
            "killed_by_stage": dict(self.killed_by_stage),
        }


@dataclass(frozen=True)
class SieveCascade:
    stages: tuple[SieveStage, ...]

    @classmethod
    def default(cls) -> "SieveCascade":
        return cls(stages=(
            LengthSieve(),
            AlphabetClosureSieve(),
            ICSieve(),
            SymbolDistributionSieve(),
        ))

    def evaluate(self, hypothesis: eh.Hypothesis, corpus: ec.Corpus) -> SieveResult:
        # FORWARD-COMPAT NOTE: when phase 7+ adds new typed errors from the
        # pipeline (e.g., MappingError, ScoringError), add their classes to
        # the except tuple below. Unexpected exceptions PROPAGATE — those
        # are framework bugs, not data conditions.
        try:
            candidate = hypothesis.execute(corpus)
        except (es.SourceError, ekd.KeyDerivError, eci.CipherError) as e:
            return SieveResult(
                hypothesis=hypothesis,
                survived=False,
                killed_at="execute",
                candidate=None,
                verdicts=(),
                error=str(e),
            )

        context = SieveContext(corpus=corpus)
        verdicts = []
        for stage in self.stages:
            verdict = stage.filter(hypothesis, candidate, context)
            verdicts.append((stage.name, verdict))
            if not verdict.keep:
                return SieveResult(
                    hypothesis=hypothesis,
                    survived=False,
                    killed_at=stage.name,
                    candidate=candidate,
                    verdicts=tuple(verdicts),
                )
        return SieveResult(
            hypothesis=hypothesis,
            survived=True,
            killed_at="",
            candidate=candidate,
            verdicts=tuple(verdicts),
        )
