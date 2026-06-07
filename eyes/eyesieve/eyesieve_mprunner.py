#!/usr/bin/env python3
"""eyesieve_mprunner.py — phase 8: multiprocess runner with checkpointing.

A parallel sibling to ``eyesieve_runner.Runner``. Same outputs, same
output-file schemas, but the sieve-pass workload is distributed across
``mp.Pool`` workers and progress is checkpointed periodically so long
runs can resume after interruption.

DESIGN
======
- Worker processes are initialized once via ``mp.Pool(initializer=...)``,
  which loads the corpus and constructs a default sieve cascade into
  module-level globals. This avoids re-loading the corpus per call.
- ``pool.imap(_evaluate_one, hypotheses, chunksize)`` preserves order
  so checkpoints correspond cleanly to "first N hypotheses processed".
  We trade some load-balance flexibility for deterministic resume.
- Checkpoint cadence is set by ``checkpoint_every``. Each checkpoint
  flushes the partial telemetry plus the running n_processed count to
  ``checkpoint.json``. Survivors are streamed to ``survivors.jsonl`` as
  they arrive so they survive crashes.
- ``--resume`` reads the checkpoint, skips ahead the corresponding number
  of hypotheses in the enumerator (cheap — iteration is ~20K hyps/sec),
  reads existing ``survivors.jsonl`` lines back into memory for scoring,
  and continues from where we left off.

WORKER STATE
============
Workers reference module-level ``_WORKER_CORPUS`` and ``_WORKER_CASCADE``
populated by ``_init_worker``. The cascade is hard-coded to ``default()``
for now — phase 10 may parameterize it.

ERROR CONTRACT
==============
All failures raise ``MPRunnerError`` with the standard prefix
``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

import eyesieve_corpus as ec
import eyesieve_enumerator as eenum
import eyesieve_sieve as esv

# Reuse the single-process runner's styling, presets, and serialization
import eyesieve_runner as erun
from eyesieve_runner import (
    bold, cyan, green, yellow, red, magenta, dim,
    TAG_RUN, TAG_OK, TAG_INFO, TAG_WARN, TAG_FAIL,
    _sieve_result_to_dict, _scoring_result_to_dict,
)

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

CHECKPOINT_SCHEMA_VERSION = 1


class MPRunnerError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: mprunner :: {msg}")


# ============================================================================
# Worker globals + functions
# ============================================================================

_WORKER_CORPUS: Optional[ec.Corpus] = None
_WORKER_CASCADE: Optional[esv.SieveCascade] = None


def _init_worker(data_path: str) -> None:
    """Initialize each pool worker. Loads corpus + default cascade once."""
    global _WORKER_CORPUS, _WORKER_CASCADE
    _WORKER_CORPUS = ec.load_corpus(data_path)
    _WORKER_CASCADE = esv.SieveCascade.default()


def _evaluate_one(hypo) -> esv.SieveResult:
    """Worker entry point — evaluates one hypothesis against the cascade."""
    return _WORKER_CASCADE.evaluate(hypo, _WORKER_CORPUS)


# ============================================================================
# Config + result types
# ============================================================================

@dataclass(frozen=True)
class MPRunConfig:
    """Configuration for one multiprocess runner invocation.

    Theory selection is via ``theory`` string ('theory1' | 'theory2' |
    'union'). The corresponding config object can be passed via
    ``theory1_config`` / ``theory2_config`` (None = use defaults).
    """
    data_path: Path
    output_dir: Path
    theory: str = "theory1"
    theory1_config: Optional[eenum.Theory1Config] = None
    theory2_config: Optional[eenum.Theory2Config] = None
    n_workers: int = 1
    chunksize: int = 100
    scoring_enabled: bool = True
    scoring_n_mappings: int = 100
    max_survivors_to_score: int = 0
    checkpoint_every: int = 5000
    progress_every: int = 1000
    quiet: bool = False
    resume: bool = False


@dataclass
class MPRunResult:
    config: MPRunConfig
    telemetry: esv.SieveTelemetry
    n_survivors: int
    n_scored: int
    sieve_elapsed_s: float
    scoring_elapsed_s: float
    output_files: dict
    resumed: bool = False
    resumed_from: int = 0


# ============================================================================
# Checkpoint persistence
# ============================================================================

def _config_fingerprint(config: MPRunConfig) -> str:
    """Stable hash of the parts of config that affect enumerator output.

    Used to refuse resume across mismatched configs. Includes data path,
    theory selection, and theory configs — but NOT scoring / workers /
    checkpoint cadence (those don't change which hypotheses are tested).
    """
    parts = {
        "data_path": str(config.data_path),
        "theory": config.theory,
        "theory1_config": (
            dataclass_dict(config.theory1_config)
            if config.theory1_config else None
        ),
        "theory2_config": (
            dataclass_dict(config.theory2_config)
            if config.theory2_config else None
        ),
    }
    payload = json.dumps(parts, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def dataclass_dict(obj) -> dict:
    """Convert a frozen dataclass instance to a plain dict (no recursion
    into nested dataclasses for our use — fields are scalars/tuples)."""
    from dataclasses import asdict
    return asdict(obj)


def _write_checkpoint(path: Path, n_processed: int, n_total: int,
                      telemetry: esv.SieveTelemetry,
                      config_fingerprint: str,
                      started_at: str) -> None:
    payload = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "started_at": started_at,
        "last_updated_at": datetime.now().isoformat(),
        "n_processed": n_processed,
        "n_total": n_total,
        "telemetry": telemetry.as_dict(),
        "config_fingerprint": config_fingerprint,
    }
    # Atomic write: temp file then rename
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)


def _read_checkpoint(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise MPRunnerError(f"checkpoint read failed: {e}")


# ============================================================================
# Runner
# ============================================================================

class MultiprocessRunner:
    """Multiprocess pipeline orchestrator (phase 8)."""

    def __init__(self, config: MPRunConfig) -> None:
        self.config = config
        if config.n_workers < 1:
            raise MPRunnerError(f"n_workers must be >= 1, got {config.n_workers}")
        if config.chunksize < 1:
            raise MPRunnerError(f"chunksize must be >= 1, got {config.chunksize}")
        if config.theory not in ("theory1", "theory2", "union"):
            raise MPRunnerError(
                f"theory must be theory1, theory2, or union; got {config.theory!r}"
            )
        self.corpus = ec.load_corpus(str(config.data_path))
        self.enumerator = self._build_enumerator()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path = self.config.output_dir / "checkpoint.json"
        self.survivors_path = self.config.output_dir / "survivors.jsonl"
        self.telemetry_path = self.config.output_dir / "telemetry.json"
        self.scored_path = self.config.output_dir / "scored.jsonl"
        self.log_path = self.config.output_dir / "run.log"
        self._fingerprint = _config_fingerprint(self.config)

    def _build_enumerator(self):
        if self.config.theory == "theory1":
            return eenum.Theory1Enumerator(
                self.corpus, self.config.theory1_config
            )
        if self.config.theory == "theory2":
            return eenum.Theory2Enumerator(
                self.corpus, self.config.theory2_config
            )
        return eenum.TheoryUnionEnumerator(
            self.corpus,
            self.config.theory1_config,
            self.config.theory2_config,
        )

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------

    def _log(self, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        full = f"{dim(ts)} {line}"
        if not self.config.quiet:
            print(full)
        clean = re.sub(r"\033\[[0-9;]*m", "", full)
        with open(self.log_path, "a") as f:
            f.write(clean + "\n")

    def _banner(self) -> None:
        cfg = self.config
        n_est = self.enumerator.estimated_count()
        print(bold(cyan("╔════════════════════════════════════════════════════════════════╗")))
        print(bold(cyan("║  EyeSieve // MPRUNNER // phase 8                               ║")))
        print(bold(cyan("╚════════════════════════════════════════════════════════════════╝")))
        print(f"  {bold('theory')}      {cfg.theory}")
        print(f"  {bold('hypotheses')}  {n_est:,} estimated")
        print(f"  {bold('workers')}     {cfg.n_workers} "
              f"(chunksize={cfg.chunksize})")
        print(f"  {bold('checkpoint')}  every {cfg.checkpoint_every:,} hypotheses")
        print(f"  {bold('scoring')}     {'enabled' if cfg.scoring_enabled else 'disabled'}")
        print(f"  {bold('output')}      {cfg.output_dir}")
        if cfg.resume:
            print(f"  {bold('resume')}      requested")
        print()

    # -----------------------------------------------------------------------
    # Resume handling
    # -----------------------------------------------------------------------

    def _maybe_resume(self) -> tuple[int, esv.SieveTelemetry, list, str]:
        """If --resume is set and a valid checkpoint exists, load state.
        Returns (skip_count, telemetry, survivors, started_at).
        Otherwise returns (0, fresh telemetry, [], now()).
        """
        now = datetime.now().isoformat()
        if not self.config.resume:
            return 0, esv.SieveTelemetry(), [], now

        ck = _read_checkpoint(self.checkpoint_path)
        if ck is None:
            self._log(f"{TAG_WARN} --resume requested but no checkpoint found; "
                      f"starting fresh")
            return 0, esv.SieveTelemetry(), [], now

        if ck.get("config_fingerprint") != self._fingerprint:
            raise MPRunnerError(
                "resume refused — checkpoint config_fingerprint does not "
                "match current config. Either match the original config or "
                "remove checkpoint.json to start over."
            )
        if ck.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            raise MPRunnerError(
                f"resume refused — checkpoint schema_version "
                f"{ck.get('schema_version')!r} != current "
                f"{CHECKPOINT_SCHEMA_VERSION}"
            )

        # Reconstruct telemetry
        t = esv.SieveTelemetry()
        td = ck["telemetry"]
        t.total_evaluated = td.get("total_evaluated", 0)
        t.survivors = td.get("survivors", 0)
        t.execute_failures = td.get("execute_failures", 0)
        t.killed_by_stage = dict(td.get("killed_by_stage", {}))

        # Read existing survivors back into memory (for scoring pass).
        # If the file has more lines than the checkpoint says (can happen
        # if the process crashed between writing a survivor and writing
        # the next checkpoint), truncate the excess so we don't double-
        # count when resume re-processes those hypotheses.
        survivors = []
        if self.survivors_path.exists():
            with open(self.survivors_path) as f:
                for line in f:
                    if line.strip():
                        survivors.append(json.loads(line))
        if len(survivors) > t.survivors:
            self._log(
                f"{TAG_WARN} survivors.jsonl has {len(survivors)} entries "
                f"but checkpoint reports {t.survivors}; truncating to "
                f"checkpoint count to avoid duplicates"
            )
            survivors = survivors[: t.survivors]
            with open(self.survivors_path, "w") as f:
                for s in survivors:
                    f.write(json.dumps(s) + "\n")

        n_processed = ck["n_processed"]
        self._log(f"{TAG_INFO} resumed from checkpoint: "
                  f"{n_processed:,} hypotheses already processed, "
                  f"{len(survivors)} survivors")
        return n_processed, t, survivors, ck.get("started_at", now)

    # -----------------------------------------------------------------------
    # Sieve pass (parallel)
    # -----------------------------------------------------------------------

    def _sieve_pass_parallel(
        self,
        n_skip: int,
        telemetry: esv.SieveTelemetry,
        survivors_in_memory: list,
        started_at: str,
    ) -> tuple[esv.SieveTelemetry, list, float]:
        """Run cascade in parallel. Appends new survivors to file and to
        the in-memory list. Returns updated telemetry, survivors list, and
        elapsed seconds."""
        n_total = self.enumerator.estimated_count()
        n_workers = self.config.n_workers
        chunksize = self.config.chunksize

        self._log(f"{TAG_RUN} sieve pass starting "
                  f"(n_workers={n_workers}, chunksize={chunksize}, "
                  f"n_total={n_total:,}, n_skip={n_skip:,})")

        # Skip-ahead iterator: drop the first n_skip hypotheses
        hypo_iter = self.enumerator.__iter__()
        for _ in range(n_skip):
            next(hypo_iter, None)

        # Open survivors file in append mode for resumability
        survivors_file = open(self.survivors_path, "a", buffering=1)

        t0 = time.perf_counter()
        n_processed = n_skip

        try:
            if n_workers == 1:
                # Single-process path: no pool overhead
                _init_worker(str(self.config.data_path))
                for hypo in hypo_iter:
                    result = _evaluate_one(hypo)
                    n_processed += 1
                    telemetry.record(result)
                    if result.survived:
                        d = _sieve_result_to_dict(result)
                        survivors_file.write(json.dumps(d) + "\n")
                        survivors_in_memory.append(d)
                    self._maybe_log_progress(n_processed, n_total, telemetry)
                    if n_processed % self.config.checkpoint_every == 0:
                        _write_checkpoint(
                            self.checkpoint_path, n_processed, n_total,
                            telemetry, self._fingerprint, started_at,
                        )
            else:
                with mp.Pool(
                    processes=n_workers,
                    initializer=_init_worker,
                    initargs=(str(self.config.data_path),),
                ) as pool:
                    for result in pool.imap(
                        _evaluate_one, hypo_iter, chunksize=chunksize
                    ):
                        n_processed += 1
                        telemetry.record(result)
                        if result.survived:
                            d = _sieve_result_to_dict(result)
                            survivors_file.write(json.dumps(d) + "\n")
                            survivors_in_memory.append(d)
                        self._maybe_log_progress(n_processed, n_total, telemetry)
                        if n_processed % self.config.checkpoint_every == 0:
                            _write_checkpoint(
                                self.checkpoint_path, n_processed, n_total,
                                telemetry, self._fingerprint, started_at,
                            )
        finally:
            survivors_file.close()

        elapsed = time.perf_counter() - t0
        self._log(
            f"{TAG_OK} sieve pass complete in {elapsed:.2f}s "
            f"({(n_processed - n_skip) / max(elapsed, 0.001):.0f} hyps/sec)"
        )
        # Final checkpoint
        _write_checkpoint(
            self.checkpoint_path, n_processed, n_total,
            telemetry, self._fingerprint, started_at,
        )
        return telemetry, survivors_in_memory, elapsed

    def _maybe_log_progress(self, n_processed: int, n_total: int,
                             telemetry: esv.SieveTelemetry) -> None:
        if n_processed % self.config.progress_every != 0:
            return
        self._log(
            f"  {dim(f'{n_processed:>9,}/{n_total:,}')}  "
            f"survivors={telemetry.survivors}  "
            f"exec_fail={telemetry.execute_failures}  "
            f"top_kill={self._top_kill_stage(telemetry)}"
        )

    @staticmethod
    def _top_kill_stage(tel: esv.SieveTelemetry) -> str:
        if not tel.killed_by_stage:
            return "—"
        stage, n = max(tel.killed_by_stage.items(), key=lambda x: x[1])
        return f"{stage}={n:,}"

    # -----------------------------------------------------------------------
    # Scoring pass
    # -----------------------------------------------------------------------

    def _scoring_pass(self, survivors: list) -> tuple[list, float, int]:
        """Score survivors in the main process. Survivors are dicts here
        (already serialized), so we extract the candidate list."""
        try:
            import eyesieve_scoring as escore
        except ImportError as e:
            self._log(f"{TAG_WARN} scoring module unavailable: {e}")
            return [], 0.0, 0

        cap = self.config.max_survivors_to_score
        to_score = survivors if cap == 0 else survivors[:cap]
        self._log(f"{TAG_RUN} scoring pass starting ({len(to_score)} candidates)")

        t0 = time.perf_counter()
        try:
            scorer = escore.Scorer(
                escore.ScoringConfig(n_mappings=self.config.scoring_n_mappings)
            )
        except escore.ScoringError as e:
            self._log(f"{TAG_FAIL} scorer init failed: {e}")
            return [], 0.0, 0

        scored = []
        for i, surv_dict in enumerate(to_score):
            try:
                sr = scorer.score(
                    tuple(surv_dict["candidate"]),
                    self.corpus.deck_size,
                )
            except escore.ScoringError as e:
                self._log(f"{TAG_WARN} scoring failed for survivor {i}: {e}")
                continue
            scored.append((surv_dict, sr))
            if (i + 1) % 50 == 0 and scored:
                best = max(s[1].best_score for s in scored)
                self._log(f"  {dim(f'{i+1}/{len(to_score)}')}  best={best:.2f}")

        elapsed = time.perf_counter() - t0
        self._log(
            f"{TAG_OK} scoring pass complete in {elapsed:.2f}s "
            f"({len(scored)/max(elapsed, 0.001):.1f} cands/sec)"
        )
        return scored, elapsed, len(scored)

    def _write_scored(self, scored) -> Path:
        scored_sorted = sorted(
            scored, key=lambda pair: pair[1].best_score, reverse=True
        )
        with open(self.scored_path, "w") as f:
            for surv_dict, scoring_result in scored_sorted:
                payload = dict(surv_dict)
                payload["scoring"] = _scoring_result_to_dict(scoring_result)
                f.write(json.dumps(payload) + "\n")
        return self.scored_path

    # -----------------------------------------------------------------------
    # Telemetry output
    # -----------------------------------------------------------------------

    def _write_telemetry(self, tel: esv.SieveTelemetry,
                          sieve_elapsed: float, scoring_elapsed: float,
                          n_scored: int, resumed: bool, resumed_from: int) -> None:
        cfg = self.config
        payload = {
            "config": {
                "data_path": str(cfg.data_path),
                "theory": cfg.theory,
                "theory1_config": (
                    dataclass_dict(cfg.theory1_config)
                    if cfg.theory1_config else None
                ),
                "theory2_config": (
                    dataclass_dict(cfg.theory2_config)
                    if cfg.theory2_config else None
                ),
                "n_workers": cfg.n_workers,
                "chunksize": cfg.chunksize,
                "scoring_enabled": cfg.scoring_enabled,
                "scoring_n_mappings": cfg.scoring_n_mappings,
            },
            "totals": tel.as_dict(),
            "timing_seconds": {
                "sieve": sieve_elapsed,
                "scoring": scoring_elapsed,
                "total": sieve_elapsed + scoring_elapsed,
            },
            "scoring": {"candidates_scored": n_scored},
            "resume": {"resumed": resumed, "resumed_from": resumed_from},
            "config_fingerprint": self._fingerprint,
        }
        self.telemetry_path.write_text(json.dumps(payload, indent=2))

    def _print_summary(self, tel, sieve_elapsed, scoring_elapsed, n_scored):
        print()
        print(bold("─" * 66))
        print(f"  {bold('SUMMARY')}")
        print(f"  total hypotheses:      {tel.total_evaluated:>9,}")
        print(f"  survivors:             {tel.survivors:>9,}")
        print(f"  execute failures:      {tel.execute_failures:>9,}")
        for stage, n in sorted(tel.killed_by_stage.items(), key=lambda x: -x[1]):
            print(f"  killed at {stage:>20}: {n:>9,}")
        print(f"  sieve time:            {sieve_elapsed:>9.2f}s "
              f"({self.config.n_workers} workers)")
        if scoring_elapsed > 0:
            print(f"  scoring time:          {scoring_elapsed:>9.2f}s "
                  f"({n_scored} scored)")
        print(bold("─" * 66))

    # -----------------------------------------------------------------------
    # Top-level run
    # -----------------------------------------------------------------------

    def run(self) -> MPRunResult:
        if not self.config.quiet:
            self._banner()

        # Open log file fresh unless resuming
        if not self.config.resume and self.log_path.exists():
            self.log_path.unlink()
        # Same for survivors file
        if not self.config.resume and self.survivors_path.exists():
            self.survivors_path.unlink()

        n_skip, telemetry, survivors, started_at = self._maybe_resume()
        resumed = n_skip > 0
        resumed_from = n_skip

        telemetry, survivors, sieve_elapsed = self._sieve_pass_parallel(
            n_skip=n_skip,
            telemetry=telemetry,
            survivors_in_memory=survivors,
            started_at=started_at,
        )

        scoring_elapsed = 0.0
        n_scored = 0
        output_files = {
            "survivors": self.survivors_path,
            "checkpoint": self.checkpoint_path,
        }

        if self.config.scoring_enabled and survivors:
            scored, scoring_elapsed, n_scored = self._scoring_pass(survivors)
            if scored:
                self._write_scored(scored)
                output_files["scored"] = self.scored_path
                self._log(
                    f"{TAG_OK} wrote {len(scored)} scored → "
                    f"{self.scored_path.name}"
                )

        self._write_telemetry(
            telemetry, sieve_elapsed, scoring_elapsed,
            n_scored, resumed, resumed_from,
        )
        output_files["telemetry"] = self.telemetry_path
        self._log(f"{TAG_OK} wrote telemetry → {self.telemetry_path.name}")

        if not self.config.quiet:
            self._print_summary(telemetry, sieve_elapsed, scoring_elapsed,
                                 n_scored)

        return MPRunResult(
            config=self.config,
            telemetry=telemetry,
            n_survivors=telemetry.survivors,
            n_scored=n_scored,
            sieve_elapsed_s=sieve_elapsed,
            scoring_elapsed_s=scoring_elapsed,
            output_files=output_files,
            resumed=resumed,
            resumed_from=resumed_from,
        )


# ============================================================================
# CLI
# ============================================================================

def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="EyeSieve multiprocess runner — phase 8")
    p.add_argument("--data", default="noita_eye_data.json")
    p.add_argument("--output-dir", default=None)
    p.add_argument("--theory", choices=("theory1", "theory2", "union"),
                   default="theory1")
    p.add_argument("--config", default="strict",
                   choices=list(erun.CONFIG_PRESETS.keys()),
                   help="Theory 1 enumerator preset (used when theory in theory1/union)")
    p.add_argument("--workers", type=int, default=1,
                   help="number of worker processes (default: 1 = single-process)")
    p.add_argument("--chunksize", type=int, default=100)
    p.add_argument("--checkpoint-every", type=int, default=5000)
    p.add_argument("--progress-every", type=int, default=1000)
    p.add_argument("--score", dest="score", action="store_true", default=True)
    p.add_argument("--no-score", dest="score", action="store_false")
    p.add_argument("--n-mappings", type=int, default=100)
    p.add_argument("--max-survivors", type=int, default=0)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.output_dir is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.output_dir = f"./runs/{ts}-{args.theory}-mp"

    t1_cfg = erun.CONFIG_PRESETS[args.config] if args.theory in ("theory1", "union") else None
    t2_cfg = eenum.Theory2Config() if args.theory in ("theory2", "union") else None

    cfg = MPRunConfig(
        data_path=Path(args.data),
        output_dir=Path(args.output_dir),
        theory=args.theory,
        theory1_config=t1_cfg,
        theory2_config=t2_cfg,
        n_workers=args.workers,
        chunksize=args.chunksize,
        scoring_enabled=args.score,
        scoring_n_mappings=args.n_mappings,
        max_survivors_to_score=args.max_survivors,
        checkpoint_every=args.checkpoint_every,
        progress_every=args.progress_every,
        resume=args.resume,
        quiet=args.quiet,
    )

    try:
        MultiprocessRunner(cfg).run()
    except MPRunnerError as e:
        print(f"{TAG_FAIL} {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
