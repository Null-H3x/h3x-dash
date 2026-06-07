#!/usr/bin/env python3
"""eyesieve_runner.py — phase 6: single-process pipeline orchestrator.

Runs the EyeSieve pipeline end-to-end:

  1. Construct corpus, enumerator, sieve cascade
  2. Stream every hypothesis through the cascade, recording telemetry
  3. Collect survivors (results that pass every cheap-sieve stage)
  4. Optionally score survivors via the phase-7 Scorer
  5. Save telemetry, survivors, and (if scored) ranked results

The runner is single-process and synchronous — phase 8 will add the
multiprocessing layer. The architecture is designed so phase 8 can
swap out the inner loop without touching the outer orchestration.

OUTPUTS
=======
``--output-dir`` receives:

  telemetry.json     — aggregate cascade stats (total, survivors, kills/stage)
  survivors.jsonl    — one survivor per line; full hypothesis name, verdict
                       trail, and candidate sequence
  scored.jsonl       — same as survivors.jsonl + per-language scoring,
                       sorted by best-language zipf_score descending
                       (only written if scoring is enabled)
  run.log            — structured progress log

CLI
===
  --config         strict | mono | no-xor | cross-pair | any-key | liberal
  --output-dir     directory for output artifacts (default: ./runs/<ts>)
  --score / --no-score   enable/disable phase-7 scoring (default: on)
  --n-mappings     Hungarian perturbation count (default: 100)
  --max-survivors  cap scored survivors at N (default: unlimited)
  --quiet          suppress per-batch progress output

ERROR CONTRACT
==============
All runner failures raise ``RunnerError`` with the standard prefix
``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import eyesieve_corpus as ec
import eyesieve_enumerator as eenum
import eyesieve_sieve as esv
from eyesieve_hypothesis import Hypothesis

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"


class RunnerError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: runner :: {msg}")


# ===========================================================================
# Output styling (SPECTR cyberpunk palette)
# ===========================================================================

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def bold(s):    return _c("1", s)
def cyan(s):    return _c("36", s)
def green(s):   return _c("32", s)
def yellow(s):  return _c("33", s)
def red(s):     return _c("31", s)
def magenta(s): return _c("35", s)
def dim(s):     return _c("2", s)


TAG_RUN  = f"[ {magenta('RUN ')} ]"
TAG_OK   = f"[ {green(' OK ')}  ]"
TAG_INFO = f"[ {cyan('INFO')} ]"
TAG_WARN = f"[ {yellow('WARN')} ]"
TAG_FAIL = f"[ {red('FAIL')} ]"


# ===========================================================================
# Config presets
# ===========================================================================

CONFIG_PRESETS: dict[str, eenum.Theory1Config] = {
    "strict":     eenum.Theory1Config(),
    "mono":       eenum.Theory1Config(bidirectional=False),
    "no-xor":     eenum.Theory1Config(include_xor_ciphers=False),
    "cross-pair": eenum.Theory1Config(strict_pairing=False),
    "any-key":    eenum.Theory1Config(fixed_key_E5=False),
    "liberal":    eenum.Theory1Config(strict_pairing=False, fixed_key_E5=False),
}


# ===========================================================================
# Runner config and result types
# ===========================================================================

@dataclass(frozen=True)
class RunConfig:
    """Configuration for one runner invocation."""
    data_path: Path
    output_dir: Path
    enumerator_config: eenum.Theory1Config = field(default_factory=eenum.Theory1Config)
    scoring_enabled: bool = True
    scoring_n_mappings: int = 100
    progress_every: int = 500
    max_survivors_to_score: int = 0   # 0 = no cap
    quiet: bool = False


@dataclass
class RunResult:
    """Aggregate outcome of one runner invocation."""
    config: RunConfig
    telemetry: esv.SieveTelemetry
    n_survivors: int
    n_scored: int
    sieve_elapsed_s: float
    scoring_elapsed_s: float
    output_files: dict[str, Path]


# ===========================================================================
# Serialization helpers
# ===========================================================================

def _verdict_to_dict(v: esv.SieveVerdict) -> dict:
    return {
        "keep": v.keep,
        "reason": v.reason,
        "metrics": dict(v.metrics),
    }


def _sieve_result_to_dict(r: esv.SieveResult) -> dict:
    return {
        "hypothesis_name": r.hypothesis.name,
        "survived": r.survived,
        "killed_at": r.killed_at,
        "candidate": list(r.candidate) if r.candidate is not None else None,
        "candidate_length": len(r.candidate) if r.candidate is not None else 0,
        "verdicts": [
            {"stage": stage_name, **_verdict_to_dict(v)}
            for stage_name, v in r.verdicts
        ],
        "error": r.error,
    }


def _scoring_result_to_dict(sr) -> dict:
    """Serialize a ScoringResult. Late-bound to avoid import dep when
    scoring is disabled."""
    return {
        "best_language": sr.best_language,
        "best_score": sr.best_score,
        "total_hits": sr.total_hits,
        "per_language": [
            {
                "language": ls.language,
                "hits": ls.hits,
                "zipf_score": ls.zipf_score,
                "decrypted_text": ls.decrypted_text,
                "best_mapping": dict(ls.best_mapping_pairs),
            }
            for ls in sr.per_language
        ],
    }


# ===========================================================================
# Runner
# ===========================================================================

class Runner:
    """Single-process pipeline orchestrator."""

    def __init__(self, config: RunConfig) -> None:
        self.config = config
        self.corpus = ec.load_corpus(str(config.data_path))
        self.enumerator = eenum.Theory1Enumerator(
            self.corpus, config.enumerator_config
        )
        self.cascade = esv.SieveCascade.default()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------

    def _log(self, line: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        line_with_ts = f"{dim(ts)} {line}"
        if not self.config.quiet:
            print(line_with_ts)
        with open(self.config.output_dir / "run.log", "a") as f:
            # Strip ANSI for the log file
            import re
            clean = re.sub(r"\033\[[0-9;]*m", "", line_with_ts)
            f.write(clean + "\n")

    def _banner(self) -> None:
        print(bold(cyan("╔════════════════════════════════════════════════════════════════╗")))
        print(bold(cyan("║  EyeSieve // RUNNER // phase 6                                 ║")))
        print(bold(cyan("╚════════════════════════════════════════════════════════════════╝")))
        cfg = self.config
        ec_cfg = cfg.enumerator_config
        n_est = self.enumerator.estimated_count()
        print(f"  {bold('config')}      strict_pairing={ec_cfg.strict_pairing}, "
              f"bidirectional={ec_cfg.bidirectional}, "
              f"fixed_key_E5={ec_cfg.fixed_key_E5}, "
              f"include_xor={ec_cfg.include_xor_ciphers}")
        print(f"  {bold('hypotheses')}  {n_est:,} estimated")
        print(f"  {bold('cascade')}     {[s.name for s in self.cascade.stages]}")
        print(f"  {bold('scoring')}     {'enabled' if cfg.scoring_enabled else 'disabled'}"
              f"{' (n_mappings=' + str(cfg.scoring_n_mappings) + ')' if cfg.scoring_enabled else ''}")
        print(f"  {bold('output')}      {cfg.output_dir}")
        print()

    # -----------------------------------------------------------------------
    # Sieve pass
    # -----------------------------------------------------------------------

    def _run_sieve_pass(self) -> tuple[esv.SieveTelemetry, list[esv.SieveResult], float]:
        """Run every hypothesis through the cheap cascade. Returns
        (telemetry, survivors, elapsed_seconds)."""
        tel = esv.SieveTelemetry()
        survivors: list[esv.SieveResult] = []
        n_total = self.enumerator.estimated_count()

        self._log(f"{TAG_RUN} sieve pass starting ({n_total:,} hypotheses)")
        t0 = time.perf_counter()

        for i, hypo in enumerate(self.enumerator):
            result = self.cascade.evaluate(hypo, self.corpus)
            tel.record(result)
            if result.survived:
                survivors.append(result)
            if (i + 1) % self.config.progress_every == 0:
                self._log(
                    f"  {dim(f'{i+1:>7,}/{n_total:,}')}  "
                    f"survivors={tel.survivors}  "
                    f"exec_fail={tel.execute_failures}  "
                    f"top_kill={self._top_kill_stage(tel)}"
                )

        elapsed = time.perf_counter() - t0
        self._log(
            f"{TAG_OK} sieve pass complete in {elapsed:.2f}s "
            f"({n_total/elapsed:.0f} hyps/sec)"
        )
        return tel, survivors, elapsed

    @staticmethod
    def _top_kill_stage(tel: esv.SieveTelemetry) -> str:
        if not tel.killed_by_stage:
            return "—"
        stage, n = max(tel.killed_by_stage.items(), key=lambda x: x[1])
        return f"{stage}={n:,}"

    # -----------------------------------------------------------------------
    # Output writers
    # -----------------------------------------------------------------------

    def _write_telemetry(self, tel: esv.SieveTelemetry,
                          sieve_elapsed: float, scoring_elapsed: float,
                          n_scored: int) -> Path:
        out = self.config.output_dir / "telemetry.json"
        payload = {
            "config": {
                "data_path": str(self.config.data_path),
                "enumerator": {
                    "strict_pairing": self.config.enumerator_config.strict_pairing,
                    "bidirectional": self.config.enumerator_config.bidirectional,
                    "fixed_key_E5": self.config.enumerator_config.fixed_key_E5,
                    "include_xor_ciphers": self.config.enumerator_config.include_xor_ciphers,
                },
                "scoring_enabled": self.config.scoring_enabled,
                "scoring_n_mappings": self.config.scoring_n_mappings,
            },
            "totals": tel.as_dict(),
            "timing_seconds": {
                "sieve": sieve_elapsed,
                "scoring": scoring_elapsed,
                "total": sieve_elapsed + scoring_elapsed,
            },
            "scoring": {
                "candidates_scored": n_scored,
            },
        }
        out.write_text(json.dumps(payload, indent=2))
        return out

    def _write_survivors(self, survivors: list[esv.SieveResult]) -> Path:
        out = self.config.output_dir / "survivors.jsonl"
        with open(out, "w") as f:
            for r in survivors:
                f.write(json.dumps(_sieve_result_to_dict(r)) + "\n")
        return out

    def _write_scored(self, scored: list[tuple[esv.SieveResult, object]]) -> Path:
        """Each tuple is (sieve_result, scoring_result). Sorted by best_score."""
        out = self.config.output_dir / "scored.jsonl"
        # Sort by best_score descending
        scored_sorted = sorted(
            scored, key=lambda pair: pair[1].best_score, reverse=True
        )
        with open(out, "w") as f:
            for sieve_result, scoring_result in scored_sorted:
                payload = _sieve_result_to_dict(sieve_result)
                payload["scoring"] = _scoring_result_to_dict(scoring_result)
                f.write(json.dumps(payload) + "\n")
        return out

    # -----------------------------------------------------------------------
    # Scoring pass
    # -----------------------------------------------------------------------

    def _run_scoring_pass(
            self, survivors: list[esv.SieveResult]
        ) -> tuple[list[tuple], float, int]:
        """Score survivors via the phase-7 Scorer. Returns
        (scored_pairs, elapsed_seconds, n_scored)."""
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
                escore.ScoringConfig(
                    n_mappings=self.config.scoring_n_mappings,
                )
            )
        except escore.ScoringError as e:
            self._log(f"{TAG_FAIL} scorer init failed: {e}")
            return [], 0.0, 0

        scored = []
        for i, r in enumerate(to_score):
            try:
                sr = scorer.score(r.candidate, self.corpus.deck_size)
            except escore.ScoringError as e:
                self._log(f"{TAG_WARN} scoring failed for survivor {i}: {e}")
                continue
            scored.append((r, sr))
            if (i + 1) % 50 == 0:
                self._log(
                    f"  {dim(f'{i+1}/{len(to_score)}')}  "
                    f"best={max(s[1].best_score for s in scored):.2f}"
                )

        elapsed = time.perf_counter() - t0
        self._log(
            f"{TAG_OK} scoring pass complete in {elapsed:.2f}s "
            f"({len(scored)/max(elapsed, 0.001):.1f} cands/sec)"
        )
        return scored, elapsed, len(scored)

    # -----------------------------------------------------------------------
    # Top-level run
    # -----------------------------------------------------------------------

    def run(self) -> RunResult:
        if not self.config.quiet:
            self._banner()

        tel, survivors, sieve_elapsed = self._run_sieve_pass()
        survivors_path = self._write_survivors(survivors)
        self._log(f"{TAG_OK} wrote {len(survivors)} survivors → {survivors_path.name}")

        scoring_elapsed = 0.0
        n_scored = 0
        output_files = {"survivors": survivors_path}

        if self.config.scoring_enabled and survivors:
            scored, scoring_elapsed, n_scored = self._run_scoring_pass(survivors)
            if scored:
                scored_path = self._write_scored(scored)
                output_files["scored"] = scored_path
                self._log(f"{TAG_OK} wrote {len(scored)} scored → {scored_path.name}")
                if not self.config.quiet:
                    self._print_top_candidates(scored, top_n=10)

        tel_path = self._write_telemetry(tel, sieve_elapsed, scoring_elapsed, n_scored)
        output_files["telemetry"] = tel_path
        self._log(f"{TAG_OK} wrote telemetry → {tel_path.name}")

        if not self.config.quiet:
            self._print_summary(tel, sieve_elapsed, scoring_elapsed, n_scored)

        return RunResult(
            config=self.config,
            telemetry=tel,
            n_survivors=len(survivors),
            n_scored=n_scored,
            sieve_elapsed_s=sieve_elapsed,
            scoring_elapsed_s=scoring_elapsed,
            output_files=output_files,
        )

    def _print_top_candidates(self, scored, top_n: int = 10) -> None:
        """Print the top-N scored candidates."""
        ordered = sorted(scored, key=lambda p: p[1].best_score, reverse=True)
        print()
        print(bold(cyan(f"  Top {min(top_n, len(ordered))} candidates by best zipf_score:")))
        for i, (sieve_r, score_r) in enumerate(ordered[:top_n]):
            lang = score_r.best_language
            score = score_r.best_score
            hits = score_r.total_hits
            # Pick text from best language
            best_lang_score = next(
                (ls for ls in score_r.per_language if ls.language == lang), None
            )
            snippet = (best_lang_score.decrypted_text[:55]
                       if best_lang_score else "")
            print(f"  {bold(f'#{i+1:>2}')}  "
                  f"{cyan(lang):>7}={score:>6.2f}  hits={hits:>3}  "
                  f"{dim(snippet)!s:<60}  "
                  f"{dim(sieve_r.hypothesis.name)}")
        print()

    def _print_summary(self, tel, sieve_elapsed, scoring_elapsed, n_scored) -> None:
        print()
        print(bold("─" * 66))
        print(f"  {bold('SUMMARY')}")
        print(f"  total hypotheses:      {tel.total_evaluated:>9,}")
        print(f"  survivors:             {tel.survivors:>9,}")
        print(f"  execute failures:      {tel.execute_failures:>9,}")
        for stage, n in sorted(tel.killed_by_stage.items(), key=lambda x: -x[1]):
            print(f"  killed at {stage:>20}: {n:>9,}")
        print(f"  sieve time:            {sieve_elapsed:>9.2f}s")
        if scoring_elapsed > 0:
            print(f"  scoring time:          {scoring_elapsed:>9.2f}s "
                  f"({n_scored} scored)")
        print(bold("─" * 66))


# ===========================================================================
# CLI
# ===========================================================================

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="EyeSieve runner — phase 6")
    p.add_argument("--data", default="noita_eye_data.json",
                   help="path to corpus JSON (default: noita_eye_data.json)")
    p.add_argument("--config", default="strict",
                   choices=list(CONFIG_PRESETS.keys()),
                   help="enumerator config preset (default: strict)")
    p.add_argument("--output-dir", default=None,
                   help="output directory (default: ./runs/<timestamp>)")
    p.add_argument("--score", dest="score", action="store_true",
                   default=True, help="enable phase-7 scoring (default)")
    p.add_argument("--no-score", dest="score", action="store_false",
                   help="disable phase-7 scoring")
    p.add_argument("--n-mappings", type=int, default=100,
                   help="Hungarian perturbation count (default: 100)")
    p.add_argument("--max-survivors", type=int, default=0,
                   help="cap scored survivors at N (0 = unlimited)")
    p.add_argument("--progress-every", type=int, default=500,
                   help="log every N hypotheses (default: 500)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-batch progress output")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    if args.output_dir is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.output_dir = f"./runs/{ts}-{args.config}"

    config = RunConfig(
        data_path=Path(args.data),
        output_dir=Path(args.output_dir),
        enumerator_config=CONFIG_PRESETS[args.config],
        scoring_enabled=args.score,
        scoring_n_mappings=args.n_mappings,
        max_survivors_to_score=args.max_survivors,
        progress_every=args.progress_every,
        quiet=args.quiet,
    )

    try:
        runner = Runner(config)
        runner.run()
    except RunnerError as e:
        print(f"{TAG_FAIL} {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"{TAG_FAIL} {ERROR_PREFIX} :: runner :: unexpected: "
              f"{type(e).__name__}: {e}", file=sys.stderr)
        raise

    return 0


if __name__ == "__main__":
    sys.exit(main())
