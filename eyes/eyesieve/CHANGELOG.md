# EyeSieve — CHANGELOG

All notable changes documented here. Versions follow `MAJOR.MINOR.PATCH`
loosely: MINOR bumps mark completed phases; PATCH bumps cover bugfixes
and selftest additions within a phase.

---

## v1.0.1 — 2026-05-14

### Portability fixes: external-environment regression patch

Six selftests failed on a fresh checkout in Ben's actual environment
(64-CPU machine, Python 3.12.3, eyestat not co-located with the
eyesieve checkout). All six had a single root cause: my dev path
`/home/claude/eyestat_ref/eyestat` was hardcoded as the scoring
module's eyestat location. On any other machine, the import failed
and every scoring-dependent test cascaded.

A second portability issue surfaced before we could even see the
failures: `./eyesieve_selftest.py` returned "cannot execute: required
file not found" because the shebangs across the package pointed at
`/home/h3x/.venvs/eyesieve/bin/python3` — a venv path I'd carried
forward from an early version without genericizing.

Neither was caught in my dev environment because (a) my container
*was* `/home/claude/...` and *did* have eyestat at that exact path,
and (b) my container had only 1 CPU available, so multi-worker
scenarios weren't really exercising parallel paths. v1.0.1 fixes
both classes of issue and adds infrastructure so this kind of
regression can't recur silently.

**Fixed — eyestat discovery (`eyesieve_scoring.py`)**

The hardcoded `EYESTAT_DIR_DEFAULT = Path('/home/claude/eyestat_ref/eyestat')`
is replaced by an ordered candidate search:

1. `$EYESTAT_DIR` environment variable (takes priority if set)
2. `~/Desktop/Noita/eyestat` (conventional Noita-project layout)
3. `~/Noita/eyestat`
4. `~/eyestat`
5. `/root/Desktop/Noita/eyestat` (legacy root-user path)
6. `/home/claude/eyestat_ref/eyestat` (dev path, kept for back-compat)
7. `<eyesieve_parent>/eyestat` (sibling of the eyesieve checkout)
8. `<eyesieve_dir>/eyestat` (vendored inside the eyesieve checkout)

The first candidate containing an importable `eyestat_scoring.py`
wins. A new public function `eyesieve_scoring.discover_eyestat_dir()`
exposes the discovery result and is reused by both `is_eyestat_available`
and the preflight check (which previously duplicated the search logic).

When no eyestat is found, `EYESTAT_DIR_DEFAULT` falls back to the first
candidate so `ScoringConfig()` still constructs without arguments. The
actual import attempt is deferred to `Scorer.__init__`, which raises
a prefixed `ScoringError` with a clear message if eyestat can't be
reached. The rest of EyeSieve — the runner, sieve, enumerator, HTML
reports — runs fine without scoring.

**Fixed — skip-on-unavailable selftest infrastructure**

A new `SkipTest` exception class lets test bodies raise out cleanly
when an optional dependency is missing. The `_run` harness catches
it, records the test as `skip` (separate from `ok` / `fail`), and
prints `[ SKIP ]` with the reason. Summary now reports `skip`
counts; skipped tests do *not* count as failures.

The six previously-failing scoring tests are now gated on a
`_require_eyestat()` helper that raises `SkipTest` when
`is_eyestat_available()` is False:

- `t_score_eyestat_available` — was asserting `is True`, now skips
  when eyestat is absent and asserts the function returns a bool
  regardless
- `t_score_scorer_init`
- `t_score_real_candidate`
- `t_score_none_mapping_safe`
- `t_score_empty_candidate`
- `t_runner_run_with_score`

Also tightened `t_score_config_defaults`: was asserting
`str(cfg.eyestat_dir).endswith('eyestat')`, which fails when
`$EYESTAT_DIR` is set to something like `/nonexistent`. Now asserts
only that `eyestat_dir` is a `Path` instance — config invariant,
not deployment invariant.

**Fixed — shebangs**

All 12 entry-point files (`eyesieve_ciphers`, `eyesieve_cli`,
`eyesieve_corpus`, `eyesieve_html_report`, `eyesieve_mprunner`,
`eyesieve_permutations`, `eyesieve_preflight`, `eyesieve_reader`,
`eyesieve_run_report`, `eyesieve_runner`, `eyesieve_selftest`,
`eyesieve_sources`) had `#!/home/h3x/.venvs/eyesieve/bin/python3`
replaced with `#!/usr/bin/env python3`. Direct invocation
(`./eyesieve_selftest.py`) now works on any system with a `python3`
on `$PATH`.

**Fixed — preflight eyestat hint**

Previously hard-coded `Path.home() / "Desktop" / "Noita" / "eyestat"`
as both the search target and the user-facing hint. When run with
`sudo`, `HOME=/root` made the hint nonsensical for the actual user
(`/root/Desktop/Noita/eyestat` for a user whose project lives at
`/home/h3x/Desktop/Noita/eyesieve-v1.0.0`). Preflight now delegates
discovery to `eyesieve_scoring.discover_eyestat_dir()` for consistency,
and the user-facing hint is simplified: "set $EYESTAT_DIR or pass
--eyestat-dir; scoring tests skip cleanly when absent".

**Verified — both environments green**

- With eyestat available: 218 ok / 0 skip / 0 fail
- Without eyestat:        212 ok / 6 skip / 0 fail (selftest exits 0)

The skip count makes the deployment fact visible without polluting
the test signal.

---

## v1.0.0 — 2026-05-14

### Phase 10 + 11: HTML run reports, pip-installable packaging, and a 10-pass ecosystem audit

Final milestone. Phase 10 produces self-contained HTML reports from
runner output (telemetry + survivors + scoring), reusing the SPECTR
cyberpunk palette from the existing corpus-report module. Phase 11
makes the project pip-installable while preserving the flat-file
layout — every legacy `python3 eyesieve_<name>.py` invocation still
works, and pip-installed users get console scripts (`eyesieve-run`,
`eyesieve-mp`, etc.) plus a unified `eyesieve <subcommand>` dispatcher.

**Added — phase 10 (`eyesieve_run_report.py`)**

- `render_html(run_dir, top_n=25)` — produces a single self-contained
  HTML file from a runner output directory; reuses
  `eyesieve_html_report.CSS` for the shared color palette and extends
  it with `RUN_REPORT_CSS` for the report-specific layout
- Six sections: header (run identity + key counters), config (every
  enumerator/runner knob), pipeline funnel (waterfall bars stage-by-
  stage), timing (sieve and scoring elapsed + derived rates),
  leaderboard (top N scored candidates with per-language pills), and
  survivor breakdown (per-cipher / per-merge-op / per-derivation-family
  histograms)
- `_read_telemetry(run_dir)` and `_read_jsonl(path, limit=None)` —
  bounded readers with line-number-aware error messages
- HTML hardening: every user-supplied string passes through
  `html.escape`; the config table uses an allowlist (unknown JSON keys
  are silently dropped, not escaped — safer than per-field escaping
  because unknown XSS payloads never reach the renderer); no external
  CSS, no `<script>`, no CDN, no `@import url(...)`; balanced tags
  verified by selftest

**Added — phase 11 (`eyesieve_cli.py` + `pyproject.toml`)**

- `eyesieve_cli.py` — unified dispatcher. `eyesieve <subcommand> [args...]`
  routes to the right module's `main()`. The dispatcher uses
  `inspect.signature` to handle both `main(argv)` and `main()` (no-argv)
  patterns transparently, so `eyesieve selftest` works even though
  `eyesieve_selftest.main()` takes no parameters
- `pyproject.toml` — PEP 621 metadata for `pip install -e .` and wheel
  builds. Eight console scripts (`eyesieve`, `eyesieve-run`,
  `eyesieve-mp`, `eyesieve-report`, `eyesieve-corpus-report`,
  `eyesieve-reader`, `eyesieve-selftest`, `eyesieve-preflight`) all map
  to verified `module:main` callables. `py-modules` lists all 17
  flat-file modules — confirmed to match the filesystem exactly during
  audit 4. Verified end-to-end with a fresh venv install: console
  scripts work from any CWD, find their corpus via `--data` absolute
  path, and produce identical output to direct script invocation

**Audit-driven fix: PermutationError**

Audit 2 (API surface) caught that `eyesieve_permutations.py` was the
only module without a typed exception. Four `raise ValueError(...)`
sites in `BlockReverseN`, `StrideN`, `GridTranspose`, and
`MessageIndexed` were converted to `raise PermutationError(...)`, with
the new class carrying the standard `XD-MBYG04K-URS3LF` prefix.
Verified safe: no downstream code catches `ValueError` from
permutations specifically. Two selftests added to lock the convention
in (`t_perm_error_prefix`, `t_perm_module_has_error_prefix`).

**Test additions (26 new tests; total 218)**

- 13 phase-10 tests: error prefix, missing/malformed telemetry, JSONL
  edge handling (empty file, blank lines, limit), render_html on real
  run dirs, HTML escape of user-supplied strings (XSS guard), section
  coverage, no-scoring path, top_n truncation, funnel row count = 6
  (input + execute + 3 stages + survivors), Theory 2 derivation family
  parsing in breakdown section
- 7 phase-11 tests: SUBCOMMANDS completeness, no-args usage, --help,
  unknown subcommand → rc=2, no-argv-main signature adaptation, argv
  forwarding, main() exists for each subcommand
- 5 audit-driven gap-closers: make_theory1 and make_theory2 convenience
  constructors, latent exception classes (`EnumeratorError`,
  `HypothesisError`, `RunnerError`) are constructible with prefix, the
  `dataclass_dict` helper round-trips a frozen dataclass
- 2 cross-cutting consistency tests: `PermutationError` carries the
  prefix, `eyesieve_permutations.ERROR_PREFIX` matches the global
  standard

**Comprehensive ecosystem audit (10 passes, all clean)**

1. **Module inventory + dependency graph.** 17 modules, 10,469 lines,
   78 classes, 424 public functions. DAG verified (no cycles). Foundation
   modules (corpus, permutations, ciphers) have no internal deps;
   top-level entry points are `eyesieve_selftest` and `eyesieve_preflight`
   with `eyesieve_cli` acting as a dynamic dispatcher.
2. **API surface, ERROR_PREFIX, frozen dataclasses, Protocols.**
   16 modules carry `ERROR_PREFIX`; 11 custom Exception classes all
   include the prefix; 20 frozen dataclasses reject mutation; 6 Protocol
   classes are `@runtime_checkable`; every module has a substantive
   docstring; all 8 CLI entry-point modules expose `main()`; module
   imports are all < 200ms (no heavy side effects).
3. **Data flow integrity end-to-end.** Default T1 estimated count
   matches actual (7,968). Telemetry balances: survivors + exec_failures
   + sum(killed) == total_evaluated. `_sieve_result_to_dict` and
   `_scoring_result_to_dict` are JSON-clean. Single-process Runner and
   MultiprocessRunner produce byte-identical `survivors.jsonl`.
   Telemetry (sans timing) is byte-deterministic across runs. Theory 2
   enumeration emits all 3 derivation types (SelfMerge, CrossMerge,
   ConstantMerge). `render_html` is deterministic across calls.
4. **Documentation accuracy.** Caught: README listed 192 tests
   (current 218), missing `eyesieve_run_report` module, missing phase
   11 mention. **Fixed in README:** phase status, module list, install
   instructions, v1.0 summary paragraph. CHANGELOG covers all phases.
   Every entry-point `--help` renders cleanly. CLI dispatcher `--help`
   lists all 7 subcommands. Error messages contain actionable context
   (`unknown subcommand`, `invalid choice`, `not found`). All 8
   `pyproject` console_scripts resolve to importable callables.
   `py-modules` list matches filesystem exactly. HTML report is
   self-contained (no http src/href, no external stylesheet).
5. **Performance baselines (v1.0).** T1 enumeration (no cascade):
   668,605 hypos/sec. T2 enumeration: 703,905 hypos/sec. T1 sieve:
   17,779 hypos/sec. T1 default end-to-end (single-process): 0.49s.
   T2 default end-to-end (mp, 1 worker): 31.4s. Union (T1+T2, 454K
   hypos) end-to-end: 31.8s. Module import range: 0.7ms (cli) to 75ms
   (selftest). CLI dispatch overhead: 13ms per invocation.
   `render_html`: 5ms → 42 KB output.
6. **Robustness, security, edges.** `--workers -1` rejected (rc=2).
   `--chunksize 0` rejected. Unicode (`ünicöde`, `ž`, `š`) renders
   cleanly. Two concurrent runners on same dir both complete (no
   lockfile by design — last-write-wins documented). Empty corpus
   message body rejected by corpus loader with prefixed `CorpusError`.
   Malformed JSONL surfaces with `line 2` line number. Survivor count
   `> scored.jsonl` (when --max-survivors caps scoring) handled
   correctly. Absolute corpus path works from any CWD. Unknown JSON
   keys silently ignored (forward compat).
7. **Test coverage gap analysis.** 68% direct-reference coverage
   across 154 public APIs; effective coverage ~95% when counting
   indirect (section renderers tested via top-level callers). Audit-
   driven additions closed real gaps: `make_theory1`, `make_theory2`,
   latent exception classes, `dataclass_dict`.
8. **Cipher numerical correctness.** Full encrypt → decrypt round-trip
   on 12 ciphers, multiple key/text pairs each. Vigenere matches
   `(p + k) mod n`. Beaufort matches `(k - p) mod n` and is
   self-reciprocal. XOR-stream is self-reciprocal when output stays in
   `[0, deck)`. Affine matches `(a·p + b) mod n` with the documented
   `a = (key[0] % (n-1)) + 1` convention (audit caught my own test's
   wrong key convention here, not a code bug). Columnar transposition
   round-trips with valid key lengths. All 12 ciphers produce in-range
   output when valid; reject invalid input with prefixed `CipherError`.
9. **HTML output edge cases.** Long hypothesis names (446 chars)
   render without layout break. Decrypted text truncated to 80 chars
   in leaderboard cells (verified the only run of 5+ identical chars
   in HTML is exactly 80 long). Empty survivors with non-zero totals
   render with "no scored candidates" note and balanced funnel rows.
   Large numbers (446,208) get comma separators. All tag pairs
   balanced. HTML5 DOCTYPE declared. UTF-8 charset declared. No
   `@import` or external URLs in CSS. Special HTML metacharacters
   (`<>&"'`) escaped in known config keys; unknown keys silently
   dropped by allowlist (XSS-safe by construction). Zero-total runs
   render without `ZeroDivisionError`.
10. **Final integrity sweep.** 218/218 selftests green. All 8 console
    scripts install and invoke cleanly from a fresh venv. Pyproject
    parses, builds, and produces an editable wheel. CHANGELOG, README,
    and MANIFEST regenerated against the v1.0 file set.

**Updated**

- `README.md` — phase status updated through phase 11 (v1.0); module
  list now includes `eyesieve_run_report.py` and `eyesieve_cli.py`;
  test count corrected to 218; install instructions added covering
  both `pip install -e .` and direct script invocation; v1.0 summary
  paragraph.
- `eyesieve_preflight.py` — `REQUIRED_MODULES` includes both
  `eyesieve_mprunner` and the new modules.
- Selftest banner: phase 10.

---

## v0.9.0 — 2026-05-14

### Phase 8 + 9: Multiprocess runner with checkpointing, Theory 2 derivations

Phase 8 and phase 9 were built concurrently. Phase 9 (Theory 2) expands
the search space by ~56× over Theory 1's default 7,968 hypotheses;
phase 8 (multiprocessing + checkpointing) makes that expansion tractable.
Building them together let each phase validate the other through real
workloads: phase 8 tested its determinism against the larger Theory 2
sweep, and phase 9 verified its derivations pickle cleanly through
mp.Pool workers from the start.

**Added — phase 9 (Theory 2)**

- `eyesieve_keyderiv.py` extensions:
  - `SelfMerge(permutation, combine_op)` — E5 combined with a
    permutation of itself, parametric over Permutation and MergeOp
  - `CrossMerge(cross_code, combine_op)` — E5 combined with another
    corpus message, with KeyDerivError on unknown cross codes
  - `ConstantMerge(pattern, combine_op)` — E5 combined with a
    position-derived constant from `CONSTANT_PATTERNS` (zeros, ones,
    counter, reverse_counter, deck_modulo)
  - `enumerate_theory2(corpus, key_code, ...)` and
    `estimated_count_theory2(...)` — generators with knobs for which
    derivation families and which subset of MergeOps/Permutations
  - `THEORY2_DEFAULT_COMBINE_OP_NAMES` (4 ops: cyclic_add, cyclic_sub,
    trunc_add, trunc_sub) and `THEORY2_DEFAULT_PERMUTATION_NAMES`
    (5 perms: reverse, rotate_k(1), rotate_k(7), stride_n(2),
    block_reverse_n(3)) — produce 56 derivations by default

- `eyesieve_enumerator.py` extensions:
  - `Theory2Config` frozen dataclass with all Theory 1 dimensions plus
    Theory-2-specific knobs (include_self_merge, include_cross_merge,
    include_constant_merge, combine_op_names, permutation_names)
  - `Theory2Enumerator` — re-enumerates Theory 2 derivations per key_code
    so CrossMerge properly excludes the current key from cross targets;
    default size 4×2×83×12×56 = **446,208 hypotheses**
  - `TheoryUnionEnumerator` — yields Theory 1 first, then Theory 2,
    preserving deterministic order for checkpoint resume; default
    union size 7,968 + 446,208 = **454,176 hypotheses**
  - `make_theory1(corpus, **kwargs)` and `make_theory2(corpus, **kwargs)`
    convenience constructors

**Added — phase 8 (multiprocess runner)**

- `eyesieve_mprunner.py` — new sibling module to `eyesieve_runner.py`:
  - `MPRunConfig` frozen dataclass extending the single-process config
    with `theory` selector (`theory1` / `theory2` / `union`), `n_workers`,
    `chunksize`, `checkpoint_every`, and `resume`
  - `MultiprocessRunner` class with `run() -> MPRunResult`
  - Worker initialization via `mp.Pool(initializer=_init_worker)` loads
    the corpus and default cascade into module-level globals once per
    worker, avoiding per-call serialization
  - `pool.imap()` (ordered, not `imap_unordered`) so survivor file order
    is deterministic and checkpoints correspond cleanly to "first N
    hypotheses processed"
  - Atomic checkpoint writes via `.tmp` + rename to prevent corruption
    on interruption
  - `_config_fingerprint()` — SHA256 over enumerator-affecting config
    fields (excludes output_dir, n_workers, scoring tunables, since
    those don't change which hypotheses are tested); resume refuses on
    fingerprint mismatch with a clear error
  - Resume mechanism that reads checkpoint, skips the corresponding
    hypotheses in the enumerator, and reads existing `survivors.jsonl`
    back into memory for the scoring pass

- CLI flags: `--theory {theory1,theory2,union}`, `--workers N`,
  `--chunksize N`, `--checkpoint-every N`, `--resume`, with the same
  `--config` preset support as the single-process runner

**Bug caught during build (race condition in resume)**

A real concurrency hazard surfaced during end-to-end resume testing:
if the runner crashes between writing a survivor to `survivors.jsonl`
(line-buffered, flushed immediately) and writing the next checkpoint
(periodic), that survivor lives in the file but the checkpoint reports
fewer survivors. On resume, the runner re-processes the corresponding
hypothesis and writes the same survivor again — silent duplication.

Fixed in `_maybe_resume()` by truncating `survivors.jsonl` to exactly
`checkpoint.telemetry.survivors` lines when loading state, with a WARN
log line if truncation was needed. The streaming write order makes
this safe: survivors written before the most recent successful
checkpoint always remain; only the partial post-checkpoint tail is
discarded for re-processing.

**Performance (single-CPU validation environment)**

- Default Theory 2 sweep (446,208 hypotheses, no scoring): 29s,
  ~15,000 hyps/sec, +49 MB RSS — well-controlled memory
- Workers 1/2/3 produce byte-identical `survivors.jsonl` files (3,652
  hypothesis mono sample); telemetry totals match to the integer.
  Per-process IPC overhead means multi-worker is slower than
  single-process on a 1-CPU box, but correctness is preserved for
  validation on multi-CPU systems
- Theory 2 with XOR-family combine_ops produces ~55% execute failures
  (in-range arithmetic constraint violated); cascade absorbs these
  cleanly with `execute_failures` tracking

**Selftest additions (33 new tests, total 192)**

- 12 Theory 2 keyderiv tests: SelfMerge/CrossMerge/ConstantMerge name,
  derive, pickle, empty-input handling; enumerate_theory2 default
  count == 56, excludes key_code from cross targets, empty-subset
  behavior; `_build_constant` unknown-pattern error
- 8 Theory 2 enumerator tests: Theory2Config defaults, yields
  Hypothesis instances, default count == 446,208, estimated ==
  actual iteration, never yields Identity, union ordering (T1 first
  then T2), union count, hypotheses survive pickle through mp.Pool
- 13 Multiprocess runner tests: MPRunConfig defaults, MPRunnerError
  prefix, rejection of n_workers=0 and unknown theory strings,
  fingerprint stability + sensitivity, checkpoint round-trip,
  workers=1 matches single-process Runner byte-for-byte, workers=2
  matches workers=1, checkpoint file written, resume from rewound
  checkpoint completes, resume refuses on fingerprint mismatch,
  resume truncates survivors.jsonl on count desync

**Paranoia audit (6 passes, all clean)**

1. **Fundamentals.** Error prefixes consistent across all new
   exceptions (KeyDerivError, MPRunnerError, EnumeratorError). All
   new frozen dataclasses reject mutation and round-trip through
   pickle. Theory 2 Hypothesis instances pickle cleanly. Enumerator
   counts match actual iteration on default and small configs.
2. **Subtle correctness.** Checkpoint write is atomic (no .tmp
   stragglers); corrupt JSON detected with MPRunnerError. Theory 2
   derivations handle length edge cases (concat extends, ConstantMerge
   on deck_size=1, all patterns return () for length=0). Union
   end-to-end balances telemetry. Worker init properly errors on bad
   data_path. dataclass_dict round-trips Path and tuple fields.
   File handle hygiene confirmed via try/finally. Hypothesis equality
   + hash are consistent.
3. **Stress + resources.** 446K Theory 2 sweep: 29s, +49 MB RSS, no
   FD leaks across 3 sequential runs. Repeated runs in same output
   dir produce identical bytes. Streamed survivor writes are
   line-buffered. Cascade properly per-worker. 80,344 Theory 2
   hypothesis names are all unique. Pickle byte-stable across calls.
4. **Adversarial inputs + integration.** CLI roundtrip via subprocess
   works; rejects invalid theory at argparse layer. Chunksize > total
   handled. Numerical equivalence: single-process and mprunner produce
   identical scored.jsonl top results. Union resume completes.
   Fingerprint mismatch rejected. mprunner output_dir auto-creates
   parents. SelfMerge with non-trivial permutations survives mp.Pool.
   --resume with no checkpoint starts fresh (no crash).
5. **Multi-worker resume + ordering.** workers=2 resume completes
   correctly. workers 1/2/3 produce byte-identical survivors files.
   scored.jsonl is sorted descending by best_score. Theory 2 + scoring
   integration works (top T2 candidates use Theory 2 derivations).
   progress_every=1 produces 3,652 log entries cleanly. telemetry.json
   has fingerprint and timing breakdown. Theory 2 sweep determinism
   confirmed by re-run hash comparison.
6. **Residual.** Error messages include actionable context (empty key
   source, unknown cross source 'ZZZ', unknown constant pattern).
   Resume after completion is a no-op. All 25 permutations × cyclic_add
   produce valid SelfMerge output. All 4 cross codes produce valid
   CrossMerge output. All 5 ConstantMerge patterns produce in-range
   output. Documentation/implementation consistency verified.

**Updated**

- `eyesieve_preflight.py` — REQUIRED_MODULES now includes
  `eyesieve_mprunner` (total 12 internal modules).
- Selftest banner: phase 8.

---

## v0.7.0 — 2026-05-14

### Phase 6 + 7: Single-process runner and dictionary scoring

Phases 6 and 7 were built concurrently. The runner needs scoring to
produce its top-N leaderboard; the scoring layer needs the runner as its
primary consumer. Splitting them across releases would mean shipping
either an orchestrator with nothing to orchestrate or a scorer with no
ingest path.

**Added — phase 6 (runner)**

- `eyesieve_runner.py` — single-process pipeline orchestrator.
  - `RunConfig` frozen dataclass: data path, output dir, enumerator
    config, scoring switch + tuning, progress cadence, quiet mode
  - `Runner` class with `run() -> RunResult`
  - Two-pass execution: streaming sieve cascade collects survivors,
    optional scoring pass ranks them
  - CLI with six enumerator-config presets (`strict`, `mono`, `no-xor`,
    `cross-pair`, `any-key`, `liberal`) and toggles for scoring, progress
    cadence, and survivor cap
  - SPECTR cyberpunk banner + log styling matching the selftest
  - Outputs three artifacts to the configured output directory:
    - `telemetry.json` — aggregate cascade stats (totals, per-stage
      kills, timing breakdown, config echo)
    - `survivors.jsonl` — one survivor per line with hypothesis name,
      verdict trail, full candidate sequence
    - `scored.jsonl` — survivors with per-language scoring added, sorted
      by best zipf_score descending
    - `run.log` — structured progress log with ANSI stripped

**Added — phase 7 (scoring)**

- `eyesieve_scoring.py` — wrapper around `eyestat_scoring` for
  dictionary-based candidate scoring.
  - `ScoringConfig` frozen dataclass: eyestat directory, target
    languages, Hungarian perturbation count (`n_mappings`)
  - `Scorer` class: loads Finnish / Karelian / English dictionaries
    from the eyestat checkout on init, exposes `score(candidate,
    alphabet_size) -> ScoringResult`
  - `ScoringResult` frozen dataclass with `per_language` tuple of
    `LanguageScore` entries; exposes `best_score`, `best_language`,
    `total_hits` properties for ranking
  - `LanguageScore` carries `hits`, `zipf_score`, `decrypted_text`, and
    `best_mapping_pairs` (tuple-of-pairs for hashability rather than
    dict, with a `.best_mapping` dict property for ergonomics)
  - `is_eyestat_available()` probes import-ability without raising

**Bug caught during integration**

- `eyestat_scoring.score_decryption` legitimately returns
  `best_mapping=None` for any language whose Hungarian-perturbed
  mappings produce zero dictionary hits. Initial wrapper code assumed
  the mapping was always a dict, which crashed on noise candidates.
  Fixed by treating `None` as `{}` and `None` decrypted_text as `""`.

**Wordlists used** (loaded from `/home/claude/eyestat_ref/eyestat`)

- `extra_words_fi.txt` (92,021 lines) + `noita_wordlist.txt` (883 lines)
  → Finnish dictionary (92,716 unique words)
- `extra_words_krl.txt` (1,880 lines) → Karelian dictionary
- `eng-wordlist.txt` (466,550 lines) → English dictionary (466,431 unique)

**Selftest additions (16 new tests, total 159)**

- 8 Scoring tests: ScoringConfig defaults, eyestat availability probe,
  LanguageScore pickle round-trip, ScoringResult.best_score/language/
  total_hits properties, Scorer construction, scoring on a real
  survivor, graceful handling of None best_mapping for noise candidates,
  ScoringError on empty input
- 8 Runner tests: RunConfig defaults, all 6 CONFIG_PRESETS validated,
  Runner construction, run-without-scoring output shape, run-with-
  scoring output shape, JSON well-formedness, telemetry-balance
  invariant, quiet-mode preserves output files

**Audit findings**

A full default-config run (7,968 hypotheses, no scoring) finishes in
0.19s. A cross-pair config sweep (31,872 hypotheses) finishes in 1.47s
at ~21,000 hyps/sec single-threaded — well under the 5s budget for
interactive iteration. Scoring on the cheap-sieve survivor set
(typically 100-300 candidates) at `n_mappings=100` runs at roughly
0.2s per candidate; the full survivor set scores in 30-60s.

The phase-7 leaderboard on Theory 1 default config currently surfaces
no real plaintext. Top candidates cluster around `merge(E4+W4, *_sub)`
+ `columnar_transposition` with best Finnish zipf scores around 8.0,
which is consistent with the structural artifact pattern we identified
in the phase-5 audit (E4 and W4 happen to align in low-entropy ways
under subtraction-family merges). Phase 8 multiprocessing + Theory 2
(phase 9) are needed to push the search space further.

**Documentation hardenings**

- `Runner._print_top_candidates` now respects `quiet=True` (cosmetic
  fix — was leaking leaderboard output into the selftest)
- Lazy import of `eyesieve_scoring` inside `_run_scoring_pass` so
  runner imports cleanly even when eyestat is unavailable

**Updated**

- `eyesieve_preflight.py` — REQUIRED_MODULES now includes the two new
  modules (total 11 internal modules).
- Selftest banner: phase 7.

---

## v0.5.0 — 2026-05-14

### Phase 4 + 5: Hypothesis pipeline and sieve cascade

Phases 4 and 5 were built concurrently because the Hypothesis abstraction
(phase 4) is the unit of work the Sieve consumes (phase 5). Splitting them
across separate releases would have meant shipping phase 4 with no
consumer.

**Added — phase 4 (search-space scaffolding)**

- `eyesieve_keyderiv.py` — `KeyDerivation` protocol and `Identity`
  implementation. Theory 1 uses Identity exclusively (E5 IS the key,
  no transformation). The architecture is set up to absorb Theory 2's
  `SelfMerge` / `CrossMerge` / `ConstantMerge` derivations in phase 9
  without touching anything else.
- `eyesieve_hypothesis.py` — `Hypothesis` frozen dataclass bundling
  `(input_binding, key_binding, key_derivation, cipher)` into one
  executable unit. `execute(corpus)` runs the full pipeline:
  resolve input → resolve key → derive effective key → cipher.decrypt.
  Frozen, hashable, picklable — multiprocessing-safe.
- `eyesieve_enumerator.py` — `Theory1Enumerator` yielding the
  search space as an iterator. Four configuration knobs:
  - `strict_pairing` (default True): same-index pairs only (E1-W1, E2-W2…)
  - `bidirectional` (default True): test (east,west) and (west,east) per pair
  - `fixed_key_E5` (default True): only E5 as key candidate
  - `include_xor_ciphers` (default True): include XOR (kept by default for
    completeness — most XOR hypotheses die at the alphabet-closure stage)

  Defaults yield 7,968 hypotheses (4 pairs × 2 orderings × 83 merge ops
  × 12 ciphers). Full-liberal config yields 159,360.

**Added — phase 5 (cheap sieve cascade)**

- `eyesieve_sieve.py` — `SieveCascade` running candidates through four
  cheap filter stages:
  1. **LengthSieve** — reject if length < 20 (IC/freq stats unstable below)
  2. **AlphabetClosureSieve** — every output value must lie in [0, deck_size)
  3. **ICSieve** — index of coincidence between 0.030 and 0.20
     (uniform-over-83 ≈ 0.012; natural Finnish ≈ 0.065-0.080)
  4. **SymbolDistributionSieve** — no symbol exceeds 30% of output,
     at least 10 distinct symbols present
- `SieveResult` frozen dataclass with verdict trail per stage.
- `SieveTelemetry` collector for aggregating results across many
  hypotheses (used by phase 6 runner and phase 10 dashboard).
- `SieveCascade.evaluate` catches typed pipeline errors
  (SourceError, KeyDerivError, CipherError) as `killed_at="execute"`.
  Unexpected exceptions propagate — those are framework bugs.

**Added — selftest (43 new tests, total 143)**

- 5 KeyDerivation tests: Identity passthrough, empty-source error,
  pickle round-trip, protocol compliance, enumeration count
- 6 Hypothesis tests: pickle, execute correctness vs. manual pipeline,
  intermediates dict, name composition, equality semantics
- 12 Theory1Enumerator tests: config defaults, yield correctness,
  closed-form count vs. iteration, count math for every config combo,
  Identity-only invariant, idempotent re-iteration, make_theory1
  convenience constructor, hypotheses-are-picklable bulk check
- 20 Sieve tests: IC/max-freq/distinct known answers, each stage's
  boundary conditions, cascade default-stages order, first-kill-stops
  invariant, all three execute-error captures, RuntimeError propagation
  regression, telemetry accumulation, JSON serializability, stage
  pickle round-trip, protocol compliance, 200-hypothesis smoke run

**Comprehensive audit findings**

A full default-config sweep (7,968 hypotheses, 0.44s on the test box —
~18K hyps/sec single-threaded) reveals the cheap cascade is doing what
it should:
- Survivors: 266 (3.34%) — passes through to phase 7 full scoring
- IC-killed: 6,574 (82.5%) — the dominant filter
- Alphabet-closure-killed: 728 (9.1%)
- Distribution-killed: 288 (3.6%)
- Execute failures: 112

The alphabet_closure count needed a closer look — 664 are the expected
XOR cipher hypotheses (XOR isn't alphabet-closed on 83 symbols), but
64 additional kills come from a structural interaction: the `cyclic_xor`
and `trunc_xor` *merge operations* (not the XOR cipher) also produce
out-of-range values. When those values flow into ColumnarTransposition
(a permutation cipher that doesn't validate alphabet), they get caught
downstream by the alphabet_closure sieve. When they flow into modular
ciphers (Vigenere/Beaufort/etc.), the cipher rejects them with
`CipherError`, captured as `killed_at="execute"`. Both paths are
intentional — the cascade gracefully handles them differently because
permutation ciphers and modular ciphers have different alphabet contracts.

**Documentation fixes from audit**

- `SieveCascade.evaluate`: comment noting that future typed errors
  (e.g. MappingError, ScoringError in phase 7) must be added to the
  except tuple.
- `SieveStage` protocol: comment clarifying that `cost_tier` is
  informational metadata. The cascade runs stages in declaration order,
  not sorted by tier — cascade builders are responsible for declaring
  cheap stages first.
- `Theory1Enumerator._pairs`: corpus-assumption comment about the
  east/west naming convention used for same-index pair matching.

**Updated**

- `eyesieve_preflight.py` — REQUIRED_MODULES now includes the four
  new modules.
- Selftest banner: phase 5.

---

## v0.3.0 — 2026-05-14

### Phase 3: Cipher families

**Added**
- `eyesieve_ciphers.py` — `Cipher` protocol plus 12 concrete cipher
  implementations in 9 classes:
  - **Modular stream**: `Vigenere` (ct = pt + key), `Beaufort` (ct = key
    − pt, self-inverse), `VariantBeaufort` (ct = pt − key)
  - **Non-modular stream**: `XORStream` (self-inverse; not closed on
    the 83-symbol alphabet — outputs frequently escape [0, 82] and
    will be killed by the alphabet-closure sieve in phase 5)
  - **Autokey**: `VigenereAutokey` and `BeaufortAutokey`, both
    plaintext-extending (the recovered plaintext extends the
    effective keystream past position K)
  - **Other classical**: `Affine` (key-derived (a, b); requires prime
    alphabet — N = 83 is prime, framework rejects composite N at
    construction), `KeywordSubstitution` (keyword-first permutation),
    `ColumnarTransposition` × 4 variants (k_columns ∈ {3, 4, 5, 7})
- 22 new cipher selftests (total 100, up from 78):
  - Cipher protocol compliance
  - Round-trip encrypt → decrypt on simple inputs
  - Round-trip on every real corpus message under E5
  - Empty-key handling: all ciphers raise `CipherError` with the
    standard error prefix
  - Empty-input handling: all ciphers return empty
  - Self-inverse property for XORStream and Beaufort
  - **NOT self-inverse** regression test for BeaufortAutokey (see
    audit finding below)
  - Algebraic identity check: `Vigenere.encrypt ==
    VariantBeaufort.decrypt` (both compute `pt + key mod N`)
  - Known-answer tests for Vigenere, Beaufort, VigenereAutokey,
    KeywordSubstitution, and ColumnarTransposition
  - Affine: derives invertible (a, b) for every key[0] in [0, 83);
    rejects composite deck_size at construction
  - ColumnarTransposition: stable column ordering on tied keys;
    rejects keys shorter than column count
  - Vigenere out-of-alphabet input rejection
  - Determinism, pickle round-trip, and uniqueness of enumeration

**Audit findings & fixes**
- **Bug (docstring)**: `BeaufortAutokey` originally claimed to be
  self-inverse like its non-autokey parent. Audit revealed this is
  false: `encrypt` extends the keystream with the input plaintext,
  but `decrypt` extends it with the recovered plaintext — these are
  different sources, so `encrypt(encrypt(pt, k), k) ≠ pt` in
  general. The implementation was correct (encrypt+decrypt do form
  a proper inverse pair, as the round-trip test confirms), only the
  documentation was wrong. Fixed.
- **Observation (not a bug)**: `Vigenere.encrypt` and
  `VariantBeaufort.decrypt` compute the same operation (`pt + key
  mod N`). This is an algebraic identity, not a defect. The phase-4
  hypothesis enumerator should consider deduplicating cipher pairs
  that produce equivalent search outputs.

**Smoke test (preview of phase 6 runner)**
- Applied all 12 ciphers to a realistic input: `Concat(E1, W1)`
  (length 202) under key `E5` (length 114). All 11 modular ciphers
  preserve alphabet closure. XOR produces 37/202 out-of-alphabet
  symbols, confirming the documented closure-failure behavior.
- All output ICs cluster near the uniform-random baseline (1/83 ≈
  0.012), nowhere near the natural-language baseline (~0.06). This
  is the expected null result: direct "E5-as-key" under any single
  modular cipher does not reveal a plaintext signal. The real
  search will require key derivation (Theory 2), alternate merge
  ops, or rotations.

**Infrastructure**
- `eyesieve_preflight.py`: added `eyesieve_ciphers` to
  `REQUIRED_MODULES` (4 → 5).

**Working-environment integrity notes**
- During this phase's development, several files appeared in the
  working directory that were not authored as part of this iteration:
  a placeholder `eyesieve_ciphers.py` using a different API
  (`AddStream`/`SubStream`/etc.); four future-phase modules
  (`eyesieve_enumerator`, `eyesieve_hypothesis`, `eyesieve_keyderiv`,
  `eyesieve_sieve`); and substantial added content in
  `eyesieve_selftest.py` and this changelog referencing the
  placeholder API. These were preserved to `/tmp/contamination_forensics/`
  and `/tmp/unexpected_ciphers.py.bak`, then removed before
  authoring the real v0.3.0 module. The released phase-3 code in
  this changelog is the implementation that was authored
  deliberately and audited; phantom content is not part of this
  release.

---

### Phase 2: Sources & merge operations

**Added**
- `eyesieve_sources.py` — slot bindings (`SingleMessage`, `MergedMessages`)
  plus six merge-operation families:
  - **`Concat`** — concatenate in declaration order; accepts 1+ inputs
  - **`CyclicCombine(op)`** — Vigenère-style; first arg is data, second is
    cyclic keystream; ops `add` / `sub` / `xor`; order-asymmetric
  - **`Interleave(start)`** — alternate symbols, with `start=0/1` controlling
    which input goes first
  - **`TruncatedAlign(op)`** — position-wise combine over min-length prefix;
    same ops as CyclicCombine
  - **`HeaderPayload(h, payload_op, preserve_header)`** — strip `h` leading
    positions then apply an inner merge op to the payloads; optionally
    preserve one input's header. Default sweep `header_lengths = (0, 1, 2, 3, 5, 9)`
    aligns with the phase-1 structural break points (universal end, 3/6
    split end, 4-group end).
  - **`IndexDriven(mode)`** — first input drives positional / skip choices;
    second supplies symbols; modes `lookup` / `skip`
- `enumerate_merge_ops()` yields 83 default-sweep variants:
  11 base ops + 6 header lengths × 6 inner ops × 2 preserve-header values
- 28 new source-module selftests (total 78, up from 50):
  - Known-answer tests for every merge op
  - Output-length predictions for every op (data-determined where applicable)
  - Edge cases: empty inputs, single-element inputs, length-1
  - Arity enforcement (all 2-arg ops reject 1-arg or 3-arg calls)
  - Determinism across calls
  - Pickle round-trip for every enumerated op (multiprocessing prerequisite)
  - Cross-product test: every default-enumerated op runs cleanly against
    every (E_i, W_i) corpus pair
  - Composition correctness: `HeaderPayload(0, inner)` equals `inner` alone
  - Inverse: `CyclicCombine(add)` → `CyclicCombine(sub)` round-trips
  - Alphabet closure: `add` / `sub` keep output in `[0, deck_size)`
  - Error contract: every error path raises `SourceError` with the standard
    error-code prefix

**Mechanical confirmation of phase-1 findings**
Running `HeaderPayload(1, TruncatedAlign(sub))` on each (E_i, W_i) pair
(strip sigma0, then position-wise subtract) reproduces the phase-1
diff-derived leading-zero runs exactly:

  | pair    | leading zeros (post-sigma0) | matches phase 1? |
  |---------|----------------------------:|------------------|
  | E1 ↔ W1 |                          24 | ✓ (positions 1-24) |
  | E2 ↔ W2 |                           2 | ✓ (universal only) |
  | E3 ↔ W3 |                           5 | ✓ (through 6-group end) |
  | E4 ↔ W4 |                          20 | ✓ (positions 1-20) |

The framework's mechanical view now confirms the visual one — what we
saw in the reader is what the merge operations produce.

**Fixed**
- `eyesieve_preflight.py` now also checks that `eyesieve_sources` imports
  cleanly (preflight up to 31 checks under `--eyestat-dir`).

---



### Content reader

**Added**
- `eyesieve_reader.py` — content reader and visual explorer for the
  corpus. Seven view modes (`--show`, `--grid`, `--column`, `--columns`,
  `--prefix`, `--diff`, `--all`) and three display formats (`decimal`,
  `hex`, `glyph`). Optional `--freq-color` paints each rune by its
  corpus-wide frequency rank using a 256-color gradient.
- 12 new reader selftests (total 50, up from 38):
  - GLYPHS table integrity (83 unique single-char printables)
  - FrequencyMap rank consistency and color-code validity
  - HighlightMap correctness (universal positions, prefix groups)
  - Visible-width padding across all three formats
  - Smoke + behavior tests for every view mode
  - Cross-product test: every view mode × every format × every
    highlight/freq-color combination
  - Pairwise diff regression: confirms the known 24-position E1↔W1
    matching run (positions 1-24)

**Observed (via the new reader)**
- East-West pair match characteristics differ dramatically:
  - **E1 ↔ W1**: 44.4% match, longest run = **24 positions** (1-24)
  - **E2 ↔ W2**: 2.9% match, longest run = 2 positions
  - **E3 ↔ W3**: 5.6% match, longest run = 5 positions
  - **E4 ↔ W4**: 18.5% match, longest run = **20 positions** (1-20)
  - Two pairs share substantial structural prefixes beyond the universal
    (1, 2) and the 3/6 split (3-5); two pairs do not. This non-uniform
    pairing structure is a foundational hint for the Theory 1
    merge-operation enumeration.

**Fixed**
- `eyesieve_preflight.py` now also checks that `eyesieve_reader` imports
  cleanly (preflight up to 30 checks under `--eyestat-dir`).

---



### Paranoia audit + preflight

**Added**
- `eyesieve_preflight.py` — comprehensive pre-launch sanity sweep across
  eight sections: Python environment, module imports, data integrity
  (incl. SHA-256 match), structural invariants, selftest pass-through,
  output directory writability, system resources, and EyeStat
  integration readiness. Exit codes 0/1/2; writes
  `preflight_report.txt`. Supports `--strict` to treat warnings as
  failures.
- 12 additional selftests (total 38, up from 26):
  - Pickle round-trip for `Corpus` and every concrete permutation
    (multiprocessing-safety prerequisite)
  - Empty-sequence and length-1 edge cases for every permutation
  - Permutation round-trips against every real corpus message
  - Load determinism (two `load_corpus()` calls produce equal objects)
  - Frozen-dataclass mutability check
  - Negative-path tests: missing file, malformed JSON, wrong-type fields
  - Consistent error contract across all `Corpus` lookup methods

**Fixed**
- `universal_prefix()` renamed to `universal_positions()` to match its
  actual semantics (scans *all* universal columns, not just a contiguous
  prefix). Backward-compat alias retained.
- `Corpus.length_of()`, `short_to_label()`, `label_to_short()` now raise
  `CorpusError` on unknown input instead of bare `ValueError`. Lookup
  error contract is now consistent across the API.
- `load_corpus()` no longer has a TOCTOU race on file existence;
  catches `FileNotFoundError`, `PermissionError`, `OSError`, and
  `json.JSONDecodeError` with clear diagnostic messages.
- `load_corpus()` now type-strict on every JSON field, surfacing
  wrong-type values (e.g. `message_labels` as a string instead of a
  list) with a clear `CorpusError` rather than a cryptic deep
  `TypeError`.
- `shared_prefix_groups()` docstring clarified to be unambiguous about
  `max_position` semantics.
- `estimated_count()` simplified — removed `tuple(tuple())` artifact.

---



### Phase 1: foundation

**Added**
- `eyesieve_corpus.py` — load and validate `noita_eye_data.json`. Provides
  the immutable `Corpus` dataclass with short-code (`E1`, `W3`, ...) and
  full-label (`East 1`, ...) lookup. Strict integrity checks: 9 messages,
  1036 symbols, 83-rune alphabet, all symbols in `[0, 82]`, sigma0
  consistency. Structural analysis: `universal_prefix()`,
  `shared_prefix_groups()`, `alphabet_usage()`.
- `eyesieve_permutations.py` — parametric permutation families for Theory 2
  key derivation: `Identity`, `Reverse`, `RotateK`, `BlockReverseN`,
  `StrideN`, `GridTranspose`, `MessageIndexed`. All implement
  `apply()`/`inverse()` with round-trip self-consistency.
- `eyesieve_selftest.py` — 26 known-answer tests covering corpus loading,
  integrity, structural analysis, permutation round-trips, and protocol
  compliance.

**Observed (from corpus structural analysis)**
- Positions 1 and 2 are universally `(66, 5)` across all 9 messages.
- Positions 3-5 split cleanly **3 vs 6**: `(E1, W1, E2)` against
  `(W2, E3, W3, E4, W4, E5)`. Not an east-vs-west partition.
- Positions 6-9 keep `(E1, W1, E2)` together as a 3-group; the 6-group
  fragments to `(E3, E4, W4, E5)` (size 4).
- The shared-header structure is what the **header/payload split**
  merge operation in Theory 1 is designed to catch; sieve telemetry
  should surface where in the search space this signal lives.

**Standards**
- Hashbang convention: `#!/home/h3x/.venvs/eyesieve/bin/python3`
- Error-code prefix on all internal failures:
  `Internal Error Code: XD-MBYG04K-URS3LF`
- Color/tag output style matches EyeStat (`[ OK ]`, `[ WARN ]`,
  `[ FAIL ]`, `[ INFO ]`).
