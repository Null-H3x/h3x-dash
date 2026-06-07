# EyeSieve

**Combinatorial structural cryptanalysis pipeline for Noita's "eye messages."**

A sibling tool to [EyeStat](https://github.com/Null-H3x/eyestat). Where
EyeStat sweeps `(cipher mode × PRNG × seed)` and statistically scores
each decryption, **EyeSieve tests a different line**: it sweeps a
constrained hypothesis space of `(partition × source-merge × key-derivation × cipher)`
configurations and runs each through a cascading sieve to surface the
small set that's worth full statistical scoring.

The two tools share the `noita_eye_data.json` corpus and EyeStat's
scoring backend; EyeSieve's contribution is the structural hypothesis
framework.

---

## Theories under test

**Theory 1.** `merge(E_i, W_i)` is decrypted by E5 (key used as-is). The
four East-West message pairs are merged in some way; the complete East 5
ciphertext is the decryption key.

**Theory 2.** Same as Theory 1, but the effective key is a transformation
of E5 rather than E5 itself. Three merge-target variants in priority order:

- **self**   — E5 with a transformation of itself (e.g. `E5 ⊕ reverse(E5)`)
- **cross**  — E5 with another specific message
- **constant** — E5 with a position-derived pattern

Theory 1 is built first; Theory 2 adds key-derivation variants on top of
the same enumerator and sieve.

---

## Status

**Phase 1 — Foundation.** ✅ (v0.1.2)
**Phase 2 — Sources & merge operations.** ✅ (v0.2.0)
**Phase 3 — Cipher families.** ✅ (v0.3.0)
**Phase 4 + 5 — Hypothesis pipeline and sieve cascade.** ✅ (v0.5.0)
**Phase 6 + 7 — Runner and dictionary scoring.** ✅ (v0.7.0)
**Phase 8 + 9 — Multiprocess runner with checkpointing, Theory 2 derivations.** ✅ (v0.9.0)
**Phase 10 + 11 — HTML run reports and pip-installable packaging.** ✅ (v1.0.0)
- `eyesieve_corpus.py`        — corpus loading, validation, structural analysis
- `eyesieve_permutations.py`  — parametric permutation families for key derivation
- `eyesieve_preflight.py`     — comprehensive pre-launch sanity sweep
- `eyesieve_reader.py`        — content reader with 7 view modes and 3 display formats
- `eyesieve_html_report.py`   — self-contained HTML corpus report
- `eyesieve_run_report.py`    — self-contained HTML run report (telemetry, leaderboard, breakdown)
- `eyesieve_sources.py`       — slot bindings + 6 merge operation families
- `eyesieve_ciphers.py`       — 12 cipher implementations in 9 classes
- `eyesieve_keyderiv.py`      — KeyDerivation protocol + Identity (Theory 1) + SelfMerge/CrossMerge/ConstantMerge (Theory 2)
- `eyesieve_hypothesis.py`    — Hypothesis frozen dataclass bundling the full pipeline
- `eyesieve_enumerator.py`    — Theory1Enumerator (7,968 hypos default) + Theory2Enumerator (446,208) + TheoryUnionEnumerator (454,176)
- `eyesieve_sieve.py`         — 4-stage cheap sieve cascade with telemetry
- `eyesieve_scoring.py`       — Hungarian-optimal rune→letter scoring via eyestat
- `eyesieve_runner.py`        — single-process pipeline orchestrator with CLI
- `eyesieve_mprunner.py`      — multiprocess runner with checkpointing and resume
- `eyesieve_cli.py`           — unified `eyesieve <subcommand>` dispatcher
- `eyesieve_selftest.py`      — 214 known-answer tests across all modules

**Installation.** Either run modules directly with `python3 eyesieve_<name>.py` (legacy flat-file style), or install via `pip install -e .` which provides console scripts: `eyesieve`, `eyesieve-run`, `eyesieve-mp`, `eyesieve-report`, `eyesieve-corpus-report`, `eyesieve-reader`, `eyesieve-selftest`, `eyesieve-preflight`.

**v1.0.** The project has stabilized: all 11 planned phases are complete, six paranoia audit passes (phase 8/9) plus an additional four-audit comprehensive ecosystem sweep (v1.0) found no functional issues. The codebase totals ~10,500 lines across 17 modules with 214 known-answer tests.

See `CHANGELOG.md` for details.

---

## Quickstart

```bash
# Verify environment, data integrity, modules, structural invariants
./eyesieve_preflight.py
./eyesieve_preflight.py --eyestat-dir ~/Desktop/Noita/eyestat   # full integration

# Run the 192-test selftest directly
./eyesieve_selftest.py

# Print a corpus summary (lengths, universal positions, prefix groups)
./eyesieve_corpus.py --data noita_eye_data.json

# Read the ciphertext content:
./eyesieve_reader.py --grid                          # all 9 messages aligned
./eyesieve_reader.py --columns 0:20 --freq-color     # range with frequency tint
./eyesieve_reader.py --diff E1 W1                    # pairwise diff + summary
./eyesieve_reader.py --show E1 E5 --format glyph     # one-char-per-rune view
./eyesieve_reader.py --all > corpus_report.txt       # everything

# Generate an HTML report of the corpus
./eyesieve_html_report.py --output eyesieve_corpus_report.html
```

## Programmatic merge-op usage (phase 2 enables this)

```python
import eyesieve_corpus as ec
import eyesieve_sources as es

c = ec.load_corpus("noita_eye_data.json")

# Six merge families, 83 default-sweep variants
for op in es.enumerate_merge_ops():
    print(op.name)

# Concrete merges
es.Concat().apply(c.by_short("E1"), c.by_short("W1"))                  # 202 runes
es.CyclicCombine(op="add").apply(c.by_short("E1"), c.by_short("W1"))   # 99 runes
es.HeaderPayload(header_length=3, payload_op=es.Concat()).apply(...)   # strips structural prefix
```

---

## Project layout (matching EyeStat conventions)

```
eyesieve/
├── README.md
├── CHANGELOG.md
├── requirements.txt
├── noita_eye_data.json
├── eyesieve_corpus.py            # phase 1
├── eyesieve_permutations.py      # phase 1
├── eyesieve_selftest.py          # phase 1
├── eyesieve_sources.py           # phase 2 — slot binding, merge operations
├── eyesieve_ciphers.py           # phase 3
├── eyesieve_keyderiv.py          # phase 4 — Theory 2 key derivations
├── eyesieve_hypothesis.py        # phase 4
├── eyesieve_sieve.py             # phase 5 — cascade
├── eyesieve_enumerator.py        # phase 6
├── eyesieve_runner.py            # phase 7
├── eyesieve_scoring.py           # phase 8 — wraps EyeStat scoring
├── eyesieve_preflight.py         # phase 9
├── eyesieve_html_report.py       # phase 10 — dashboard
├── install.sh                    # later
└── run.sh                        # later
```

---

## Error code convention

All `eyesieve_*` failures prefix their messages with
`Internal Error Code: XD-MBYG04K-URS3LF` so they're greppable across logs.
