#!/usr/bin/env python3
"""eyesieve_cli.py — phase 11: unified dispatcher.

A single entry point that delegates to the right module's ``main()`` based
on a subcommand. Lets users type ``eyesieve mp --theory union`` instead
of ``python3 -m eyesieve_mprunner --theory union``.

SUBCOMMANDS
===========
  run                single-process runner          (eyesieve_runner)
  mp                 multiprocess runner            (eyesieve_mprunner)
  report             HTML run report                (eyesieve_run_report)
  corpus-report      HTML corpus report             (eyesieve_html_report)
  reader             corpus content reader          (eyesieve_reader)
  selftest           run all known-answer tests     (eyesieve_selftest)
  preflight          pre-launch sanity sweep        (eyesieve_preflight)

The dispatcher forwards all remaining arguments to the chosen subcommand,
so ``eyesieve mp --help`` is equivalent to ``eyesieve_mprunner.py --help``.
"""

from __future__ import annotations
import importlib
import sys

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"

SUBCOMMANDS = {
    "run":            "eyesieve_runner",
    "mp":             "eyesieve_mprunner",
    "report":         "eyesieve_run_report",
    "corpus-report":  "eyesieve_html_report",
    "reader":         "eyesieve_reader",
    "selftest":       "eyesieve_selftest",
    "preflight":      "eyesieve_preflight",
}

USAGE = """\
EyeSieve unified CLI

usage: eyesieve <subcommand> [args...]

subcommands:
  run            single-process runner
  mp             multiprocess runner with checkpointing
  report         render HTML run report from a runner output dir
  corpus-report  render HTML corpus report from a JSON corpus
  reader         pretty-print corpus content in various views
  selftest       run all 192 known-answer tests
  preflight      run pre-launch sanity sweep

Use 'eyesieve <subcommand> --help' to see subcommand-specific options.
"""


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0

    subcmd = argv[0]
    if subcmd not in SUBCOMMANDS:
        print(f"{ERROR_PREFIX} :: cli :: unknown subcommand: {subcmd!r}",
              file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    module_name = SUBCOMMANDS[subcmd]
    try:
        mod = importlib.import_module(module_name)
    except ImportError as e:
        print(f"{ERROR_PREFIX} :: cli :: failed to import {module_name}: {e}",
              file=sys.stderr)
        return 2

    if not hasattr(mod, "main"):
        print(f"{ERROR_PREFIX} :: cli :: {module_name} has no main()",
              file=sys.stderr)
        return 2

    # Forward remaining args. Some main() functions don't take argv
    # (e.g. eyesieve_selftest.main()). Probe and adapt.
    import inspect
    sig = inspect.signature(mod.main)
    forwarded = argv[1:]
    if len(sig.parameters) == 0:
        if forwarded:
            print(f"{ERROR_PREFIX} :: cli :: {subcmd} subcommand "
                  f"takes no arguments; ignoring: {forwarded}",
                  file=sys.stderr)
        return mod.main()
    return mod.main(forwarded)


if __name__ == "__main__":
    sys.exit(main())
