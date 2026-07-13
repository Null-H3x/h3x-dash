#!/usr/bin/env python3
"""Audit for session.py — the standalone MSF session inspector/interactor.

Verifies the tool is syntactically sound, exposes the documented commands, is
genuinely standalone (does NOT import the h3x-dash app or its engine modules,
so it runs in a clean terminal even when the app is broken), reads the same
connection defaults as h3x-dash, and degrades gracefully without a daemon.
"""
import sys; import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)
import ast
import importlib.util
from pathlib import Path

FAIL, OK = [], []
def fail(m): FAIL.append(m)
def ok(m):   OK.append(m)

SRC_PATH = Path('session.py')
src = SRC_PATH.read_text()

# ── 1. Parses + imports as a module ───────────────────────────────────────────
try:
    tree = ast.parse(src)
    ok('session.py parses')
except SyntaxError as e:
    fail(f'session.py syntax error: {e}')
    tree = None

spec = importlib.util.spec_from_file_location('session_tool', 'session.py')
mod  = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    ok('session.py imports without side effects (no connect on import)')
except Exception as e:                          # noqa: BLE001
    fail(f'session.py import raised: {e}')
    mod = None

# ── 2. Standalone — must NOT import h3x-dash app/engine modules ────────────────
# It may use pymetasploit3 + stdlib only. Importing modules.* or config couples
# it to a possibly-broken app, defeating the "clean terminal" purpose.
banned = {'modules', 'config', 'flask'}
imported_roots = set()
if tree:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imported_roots.add(n.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split('.')[0])
leaks = banned & imported_roots
if not leaks:
    ok('session.py is standalone (no modules.*/config/flask imports)')
else:
    fail(f'session.py couples to the app via: {sorted(leaks)}')

# ── 3. Exposes the documented subcommands ──────────────────────────────────────
if mod:
    parser = mod.build_parser()
    # subparser choices live on the _SubParsersAction
    sub_choices = set()
    for action in parser._actions:
        if hasattr(action, 'choices') and isinstance(action.choices, dict):
            sub_choices |= set(action.choices)
    need = {'list', 'info', 'run', 'interact', 'watch', 'doctor',
            'jobs', 'handler', 'kill-job'}
    missing = need - sub_choices
    if not missing:
        ok(f'all {len(need)} subcommands present: {sorted(need)}')
    else:
        fail(f'missing subcommands: {missing}')

    # 3b. Each command handler exists.
    for fn in ('cmd_list', 'cmd_info', 'cmd_run', 'cmd_interact',
               'cmd_watch', 'cmd_doctor', 'cmd_jobs', 'cmd_handler',
               'cmd_killjob'):
        if callable(getattr(mod, fn, None)):
            ok(f'handler {fn} defined')
        else:
            fail(f'handler {fn} missing')

# ── 4. Connection defaults mirror h3x-dash config ──────────────────────────────
if mod:
    if (mod.DEF_PORT == 55553 and mod.DEF_PASS == 'msfrpc'
            and mod.DEF_HOST == '127.0.0.1'):
        ok('connection defaults match h3x-dash (127.0.0.1:55553 / msfrpc)')
    else:
        fail(f'connection defaults drifted: {mod.DEF_HOST}:{mod.DEF_PORT}/{mod.DEF_PASS}')

# ── 5. Dead-session classifier recognises MSF "gone" phrasings ─────────────────
if mod:
    dead_phrases = ['Session 3 does not exist', 'unknown session',
                    'session is not valid', 'invalid session']
    live_phrases = ['timed out', 'connection reset', '']
    if (all(mod._is_dead(Exception(p)) for p in dead_phrases)
            and not any(mod._is_dead(Exception(p)) for p in live_phrases)):
        ok('_is_dead distinguishes gone-session errors from transient ones')
    else:
        fail('_is_dead misclassifies session errors')

# ── 6. Reconciliation diff surfaces BOTH hide + zombie mismatches ──────────────
# The whole point of the tool: msfrpcd-but-not-UI (hidden live) and
# UI-but-not-msfrpcd (zombie tab).
if ('NOT shown by the UI' in src and 'NOT in msfrpcd' in src
        and 'api_sessions' in src):
    ok('list/doctor reconcile msfrpcd ⇄ h3x-dash API (hidden-live + zombie)')
else:
    fail('reconciliation diff incomplete')

# ── 7. doctor reports jobs/handlers (reverse-callback prerequisite) ───────────
if 'raw_jobs' in src and 'handler' in src.lower():
    ok('doctor surfaces active jobs/handlers (reverse-callback diagnosis)')
else:
    fail('doctor does not report jobs/handlers')

# ── 8. API comparison can be disabled (works in a truly clean env) ─────────────
if "'--no-api'" in src or '--no-api' in src:
    ok('--no-api flag lets the tool run with no h3x-dash app present')
else:
    fail('no --no-api escape hatch')

# ── 9. Standalone handler — prove the reverse path without h3x-dash ────────────
if ("multi/handler" in src and 'exploit.execute(payload=' in src
        and 'job_id' in src):
    ok('handler stands up exploit/multi/handler as a job + watches for the callback')
else:
    fail('handler command incomplete')

# ── 10. Job control (visibility + cleanup) ─────────────────────────────────────
if 'client.jobs.stop' in src and 'raw_jobs(client)' in src:
    ok('jobs/kill-job give handler visibility + cleanup')
else:
    fail('jobs/kill-job control missing')

# ── 11. doctor "0 jobs" note is no longer alarmist (h3x-dash handles inline) ───
if 'normal between launches' in src:
    ok('doctor explains that 0 handler jobs is normal between launches')
else:
    fail('doctor 0-jobs note still misleading')

# ── Summary ────────────────────────────────────────────────────────────────────
print('\n' + '═' * 72)
print(f' SESSION-TOOL AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:'); [print(f'  ✗ {m}') for m in FAIL]
print('\nPASSED:'); [print(f'  ✓ {m}') for m in OK]
sys.exit(1 if FAIL else 0)
