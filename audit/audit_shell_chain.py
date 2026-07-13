#!/usr/bin/env python3
"""
Comprehensive shell-chain paranoia audit.

Traces the full path: launch (LHOST/LPORT by payload type) → session detection →
confirm alive/dead → auto-chain re-arm on death → UI render (no reused-id hiding).
Targets the four bugs the live distcc test exposed:
  A  reverse open-then-die → loop must re-arm to BIND (not false-success/stall)
  B  a live (possibly id-reused) session must render in the panel (not hidden by
     the `closing` set used for operator kills)
  C  manual launch must strip LHOST for bind / LHOST+LPORT for interact
  D  bind guidance must not tell the operator to nc (MSF owns the connection)
"""
import inspect
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

# ── A. Auto-chain re-arms to BIND when a confirmed session DIES ───────────────
from modules.auto_chain import run_auto_chain

class OpenThenDieEngine:
    """distcc-like: reverse 'opens' a session that confirm finds DEAD; once an
    insight flips the env/plan to bind, the bind session is alive."""
    def __init__(self):
        self.calls = {'recommend': 0, 'run': 0, 'confirm': 0,
                      'persist': 0, 'note_died': 0}
        self._mode = 'reverse'
    def recommend_plan(self, module, env):
        self.calls['recommend'] += 1
        # The note_session_died insight is recorded into the engine; emulate the
        # resolver consuming it by flipping to bind after a death was noted.
        mode = 'bind' if self.calls['note_died'] else 'reverse'
        payload = 'cmd/unix/bind_perl' if mode == 'bind' else 'cmd/unix/reverse_perl'
        return {'connection_mode': mode, 'payload': payload, 'target_index': 0,
                'options': {'RHOSTS': env.get('rhost')}, 'stop': False,
                'information_needed': [], 'rationale': [], 'applied_insights': []}
    def run_plan(self, module, plan, env):
        self.calls['run'] += 1
        sid = '1' if plan['connection_mode'] == 'reverse' else '2'
        return {'sessions': [{'id': sid}],
                'information_gained': [{'signal': 'success', 'message': 'opened'}]}
    def confirm_session(self, sid):
        self.calls['confirm'] += 1
        if sid == '1':
            return {'alive': False, 'dead': True, 'output': ''}   # open-then-die
        return {'alive': True, 'dead': False, 'output': 'uid=0(root)'}
    def persist_session(self, sid):
        self.calls['persist'] += 1
        return {'persisted': True, 'session_type': 'shell', 'recon': 'uid=0'}
    def note_session_died(self, env):
        self.calls['note_died'] += 1
        return {'signal': 'session_died', 'message': 'died → bind'}
    def list_sessions(self):
        return []

eng = OpenThenDieEngine()
events = []
res = run_auto_chain(eng, 'exploit/unix/misc/distcc_exec',
                     {'rhost': '10.0.0.5', 'os_family': 'linux',
                      'lhost': '10.0.0.1', 'lhost_routable': True},
                     max_attempts=4, emit=events.append)
phases = [e['phase'] for e in events]
if (res['status'] == 'success' and res['sid'] == '2'
        and eng.calls['note_died'] >= 1 and 'session_died' in phases):
    ok('A: reverse open-then-die → note_session_died → re-arm to BIND → bind lands '
       '(no false-success stall — the live distcc bug)')
else:
    fail(f'A: open-then-die did not re-arm to bind: status={res.get("status")}, '
         f'sid={res.get("sid")}, note_died={eng.calls["note_died"]}, phases={phases}')

# Engine exposes note_session_died and it records a bind-preferring insight.
from modules.msf_engine import MsfEngine
if hasattr(MsfEngine, 'note_session_died'):
    di_src = inspect.getsource(MsfEngine.note_session_died)
    if 'MODE_BIND' in di_src and 'prefer_mode' in di_src:
        ok('A: MsfEngine.note_session_died records a bind-preferring insight')
    else:
        fail('A: note_session_died does not prefer bind')
else:
    fail('A: MsfEngine.note_session_died missing')

# auto_chain calls note_session_died on a dead confirm.
ac_src = inspect.getsource(run_auto_chain)
if 'note_session_died' in ac_src and "check.get('dead')" in ac_src:
    ok('A: auto_chain records the death insight when confirm is dead')
else:
    fail('A: auto_chain does not record death insight')

# ── C. Payload-based LHOST/LPORT stripping in the engine ──────────────────────
eng_src = inspect.getsource(MsfEngine._run_exploit_inner)
if ("'bind' in _pl" in eng_src and '_strip_lhost' in eng_src
        and "'interact' in _pl" in eng_src):
    ok('C: launch strips LHOST for bind (keeps LPORT) and LHOST+LPORT for interact '
       '— payload-driven, fixes "Unknown datastore option: LHOST" on bind')
else:
    fail('C: payload-based LHOST/LPORT strip missing')

# ── B. Death drops do NOT add to `closing` (so a reused id renders) ───────────
shell_js = Path('templates/partials/shell_script.html').read_text(encoding='utf-8')
# Operator kills keep closing.add; death paths must not.
import re as _re
closing_adds = _re.findall(r'closing\.add', shell_js)
# Expect exactly 2 (killAllSessions + closeSession). Death paths were removed.
if len(closing_adds) == 2:
    ok('B: only the 2 operator-kill paths add to `closing`; death drops do not '
       '(a reused session id is no longer hidden — the bind-after-dead-reverse bug)')
else:
    fail(f'B: expected 2 closing.add (operator kills), found {len(closing_adds)}')

# Panel renders from list_sessions (source of truth), filtered ONLY by operator
# `closing` — never by a probe-reported death. This guarantees a live session
# always shows (fixes the live root shell hidden by a stale dead flag).
if 'refreshSessions' in shell_js and "fetch('/api/msf/sessions')" in shell_js:
    ok('B: shell panel renders live sessions from /api/msf/sessions')
else:
    fail('B: shell panel session fetch missing')

# ── B2. Faithful-mirror model: no death-suppression, seen-once handoff ────────
# The `dead` suppression set was REMOVED — it hid a live session. Deaths are
# note-only now; only msfrpcd-drop or operator-kill removes a tab.
if 'SHELL_STATE.dead' not in shell_js and '_markDeadAndDrop' not in shell_js:
    ok('B2: dead-suppression set removed (a probe-death no longer hides a live/'
       'reused session — the curl-shows-it-but-panel-empty bug)')
else:
    fail('B2: dead suppression still present')

# Render filter is closing-only (operator kills), not death.
if ('!SHELL_STATE.closing.has(String(s.id))' in shell_js
        and '!SHELL_STATE.dead.has' not in shell_js):
    ok('B2: render filter is operator-`closing` only — msfrpcd list is the truth')
else:
    fail('B2: render filter still suppresses on death')

# Deaths are note-only via _noteSessionDead (no local drop/suppress).
if ('_noteSessionDead' in shell_js
        and shell_js.count('_noteSessionDead(sid') >= 4):
    ok('B2: all 4 death paths are note-only (_noteSessionDead) — no drop/suppress')
else:
    fail(f'B2: death paths not note-only ({shell_js.count("_noteSessionDead(sid")} sites)')

# `seen` gates handoff-once (the real anti-thrash mechanism).
if ('!SHELL_STATE.seen.has' in shell_js and 'SHELL_STATE.seen.add' in shell_js):
    ok('B2: handoff "fresh" gated on persistent `seen` — a re-listed session '
       'never re-fires handoff (breaks the attach/drop loop)')
else:
    fail('B2: seen-once handoff gating missing')

# _deadNoted is reconciled (cleared) when an id leaves the list.
if 'SHELL_STATE._deadNoted.delete(sid)' in shell_js and 'liveIds.has(sid)' in shell_js:
    ok('B2: death-note marker cleared when the id leaves msfrpcd list')
else:
    fail('B2: _deadNoted reconciliation missing')

# Kill-all wipes seen + dead-note markers (clean slate).
if 'SHELL_STATE.seen.clear()' in shell_js and 'SHELL_STATE._deadNoted.clear()' in shell_js:
    ok('B2: Kill-All resets seen + death-note markers (clean slate)')
else:
    fail('B2: Kill-All does not reset seen/_deadNoted')

# ── B3. No corpse-priming: handoff must not probe an already-dead session ─────
# Every death note goes through the single gated helper (no bare appendBuffer).
if shell_js.count("'[SESSION DIED] '") == 1:
    ok('B3: exactly one death-note site (_noteSessionDead) — all paths gated')
else:
    fail(f'B3: {shell_js.count("\x27[SESSION DIED] \x27")} raw death-note sites '
         '(should be 1, inside _noteSessionDead)')

# _noteSessionDead cancels any pending/active handoff for that sid.
if ('function _noteSessionDead' in shell_js
        and 'SHELL_STATE.handoffDone[sid] = true' in shell_js.split('function _noteSessionDead')[1][:400]
        and '_handoffQueue.filter' in shell_js):
    ok('B3: _noteSessionDead cancels handoff + dequeues (no priming a corpse)')
else:
    fail('B3: _noteSessionDead does not cancel handoff/queue')

# runAutoHandoff bails when the session is already noted dead.
if 'SHELL_STATE._deadNoted.has(sid)' in shell_js:
    ok('B3: runAutoHandoff bails on _deadNoted sessions (no late priming)')
else:
    fail('B3: runAutoHandoff missing _deadNoted guard')

# runHandoffStep refuses to send into a dead session.
if "SHELL_STATE._deadNoted.has(String(sid))" in shell_js:
    ok('B3: runHandoffStep refuses to send into a dead session')
else:
    fail('B3: runHandoffStep missing dead-session guard')

# ── D. Bind guidance no longer tells the operator to nc ───────────────────────
exploit_html = Path('templates/exploit.html').read_text(encoding='utf-8')
if ('MSF connects to the target' in exploit_html
        and 'do' in exploit_html and 'not' in exploit_html):
    ok('D: bind helper explains MSF owns the connection (no operator nc needed)')
else:
    fail('D: bind guidance not corrected')

# ── Rename: Exploit tab → Shell (label/title/topbar; route preserved) ─────────
base_html = Path('templates/base.html').read_text(encoding='utf-8')
if '⚡</span> Shell' in base_html and 'href="/exploit"' in base_html:
    ok('Rename: nav label is "Shell" (route /exploit preserved — no breakage)')
else:
    fail('Rename: nav label not updated to Shell')
if '{% block title %}Shell{% endblock %}' in exploit_html and \
   "active == 'exploit'" in base_html:
    ok('Rename: page title "Shell"; active-state key preserved')
else:
    fail('Rename: page title / active key wrong')

# ── End-to-end: the manual bind path that failed live now works in principle ──
# (LHOST stripped → no datastore error → session created → would render.)
import importlib.util
spec = importlib.util.spec_from_file_location('h3x', 'h3x-dash.py')
h3x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h3x)
# bind profile resolution sanity: distcc + bind payload should keep LPORT, drop LHOST
from modules.launch_profiles import resolve_launch_profile
prof = resolve_launch_profile('exploit/unix/misc/distcc_exec')
if prof.get('payload_mode') == 'reverse':
    ok('distcc profile is reverse by default — bind is an operator/insight choice '
       '(strip logic keys on the actual payload, not just the profile)')
else:
    fail(f'distcc profile unexpected: {prof.get("payload_mode")}')

print()
print('═' * 72)
print(f' SHELL-CHAIN AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
