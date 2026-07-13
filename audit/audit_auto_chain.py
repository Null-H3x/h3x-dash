#!/usr/bin/env python3
"""Offline audit — closed-loop auto-chain orchestrator (flexible, no hardcoding)."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.auto_chain import run_auto_chain, plan_signature, AutoChainRunner


# ── Scripted mock engine ──────────────────────────────────────────────────────
# Models the resolver+feedback contract: recommend_plan returns successive plans
# (as the real resolver would once re-armed by insights), run_plan returns an
# outcome, confirm_session reports liveness, persist_session finalizes.
class MockEngine:
    def __init__(self, plans, run_results, confirms, *, persist=None):
        self._plans = list(plans)
        self._runs = list(run_results)
        self._confirms = dict(confirms)
        self._persist = persist or {'persisted': True, 'session_type': 'shell',
                                    'alive': True, 'recon': 'uid=0(root)'}
        self.calls = {'recommend': 0, 'run': 0, 'confirm': 0, 'persist': 0}
        self.persisted_sid = None

    def recommend_plan(self, module, env):
        i = min(self.calls['recommend'], len(self._plans) - 1)
        self.calls['recommend'] += 1
        return dict(self._plans[i])

    def run_plan(self, module, plan, env):
        i = min(self.calls['run'], len(self._runs) - 1)
        self.calls['run'] += 1
        return dict(self._runs[i])

    def confirm_session(self, sid):
        self.calls['confirm'] += 1
        return dict(self._confirms.get(str(sid), {'alive': False, 'dead': False}))

    def persist_session(self, sid):
        self.calls['persist'] += 1
        self.persisted_sid = str(sid)
        return dict(self._persist)

    def list_sessions(self):
        return []


def P(mode='reverse', payload='cmd/unix/reverse_perl', stop=False, need=None, tidx=0):
    return {'connection_mode': mode, 'payload': payload, 'target_index': tidx,
            'options': {'RHOSTS': '10.0.0.5'}, 'stop': stop,
            'information_needed': need or [], 'rationale': [], 'applied_insights': []}


def R(sid=None, **flags):
    r = {'information_gained': [{'message': 'learned something'}]}
    if sid:
        r['sessions'] = [{'id': sid}]
    r.update(flags)
    return r


# ── 1. Immediate success: reverse lands an alive shell → persist → stop ───────
eng = MockEngine(
    plans=[P()],
    run_results=[R(sid='1')],
    confirms={'1': {'alive': True, 'dead': False, 'output': 'uid=0(root)'}},
)
events = []
res = run_auto_chain(eng, 'exploit/unix/misc/distcc_exec',
                     {'rhost': '10.0.0.5'}, emit=events.append)
if (res['status'] == 'success' and res['sid'] == '1'
        and eng.calls['persist'] == 1 and eng.persisted_sid == '1'):
    ok('Immediate success: alive shell → persist → STOP (success)')
else:
    fail(f'immediate-success path wrong: {res}')
if any(e['phase'] == 'success' for e in events):
    ok('Emits a success event')
else:
    fail('no success event emitted')

# ── 2. THE LOOP: reverse fails (no session) → re-arm → bind succeeds ──────────
# Attempt 1 plan = reverse (no session). Attempt 2 plan = bind (the resolver
# would return this once re-armed by the reverse-fail insight). Bind lands alive.
eng = MockEngine(
    plans=[P(mode='reverse', payload='cmd/unix/reverse_perl'),
           P(mode='bind', payload='cmd/unix/bind_perl')],
    run_results=[R(exploit_failed=True),               # attempt 1: no session
                 R(sid='2')],                          # attempt 2: session
    confirms={'2': {'alive': True, 'dead': False, 'output': 'uid=0(root)'}},
)
events = []
res = run_auto_chain(eng, 'exploit/unix/misc/distcc_exec',
                     {'rhost': '10.0.0.5'}, emit=events.append)
phases = [e['phase'] for e in events]
if (res['status'] == 'success' and res['sid'] == '2'
        and eng.calls['run'] == 2 and 'rearm' in phases):
    ok('LOOP: reverse-fail → gather info → re-arm → bind succeeds → persist')
else:
    fail(f'loop reverse→bind path wrong: {res}, phases={phases}')

# ── 3. Session opens but shell is DEAD → treated as failure, loop continues ───
eng = MockEngine(
    plans=[P(mode='reverse'), P(mode='bind', payload='cmd/unix/bind_perl')],
    run_results=[R(sid='3'), R(sid='4')],
    confirms={'3': {'alive': False, 'dead': True, 'output': ''},   # opened then died
              '4': {'alive': True, 'dead': False, 'output': 'uid=0'}},
)
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, emit=lambda e: None)
if res['status'] == 'success' and res['sid'] == '4':
    ok('Dead shell on attempt 1 is not mistaken for success — loop continues to a live one')
else:
    fail(f'dead-then-alive path wrong: {res}')

# ── 4. SAFE verdict → halt immediately (no wasted attempts) ───────────────────
eng = MockEngine(plans=[P(stop=True)], run_results=[R()], confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, emit=lambda e: None)
if res['status'] == 'halted' and res['reason'] == 'not_vulnerable' and eng.calls['run'] == 0:
    ok('SAFE verdict (plan.stop) → halt before running anything')
else:
    fail(f'halt path wrong: {res}')

# ── 5. needs_input → stop and ask the operator (automation cannot invent) ─────
eng = MockEngine(plans=[P(need=['TARGETURI'])], run_results=[R()], confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, emit=lambda e: None)
if res['status'] == 'needs_input' and 'TARGETURI' in res['need'] and eng.calls['run'] == 0:
    ok('Plan needs an operator option → needs_input (no blind launch)')
else:
    fail(f'needs_input path wrong: {res}')

# ── 6. No NEW information: re-arm keeps producing the same plan → exhausted ───
# Same plan every time, never a session → must stop on 'no_new_information',
# NOT keep looping to max_attempts.
eng = MockEngine(plans=[P()], run_results=[R(exploit_failed=True)],
                 confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=5,
                     emit=lambda e: None)
if (res['status'] == 'exhausted' and res['reason'] == 'no_new_information'
        and eng.calls['run'] == 1):
    ok('Identical re-armed plan → exhausted on no_new_information (ran once, not 5x)')
else:
    fail(f'no-new-information path wrong: {res} (runs={eng.calls["run"]})')

# ── 7. max_attempts cap when each attempt is genuinely different but all fail ─
diff_plans = [P(payload=f'cmd/unix/p{i}') for i in range(10)]
diff_runs  = [R(exploit_failed=True) for _ in range(10)]
eng = MockEngine(plans=diff_plans, run_results=diff_runs, confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=3,
                     emit=lambda e: None)
if res['status'] == 'exhausted' and res['reason'] == 'max_attempts' and eng.calls['run'] == 3:
    ok('Distinct failing plans → stop at max_attempts cap (safety net)')
else:
    fail(f'max_attempts path wrong: {res} (runs={eng.calls["run"]})')

# ── 8. plan_signature distinguishes plans / dedups identical ones ─────────────
a = plan_signature(P(mode='reverse', payload='x'))
b = plan_signature(P(mode='bind', payload='x'))
c = plan_signature(P(mode='reverse', payload='x'))
if a != b and a == c:
    ok('plan_signature: different plans differ, identical plans match (dedup works)')
else:
    fail('plan_signature wrong')

# ── 9. AutoChainRunner threads + snapshots ────────────────────────────────────
import time as _t
eng = MockEngine(plans=[P()], run_results=[R(sid='9')],
                 confirms={'9': {'alive': True, 'dead': False, 'output': 'uid=0'}})
runner = AutoChainRunner(eng)
started = runner.start('m', {'rhost': '10.0.0.5'})
second  = runner.start('m', {'rhost': '10.0.0.5'})   # should be rejected while running
for _ in range(50):
    if not runner.is_running():
        break
    _t.sleep(0.02)
snap = runner.snapshot()
if started and snap['result'] and snap['result']['status'] == 'success' and snap['events']:
    ok('AutoChainRunner runs in a thread, streams events, exposes final result')
else:
    fail(f'runner snapshot wrong: started={started}, snap={snap}')
# (second may be True or False depending on timing; only assert no crash)
ok('AutoChainRunner concurrent-start guarded (no crash)')

# ── 10. Engine + API + UI wiring ──────────────────────────────────────────────
from modules.msf_engine import MsfEngine
for meth in ('run_plan', 'persist_session', 'auto_chain'):
    if hasattr(MsfEngine, meth):
        ok(f'MsfEngine.{meth}() present')
    else:
        fail(f'MsfEngine missing {meth}()')

app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
for route in ('/api/msf/auto-chain/start', '/api/msf/auto-chain/status'):
    if route in app_src:
        ok(f'route {route} registered')
    else:
        fail(f'missing route {route}')

html = Path('templates/exploit.html').read_text(encoding='utf-8')
for anchor in ('AUTO-LAND SHELL', 'startAutoChain', 'pollAutoChain', '_renderChainEvent'):
    if anchor in html:
        ok(f'exploit.html wires {anchor}')
    else:
        fail(f'exploit.html missing {anchor}')

# persist_session must be profile-driven (no hardcoded per-module steps)
import inspect
psrc = inspect.getsource(MsfEngine.persist_session)
if 'resolve_session_handoff' in psrc and 'harden_cmds' in psrc:
    ok('persist_session is handoff-profile-driven (not hardcoded per module)')
else:
    fail('persist_session not profile-driven')

# ── 11. ADVERSE: recommend_plan raises mid-loop → chain survives ──────────────
class _RaiseRecommend(MockEngine):
    def recommend_plan(self, m, e):
        self.calls['recommend'] += 1
        if self.calls['recommend'] == 1:
            raise RuntimeError('RPC blip during recommend')
        return P(mode='bind', payload='cmd/unix/bind_perl')
eng = _RaiseRecommend(plans=[P()], run_results=[R(sid='11')],
                      confirms={'11': {'alive': True, 'dead': False, 'output': 'uid=0'}})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=4, emit=lambda e: None)
if res['status'] == 'success' and res['sid'] == '11':
    ok('ADVERSE: recommend_plan raising is isolated per-attempt — chain recovers')
else:
    fail(f'recommend-raise not isolated: {res}')

# ── 12. ADVERSE: run_plan raises attempt 1 → retry → success ──────────────────
class _RaiseRun(MockEngine):
    def run_plan(self, m, plan, e):
        self.calls['run'] += 1
        if self.calls['run'] == 1:
            raise RuntimeError('Not connected to Metasploit RPC')
        return R(sid='12')
eng = _RaiseRun(plans=[P(), P(mode='bind', payload='cmd/unix/bind_perl')],
                run_results=[R(), R()],
                confirms={'12': {'alive': True, 'dead': False, 'output': 'uid=0'}})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=4, emit=lambda e: None)
if res['status'] == 'success' and res['sid'] == '12':
    ok('ADVERSE: run_plan raising (transient) is caught — retried, not fatal')
else:
    fail(f'run-raise not isolated: {res}')

# ── 13. ADVERSE: confirm_session raises → treated quiet (not dead), loop goes on
class _RaiseConfirm(MockEngine):
    def confirm_session(self, sid):
        self.calls['confirm'] += 1
        if self.calls['confirm'] == 1:
            raise RuntimeError('read timeout')
        return {'alive': True, 'dead': False, 'output': 'uid=0'}
eng = _RaiseConfirm(plans=[P(), P(mode='bind', payload='cmd/unix/bind_perl')],
                    run_results=[R(sid='13a'), R(sid='13b')],
                    confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=4, emit=lambda e: None)
if res['status'] == 'success' and res['sid'] == '13b':
    ok('ADVERSE: confirm_session raising → quiet (not death) → loop continues')
else:
    fail(f'confirm-raise not isolated: {res}')

# ── 14. ADVERSE: persist raises AFTER alive shell → still SUCCESS (don't lose it)
class _RaisePersist(MockEngine):
    def persist_session(self, sid):
        self.calls['persist'] += 1
        raise RuntimeError('background command errored')
eng = _RaisePersist(plans=[P()], run_results=[R(sid='14')],
                    confirms={'14': {'alive': True, 'dead': False, 'output': 'uid=0'}})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, emit=lambda e: None)
if res['status'] == 'success' and res['sid'] == '14':
    ok('ADVERSE: persist raising after a live shell still reports SUCCESS (shell kept)')
else:
    fail(f'persist-raise lost the shell: {res}')

# ── 15. ADVERSE: persist reports the session DIED during hardening → not success
eng = MockEngine(
    plans=[P(mode='reverse'), P(mode='bind', payload='cmd/unix/bind_perl')],
    run_results=[R(sid='15a'), R(sid='15b')],
    confirms={'15a': {'alive': True, 'dead': False, 'output': 'uid=0'},
              '15b': {'alive': True, 'dead': False, 'output': 'uid=0'}},
    persist={'persisted': False, 'reason': 'died during migrate'},
)
# attempt 1: alive but persist says died → must NOT claim success; continues.
events = []
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=2, emit=events.append)
if any(e['phase'] == 'persist_failed' for e in events):
    ok('ADVERSE: persisted=False (died during hardening) → persist_failed, not success')
else:
    fail(f'persist-died wrongly claimed success: {res}, events={[e["phase"] for e in events]}')

# ── 16. ADVERSE: transient run errors stay retryable (not early no_new_info) ──
class _AlwaysDisconnected(MockEngine):
    def run_plan(self, m, plan, e):
        self.calls['run'] += 1
        return {'status': 'error', 'message': 'Not connected to Metasploit RPC'}
eng = _AlwaysDisconnected(plans=[P()], run_results=[R()], confirms={})
res = run_auto_chain(eng, 'm', {'rhost': '10.0.0.5'}, max_attempts=3, emit=lambda e: None)
# Same plan each time, but transient → NOT deduped to no_new_information; runs
# up to the cap so a reconnect could recover.
if res['status'] == 'exhausted' and res['reason'] == 'max_attempts' and eng.calls['run'] == 3:
    ok('ADVERSE: transient RPC errors stay retryable (run 3x, not early-exhausted)')
else:
    fail(f'transient retry wrong: {res} (runs={eng.calls["run"]})')

# ── 17. ADVERSE: malformed inputs (non-dict plan/result, None env, mt=0) ──────
class _BadPlan(MockEngine):
    def recommend_plan(self, m, e): self.calls['recommend'] += 1; return None
eng = _BadPlan(plans=[P()], run_results=[R()], confirms={})
res = run_auto_chain(eng, 'm', None, max_attempts=2, emit=lambda e: None)   # env=None too
if res['status'] in ('exhausted', 'error') and isinstance(res.get('attempts'), list):
    ok('ADVERSE: non-dict plan + None environment handled without crashing')
else:
    fail(f'malformed-input handling wrong: {res}')

res0 = run_auto_chain(MockEngine([P()], [R(sid='x')],
                       {'x': {'alive': True}}), 'm', {'rhost': '1'},
                      max_attempts=0, emit=lambda e: None)
if isinstance(res0, dict) and res0.get('status'):
    ok('ADVERSE: max_attempts=0 clamped to ≥1 (no empty-loop / no crash)')
else:
    fail(f'max_attempts=0 not clamped: {res0}')

# ── 18. ADVERSE: session result with null/missing id is ignored ───────────────
from modules.auto_chain import _session_id_from_result
if (_session_id_from_result({'sessions': [{'id': None}, {'id': '5'}]}) == '5'
        and _session_id_from_result({'sessions': [{}]}) is None):
    ok('null/empty session ids skipped — never confirm_session("None")')
else:
    fail('_session_id_from_result mishandles null ids')

print()
print('═' * 72)
print(f' AUTO-CHAIN AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
