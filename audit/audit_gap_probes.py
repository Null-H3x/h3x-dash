#!/usr/bin/env python3
"""Offline audit — active information-gap scanning between exploit attempts."""
import sys
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.gap_probes import (
    probe_plan_for, interpret_probes, dominant_signal,
    PROBE_ROUTE, PROBE_LPORT_FREE, PROBE_RPORT_OPEN, PROBE_COMPAT, PROBE_FINGERPRINT,
)

# ── 1. Probe plans are tailored to the failure signal ─────────────────────────
if (PROBE_ROUTE in probe_plan_for('reverse_no_session')
        and PROBE_RPORT_OPEN in probe_plan_for('reverse_no_session')):
    ok('reverse_no_session → route + handler-port + target-port probes')
else:
    fail(f'reverse plan wrong: {probe_plan_for("reverse_no_session")}')

if probe_plan_for('unreachable') == [PROBE_RPORT_OPEN]:
    ok('unreachable → target-port probe only')
else:
    fail(f'unreachable plan wrong: {probe_plan_for("unreachable")}')

if probe_plan_for('payload_incompatible') == [PROBE_COMPAT]:
    ok('payload_incompatible → compatible-payload refresh')
else:
    fail(f'payload_incompat plan wrong: {probe_plan_for("payload_incompatible")}')

# Conclusive signals get no probe (can't help).
if probe_plan_for('not_vulnerable') == [] and probe_plan_for('success') == []:
    ok('Conclusive signals (not_vulnerable/success) → no probe (scan would not help)')
else:
    fail('conclusive signals should not probe')

# ── 2. interpret: route-down → bind re-arm + fact ─────────────────────────────
r = interpret_probes('reverse_no_session', {
    PROBE_ROUTE: {'routable': False}, PROBE_RPORT_OPEN: {'open': True}})
if (r['facts'].get('lhost_routable') is False
        and any(i['rearm'].get('prefer_mode') == 'bind' for i in r['insights'])
        and r['produced_new_info']):
    ok('Gap scan: LHOST not routable → fact + insight to prefer BIND')
else:
    fail(f'route-down interpret wrong: {r}')

# ── 3. interpret: target port closed → unreachable insight + fact ─────────────
r = interpret_probes('unreachable', {PROBE_RPORT_OPEN: {'open': False}})
if (r['facts'].get('rport_open') is False
        and any(i['signal'] == 'unreachable' for i in r['insights'])):
    ok('Gap scan: target port closed → rport_open=False + unreachable insight')
else:
    fail(f'port-closed interpret wrong: {r}')

# ── 4. interpret: compat refresh exposes facts ────────────────────────────────
r = interpret_probes('payload_incompatible',
                     {PROBE_COMPAT: {'payloads': ['cmd/unix/reverse_perl', 'cmd/unix/bind_perl']}})
if r['facts'].get('compatible_payloads') == ['cmd/unix/reverse_perl', 'cmd/unix/bind_perl']:
    ok('Gap scan: compatible-payload refresh surfaces the live list as a fact')
else:
    fail(f'compat interpret wrong: {r}')

# ── 5. interpret: fingerprint refines OS → wrong_target insight ───────────────
r = interpret_probes('wrong_target', {PROBE_FINGERPRINT: {'os_family': 'linux',
                     'service': 'ssh', 'version': 'OpenSSH 4.7'}})
if (r['facts'].get('os_family') == 'linux'
        and any(i['signal'] == 'wrong_target' for i in r['insights'])):
    ok('Gap scan: re-fingerprint refines OS/service → fact + re-target insight')
else:
    fail(f'fingerprint interpret wrong: {r}')

# ── 6. interpret: nothing learned → produced_new_info False ───────────────────
r = interpret_probes('inconclusive', {})
if r['produced_new_info'] is False:
    ok('Gap scan with no probe results → produced_new_info=False (honest)')
else:
    fail('empty gap scan wrongly claims new info')

# ── 7. dominant_signal prioritizes the actionable one ─────────────────────────
ins = [{'signal': 'inconclusive'}, {'signal': 'reverse_no_session'}]
if dominant_signal(ins) == 'reverse_no_session':
    ok('dominant_signal picks the most actionable signal for probing')
else:
    fail(f'dominant_signal wrong: {dominant_signal(ins)}')

# ── 8. END-TO-END: gap scan turns a stuck loop into a productive re-arm ───────
# A reverse attempt fails with NO actionable run-insight; without gap scanning
# the resolver would re-recommend reverse → dedupe-exhaust. With the gap scan
# discovering the route is down, the env flips to bind and a bind attempt lands.
from modules.auto_chain import run_auto_chain

class GapEngine:
    """Resolver-faithful mock: chooses reverse while routable, bind once the
    gap scan sets lhost_routable=False in the environment."""
    def __init__(self):
        self.calls = {'recommend': 0, 'run': 0, 'gap': 0, 'confirm': 0, 'persist': 0}
    def recommend_plan(self, module, env):
        self.calls['recommend'] += 1
        mode = 'bind' if env.get('lhost_routable') is False else 'reverse'
        payload = 'cmd/unix/bind_perl' if mode == 'bind' else 'cmd/unix/reverse_perl'
        return {'connection_mode': mode, 'payload': payload, 'target_index': 0,
                'options': {'RHOSTS': env.get('rhost')}, 'stop': False,
                'information_needed': [], 'rationale': [], 'applied_insights': []}
    def run_plan(self, module, plan, env):
        self.calls['run'] += 1
        if plan['connection_mode'] == 'reverse':
            # reverse never calls back, NO actionable run-insight on its own
            return {'exploit_failed': True, 'information_gained':
                    [{'signal': 'reverse_no_session', 'message': 'no callback'}]}
        return {'sessions': [{'id': '9'}], 'information_gained': []}
    def confirm_session(self, sid):
        self.calls['confirm'] += 1
        return {'alive': True, 'dead': False, 'output': 'uid=0(root)'}
    def persist_session(self, sid):
        self.calls['persist'] += 1
        return {'persisted': True, 'session_type': 'shell', 'recon': 'uid=0'}
    def list_sessions(self):
        return []
    def gather_gap_information(self, signal, env):
        # The "tailored scan": discover the route is down → re-arm to bind.
        self.calls['gap'] += 1
        return {'facts': {'lhost_routable': False}, 'insights': [],
                'summary': 'gap scan: LHOST not routable → bind',
                'produced_new_info': True}

eng = GapEngine()
events = []
res = run_auto_chain(eng, 'exploit/unix/misc/distcc_exec',
                     {'rhost': '10.0.0.5', 'os_family': 'linux',
                      'lhost': '10.0.0.1', 'lhost_routable': True},
                     max_attempts=4, emit=events.append)
phases = [e['phase'] for e in events]
if (res['status'] == 'success' and res['sid'] == '9'
        and eng.calls['gap'] >= 1 and 'gap_scan' in phases):
    ok('END-TO-END: reverse-fail → GAP SCAN (route down) → env flips to bind → '
       'bind lands. Active info acquisition rescued a stuck loop.')
else:
    fail(f'gap-scan end-to-end failed: status={res.get("status")}, '
         f'gap_calls={eng.calls["gap"]}, phases={phases}')

# ── 9. Without gap scanning, the same stuck loop would exhaust (control) ───────
class NoGapEngine(GapEngine):
    # Explicitly None so getattr(engine, 'gather_gap_information', None) is falsy
    # → the orchestrator skips active scanning entirely.
    gather_gap_information = None
eng2 = NoGapEngine()
res2 = run_auto_chain(eng2, 'm', {'rhost': '10.0.0.5', 'os_family': 'linux',
                                  'lhost': '10.0.0.1', 'lhost_routable': True},
                      max_attempts=4, emit=lambda e: None)
if res2['status'] == 'exhausted':
    ok('CONTROL: without gap scanning the same loop exhausts — proves the gap '
       'scan is what makes re-arming productive')
else:
    fail(f'control case unexpectedly succeeded without gap scan: {res2}')

# ── 10. Engine + wiring ───────────────────────────────────────────────────────
from modules.msf_engine import MsfEngine
if hasattr(MsfEngine, 'gather_gap_information'):
    ok('MsfEngine.gather_gap_information() present')
else:
    fail('MsfEngine missing gather_gap_information')

import inspect
src = inspect.getsource(run_auto_chain)
if 'gather_gap_information' in src and 'gap_scan' in src:
    ok('auto_chain runs the gap scan + emits gap_scan events')
else:
    fail('auto_chain not wired to gap scanning')

html = Path('templates/exploit.html').read_text(encoding='utf-8')
if "gap_scan" in html and 'gap-scan' in html:
    ok('exploit.html renders gap_scan events')
else:
    fail('exploit.html missing gap_scan rendering')

print()
print('═' * 72)
print(f' GAP-PROBE AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
