"""
gap_probes.py — Active information acquisition between exploit attempts.

The auto-chain learns *passively* from each run's output (analyze_outcome). But
when a run fails with no actionable detail, there's no new information and the
loop would dedupe-exhaust. This module makes the loop learn *actively*: given
the dominant failure signal, it decides which targeted probes to run, and
interprets their results into (facts, insights) that re-arm the NEXT attempt.

It is deliberately split into:
  • PURE logic here — probe_plan_for(signal) and interpret_probes(signal, results)
    decide what to probe and what the results MEAN. No I/O → fully unit-testable.
  • The actual probes (route check, port connect, compatible-payload refresh,
    service fingerprint) live in MsfEngine.gather_gap_information(), which calls
    these functions to plan and interpret.

`facts` are merged into the resolver environment (so the next recommend_plan
adapts — e.g. lhost_routable=False → bind). `insights` are recorded like run
insights so recommend_plan re-arms on them too.
"""
from __future__ import annotations

from typing import Any

# Probe identifiers.
PROBE_ROUTE       = 'route'        # does LHOST route to the target?
PROBE_LPORT_FREE  = 'lport_free'   # is the handler port free on LHOST?
PROBE_RPORT_OPEN  = 'rport_open'   # is the target service port reachable?
PROBE_COMPAT      = 'compat'       # refresh the module's compatible payloads
PROBE_FINGERPRINT = 'fingerprint'  # re-fingerprint the service/version/OS

# Map a failure signal → the tailored probes worth running for it. This is the
# "tailored scan for the information gap" the operator asked for.
_PROBE_PLANS: dict[str, list[str]] = {
    'reverse_no_session':  [PROBE_ROUTE, PROBE_LPORT_FREE, PROBE_RPORT_OPEN],
    'session_died':        [PROBE_ROUTE, PROBE_RPORT_OPEN],
    'unreachable':         [PROBE_RPORT_OPEN],
    'payload_incompatible':[PROBE_COMPAT],
    'wrong_target':        [PROBE_FINGERPRINT],
    'no_check':            [PROBE_RPORT_OPEN, PROBE_FINGERPRINT],
    'inconclusive':        [PROBE_RPORT_OPEN, PROBE_ROUTE, PROBE_FINGERPRINT],
}

# Signals where probing can't help (verdict is conclusive) — skip the scan.
_NO_PROBE_SIGNALS = {'not_vulnerable', 'success', 'missing_required',
                     'single_shot_consumed', 'unknown_option'}


def probe_plan_for(signal: str | None) -> list[str]:
    """Return the ordered probe ids to run for a failure signal (may be empty)."""
    if not signal or signal in _NO_PROBE_SIGNALS:
        return []
    return list(_PROBE_PLANS.get(signal, [PROBE_RPORT_OPEN, PROBE_ROUTE]))


def _insight(signal, detail, message, **rearm):
    base = {'exclude_payloads': [], 'exclude_options': [], 'prefer_mode': None,
            'try_target_index': None, 'need_options': [], 'escalate_migrate': False,
            'retrigger': False, 'stop': False}
    base.update(rearm)
    return {'signal': signal, 'detail': detail, 'message': message,
            'rearm': base, 'source': 'gap_probe'}


def interpret_probes(signal: str, results: dict[str, Any]) -> dict[str, Any]:
    """
    Turn raw probe results into {facts, insights, summary}.

    results may contain:
      route:       {'routable': bool|None}
      lport_free:  {'free': bool|None}
      rport_open:  {'open': bool|None}
      compat:      {'payloads': [..]}        (refreshed compatible list)
      fingerprint: {'service': str, 'version': str, 'os_family': str}
    """
    results = results or {}
    facts: dict[str, Any] = {}
    insights: list[dict] = []
    notes: list[str] = []

    # ── Reachability of the target service port ──────────────────────────────
    rp = results.get(PROBE_RPORT_OPEN) or {}
    if rp.get('open') is not None:
        facts['rport_open'] = bool(rp['open'])
        if rp['open'] is False:
            notes.append('target service port is CLOSED/filtered')
            insights.append(_insight(
                'unreachable',
                'gap scan: target service port not reachable',
                'Gap scan: the target service port is closed/filtered — verify '
                'RPORT or that the service is up before retrying.'))
        else:
            notes.append('target service port is OPEN')

    # ── Reverse-callback feasibility (route + handler port) ──────────────────
    route = results.get(PROBE_ROUTE) or {}
    lport = results.get(PROBE_LPORT_FREE) or {}
    if route.get('routable') is not None:
        facts['lhost_routable'] = bool(route['routable'])
    if lport.get('free') is not None:
        facts['lport_free'] = bool(lport['free'])

    if route.get('routable') is False:
        notes.append('LHOST does not route to target')
        insights.append(_insight(
            'reverse_no_session',
            'gap scan: LHOST has no route to the target',
            'Gap scan: LHOST does not route to the target (NAT/segmented) — '
            're-arming to a BIND payload (MSF connects out to the target).',
            prefer_mode='bind'))
    elif lport.get('free') is False:
        notes.append('handler LPORT already in use')
        insights.append(_insight(
            'reverse_no_session',
            'gap scan: handler port already in use on LHOST',
            'Gap scan: the handler LPORT is already bound on LHOST — a stale '
            'handler may be stealing the callback. Re-arming (bind avoids it).',
            prefer_mode='bind'))

    # ── Compatible-payload refresh ───────────────────────────────────────────
    compat = results.get(PROBE_COMPAT) or {}
    payloads = compat.get('payloads')
    if payloads:
        facts['compatible_payloads'] = list(payloads)
        notes.append(f'refreshed {len(payloads)} compatible payload(s)')

    # ── Service / OS fingerprint refinement ──────────────────────────────────
    fp = results.get(PROBE_FINGERPRINT) or {}
    if fp.get('os_family'):
        facts['os_family'] = fp['os_family']
        notes.append(f'OS refined → {fp["os_family"]}')
    if fp.get('service'):
        facts['service'] = fp['service']
    if fp.get('version'):
        facts['version'] = fp['version']
    if fp.get('os_family') or fp.get('service'):
        insights.append(_insight(
            'wrong_target',
            f'gap scan: refingerprint {fp.get("service","")} {fp.get("version","")}'.strip(),
            'Gap scan: re-fingerprinted the service — using the refined OS/'
            'service to re-pick the target index and payload.'))

    produced = bool(facts or insights)
    summary = ('gap scan: ' + '; '.join(notes)) if notes else \
              'gap scan: no new information acquired'
    return {'facts': facts, 'insights': insights, 'summary': summary,
            'produced_new_info': produced}


def dominant_signal(information_gained: list[dict]) -> str | None:
    """Pick the most actionable signal from a run's insights to drive probing."""
    if not information_gained:
        return None
    # Priority: the most specific/actionable signals first.
    priority = ['reverse_no_session', 'session_died', 'unreachable',
                'wrong_target', 'payload_incompatible', 'no_check', 'inconclusive']
    signals = [i.get('signal') for i in information_gained if isinstance(i, dict)]
    for p in priority:
        if p in signals:
            return p
    return signals[0] if signals else None
