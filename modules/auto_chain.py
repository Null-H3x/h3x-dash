"""
auto_chain.py — Closed-loop "land a stable shell" orchestrator.

This is the post-validate automation the operator asked for, expressed as a
state machine that is driven entirely by the flexible resolver + the
information-gained feedback loop — NOT by hardcoded per-module ladders:

    recommend ──► run ──► shell check ─┬─ alive ─► persist ─► STOP (success)
        ▲                              │
        │                             dead/quiet/no-session
        │                              │
        └──── re-arm ◄── gather information ◄┘

Termination is information-driven, so it can't loop forever and isn't a fixed
recipe:
  • success      — a session confirmed alive and persisted
  • halted       — a verdict says the target is NOT vulnerable (no retry helps)
  • needs_input  — the recommended plan needs an operator-supplied option
                   (e.g. TARGETURI) that automation can't invent
  • exhausted    — re-arming produced a plan we already tried (no NEW information
                   to act on), or the attempt cap was hit

The orchestrator is pure control-flow: it calls an `engine` object that provides
recommend_plan / run_plan / confirm_session / persist_session / list_sessions.
That keeps it fully unit-testable with a scripted mock engine (audit_auto_chain).
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable


def plan_signature(plan: dict) -> tuple:
    """A hashable identity for a plan — used to detect 'no new information'."""
    opts = plan.get('options') or {}
    return (
        plan.get('connection_mode'),
        plan.get('payload'),
        plan.get('target_index'),
        tuple(sorted((str(k), str(v)) for k, v in opts.items())),
    )


def _session_id_from_result(result: dict) -> str | None:
    sessions = result.get('sessions') or []
    for s in sessions:
        if isinstance(s, dict) and s.get('id') not in (None, ''):
            return str(s['id'])
    return None


def run_auto_chain(engine, module: str, environment: dict, *,
                   max_attempts: int = 5,
                   session_wait: float = 0.0,
                   emit: Callable[[dict], None] | None = None) -> dict[str, Any]:
    """
    Drive the recommend→run→check→persist/re-arm loop until a stable shell lands
    or the chain terminates for an information-driven reason.

    `engine` must provide:
      recommend_plan(module, environment) -> plan
      run_plan(module, plan, environment) -> run result (with information_gained)
      confirm_session(sid) -> {alive, dead, output, ...}
      persist_session(sid) -> {persisted, ...}
      list_sessions() -> [ {id, ...} ]   (for late-session polling)
    """
    emit = emit or (lambda ev: None)
    environment = environment if isinstance(environment, dict) else {}
    environment.setdefault('module', module)       # probes/resolver need it
    try:
        max_attempts = int(max_attempts)
    except (TypeError, ValueError):
        max_attempts = 5
    max_attempts = max(1, max_attempts)            # never an empty loop
    tried: set = set()
    history: list[dict] = []

    def _emit(phase, **kw):
        ev = {'phase': phase, **kw}
        try:
            emit(ev)
        except Exception:
            pass
        return ev

    def _gained_messages(info):
        out = []
        for i in (info or []):
            if isinstance(i, dict):
                out.append(i.get('message', ''))
        return [m for m in out if m]

    _emit('start', module=module, rhost=environment.get('rhost', ''),
          max_attempts=max_attempts)

    for attempt in range(1, max_attempts + 1):
        # ── RECOMMEND (re-armed by all insights gathered so far) ─────────────
        # A recommender failure is transient (e.g. RPC blip) — record + retry,
        # never crash the chain.
        try:
            plan = engine.recommend_plan(module, environment)
        except Exception as exc:
            _emit('attempt_error', attempt=attempt, stage='recommend', message=str(exc))
            history.append({'attempt': attempt, 'error': f'recommend: {exc}'})
            continue
        if not isinstance(plan, dict):
            _emit('attempt_error', attempt=attempt, stage='recommend',
                  message='recommender returned a non-plan')
            history.append({'attempt': attempt, 'error': 'recommend: non-dict plan'})
            continue

        _emit('recommend', attempt=attempt,
              mode=plan.get('connection_mode'), payload=plan.get('payload'),
              target_index=plan.get('target_index'),
              rationale=plan.get('rationale', []),
              applied_insights=plan.get('applied_insights', []))

        # Halt: a prior verdict said NOT vulnerable, or the module is
        # OS-incompatible with a high-confidence classification.
        if plan.get('stop'):
            reason = 'os_incompatible' if plan.get('incompatible') else 'not_vulnerable'
            _emit('halt', reason=reason, attempt=attempt,
                  detail=(plan.get('rationale') or [''])[0])
            return {'status': 'halted', 'reason': reason,
                    'attempts': history, 'attempt_count': attempt - 1}

        # Needs operator input the automation can't invent.
        if plan.get('information_needed'):
            _emit('needs_input', attempt=attempt, need=plan['information_needed'])
            return {'status': 'needs_input', 'need': plan['information_needed'],
                    'attempts': history, 'attempt_count': attempt - 1}

        # No NEW information — re-arm produced a plan we already ran (and that
        # run produced real signal, not a transient error — see below).
        sig = plan_signature(plan)
        if sig in tried:
            _emit('exhausted', reason='no_new_information', attempt=attempt)
            return {'status': 'exhausted', 'reason': 'no_new_information',
                    'attempts': history, 'attempt_count': attempt - 1}

        # ── RUN ──────────────────────────────────────────────────────────────
        _emit('run', attempt=attempt, mode=plan.get('connection_mode'),
              payload=plan.get('payload') or 'module default')
        try:
            result = engine.run_plan(module, plan, environment)
        except Exception as exc:
            result = {'status': 'error', 'message': str(exc)}
        if not isinstance(result, dict):
            result = {'status': 'error', 'message': 'run returned a non-dict'}
        info = result.get('information_gained') or []

        # A transient/transport failure (RPC drop, not connected, engine error
        # with no actionable signal) must NOT count as "tried" — otherwise a
        # reconnect-able blip would dedupe-exhaust the chain. It stays retryable,
        # bounded by max_attempts.
        transient = _is_transient_failure(result, info)
        if not transient:
            tried.add(sig)

        # ── SHELL CHECK ────────────────────────────────────────────────────
        sid = _session_id_from_result(result)
        if not sid and result.get('session_unconfirmed') and session_wait > 0:
            sid = _poll_for_session(engine, session_wait)

        check = None
        landed = False
        if sid:
            try:
                check = engine.confirm_session(sid)
            except Exception as exc:
                # A confirm failure is NOT death — treat as quiet, keep looping.
                check = {'alive': False, 'dead': False,
                         'message': f'confirm error: {exc}'}
            if not isinstance(check, dict):
                check = {'alive': False, 'dead': False}
            _emit('shell_check', attempt=attempt, sid=sid,
                  alive=bool(check.get('alive')), dead=bool(check.get('dead')),
                  output=(check.get('output') or '')[:2000])

            if check.get('alive'):
                # ── PERSIST → STOP ─────────────────────────────────────────
                # The shell IS landed. A persistence error must not lose the
                # win; only a persistence-confirmed death continues the loop.
                try:
                    persist = engine.persist_session(sid)
                except Exception as exc:
                    persist = {'persisted': True, 'session_type': 'shell',
                               'warning': f'persistence step errored: {exc}'}
                if not isinstance(persist, dict):
                    persist = {'persisted': True, 'warning': 'persist returned non-dict'}

                if persist.get('persisted'):
                    _emit('success', attempt=attempt, sid=sid,
                          session_type=persist.get('session_type'),
                          persisted=True, warning=persist.get('warning'),
                          recon=(persist.get('recon') or check.get('output') or '')[:2000])
                    return {'status': 'success', 'sid': sid, 'persist': persist,
                            'attempts': history, 'attempt_count': attempt}
                # Session died DURING persistence (e.g. fragile migrate) — this
                # is new information; record + re-arm rather than claim success.
                _emit('persist_failed', attempt=attempt, sid=sid,
                      reason=persist.get('reason', 'session died during persistence'))
            elif check.get('dead'):
                # The run may have reported "session opened" (false success), but
                # confirmation is authoritative: it DIED. Record a session-died
                # insight so the NEXT attempt pivots (reverse → bind). This is the
                # fix for distcc reverse_perl open-then-die stalling the chain.
                noter = getattr(engine, 'note_session_died', None)
                if noter:
                    try:
                        di = noter(environment)
                        _emit('session_died', attempt=attempt, sid=sid,
                              message=di.get('message') if isinstance(di, dict) else None)
                    except Exception:
                        pass
        else:
            _emit('no_session', attempt=attempt,
                  transient=transient)

        # ── ACTIVE GAP SCAN — acquire NEW information before re-arming ───────
        # If the attempt didn't land a shell, probe the specific gap the failure
        # points at (route / handler-port / target-port / compatible payloads /
        # fingerprint). Facts merge into the environment so the next recommend
        # adapts (e.g. lhost_routable=False → bind); insights are recorded by the
        # engine. This is what turns dedupe-exhaustion into productive iteration.
        gap = None
        gather = getattr(engine, 'gather_gap_information', None)
        if gather and not (check and check.get('alive')):
            from modules.gap_probes import dominant_signal
            probe_signal = dominant_signal(info)
            if probe_signal:
                try:
                    gap = gather(probe_signal, environment)
                except Exception as exc:
                    gap = {'summary': f'gap scan error: {exc}',
                           'facts': {}, 'produced_new_info': False}
                for k, v in (gap.get('facts') or {}).items():
                    environment[k] = v          # re-arm the environment in place
                _emit('gap_scan', attempt=attempt, signal=probe_signal,
                      summary=gap.get('summary'),
                      produced=bool(gap.get('produced_new_info')),
                      facts=gap.get('facts') or {})

        # ── GATHER INFORMATION → RE-ARM (next loop) ──────────────────────────
        history.append({'attempt': attempt, 'plan': plan,
                        'information_gained': info, 'check': check, 'sid': sid,
                        'transient': transient, 'gap': gap})
        _emit('rearm', attempt=attempt, gained=_gained_messages(info),
              transient=transient,
              session_was=('alive' if (check and check.get('alive'))
                           else 'dead' if (check and check.get('dead'))
                           else 'none'))

    _emit('exhausted', reason='max_attempts', attempt=max_attempts)
    return {'status': 'exhausted', 'reason': 'max_attempts',
            'attempts': history, 'attempt_count': max_attempts}


def _is_transient_failure(result: dict, info: list) -> bool:
    """
    True when an attempt failed for an environmental/transport reason (RPC drop,
    not connected, engine error) rather than a real exploit outcome. Such an
    attempt stays retryable — it should not dedupe-exhaust the chain.
    """
    if result.get('status') == 'error':
        msg = (result.get('message') or '').lower()
        # A 'missing required' error IS actionable (it produced insights) — not transient.
        if result.get('missing_required'):
            return False
        transient_markers = ('not connected', 'connection', 'rpc', 'timeout',
                             'timed out', 'console creation failed', 'refused',
                             'non-dict')
        if any(m in msg for m in transient_markers) or not info:
            return True
    return False


class AutoChainRunner:
    """
    Thread-backed wrapper around run_auto_chain for the UI. The orchestrator runs
    in the background; the UI polls snapshot() for the streamed event log + final
    result. Only one chain runs at a time.
    """

    def __init__(self, engine):
        self._engine = engine
        self._lock = threading.Lock()
        self._thread = None
        self._running = False
        self._events: list[dict] = []
        self._result: dict | None = None
        self._target: dict | None = None

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def _sink(self, ev: dict) -> None:
        ev = dict(ev)
        ev['ts'] = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._events.append(ev)

    def start(self, module: str, environment: dict, max_attempts: int = 5) -> bool:
        with self._lock:
            if self._running:
                return False
            self._running = True
            self._events = []
            self._result = None
            self._target = {'module': module, 'rhost': environment.get('rhost', '')}

        def _worker():
            # Initialize result up front so the finally never UnboundLocalErrors,
            # even on BaseException (KeyboardInterrupt) or a sink failure.
            result = {'status': 'error', 'message': 'worker did not complete'}
            try:
                result = run_auto_chain(self._engine, module, environment,
                                        max_attempts=max_attempts,
                                        session_wait=20.0, emit=self._sink)
            except BaseException as exc:           # never leave _running stuck
                try:
                    self._sink({'phase': 'error', 'message': str(exc)})
                except Exception:
                    pass
                result = {'status': 'error', 'message': str(exc)}
            finally:
                with self._lock:
                    self._result = result
                    self._running = False

        self._thread = threading.Thread(target=_worker, daemon=True,
                                        name='h3x-auto-chain')
        self._thread.start()
        return True

    def snapshot(self) -> dict:
        with self._lock:
            return {
                'running': self._running,
                'target':  dict(self._target) if self._target else None,
                'events':  list(self._events),
                'result':  dict(self._result) if self._result else None,
            }


def _poll_for_session(engine, wait: float, interval: float = 1.0) -> str | None:
    """Poll list_sessions for a newly-registered session id, up to `wait` secs."""
    try:
        before = {str(s.get('id')) for s in engine.list_sessions()}
    except Exception:
        before = set()
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(interval)
        try:
            now = engine.list_sessions()
        except Exception:
            now = []
        fresh = [str(s.get('id')) for s in now if str(s.get('id')) not in before]
        if fresh:
            return fresh[-1]
    return None
