"""
scanner_runner.py — Run MSF auxiliary/scanner modules as a post-enumeration step.

Auxiliary scanners are reconnaissance, not exploitation. They belong with the
Enumerate stage, NOT the feasibility validator: the validator runs each module's
`check` method and produces a VULNERABLE / SAFE verdict, but scanners have no
meaningful `check` — running them through validation just burns 10-13s per
module returning NO_CHECK noise (the operator's exact complaint).

This runner instead executes each selected scanner with action='run' and streams
its console output, so SMB/SSH/FTP/etc. scanners surface their findings where
they belong — alongside the rest of enumeration. It mirrors MsfValidator's
background-thread + callback design so the SSE plumbing in the app is identical.
"""
from __future__ import annotations

import threading
import time


# Inter-module delay (seconds) per stealth level 0-3 — matches the validator.
_STEALTH_DELAY = {0: 0.0, 1: 1.0, 2: 3.0, 3: 8.0}


def is_scanner_module(module: str) -> bool:
    """True for MSF auxiliary/scanner/* modules (recon, not exploitation).

    These are the modules that should be run under Enumerate rather than
    feasibility-validated. Matches with or without a leading slash and is
    case-insensitive so it is robust to however the suggestion was produced.
    """
    m = (module or '').strip().lower().lstrip('/')
    return m.startswith('auxiliary/scanner/')


class ScannerRunner:
    def __init__(self, msf_engine):
        self._engine  = msf_engine
        self._lock    = threading.Lock()
        self._running = False
        self._thread  = None

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def run(self, ip: str, modules: list, stealth: int = 0,
            on_progress=None, on_result=None, on_complete=None) -> bool:
        """Start a background scanner run.

        modules: list of dicts, each with at least 'msf_module' and optionally
                 'msf_rport' / 'port' / 'cve'.
        Returns False if a run is already in progress.
        """
        try:
            stealth = int(stealth)
        except (TypeError, ValueError):
            stealth = 0
        stealth = max(0, min(3, stealth))

        with self._lock:
            if self._running:
                return False
            self._running = True

        def emit(msg):
            if on_progress:
                try: on_progress(msg)
                except Exception: pass

        def _worker():
            try:
                self._run(ip, modules, stealth, emit, on_result, on_complete)
            except Exception as exc:
                emit(f'[!] Scanner runner error: {exc}')
            finally:
                with self._lock:
                    self._running = False

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def _run(self, ip, modules, stealth, emit, on_result, on_complete):
        # Dedupe by module, keep only real scanner modules.
        seen, uniq = set(), []
        for c in (modules or []):
            mod = (c or {}).get('msf_module')
            if not mod or mod in seen or not is_scanner_module(mod):
                continue
            seen.add(mod)
            uniq.append(c)

        if not uniq:
            emit('[!] No scanner modules to run')
            if on_complete:
                try: on_complete({})
                except Exception: pass
            return

        delay   = _STEALTH_DELAY.get(stealth, 0.0)
        results = {}
        emit(f'[*] Running {len(uniq)} scanner module(s) against {ip} '
             f'(stealth {stealth})')

        for i, cand in enumerate(uniq):
            module = cand['msf_module']
            rport  = cand.get('msf_rport') or cand.get('port')
            emit(f'[*] [{i+1}/{len(uniq)}] {module} ...')

            opts = {'RHOSTS': ip}
            if rport:
                opts['RPORT'] = str(rport)

            try:
                res    = self._engine.run_exploit(module, options=opts, action='run')
                status = res.get('status')
                out    = res.get('console_output') or res.get('result') or ''
                if status == 'error':
                    summary = {'module': module, 'state': 'error',
                               'detail': res.get('message', 'run errored')}
                    emit(f'[!] {module} → ERROR: {summary["detail"]}')
                else:
                    summary = {'module': module, 'state': 'ran',
                               'detail': 'completed',
                               'output': (out or '')[-4000:]}
                    emit(f'[+] {module} → ran')
                    for line in (out or '').splitlines():
                        if line.strip():
                            emit('    ' + line)
            except Exception as exc:
                summary = {'module': module, 'state': 'error', 'detail': str(exc)}
                emit(f'[!] {module} → ERROR: {exc}')

            summary['cve'] = cand.get('cve')
            results[module] = summary
            if on_result:
                try: on_result(summary)
                except Exception: pass

            if delay and i < len(uniq) - 1:
                time.sleep(delay)

        emit(f'[*] Scanner run complete — {len(uniq)} module(s)')
        if on_complete:
            try: on_complete(results)
            except Exception: pass
