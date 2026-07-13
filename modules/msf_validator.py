"""
msf_validator.py — Batch MSF feasibility validation.

The validation stage sits between Enumerate and Exploit. Where the CVE chain
tells you what is *possible* (a module exists for this service), the validator
tells you what is *feasible* in THIS environment by running MSF's own check
logic against the target.

Why this is the authoritative green light
─────────────────────────────────────────
An MSF exploit's `check` method (and its companion auxiliary/scanner modules)
use the SAME vulnerability-detection logic the exploit itself relies on. So a
VULNERABLE verdict here means the exploit's own preconditions are satisfied —
a far stronger signal than an nmap NSE probe, which only infers vulnerability
from banner/response heuristics.

Design
──────
- Reuses MsfEngine.run_exploit(action='check') — no duplicated console logic.
- Runs in a background thread with progress callbacks (mirrors EnumEngine).
- Dedupes modules (multiple CVE suggestions can map to one module).
- Persists verdicts to loot/msf_validation.json keyed by "{ip}::{module}" so
  the Exploit tab can badge each suggestion with the feasibility verdict.
- Respects a stealth level: higher levels add inter-check delay to spread the
  check traffic out (the selectable-noise principle).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


# ── Verdict constants ──────────────────────────────────────────────────────────
VULNERABLE     = 'VULNERABLE'
NOT_VULNERABLE = 'NOT_VULNERABLE'
DETECTED       = 'DETECTED'      # service present, exploitability unconfirmed
NO_CHECK       = 'NO_CHECK'      # module has no check method (expected for many MT2)
UNKNOWN        = 'UNKNOWN'
ERROR          = 'ERROR'

# Inter-check delay (seconds) per stealth level 0-3. Level 0 = back-to-back.
_STEALTH_DELAY = {0: 0.0, 1: 1.0, 2: 3.0, 3: 8.0}


class MsfValidator:
    def __init__(self, msf_engine, loot_dir: Path):
        self._engine   = msf_engine
        self._loot_dir = Path(loot_dir)
        self._loot_dir.mkdir(parents=True, exist_ok=True)
        self._store    = self._loot_dir / 'msf_validation.json'

        self._lock     = threading.Lock()
        self._running  = False
        self._thread   = None
        self._status   = {
            'running':   False,
            'target':    None,
            'total':     0,
            'done':      0,
            'current':   None,
            'verdicts':  {},      # module -> verdict dict
        }

    # ── Public state ────────────────────────────────────────────────────────────
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def get_status(self) -> dict:
        with self._lock:
            # shallow copy so callers can't mutate internal state
            s = dict(self._status)
            s['verdicts'] = dict(self._status['verdicts'])
            return s

    # ── Persistence ──────────────────────────────────────────────────────────────
    def _load_store(self) -> dict:
        try:
            if self._store.exists():
                return json.loads(self._store.read_text())
        except Exception:
            pass
        return {}

    def _save_verdict(self, ip: str, module: str, verdict: dict) -> None:
        with self._lock:
            data = self._load_store()
            data[f'{ip}::{module}'] = verdict
            try:
                self._store.write_text(json.dumps(data, indent=2))
            except Exception:
                pass

    def get_verdicts_for_host(self, ip: str) -> dict:
        """Return {module: verdict_dict} for every stored verdict on this host."""
        data = self._load_store()
        out  = {}
        prefix = f'{ip}::'
        for key, verdict in data.items():
            if key.startswith(prefix):
                out[key[len(prefix):]] = verdict
        return out

    def clear_host(self, ip: str) -> None:
        with self._lock:
            data = self._load_store()
            for key in [k for k in data if k.startswith(f'{ip}::')]:
                del data[key]
            try:
                self._store.write_text(json.dumps(data, indent=2))
            except Exception:
                pass

    # ── Verdict mapping ────────────────────────────────────────────────────────
    # CheckCode-aware codes that the engine now returns map straight onto the
    # validator's verdict buckets. Falls back to the legacy boolean flags for
    # older engine results that don't carry check_code.
    _CODE_TO_VERDICT = {
        'VULNERABLE':  VULNERABLE,
        'APPEARS':     VULNERABLE,
        'DETECTED':    DETECTED,
        'SAFE':        NOT_VULNERABLE,
        'UNSUPPORTED': NO_CHECK,
        'UNREACHABLE': ERROR,
        'UNKNOWN':     UNKNOWN,
    }

    @classmethod
    def _verdict_from_result(cls, result: dict) -> dict:
        """Map a run_exploit(action='check') result to a verdict dict.

        Prefers the CheckCode-aware 'check_code' (Vulnerable/Appears/Detected/
        Safe/Unsupported/Unreachable/Unknown). Falls back to the legacy
        check_vulnerable/check_safe booleans when an older engine produced the
        result.
        """
        status = result.get('status')
        if status == 'error':
            return {'verdict': ERROR,
                    'detail':  result.get('message', 'check errored')}

        code = result.get('check_code')
        if code:
            verdict = cls._CODE_TO_VERDICT.get(code, UNKNOWN)
            detail  = result.get('check_detail') or f'MSF CheckCode: {code}'
            return {'verdict': verdict, 'detail': detail, 'check_code': code}

        # ── Legacy fallback (engine without check_code) ──────────────────────
        if result.get('check_vulnerable'):
            return {'verdict': VULNERABLE,
                    'detail':  'MSF check confirms the target is vulnerable'}
        if result.get('check_safe'):
            return {'verdict': NOT_VULNERABLE,
                    'detail':  'MSF check reports the target is not vulnerable'}
        return {'verdict': UNKNOWN,
                'detail':  'Module ran but returned no definitive verdict '
                           '(may not implement check)'}

    # ── Core run ──────────────────────────────────────────────────────────────────
    def validate(self, ip: str, candidates: list, stealth: int = 0,
                 on_progress=None, on_verdict=None, on_complete=None) -> bool:
        """
        Start a background validation run.

        candidates: list of dicts, each with at least 'msf_module' and
                    optionally 'msf_rport' / 'cve' / 'description'.
        Returns False if a run is already in progress.
        """
        # Sanitize stealth at the boundary — clamp to a valid 0-3 int. A
        # malformed value must never reach the worker (where int() would throw
        # and leave _running stuck True, bricking all future runs).
        try:
            stealth = int(stealth)
        except (TypeError, ValueError):
            stealth = 0
        stealth = max(0, min(3, stealth))

        with self._lock:
            if self._running:
                return False
            self._running = True

        def _emit_progress(msg):
            if on_progress:
                try: on_progress(msg)
                except Exception: pass

        def _worker():
            try:
                self._run_validation(ip, candidates, stealth,
                                     _emit_progress, on_verdict, on_complete)
            except Exception as exc:
                # Defensive backstop: any unexpected error must not leave the
                # validator wedged. Log, emit, and fall through to the finally.
                _emit_progress(f'[!] Validation worker error: {exc}')
            finally:
                with self._lock:
                    self._running = False
                    self._status['running'] = False
                    self._status['current'] = None

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def _run_validation(self, ip, candidates, stealth,
                        emit_progress, on_verdict, on_complete):
        """The actual validation loop. Runs inside the worker thread, wrapped by
        _worker's try/finally so _running is always cleared on exit."""
        # Dedupe by module — multiple CVEs can map to one module.
        seen, uniq = set(), []
        for c in candidates:
            mod = c.get('msf_module')
            if not mod or mod in seen:
                continue
            seen.add(mod)
            uniq.append(c)

        with self._lock:
            self._status.update({
                'running': True, 'target': ip, 'total': len(uniq),
                'done': 0, 'current': None, 'verdicts': {},
            })

        delay = _STEALTH_DELAY.get(stealth, 0.0)
        emit_progress(f'[*] MSF validation starting — {len(uniq)} module(s) '
                      f'against {ip} (stealth {stealth})')

        for i, cand in enumerate(uniq):
            module = cand['msf_module']
            rport  = cand.get('msf_rport') or cand.get('port')
            with self._lock:
                self._status['current'] = module
            emit_progress(f'[*] [{i+1}/{len(uniq)}] checking {module} ...')

            opts = {'RHOSTS': ip}
            if rport:
                opts['RPORT'] = str(rport)

            try:
                result = self._engine.run_exploit(
                    module, options=opts, action='check')
                verdict = self._verdict_from_result(result)
            except Exception as exc:
                verdict = {'verdict': ERROR, 'detail': f'check raised: {exc}'}

            verdict['module'] = module
            verdict['cve']    = cand.get('cve')
            self._save_verdict(ip, module, verdict)

            with self._lock:
                self._status['done'] = i + 1
                self._status['verdicts'][module] = verdict

            glyph = {'VULNERABLE': '[+]', 'NOT_VULNERABLE': '[-]',
                     'UNKNOWN': '[?]', 'ERROR': '[!]'}.get(verdict['verdict'], '[?]')
            emit_progress(f'{glyph} {module} → {verdict["verdict"]}: '
                          f'{verdict["detail"]}')
            if on_verdict:
                try: on_verdict(verdict)
                except Exception: pass

            if delay and i < len(uniq) - 1:
                time.sleep(delay)

        with self._lock:
            final = dict(self._status['verdicts'])

        vuln_count = sum(1 for v in final.values()
                         if v.get('verdict') == VULNERABLE)
        emit_progress(f'[*] Validation complete — {vuln_count} confirmed '
                      f'VULNERABLE of {len(uniq)} checked')
        if on_complete:
            try: on_complete(final)
            except Exception: pass
