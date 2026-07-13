#!/usr/bin/env python3
"""
H3x-Dash — Synthetic C2 Beacon Emitter (purple-team detection validation).

This is NOT a command-and-control framework. It is a *benign traffic generator*
for detection testing: it emits periodic, jittered HTTP(S)/DNS callbacks to a
sink the operator controls, shaped to resemble known beacon signatures
(user-agent, URI, cadence). There is deliberately:

  * no command channel — responses are ignored (only the status code is read),
  * no payload and no data transfer (that's a separate concern — exfil),
  * no persistence, no target other than the operator-supplied sink.

The whole point is to exercise a SIEM/IDS's beaconing detections — regular
callbacks with jitter to a low-reputation URI — and confirm they fire. Runs
against operator-supplied targets only.

Testable seams: ``next_sleep`` (jitter math) and ``build_http_request``
(profile → request shaping) are pure; the network sender is an injectable
method so the lifecycle can be validated without touching the network.
"""

import random
import secrets
import socket
import threading
import time
from datetime import datetime, timezone

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:                                    # pragma: no cover
    requests = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+0000')


# Detection-test signatures. These shape only the request *metadata* (UA / URI /
# method) so blue-team rules keyed to those patterns can be validated. They
# carry no capability — every request is an empty heartbeat.
PROFILES = {
    'generic':   {'label': 'Generic heartbeat',    'method': 'GET',  'uri': '/api/v1/health',        'ua': 'Mozilla/5.0 (compatible; H3xBeacon/1.0)'},
    'browser':   {'label': 'Browser-like GET',     'method': 'GET',  'uri': '/gsi/status',           'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'},
    'jquery':    {'label': 'jQuery malleable-style','method': 'GET', 'uri': '/jquery-3.3.1.min.js',   'ua': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'},
    'post':      {'label': 'POST check-in',         'method': 'POST', 'uri': '/submit.php',           'ua': 'Mozilla/5.0 (compatible; H3xBeacon/1.0)'},
    'dns':       {'label': 'DNS beacon',            'method': 'DNS',  'uri': '',                      'ua': ''},
}


# ── pure helpers (unit-testable) ──────────────────────────────────────────────

def next_sleep(interval_s: float, jitter_pct: float) -> float:
    """Beacon cadence: interval ± jitter%. Clamped to a sane floor."""
    j = max(0.0, min(90.0, float(jitter_pct))) / 100.0
    return max(0.2, float(interval_s) * (1 + random.uniform(-j, j)))


def build_http_request(profile_key: str, target: str, seq: int) -> dict:
    """Shape a heartbeat request from a profile. Pure — no I/O."""
    p = PROFILES.get(profile_key, PROFILES['generic'])
    base = target.rstrip('/')
    return {
        'method': 'GET' if p['method'] in ('DNS', '') else p['method'],
        'url': base + p['uri'],
        'headers': {'User-Agent': p['ua'] or 'H3xBeacon/1.0', 'Accept': '*/*'},
    }


# ── engine ────────────────────────────────────────────────────────────────────

class BeaconEmitter:
    def __init__(self):
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def profiles(self) -> list:
        return [{'id': k, 'label': v['label'],
                 'transport': 'dns' if v['method'] == 'DNS' else 'http',
                 'method': v['method'], 'uri': v['uri']} for k, v in PROFILES.items()]

    def running(self, client_id: str) -> bool:
        with self._lock:
            return client_id in self._jobs

    def status(self, client_id: str) -> dict:
        with self._lock:
            j = self._jobs.get(client_id)
            return dict(j['stats']) if j else {'sent': 0, 'running': False}

    def stop(self, client_id: str) -> bool:
        with self._lock:
            j = self._jobs.get(client_id)
        if j:
            j['stop'].set()
            return True
        return False

    # injectable senders (overridden in tests so no real network is needed)
    def _send_http(self, method: str, url: str, headers: dict, timeout: float = 4.0):
        if requests is None:
            raise RuntimeError('requests unavailable')
        r = requests.request(method, url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False,
                             data=(b'' if method == 'POST' else None))
        return r.status_code

    def _send_dns(self, domain: str) -> str:
        host = f'{secrets.token_hex(3)}.{domain.lstrip(".")}'
        socket.getaddrinfo(host, None)            # triggers a real DNS query
        return host

    def start(self, spec: dict, on_event, on_complete) -> tuple[bool, str]:
        target = (spec.get('target') or '').strip()
        if not target:
            return False, 'a callback sink (URL or domain) is required'
        transport = spec.get('transport', 'https')
        if transport not in ('http', 'https', 'dns'):
            return False, f'unknown transport {transport}'
        client_id = spec.get('client_id')
        stop = threading.Event()
        stats = {'sent': 0, 'ok': 0, 'err': 0, 'last': None, 'last_code': None,
                 'running': True, 'transport': transport, 'target': target}
        with self._lock:
            self._jobs[client_id] = {'stop': stop, 'stats': stats}
        t = threading.Thread(target=self._loop,
                             args=(client_id, spec, on_event, on_complete),
                             daemon=True)
        t.start()
        return True, 'started'

    def _loop(self, client_id, spec, on_event, on_complete):
        transport = spec.get('transport', 'https')
        target = (spec.get('target') or '').strip()
        interval = float(spec.get('interval_s', 30) or 30)
        jitter = float(spec.get('jitter_pct', 20) or 0)
        profile = spec.get('profile', 'generic')
        max_b = int(spec.get('max_beacons', 0) or 0)
        job = self._jobs.get(client_id, {})
        stop = job.get('stop')
        stats = job.get('stats', {})
        seq = 0
        while stop is not None and not stop.is_set():
            seq += 1
            ts = _now_iso()
            try:
                if transport == 'dns':
                    detail = self._send_dns(target)
                    code = 'DNS'
                    ok = True
                else:
                    url_base = target if target.startswith('http') else f'{transport}://{target}'
                    req = build_http_request(profile, url_base, seq)
                    code = self._send_http(req['method'], req['url'], req['headers'],
                                           timeout=float(spec.get('timeout', 4)))
                    detail = req['url']
                    ok = True
            except Exception as exc:
                code, detail, ok = 'ERR', exc.__class__.__name__, False
            stats['sent'] = stats.get('sent', 0) + 1
            stats['last'] = ts
            stats['last_code'] = code
            stats['ok' if ok else 'err'] = stats.get('ok' if ok else 'err', 0) + 1
            sl = next_sleep(interval, jitter)
            try:
                on_event({'type': 'beacon', 'seq': seq, 'code': code, 'detail': detail,
                          'ok': ok, 'ts': ts, 'next_s': round(sl, 1)})
            except Exception:
                pass
            if max_b and seq >= max_b:
                break
            end = time.time() + sl
            while time.time() < end and not stop.is_set():
                time.sleep(min(0.25, max(0.0, end - time.time())))
        if stats:
            stats['running'] = False
        try:
            on_complete({'sent': stats.get('sent', 0), 'ok': stats.get('ok', 0),
                         'err': stats.get('err', 0)})
        except Exception:
            pass
        with self._lock:
            self._jobs.pop(client_id, None)
