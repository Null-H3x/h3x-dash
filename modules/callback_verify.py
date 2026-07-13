"""
callback_verify.py — Pre-exploit callback path checks.

Validates that reverse or bind payloads have a plausible network path before
the operator fires an exploit. Used by POST /api/network/callback-verify.
"""
from __future__ import annotations

import re
import socket
import subprocess
from typing import Any


def _is_bind_payload(payload: str | None) -> bool:
    return bool(payload and 'bind' in payload.lower())


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, f'TCP {host}:{port} reachable'
    except socket.timeout:
        return False, f'TCP {host}:{port} timed out'
    except ConnectionRefusedError:
        return False, f'TCP {host}:{port} connection refused'
    except OSError as exc:
        return False, f'TCP {host}:{port} — {exc}'


def _lport_free_on_lhost(lhost: str, lport: int, timeout: float = 1.0) -> tuple[bool, str]:
    """Reverse handlers need LPORT free on Kali (connect should fail)."""
    ok, detail = _tcp_probe(lhost, lport, timeout=timeout)
    if ok:
        return False, (f'LPORT {lport} already has a listener on {lhost} — '
                       f'handler may conflict ({detail})')
    if 'refused' in detail.lower():
        return True, f'LPORT {lport} free on {lhost} (ready for handler)'
    return True, f'LPORT {lport} appears free on {lhost} ({detail})'


def _route_src_for(rhost: str) -> tuple[str | None, str]:
    try:
        out = subprocess.check_output(
            ['ip', 'route', 'get', rhost],
            stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
        m = re.search(r'\bsrc\s+([\d.a-fA-F:]+)', out)
        if m:
            return m.group(1), out.strip()
        return None, out.strip() or 'no src in route output'
    except FileNotFoundError:
        return None, 'iproute2 not available (ip route get)'
    except Exception as exc:
        return None, str(exc)


def verify_callback(*,
                    rhost: str,
                    rport: int | None = None,
                    lhost: str = '',
                    lport: int = 4444,
                    payload: str | None = None) -> dict[str, Any]:
    """
    Run callback-path checks. Returns {checks, ready, is_bind, bind_connect_cmd, summary}.
    """
    checks: list[dict[str, Any]] = []
    is_bind = _is_bind_payload(payload)

    def add(cid: str, label: str, ok: bool, detail: str) -> None:
        checks.append({'id': cid, 'label': label, 'ok': ok, 'detail': detail})

    # ── RHOST / RPORT (exploit target service) ────────────────────────────────
    if rhost:
        if rport:
            ok, detail = _tcp_probe(rhost, int(rport))
            add('rhost_rport', f'Target service {rhost}:{rport}', ok, detail)
        else:
            add('rhost_set', 'RHOST configured', True, rhost)
    else:
        add('rhost_set', 'RHOST configured', False, 'Set RHOST before launch')

    bind_cmd = ''
    if is_bind:
        bp = int(lport or 4444)
        bind_cmd = f'nc -v {rhost} {bp}'
        add('bind_mode', 'Bind payload mode', True,
            f'After exploit, connect from Kali: {bind_cmd}')
        if rhost and rport:
            add('bind_note', 'Bind listener lands on target', True,
                f'MSF opens port {bp} on the target — connect after exploit completes')
    else:
        # ── Reverse payload path ─────────────────────────────────────────────
        if lhost:
            add('lhost_set', 'LHOST configured', True, lhost)
            route_src, route_detail = _route_src_for(rhost) if rhost else (None, '')
            if route_src:
                matches = (route_src == lhost
                           or lhost in route_detail
                           or route_src.split('.')[:3] == lhost.split('.')[:3])
                add('route', f'Route to {rhost}', matches,
                    f'Kernel src {route_src}' + ('' if matches else f' ≠ LHOST {lhost}'))
            else:
                add('route', f'Route to {rhost}', False, route_detail)
            free, ldetail = _lport_free_on_lhost(lhost, int(lport or 4444))
            add('lport_free', f'Handler port {lhost}:{lport}', free, ldetail)
        else:
            add('lhost_set', 'LHOST configured', False,
                'Reverse payload needs LHOST — use auto-detect or set manually')

    critical = {'rhost_set', 'rhost_rport', 'lhost_set', 'route', 'lport_free'}
    if is_bind:
        critical = {'rhost_set', 'rhost_rport'}

    ready = all(c['ok'] for c in checks if c['id'] in critical)
    failed = [c['label'] for c in checks if c['id'] in critical and not c['ok']]
    summary = ('Callback path looks good.' if ready
               else 'Fix failed checks before launch: ' + ', '.join(failed))

    return {
        'checks':          checks,
        'ready':           ready,
        'is_bind':         is_bind,
        'bind_connect_cmd': bind_cmd,
        'summary':         summary,
        'rhost':           rhost,
        'lport':           lport,
    }
