#!/usr/bin/env python3
"""
shell_doctor.py — Live Shell / MSF session diagnostic for H3x-Dash.

Run this in a SEPARATE terminal (on the Kali box, in the h3x-dash dir) while you
drive the H3x-Dash UI. It pinpoints WHERE the "Active Sessions" / handoff failure
happens by separating the pipeline into independent stages:

    STAGE A  msfrpcd reachable + auth works
    STAGE B  msfrpcd actually LISTS the session (raw RPC ground truth)
    STAGE C  the session PERSISTS over time (does it die on its own?)
    STAGE D  the session RESPONDS to a probe (read / echo / sysinfo)
    STAGE E  H3x-Dash's own MsfEngine sees the SAME thing the raw RPC does

The key question this answers: does the session die *by itself* inside msfrpcd
(Stage C — a fragile/one-shot payload), or is it alive in msfrpcd but the
liveness probe misreads it as dead (Stage D / E)?

USAGE
    python3 shell_doctor.py                 # one full snapshot of all stages
    python3 shell_doctor.py --watch         # observe-only: track session
                                            #   land/lifetime/death, NO probing
    python3 shell_doctor.py --watch --probe-newest
                                            # also probe the newest session each
                                            #   cycle (shows if probing kills it)
    python3 shell_doctor.py --probe 1       # one deep probe of session id 1
    python3 shell_doctor.py --watch --interval 2 --duration 120

Connection defaults come from H3xConfig (which loads .env): MSF_HOST/PORT/PASS/SSL.
Override with --host/--port/--password/--ssl.

Recommended troubleshooting flow:
  1. Start `python3 shell_doctor.py --watch` BEFORE you launch the exploit in the
     UI. Watch whether the session lands and how long it survives WITHOUT anyone
     probing it. If it dies in a few seconds untouched → it's a payload-stability
     problem (Stage C), not a UI bug.
  2. If it survives untouched, run `python3 shell_doctor.py --probe <sid>` to see
     exactly what the read/echo/sysinfo probe returns (Stage D), and whether the
     probe itself is what kills it.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from datetime import datetime

sys.path.insert(0, '.')

# ── Colors (plain if not a TTY) ───────────────────────────────────────────────
def _c(code):
    return f'\033[{code}m' if sys.stdout.isatty() else ''
RST, BOLD, DIM = _c(0), _c(1), _c(2)
CYN, GRN, RED, YLW, MGT, WHT = _c(96), _c(92), _c(91), _c(93), _c(95), _c(97)

OK, BAD, WARN, INFO = f'{GRN}✓{RST}', f'{RED}✗{RST}', f'{YLW}⚠{RST}', f'{CYN}·{RST}'


def ts() -> str:
    return datetime.now().strftime('%H:%M:%S')


def hdr(title: str):
    print(f'\n{CYN}{BOLD}── {title} {"─" * max(0, 60 - len(title))}{RST}')


def line(mark: str, msg: str):
    print(f'  {mark} {msg}')


# ── Config ────────────────────────────────────────────────────────────────────
def load_defaults():
    try:
        from config import H3xConfig          # also loads .env
        return dict(host=H3xConfig.MSF_HOST, port=H3xConfig.MSF_PORT,
                    password=H3xConfig.MSF_PASS, ssl=H3xConfig.MSF_SSL)
    except Exception as exc:
        print(f'{WARN} could not import H3xConfig ({exc}); using built-in defaults')
        return dict(host='127.0.0.1', port=55553, password='msfrpc', ssl=False)


def port_open(host, port, timeout=3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── Raw RPC ground truth ──────────────────────────────────────────────────────
def connect_raw(host, port, password, ssl):
    """Return (client, version) or (None, error_str). Tries no-SSL then SSL."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError:
        return None, ('pymetasploit3 not installed — '
                      'sudo apt-get install python3-pymetasploit3')
    attempts = [(ssl, 'configured'), (not ssl, 'fallback')]
    last = None
    for use_ssl, label in attempts:
        try:
            cli = MsfRpcClient(password, server=host, port=port, ssl=use_ssl)
            ver = cli.core.version
            return cli, ver
        except Exception as exc:
            last = f'{exc} (ssl={use_ssl}, {label})'
    return None, last


def raw_sessions(client) -> dict:
    """Raw session.list dict, keys normalized to str. Raises on RPC error."""
    raw = client.sessions.list or {}
    out = {}
    for sid, info in raw.items():
        k = sid.decode() if isinstance(sid, bytes) else str(sid)
        out[k] = info if isinstance(info, dict) else {'(raw)': info}
    return out


def _g(info: dict, *keys, default='—'):
    for k in keys:
        for kk in (k, k.encode()):
            if kk in info:
                v = info[kk]
                return v.decode('utf-8', 'replace') if isinstance(v, bytes) else v
    return default


def describe_session(sid: str, info: dict) -> str:
    return (f'[{sid}] {_g(info, "type")}  '
            f'tunnel={_g(info, "tunnel_local")}->{_g(info, "tunnel_peer")}  '
            f'host={_g(info, "session_host", "target_host")}  '
            f'via={_g(info, "via_exploit")}/{_g(info, "via_payload")}  '
            f'plat={_g(info, "platform")}/{_g(info, "arch")}')


# ── Stage A/B/E snapshot ───────────────────────────────────────────────────────
def snapshot(args):
    defaults = load_defaults()
    host = args.host or defaults['host']
    port = args.port or defaults['port']
    password = args.password or defaults['password']
    ssl = defaults['ssl'] if args.ssl is None else args.ssl

    hdr('STAGE A — msfrpcd reachability + auth')
    line(INFO, f'target {host}:{port}  ssl={ssl}  (password from '
               f'{"--password" if args.password else ".env/config"})')
    if not port_open(host, port):
        line(BAD, f'TCP {host}:{port} not open — is msfrpcd running? '
                  f'Start it: msfrpcd -P {password} -S -f')
        return None, None
    line(OK, f'TCP {host}:{port} open')

    client, ver = connect_raw(host, port, password, ssl)
    if client is None:
        line(BAD, f'auth/connect failed: {ver}')
        return None, None
    line(OK, f'authenticated — Metasploit {ver}')

    # Jobs (handlers) — relevant for reverse payloads
    try:
        jobs = client.jobs.list or {}
        if jobs:
            line(INFO, f'{len(jobs)} background job(s): ' +
                 ', '.join(f'{j}:{_g(v, "name") if isinstance(v, dict) else v}'
                           for j, v in jobs.items()))
        else:
            line(INFO, 'no background jobs (no multi/handler running)')
    except Exception as exc:
        line(WARN, f'jobs.list failed: {exc}')

    hdr('STAGE B — raw session list (msfrpcd ground truth)')
    try:
        sess = raw_sessions(client)
    except Exception as exc:
        line(BAD, f'sessions.list RPC raised: {exc}')
        line(WARN, 'msfrpcd auth ok but session listing failed — note the error above.')
        return client, None
    if not sess:
        line(WARN, 'msfrpcd reports ZERO sessions right now.')
        line(INFO, 'If the UI said "session landed", it has already dropped — '
                   'run with --watch and re-launch to catch its lifetime.')
    else:
        line(OK, f'msfrpcd lists {len(sess)} session(s):')
        for sid, info in sorted(sess.items()):
            print(f'      {describe_session(sid, info)}')

    hdr('STAGE E — H3x-Dash MsfEngine parity')
    try:
        from modules.msf_engine import MsfEngine
        eng = MsfEngine()
        res = eng.connect(host=host, port=port, password=password, ssl=ssl)
        if res.get('status') != 'connected':
            line(BAD, f'MsfEngine.connect failed: {res.get("message")}')
        else:
            eng_sessions = eng.list_sessions()
            eng_ids = {s['id'] for s in eng_sessions}
            raw_ids = set(sess.keys()) if sess else set()
            line(OK if eng_ids == raw_ids else BAD,
                 f'MsfEngine.list_sessions sees {sorted(eng_ids)} ; '
                 f'raw RPC sees {sorted(raw_ids)}')
            if eng_ids != raw_ids:
                line(BAD, 'PARITY MISMATCH — MsfEngine is dropping/adding sessions '
                          'vs msfrpcd. This is a Stage E (app-side) bug.')
            else:
                line(OK, 'parity OK — the app sees exactly what msfrpcd sees.')
        return eng, sess
    except Exception as exc:
        line(WARN, f'MsfEngine parity check skipped: {exc}')
        return client, sess


# ── Stage D — deep probe of one session ────────────────────────────────────────
def probe_session(eng, sid: str):
    hdr(f'STAGE D — probe session [{sid}]')
    import secrets
    # 1. session type as the app sees it
    try:
        stype = eng._session_type(sid)
    except Exception as exc:
        stype = f'(error: {exc})'
    line(INFO, f'session type (per MsfEngine): {stype!r}')

    # 2. raw non-blocking read
    line(INFO, 'raw read (session_read)…')
    r = eng.session_read(sid)
    if r.get('session_dead'):
        line(BAD, f'read → SESSION DEAD: {r.get("message")}')
        line(WARN, 'msfrpcd refused the read with "does not exist" — the session '
                   'dropped at the framework level (Stage C/D boundary).')
    elif r.get('status') == 'ok':
        out = (r.get('output') or '').strip()
        line(OK, f'read ok ({len(out)} bytes){": " + out[:200] if out else " (empty buffer)"}')
    else:
        line(WARN, f'read returned: {r}')

    # 3. liveness probe — EXACTLY what the UI handoff/confirm uses
    line(INFO, 'liveness probe (confirm_session — same call the UI handoff makes)…')
    try:
        c = eng.confirm_session(sid, timeout=12, attempts=3)
    except Exception as exc:
        line(BAD, f'confirm_session raised: {exc}')
        return
    verdict = (f'{RED}DEAD{RST}' if c.get('dead')
               else f'{GRN}ALIVE{RST}' if c.get('alive')
               else f'{YLW}QUIET (attached, unconfirmed){RST}')
    line(OK if c.get('alive') else (BAD if c.get('dead') else WARN),
         f'verdict: {verdict} — {c.get("message")}')
    if c.get('output'):
        print(f'{DIM}      ---- probe output ----{RST}')
        for ln in str(c['output']).splitlines()[:15]:
            print(f'      {ln}')

    # 4. interpretation
    print()
    if c.get('dead'):
        line(WARN, 'INTERPRETATION: the session is gone at the msfrpcd level. '
                   'Re-run --watch WITHOUT probing to see if it dies on its own '
                   '(payload stability) or only after this probe.')
    elif c.get('alive'):
        line(OK, 'INTERPRETATION: session is alive and responsive. If the UI still '
                 'shows "died", the problem is in the browser/polling layer — tell '
                 'me and we will look at refreshSessions / the /confirm response.')
    else:
        line(WARN, 'INTERPRETATION: session is attached but did not answer the probe '
                   '(common for dumb reverse shells). It is NOT dead — typing a '
                   'command in the UI should wake it.')


# ── Watch mode — track land / lifetime / death ─────────────────────────────────
def watch(args):
    defaults = load_defaults()
    host = args.host or defaults['host']
    port = args.port or defaults['port']
    password = args.password or defaults['password']
    ssl = defaults['ssl'] if args.ssl is None else args.ssl

    client, ver = (None, None)
    if port_open(host, port):
        client, ver = connect_raw(host, port, password, ssl)
    if client is None:
        print(f'{BAD} cannot connect to msfrpcd at {host}:{port} ({ver}). '
              f'Start msfrpcd and retry.')
        return

    eng = None
    if args.probe_newest:
        try:
            from modules.msf_engine import MsfEngine
            eng = MsfEngine()
            eng.connect(host=host, port=port, password=password, ssl=ssl)
        except Exception as exc:
            print(f'{WARN} probe-newest disabled (MsfEngine connect failed: {exc})')
            eng = None

    print(f'{CYN}{BOLD}Watching msfrpcd {host}:{port} (Metasploit {ver}){RST}')
    print(f'{DIM}interval={args.interval}s  duration={args.duration}s  '
          f'probe-newest={bool(eng)}  — Ctrl-C to stop{RST}')
    print(f'{DIM}Launch your exploit in the UI now; lands/deaths print below.{RST}\n')

    seen: dict[str, dict] = {}        # sid -> {first, last, info}
    start = time.time()
    try:
        while time.time() - start < args.duration:
            now = time.time()
            try:
                cur = raw_sessions(client)
            except Exception as exc:
                print(f'{ts()} {RED}sessions.list error: {exc}{RST}')
                time.sleep(args.interval)
                continue

            # New sessions
            for sid, info in cur.items():
                if sid not in seen:
                    seen[sid] = {'first': now, 'last': now, 'info': info, 'dead': False}
                    print(f'{ts()} {GRN}● LANDED{RST}   {describe_session(sid, info)}')
                else:
                    seen[sid]['last'] = now
                    seen[sid]['info'] = info

            # Disappeared sessions = died/closed at the framework level
            for sid, rec in seen.items():
                if sid not in cur and not rec['dead']:
                    rec['dead'] = True
                    lifetime = rec['last'] - rec['first']
                    print(f'{ts()} {RED}● DIED{RST}     [{sid}] '
                          f'{_g(rec["info"], "type")} — survived '
                          f'{lifetime:.1f}s in msfrpcd '
                          f'(NOT touched by this watcher{" unless probe-newest" if eng else ""})')

            # Optional: probe the newest live session
            if eng:
                live = [s for s in cur]
                if live:
                    newest = sorted(live, key=lambda x: (len(x), x))[-1]
                    try:
                        c = eng.confirm_session(newest, timeout=8, attempts=2)
                        verd = ('DEAD' if c.get('dead') else
                                'ALIVE' if c.get('alive') else 'QUIET')
                        col = (RED if c.get('dead') else GRN if c.get('alive') else YLW)
                        print(f'{ts()} {col}  probe[{newest}] → {verd}{RST}  '
                              f'{DIM}{c.get("message","")[:80]}{RST}')
                    except Exception as exc:
                        print(f'{ts()} {YLW}  probe[{newest}] error: {exc}{RST}')

            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    # Summary
    print()
    hdr('WATCH SUMMARY')
    if not seen:
        line(WARN, 'No sessions appeared during the watch window. The exploit '
                   'never registered a session in msfrpcd → the failure is at '
                   'launch/payload time, before "Active Sessions" is even involved.')
    for sid, rec in sorted(seen.items()):
        life = rec['last'] - rec['first']
        state = f'{RED}died after {life:.1f}s{RST}' if rec['dead'] else f'{GRN}still alive ({life:.1f}s){RST}'
        line(INFO, f'[{sid}] {_g(rec["info"], "type")} — {state}')
    print()
    line(INFO, 'If sessions DIE within a few seconds untouched: payload stability '
               '(Stage C). Try a handler-first reverse_perl or a bind payload, or '
               'auto-migrate ON for Meterpreter. Share this summary with me.')


def main():
    p = argparse.ArgumentParser(
        description='H3x-Dash Shell / MSF session diagnostic',
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument('--host', help='msfrpcd host (default: from .env/config)')
    p.add_argument('--port', type=int, help='msfrpcd port (default: from .env/config)')
    p.add_argument('--password', help='msfrpcd password (default: from .env/config)')
    p.add_argument('--ssl', dest='ssl', action='store_true', default=None,
                   help='force SSL on')
    p.add_argument('--no-ssl', dest='ssl', action='store_false',
                   help='force SSL off')
    p.add_argument('--watch', action='store_true',
                   help='observe session land/lifetime/death over time')
    p.add_argument('--probe-newest', action='store_true',
                   help='(with --watch) also run the liveness probe on the newest session each cycle')
    p.add_argument('--probe', metavar='SID',
                   help='deep-probe a single session id and exit')
    p.add_argument('--interval', type=float, default=3.0,
                   help='watch poll interval seconds (default 3)')
    p.add_argument('--duration', type=float, default=300.0,
                   help='watch duration seconds (default 300)')
    args = p.parse_args()

    print(f'{MGT}{BOLD}H3x-Dash // shell_doctor // session diagnostic{RST}')

    if args.watch:
        watch(args)
        return

    eng, sess = snapshot(args)

    if args.probe:
        if eng is None:
            print(f'{BAD} cannot probe — no MSF connection.')
            return
        # eng may be a raw client (parity skipped) — only MsfEngine has probe API
        if not hasattr(eng, 'confirm_session'):
            print(f'{WARN} MsfEngine unavailable; cannot run the UI probe. '
                  f'Re-run without import errors.')
            return
        probe_session(eng, str(args.probe))
    elif sess:
        print(f'\n{DIM}Tip: deep-probe a session with '
              f'`python3 shell_doctor.py --probe <sid>`, or observe lifetimes '
              f'with `python3 shell_doctor.py --watch`.{RST}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled.')
        sys.exit(130)
