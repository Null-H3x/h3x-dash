#!/usr/bin/env python3
"""
session.py — standalone MSF session inspector / interactor for h3x-dash labs.

A clean-terminal troubleshooting tool that talks DIRECTLY to msfrpcd (the same
daemon h3x-dash drives) so you can see ground truth instead of debugging the
browser UI blind. It does not loot, write artifacts, or import h3x-dash — it
only needs `pymetasploit3` and (optionally) the h3x-dash HTTP API for a
side-by-side comparison.

Workflow:  scan → enumerate → validate → shell → session.py → interact

Connection (same defaults as h3x-dash, override via env or flags):
    MSF_HOST=127.0.0.1  MSF_PORT=55553  MSF_PASS=msfrpc  MSF_SSL=false

Commands:
    list                 List live msfrpcd sessions; diff against the h3x-dash API.
    info   <id>          Detailed info for one session (+ jobs/handlers).
    run    <id> <cmd>    Run a single command in a session and print the output.
    interact <id>        Drop into an interactive prompt for a session.
    watch  [secs]        Poll sessions and flag appear/disappear events live.
    doctor               Full diagnostic: msfrpcd ⇄ API ⇄ jobs mismatch report.

Examples:
    python3 session.py list
    python3 session.py doctor
    python3 session.py watch 2
    python3 session.py run 1 id
    python3 session.py interact 1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request


# ── Connection defaults (mirror h3x-dash config / env) ───────────────────────
DEF_HOST = os.environ.get('MSF_HOST', '127.0.0.1')
DEF_PORT = int(os.environ.get('MSF_PORT', 55553))
DEF_PASS = os.environ.get('MSF_PASS', 'msfrpc')
DEF_SSL  = os.environ.get('MSF_SSL', 'false').lower() == 'true'
DEF_API  = os.environ.get('H3X_API', 'http://127.0.0.1:5000')


# ── Tiny ANSI helper (degrades to plain text when not a TTY) ─────────────────
class C:
    _on = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
    @classmethod
    def _w(cls, code, s):
        return f'\033[{code}m{s}\033[0m' if cls._on else s
    @classmethod
    def green(cls, s):  return cls._w('32', s)
    @classmethod
    def red(cls, s):    return cls._w('31', s)
    @classmethod
    def yellow(cls, s): return cls._w('33', s)
    @classmethod
    def cyan(cls, s):   return cls._w('36', s)
    @classmethod
    def violet(cls, s): return cls._w('35', s)
    @classmethod
    def dim(cls, s):    return cls._w('2', s)
    @classmethod
    def bold(cls, s):   return cls._w('1', s)


def die(msg, code=1):
    print(C.red('[!] ') + msg, file=sys.stderr)
    sys.exit(code)


# ── msfrpcd connection (ground truth) ────────────────────────────────────────
def connect(host, port, password, ssl):
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError:
        die('pymetasploit3 not installed. On Kali:\n'
            '    sudo apt-get install python3-pymetasploit3\n'
            '    # or: pip install pymetasploit3 --break-system-packages')
    # Try the preferred SSL setting first, then fall back (matches msf_engine).
    attempts = [(ssl, 'ssl' if ssl else 'no-ssl'),
                (not ssl, 'no-ssl' if ssl else 'ssl')]
    last = None
    for use_ssl, label in attempts:
        try:
            client = MsfRpcClient(password, server=host, port=port, ssl=use_ssl)
            _ = client.core.version            # ping — raises on auth failure
            return client, label
        except Exception as exc:               # noqa: BLE001
            last = exc
    die(f'Cannot connect to msfrpcd at {host}:{port} ({label}). '
        f'Is it running?  Start with:  msfrpcd -P {password} -S -f\n'
        f'    last error: {last}')


def raw_sessions(client):
    """Return msfrpcd's session table as {sid(str): info(dict)}."""
    try:
        raw = client.sessions.list or {}
    except Exception as exc:                    # noqa: BLE001
        die(f'sessions.list failed: {exc}')
    return {str(k): v for k, v in raw.items()}


def raw_jobs(client):
    try:
        return {str(k): v for k, v in (client.jobs.list or {}).items()}
    except Exception:                           # noqa: BLE001
        return {}


# ── h3x-dash API (what the UI sees) — optional comparison ────────────────────
def api_sessions(base):
    """Return the h3x-dash API session list, or None if unreachable."""
    try:
        with urllib.request.urlopen(base.rstrip('/') + '/api/msf/sessions',
                                    timeout=4) as r:
            data = json.loads(r.read().decode())
        return {str(s.get('id')): s for s in (data.get('sessions') or [])}
    except Exception:                           # noqa: BLE001
        return None


# ── Formatting ────────────────────────────────────────────────────────────────
def _stype(info):
    return (info.get('type') or '?')


def _row(sid, info):
    stype  = _stype(info)
    peer   = info.get('tunnel_peer') or info.get('session_host') or ''
    local  = info.get('tunnel_local') or ''
    user   = info.get('username') or info.get('info') or ''
    plat   = (info.get('platform') or '').split('/')[0]
    arch   = info.get('arch') or ''
    via    = info.get('via_exploit') or ''
    color  = C.green if stype == 'meterpreter' else C.cyan
    return (f"  {C.bold(sid):<3}  {color(stype):<14}  "
            f"{peer or local:<22}  {C.violet(user):<12}  "
            f"{plat} {arch}".rstrip()
            + (f"\n        {C.dim('via ' + via)}" if via else ''))


def print_sessions(sessions, title='msfrpcd sessions'):
    print(C.bold(f'\n{title}  ({len(sessions)})'))
    if not sessions:
        print(C.dim('  (none)'))
        return
    print(C.dim('  ID   TYPE            PEER / TUNNEL           USER          PLATFORM'))
    for sid in sorted(sessions, key=lambda x: int(x) if x.isdigit() else x):
        print(_row(sid, sessions[sid]))


# ── Session run / interact ────────────────────────────────────────────────────
def _read_until_quiet(sess, timeout, settle=0.4):
    """Accumulate shell output until a silence gap (dumb shells stream slowly)."""
    out = ''
    deadline = time.time() + timeout
    silent = 0
    got = False
    time.sleep(settle)
    while time.time() < deadline:
        try:
            chunk = sess.read() or ''
        except Exception as exc:                # noqa: BLE001
            raise RuntimeError(str(exc))
        if chunk:
            out += chunk
            got = True
            silent = 0
        else:
            silent += 1
            # patient before first byte, snappier once it's gone quiet
            if (got and silent >= 3) or (not got and silent >= 12):
                break
        time.sleep(0.25)
    return out


def run_command(client, sid, cmd, timeout=15):
    """Run one command; returns (output, dead, err).

    Distinguishes a *clean death* (the session left msfrpcd's list — the
    fragile-shell case) from an *RPC read error on a still-listed session*, so
    we stop blaming the wrong layer.
    """
    sid = str(sid)
    sessions = raw_sessions(client)
    if sid not in sessions:
        return '', True, f'session {sid} is not in msfrpcd (already gone)'
    stype = _stype(sessions[sid])
    try:
        sess = client.sessions.session(sid)
    except Exception as exc:                    # noqa: BLE001
        # session() re-reads the live list; if it raises now, the session left
        # the list between our two reads → it died in that instant.
        if sid in raw_sessions(client):
            return '', _is_dead(exc), (f'{type(exc).__name__}: {exc} '
                                       '(still listed — RPC read error, not a clean death)')
        return '', True, (f'session {sid} left msfrpcd between reads — it died '
                          'within moments of landing (fragile cmd shell)')
    try:
        if stype == 'meterpreter' and hasattr(sess, 'run_with_output'):
            return sess.run_with_output(cmd, timeout=timeout) or '', False, None
        sess.write(cmd + '\n')
        return _read_until_quiet(sess, timeout), False, None
    except Exception as exc:                     # noqa: BLE001
        still = sid in raw_sessions(client)
        suffix = '' if still else ' (session left msfrpcd — it died during the command)'
        return '', (_is_dead(exc) or not still), f'{type(exc).__name__}: {exc}{suffix}'


def _is_dead(exc):
    low = str(exc).lower()
    return any(k in low for k in
               ('does not exist', 'unknown session', 'not valid',
                'invalid session', 'failure'))


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_list(args, client):
    sessions = raw_sessions(client)
    print_sessions(sessions)
    api = api_sessions(args.api) if not args.no_api else None
    if api is None:
        if not args.no_api:
            print(C.dim(f'\n  (h3x-dash API at {args.api} unreachable — skipping UI diff)'))
        return
    _diff(sessions, api)


def _diff(sessions, api):
    msf_ids = set(sessions)
    api_ids = set(api)
    print(C.bold(f'\nh3x-dash API sessions  ({len(api)})'))
    if api:
        for sid in sorted(api_ids):
            s = api[sid]
            print(f"  {C.bold(sid):<3}  {C.cyan(s.get('type','?')):<14}  "
                  f"{s.get('tunnel','') or '':<22}  {C.violet(s.get('user',''))}")
    else:
        print(C.dim('  (none)'))

    only_msf = msf_ids - api_ids
    only_api = api_ids - msf_ids
    print(C.bold('\nreconciliation'))
    if not only_msf and not only_api:
        print(C.green('  ✓ msfrpcd and the h3x-dash UI agree on the session set'))
    if only_msf:
        print(C.yellow(f'  ⚠ in msfrpcd but NOT shown by the UI: {sorted(only_msf)}'))
        print(C.dim('    → a live session the Shell panel is hiding (refresh / check filters)'))
    if only_api:
        print(C.yellow(f'  ⚠ shown by the UI but NOT in msfrpcd: {sorted(only_api)}'))
        print(C.dim('    → a stale/zombie tab; msfrpcd already dropped it'))


def cmd_info(args, client):
    sessions = raw_sessions(client)
    sid = str(args.id)
    if sid not in sessions:
        die(f'session {sid} not found in msfrpcd ({sorted(sessions)} live)')
    info = sessions[sid]
    print(C.bold(f'\nsession {sid}'))
    for k in sorted(info):
        print(f"  {C.dim(k+':'):<22} {info[k]}")
    jobs = raw_jobs(client)
    if jobs:
        print(C.bold('\nactive jobs / handlers'))
        for jid, name in sorted(jobs.items()):
            print(f"  {C.bold(jid):<3} {name}")


def cmd_run(args, client):
    cmd = ' '.join(args.cmd)
    out, dead, err = run_command(client, str(args.id), cmd, timeout=args.timeout)
    if dead:
        die(f'session {args.id} is DEAD: {err}')
    if err:
        print(C.yellow(f'[warn] {err}'))
    sys.stdout.write(out if out.endswith('\n') or not out else out + '\n')
    if not out.strip():
        print(C.dim('  (no output — shell may be quiet; try again or :raw in interact)'))


def cmd_interact(args, client):
    sid = str(args.id)
    sessions = raw_sessions(client)
    if sid not in sessions:
        die(f'session {sid} not found in msfrpcd ({sorted(sessions)} live)')
    stype = _stype(sessions[sid])
    print(C.bold(f'\nInteracting with session {sid} ({stype}). ')
          + C.dim('Commands: :info  :raw  :quit'))
    print(C.dim('Tip: dumb reverse shells answer slowly — give each command a beat.\n'))
    try:
        import readline  # noqa: F401  (enables history/editing if available)
    except Exception:
        pass
    while True:
        try:
            line = input(C.green(f'sess {sid}> '))
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line.strip():
            continue
        if line in (':quit', ':q', 'exit'):
            break
        if line == ':info':
            cmd_info(argparse.Namespace(id=sid), client)
            continue
        if line == ':raw':
            try:
                sess = client.sessions.session(sid)
                print(sess.read() or C.dim('(nothing buffered)'))
            except Exception as exc:            # noqa: BLE001
                print(C.red(f'read failed: {exc}'))
            continue
        out, dead, err = run_command(client, sid, line, timeout=args.timeout)
        if dead:
            print(C.red(f'[SESSION DIED] {err}'))
            print(C.dim('  msfrpcd no longer has this session — exiting interact.'))
            break
        if err:
            print(C.yellow(f'[warn] {err}'))
        if out:
            sys.stdout.write(out if out.endswith('\n') else out + '\n')
        else:
            print(C.dim('(no output)'))


def cmd_watch(args, client):
    interval = max(1, int(args.secs or 2))
    print(C.bold(f'Watching msfrpcd sessions every {interval}s — Ctrl-C to stop.\n'))
    prev = {}
    first = True
    try:
        while True:
            cur = raw_sessions(client)
            ts  = time.strftime('%H:%M:%S')
            cur_ids, prev_ids = set(cur), set(prev)
            appeared = cur_ids - prev_ids
            gone     = prev_ids - cur_ids
            if first:
                print(C.dim(f'[{ts}] baseline: {sorted(cur_ids) or "no sessions"}'))
                first = False
            for sid in sorted(appeared):
                info = cur[sid]
                print(C.green(f'[{ts}] + session {sid} OPENED ')
                      + C.dim(f'({_stype(info)} '
                              f'{info.get("tunnel_peer") or info.get("tunnel_local","")} '
                              f'{info.get("username","")})'))
            for sid in sorted(gone):
                print(C.red(f'[{ts}] - session {sid} CLOSED/DIED'))
            prev = cur
            time.sleep(interval)
    except KeyboardInterrupt:
        print(C.dim('\nstopped.'))


def cmd_jobs(args, client):
    jobs = raw_jobs(client)
    print(C.bold(f'\nactive jobs ({len(jobs)})'))
    if not jobs:
        print(C.dim('  (none)'))
        return
    for jid, name in sorted(jobs.items()):
        print(f'  {C.bold(jid):<3} {name}')


def cmd_killjob(args, client):
    jid = str(args.id)
    try:
        client.jobs.stop(jid)
        print(C.green(f'✓ stopped job {jid}'))
    except Exception as exc:                     # noqa: BLE001
        die(f'failed to stop job {jid}: {exc}')


def cmd_handler(args, client):
    """Stand up a persistent exploit/multi/handler, independent of h3x-dash, and
    watch for the callback. Use it to prove the reverse path end-to-end (past
    your firewall/IPS) without involving the dashboard's launch flow."""
    payload = args.payload
    lhost   = args.lhost or '0.0.0.0'
    lport   = str(args.lport)
    print(C.bold(f'\nStarting exploit/multi/handler  '
                 f'payload={payload}  LHOST={lhost}  LPORT={lport}'))
    try:
        exploit = client.modules.use('exploit', 'multi/handler')
        pl      = client.modules.use('payload', payload)
        pl['LHOST'] = lhost
        pl['LPORT'] = int(lport)
        result  = exploit.execute(payload=pl)
    except Exception as exc:                      # noqa: BLE001
        die(f'failed to start handler (is the payload name valid?): {exc}')
    jid = (result or {}).get('job_id')
    if jid is None:
        die(f'handler did not start: {result}')
    print(C.green(f'✓ handler running as job {jid} — listening for the callback'))
    print(C.dim('  Fire your payload now (or launch from h3x-dash). '
                'Ctrl-C stops watching; the handler job keeps running until you '
                f'run:  session.py kill-job {jid}'))
    baseline = set(raw_sessions(client))
    try:
        while True:
            cur = raw_sessions(client)
            for sid in sorted(set(cur) - baseline):
                info = cur[sid]
                ts = time.strftime('%H:%M:%S')
                print(C.green(f'  [{ts}] [+] session {sid} LANDED ')
                      + C.dim(f'({_stype(info)} '
                              f'{info.get("tunnel_peer") or info.get("tunnel_local","")} '
                              f'{info.get("username","")})'))
                # Immediately probe longevity — a single `id` is a safe liveness
                # check that tells us whether this is a stable shell or one that
                # dies on landing (the fragile reverse_perl/distcc case).
                out, dead, err = run_command(client, sid, 'id', timeout=6)
                if dead:
                    print(C.red(f'      ✗ shell died on landing — {err}'))
                    print(C.dim('        → callback/network is FINE (it connected); '
                                'the shell itself is short-lived. See persistence note.'))
                elif out.strip():
                    print(C.green('      ✓ shell responsive: ') + out.strip())
                    print(C.dim(f'        interact with:  session.py interact {sid}'))
                else:
                    print(C.yellow('      ? landed but quiet — try: '
                                   f'session.py interact {sid}'))
            baseline |= set(cur)
            time.sleep(1.5)
    except KeyboardInterrupt:
        print(C.dim(f'\nstopped watching. handler job {jid} still running '
                    f'(stop it with: session.py kill-job {jid}).'))


def cmd_doctor(args, client, label):
    print(C.bold('═' * 60))
    print(C.bold(' h3x-dash session doctor'))
    print(C.bold('═' * 60))
    try:
        ver = client.core.version
        print(C.green(f'✓ msfrpcd connected ({label}) — '
                      f'framework {ver.get("version","?")}'))
    except Exception as exc:                     # noqa: BLE001
        print(C.red(f'✗ msfrpcd version probe failed: {exc}'))

    sessions = raw_sessions(client)
    print_sessions(sessions)

    jobs = raw_jobs(client)
    print(C.bold(f'\nactive jobs / handlers  ({len(jobs)})'))
    if jobs:
        for jid, name in sorted(jobs.items()):
            print(f'  {C.bold(jid):<3} {name}')
        print(C.dim('  (a reverse payload needs a matching handler job here at '
                    'callback time)'))
    else:
        print(C.dim('  (none — normal between launches: h3x-dash handles the '
                    'callback inline during a run. Only an issue if you expect a '
                    'callback NOW — then start one with: session.py handler <lport>)'))

    api = api_sessions(args.api) if not args.no_api else None
    if api is None:
        if not args.no_api:
            print(C.dim(f'\n(h3x-dash API at {args.api} unreachable — UI diff skipped)'))
    else:
        _diff(sessions, api)

    # Heuristics
    print(C.bold('\nnotes'))
    if not sessions:
        print(C.dim('  • No live sessions. If you JUST launched, the callback may '
                    'not have landed — run `watch` while you re-fire.'))
    shells = [s for s in sessions.values() if _stype(s) == 'shell']
    if shells:
        print(C.dim('  • cmd/shell sessions are fragile: avoid over-probing. One '
                    '`run <id> id` is a safe liveness check.'))
    print()


# ── Arg parsing ───────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog='session.py',
        description='Standalone MSF session inspector/interactor for h3x-dash labs.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Connection via env: MSF_HOST MSF_PORT MSF_PASS MSF_SSL  '
               '(or the flags below).')
    p.add_argument('--host', default=DEF_HOST, help=f'msfrpcd host (default {DEF_HOST})')
    p.add_argument('--port', type=int, default=DEF_PORT, help=f'msfrpcd port (default {DEF_PORT})')
    p.add_argument('--password', default=DEF_PASS, help='msfrpcd password (default msfrpc)')
    p.add_argument('--ssl', action='store_true', default=DEF_SSL, help='use SSL first')
    p.add_argument('--api', default=DEF_API, help=f'h3x-dash API base (default {DEF_API})')
    p.add_argument('--no-api', action='store_true', help='skip the h3x-dash API comparison')
    p.add_argument('--timeout', type=int, default=15, help='per-command read timeout (s)')

    sub = p.add_subparsers(dest='command')
    sub.add_parser('list', help='list live sessions + diff against the UI')
    pi = sub.add_parser('info', help='detailed info for one session'); pi.add_argument('id')
    pr = sub.add_parser('run', help='run one command in a session')
    pr.add_argument('id'); pr.add_argument('cmd', nargs=argparse.REMAINDER)
    px = sub.add_parser('interact', help='interactive session prompt'); px.add_argument('id')
    pw = sub.add_parser('watch', help='poll + flag appear/disappear events')
    pw.add_argument('secs', nargs='?', default=2)
    sub.add_parser('doctor', help='full msfrpcd ⇄ API ⇄ jobs diagnostic')
    sub.add_parser('jobs', help='list active jobs / handlers')
    ph = sub.add_parser('handler',
                        help='start a standalone multi/handler + watch for the callback')
    ph.add_argument('lport', help='listen port (LPORT)')
    ph.add_argument('--payload', default='cmd/unix/reverse_perl',
                    help='payload to handle (default cmd/unix/reverse_perl)')
    ph.add_argument('--lhost', default=None, help='bind/listen address (default 0.0.0.0)')
    pk = sub.add_parser('kill-job', help='stop a running job by id')
    pk.add_argument('id')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.command:
        args.command = 'list'
    client, label = connect(args.host, args.port, args.password, args.ssl)

    if args.command == 'list':
        cmd_list(args, client)
    elif args.command == 'info':
        cmd_info(args, client)
    elif args.command == 'run':
        if not args.cmd:
            die('run needs a command:  session.py run <id> <command...>')
        cmd_run(args, client)
    elif args.command == 'interact':
        cmd_interact(args, client)
    elif args.command == 'watch':
        cmd_watch(args, client)
    elif args.command == 'doctor':
        cmd_doctor(args, client, label)
    elif args.command == 'jobs':
        cmd_jobs(args, client)
    elif args.command == 'handler':
        cmd_handler(args, client)
    elif args.command == 'kill-job':
        cmd_killjob(args, client)


if __name__ == '__main__':
    main()
