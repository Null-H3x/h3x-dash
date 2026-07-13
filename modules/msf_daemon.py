"""
H3x-Dash MsfDaemon
Manages the msfrpcd process lifecycle.

Checks if msfrpcd is already listening, starts it if not.
Runs in a background thread so Flask comes up immediately.
The MsfEngine auto-connect loop takes over once the port opens.

Log:  /tmp/h3x_msfrpcd.log
PID:  /tmp/h3x_msfrpcd.pid
"""

import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

LOG_FILE = Path('/tmp/h3x_msfrpcd.log')
PID_FILE = Path('/tmp/h3x_msfrpcd.pid')

# Module-level state visible to the rest of the app
status: dict = {
    'state':   'unknown',   # 'checking' | 'already_running' | 'starting' |
                            # 'ready' | 'failed' | 'not_found' | 'skipped'
    'message': '',
    'pid':     None,
    'log':     str(LOG_FILE),
}
_lock = threading.Lock()


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _set(state: str, message: str, pid=None):
    with _lock:
        status['state']   = state
        status['message'] = message
        if pid is not None:
            status['pid'] = pid
    print(f'[H3x-Dash] msfrpcd: [{state.upper()}] {message}')


def ensure_msfrpcd(host='127.0.0.1', port=55553, password='msfrpc',
                   ssl=False, wait_timeout=120):
    """
    Blocking call — checks for msfrpcd, starts it if absent, waits until ready.
    Intended to be called from a daemon thread.
    Returns True if msfrpcd is reachable by the end, False otherwise.
    """
    _set('checking', f'Probing {host}:{port}...')

    # ── 1. Already running? ───────────────────────────────────────────────────
    if _port_open(host, port):
        _set('already_running', f'msfrpcd already listening on {host}:{port}')
        return True

    # ── 2. Find the binary ────────────────────────────────────────────────────
    msfrpcd = shutil.which('msfrpcd')
    if not msfrpcd:
        _set('not_found',
             'msfrpcd not found — install Metasploit Framework: '
             'sudo apt-get install metasploit-framework')
        return False

    # ── 3. Build command ──────────────────────────────────────────────────────
    # No -f flag — msfrpcd daemonizes itself without it.
    # -a binds to loopback only (no reason to expose RPC on LAN).
    cmd = [msfrpcd, '-P', password, '-p', str(port), '-a', host]
    if not ssl:
        cmd.append('-S')   # disable SSL — H3x-Dash connects with ssl=False

    _set('starting',
         f'Launching: {" ".join(cmd)}\n'
         f'          Log → {LOG_FILE}\n'
         f'          First run may take 30–90s while MSF loads modules...')

    # ── 4. Launch ─────────────────────────────────────────────────────────────
    try:
        LOG_FILE.write_text('')   # truncate previous log
        with open(LOG_FILE, 'a') as log_fh:
            proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                start_new_session=True,   # detach from h3x-dash.py's process group
            )
        PID_FILE.write_text(str(proc.pid))
        _set('starting', f'msfrpcd launched (PID {proc.pid}) — waiting for port...', pid=proc.pid)
    except PermissionError:
        _set('failed', 'Permission denied launching msfrpcd — are you running as root?')
        return False
    except Exception as exc:
        _set('failed', f'Could not launch msfrpcd: {exc}')
        return False

    # ── 5. Poll until ready ───────────────────────────────────────────────────
    deadline = time.monotonic() + wait_timeout
    elapsed  = 0

    while time.monotonic() < deadline:
        time.sleep(3)
        elapsed += 3

        if _port_open(host, port):
            _set('ready', f'msfrpcd ready after {elapsed}s — PID {proc.pid}')
            return True

        # Check if process exited early (crash / bad args)
        ret = proc.poll()
        if ret is not None:
            log_tail = _tail(LOG_FILE, 10)
            _set('failed',
                 f'msfrpcd exited with code {ret} after {elapsed}s.\n'
                 f'Last log lines:\n{log_tail}\n'
                 f'Full log: {LOG_FILE}')
            return False

        print(f'[H3x-Dash] msfrpcd starting... ({elapsed}s / {wait_timeout}s)')

    _set('failed',
         f'msfrpcd did not open port {port} within {wait_timeout}s. '
         f'Check {LOG_FILE} for details.')
    return False


def stop_msfrpcd():
    """
    Stop the msfrpcd instance H3x-Dash started, if we have its PID.
    Safe to call even if we didn't start it — just a no-op in that case.
    """
    if not PID_FILE.exists():
        print('[H3x-Dash] msfrpcd: no PID file — not managed by H3x-Dash')
        return
    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, 15)   # SIGTERM — graceful shutdown
        PID_FILE.unlink(missing_ok=True)
        print(f'[H3x-Dash] msfrpcd (PID {pid}) stopped')
    except ProcessLookupError:
        PID_FILE.unlink(missing_ok=True)
        print('[H3x-Dash] msfrpcd: process not found — may have already exited')
    except ValueError:
        PID_FILE.unlink(missing_ok=True)
        print('[H3x-Dash] msfrpcd: PID file corrupted')
    except Exception as exc:
        print(f'[H3x-Dash] msfrpcd stop failed: {exc}')


def start_background(host='127.0.0.1', port=55553, password='msfrpc',
                     ssl=False, wait_timeout=120):
    """
    Non-blocking entry point — runs ensure_msfrpcd() in a daemon thread.
    Flask starts immediately; dashboard polls /api/msf/daemon for status.
    MsfEngine auto-connect loop takes over once the port is open.
    """
    t = threading.Thread(
        target  = _daemon_worker,
        args    = (host, port, password, ssl, wait_timeout),
        daemon  = True,
        name    = 'h3x-msfrpcd',
    )
    t.start()
    return t


def _daemon_worker(host, port, password, ssl, wait_timeout):
    ok = ensure_msfrpcd(host=host, port=port, password=password,
                         ssl=ssl, wait_timeout=wait_timeout)
    if not ok and status['state'] not in ('already_running', 'ready'):
        print('[H3x-Dash] msfrpcd could not be started automatically.')
        print('[H3x-Dash] Start it manually: msfrpcd -P msfrpc -S -f')


def get_status() -> dict:
    with _lock:
        return dict(status)


# ── Utilities ─────────────────────────────────────────────────────────────────

def _tail(path: Path, n: int = 10) -> str:
    """Return the last n lines of a file."""
    try:
        lines = path.read_text(errors='replace').splitlines()
        return '\n'.join(lines[-n:])
    except Exception:
        return '(could not read log)'
