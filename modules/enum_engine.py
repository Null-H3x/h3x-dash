"""
H3x-Dash EnumEngine
Post-scan enumeration dispatcher. Triggered by open port data from NmapEngine.
Runs service-specific Kali tools in parallel threads per host, streams output
via SSE callback, and builds structured findings that enrich the CVE chain.

Tool install reference (Kali):
    sudo apt-get install -y nikto whatweb gobuster sslyze enum4linux-ng \
        smbmap netexec onesixtyone snmp dnsrecon ldap-utils ssh-audit
"""

import ftplib
import json
import re
import shutil
import socket
import subprocess
import threading
import urllib.request
from pathlib import Path

from config import H3xConfig
from modules.preflight import validate_ip

# ── Tool availability check ───────────────────────────────────────────────────

# Common Kali/Debian tool directories — checked explicitly when shutil.which()
# returns None. Under 'sudo', the secure_path in /etc/sudoers often strips
# directories that appear in the interactive shell PATH, causing tools to appear
# absent even when they're installed.
_KALI_PATHS = [
    '/usr/bin', '/usr/sbin',
    '/usr/local/bin', '/usr/local/sbin',
    '/bin', '/sbin',
    '/usr/games', '/usr/local/games',
]


def _which(tool: str) -> str | None:
    """
    Find a tool binary. Tries shutil.which() first (respects PATH), then falls
    back to an explicit walk of common Kali installation directories so that
    tools installed via apt are found even when sudo strips PATH.
    """
    import os as _os

    found = shutil.which(tool)
    if found:
        return found

    # Explicit fallback — covers the sudo secure_path stripping case
    for directory in _KALI_PATHS:
        candidate = _os.path.join(directory, tool)
        if _os.path.isfile(candidate) and _os.access(candidate, _os.X_OK):
            return candidate

    return None


# ── Port → tool trigger map ───────────────────────────────────────────────────
# Maps open port numbers to candidate tool IDs.  Actual execution is gated by
# TOOL_TIERS so Recon stays fast (httpx/whatweb), Standard adds depth (nikto,
# gobuster, enum4linux), and Deep is opt-in (nuclei, feroxbuster, CMS scans).

_WEB_TOOLS      = ['httpx', 'wafw00f', 'whatweb', 'nikto', 'gobuster',
                   'wpscan', 'droopescan', 'ffuf', 'feroxbuster', 'nuclei']
_WEB_TLS_TOOLS  = ['sslscan', 'sslyze', 'testssl']
_WEB_SSL_TOOLS  = ['httpx', 'wafw00f', 'whatweb', 'nikto', 'gobuster_ssl',
                   'wpscan', 'droopescan', 'ffuf', 'feroxbuster', 'nuclei']

PORT_TOOLS: dict[int, list[str]] = {
    21:    ['ftp_anon', 'searchsploit'],
    22:    ['ssh_audit', 'searchsploit'],
    25:    ['smtp_enum'],
    53:    ['dnsrecon', 'dnsenum'],
    80:    list(_WEB_TOOLS),
    88:    ['kerbrute'],
    110:   ['smtp_enum'],
    137:   ['nbtscan'],
    139:   ['nbtscan', 'smbnull', 'rpcnull', 'enum4linux', 'smbmap'],
    161:   ['snmp_check'],
    389:   ['ldap_enum', 'ldapdomaindump', 'kerbrute'],
    443:   list(_WEB_TLS_TOOLS) + list(_WEB_SSL_TOOLS),
    445:   ['smbnull', 'rpcnull', 'enum4linux', 'smbmap', 'netexec',
            'searchsploit'],
    636:   ['sslscan', 'sslyze', 'testssl', 'ldap_enum', 'ldapdomaindump'],
    1433:  ['searchsploit'],
    3306:  ['searchsploit'],
    3389:  ['rdp_check'],
    5432:  ['searchsploit'],
    5900:  ['vnc_check'],
    6379:  ['redis_check'],
    1099:  ['rmi_check', 'searchsploit'],
    3632:  ['distcc_check', 'searchsploit'],
    6667:  ['irc_check', 'searchsploit'],
    8080:  list(_WEB_TOOLS),
    8443:  list(_WEB_TLS_TOOLS) + list(_WEB_SSL_TOOLS),
    9200:  ['elastic_check', 'nuclei'],
    27017: ['mongo_check'],
}

# Service name triggers (supplement port-based triggers)
SERVICE_TOOLS: dict[str, list[str]] = {
    'http':          list(_WEB_TOOLS),
    'https':         list(_WEB_TLS_TOOLS) + list(_WEB_SSL_TOOLS),
    'ssl/http':      list(_WEB_TLS_TOOLS) + list(_WEB_SSL_TOOLS),
    'ftp':           ['ftp_anon', 'searchsploit'],
    'ssh':           ['ssh_audit', 'searchsploit'],
    'smtp':          ['smtp_enum'],
    'domain':        ['dnsrecon', 'dnsenum'],
    'smb':           ['smbnull', 'rpcnull', 'enum4linux', 'smbmap', 'netexec'],
    'microsoft-ds':  ['smbnull', 'rpcnull', 'enum4linux', 'smbmap', 'netexec'],
    'netbios-ssn':   ['nbtscan', 'smbnull', 'rpcnull', 'enum4linux', 'smbmap'],
    'snmp':          ['snmp_check'],
    'ldap':          ['ldap_enum', 'ldapdomaindump', 'kerbrute'],
    'kerberos-sec':  ['kerbrute'],
    'rdp':           ['rdp_check'],
    'ms-wbt-server': ['rdp_check'],
    'vnc':           ['vnc_check'],
    'redis':         ['redis_check'],
    'elasticsearch': ['elastic_check', 'nuclei'],
    'mongodb':       ['mongo_check'],
    'rmiregistry':   ['rmi_check', 'searchsploit'],
    'java-rmi':      ['rmi_check', 'searchsploit'],
    'distccd':       ['distcc_check', 'searchsploit'],
    'distcc':        ['distcc_check', 'searchsploit'],
    'irc':           ['irc_check', 'searchsploit'],
}

TOOL_LABELS: dict[str, str] = {
    'whatweb':      'WhatWeb',
    'nikto':        'Nikto',
    'gobuster':     'GoBuster',
    'gobuster_ssl': 'GoBuster (SSL)',
    'sslyze':       'SSLyze',
    'enum4linux':   'enum4linux-ng',
    'smbmap':       'smbmap',
    'netexec':      'NetExec',
    'snmp_check':   'onesixtyone + snmpwalk',
    'smtp_enum':    'smtp-user-enum',
    'ldap_enum':    'ldapsearch',
    'dnsrecon':     'dnsrecon',
    'ftp_anon':     'FTP anon check',
    'ssh_audit':    'ssh-audit',
    'rdp_check':    'rdp-sec-check (nmap NSE)',
    'vnc_check':    'VNC probe',
    'redis_check':  'Redis probe',
    'elastic_check':'Elasticsearch probe',
    'mongo_check':  'MongoDB probe',
    'distcc_check': 'distccd probe (3632)',
    'irc_check':    'IRC banner probe (6667)',
    'rmi_check':    'Java RMI registry probe (1099)',
    'searchsploit': 'searchsploit',
    'httpx':        'httpx (HTTP triage)',
    'nbtscan':      'nbtscan (NetBIOS)',
    'feroxbuster':  'feroxbuster (content discovery)',
    'nuclei':       'nuclei (template scan)',
    'testssl':      'testssl.sh (deep TLS)',
    'wpscan':       'wpscan (WordPress)',
    'droopescan':   'droopescan (Drupal)',
    'kerbrute':     'kerbrute (Kerberos user enum)',
    'ldapdomaindump': 'ldapdomaindump (AD LDAP dump)',
    'wafw00f':      'wafw00f (WAF / CDN fingerprint)',
    'ffuf':         'ffuf (web fuzzer)',
    'dnsenum':      'dnsenum (DNS enum)',
    'sslscan':      'sslscan (fast TLS)',
    'smbnull':      'smbclient (null-session)',
    'rpcnull':      'rpcclient (null-session)',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

# ── Sweep depth tiers ─────────────────────────────────────────────────────────
# A tool runs only when its tier <= the operator-selected sweep depth.
#   TIER 1 RECON    — httpx, whatweb, wafw00f, sslscan, NetBIOS/null-session
#   TIER 2 STANDARD — nikto, gobuster, enum4linux, sslyze, snmp, ldap, …
#   TIER 3 DEEP     — nuclei, feroxbuster, testssl, CMS scanners, ffuf
TIER_RECON, TIER_STANDARD, TIER_DEEP = 1, 2, 3

TOOL_TIERS: dict[str, int] = {
    # ── Tier 1 — Recon (fast, low-noise) ──────────────────────────────────────
    'httpx':         TIER_RECON,
    'whatweb':       TIER_RECON,
    'wafw00f':       TIER_RECON,
    'sslscan':       TIER_RECON,
    'nbtscan':       TIER_RECON,
    'smbnull':       TIER_RECON,
    'rpcnull':       TIER_RECON,
    'ftp_anon':      TIER_RECON,
    'vnc_check':     TIER_RECON,
    'redis_check':   TIER_RECON,
    'elastic_check': TIER_RECON,
    'mongo_check':   TIER_RECON,
    'distcc_check':  TIER_RECON,
    'irc_check':     TIER_RECON,
    'rmi_check':     TIER_RECON,
    'searchsploit':  TIER_RECON,
    # ── Tier 2 — Standard (default depth) ─────────────────────────────────────
    'nikto':         TIER_STANDARD,
    'gobuster':      TIER_STANDARD,
    'gobuster_ssl':  TIER_STANDARD,
    'sslyze':        TIER_STANDARD,
    'enum4linux':    TIER_STANDARD,
    'smbmap':        TIER_STANDARD,
    'netexec':       TIER_STANDARD,
    'snmp_check':    TIER_STANDARD,
    'smtp_enum':     TIER_STANDARD,
    'ldap_enum':     TIER_STANDARD,
    'dnsrecon':      TIER_STANDARD,
    'ssh_audit':     TIER_STANDARD,
    'rdp_check':     TIER_STANDARD,
    'kerbrute':      TIER_STANDARD,
    'ldapdomaindump':TIER_STANDARD,
    # ── Tier 3 — Deep (slow / loud / opt-in) ──────────────────────────────────
    'nuclei':        TIER_DEEP,
    'feroxbuster':   TIER_DEEP,
    'testssl':       TIER_DEEP,
    'wpscan':        TIER_DEEP,
    'droopescan':    TIER_DEEP,
    'ffuf':          TIER_DEEP,
    'dnsenum':       TIER_DEEP,
}

TIER_LABELS = {
    TIER_RECON:    'Recon',
    TIER_STANDARD: 'Standard',
    TIER_DEEP:     'Deep',
}

# Tool Availability panel — grouped by enumeration purpose (binary keys from
# available_tools(), display labels for the UI).
TOOL_AVAILABILITY_CATEGORIES: list[tuple[str, list[tuple[str, str]]]] = [
    ('Network & HTTP Triage', [
        ('nmap',     'Nmap'),
        ('httpx',    'httpx'),
        ('nbtscan',  'nbtscan'),
    ]),
    ('Web Enumeration', [
        ('whatweb',      'WhatWeb'),
        ('wafw00f',      'wafw00f'),
        ('nikto',        'Nikto'),
        ('gobuster',     'GoBuster'),
        ('feroxbuster',  'feroxbuster'),
        ('ffuf',         'ffuf'),
        ('nuclei',       'nuclei'),
        ('wpscan',       'wpscan'),
        ('droopescan',   'droopescan'),
    ]),
    ('TLS & Certificates', [
        ('sslscan',    'sslscan'),
        ('sslyze',     'SSLyze'),
        ('testssl.sh', 'testssl.sh'),
    ]),
    ('SMB / Windows', [
        ('enum4linux-ng', 'enum4linux-ng'),
        ('smbmap',        'smbmap'),
        ('netexec',       'NetExec'),
        ('smbclient',     'smbclient'),
        ('rpcclient',     'rpcclient'),
    ]),
    ('Active Directory', [
        ('ldapsearch',      'ldapsearch'),
        ('ldapdomaindump',  'ldapdomaindump'),
        ('kerbrute',        'kerbrute'),
    ]),
    ('DNS', [
        ('dnsrecon', 'dnsrecon'),
        ('dnsenum',  'dnsenum'),
    ]),
    ('Infrastructure Services', [
        ('onesixtyone', 'onesixtyone'),
        ('snmpwalk',    'snmpwalk'),
        ('ssh-audit',   'ssh-audit'),
    ]),
    ('Exploit Intelligence', [
        ('searchsploit', 'searchsploit'),
    ]),
]


# ── State ─────────────────────────────────────────────────────────────────────

class EnumState:
    IDLE     = 'idle'
    RUNNING  = 'running'
    COMPLETE = 'complete'
    ERROR    = 'error'


# ── EnumEngine ────────────────────────────────────────────────────────────────

class EnumEngine:

    def __init__(self):
        self._state       = EnumState.IDLE
        self._findings    = {}   # {ip: [finding_dict, ...]}
        self._tool_status = {}   # {ip: {tool_id: 'pending'|'running'|'done'|'error'|'skip'}}
        self._lock        = threading.Lock()
        self._stop_evt    = threading.Event()   # set by stop_all() → halts enum
        self._active      = set()                # live subprocess.Popen handles

    # ── Public API ────────────────────────────────────────────────────────────

    def start_enum(self, hosts: list, params: dict,
                   on_output=None, on_finding=None, on_complete=None) -> bool:
        with self._lock:
            if self._state == EnumState.RUNNING:
                return False
            self._state       = EnumState.RUNNING
            self._findings    = {}
            self._tool_status = {}
            self._stop_evt.clear()

        threading.Thread(
            target  = self._run,
            args    = (hosts, params, on_output, on_finding, on_complete),
            daemon  = True,
            name    = 'h3x-enum',
        ).start()
        return True

    def stop_all(self) -> dict:
        """Operator / CEASE halt for enumeration.

        Sets the stop flag (which suppresses any pending tool launches inside
        _run_cmd) then process-group-kills every in-flight subprocess so the
        grandchildren (rpcclient, smbclient, polenum, …) die with their parent.
        Returns an honest count of what was actually killed — never fabricated.
        """
        import os, signal
        with self._lock:
            self._stop_evt.set()
            procs = list(self._active)
            self._active.clear()
            self._state = EnumState.IDLE
        killed = 0
        for p in procs:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                killed += 1
            except Exception:
                try:
                    p.kill()
                    killed += 1
                except Exception:
                    pass
        return {'stopped': True, 'killed': killed, 'count': killed}

    def get_status(self) -> dict:
        return {
            'state':         self._state,
            'tool_status':   self._tool_status,
            'finding_count': sum(len(v) for v in self._findings.values()),
        }

    def get_findings(self) -> dict:
        return self._findings

    def get_findings_flat(self) -> list:
        with self._lock:
            # Snapshot the dict and each list before iterating
            snapshot = {ip: list(lst) for ip, lst in self._findings.items()}
        flat = []
        for ip, findings in snapshot.items():
            for f in findings:
                flat.append({**f, 'host_ip': ip})
        return sorted(flat, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 4))

    def get_findings_for_host(self, ip: str) -> list:
        return self._findings.get(ip, [])

    def get_finding_count(self) -> int:
        return sum(len(v) for v in self._findings.values())

    @staticmethod
    def available_tools() -> dict[str, bool]:
        return {
            'whatweb':       bool(_which('whatweb')),
            'nikto':         bool(_which('nikto')),
            'gobuster':      bool(_which('gobuster')),
            'sslyze':        bool(_which('sslyze')),
            'enum4linux-ng': bool(_which('enum4linux-ng') or _which('enum4linux')),
            'smbmap':        bool(_which('smbmap')),
            'netexec':       bool(_which('netexec') or _which('nxc') or _which('crackmapexec')),
            'onesixtyone':   bool(_which('onesixtyone')),
            'snmpwalk':      bool(_which('snmpwalk')),
            'dnsrecon':      bool(_which('dnsrecon')),
            'ldapsearch':    bool(_which('ldapsearch')),
            'ssh-audit':     bool(_which('ssh-audit')),
            'searchsploit':  bool(_which('searchsploit')),
            'nmap':          bool(_which('nmap')),
            'httpx':         bool(_which('httpx') or _which('httpx-toolkit')),
            'nbtscan':       bool(_which('nbtscan')),
            'feroxbuster':   bool(_which('feroxbuster')),
            'nuclei':        bool(_which('nuclei')),
            'testssl.sh':    bool(_which('testssl') or _which('testssl.sh')),
            'wpscan':        bool(_which('wpscan')),
            'droopescan':    bool(_which('droopescan')),
            'kerbrute':      bool(_which('kerbrute')),
            'ldapdomaindump': bool(_which('ldapdomaindump')),
            'wafw00f':       bool(_which('wafw00f')),
            'ffuf':          bool(_which('ffuf')),
            'dnsenum':       bool(_which('dnsenum')),
            'sslscan':       bool(_which('sslscan')),
            'smbclient':     bool(_which('smbclient')),
            'rpcclient':     bool(_which('rpcclient')),
        }

    @staticmethod
    def tool_availability_layout() -> list[dict]:
        """Category-grouped tool availability for the Enumerate tab UI."""
        avail = EnumEngine.available_tools()
        layout = []
        seen: set[str] = set()
        for title, tools in TOOL_AVAILABILITY_CATEGORIES:
            items = []
            for key, label in tools:
                seen.add(key)
                items.append({
                    'key':       key,
                    'label':     label,
                    'available': avail.get(key, False),
                })
            layout.append({'title': title, 'tools': items})
        extras = sorted(k for k in avail if k not in seen)
        if extras:
            layout.append({
                'title': 'Other',
                'tools': [{'key': k, 'label': k, 'available': avail[k]}
                          for k in extras],
            })
        return layout

    # ── Orchestrator ──────────────────────────────────────────────────────────

    def _run(self, hosts, params, on_output, on_finding, on_complete):
        def emit(line):
            if on_output:
                on_output(line)

        # Cap concurrent host threads — avoids spawning 50+ subprocess trees on a /24
        _HOST_CONCURRENCY = 8
        _sem = threading.Semaphore(_HOST_CONCURRENCY)

        try:
            emit(f'[H3x-Dash] Enumeration started — {len(hosts)} host(s) queued '
                 f'(max {_HOST_CONCURRENCY} concurrent)')

            host_threads = []
            for host in hosts:
                ip = host.get('ip')
                if not ip:
                    continue
                with self._lock:
                    self._findings[ip]    = []
                    self._tool_status[ip] = {}

                def _target(h=host, s=_sem):
                    with s:
                        self._enumerate_host(h, params, on_output, on_finding)

                t = threading.Thread(
                    target = _target,
                    daemon = True,
                    name   = f'h3x-enum-{ip}',
                )
                host_threads.append(t)
                t.start()

            for t in host_threads:
                t.join()

            total = self.get_finding_count()
            with self._lock:
                self._state = EnumState.COMPLETE

            emit(f'[H3x-Dash] Enumeration complete — {total} finding(s) across {len(hosts)} host(s)')
            if on_complete:
                on_complete(self._findings)

        except Exception as exc:
            with self._lock:
                self._state = EnumState.ERROR
            emit(f'[ERROR] Enumeration crashed: {exc}')

    def _enumerate_host(self, host, params, on_output, on_finding):
        ip    = host.get('ip', '')
        ports = host.get('ports', [])

        # Validate IP before passing to any subprocess
        if not validate_ip(ip):
            if on_output:
                on_output(f'[SKIP] Invalid/unsafe IP rejected: {ip!r}')
            return

        def emit(line):
            if on_output:
                on_output(f'[{ip}] {line}')

        def finding(f):
            with self._lock:
                self._findings[ip].append(f)
            enriched = {**f, 'host_ip': ip}
            # Credential capture hook — set by h3x-dash.py on the engine.
            # Failures here are swallowed so cred-store issues never break enum.
            hook = getattr(self, 'on_finding_hook', None)
            if hook is not None:
                try:
                    hook(enriched)
                except Exception:
                    pass
            if on_finding:
                on_finding(enriched)

        # Build tool dispatch table for this host
        # tool_id -> best context (port, service, version)
        dispatch: dict[str, dict] = {}

        for port_info in ports:
            port_num = port_info.get('port')
            service  = (port_info.get('service') or '').lower().strip()
            version  = (port_info.get('version') or '').strip()
            ctx      = {'port': port_num, 'service': service, 'version': version}

            for tool in PORT_TOOLS.get(port_num, []):
                dispatch.setdefault(tool, ctx)

            for svc_key, tool_list in SERVICE_TOOLS.items():
                if svc_key in service:
                    for tool in tool_list:
                        dispatch.setdefault(tool, ctx)

        if not dispatch:
            emit('No enumeration tools triggered — no recognised service ports')
            return

        # ── Filter by sweep depth tier ────────────────────────────────────────
        # A tool runs only if its tier <= the selected depth. Default STANDARD,
        # so Tier-3 tools (nuclei, feroxbuster, testssl) are strictly opt-in.
        try:
            tier = int(params.get('tier', TIER_STANDARD))
        except (TypeError, ValueError):
            tier = TIER_STANDARD
        tier = max(TIER_RECON, min(TIER_DEEP, tier))   # clamp to 1..3

        before = set(dispatch)
        dispatch = {tid: ctx for tid, ctx in dispatch.items()
                    if TOOL_TIERS.get(tid, TIER_STANDARD) <= tier}
        gated = before - set(dispatch)

        emit(f'Sweep depth: {TIER_LABELS.get(tier, tier)} (tier {tier})')
        if gated:
            emit(f'Gated by tier: {", ".join(sorted(TOOL_LABELS.get(t, t) for t in gated))}')
        if not dispatch:
            emit('All triggered tools are above the selected sweep depth — '
                 'raise the tier to enumerate this host')
            return

        emit(f'Tools: {", ".join(TOOL_LABELS.get(t, t) for t in dispatch)}')

        for tool_id, ctx in dispatch.items():
            with self._lock:
                self._tool_status[ip][tool_id] = 'running'

            emit(f'── {TOOL_LABELS.get(tool_id, tool_id)} ──')
            try:
                runner = getattr(self, f'_run_{tool_id}', None)
                if runner:
                    runner(ip, ctx, emit, finding, params)
                    status = 'done'
                else:
                    emit(f'[SKIP] No runner for {tool_id}')
                    status = 'skip'
            except Exception as exc:
                emit(f'[ERROR] {TOOL_LABELS.get(tool_id, tool_id)}: {exc}')
                status = 'error'

            with self._lock:
                self._tool_status[ip][tool_id] = status

    # ── Subprocess helper ─────────────────────────────────────────────────────

    def _run_cmd(self, cmd: list, emit, timeout: int = 120) -> tuple[int, list[str]]:
        """
        Run a command, stream stdout line by line via emit(), return (rc, lines).

        Process-group kill (the important part)
        ───────────────────────────────────────
        Tools like enum4linux-ng spawn their OWN children (rpcclient, smbclient,
        polenum, nmblookup). Those grandchildren inherit our stdout pipe FD.
        If we kill only the direct child with proc.kill(), the grandchildren
        survive, keep the pipe open, and `for raw in proc.stdout` blocks on an
        EOF that never arrives — the read loop hangs forever despite the timer
        firing. This is THE cause of enum hanging on "Password Policy Information"
        against Windows hosts.

        Fix: start_new_session=True puts the child in its own process group, and
        os.killpg() on timeout kills the entire tree — grandchildren included —
        so the pipe closes and the loop exits.
        """
        import re as _re
        import os, signal

        # CEASE: once stop_all() has fired, suppress any further tool launches so
        # the enum unwinds instead of marching through its remaining tool list.
        if self._stop_evt.is_set():
            emit(f'[CEASE] {cmd[0]} suppressed — enum halted')
            return -4, []

        _ansi = _re.compile(r'\x1b\[[0-9;]*[mGKHF]')

        lines: list[str] = []
        proc: subprocess.Popen | None = None
        _timed_out = threading.Event()

        def _kill_tree(p):
            """Kill the process group, falling back to single-process kill."""
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors='replace',
                start_new_session=True,    # own process group → killpg reaches kids
            )
            with self._lock:
                self._active.add(proc)     # tracked so stop_all() can killpg it

            def _kill():
                _timed_out.set()
                _kill_tree(proc)

            timer = threading.Timer(timeout, _kill)
            timer.start()
            try:
                for raw in proc.stdout:
                    line = _ansi.sub('', raw.rstrip())
                    if line:
                        lines.append(line)
                        emit(line)
            finally:
                timer.cancel()

            proc.wait()
            if _timed_out.is_set():
                emit(f'[TIMEOUT] {cmd[0]} killed after {timeout}s '
                     f'(process group terminated)')
                return -1, lines
            return proc.returncode, lines

        except FileNotFoundError:
            emit(f'[SKIP] {cmd[0]} not found')
            return -2, lines
        except Exception as exc:
            emit(f'[ERROR] {cmd[0]}: {exc}')
            return -3, lines
        finally:
            if proc is not None:
                with self._lock:
                    self._active.discard(proc)
            if proc and proc.poll() is None:
                _kill_tree(proc)

    # ── Tool runners ──────────────────────────────────────────────────────────

    # ── WhatWeb ───────────────────────────────────────────────────────────────
    def _run_whatweb(self, ip, ctx, emit, finding, params):
        if not _which('whatweb'):
            emit('[SKIP] whatweb: sudo apt-get install whatweb')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        tmp    = f'/tmp/h3x_whatweb_{ip}_{port}.json'
        emit(f'WhatWeb → {url}')
        self._run_cmd(['whatweb', '--log-json', tmp, '-a', '3', '--quiet', url], emit, 60)
        p = Path(tmp)
        try:
            if p.exists():
                try:
                    data = json.loads(p.read_text())
                    entries = data if isinstance(data, list) else [data]
                    for entry in entries:
                        for plugin, info in entry.get('plugins', {}).items():
                            ver = info.get('version', [])
                            finding({
                                'tool': 'whatweb', 'type': 'web_tech', 'severity': 'INFO',
                                'port': port,
                                'title': f'{plugin}{" " + ver[0] if ver else ""}',
                                'detail': f'Technology detected on {url}',
                            })
                except Exception:
                    pass
        finally:
            Path(tmp).unlink(missing_ok=True)

    # ── Nikto ─────────────────────────────────────────────────────────────────
    def _run_nikto(self, ip, ctx, emit, finding, params):
        if not _which('nikto'):
            emit('[SKIP] nikto: sudo apt-get install nikto')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        emit(f'Nikto → {scheme}://{ip}:{port}')
        cmd = ['nikto', '-h', ip, '-p', str(port),
               '-Tuning', '1234567890abc', '-maxtime', '90s', '-nointeractive']
        if scheme == 'https':
            cmd.append('-ssl')
        _, lines = self._run_cmd(cmd, emit, 120)
        for line in lines:
            if line.startswith('+ ') and any(kw in line for kw in
                    ['OSVDB', 'CVE', 'allows', 'vulner', 'disclose', 'expose',
                     'default', 'install', 'admin', 'backup', 'config']):
                cve_m = re.search(r'CVE-[\d-]+', line)
                cve   = cve_m.group() if cve_m else None
                finding({
                    'tool': 'nikto', 'type': 'web_vuln',
                    'severity': 'HIGH' if cve else 'MEDIUM',
                    'port': port, 'cve': cve,
                    'title': line.strip().lstrip('+ '),
                    'detail': line.strip(),
                })

    # ── GoBuster ──────────────────────────────────────────────────────────────
    def _run_gobuster(self, ip, ctx, emit, finding, params):
        self._gobuster_impl(ip, ctx, emit, finding, ssl=False)

    def _run_gobuster_ssl(self, ip, ctx, emit, finding, params):
        self._gobuster_impl(ip, ctx, emit, finding, ssl=True)

    def _gobuster_impl(self, ip, ctx, emit, finding, ssl=False):
        if not _which('gobuster'):
            emit('[SKIP] gobuster: sudo apt-get install gobuster')
            return
        port      = ctx['port']
        wordlist  = '/usr/share/wordlists/dirb/common.txt'
        if not Path(wordlist).exists():
            emit('[SKIP] dirb wordlist missing: sudo apt-get install dirb')
            return
        scheme = 'https' if ssl else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'GoBuster → {url}')
        cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist,
               '-q', '-t', '20', '--timeout', '5s']
        if ssl:
            cmd.append('-k')
        _, lines = self._run_cmd(cmd, emit, 120)
        for line in lines:
            sc_m = re.search(r'\(Status: (\d+)\)', line)
            sc   = int(sc_m.group(1)) if sc_m else 0
            if sc in (200, 204, 301, 302, 401, 403):
                finding({
                    'tool': 'gobuster', 'type': 'web_dir',
                    'severity': 'HIGH' if sc in (200, 301, 302) else 'MEDIUM',
                    'port': port,
                    'title': line.strip(),
                    'detail': f'HTTP {sc} — {line.strip()}',
                })

    # ── SSLyze ────────────────────────────────────────────────────────────────
    def _run_sslyze(self, ip, ctx, emit, finding, params):
        if not _which('sslyze'):
            emit('[SKIP] sslyze: sudo apt-get install sslyze')
            return
        port = ctx['port']
        tmp  = f'/tmp/h3x_sslyze_{ip}_{port}.json'
        emit(f'SSLyze → {ip}:{port}')
        self._run_cmd(['sslyze', f'{ip}:{port}', f'--json_out={tmp}'], emit, 90)
        p = Path(tmp)
        try:
            if p.exists():
                try:
                    data = json.loads(p.read_text())
                    for srv in data.get('server_scan_results', []):
                        r = srv.get('scan_result', {})
                        hb = r.get('heartbleed', {}).get('result', {})
                        if hb.get('is_vulnerable_to_heartbleed'):
                            finding({'tool':'sslyze','type':'ssl_vuln','severity':'CRITICAL',
                                     'port':port,'cve':'CVE-2014-0160',
                                     'title':'Heartbleed (CVE-2014-0160)',
                                     'detail':'Server is vulnerable to Heartbleed memory disclosure'})
                        if 'VULNERABLE' in str(r.get('robot',{}).get('result',{}).get('robot_result','')):
                            finding({'tool':'sslyze','type':'ssl_vuln','severity':'HIGH',
                                     'port':port,'title':'ROBOT Attack',
                                     'detail':'Bleichenbacher oracle detected — RSA decryption possible'})
                        if r.get('tls_1_0_cipher_suites',{}).get('result',{}).get('accepted_cipher_suites'):
                            finding({'tool':'sslyze','type':'ssl_vuln','severity':'MEDIUM',
                                     'port':port,'title':'TLS 1.0 Supported',
                                     'detail':'Legacy TLS 1.0 enabled — POODLE / BEAST risk'})
                        if r.get('tls_1_1_cipher_suites',{}).get('result',{}).get('accepted_cipher_suites'):
                            finding({'tool':'sslyze','type':'ssl_vuln','severity':'LOW',
                                     'port':port,'title':'TLS 1.1 Supported',
                                     'detail':'Legacy TLS 1.1 enabled — consider disabling'})
                except Exception:
                    pass
        finally:
            Path(tmp).unlink(missing_ok=True)

    # ── enum4linux-ng ─────────────────────────────────────────────────────────
    def _run_enum4linux(self, ip, ctx, emit, finding, params):
        tool = _which('enum4linux-ng') or _which('enum4linux')
        if not tool:
            emit('[SKIP] enum4linux-ng: sudo apt-get install enum4linux-ng')
            return
        emit(f'enum4linux-ng → {ip}')
        tmp = f'/tmp/h3x_e4l_{ip}'
        if 'ng' in tool:
            # -t 5  : 5s connection timeout per check. Without this, the
            #         password-policy + RID-cycling phases block for minutes
            #         against Windows hosts that respond slowly or not at all
            #         to the RPC calls enum4linux-ng issues. The outer 120s
            #         process-group kill is the backstop; -t makes each probe
            #         fail fast so the whole run finishes well under it.
            self._run_cmd([tool, '-A', '-t', '5', ip, '-oJ', tmp], emit, 120)
            jp = Path(tmp + '.json')
            try:
                if jp.exists():
                    try:
                        data = json.loads(jp.read_text())
                        for uid, info in data.get('users', {}).items():
                            uname = info.get('username', str(uid))
                            finding({'tool':'enum4linux','type':'user','severity':'HIGH',
                                     'port':445,'title':f'User: {uname}',
                                     'detail':f'RID {uid} — {info.get("name","")}',
                                     'username': uname})
                        for share, info in data.get('shares', {}).items():
                            access = info.get('access', 'UNKNOWN')
                            sev = ('CRITICAL' if 'WRITE' in str(access)
                                   else 'HIGH' if 'READ' in str(access) else 'INFO')
                            finding({'tool':'enum4linux','type':'smb_share','severity':sev,
                                     'port':445,'title':f'Share: \\\\{ip}\\{share} [{access}]',
                                     'detail':str(info)})
                        dom = data.get('domain', {})
                        if dom:
                            finding({'tool':'enum4linux','type':'domain_info','severity':'INFO',
                                     'port':445,'title':f'Domain: {dom.get("domain","")}',
                                     'detail':str(dom)})
                    except Exception:
                        pass
            finally:
                Path(tmp + '.json').unlink(missing_ok=True)
        else:
            self._run_cmd([tool, '-a', ip], emit, 180)

    # ── smbmap ────────────────────────────────────────────────────────────────
    def _run_smbmap(self, ip, ctx, emit, finding, params):
        if not _which('smbmap'):
            emit('[SKIP] smbmap: sudo apt-get install smbmap')
            return
        emit(f'smbmap → {ip}')
        _, lines = self._run_cmd(['smbmap', '-H', ip], emit, 60)
        for line in lines:
            if any(kw in line for kw in ['READ', 'WRITE', 'NO ACCESS']):
                sev = ('CRITICAL' if 'WRITE' in line
                       else 'HIGH' if 'READ' in line else 'INFO')
                finding({'tool':'smbmap','type':'smb_share','severity':sev,
                         'port':445,'title':line.strip(),'detail':line.strip()})

    # ── NetExec ───────────────────────────────────────────────────────────────
    def _run_netexec(self, ip, ctx, emit, finding, params):
        tool = _which('netexec') or _which('nxc') or _which('crackmapexec')
        if not tool:
            emit('[SKIP] netexec: sudo apt-get install netexec')
            return
        emit(f'NetExec SMB → {ip}')
        _, lines = self._run_cmd([tool, 'smb', ip], emit, 60)
        for line in lines:
            if 'SMBv1' in line and 'True' in line:
                finding({'tool':'netexec','type':'protocol_vuln','severity':'CRITICAL',
                         'port':445,'title':'SMBv1 Enabled — EternalBlue may be applicable',
                         'detail':line.strip(),
                         'msf_module':'auxiliary/scanner/smb/smb_ms17_010'})
            if 'signing' in line.lower() and 'False' in line:
                finding({'tool':'netexec','type':'protocol_vuln','severity':'HIGH',
                         'port':445,'title':'SMB Signing Disabled — relay attacks possible',
                         'detail':line.strip()})

    # ── SNMP ──────────────────────────────────────────────────────────────────
    def _run_snmp_check(self, ip, ctx, emit, finding, params):
        if not _which('onesixtyone'):
            emit('[SKIP] onesixtyone: sudo apt-get install onesixtyone')
            return
        emit(f'SNMP community strings → {ip}')
        _, lines = self._run_cmd(['onesixtyone', ip], emit, 30)
        communities = []
        for line in lines:
            m = re.search(r'\[(.+?)\]', line)
            if m:
                community = m.group(1)
                communities.append(community)
                finding({'tool':'snmp','type':'snmp_community','severity':'HIGH',
                         'port':161,'title':f'SNMP Community String: {community}',
                         'detail':line.strip()})
        if communities and _which('snmpwalk'):
            emit(f'snmpwalk -v2c -c {communities[0]} {ip} system')
            self._run_cmd(
                ['snmpwalk', '-v2c', '-c', communities[0], ip, '-t', '5', 'system'],
                emit, 60
            )

    # ── SMTP user enumeration ─────────────────────────────────────────────────
    def _run_smtp_enum(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 25)
        emit(f'SMTP user enum → {ip}:{port}')
        tool = _which('smtp-user-enum')
        if not tool:
            emit('[SKIP] smtp-user-enum not found — try: sudo apt-get install smtp-user-enum')
            return
        wordlist = '/usr/share/wordlists/metasploit/unix_users.txt'
        if not Path(wordlist).exists():
            wordlist = '/usr/share/wordlists/dirb/others/names.txt'
        if not Path(wordlist).exists():
            emit('[SKIP] No suitable username wordlist found')
            return
        _, lines = self._run_cmd(
            [tool, '-M', 'VRFY', '-U', wordlist, '-t', ip, '-p', str(port)],
            emit, 90
        )
        for line in lines:
            if 'exists' in line.lower():
                finding({'tool':'smtp_enum','type':'user','severity':'MEDIUM',
                         'port':port,'title':line.strip(),'detail':line.strip()})

    # ── LDAP ─────────────────────────────────────────────────────────────────
    def _run_ldap_enum(self, ip, ctx, emit, finding, params):
        if not _which('ldapsearch'):
            emit('[SKIP] ldapsearch: sudo apt-get install ldap-utils')
            return
        port = ctx.get('port', 389)
        emit(f'LDAP anonymous bind → {ip}:{port}')
        _, lines = self._run_cmd(
            ['ldapsearch', '-x', '-H', f'ldap://{ip}:{port}',
             '-b', '', '-s', 'base', 'namingContexts'],
            emit, 30
        )
        for line in lines:
            if any(kw in line for kw in ['namingContexts', 'defaultNamingContext', 'dc=']):
                finding({'tool':'ldap_enum','type':'ldap_info','severity':'HIGH',
                         'port':port,'title':f'LDAP Anon Bind: {line.strip()}',
                         'detail':'Anonymous LDAP bind successful — domain naming context exposed'})

    # ── dnsrecon ──────────────────────────────────────────────────────────────
    def _run_dnsrecon(self, ip, ctx, emit, finding, params):
        if not _which('dnsrecon'):
            emit('[SKIP] dnsrecon: sudo apt-get install dnsrecon')
            return
        emit(f'dnsrecon → {ip}')
        _, lines = self._run_cmd(
            ['dnsrecon', '-d', ip, '-t', 'std,axfr', '--lifetime', '5'],
            emit, 120
        )
        for line in lines:
            if 'Zone Transfer' in line and 'success' in line.lower():
                finding({'tool':'dnsrecon','type':'dns_axfr','severity':'CRITICAL',
                         'port':53,'title':'DNS Zone Transfer Allowed',
                         'detail':line.strip()})
            elif re.search(r'\b(A|MX|NS|SOA|TXT)\b', line) and ip not in line:
                finding({'tool':'dnsrecon','type':'dns_record','severity':'INFO',
                         'port':53,'title':line.strip(),'detail':line.strip()})

    # ── FTP anonymous login ───────────────────────────────────────────────────
    def _run_ftp_anon(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 21)
        emit(f'FTP anonymous login → {ip}:{port}')
        try:
            ftp = ftplib.FTP(timeout=10)
            ftp.connect(ip, port)
            ftp.login('anonymous', 'h3xdash@pentest.local')
            try:
                files = ftp.nlst()
            except Exception:
                files = []
            ftp.quit()
            finding({'tool':'ftp_anon','type':'anon_access','severity':'HIGH',
                     'port':port,
                     'title':f'FTP Anonymous Login Allowed — {len(files)} item(s) in root',
                     'detail':f'Files: {", ".join(files[:10])}'})
            emit(f'[+] Anonymous FTP login SUCCESS — {len(files)} item(s) listed')
        except ftplib.error_perm:
            emit('[-] Anonymous FTP login denied')
        except Exception as exc:
            emit(f'[-] FTP probe failed: {exc}')

    # ── ssh-audit ─────────────────────────────────────────────────────────────
    def _run_ssh_audit(self, ip, ctx, emit, finding, params):
        if not _which('ssh-audit'):
            emit('[SKIP] ssh-audit: sudo apt-get install ssh-audit')
            return
        port = ctx.get('port', 22)
        emit(f'ssh-audit → {ip}:{port}')
        _, lines = self._run_cmd(['ssh-audit', '-p', str(port), ip], emit, 60)
        for line in lines:
            if '-- [fail]' in line:
                finding({'tool':'ssh_audit','type':'ssh_config','severity':'HIGH',
                         'port':port,'title':line.strip(),'detail':line.strip()})
            elif '-- [warn]' in line:
                finding({'tool':'ssh_audit','type':'ssh_config','severity':'MEDIUM',
                         'port':port,'title':line.strip(),'detail':line.strip()})

    # ── RDP security check ────────────────────────────────────────────────────
    def _run_rdp_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 3389)
        emit(f'RDP NSE → {ip}:{port}')
        _, lines = self._run_cmd(
            ['nmap', '-p', str(port), '--script', 'rdp-enum-encryption',
             ip, '-Pn', '--open'],
            emit, 60
        )
        for line in lines:
            if 'Classic RDP' in line or 'RDP Security Layer' in line:
                finding({'tool':'rdp_check','type':'rdp_config','severity':'HIGH',
                         'port':port,
                         'title':'RDP: Classic/Legacy Security Layer Detected',
                         'detail':line.strip()})
            elif 'NLA' in line or 'CredSSP' in line:
                finding({'tool':'rdp_check','type':'rdp_config','severity':'INFO',
                         'port':port,'title':f'RDP: {line.strip()}','detail':line.strip()})

    # ── VNC probe ─────────────────────────────────────────────────────────────
    def _run_vnc_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 5900)
        emit(f'VNC NSE → {ip}:{port}')
        _, lines = self._run_cmd(
            ['nmap', '-p', str(port), '--script', 'vnc-info,vnc-auth-bypass',
             ip, '-Pn'],
            emit, 60
        )
        for line in lines:
            if any(kw in line for kw in ['Authentication disabled', 'None', 'No auth']):
                finding({'tool':'vnc_check','type':'vuln','severity':'CRITICAL',
                         'port':port,'title':'VNC: No Authentication Required',
                         'detail':line.strip(),
                         'msf_module':'auxiliary/scanner/vnc/vnc_none_auth'})

    # ── Redis probe ───────────────────────────────────────────────────────────
    def _run_redis_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 6379)
        emit(f'Redis probe → {ip}:{port}')
        try:
            s = socket.create_connection((ip, port), timeout=5)
            s.send(b'PING\r\n')
            resp = s.recv(64).decode('utf-8', errors='replace')
            s.close()
            if '+PONG' in resp:
                finding({'tool':'redis_check','type':'vuln','severity':'CRITICAL',
                         'port':port,
                         'title':'Redis: Unauthenticated Access (PING → PONG)',
                         'detail':'Redis answered PING without auth — RCE via replication possible',
                         'msf_module':'exploit/linux/redis/redis_replication_cmd_exec'})
                emit('[+] Redis UNAUTHENTICATED — PONG received')
            else:
                emit(f'[-] Redis response: {resp[:40]}')
        except Exception as exc:
            emit(f'[-] Redis probe: {exc}')

    # ── Elasticsearch probe ───────────────────────────────────────────────────
    def _run_elastic_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 9200)
        emit(f'Elasticsearch probe → {ip}:{port}')
        try:
            resp = urllib.request.urlopen(f'http://{ip}:{port}/', timeout=5)
            data = json.loads(resp.read())
            ver  = data.get('version', {}).get('number', 'unknown')
            finding({'tool':'elastic_check','type':'vuln','severity':'CRITICAL',
                     'port':port,
                     'title':f'Elasticsearch Open (unauthenticated) — v{ver}',
                     'detail':'No authentication required — cluster data accessible'})
            emit(f'[+] Elasticsearch OPEN — version {ver}')
        except Exception as exc:
            emit(f'[-] Elasticsearch probe: {exc}')

    # ── distccd probe (MT2 port 3632) ────────────────────────────────────────
    def _run_distcc_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 3632)
        emit(f'distccd probe → {ip}:{port}')
        try:
            s = socket.create_connection((ip, port), timeout=5)
            s.close()
            version = (ctx.get('version') or '').strip()
            title = f'distccd v1 exposed on {port}'
            if version and 'distcc' in version.lower():
                title = f'distccd exposed — {version}'
            finding({'tool': 'distcc_check', 'type': 'vuln', 'severity': 'CRITICAL',
                     'port': port,
                     'title': title,
                     'detail': 'distccd daemon reachable — distcc_exec RCE likely',
                     'msf_module': 'exploit/unix/misc/distcc_exec',
                     'cve': 'CVE-2004-2687'})
            emit('[+] distccd port open — distcc_exec candidate')
        except Exception as exc:
            emit(f'[-] distcc probe: {exc}')

    # ── IRC banner probe (MT2 port 6667) ───────────────────────────────────────
    def _run_irc_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 6667)
        emit(f'IRC banner probe → {ip}:{port}')
        try:
            s = socket.create_connection((ip, port), timeout=5)
            s.settimeout(4)
            banner = s.recv(512).decode('utf-8', errors='replace').strip()
            s.close()
            if banner:
                emit(f'[*] Banner: {banner[:100]}')
            bl = banner.lower()
            if 'unrealircd' in bl or 'unreal ircd' in bl:
                finding({'tool': 'irc_check', 'type': 'vuln', 'severity': 'CRITICAL',
                         'port': port,
                         'title': f'UnrealIRCd detected — {banner[:72]}',
                         'detail': 'UnrealIRCd 3.2.8.1 backdoor module may apply',
                         'msf_module': 'exploit/unix/irc/unreal_ircd_3281_backdoor',
                         'cve': 'CVE-2010-2075'})
                emit('[+] UnrealIRCd banner — backdoor module candidate')
            elif banner.startswith(':') or 'irc' in (ctx.get('service') or '').lower():
                finding({'tool': 'irc_check', 'type': 'info', 'severity': 'MEDIUM',
                         'port': port,
                         'title': f'IRC server reachable on {port}',
                         'detail': banner[:160] or 'IRC port open — manual banner check'})
                emit('[*] IRC service open')
            else:
                emit('[-] No IRC banner received')
        except Exception as exc:
            emit(f'[-] IRC probe: {exc}')

    # ── Java RMI registry probe (MT2 port 1099) ───────────────────────────────
    def _run_rmi_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 1099)
        emit(f'Java RMI probe → {ip}:{port}')
        try:
            s = socket.create_connection((ip, port), timeout=5)
            s.settimeout(3)
            # Stream protocol handshake — JRMI + version 2 + StreamProtocol (K)
            s.sendall(b'\x4a\x52\x4d\x49\x00\x02\x4b')
            resp = s.recv(32)
            s.close()
            rmi_ok = bool(resp) and resp[0:1] in (b'N', b'H')
            version = (ctx.get('version') or '').strip()
            if rmi_ok or 'rmi' in (ctx.get('service') or '').lower():
                detail = (f'RMI handshake response {resp[:8]!r}'
                          if rmi_ok else 'rmiregistry port open — verify registry auth')
                finding({'tool': 'rmi_check', 'type': 'vuln', 'severity': 'CRITICAL',
                         'port': port,
                         'title': f'Java RMI Registry exposed on {port}',
                         'detail': detail + (f' ({version})' if version else ''),
                         'msf_module': 'exploit/multi/misc/java_rmi_server'})
                emit('[+] Java RMI registry candidate — java_rmi_server module')
            else:
                emit(f'[-] Port open but RMI handshake inconclusive: {resp[:16]!r}')
        except Exception as exc:
            emit(f'[-] RMI probe: {exc}')

    # ── MongoDB probe ─────────────────────────────────────────────────────────
    def _run_mongo_check(self, ip, ctx, emit, finding, params):
        port = ctx.get('port', 27017)
        emit(f'MongoDB probe → {ip}:{port}')
        try:
            s = socket.create_connection((ip, port), timeout=5)
            s.close()
            finding({'tool':'mongo_check','type':'info','severity':'HIGH',
                     'port':port,'title':'MongoDB: Port Reachable — Verify Auth',
                     'detail':'Port 27017 open — confirm whether auth is required'})
            emit('[*] MongoDB port open — manual auth check recommended')
        except Exception as exc:
            emit(f'[-] MongoDB probe: {exc}')

    # ── searchsploit ──────────────────────────────────────────────────────────
    def _run_searchsploit(self, ip, ctx, emit, finding, params):
        if not _which('searchsploit'):
            emit('[SKIP] searchsploit not found (part of exploitdb)')
            return
        service = ctx.get('service', '').strip()
        version = ctx.get('version', '').strip()
        if not service:
            return
        query = f'{service} {version}'.strip()
        emit(f'searchsploit → "{query}"')
        _, lines = self._run_cmd(
            ['searchsploit', '--disable-colour', '-w', query],
            emit, 30
        )
        for line in lines:
            if '|' in line and '------' not in line and 'Exploit Title' not in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[0]:
                    title = parts[0]
                    url   = parts[-1]
                    sev   = ('CRITICAL' if 'Metasploit' in title or 'Remote' in title
                             else 'HIGH')
                    finding({'tool':'searchsploit','type':'exploit_ref',
                             'severity':sev,'port':ctx.get('port'),
                             'title':title,'detail':url,
                             'service':service,'version':version})

    # ══════════════════════════════════════════════════════════════════════════
    #  TIER-1 / TIER-3 ROBUSTNESS RUNNERS
    # ══════════════════════════════════════════════════════════════════════════

    # ── httpx — fast HTTP triage (Tier 1) ─────────────────────────────────────
    def _run_httpx(self, ip, ctx, emit, finding, params):
        """
        ProjectDiscovery httpx — fast fingerprint of an HTTP service:
        title, status code, web server, detected technologies. Runs first so
        the operator can triage many web hosts before the heavy web tools fire.
        On Kali the binary is 'httpx-toolkit' (renamed to avoid the python httpx).
        """
        tool = _which('httpx-toolkit') or _which('httpx')
        if not tool:
            emit('[SKIP] httpx: sudo apt-get install httpx-toolkit')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'httpx → {url}')
        cmd = [tool, '-u', url,
               '-title', '-status-code', '-web-server', '-tech-detect',
               '-content-length', '-follow-redirects',
               '-no-color', '-silent', '-timeout', '10']
        rc, lines = self._run_cmd(cmd, emit, 45)
        got = False
        for line in lines:
            text = line.strip()
            # httpx -silent emits one result line per URL, always starting with
            # the scheme. Anything else (banners, [WRN]/[INF], stray stderr) is
            # not a result and must not become a finding.
            if not text.lower().startswith(('http://', 'https://')):
                continue
            got = True
            finding({
                'tool': 'httpx', 'type': 'web_fingerprint', 'severity': 'INFO',
                'port': port,
                'title': 'HTTP service fingerprint',
                'detail': text,
            })
        if not got:
            emit('httpx: no HTTP response on this port')

    # ── nbtscan — NetBIOS name enumeration (Tier 1) ───────────────────────────
    def _run_nbtscan(self, ip, ctx, emit, finding, params):
        """
        nbtscan — queries the NetBIOS name service (137/UDP) for the host's
        NetBIOS name, workgroup/domain, logged-in user and MAC address.
        Fast and unauthenticated — useful early signal on Windows hosts.
        """
        if not _which('nbtscan'):
            emit('[SKIP] nbtscan: sudo apt-get install nbtscan')
            return
        emit(f'nbtscan → {ip}')
        rc, lines = self._run_cmd(['nbtscan', '-v', '-s', ':', ip], emit, 30)
        got = False
        for line in lines:
            text = line.strip()
            # Verbose colon-separated format: IP:NAME:<00>:U:...
            if text.startswith(ip) and ':' in text:
                got = True
                parts = [p.strip() for p in text.split(':')]
                detail = ' '.join(p for p in parts[1:] if p)
                finding({
                    'tool': 'nbtscan', 'type': 'netbios', 'severity': 'INFO',
                    'port': 139,
                    'title': 'NetBIOS name record',
                    'detail': detail or text,
                })
        if not got:
            emit('nbtscan: no NetBIOS response (host may not run SMB/NetBIOS)')

    # ── feroxbuster — recursive content discovery (Tier 3) ────────────────────
    def _run_feroxbuster(self, ip, ctx, emit, finding, params):
        """
        feroxbuster — fast recursive directory/file brute-force. Tier 3:
        slow and noisy. Recursion depth capped at 2 and concurrent recursive
        scans capped so it stays bounded. Prefers a SecLists wordlist, falls
        back to the dirb common list.
        """
        tool = _which('feroxbuster')
        if not tool:
            emit('[SKIP] feroxbuster: sudo apt-get install feroxbuster')
            return
        wordlist = next((w for w in (
            '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
        ) if Path(w).exists()), None)
        if not wordlist:
            emit('[SKIP] feroxbuster: no wordlist — sudo apt-get install seclists')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'feroxbuster → {url} (depth 2, wordlist: {Path(wordlist).name})')
        # NOTE: use -q (quiet) NOT --silent. --silent emits URL-only lines;
        # -q keeps the result rows (status/method/size columns) we parse below.
        # --scan-limit bounds concurrent recursive scans; -d bounds depth.
        cmd = [tool, '-u', url, '-w', wordlist,
               '-d', '2', '-t', '30', '-x', 'php,txt,html,bak',
               '-k', '-q', '--scan-limit', '4', '--no-state']
        rc, lines = self._run_cmd(cmd, emit, 240)
        _keep = {'200', '204', '301', '302', '307', '401', '403'}
        seen  = set()
        for line in lines:
            text = line.strip()
            # feroxbuster -q rows: "<status> GET <Nl> <Nw> <Nc> <url>"
            # Parse status and URL independently — column count varies.
            sm = re.match(r'^(\d{3})\b', text)
            um = re.search(r'(https?://\S+)', text)
            if not sm or not um:
                continue
            status    = sm.group(1)
            found_url = um.group(1).split()[0].rstrip('/')
            if status not in _keep or found_url in seen:
                continue
            seen.add(found_url)
            sev = 'MEDIUM' if status in ('401', '403') else 'LOW'
            finding({
                'tool': 'feroxbuster', 'type': 'content_discovery',
                'severity': sev, 'port': port,
                'title': f'[{status}] {found_url}',
                'detail': f'Discovered path — HTTP {status}',
            })

    # ── nuclei — template-based vulnerability scan (Tier 3) ───────────────────
    def _run_nuclei(self, ip, ctx, emit, finding, params):
        """
        nuclei — community-template vulnerability scanner. Tier 3.
        DoS and intrusive templates are explicitly excluded; rate-limited to
        50 req/s for purple-team friendliness. JSON-lines output is parsed
        directly into findings with nuclei's own severity classification.
        """
        if not _which('nuclei'):
            emit('[SKIP] nuclei: sudo apt-get install nuclei')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'nuclei → {url}  (excluding dos/intrusive, rate-limit 50)')
        cmd = ['nuclei', '-u', url,
               '-severity', 'low,medium,high,critical',
               '-exclude-tags', 'dos,intrusive',
               '-rate-limit', '50', '-timeout', '8', '-retries', '1',
               '-no-color', '-silent', '-jsonl']
        rc, lines = self._run_cmd(cmd, emit, 300)
        _sev_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
                    'low': 'LOW', 'info': 'INFO', 'unknown': 'INFO'}
        hits = 0
        for line in lines:
            text = line.strip()
            if not text.startswith('{'):
                continue
            try:
                data = json.loads(text)
            except Exception:
                continue
            info     = data.get('info', {})
            sev      = _sev_map.get((info.get('severity') or 'info').lower(), 'INFO')
            name     = info.get('name', data.get('template-id', 'nuclei finding'))
            matched  = data.get('matched-at', url)
            classif  = info.get('classification', {}) or {}
            # cve-id is normally a list, but tolerate a bare string or None.
            cve_raw  = classif.get('cve-id')
            if isinstance(cve_raw, str):
                cve = cve_raw.upper() or None
            elif isinstance(cve_raw, list) and cve_raw:
                cve = str(cve_raw[0]).upper()
            else:
                cve = None
            hits += 1
            finding({
                'tool': 'nuclei', 'type': 'template_vuln', 'severity': sev,
                'port': port, 'cve': cve,
                'title': name,
                'detail': f'{matched}  [template: {data.get("template-id","?")}]',
            })
        if hits == 0:
            emit('nuclei: no template matches (templates may need '
                 '`nuclei -update-templates`)')

    # ── testssl.sh — deep TLS / cipher audit (Tier 3) ─────────────────────────
    def _run_testssl(self, ip, ctx, emit, finding, params):
        """
        testssl.sh — thorough TLS audit: protocol support, cipher strength,
        and named vulnerabilities (Heartbleed, ROBOT, etc.). Tier 3 — slower
        than SSLyze. Uses --jsonfile so findings are parsed from testssl's own
        severity classification rather than scraped from plain text.
        """
        tool = _which('testssl') or _which('testssl.sh')
        if not tool:
            emit('[SKIP] testssl.sh: sudo apt-get install testssl.sh')
            return
        port = ctx['port']
        tmp  = f'/tmp/h3x_testssl_{ip}_{port}.json'
        # testssl refuses to overwrite an existing JSON file — clear any stale one.
        Path(tmp).unlink(missing_ok=True)
        emit(f'testssl.sh → {ip}:{port}  (--fast, JSON out)')
        cmd = [tool, '--quiet', '--color', '0', '--fast',
               '--severity', 'LOW', '--warnings', 'off',
               '--jsonfile', tmp, f'{ip}:{port}']
        self._run_cmd(cmd, emit, 300)
        _sev_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM',
                    'LOW': 'LOW', 'WARN': 'LOW'}
        p = Path(tmp)
        try:
            if p.exists():
                try:
                    data    = json.loads(p.read_text() or '[]')
                    entries = data if isinstance(data, list) else [data]
                    for e in entries:
                        raw = str(e.get('severity', 'INFO')).upper()
                        sev = _sev_map.get(raw)
                        if not sev:          # OK / INFO / DEBUG — skip
                            continue
                        fid   = e.get('id', 'tls')
                        fnd   = str(e.get('finding', '')).strip()
                        # testssl records CVEs in a dedicated 'cve' field
                        # (space-separated if several); fall back to the
                        # finding text only if that field is absent.
                        cve_src = str(e.get('cve', '') or '')
                        cve_m   = (re.search(r'CVE-[\d-]+', cve_src)
                                   or re.search(r'CVE-[\d-]+', fnd))
                        finding({
                            'tool': 'testssl', 'type': 'tls_vuln', 'severity': sev,
                            'port': port,
                            'cve': cve_m.group() if cve_m else None,
                            'title': f'{fid}: {fnd[:100]}' if fnd else fid,
                            'detail': fnd or fid,
                        })
                except Exception as exc:
                    emit(f'testssl: could not parse JSON output ({exc})')
            else:
                emit('testssl: no JSON output produced')
        finally:
            Path(tmp).unlink(missing_ok=True)

    # ── wpscan — WordPress scanner ────────────────────────────────────────────
    def _run_wpscan(self, ip, ctx, emit, finding, params):
        if not _which('wpscan'):
            emit('[SKIP] wpscan: sudo apt-get install wpscan')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        tmp    = f'/tmp/h3x_wpscan_{ip}_{port}.json'
        emit(f'wpscan \u2192 {url}')
        cmd = ['wpscan', '--url', url, '--no-update',
               '--random-user-agent', '--disable-tls-checks',
               '--format', 'json', '--output', tmp,
               '--enumerate', 'vp,u', '--plugins-detection', 'passive',
               '--max-threads', '5']
        self._run_cmd(cmd, emit, 240)
        p = Path(tmp)
        try:
            if not p.exists() or p.stat().st_size == 0:
                return
            try:
                data = json.loads(p.read_text())
            except Exception:
                emit('wpscan: could not parse JSON output')
                return
            if not (data.get('version') or data.get('main_theme')
                    or data.get('plugins') or data.get('users')):
                emit('wpscan: target does not appear to be WordPress')
                return
            ver = (data.get('version') or {}).get('number')
            if ver:
                finding({
                    'tool': 'wpscan', 'type': 'web_cms', 'severity': 'INFO',
                    'port': port,
                    'title': f'WordPress {ver} detected',
                    'detail': f'WordPress {ver} on {url}',
                    'msf_module': 'auxiliary/scanner/http/wordpress_login_enum',
                })
            for slug, info in (data.get('plugins') or {}).items():
                v     = (info.get('version') or {}).get('number', '')
                vulns = info.get('vulnerabilities', []) or []
                cves  = []
                for vv in vulns:
                    for ref in (vv.get('references') or {}).get('cve', []):
                        cves.append(f'CVE-{ref}')
                if vulns:
                    finding({
                        'tool': 'wpscan', 'type': 'web_plugin_vuln',
                        'severity': 'HIGH', 'port': port,
                        'cve': cves[0] if cves else None,
                        'title': f'WP plugin "{slug}" {v} \u2014 {len(vulns)} known vuln(s)'.rstrip(),
                        'detail': '; '.join(vv.get('title','')[:80] for vv in vulns[:3]),
                    })
            users = list((data.get('users') or {}).keys())
            if users:
                finding({
                    'tool': 'wpscan', 'type': 'web_users',
                    'severity': 'MEDIUM', 'port': port,
                    'title': f'WordPress users enumerated ({len(users)})',
                    'detail': ', '.join(users[:8]),
                })
        finally:
            Path(tmp).unlink(missing_ok=True)

    # ── droopescan — Drupal scanner ───────────────────────────────────────────
    def _run_droopescan(self, ip, ctx, emit, finding, params):
        if not _which('droopescan'):
            emit('[SKIP] droopescan: sudo apt-get install droopescan')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'droopescan \u2192 drupal {url}')
        _, lines = self._run_cmd(
            ['droopescan', 'scan', 'drupal', '-u', url,
             '--enumerate', 'vp', '-t', '4'], emit, 180)
        if not any('Possible version' in ln or 'Found by' in ln for ln in lines):
            emit('droopescan: target does not appear to be Drupal')
            return
        for i, line in enumerate(lines):
            if 'Possible version(s)' in line:
                versions = [l.strip() for l in lines[i+1:i+5]
                            if l.strip() and not l.strip().startswith('[')]
                if versions:
                    finding({
                        'tool': 'droopescan', 'type': 'web_cms',
                        'severity': 'INFO', 'port': port,
                        'title': f'Drupal version candidate: {versions[0]}',
                        'detail': f'droopescan: {", ".join(versions[:3])}',
                        'msf_module': 'exploit/unix/webapp/drupal_drupalgeddon2',
                    })
            if 'Possible interesting urls found' in line:
                finding({
                    'tool': 'droopescan', 'type': 'web_paths',
                    'severity': 'LOW', 'port': port,
                    'title': 'Drupal interesting URLs disclosed',
                    'detail': 'droopescan flagged disclosed paths on the Drupal install',
                })

    # ── kerbrute — Kerberos username enum (anonymous, no creds required) ──────
    def _run_kerbrute(self, ip, ctx, emit, finding, params):
        if not _which('kerbrute'):
            emit('[SKIP] kerbrute: sudo apt-get install kerbrute')
            return
        domain = self._detect_kerberos_realm(ip)
        if not domain:
            emit('[SKIP] kerbrute: realm not detected \u2014 run enum4linux-ng or '
                 'ldap_enum on this host first so the AD domain is known')
            return
        wl = next((w for w in [
            '/usr/share/seclists/Usernames/Names/names.txt',
            '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
            '/usr/share/wordlists/seclists/Usernames/Names/names.txt',
        ] if Path(w).is_file()), None)
        if not wl:
            emit('[SKIP] kerbrute: no username wordlist (sudo apt-get install seclists)')
            return
        emit(f'kerbrute \u2192 userenum realm={domain} dc={ip} ({Path(wl).name})')
        _, lines = self._run_cmd(
            ['kerbrute', 'userenum', '--dc', ip, '--domain', domain,
             wl, '-t', '10', '--safe'], emit, 180)
        valid = []
        for line in lines:
            m = re.search(r'VALID USERNAME:\s+(\S+)', line)
            if m:
                valid.append(m.group(1).split('@')[0])
        if valid:
            finding({
                'tool': 'kerbrute', 'type': 'ad_users', 'severity': 'HIGH',
                'port': 88,
                'title': f'Kerberos enum found {len(valid)} valid AD user(s)',
                'detail': ', '.join(valid[:12]) +
                          (f' + {len(valid)-12} more' if len(valid) > 12 else ''),
                'msf_module': 'auxiliary/scanner/winrm/winrm_login',
            })

    def _detect_kerberos_realm(self, ip):
        """Hunt for a Kerberos realm in this host's existing findings."""
        with self._lock:
            host_findings = list(self._findings.get(ip, []))
        for f in host_findings:
            txt = ((f.get('title') or '') + ' ' + (f.get('detail') or ''))
            # enum4linux / smb: "Domain Name: CORP.LOCAL"
            m = re.search(r'(?:domain|realm)\s*(?:name)?\s*[:=]\s*([A-Za-z][\w.-]{3,})',
                          txt, re.I)
            if m:
                v = m.group(1).strip().strip('.')
                if v.upper() != 'WORKGROUP' and '.' in v:
                    return v
            # LDAP base DN
            m = re.search(r'(dc=[\w-]+(?:,dc=[\w-]+)+)', txt, re.I)
            if m:
                return '.'.join(p.split('=', 1)[1] for p in m.group().split(','))
        return None

    # ── ldapdomaindump — AD dump via LDAP (anonymous bind attempt) ────────────
    def _run_ldapdomaindump(self, ip, ctx, emit, finding, params):
        if not _which('ldapdomaindump'):
            emit('[SKIP] ldapdomaindump: sudo apt-get install ldapdomaindump')
            return
        port   = ctx['port']
        outdir = f'/tmp/h3x_ldd_{ip}_{port}'
        Path(outdir).mkdir(parents=True, exist_ok=True)
        emit(f'ldapdomaindump \u2192 {ip} (anonymous bind)')
        rc, lines = self._run_cmd(
            ['ldapdomaindump', '-u', ':', '--no-json',
             '-o', outdir, ip], emit, 90)
        if rc != 0 or any(
                t in ln for ln in lines
                for t in ('invalidCredentials', 'strongerAuthRequired',
                          'bind failed', 'Could not connect')):
            emit('ldapdomaindump: anonymous bind rejected \u2014 needs creds')
            return
        for fname, label, sev in [
                ('domain_users.grep',     'AD users',     'MEDIUM'),
                ('domain_computers.grep', 'AD computers', 'INFO'),
                ('domain_groups.grep',    'AD groups',    'INFO')]:
            fp = Path(outdir) / fname
            if not fp.is_file():
                continue
            try:
                rows = [ln for ln in fp.read_text().splitlines()
                        if ln.strip() and not ln.startswith('#')]
            except Exception:
                continue
            if rows:
                finding({
                    'tool': 'ldapdomaindump', 'type': 'ad_enum',
                    'severity': sev, 'port': port,
                    'title': f'{label} enumerated via anonymous LDAP ({len(rows)})',
                    'detail': f'ldapdomaindump dumped {fname} ({len(rows)} entries)',
                    'msf_module': 'auxiliary/gather/ldap_query',
                })

    # ── wafw00f — WAF / CDN fingerprint ───────────────────────────────────────
    def _run_wafw00f(self, ip, ctx, emit, finding, params):
        if not _which('wafw00f'):
            emit('[SKIP] wafw00f: sudo apt-get install wafw00f')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}'
        emit(f'wafw00f \u2192 {url}')
        _, lines = self._run_cmd(['wafw00f', url, '-a'], emit, 60)
        wafs = []
        for line in lines:
            m = re.search(r'is behind ([A-Za-z][\w \-/().]+?) (?:WAF|\()', line)
            if m:
                name = m.group(1).strip()
                if name not in wafs:
                    wafs.append(name)
            elif 'seems to be behind a WAF' in line.lower() and 'Generic' not in wafs:
                wafs.append('Generic WAF')
        if wafs:
            finding({
                'tool': 'wafw00f', 'type': 'web_waf',
                'severity': 'INFO', 'port': port,
                'title': f'WAF / CDN: {", ".join(wafs)}',
                'detail': f'wafw00f identified protection on {url} \u2014 '
                          'nikto / feroxbuster output may be filtered',
            })
        else:
            emit('wafw00f: no WAF detected')

    # ── ffuf — modern web content fuzzer ──────────────────────────────────────
    def _run_ffuf(self, ip, ctx, emit, finding, params):
        if not _which('ffuf'):
            emit('[SKIP] ffuf: sudo apt-get install ffuf')
            return
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        url    = f'{scheme}://{ip}:{port}/FUZZ'
        wl = next((w for w in [
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
        ] if Path(w).is_file()), None)
        if not wl:
            emit('[SKIP] ffuf: no wordlist (sudo apt-get install seclists)')
            return
        tmp = f'/tmp/h3x_ffuf_{ip}_{port}.json'
        emit(f'ffuf \u2192 {url}  ({Path(wl).name})')
        self._run_cmd(
            ['ffuf', '-u', url, '-w', wl, '-t', '40',
             '-mc', '200,204,301,302,307,401,403', '-fc', '404',
             '-of', 'json', '-o', tmp, '-s'], emit, 180)
        p = Path(tmp)
        try:
            if not p.exists():
                return
            try:
                data = json.loads(p.read_text())
            except Exception:
                return
            results = data.get('results', [])
            for r in results[:50]:
                status = r.get('status')
                path   = (r.get('input', {}) or {}).get('FUZZ', '')
                if not path:
                    continue
                sev = ('MEDIUM' if status == 200
                       else 'INFO' if status in (301, 302, 307) else 'LOW')
                finding({
                    'tool': 'ffuf', 'type': 'web_path',
                    'severity': sev, 'port': port,
                    'title': f'/{path} [{status}]',
                    'detail': f'ffuf: /{path} returned HTTP {status}',
                })
            if len(results) > 50:
                emit(f'ffuf: {len(results)} hits; reported first 50')
        finally:
            Path(tmp).unlink(missing_ok=True)

    # ── dnsenum — DNS zone-transfer / subdomain enum ──────────────────────────
    def _run_dnsenum(self, ip, ctx, emit, finding, params):
        if not _which('dnsenum'):
            emit('[SKIP] dnsenum: sudo apt-get install dnsenum')
            return
        port = ctx['port']
        emit(f'dnsenum \u2192 {ip}')
        _, lines = self._run_cmd(
            ['dnsenum', '--noreverse', '-t', '8', '--threads', '4',
             '-s', '0', ip], emit, 120)
        zone_xfer = any('AXFR' in ln and 'successful' in ln.lower() for ln in lines)
        if zone_xfer:
            finding({
                'tool': 'dnsenum', 'type': 'dns_zone_xfer',
                'severity': 'HIGH', 'port': port,
                'title': 'DNS zone transfer (AXFR) succeeded',
                'detail': 'Server permits AXFR \u2014 full zone disclosed',
                'msf_module': 'auxiliary/gather/enum_dns',
            })
        subdomains = set()
        for line in lines:
            m = re.match(r'^\s*([\w.-]+\.[a-z]{2,})\s+\d+\s+IN\s+A\s+', line, re.I)
            if m:
                subdomains.add(m.group(1).rstrip('.'))
        if subdomains:
            finding({
                'tool': 'dnsenum', 'type': 'dns_subdomains',
                'severity': 'INFO', 'port': port,
                'title': f'Subdomains enumerated ({len(subdomains)})',
                'detail': ', '.join(sorted(subdomains)[:10]),
            })

    # ── sslscan — fast TLS / cipher / cert scanner ────────────────────────────
    def _run_sslscan(self, ip, ctx, emit, finding, params):
        if not _which('sslscan'):
            emit('[SKIP] sslscan: sudo apt-get install sslscan')
            return
        port = ctx['port']
        target = f'{ip}:{port}'
        emit(f'sslscan \u2192 {target}')
        _, lines = self._run_cmd(['sslscan', '--no-colour', target], emit, 60)
        legacy, weak_ciphers = [], []
        for line in lines:
            for proto in ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'):
                if proto in line and 'enabled' in line.lower() and proto not in legacy:
                    legacy.append(proto)
            if 'Accepted' in line and any(w in line for w in
                    ('RC4', 'DES-CBC', 'EXPORT', 'NULL', 'ADH', 'AECDH')):
                m = re.search(r'(\S+-\S+)\s*$', line.strip())
                if m:
                    weak_ciphers.append(m.group(1))
        if legacy:
            finding({
                'tool': 'sslscan', 'type': 'tls_legacy',
                'severity': 'HIGH', 'port': port,
                'title': f'Legacy TLS supported: {", ".join(legacy)}',
                'detail': f'{target} accepts deprecated protocol(s) {", ".join(legacy)}',
            })
        if weak_ciphers:
            finding({
                'tool': 'sslscan', 'type': 'tls_weak_cipher',
                'severity': 'MEDIUM', 'port': port,
                'title': f'Weak ciphers accepted ({len(weak_ciphers)})',
                'detail': ', '.join(weak_ciphers[:6]),
            })

    # ── smbnull — SMB null-session share enum via smbclient ───────────────────
    def _run_smbnull(self, ip, ctx, emit, finding, params):
        if not _which('smbclient'):
            emit('[SKIP] smbclient: sudo apt-get install smbclient')
            return
        port = ctx['port']
        emit(f'smbclient -L \u2192 //{ip}/  (null session)')
        _, lines = self._run_cmd(
            ['smbclient', '-L', f'//{ip}/', '-N',
             '--option=client min protocol=NT1'], emit, 30)
        shares, in_table = [], False
        for line in lines:
            if 'Sharename' in line and 'Type' in line:
                in_table = True
                continue
            if in_table:
                if line.startswith('-') or 'Reconnecting' in line or not line.strip():
                    in_table = False
                    continue
                m = re.match(r'^\s+(\S+)\s+(\S+)\s*(.*)$', line)
                if m and m.group(2).lower() in ('disk', 'ipc', 'printer'):
                    shares.append((m.group(1), m.group(2), m.group(3)))
        if shares:
            finding({
                'tool': 'smbnull', 'type': 'smb_shares',
                'severity': 'MEDIUM', 'port': port,
                'title': f'Null-session SMB shares enumerated ({len(shares)})',
                'detail': '; '.join(f'{n}({t})' for n, t, _ in shares[:8]),
                'msf_module': 'auxiliary/scanner/smb/smb_enumshares',
            })
            disk = [s for s in shares if s[1].lower() == 'disk']
            if disk:
                finding({
                    'tool': 'smbnull', 'type': 'smb_share_listed',
                    'severity': 'HIGH', 'port': port,
                    'title': f'Disk shares listable without auth ({len(disk)})',
                    'detail': 'Shares: ' + ', '.join(s[0] for s in disk),
                })

    # ── rpcnull — null-session RPC enum via rpcclient ─────────────────────────
    def _run_rpcnull(self, ip, ctx, emit, finding, params):
        if not _which('rpcclient'):
            emit('[SKIP] rpcclient: sudo apt-get install samba-common-bin')
            return
        port = ctx['port']
        emit(f'rpcclient null-session \u2192 {ip}  (srvinfo / lsaquery / enumdomusers)')
        script = 'srvinfo\nlsaquery\nenumdomusers\nquerydominfo\nquit\n'
        try:
            proc = subprocess.run(
                ['rpcclient', '-U', '', '-N', ip],
                input=script, capture_output=True, text=True,
                timeout=60, errors='replace')
            out = (proc.stdout or '') + (proc.stderr or '')
            for ln in out.splitlines():
                if ln:
                    emit(ln)
            lines = out.splitlines()
        except subprocess.TimeoutExpired:
            emit('[TIMEOUT] rpcclient killed after 60s')
            return
        except Exception as exc:
            emit(f'rpcclient: {exc}')
            return
        bound = any('Domain Name' in ln or 'Server name' in ln or
                    'user:' in ln.lower() for ln in lines)
        if not bound:
            emit('rpcclient: null-session bind rejected')
            return
        srv    = next((ln.split(':', 1)[1].strip() for ln in lines
                       if ln.strip().startswith('Server name')), '')
        domain = next((ln.split(':', 1)[1].strip() for ln in lines
                       if ln.strip().startswith('Domain Name')), '')
        if srv or domain:
            finding({
                'tool': 'rpcnull', 'type': 'smb_rpc_info',
                'severity': 'MEDIUM', 'port': port,
                'title': f'RPC null bind: server={srv or "?"}  domain={domain or "?"}',
                'detail': 'rpcclient anonymous bind succeeded \u2014 '
                          'server allows null-session RPC queries',
            })
        users = [m.group(1) for ln in lines
                 for m in [re.match(r'user:\[([^\]]+)\]', ln)] if m]
        if users:
            finding({
                'tool': 'rpcnull', 'type': 'ad_users',
                'severity': 'HIGH', 'port': port,
                'title': f'Null-session user enumeration ({len(users)} users)',
                'detail': ', '.join(users[:12]),
                'msf_module': 'auxiliary/scanner/smb/smb_enumusers',
            })
