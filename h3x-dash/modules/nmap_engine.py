"""
H3x-Dash NmapEngine
Wraps Nmap-Configurabulator.py as a stateful, threaded scan manager.
Loaded via importlib — bundled directly in the H3x-Dash project.
"""
import threading
import importlib.util
import sys
import builtins
from datetime import datetime
from pathlib import Path

from config import H3xConfig

# ── Load Configurobulator ─────────────────────────────────────────────────────

_CFGPATH = Path(__file__).parent.parent / 'Nmap-Configurabulator.py'

# Module-level lock protecting the builtins.print monkey-patch
_PRINT_LOCK = threading.Lock()
_cfgmod  = None

def _load_configurobulator():
    global _cfgmod
    if _cfgmod is not None:
        return True
    if not _CFGPATH.exists():
        return False
    try:
        spec = importlib.util.spec_from_file_location('nmap_configurobulator', _CFGPATH)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _cfgmod = mod
        return True
    except Exception as e:
        print(f'[H3x-Dash] Configurobulator load error: {e}')
        return False

_load_configurobulator()

# ── Exported constants (with fallbacks) ───────────────────────────────────────

PORT_RISK = getattr(_cfgmod, 'PORT_RISK', {
    21: ('ftp', 'danger'), 22: ('ssh', 'info'), 23: ('telnet', 'danger'),
    25: ('smtp', 'warning'), 53: ('dns', 'info'), 80: ('http', 'info'),
    139: ('netbios', 'danger'), 161: ('snmp', 'warning'), 389: ('ldap', 'warning'),
    443: ('https', 'info'), 445: ('smb', 'danger'), 1433: ('mssql', 'danger'),
    3306: ('mysql', 'warning'), 3389: ('rdp', 'danger'), 5432: ('psql', 'warning'),
    5900: ('vnc', 'warning'), 6379: ('redis', 'danger'), 8080: ('http-alt', 'info'),
    9200: ('elasticsearch', 'danger'), 27017: ('mongodb', 'danger'),
})

PORT_PROFILES = getattr(_cfgmod, 'PORT_PROFILES', {
    'driveby':  '21-25,53,80,110-111,135,139,161,389,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017',
    'spyglass': '1-1024,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017',
    'web':      '80,443,8000,8008,8080,8443,8888,3000,5000,9443',
    'full':     '1-65535',
})

# Scan modes exposed on the Scan tab.  network = classic port discovery;
# web = HTTP/S port sweep + Layer-7 fingerprint; web_only = Layer-7 only.
SCAN_MODES = {
    'network':  'Network discovery — multi-service port scan (Linux, Windows, IoT, …)',
    'web':      'Web services — HTTP/S ports + Layer-7 fingerprint (titles, TLS, tech)',
    'web_only': 'Layer-7 only — skip nmap, run web scanner on URL/IP targets',
}

# Human-readable port profile blurbs for the UI <select>.
PORT_PROFILE_DESC = {
    'driveby':  'High-value ports across common services — fast lab default',
    'spyglass': 'Top 1024 + database/RDP/web extras — balanced internal sweep',
    'web':      'HTTP/S and alt-web ports only — pairs with Web Services mode',
    'full':     'All 65535 ports — slow; single-host or tiny ranges only',
}

TIMING_DESC = getattr(_cfgmod, 'TIMING_DESC', {
    'T1': 'Sneaky Ninja     — very slow, IDS evasion',
    'T2': 'Polite Brit      — slow, low bandwidth',
    'T3': 'Boringly Average — default nmap timing',
    'T4': 'Antagonistic     — fast, reliable on LAN  (recommended)',
    'T5': 'Roid Rage        — maximum speed, may drop packets',
})

SCRIPT_PROFILES = getattr(_cfgmod, 'SCRIPT_PROFILES', {
    'none': [], 'banner': ['banner'], 'default': ['default', 'banner'],
    'safe': ['safe', 'banner'], 'vuln': ['vuln', 'default', 'banner'],
    'full': ['vuln', 'auth', 'discovery', 'default', 'banner'],
})

SCRIPT_DESC = getattr(_cfgmod, 'SCRIPT_DESC', {
    'none':    'No scripts — fastest',
    'banner':  'Banner grab only',
    'default': 'Default + banner',
    'safe':    'Safe scripts',
    'vuln':    'Vulnerability scan',
    'full':    'Full suite — very slow',
})


# ── State machine ─────────────────────────────────────────────────────────────

class ScanState:
    IDLE     = 'idle'
    RUNNING  = 'running'
    COMPLETE = 'complete'
    ERROR    = 'error'


# ── NmapEngine ────────────────────────────────────────────────────────────────

class NmapEngine:
    def __init__(self):
        self._state   = ScanState.IDLE
        self._hosts   = []      # parsed host dicts
        self._meta    = {}      # scan metadata
        self._history = []      # past scan summaries
        self._lock    = threading.Lock()
        self._thread  = None
        self._stop_ev = threading.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    def start_scan(self, params: dict, on_output=None, on_complete=None) -> bool:
        """Launch a background scan. Returns False if one is already running."""
        with self._lock:
            if self._state == ScanState.RUNNING:
                return False
            self._state = ScanState.RUNNING
            self._stop_ev.clear()

        self._thread = threading.Thread(
            target  = self._run,
            args    = (params, on_output, on_complete),
            daemon  = True,
            name    = 'h3x-nmap-scan',
        )
        self._thread.start()
        return True

    def stop_scan(self):
        self._stop_ev.set()

    def get_status(self) -> dict:
        return {
            'state':      self._state,
            'host_count': len(self._hosts),
            'meta':       self._meta,
        }

    def get_results(self) -> dict:
        # Return copies — callers must not mutate engine internals
        with self._lock:
            return {'hosts': list(self._hosts), 'meta': dict(self._meta)}

    def get_hosts_with_ports(self) -> list:
        with self._lock:
            return [h for h in self._hosts if h.get('ports')]

    def get_host_count(self)  -> int: return len(self._hosts)
    def get_scan_count(self)  -> int: return len(self._history)

    def get_vuln_count(self) -> int:
        return sum(
            1 for h in self._hosts
            for p in h.get('ports', [])
            if p.get('risk') == 'danger'
        )

    def get_recent_activity(self) -> list:
        return list(reversed(self._history[-10:]))

    # ── Internal scan runner ──────────────────────────────────────────────────

    @staticmethod
    def _is_relevant(raw: str) -> bool:
        """Filter noisy Configurobulator output — only pass meaningful findings."""
        import re as _re
        line = _re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', raw).strip()
        if not line:
            return False
        if line.startswith('[H3x-Dash]'):
            return True
        lo = line.lower()
        if 'nmap scan report' in lo:
            return True
        if _re.search(r'\d+/(tcp|udp)', lo):
            return True
        if ('host' in lo or 'hosts' in lo) and ('up' in lo or 'down' in lo):
            return True
        if 'elapsed' in lo or ('done' in lo and 'nmap' in lo):
            return True
        if any(x in lo for x in ('[error]', '[!]', 'error:', 'warning:', 'failed')):
            return True
        if line.startswith('|'):
            return True
        if lo.startswith(('mac address', 'os details', 'running:', 'service info:')):
            return True
        if any(line.startswith(x) for x in ('[+]', '[*]', '[\u2713]')):
            return True
        if 'web scan' in lo or 'layer-7' in lo:
            return True
        if '\u2514' in line or ' unreachable' in lo:
            return True
        return False

    @staticmethod
    def _expand_web_targets(target: str) -> list[str]:
        """Turn a Scan-tab target into explicit web_scan targets."""
        try:
            import web_scan as _ws
            web_ports = sorted(_ws.WEB_PORTS)
        except ImportError:
            web_ports = [80, 443, 8080, 8443]

        expanded: list[str] = []
        for raw in target.replace(',', ' ').split():
            tok = raw.strip()
            if not tok:
                continue
            if tok.startswith(('http://', 'https://')):
                expanded.append(tok)
            elif ':' in tok and not tok.startswith('['):
                expanded.append(tok)
            else:
                for port in web_ports:
                    expanded.append(f'{tok}:{port}')
        return expanded

    @staticmethod
    def _attach_web_records(hosts: list, web_records: list) -> list:
        """Merge Layer-7 web records onto host dicts and enrich port metadata."""
        by_ip: dict[str, list] = {}
        for rec in web_records or []:
            ip = rec.get('host_ip') or rec.get('host')
            if ip:
                by_ip.setdefault(str(ip), []).append(rec)

        for h in hosts:
            ip = str(h.get('ip', ''))
            recs = by_ip.get(ip, [])
            if recs:
                h['web'] = recs
            for rec in recs:
                port_num = rec.get('port')
                fp = rec.get('fingerprint') or {}
                bits = [fp.get('server', ''), fp.get('title', '')]
                extra = ' | '.join(b for b in bits if b)
                if not extra:
                    continue
                for p in h.get('ports', []):
                    if p.get('port') == port_num:
                        cur = (p.get('version') or '').strip()
                        p['version'] = f'{cur} — {extra}' if cur else extra
        return hosts

    def _run_web_only(self, params: dict, emit) -> tuple[list, dict, list]:
        """Layer-7-only scan — no nmap. Builds synthetic host entries for Enum."""
        try:
            import web_scan as _ws
        except ImportError as exc:
            raise RuntimeError(f'web_scan.py not available: {exc}') from exc

        target = (params.get('target') or '').strip()
        if not target:
            raise ValueError('No target specified')

        targets = self._expand_web_targets(target)
        if not targets:
            raise ValueError('No web targets to scan')

        include_nse = bool(params.get('web_nse', False))
        emit(f'[H3x-Dash] Layer-7 web scan — {len(targets)} endpoint(s)')
        if include_nse:
            emit('[H3x-Dash] http-NSE enabled (slower)')

        hosts_map: dict[str, dict] = {}
        web_records: list = []

        for idx, t in enumerate(targets, 1):
            if self._stop_ev.is_set():
                emit('[H3x-Dash] Web scan aborted.')
                break
            emit(f'[*] ({idx}/{len(targets)}) {t}')
            try:
                rec = _ws.scan_target(t, include_nse=include_nse)
            except Exception as exc:
                emit(f'[!] web scan failed for {t}: {exc}')
                continue

            web_records.append(rec)
            if _cfgmod and hasattr(_cfgmod, '_print_web_summary'):
                with _PRINT_LOCK:
                    _orig = builtins.print
                    try:
                        builtins.print = lambda *a, **kw: emit(
                            ' '.join(str(x) for x in a))
                        _cfgmod._print_web_summary(rec)
                    finally:
                        builtins.print = _orig
            elif rec.get('reachable'):
                fp = rec.get('fingerprint') or {}
                emit(f'    └ {rec.get("url")}  [{fp.get("status","?")}]  '
                     f'{fp.get("server") or "server n/d"}')

            ip = str(rec.get('host') or '')
            if not ip:
                continue
            host = hosts_map.setdefault(ip, {
                'ip': ip, 'type': 'server', 'os': '', 'ports': [], 'web': [],
            })
            host['web'].append(rec)
            port_num = rec.get('port')
            if not port_num:
                continue
            svc = 'https' if rec.get('scheme') == 'https' else 'http'
            fp = rec.get('fingerprint') or {}
            version = ' | '.join(x for x in [fp.get('server', ''),
                                             fp.get('title', '')] if x)
            entry = {
                'port':     port_num,
                'protocol': 'tcp',
                'service':  svc,
                'version':  version,
                'risk':     'info',
            }
            if not any(p.get('port') == port_num for p in host['ports']):
                host['ports'].append(entry)

        hosts = sorted(hosts_map.values(), key=lambda h: h.get('ip', ''))
        meta = {
            'target':      target,
            'scan_mode':   'web_only',
            'web_records': web_records,
            'command':     'web_scan (Layer-7 only)',
        }
        return hosts, meta, web_records

    def _run(self, params: dict, on_output, on_complete):
        def emit(line: str, force: bool = False):
            if on_output and (force or self._is_relevant(line)):
                on_output(line)

        try:
            if _cfgmod is None:
                raise RuntimeError(
                    'Nmap-Configurabulator.py not found. '
                    f'Expected at: {_CFGPATH}'
                )

            scan_mode = params.get('scan_mode', 'network')
            if scan_mode not in SCAN_MODES:
                scan_mode = 'network'

            # ── Layer-7-only path (no nmap) ────────────────────────────
            if scan_mode == 'web_only':
                hosts, meta, web_records = self._run_web_only(params, emit)
                meta['web_records'] = web_records
                with self._lock:
                    self._hosts = hosts
                    self._meta  = meta
                    self._state = ScanState.COMPLETE
                    self._history.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'target':    params.get('target', ''),
                        'hosts':     len(hosts),
                        'command':   meta.get('command', 'web_scan'),
                        'state':     'complete',
                    })
                emit(f'[H3x-Dash] Web scan complete — {len(hosts)} host(s) profiled.')
                if on_complete:
                    on_complete(hosts, meta)
                return

            # Build Config object from dashboard params
            cfg              = _cfgmod.Config()
            cfg.target       = params.get('target', '')
            cfg.timing       = params.get('timing',       H3xConfig.DEFAULT_TIMING)
            cfg.port_profile = params.get('port_profile', H3xConfig.DEFAULT_PORTS)
            cfg.scripts      = params.get('scripts',      H3xConfig.DEFAULT_SCRIPTS)
            cfg.use_sudo     = params.get('use_sudo',     True)
            cfg.out_dir      = str(H3xConfig.NMAP_DIR)
            cfg.extra_args   = list(params.get('extra_args', []))

            if scan_mode == 'web':
                cfg.port_profile = 'web'
                cfg.web_scan     = True
            else:
                cfg.web_scan = bool(params.get('web_scan', False))
            cfg.web_nse     = bool(params.get('web_nse', False))
            cfg.web_targets = list(params.get('web_targets') or [])

            # ── Layer evasion flags onto the nmap command ──────────────
            # Stealth level 0 contributes nothing; 1–3 add timing, fragmentation,
            # decoys etc. (see modules/evasion.py). Operator-supplied extra_args
            # always come AFTER evasion flags so manual overrides win.
            from modules import evasion as _evasion
            stealth = params.get('stealth_level', _evasion.get_level())
            evasion_flags = _evasion.nmap_flags_for(stealth)
            if evasion_flags:
                # Prepend evasion flags so user's extra_args can override them
                cfg.extra_args = evasion_flags + cfg.extra_args
                profile = _evasion.level_profile(stealth)
                emit(f'[H3x-Dash] Stealth      : {profile["name"]} '
                     f'({profile["estimated_slowdown"]} slowdown) '
                     f'— flags: {" ".join(evasion_flags)}')

            emit(f'[H3x-Dash] Scan mode    : {scan_mode}')
            emit(f'[H3x-Dash] Target       : {cfg.target}')
            emit(f'[H3x-Dash] Port profile : {cfg.port_profile}')
            emit(f'[H3x-Dash] Timing       : {cfg.timing}')
            emit(f'[H3x-Dash] NSE scripts  : {cfg.scripts}')
            if cfg.web_scan or cfg.web_targets:
                note = 'on' + (' + http-NSE' if cfg.web_nse else '')
                emit(f'[H3x-Dash] Layer-7 web  : {note}')

            _cfgmod.preflight_check(cfg)

            # Capture all print() output from Configurobulator.
            # builtins.print is global state — hold a module-level lock so
            # concurrent Flask threads don't get redirected into this scan's emit().
            # Since only one scan runs at a time (ScanState.RUNNING guard above),
            # this lock is belt-and-suspenders but makes the intent explicit.
            _orig_print = builtins.print
            def _capture(*args, **kw):
                line = ' '.join(str(a) for a in args)
                emit(line)
                _orig_print(*args, **kw)

            with _PRINT_LOCK:
                builtins.print = _capture
                try:
                    xml_str, nmap_cmd, monitor = _cfgmod.run_nmap(cfg)
                    hosts, meta, down_ips, no_port_ips = _cfgmod.parse_nmap_xml(xml_str, cfg.target)

                    # Enrich hosthint-recovered hosts with PTY-captured port data
                    if monitor.discovered_ports:
                        for h in hosts:
                            if h.get('_from_hint'):
                                live = monitor.discovered_ports.get(h['ip'], [])
                                if live:
                                    h['ports'] = sorted(live, key=lambda p: p['port'])

                    hosts = _cfgmod.inject_local_host(hosts, cfg.target)
                    nodes, links = _cfgmod.build_topology(hosts) if hosts else ([], [])

                    web_records = []
                    if hasattr(_cfgmod, 'collect_web_records'):
                        if cfg.web_scan or cfg.web_targets:
                            web_records = _cfgmod.collect_web_records(cfg, hosts)
                    nodes = self._attach_web_records(nodes, web_records)

                    meta['command']     = nmap_cmd
                    meta['down_ips']    = down_ips
                    meta['no_port_ips'] = no_port_ips
                    meta['target']      = cfg.target
                    meta['scan_mode']   = scan_mode
                    meta['web_records'] = web_records

                finally:
                    builtins.print = _orig_print

            with self._lock:
                self._hosts = nodes
                self._meta  = meta
                self._state = ScanState.COMPLETE
                self._history.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'target':    cfg.target,
                    'hosts':     len(nodes),
                    'command':   nmap_cmd,
                    'state':     'complete',
                })

            emit(f'[H3x-Dash] Scan complete — {len(nodes)} host(s) found.')
            if on_complete:
                on_complete(nodes, meta)

        except Exception as exc:
            with self._lock:
                self._state          = ScanState.ERROR
                self._meta['error']  = str(exc)
                self._history.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'target':    params.get('target', '?'),
                    'hosts':     0,
                    'state':     'error',
                    'error':     str(exc),
                })
            emit(f'[H3x-Dash][ERROR] {exc}')
            if on_output:
                on_output(f'[ERROR] {exc}')
