#!/usr/bin/env python3
"""
H3x-Dash — Automated Penetration Framework
Flask application core: routes, SSE streaming, API endpoints.
"""

import json
import queue
import threading
import uuid
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

# ── App init ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = H3xConfig.SECRET_KEY
H3xConfig.init_dirs()

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

from modules.msf_validator import MsfValidator
msf_validator = MsfValidator(msf_engine, H3xConfig.LOOT_DIR)


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
        'msf_conn': msf_engine.is_connected(),
    }

# ── Credential auto-capture from enum findings ────────────────────────────────
# Hook into the EnumEngine's per-finding emission. The finding closure inside
# _enumerate_host calls this for every finding it dispatches; we extract any
# credential indicators and persist them.
def _capture_creds_from_finding(finding: dict) -> None:
    """Side-effect: pull creds out of a finding dict, store them, tag finding."""
    try:
        for c in creds_from_finding(finding):
            cred_id = cred_store.add(c)
    except Exception as exc:
        # never let cred-capture failures bubble up and break enum
        print(f"  [cred-capture] {finding.get('tool', '?')}: {exc}")

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

import sys as _sys
_SKIP_MSF_DAEMON = '--no-msf' in _sys.argv

if not _SKIP_MSF_DAEMON:
    msf_daemon_start(
        host     = H3xConfig.MSF_HOST,
        port     = H3xConfig.MSF_PORT,
        password = H3xConfig.MSF_PASS,
        ssl      = H3xConfig.MSF_SSL,
    )
else:
    print('[H3x-Dash] --no-msf flag set — skipping msfrpcd auto-start')

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
        try:
            q.put_nowait({'type': 'output', 'data': line})
        except queue.Full:
            pass

    def on_complete(hosts, meta):
        try:
            q.put_nowait({'type': 'complete', 'host_count': len(hosts), 'meta': meta})
        except queue.Full:
            pass

    # Validate target before any subprocess runs
    target = data.get('target', '').strip()
    ok, msg = validate_target(target)
    if not ok:
        return jsonify({'status': 'error', 'message': f'Invalid target: {msg}'}), 400

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


@app.route('/api/msf/session/<sid>/capture_creds', methods=['POST'])
def api_msf_session_capture_creds(sid):
    """
    Run an appropriate credential-dump command for the session type, parse the
    output, and push every parsed cred into the credential store. Returns
    {captured: N, sample: [...]}.
    """
    from modules.credentials import (parse_hashdump_output,
                                      parse_kiwi_creds,
                                      parse_shadow_output)

    stype = msf_engine._session_type(sid)
    sess_target = ''
    for s in msf_engine.list_sessions():
        if str(s.get('id')) == str(sid):
            sess_target = s.get('target', '')
            break

    if stype == 'meterpreter':
        # Try hashdump first (Windows)
        result = msf_engine.session_meterpreter_run(sid, 'hashdump', timeout=30)
        creds  = parse_hashdump_output(result.get('output', ''),
                                        host_ip=sess_target,
                                        source_tool='meterpreter_hashdump')
        if not creds:
            # Maybe a Linux Meterpreter — try cat /etc/shadow
            result = msf_engine.session_meterpreter_run(
                sid, 'shell -c "cat /etc/shadow"', timeout=15)
            creds = parse_shadow_output(result.get('output', ''),
                                         host_ip=sess_target)
    else:
        # Raw shell — try both
        out_shadow = msf_engine.session_run(sid, 'cat /etc/shadow',
                                              timeout=10).get('output', '')
        creds = parse_shadow_output(out_shadow, host_ip=sess_target)

    added_ids = [cred_store.add(c) for c in creds]
    return jsonify({
        'captured':  len(added_ids),
        'session':   sid,
        'session_type': stype,
        'sample':    [{'username': c.get('username'),
                       'type': c.get('type'),
                       'host_ip': c.get('host_ip')}
                       for c in creds[:5]],
    })


# ── Shell page route ─────────────────────────────────────────────────────────

@app.route('/shell')
def page_shell():
    """Legacy route — shell UI now lives on the Exploit page."""
    sid = request.args.get('sid')
    dest = '/exploit'
    if sid:
        dest += f'?sid={sid}'
    return redirect(dest + '#shell-panel')


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
        try: q.put_nowait({'type': 'output', 'data': line})
        except: pass

    def on_finding(f):
        try: q.put_nowait({'type': 'finding', 'finding': f})
        except: pass

    def on_complete(findings):
        count = sum(len(v) for v in findings.values())
        try: q.put_nowait({'type': 'complete', 'finding_count': count})
        except: pass

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
    candidates = [s for s in suggestions if s.get('msf_module')]
    if not candidates:
        return jsonify({'status': 'error',
                        'message': 'No MSF-backed candidates to validate for '
                                   f'{ip} — run enumeration first'}), 404

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
                    'candidate_count': len(candidates)})


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
        scan_results = scan_engine.get_results(),
        sessions     = msf_engine.list_sessions(),
        fmt          = data.get('format', 'html'),
    )
    return jsonify(report)


@app.route('/api/loot/reports')
def api_loot_list():
    return jsonify({'reports': loot_manager.list_reports()})


@app.route('/api/loot/download/<filename>')
def api_loot_download(filename):
    report_dir = H3xConfig.REPORT_DIR.resolve()
    # Reject any path components that could escape the reports directory
    if '/' in filename or '\\' in filename or '..' in filename:
        return jsonify({'error': 'Invalid filename'}), 400
    safe_path = (report_dir / filename).resolve()
    try:
        safe_path.relative_to(report_dir)   # raises ValueError if outside
    except ValueError:
        return jsonify({'error': 'Path traversal rejected'}), 400
    if not safe_path.exists():
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


if __name__ == '__main__':
    print("""
  ██╗  ██╗██████╗ ██╗  ██╗      ██████╗  █████╗ ███████╗██╗  ██╗
  ██║  ██║╚════██╗╚██╗██╔╝      ██╔══██╗██╔══██╗██╔════╝██║  ██║
  ███████║ █████╔╝ ╚███╔╝ █████╗██║  ██║███████║███████╗███████║
  ██╔══██║ ╚═══██╗ ██╔██╗ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║
  ██║  ██║██████╔╝██╔╝ ██╗      ██████╔╝██║  ██║███████║██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  // AUTOMATED PENETRATION FRAMEWORK // AUTHORIZED USE ONLY //

  Usage:  sudo python3 h3x-dash.py [--no-msf]

  --no-msf   Skip msfrpcd auto-start (manage it externally)
             Default: msfrpcd is launched automatically on first run

  Dashboard: http://127.0.0.1:5000
    """)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
