"""
report_engine.py — H3x-Dash client-deliverable report generator.

Aggregates the artifacts the framework already collects into a single
engagement report. Unlike loot.py (a focused scan → host/port renderer),
this pulls from EVERY source and cross-references them into findings:

    scan (reports/*.json) ── hosts / ports / risk tiers
    cred_store            ── recovered credentials (masked by default)
    ops_log (logs/exploit)── what was actually run + whether a shell opened
    msf_validator         ── per-{ip::module} feasibility verdict
    cve_chain.suggest()   ── candidate CVEs / MSF modules (live only)
    mitre_mapping         ── ATT&CK techniques → the coverage heatmap

Design notes
------------
* Dual-sourced: assemble_from_live() fills the report dict from the running
  engine objects; assemble_from_disk() rebuilds it from persisted artifacts so
  the report (and its audit) run with no live msfrpcd.
* Secrets are MASKED by default. Pass include_secrets=True only for an internal
  copy. ops_log already masks sensitive option keys — this keeps the report
  consistent and safe to hand to a client.
* HTML now, PDF-ready: the markup is print-clean (@media print + page-break
  rules), so an operator gets browser → "Save as PDF" today, and to_pdf()
  drops in WeasyPrint later with no renderer change.
* Pure stdlib (html, json, datetime, pathlib) + the in-repo mitre_mapping.
  No new pip dependency, matching the rest of the toolkit.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from modules import mitre_mapping

# ── SPECTR palette (matches loot.py + templates) ──────────────────────────────
VOID   = '#0d0d12'
PANEL  = '#13131a'
LINE   = '#1e1e2e'
CYAN   = '#0ff0fc'
VIOLET = '#9b30ff'
ACID   = '#39ff14'
DIM    = '#555'

# ── Severity model ────────────────────────────────────────────────────────────
# cve_chain / validator findings carry CRITICAL/HIGH/MEDIUM/LOW/INFO.
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEVERITY_COLOR = {
    'CRITICAL': '#ff2d55',
    'HIGH':     '#ff8c00',
    'MEDIUM':   '#e6b800',
    'LOW':      '#0ff0fc',
    'INFO':     '#5a6b7a',
}
# nmap port risk (danger/warning/info) → severity, for appendix roll-ups only.
_RISK_TO_SEV = {'danger': 'HIGH', 'warning': 'MEDIUM', 'info': 'INFO'}  # unconfirmed exposure

# ── Validator verdict presentation ────────────────────────────────────────────
VERDICT_COLOR = {
    'VULNERABLE':     '#ff2d55',
    'NOT_VULNERABLE': '#1D9E75',
    'DETECTED':       '#ff8c00',
    'NO_CHECK':       '#888',
    'UNKNOWN':        '#888',
    'ERROR':          '#666',
}
VERDICT_LABEL = {
    'VULNERABLE':     'VULNERABLE',
    'NOT_VULNERABLE': 'NOT VULNERABLE',
    'DETECTED':       'DETECTED',
    'NO_CHECK':       'NO CHECK METHOD',
    'UNKNOWN':        'UNKNOWN',
    'ERROR':          'CHECK ERROR',
}

# ── ATT&CK technique → primary tactic ─────────────────────────────────────────
# The heatmap renders tactics as columns. mitre_mapping stores technique→label
# but not tactic, so we map every technique in its vocabulary to a single
# *primary* tactic here (several ATT&CK techniques legitimately span tactics;
# for a one-cell-per-technique grid we pick the dominant offensive-use tactic).
TACTIC_ORDER = [
    'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
    'Privilege Escalation', 'Credential Access', 'Discovery',
    'Lateral Movement', 'Command and Control', 'Impact',
]
TECHNIQUE_TACTIC = {
    'T1595': 'Reconnaissance', 'T1595.002': 'Reconnaissance', 'T1592': 'Reconnaissance',
    'T1190': 'Initial Access', 'T1133': 'Initial Access',
    'T1078': 'Initial Access', 'T1078.002': 'Initial Access',
    'T1059': 'Execution', 'T1059.001': 'Execution',
    'T1098': 'Persistence', 'T1505.003': 'Persistence',
    'T1068': 'Privilege Escalation',
    'T1003': 'Credential Access', 'T1003.001': 'Credential Access',
    'T1003.006': 'Credential Access', 'T1110': 'Credential Access',
    'T1110.001': 'Credential Access', 'T1110.003': 'Credential Access',
    'T1110.004': 'Credential Access', 'T1212': 'Credential Access',
    'T1552.001': 'Credential Access', 'T1557.001': 'Credential Access',
    'T1558.003': 'Credential Access',
    'T1018': 'Discovery', 'T1083': 'Discovery', 'T1087': 'Discovery',
    'T1087.001': 'Discovery', 'T1087.002': 'Discovery', 'T1135': 'Discovery',
    'T1021.001': 'Lateral Movement', 'T1021.002': 'Lateral Movement',
    'T1021.004': 'Lateral Movement', 'T1021.006': 'Lateral Movement',
    'T1210': 'Lateral Movement',
    'T1090': 'Command and Control', 'T1573.001': 'Command and Control',
    'T1499': 'Impact',
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ''))


# ══════════════════════════════════════════════════════════════════════════════
#  Credential masking
# ══════════════════════════════════════════════════════════════════════════════

def mask_secret(cred: dict, include_secrets: bool = False) -> str:
    """Render a credential's secret for display.

    Masked (default): reveals TYPE + length only, never the material — safe to
    hand a client. A plaintext value shows a 1-char hint so the operator can
    eyeball-match without disclosure. include_secrets=True prints the raw value
    (still HTML-escaped) for an internal copy.
    """
    ctype = cred.get('type', 'unknown')
    val = cred.get('value') or ''
    if include_secrets and val:
        return _esc(val)
    n = len(val)
    if ctype == 'password':
        if n == 0:
            return '<span style="color:#555">— (username only)</span>'
        hint = _esc(val[0]) if n else ''
        return f'<span title="masked">{hint}{"•" * min(n - 1, 11)}&nbsp;'\
               f'<span style="color:#555">({n} chars)</span></span>'
    if ctype in ('ntlm_hash', 'unix_hash'):
        return f'<span style="color:#9b30ff">{_esc(ctype)}</span>'\
               f'&nbsp;<span style="color:#555">· {n} chars</span>'
    if ctype == 'ssh_key':
        return f'<span style="color:#9b30ff">PEM private key</span>'\
               f'&nbsp;<span style="color:#555">· {n} bytes</span>'
    if ctype in ('kerberos_ticket', 'kerberos_spn'):
        return f'<span style="color:#9b30ff">{_esc(ctype)}</span>'
    if ctype in ('token', 'cookie'):
        return f'<span style="color:#9b30ff">{_esc(ctype)}</span>'\
               f'&nbsp;<span style="color:#555">· masked</span>'
    if ctype == 'username_only':
        return '<span style="color:#555">— (no secret)</span>'
    return f'<span style="color:#555">masked · {n} chars</span>'


# ══════════════════════════════════════════════════════════════════════════════
#  Findings assembly — the cross-referencing core
# ══════════════════════════════════════════════════════════════════════════════

def build_findings(hosts: list, verdicts_by_host: dict,
                   exploit_runs: list) -> list:
    """Cross-reference every source into a normalized, annotated finding list.

    A finding is one (host, module/CVE) pair we have something to say about:
    a validator verdict, an exploit attempt, or a dangerous open service.
    Deduped on (host, module|cve|service); enriched with ATT&CK + CVSS via
    mitre_mapping so the renderer stays presentation-only.

    Exploitation is attributed ONLY from a module's own run.session_opened —
    never inferred from a host having a shell (a host can be popped by module A
    while module B was merely checked; conflating them fabricates evidence).
    """
    # Index exploit runs by (rhost, module) for outcome lookup.
    runs_by_key: dict[tuple, list] = {}
    for r in exploit_runs or []:
        key = (str(r.get('rhost', '')).strip(),
               str(r.get('module', '')).strip())
        runs_by_key.setdefault(key, []).append(r)

    findings: list[dict] = []
    seen: set = set()

    def _emit(host_ip, *, module=None, cve=None, service='', port=None,
              severity='INFO', ftype='exploit', verdict=None, detail='',
              evidence=None):
        dedup = (host_ip, module or cve or f'{service}:{port}')
        if dedup in seen:
            return
        seen.add(dedup)

        runs = runs_by_key.get((host_ip, module or ''), []) if module else []
        exploited = any(bool(r.get('session_opened')) for r in runs)
        # A confirmed shell is the maximal outcome — it overrides any milder
        # verdict-derived severity (e.g. NO_CHECK modules that still popped).
        if exploited:
            severity = 'CRITICAL'
        ev = list(evidence or [])
        for r in runs[:3]:
            tag = 'session opened' if r.get('session_opened') else (
                'exploit failed' if r.get('exploit_failed') else
                str(r.get('status') or 'ran'))
            ev.append(f"[{r.get('ts', '')[:19]}] {r.get('action', 'run')} "
                      f"→ {tag}")

        f = mitre_mapping.annotate_finding({
            'host_ip':   host_ip,
            'msf_module': module,
            'cve':        cve,
            'service':    service,
            'port':       port,
            'type':       ftype,
            'severity':   severity,
        })
        f.update({
            'verdict':   verdict,
            'detail':    detail,
            'exploited': bool(exploited),
            'evidence':  ev,
            'remediation': _remediation_for(f.get('attack_techniques', []),
                                            service, module, cve),
        })
        findings.append(f)

    # 1) Validator verdicts are the strongest signal — one finding each.
    for host_ip, verdicts in (verdicts_by_host or {}).items():
        for module, vd in (verdicts or {}).items():
            verdict = vd.get('verdict', 'UNKNOWN')
            sev = _severity_for_verdict(verdict, module)
            _emit(host_ip, module=module,
                  cve=_cve_hint_from_module(module),
                  severity=sev, ftype='exploit',
                  verdict=verdict, detail=vd.get('detail', ''))

    # 2) Exploit runs without a stored verdict (e.g. straight run, no check).
    for (host_ip, module), runs in runs_by_key.items():
        if not host_ip or not module:
            continue
        if (host_ip, module) in seen:
            continue
        opened = any(r.get('session_opened') for r in runs)
        sev = 'CRITICAL' if opened else 'HIGH'
        _emit(host_ip, module=module, cve=_cve_hint_from_module(module),
              severity=sev, ftype='exploit',
              verdict='VULNERABLE' if opened else None,
              detail='Session opened during engagement.' if opened else
                     'Exploit attempted; no session recorded.')

    # 3) Dangerous open services from the scan that nothing else flagged.
    for h in hosts or []:
        ip = str(h.get('ip', '')).strip()
        for p in h.get('ports', []):
            if p.get('risk') != 'danger':
                continue
            svc = p.get('service', '')
            _emit(ip, service=svc, port=p.get('port'),
                  severity=_RISK_TO_SEV.get('danger', 'MEDIUM'),
                  ftype='service',
                  detail=f"High-risk service exposed: {svc} "
                         f"{p.get('version', '') or ''}".strip())

    findings.sort(key=lambda f: (
        0 if f.get('exploited') else 1,
        SEVERITY_ORDER.get(str(f.get('severity', 'INFO')).upper(), 9),
        0 if f.get('verdict') == 'VULNERABLE' else 1,
        str(f.get('host_ip', '')),
    ))
    return findings


def _severity_for_verdict(verdict: str, module: str) -> str:
    if verdict == 'VULNERABLE':
        return 'CRITICAL' if 'exploit/' in (module or '') else 'HIGH'
    if verdict == 'DETECTED':
        return 'MEDIUM'
    if verdict == 'NOT_VULNERABLE':
        return 'INFO'
    return 'LOW'


def _cve_hint_from_module(module: str | None) -> str | None:
    """Best-effort CVE surfacing for well-known chain modules (display only)."""
    if not module:
        return None
    m = module.lower()
    table = {
        'ms17_010': 'CVE-2017-0144', 'eternalblue': 'CVE-2017-0144',
        'smbghost':  'CVE-2020-0796', 'cve_2020_0796': 'CVE-2020-0796',
        'zerologon': 'CVE-2020-1472', 'samba_usermap': 'CVE-2007-2447',
        'is_known_pipename': 'CVE-2017-7494', 'drupalgeddon2': 'CVE-2018-7600',
        'printnightmare': 'CVE-2021-1675',
    }
    for k, v in table.items():
        if k in m:
            return v
    return None


def _remediation_for(techniques: list, service: str,
                     module: str | None, cve: str | None) -> str:
    """Short, actionable remediation keyed by ATT&CK technique / service.

    Generic-but-useful guidance so the client report always has a next step;
    the operator can hand-edit per finding.
    """
    t = set(techniques or [])
    if 'T1190' in t or 'T1210' in t:
        base = ('Patch the affected service to a fixed release and remove it '
                'from untrusted network exposure; restrict inbound access to '
                'management VLANs.')
    elif t & {'T1003', 'T1003.001', 'T1003.006', 'T1552.001'}:
        base = ('Rotate all exposed credentials, enable LSASS protection '
                '(RunAsPPL / Credential Guard), and constrain accounts with '
                'DCSync rights.')
    elif t & {'T1110', 'T1110.001', 'T1110.003', 'T1110.004'}:
        base = ('Enforce account lockout + strong password policy, enable MFA '
                'on the service, and monitor for spray patterns.')
    elif 'T1558.003' in t:
        base = ('Set 25+ char managed passwords on service accounts, disable '
                'RC4, and monitor TGS-REQ for kerberoasting.')
    elif t & {'T1021.001', 'T1021.002', 'T1021.004', 'T1021.006'}:
        base = ('Restrict remote-service reachability to jump hosts, enforce '
                'MFA/network-level auth, and segment management protocols.')
    elif 'T1505.003' in t:
        base = ('Remove the web shell, restore from known-good, and audit the '
                'application for the upload/RCE vector used to plant it.')
    else:
        base = ('Apply vendor patches, remove unnecessary exposure, and '
                'validate the fix.')
    if cve:
        base += f' Reference {cve}.'
    return base


# ══════════════════════════════════════════════════════════════════════════════
#  Live + disk assembly
# ══════════════════════════════════════════════════════════════════════════════

def assemble_from_live(*, scan_results: dict, sessions: list,
                       cred_store=None, msf_validator=None, ops_log=None,
                       cve_chain=None, engagement: dict | None = None) -> dict:
    """Build the report dict from running engine objects (called by the route)."""
    hosts = (scan_results or {}).get('hosts', []) or []
    meta = (scan_results or {}).get('meta', {}) or {}

    verdicts_by_host = {}
    if msf_validator is not None:
        for h in hosts:
            ip = str(h.get('ip', '')).strip()
            if not ip:
                continue
            try:
                v = msf_validator.get_verdicts_for_host(ip)
            except Exception:
                v = {}
            if v:
                verdicts_by_host[ip] = v

    exploit_runs = []
    if ops_log is not None:
        try:
            exploit_runs = ops_log.list_exploit_logs(limit=50)
        except Exception:
            exploit_runs = []

    creds = []
    if cred_store is not None:
        try:
            creds = cred_store.list()
        except Exception:
            creds = []

    findings = build_findings(hosts, verdicts_by_host, exploit_runs)
    return _finalize(hosts, sessions, creds, findings, meta, engagement)


def assemble_from_disk(config, scan_json: str | Path | None = None,
                       engagement: dict | None = None) -> dict:
    """Rebuild the report dict from persisted artifacts (no live engines).

    Reads the newest reports/*.json (or an explicit one), loot/credentials.json,
    loot/msf_validation.json, and logs/exploit/*.json. This is what makes the
    engine testable and lets an operator regenerate a report post-engagement.
    """
    report_dir = Path(config.REPORT_DIR)
    loot_dir   = Path(config.LOOT_DIR)
    log_dir    = Path(config.LOG_DIR)

    # Latest scan snapshot.
    scan = {}
    path = Path(scan_json) if scan_json else None
    if path is None:
        candidates = sorted(report_dir.glob('h3x-dash_report_*.json'),
                            reverse=True)
        path = candidates[0] if candidates else None
    if path and path.is_file():
        try:
            scan = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            scan = {}
    hosts    = scan.get('hosts', []) or []
    sessions = scan.get('sessions', []) or []
    meta     = scan.get('meta', {}) or {}

    # Credentials.
    creds = []
    cfile = loot_dir / 'credentials.json'
    if cfile.is_file():
        try:
            creds = list((json.loads(cfile.read_text(encoding='utf-8'))
                          .get('credentials') or {}).values())
        except (OSError, json.JSONDecodeError):
            creds = []

    # Validator verdicts, keyed "{ip}::{module}".
    verdicts_by_host: dict = {}
    vfile = loot_dir / 'msf_validation.json'
    if vfile.is_file():
        try:
            raw = json.loads(vfile.read_text(encoding='utf-8'))
            for key, vd in (raw or {}).items():
                if '::' not in key:
                    continue
                ip, module = key.split('::', 1)
                verdicts_by_host.setdefault(ip, {})[module] = vd
        except (OSError, json.JSONDecodeError):
            verdicts_by_host = {}

    # Exploit runs from the ops log.
    exploit_runs = []
    edir = log_dir / 'exploit'
    if edir.is_dir():
        for jp in sorted(edir.glob('*.json'), reverse=True)[:100]:
            try:
                d = json.loads(jp.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                continue
            opts = d.get('options') or {}
            exploit_runs.append({
                'ts':     d.get('ts', ''),
                'module': d.get('module', ''),
                'action': d.get('action', ''),
                'rhost':  str(opts.get('RHOSTS', '')).split(',')[0].strip(),
                'status': d.get('status'),
                'session_opened': d.get('session_opened'),
                'exploit_failed': d.get('exploit_failed'),
            })

    findings = build_findings(hosts, verdicts_by_host, exploit_runs)
    return _finalize(hosts, sessions, creds, findings, meta, engagement)


def _finalize(hosts, sessions, creds, findings, meta, engagement) -> dict:
    sev_counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get('severity', 'INFO')).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    matrix = mitre_mapping.attack_matrix(findings)
    return {
        'generated':   _utcnow().isoformat(),
        'engagement':  engagement or {},
        'meta':        meta,
        'hosts':       hosts,
        'sessions':    sessions,
        'credentials': creds,
        'findings':    findings,
        'sev_counts':  sev_counts,
        'attack_matrix': {k: len(v) for k, v in matrix.items()},
        'stats': {
            'hosts':     len(hosts),
            'findings':  len(findings),
            'exploited': sum(1 for f in findings if f.get('exploited')),
            'creds':     len(creds),
            'sessions':  len(sessions),
            'critical':  sev_counts.get('CRITICAL', 0),
            'high':      sev_counts.get('HIGH', 0),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Renderer
# ══════════════════════════════════════════════════════════════════════════════

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d12;color:#0ff0fc;font-family:"Share Tech Mono","Courier New",monospace;padding:2.5rem 2rem;line-height:1.6}
.wrap{max-width:1100px;margin:0 auto}
h1{font-family:"Rajdhani",sans-serif;font-size:38px;letter-spacing:.12em;color:#fff;line-height:1}
h2{font-size:12px;color:#9b30ff;letter-spacing:.28em;margin:2.75rem 0 1.1rem;padding-bottom:.5rem;border-bottom:1px solid #1e1e2e}
h3{font-family:"Rajdhani",sans-serif;font-size:17px;color:#fff;letter-spacing:.04em}
a{color:#0ff0fc}
.sub{font-family:"Rajdhani",sans-serif;font-size:13px;color:#9b30ff;letter-spacing:.3em;margin-top:.35rem}
.cover{border:1px solid #1e1e2e;border-left:3px solid #39ff14;border-radius:8px;padding:1.75rem 2rem;background:linear-gradient(135deg,#111119,#0d0d12);margin-bottom:1.5rem}
.metagrid{display:flex;flex-wrap:wrap;gap:.4rem 2.5rem;font-size:11px;color:#888;letter-spacing:.05em;margin-top:1.1rem}
.metagrid b{color:#0ff0fc;font-weight:400}
.banner{font-size:10px;color:#ff8c00;border:1px solid #3a2600;background:#1a0f00;border-radius:4px;padding:.5rem .8rem;letter-spacing:.08em;margin-top:1.1rem}
.lede{font-size:13px;color:#c9d6e0;line-height:1.7;margin:.4rem 0 .3rem}
.stat-grid{display:flex;gap:12px;margin:1.25rem 0 .5rem;flex-wrap:wrap}
.stat{background:#13131a;border:1px solid #1e1e2e;padding:.9rem 1.35rem;border-radius:6px;min-width:104px;text-align:center;flex:1}
.stat-val{font-family:"Rajdhani",sans-serif;font-size:30px;font-weight:700;line-height:1}
.stat-label{font-size:8.5px;color:#555;letter-spacing:.18em;margin-top:5px}
.sevbar{display:flex;height:26px;border-radius:5px;overflow:hidden;border:1px solid #1e1e2e;margin:.4rem 0 .2rem;font-size:10px}
.sevbar span{display:flex;align-items:center;justify-content:center;color:#0d0d12;font-weight:700;min-width:0}
.sevkey{display:flex;gap:1.2rem;flex-wrap:wrap;font-size:10px;color:#888;margin-top:.5rem;letter-spacing:.08em}
.sevkey i{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:5px;vertical-align:middle}
.finding{background:#13131a;border:1px solid #1e1e2e;border-radius:7px;margin-bottom:14px;overflow:hidden;border-left:3px solid #444}
.finding-head{display:flex;align-items:center;gap:11px;padding:.8rem 1.1rem;border-bottom:1px solid #1e1e2e;flex-wrap:wrap}
.sev-badge{font-size:10px;font-weight:700;padding:2px 9px;border-radius:3px;letter-spacing:.1em;color:#0d0d12}
.verdict{font-size:9.5px;padding:1px 8px;border-radius:3px;letter-spacing:.09em;border:1px solid}
.shell-flag{font-size:9.5px;color:#0d0d12;background:#39ff14;padding:1px 8px;border-radius:3px;letter-spacing:.06em;font-weight:700}
.finding-host{margin-left:auto;font-size:12px;color:#fff}
.finding-body{padding:.85rem 1.1rem;font-size:12px}
.kv{display:flex;flex-wrap:wrap;gap:.3rem 2rem;color:#888;font-size:11px;margin-bottom:.6rem}
.kv b{color:#0ff0fc;font-weight:400}
.chips{margin:.5rem 0}
.chip{display:inline-block;font-size:9.5px;color:#9b30ff;border:1px solid #2a1a3a;background:#150e20;border-radius:10px;padding:1px 9px;margin:2px 3px 2px 0;letter-spacing:.03em}
.evidence{background:#080810;border:1px solid #1a1a2e;border-left:2px solid #9b30ff;border-radius:4px;padding:.6rem .8rem;font-size:10.5px;color:#7fe3ea;margin:.5rem 0;white-space:pre-wrap;word-break:break-word}
.remediation{font-size:11.5px;color:#c9d6e0;border-left:2px solid #39ff14;padding-left:.7rem;margin-top:.5rem}
.remediation b{color:#39ff14;font-weight:400;letter-spacing:.1em;font-size:9.5px;display:block;margin-bottom:2px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:6px 12px;text-align:left;color:#444;font-size:9px;letter-spacing:.2em;border-bottom:1px solid #1e1e2e}
td{padding:7px 12px;border-bottom:1px solid #0d0d12;vertical-align:top}
.badge-ok{color:#39ff14;border:1px solid #1e5e2e;border-radius:3px;font-size:9px;padding:0 6px;letter-spacing:.08em}
.badge-no{color:#666;border:1px solid #262626;border-radius:3px;font-size:9px;padding:0 6px;letter-spacing:.08em}
.heat{border-collapse:separate;border-spacing:6px;width:100%;table-layout:fixed}
.heat th{font-family:"Rajdhani",sans-serif;font-size:10px;color:#9b30ff;letter-spacing:.06em;text-align:center;padding:0 0 4px;border:none;vertical-align:bottom}
.cell{border-radius:4px;padding:6px 5px;font-size:9px;text-align:center;line-height:1.25;border:1px solid #1a1a2e;min-height:38px}
.cell b{display:block;font-family:"Rajdhani",sans-serif;font-size:11px;letter-spacing:.02em}
.host-card{background:#13131a;border:1px solid #1e1e2e;border-radius:6px;margin-bottom:11px;overflow:hidden}
.host-header{display:flex;align-items:center;gap:12px;padding:.65rem 1rem;border-bottom:1px solid #1e1e2e;flex-wrap:wrap}
.host-ip{font-size:14px;color:#fff}
.host-os{font-size:11px;color:#555;margin-left:auto}
.empty-msg{font-size:12px;color:#444;padding:1rem;text-align:center}
.footer{margin-top:3rem;font-size:10px;color:#2a2a2a;text-align:center;letter-spacing:.2em;border-top:1px solid #131320;padding-top:1.2rem}
.toc{font-size:11px;color:#888;columns:2;margin-top:.5rem}
.toc a{color:#0ff0fc;text-decoration:none}
@media print{
  body{background:#fff;color:#111;padding:0}
  .cover,.finding,.host-card,.stat,.evidence,table,.heat{break-inside:avoid;page-break-inside:avoid}
  h2{break-after:avoid;page-break-after:avoid}
  .section{break-before:auto}
  a{color:#111;text-decoration:none}
}
"""


def render_html(data: dict, include_secrets: bool = False) -> str:
    """Render the full SPECTR engagement report as a standalone HTML document."""
    eng = data.get('engagement') or {}
    meta = data.get('meta') or {}
    st = data.get('stats') or {}
    gen = _esc(data.get('generated', ''))
    client  = _esc(eng.get('client', 'Authorized Engagement'))
    scope   = _esc(eng.get('scope', meta.get('target', 'unknown')))
    operator = _esc(eng.get('operator', 'H3x-Dash Operator'))

    parts: list[str] = []
    parts.append(f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>H3x-Dash // Engagement Report // {gen}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
<style>{_CSS}</style></head><body><div class="wrap">''')

    # ── Cover ─────────────────────────────────────────────────────────────────
    parts.append(f'''<div class="cover">
<h1>// H3x-Dash //</h1>
<div class="sub">PENETRATION TEST — ENGAGEMENT REPORT</div>
<div class="metagrid">
  <span>CLIENT: <b>{client}</b></span>
  <span>SCOPE: <b>{scope}</b></span>
  <span>OPERATOR: <b>{operator}</b></span>
  <span>GENERATED: <b>{gen}</b></span>
</div>
<div class="banner">AUTHORIZED USE ONLY — This report documents testing performed under written authorization. Contains sensitive security findings; handle as confidential.</div>
</div>''')

    # ── Table of contents ─────────────────────────────────────────────────────
    parts.append('''<div class="toc">
<a href="#exec">01 · Executive Summary</a><br>
<a href="#findings">02 · Findings</a><br>
<a href="#creds">03 · Recovered Credentials</a><br>
<a href="#attack">04 · MITRE ATT&CK Coverage</a><br>
<a href="#appendix">05 · Host Enumeration Appendix</a></div>''')

    # ── Executive summary ─────────────────────────────────────────────────────
    parts.append('<div class="section" id="exec"><h2>// 01 · EXECUTIVE SUMMARY</h2>')
    parts.append(f'<p class="lede">{_esc(_exec_lede(data))}</p>')
    parts.append(_stat_grid(st))
    parts.append(_sev_bar(data.get('sev_counts', {})))
    parts.append('</div>')

    # ── Findings ──────────────────────────────────────────────────────────────
    parts.append('<div class="section" id="findings"><h2>// 02 · FINDINGS</h2>')
    findings = data.get('findings', [])
    if findings:
        for i, f in enumerate(findings, 1):
            parts.append(_finding_card(i, f))
    else:
        parts.append('<p class="empty-msg">No findings recorded for this engagement.</p>')
    parts.append('</div>')

    # ── Credentials ───────────────────────────────────────────────────────────
    parts.append('<div class="section" id="creds"><h2>// 03 · RECOVERED CREDENTIALS</h2>')
    parts.append(_creds_table(data.get('credentials', []), include_secrets))
    parts.append('</div>')

    # ── ATT&CK coverage ───────────────────────────────────────────────────────
    parts.append('<div class="section" id="attack"><h2>// 04 · MITRE ATT&CK COVERAGE</h2>')
    parts.append(_attack_heatmap(data.get('attack_matrix', {})))
    parts.append('</div>')

    # ── Host appendix ─────────────────────────────────────────────────────────
    parts.append('<div class="section" id="appendix"><h2>// 05 · HOST ENUMERATION APPENDIX</h2>')
    parts.append(_host_appendix(data.get('hosts', [])))
    parts.append('</div>')

    parts.append(f'<p class="footer">H3x-Dash // Automated Penetration Framework // '
                 f'Authorized Use Only // {gen}</p></div></body></html>')
    return ''.join(parts)


def _exec_lede(data: dict) -> str:
    st = data.get('stats', {})
    sc = data.get('sev_counts', {})
    bits = [f"{st.get('hosts', 0)} host(s) assessed within scope"]
    if st.get('findings'):
        bits.append(f"{st['findings']} finding(s) recorded "
                    f"({sc.get('CRITICAL', 0)} critical, {sc.get('HIGH', 0)} high)")
    if st.get('exploited'):
        bits.append(f"{st['exploited']} confirmed by opened session")
    if st.get('creds'):
        bits.append(f"{st['creds']} credential(s) recovered")
    lede = '; '.join(bits) + '.'
    if sc.get('CRITICAL'):
        lede += (' Critical findings permit full compromise of affected hosts '
                 'and require immediate remediation.')
    elif st.get('findings'):
        lede += ' Prioritise remediation by severity as detailed below.'
    else:
        lede += ' No exploitable conditions were confirmed during this window.'
    return lede


def _stat_grid(st: dict) -> str:
    cells = [
        ('#fff',     st.get('hosts', 0),     'HOSTS'),
        ('#ff2d55',  st.get('critical', 0),  'CRITICAL'),
        ('#ff8c00',  st.get('high', 0),      'HIGH'),
        ('#39ff14',  st.get('exploited', 0), 'SHELLS'),
        ('#9b30ff',  st.get('creds', 0),     'CREDS'),
        ('#0ff0fc',  st.get('findings', 0),  'FINDINGS'),
    ]
    inner = ''.join(
        f'<div class="stat"><div class="stat-val" style="color:{c}">{v}</div>'
        f'<div class="stat-label">{lbl}</div></div>' for c, v, lbl in cells)
    return f'<div class="stat-grid">{inner}</div>'


def _sev_bar(sev_counts: dict) -> str:
    total = sum(sev_counts.values()) or 0
    if not total:
        return ''
    segs = ''
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        n = sev_counts.get(sev, 0)
        if not n:
            continue
        pct = round(100 * n / total, 1)
        label = str(n) if pct >= 6 else ''
        segs += (f'<span style="flex:{n};background:{SEVERITY_COLOR[sev]}" '
                 f'title="{sev}: {n}">{label}</span>')
    key = ''.join(
        f'<span><i style="background:{SEVERITY_COLOR[s]}"></i>{s} '
        f'{sev_counts.get(s, 0)}</span>'
        for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
        if sev_counts.get(s, 0))
    return f'<div class="sevbar">{segs}</div><div class="sevkey">{key}</div>'


def _finding_card(idx: int, f: dict) -> str:
    sev = str(f.get('severity', 'INFO')).upper()
    sev_color = SEVERITY_COLOR.get(sev, '#888')
    title = _esc(f.get('msf_module') or f.get('cve')
                 or f"{f.get('service', 'service')} on {f.get('host_ip', '?')}")
    verdict = f.get('verdict')
    verdict_html = ''
    if verdict:
        vc = VERDICT_COLOR.get(verdict, '#888')
        verdict_html = (f'<span class="verdict" style="color:{vc};'
                        f'border-color:{vc}">{VERDICT_LABEL.get(verdict, verdict)}</span>')
    shell_html = ('<span class="shell-flag">◆ SESSION OPENED</span>'
                  if f.get('exploited') else '')

    kv = []
    if f.get('cve'):
        kv.append(f'CVE: <b>{_esc(f["cve"])}</b>')
    if f.get('msf_module'):
        kv.append(f'MODULE: <b>{_esc(f["msf_module"])}</b>')
    if f.get('service'):
        port = f.get('port')
        kv.append(f'SERVICE: <b>{_esc(f["service"])}'
                  f'{":" + _esc(port) if port else ""}</b>')
    if f.get('cvss_score'):
        kv.append(f'CVSS: <b>{_esc(f["cvss_score"])}</b>')
    kv_html = f'<div class="kv">{"".join(f"<span>{x}</span>" for x in kv)}</div>' if kv else ''

    labels = f.get('attack_labels') or []
    techs = f.get('attack_techniques') or []
    chips = ''.join(
        f'<span class="chip">{_esc(t)} · {_esc(lbl)}</span>'
        for t, lbl in zip(techs, labels))
    chips_html = f'<div class="chips">{chips}</div>' if chips else ''

    detail = f.get('detail', '')
    ev_lines = [detail] if detail else []
    ev_lines += list(f.get('evidence') or [])
    ev_html = ''
    if ev_lines:
        ev_html = ('<div class="evidence">'
                   + '\n'.join(_esc(l) for l in ev_lines if l) + '</div>')

    rem = f.get('remediation', '')
    rem_html = (f'<div class="remediation"><b>REMEDIATION</b>{_esc(rem)}</div>'
                if rem else '')

    return f'''<div class="finding" style="border-left-color:{sev_color}">
<div class="finding-head">
  <span style="color:#555;font-size:11px">#{idx:02d}</span>
  <span class="sev-badge" style="background:{sev_color}">{sev}</span>
  {verdict_html}{shell_html}
  <span class="finding-host">{_esc(f.get('host_ip', ''))}</span>
</div>
<div class="finding-body">
  <h3>{title}</h3>
  {kv_html}{chips_html}{ev_html}{rem_html}
</div></div>'''


def _creds_table(creds: list, include_secrets: bool) -> str:
    if not creds:
        return '<p class="empty-msg">No credentials recovered during this engagement.</p>'
    note = ('' if include_secrets else
            '<p style="font-size:10px;color:#555;margin-bottom:.6rem;'
            'letter-spacing:.05em">Secret material is masked in this copy. '
            'Regenerate with include_secrets for an internal working copy.</p>')
    rows = ''
    for c in creds:
        user = _esc(c.get('username', '') or '—')
        dom = c.get('domain')
        if dom:
            user = f'{_esc(dom)}\\{user}'
        host = _esc(c.get('host_ip', '') or '—')
        port = c.get('host_port')
        if port:
            host += f':{_esc(port)}'
        verified = (('<span class="badge-ok">VERIFIED</span>')
                    if c.get('verified') else
                    '<span class="badge-no">unverified</span>')
        rows += f'''<tr>
  <td style="color:#9b30ff">{_esc(c.get('type', ''))}</td>
  <td style="color:#fff">{user}</td>
  <td style="color:#0ff0fc">{host}</td>
  <td>{mask_secret(c, include_secrets)}</td>
  <td>{verified}</td>
  <td style="color:#555;font-size:10px">{_esc(c.get('source_tool', ''))}</td>
</tr>'''
    return (f'{note}<table><thead><tr><th>TYPE</th><th>USERNAME</th>'
            f'<th>HOST</th><th>SECRET</th><th>STATUS</th><th>SOURCE</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')


def _attack_heatmap(matrix_counts: dict) -> str:
    """ATT&CK Navigator-style grid: tactics as columns, chain techniques as
    heat-colored cells (count of findings that touched each technique)."""
    by_tactic: dict[str, list] = {t: [] for t in TACTIC_ORDER}
    for tech, tactic in TECHNIQUE_TACTIC.items():
        by_tactic.setdefault(tactic, []).append(tech)
    present = [t for t in TACTIC_ORDER if by_tactic.get(t)]
    if not present:
        return '<p class="empty-msg">No ATT&CK techniques in scope.</p>'

    total_hits = sum(v for k, v in matrix_counts.items() if k != 'unmapped')
    unmapped = matrix_counts.get('unmapped', 0)

    def _heat(n: int) -> tuple[str, str]:
        if n <= 0:
            return '#0f0f16', '#3a3a4a'      # covered-not-triggered
        if n == 1:
            return '#241436', '#9b30ff'      # touched
        if n <= 3:
            return '#3a1350', '#c060ff'      # repeated
        return '#0a2e30', '#0ff0fc'          # heavy

    cols = ''
    for tactic in present:
        techs = sorted(by_tactic[tactic],
                       key=lambda t: (-matrix_counts.get(t, 0), t))
        cells = ''
        for t in techs:
            n = matrix_counts.get(t, 0)
            bg, fg = _heat(n)
            badge = f'<span style="color:#0ff0fc">×{n}</span>' if n else ''
            cells += (f'<div class="cell" style="background:{bg};'
                      f'border-color:{fg};color:{fg}">'
                      f'<b>{_esc(t)}</b>{_esc(mitre_mapping.technique_label(t))} '
                      f'{badge}</div>')
        cols += (f'<td style="vertical-align:top">'
                 f'<div style="font-family:Rajdhani,sans-serif;font-size:10px;'
                 f'color:#9b30ff;letter-spacing:.05em;text-align:center;'
                 f'margin-bottom:5px">{_esc(tactic.upper())}</div>{cells}</td>')

    legend = ('<div class="sevkey" style="margin-top:.9rem">'
              '<span><i style="background:#241436;border:1px solid #9b30ff"></i>touched</span>'
              '<span><i style="background:#3a1350;border:1px solid #c060ff"></i>repeated</span>'
              '<span><i style="background:#0a2e30;border:1px solid #0ff0fc"></i>heavy use</span>'
              '<span><i style="background:#0f0f16;border:1px solid #3a3a4a"></i>in chain, not triggered</span>'
              '</div>')
    summ = (f'<p style="font-size:11px;color:#888;margin-bottom:.8rem">'
            f'{total_hits} finding-to-technique mapping(s) across {len(present)} '
            f'tactic(s)'
            + (f'; {unmapped} finding(s) unmapped.' if unmapped else '.')
            + '</p>')
    return (f'{summ}<table class="heat"><tr>{cols}</tr></table>{legend}')


def _host_appendix(hosts: list) -> str:
    if not hosts:
        return '<p class="empty-msg">No hosts recorded.</p>'
    out = ''
    for h in hosts:
        rows = ''
        for p in h.get('ports', []):
            rc = {'danger': '#ff4444', 'warning': '#ff8c00',
                  'info': '#0ff0fc'}.get(p.get('risk', 'info'), '#888')
            rows += (f'<tr><td style="color:{rc}">{_esc(p.get("port", ""))}</td>'
                     f'<td style="color:#888">{_esc(str(p.get("protocol", "tcp")).upper())}</td>'
                     f'<td style="color:{rc}">{_esc(p.get("service", ""))}</td>'
                     f'<td style="color:#aaa;font-size:11px">{_esc(p.get("version", "—") or "—")}</td>'
                     f'<td style="color:{rc};font-size:10px">{_esc(str(p.get("risk", "info")).upper())}</td></tr>')
        table = ('<table><thead><tr><th>PORT</th><th>PROTO</th><th>SERVICE</th>'
                 '<th>VERSION</th><th>RISK</th></tr></thead><tbody>'
                 + rows + '</tbody></table>') if rows else \
                '<p class="empty-msg">No open ports recorded.</p>'
        out += f'''<div class="host-card"><div class="host-header">
<span class="host-ip">{_esc(h.get("ip", ""))}</span>
<span class="host-os">{_esc(h.get("os", "Unknown OS"))}</span>
</div>{table}</div>'''
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Public engine
# ══════════════════════════════════════════════════════════════════════════════

class ReportEngine:
    """Generate and persist client-deliverable engagement reports."""

    def __init__(self, report_dir):
        self.report_dir = Path(report_dir)

    def generate(self, data: dict, fmt: str = 'html',
                 include_secrets: bool = False) -> dict:
        """Render + persist. Returns loot-style {status, filename, path, ...}."""
        fmt = (fmt or 'html').strip().lower()
        ts = _utcnow().strftime('%Y%m%d_%H%M%S')
        stem = f'h3x-dash_pentest_report_{ts}'
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            # Always persist the machine-readable JSON alongside.
            json_path = self.report_dir / f'{stem}.json'
            json_path.write_text(json.dumps(data, indent=2, default=str),
                                 encoding='utf-8')
            if fmt == 'json':
                out_path = json_path
            else:
                html_path = self.report_dir / f'{stem}.html'
                html_path.write_text(render_html(data, include_secrets),
                                     encoding='utf-8')
                out_path = html_path
        except OSError as exc:
            return {'status': 'error', 'message': f'report write failed: {exc}'}

        return {
            'status':   'ok',
            'filename': out_path.name,
            'path':     str(out_path),
            'size_kb':  round(out_path.stat().st_size / 1024, 1),
            'size':     out_path.stat().st_size,
            'findings': (data.get('stats') or {}).get('findings', 0),
        }

    @staticmethod
    def to_pdf(html_path) -> dict:
        """Render an existing HTML report to PDF if WeasyPrint is installed.

        Kept dependency-free by design: without WeasyPrint the operator uses
        the browser's built-in "Save as PDF" (the markup is print-styled). This
        is the single hook a future PDF path plugs into.
        """
        html_path = Path(html_path)
        pdf_path = html_path.with_suffix('.pdf')
        try:
            from weasyprint import HTML  # type: ignore
        except Exception:
            return {'status': 'unavailable',
                    'message': 'WeasyPrint not installed — open the HTML in a '
                               'browser and Print → Save as PDF, or '
                               '`pip install weasyprint`.'}
        try:
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return {'status': 'ok', 'path': str(pdf_path),
                    'filename': pdf_path.name}
        except Exception as exc:
            return {'status': 'error', 'message': f'pdf render failed: {exc}'}
