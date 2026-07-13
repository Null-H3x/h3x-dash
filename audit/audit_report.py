#!/usr/bin/env python3
"""Audit for report_engine — findings assembly, masking, rendering, disk load.

Offline only (no msfrpcd). Exercises the cross-referencing logic, the
secret-masking guarantee, ATT&CK heatmap rendering, HTML escaping, and the
disk-assembly path against synthetic artifacts.
"""
import sys; import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)
import json
import tempfile
from pathlib import Path

from modules import report_engine as R

FAIL, OK = [], []
def fail(m): FAIL.append(m)
def ok(m):   OK.append(m)


# ── Fixtures ──────────────────────────────────────────────────────────────────
HOSTS = [
    {'ip': '10.0.0.5', 'os': 'Windows Server 2016', 'ports': [
        {'port': 445, 'protocol': 'tcp', 'service': 'microsoft-ds',
         'version': 'Samba', 'risk': 'danger'},
        {'port': 80, 'protocol': 'tcp', 'service': 'http',
         'version': 'IIS', 'risk': 'info'}]},
    {'ip': '10.0.0.12', 'os': 'Ubuntu 14.04', 'ports': [
        {'port': 139, 'protocol': 'tcp', 'service': 'netbios-ssn',
         'version': 'Samba 3.0.20', 'risk': 'danger'}]},
]
SESSIONS = [
    {'id': '1', 'type': 'meterpreter', 'target': '10.0.0.5:445',
     'user': 'SYSTEM', 'platform': 'windows', 'arch': 'x64'},
]
VERDICTS = {
    '10.0.0.5': {
        'exploit/windows/smb/ms17_010_eternalblue':
            {'verdict': 'VULNERABLE', 'detail': 'likely vulnerable'},
        'exploit/windows/smb/cve_2020_0796_smbghost':
            {'verdict': 'DETECTED', 'detail': 'compression on'},
    },
    '10.0.0.12': {
        'exploit/multi/samba/usermap_script':
            {'verdict': 'NO_CHECK', 'detail': 'no check method'},
    },
}
RUNS = [
    # EternalBlue popped a shell.
    {'ts': '2026-07-13T14:00:00', 'module': 'exploit/windows/smb/ms17_010_eternalblue',
     'action': 'run', 'rhost': '10.0.0.5', 'status': 'session_opened',
     'session_opened': True, 'exploit_failed': False},
    # smbghost was only CHECKED — no session. Must NOT be marked exploited even
    # though the same host has a shell from EternalBlue.
    {'ts': '2026-07-13T14:05:00', 'module': 'exploit/windows/smb/cve_2020_0796_smbghost',
     'action': 'check', 'rhost': '10.0.0.5', 'status': 'launched',
     'session_opened': False, 'exploit_failed': False},
    # usermap popped a shell but the module has NO_CHECK verdict.
    {'ts': '2026-07-13T14:10:00', 'module': 'exploit/multi/samba/usermap_script',
     'action': 'run', 'rhost': '10.0.0.12', 'status': 'session_opened',
     'session_opened': True, 'exploit_failed': False},
]
CREDS = [
    {'type': 'ntlm_hash', 'username': 'Administrator', 'domain': 'WIN',
     'value': 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
     'host_ip': '10.0.0.5', 'source_tool': 'hashdump', 'verified': True},
    {'type': 'password', 'username': 'bob', 'value': 'S3cr3tP@ss',
     'host_ip': '10.0.0.12', 'source_tool': 'ssh', 'verified': False},
    {'type': 'ssh_key', 'username': 'root',
     'value': '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAmisc\n-----END-----',
     'host_ip': '10.0.0.12', 'source_tool': 'loot', 'verified': False},
    {'type': 'username_only', 'username': 'svc_backup', 'value': '',
     'host_ip': '10.0.0.5', 'source_tool': 'enum4linux', 'verified': False},
]
SECRET_STRINGS = ['31d6cfe0d16ae931b73c59d7e0c089c0', 'S3cr3tP@ss', 'OPENSSH PRIVATE KEY']


def _find(findings, host, needle):
    for f in findings:
        if f.get('host_ip') == host and needle in (
                (f.get('msf_module') or '') + (f.get('service') or '')):
            return f
    return None


# ── build_findings ────────────────────────────────────────────────────────────
fx = R.build_findings(HOSTS, VERDICTS, RUNS)

eb = _find(fx, '10.0.0.5', 'eternalblue')
if eb and eb['severity'] == 'CRITICAL' and eb['exploited']:
    ok('EternalBlue: VULNERABLE + session_opened → CRITICAL/exploited')
else:
    fail(f'EternalBlue finding wrong: {eb}')

um = _find(fx, '10.0.0.12', 'usermap')
if um and um['exploited'] and um['severity'] == 'CRITICAL':
    ok('usermap NO_CHECK but session_opened → severity overridden to CRITICAL')
else:
    fail(f'usermap severity override failed: {um}')

sg = _find(fx, '10.0.0.5', 'smbghost')
if sg and sg['exploited'] is False and sg['severity'] == 'MEDIUM':
    ok('smbghost check-only NOT credited with EternalBlue\'s shell (no false positive)')
else:
    fail(f'smbghost false-positive attribution: {sg}')

svc = _find(fx, '10.0.0.12', 'netbios-ssn')
if svc and svc['severity'] == 'HIGH' and not svc['exploited']:
    ok('Unconfirmed dangerous service → HIGH exposure finding')
else:
    fail(f'dangerous-service finding wrong: {svc}')

# Sorting: first finding must be exploited + CRITICAL.
if fx and fx[0].get('exploited') and fx[0]['severity'] == 'CRITICAL':
    ok('Findings sorted: exploited/critical first')
else:
    fail(f'sort order wrong, head={fx[0] if fx else None}')

# ATT&CK annotation applied.
if eb and eb.get('attack_techniques'):
    ok(f'ATT&CK techniques annotated ({eb["attack_techniques"]})')
else:
    fail('ATT&CK annotation missing on finding')

# Dedup: no duplicate (host, module).
keys = [(f.get('host_ip'), f.get('msf_module') or f.get('cve')
         or f.get('service')) for f in fx]
if len(keys) == len(set(keys)):
    ok('No duplicate findings')
else:
    fail(f'duplicate findings: {keys}')


# ── mask_secret ───────────────────────────────────────────────────────────────
for c in CREDS:
    masked = R.mask_secret(c, include_secrets=False)
    if c['value'] and c['value'] in masked and c['type'] != 'username_only':
        fail(f'mask leaked raw value for {c["type"]}: {masked}')
        break
else:
    ok('mask_secret hides raw material for every cred type')

pw = next(c for c in CREDS if c['type'] == 'password')
if '•' in R.mask_secret(pw) and 'S3cr3tP@ss' not in R.mask_secret(pw):
    ok('Password masked to dots + length, value withheld')
else:
    fail('password masking wrong')

if R.mask_secret(pw, include_secrets=True) == R._esc('S3cr3tP@ss'):
    ok('include_secrets=True reveals raw value (internal copy)')
else:
    fail('include_secrets did not reveal value')


# ── render_html: masking + escaping + structure ───────────────────────────────
data = R._finalize(HOSTS, SESSIONS, CREDS, fx,
                   {'target': '10.0.0.0/24'}, {'client': 'Range'})

client_html = R.render_html(data, include_secrets=False)
intl_html   = R.render_html(data, include_secrets=True)

leaked = [s for s in SECRET_STRINGS if s in client_html]
if not leaked:
    ok('CLIENT report contains NO raw secret material')
else:
    fail(f'CLIENT report LEAKED: {leaked}')

present = [s for s in SECRET_STRINGS if s in intl_html]
if len(present) == len(SECRET_STRINGS):
    ok('INTERNAL report (include_secrets) contains full material')
else:
    fail(f'internal report missing secrets: '
         f'{set(SECRET_STRINGS) - set(present)}')

# XSS / injection escaping — a compromised host can return hostile strings.
xss_host = [{'ip': '<script>alert(1)</script>', 'os': '"><img src=x onerror=alert(2)>',
             'ports': [{'port': 1, 'service': '<b>evil</b>', 'risk': 'danger'}]}]
xf = R.build_findings(xss_host, {}, [])
xdata = R._finalize(xss_host, [], [], xf, {}, {})
xhtml = R.render_html(xdata)
# The payload is neutralised when its '<' delimiter is escaped — the report is
# also entirely script-free, so any surviving '<script'/'<img' means injection.
# (Inert text like 'onerror=alert(2)' inside an escaped &lt;img&gt; is harmless
# and is NOT a leak, so we check for the tag delimiter, not the substring.)
low = xhtml.lower()
if '<script' not in low and '<img' not in low and '&lt;script&gt;' in xhtml:
    ok('Hostile host strings HTML-escaped; report is tag-injection-free')
else:
    fail('XSS escaping failed in rendered report')

# ATT&CK heatmap present with tactic columns.
if 'MITRE ATT&CK COVERAGE' in client_html and 'CREDENTIAL ACCESS' in client_html \
        and 'LATERAL MOVEMENT' in client_html:
    ok('ATT&CK heatmap renders tactic columns')
else:
    fail('ATT&CK heatmap tactics missing')

# Exec summary reflects counts.
if 'host(s) assessed' in client_html and 'CRITICAL' in client_html:
    ok('Executive summary renders')
else:
    fail('executive summary missing')


# ── Empty-state safety ────────────────────────────────────────────────────────
try:
    empty = R._finalize([], [], [], [], {}, {})
    ehtml = R.render_html(empty)
    if 'No findings recorded' in ehtml and 'No credentials recovered' in ehtml:
        ok('Empty engagement renders without error')
    else:
        fail('empty-state text missing')
except Exception as exc:
    fail(f'empty render raised: {exc}')


# ── assemble_from_disk ────────────────────────────────────────────────────────
class _Cfg:
    pass

try:
    tmp = Path(tempfile.mkdtemp())
    cfg = _Cfg()
    cfg.REPORT_DIR = tmp / 'reports'; cfg.LOOT_DIR = tmp / 'loot'
    cfg.LOG_DIR = tmp / 'logs'
    for d in (cfg.REPORT_DIR, cfg.LOOT_DIR, cfg.LOG_DIR / 'exploit'):
        d.mkdir(parents=True, exist_ok=True)

    (cfg.REPORT_DIR / 'h3x-dash_report_20260713_120000.json').write_text(
        json.dumps({'hosts': HOSTS, 'sessions': SESSIONS,
                    'meta': {'target': '10.0.0.0/24'}}))
    (cfg.LOOT_DIR / 'credentials.json').write_text(
        json.dumps({'credentials': {c['type'] + str(i): c
                                    for i, c in enumerate(CREDS)}}))
    (cfg.LOOT_DIR / 'msf_validation.json').write_text(json.dumps(
        {f'{ip}::{mod}': vd
         for ip, mods in VERDICTS.items() for mod, vd in mods.items()}))
    (cfg.LOG_DIR / 'exploit' / '20260713T140000_run_eb_10_0_0_5.json').write_text(
        json.dumps({'ts': '2026-07-13T14:00:00',
                    'module': 'exploit/windows/smb/ms17_010_eternalblue',
                    'action': 'run', 'status': 'session_opened',
                    'session_opened': True,
                    'options': {'RHOSTS': '10.0.0.5'}}))

    d2 = R.assemble_from_disk(cfg)
    checks = [
        (d2['stats']['hosts'] == 2, 'hosts loaded'),
        (d2['stats']['creds'] == len(CREDS), 'creds loaded'),
        (any(f.get('verdict') == 'VULNERABLE' for f in d2['findings']),
         'validator verdicts loaded'),
        (any(f.get('exploited') for f in d2['findings']),
         'exploit runs loaded + attributed'),
    ]
    if all(c for c, _ in checks):
        ok('assemble_from_disk reconstructs report from all 4 artifact sources')
    else:
        fail('assemble_from_disk missing: '
             + ', '.join(m for c, m in checks if not c))

    # Full generate() writes a file.
    eng = R.ReportEngine(cfg.REPORT_DIR)
    res = eng.generate(d2, fmt='html')
    if res['status'] == 'ok' and Path(res['path']).is_file():
        ok(f'ReportEngine.generate wrote {res["filename"]} ({res["size_kb"]} KB)')
    else:
        fail(f'generate failed: {res}')
except Exception as exc:
    import traceback; traceback.print_exc()
    fail(f'disk-assembly path raised: {exc}')


# ── to_pdf graceful degradation ───────────────────────────────────────────────
pdf_res = R.ReportEngine.to_pdf(tmp / 'nope.html')
if pdf_res['status'] in ('unavailable', 'ok', 'error'):
    ok(f'to_pdf degrades gracefully (status={pdf_res["status"]})')
else:
    fail(f'to_pdf unexpected: {pdf_res}')


# ── Summary ───────────────────────────────────────────────────────────────────
print('\n'.join(f'  [OK]   {m}' for m in OK))
print('\n'.join(f'  [FAIL] {m}' for m in FAIL))
print('═' * 64)
print(f' REPORT_ENGINE AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 64)
sys.exit(1 if FAIL else 0)
