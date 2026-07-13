#!/usr/bin/env python3
"""Offline audit — Loot report generation, escaping, and download hardening.

Regression-guards the Loot bugs fixed in the Operations pass:
  * HTML reports escape session metadata + scan command/target (stored XSS)
  * format is case-insensitive and JSON reports report size_kb
  * list_reports skips non-file entries / broken symlinks
  * the download route whitelists report filenames + requires is_file()
  * loot.html refreshes safely (esc helper, /run modal, always-present tbody)
"""
import sys
import tempfile
from pathlib import Path

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.loot import LootManager

XSS = '<script>alert(1)</script>'

with tempfile.TemporaryDirectory() as td:
    lm = LootManager()
    lm._report_dir = Path(td)          # redirect output to the sandbox

    scan = {
        'hosts': [{'ip': '10.0.0.5', 'type': 'server', 'os': 'Linux',
                   'ports': [{'port': 445, 'service': 'smb', 'risk': 'danger',
                              'version': XSS}]}],
        'meta': {'target': f'10.0.0.0/24 {XSS}', 'command': f'nmap {XSS}'},
    }
    sessions = [{'id': '1', 'type': 'shell', 'target': '10.0.0.5',
                 'user': XSS, 'platform': 'linux', 'arch': 'x64', 'info': XSS}]

    # ── HTML escaping ──────────────────────────────────────────────────────────
    html = lm._render_html({
        'generated': '2026-06-14T00:00:00', 'scan_target': scan['meta']['target'],
        'scan_command': scan['meta']['command'], 'hosts': scan['hosts'],
        'sessions': sessions, 'vuln_summary': lm._vuln_summary(scan['hosts']),
        'meta': scan['meta'],
    })
    if '<script>alert(1)</script>' not in html:
        ok('raw <script> never appears in the rendered report')
    else:
        fail('UNESCAPED <script> in HTML report — stored XSS')
    if html.count('&lt;script&gt;') >= 3:    # session info+user, scan cmd, target, version
        ok('session/scan/target fields are HTML-escaped')
    else:
        fail(f'expected ≥3 escaped XSS occurrences, got {html.count("&lt;script&gt;")}')

    # ── format case-insensitivity + size_kb ─────────────────────────────────────
    r_html = lm.generate_report(scan, sessions, fmt='HTML')   # uppercase
    if r_html['status'] == 'ok' and r_html['filename'].endswith('.html') \
            and 'size_kb' in r_html:
        ok('fmt="HTML" (uppercase) produces an .html report with size_kb')
    else:
        fail(f'uppercase HTML format wrong: {r_html}')
    r_json = lm.generate_report(scan, sessions, fmt='json')
    if r_json['filename'].endswith('.json') and 'size_kb' in r_json:
        ok('JSON report reports size_kb')
    else:
        fail(f'JSON report size_kb missing: {r_json}')

    # ── list_reports skips a non-file entry ─────────────────────────────────────
    (Path(td) / 'h3x-dash_report_99999999_000000').mkdir()    # a directory match
    listed = lm.list_reports()
    if all(not r['filename'].endswith('_000000') for r in listed) and listed:
        ok('list_reports skips directory entries matching the report glob')
    else:
        fail('list_reports included a non-file entry')

# ── download route hardening (source scan) ────────────────────────────────────
app_src = Path('h3x-dash.py').read_text(encoding='utf-8')
for needle, desc in [
    ('_REPORT_NAME_RX', 'download route whitelists report filenames by regex'),
    ('safe_path.is_file()', 'download route requires is_file()'),
    ('h3x-dash_(pentest_)?report_[0-9_]+', 'whitelist regex matches generated report names only'),
]:
    if needle in app_src:
        ok(desc)
    else:
        fail(f'missing: {desc}')

# ── loot.html safe rendering (source scan) ────────────────────────────────────
html_src = Path('templates/loot.html').read_text(encoding='utf-8')
for needle, desc in [
    ('function esc(', 'loot.html defines an esc() helper'),
    ('session-cmd-btn', 'CMD buttons use event delegation (no inline onclick id)'),
    ('/run', 'session modal uses the type-aware /run endpoint'),
    ('id="sessions-tbody"', 'sessions tbody always present for live refresh'),
    ('id="reports-tbody"', 'reports tbody always present for live refresh'),
]:
    if needle in html_src:
        ok(desc)
    else:
        fail(f'missing in loot.html: {desc}')
if '/api/msf/session/cmd' not in html_src:
    ok('loot.html no longer uses the broken /api/msf/session/cmd endpoint')
else:
    fail('loot.html still posts to /api/msf/session/cmd (Meterpreter broken)')

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print('═' * 72)
print(f' LOOT AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
