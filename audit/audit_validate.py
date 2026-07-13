#!/usr/bin/env python3
"""Audit for the MSF validation stage — engine, endpoints, page, carry-forward."""
import sys; import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)
import tempfile, time, json
from pathlib import Path

from modules.msf_validator import (
    MsfValidator, VULNERABLE, NOT_VULNERABLE, DETECTED, NO_CHECK, UNKNOWN, ERROR,
)

FAIL, OK = [], []
def fail(m): FAIL.append(m)
def ok(m):   OK.append(m)


# ── Fake engine that returns scripted check verdicts ──────────────────────────
class FakeEngine:
    def __init__(self):
        self.calls = []
    def run_exploit(self, module, options, action):
        self.calls.append((module, dict(options), action))
        if action != 'check':
            return {'status': 'error', 'message': 'expected check action'}
        if 'eternalblue' in module:
            return {'status': 'launched', 'check_vulnerable': True, 'check_safe': False}
        if 'smbghost' in module:
            return {'status': 'launched', 'check_vulnerable': False, 'check_safe': True}
        if 'broken' in module:
            return {'status': 'error', 'message': 'msfrpcd malformed response'}
        return {'status': 'launched', 'check_vulnerable': False, 'check_safe': False}


def fresh_validator():
    tmp = Path(tempfile.mkdtemp())
    return MsfValidator(FakeEngine(), tmp), tmp


def run_and_wait(v, ip, cands, stealth=0):
    lines = []
    v.validate(ip, cands, stealth=stealth, on_progress=lambda m: lines.append(m))
    # wait for thread
    for _ in range(200):
        if not v.is_running():
            break
        time.sleep(0.02)
    time.sleep(0.05)
    return lines


CANDS = [
    {'msf_module': 'exploit/windows/smb/ms17_010_eternalblue', 'msf_rport': 445, 'cve': 'CVE-2017-0144'},
    {'msf_module': 'exploit/windows/smb/cve_2020_0796_smbghost', 'msf_rport': 445, 'cve': 'CVE-2020-0796'},
    {'msf_module': 'exploit/windows/smb/broken_mod', 'msf_rport': 445, 'cve': None},
    {'msf_module': 'exploit/windows/smb/no_check_mod', 'msf_rport': 445, 'cve': None},
]

# ── 1. Verdict mapping ─────────────────────────────────────────────────────────
v, _ = fresh_validator()
run_and_wait(v, '192.168.1.43', CANDS)
verds = v.get_verdicts_for_host('192.168.1.43')
expect = {
    'exploit/windows/smb/ms17_010_eternalblue':   VULNERABLE,
    'exploit/windows/smb/cve_2020_0796_smbghost': NOT_VULNERABLE,
    'exploit/windows/smb/broken_mod':             ERROR,
    'exploit/windows/smb/no_check_mod':           UNKNOWN,
}
bad = {m: verds.get(m, {}).get('verdict') for m, e in expect.items()
       if verds.get(m, {}).get('verdict') != e}
if not bad:
    ok("Verdict mapping correct: vulnerable→VULNERABLE, safe→NOT_VULNERABLE, "
       "error→ERROR, no-verdict→UNKNOWN")
else:
    fail(f"Verdict mapping wrong: {bad}")

# ── 2. Dedup — same module across multiple CVEs checked once ──────────────────
v, _ = fresh_validator()
dup_cands = CANDS + [{'msf_module': 'exploit/windows/smb/ms17_010_eternalblue',
                      'msf_rport': 445, 'cve': 'dupe'}]
run_and_wait(v, '10.0.0.1', dup_cands)
eb_checks = [c for c in v._engine.calls
             if 'eternalblue' in c[0]]
if len(eb_checks) == 1:
    ok("Dedup works — module appearing under multiple CVEs is checked once")
else:
    fail(f"Dedup failed — eternalblue checked {len(eb_checks)} times")

# ── 3. check action + RHOSTS/RPORT passed correctly ───────────────────────────
v, _ = fresh_validator()
run_and_wait(v, '192.168.50.5', CANDS[:1])
call = v._engine.calls[0]
if (call[2] == 'check' and call[1].get('RHOSTS') == '192.168.50.5'
    and call[1].get('RPORT') == '445'):
    ok("Validator calls run_exploit with action='check' + correct RHOSTS/RPORT")
else:
    fail(f"check call malformed: {call}")

# ── 4. Persistence — verdicts survive reload from disk ─────────────────────────
v, tmp = fresh_validator()
run_and_wait(v, '172.16.0.9', CANDS)
# New validator instance pointing at same loot dir reads prior verdicts
v2 = MsfValidator(FakeEngine(), tmp)
reloaded = v2.get_verdicts_for_host('172.16.0.9')
if reloaded.get('exploit/windows/smb/ms17_010_eternalblue', {}).get('verdict') == VULNERABLE:
    ok("Verdicts persist to disk and reload across validator instances")
else:
    fail(f"Persistence failed: {reloaded}")

# ── 5. clear_host wipes only that host ─────────────────────────────────────────
v, _ = fresh_validator()
run_and_wait(v, '10.10.10.1', CANDS)
run_and_wait(v, '10.10.10.2', CANDS)
v.clear_host('10.10.10.1')
if (not v.get_verdicts_for_host('10.10.10.1')
        and v.get_verdicts_for_host('10.10.10.2')):
    ok("clear_host removes only the target host's verdicts, leaves others")
else:
    fail("clear_host wiped wrong scope")

# ── 6. Concurrent-run guard ────────────────────────────────────────────────────
v, _ = fresh_validator()
# Use stealth to slow it down so the first run is still active
v.validate('1.2.3.4', CANDS, stealth=3,
           on_progress=lambda m: None)
second = v.validate('1.2.3.4', CANDS, on_progress=lambda m: None)
if second is False:
    ok("Concurrent validation blocked while one is running")
else:
    fail("Validator allowed two concurrent runs")
# let the slow one finish so it doesn't leak into other tests
for _ in range(500):
    if not v.is_running(): break
    time.sleep(0.02)

# ── 7. Stealth delay actually spaces checks ────────────────────────────────────
v, _ = fresh_validator()
t0 = time.time()
run_and_wait(v, '5.5.5.5', CANDS[:3], stealth=1)   # 3 modules, 1s delay → ~2s
elapsed = time.time() - t0
if elapsed >= 1.8:
    ok(f"Stealth delay spaces checks (3 modules @ stealth 1 took {elapsed:.1f}s)")
else:
    fail(f"Stealth delay not applied — 3 modules took only {elapsed:.1f}s")

# ── 8. Status reporting during/after run ───────────────────────────────────────
v, _ = fresh_validator()
run_and_wait(v, '8.8.8.8', CANDS)
st = v.get_status()
if (st['running'] is False and st['done'] == 4 and st['total'] == 4
        and len(st['verdicts']) == 4):
    ok("Status reports running=False, done/total, and all verdicts post-run")
else:
    fail(f"Status wrong post-run: {st}")

# ── 9. App wiring — routes + instantiation + suggestion carry-forward ─────────
import importlib.util
spec = importlib.util.spec_from_file_location('h3x', 'h3x-dash.py')
h3x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h3x)
routes = {r.rule for r in h3x.app.url_map.iter_rules()}
need_routes = {'/validate', '/api/msf/validate/start', '/api/msf/validate/stream',
               '/api/msf/validate/status', '/api/msf/validate/results'}
missing = need_routes - routes
if not missing:
    ok(f"All {len(need_routes)} validation routes registered")
else:
    fail(f"Missing validation routes: {missing}")

if hasattr(h3x, 'msf_validator') and isinstance(h3x.msf_validator, MsfValidator):
    ok("msf_validator instantiated in app")
else:
    fail("msf_validator not instantiated in app")

# ── 10. Page template + nav wiring ─────────────────────────────────────────────
base_html = Path('templates/base.html').read_text()
if 'href="/validate"' in base_html and "active == 'validate'" in base_html:
    ok("Validate nav link wired into sidebar with active-state")
else:
    fail("Validate nav link missing or missing active-state")

val_html = Path('templates/validate.html').read_text()
for needle, desc in [
    ('val-host', 'host selector'),
    ('val-stealth', 'stealth selector'),
    ('/api/msf/validate/start', 'start endpoint call'),
    ('/api/msf/validate/stream', 'stream consumption'),
    ('/api/msf/validate/results', 'results restore'),
    ('SKIP TO EXPLOIT', 'skip-to-exploit affordance'),
    ('EventSource', 'SSE consumption'),
]:
    if needle in val_html:
        ok(f"validate.html has {desc}")
    else:
        fail(f"validate.html missing {desc} ({needle})")

# ── 11. Carry-forward — api_cve_suggest stamps msf_verdict ─────────────────────
h3x_src = Path('h3x-dash.py').read_text()
if "s['msf_verdict']" in h3x_src and 'get_verdicts_for_host' in h3x_src:
    ok("api_cve_suggest stamps suggestions with msf_verdict (Exploit-tab badges)")
else:
    fail("Carry-forward missing — suggestions won't show validation verdicts")

# ── 12. PARANOIA: the verdict badge is actually RENDERED on the exploit page ───
# Backend stamping msf_verdict is useless if the frontend never displays it.
exploit_html = Path('templates/exploit.html').read_text()
if 's.msf_verdict' in exploit_html and 'verdictBadge' in exploit_html:
    ok("exploit.html RENDERS the msf_verdict badge (carry-forward is live, not dead)")
else:
    fail("exploit.html does not render msf_verdict — carry-forward data is dead")

# ── 13. PARANOIA: malformed stealth must not crash/brick the validator ─────────
class _FakeEng:
    def run_exploit(self, module, options, action):
        return {'status': 'launched', 'check_vulnerable': True, 'check_safe': False}
vv = MsfValidator(_FakeEng(), Path(tempfile.mkdtemp()))
_c = [{'msf_module': 'exploit/x/eternalblue', 'msf_rport': 445, 'cve': 'X'}]
done = {'v': False}
started = vv.validate('1.1.1.1', _c, stealth='garbage',
                      on_progress=lambda m: None,
                      on_complete=lambda x: done.update(v=True))
for _ in range(200):
    if not vv.is_running(): break
    time.sleep(0.02)
time.sleep(0.05)
second = vv.validate('1.1.1.1', _c, stealth=0, on_progress=lambda m: None)
for _ in range(200):
    if not vv.is_running(): break
    time.sleep(0.02)
if started and done['v'] and second:
    ok("Malformed stealth sanitized — run completes, validator NOT bricked "
       "(second run still allowed)")
else:
    fail(f"Malformed stealth broke validator: started={started}, "
         f"completed={done['v']}, second_run_allowed={second}")

# ── 14. PARANOIA: a worker exception must always reset _running ────────────────
# Engine whose run_exploit raises a non-handled error type at the loop level.
class _ExplodingEng:
    def run_exploit(self, module, options, action):
        raise KeyboardInterrupt("simulated catastrophic failure")
vv2 = MsfValidator(_ExplodingEng(), Path(tempfile.mkdtemp()))
# KeyboardInterrupt isn't caught by the per-check `except Exception`, so it
# propagates to the worker's try/finally — which must still clear _running.
try:
    vv2.validate('2.2.2.2', _c, stealth=0, on_progress=lambda m: None)
    for _ in range(200):
        if not vv2.is_running(): break
        time.sleep(0.02)
except Exception:
    pass
time.sleep(0.05)
if not vv2.get_status()['running']:
    ok("Worker try/finally clears _running even on an uncaught exception "
       "(validator can't get permanently wedged)")
else:
    fail("Worker exception left _running stuck True — validator bricked")

# ── 15. PARANOIA: context processor must NOT make a live RPC per render ────────
# msf_session_count was an unused live list_sessions() call on every page load.
if 'msf_session_count' not in h3x_src.split('def _inject_global_context')[1].split('def ')[0]:
    ok("Context processor no longer makes a live RPC (list_sessions) per render")
else:
    fail("Context processor still calls list_sessions on every render (perf/hang risk)")

# ── 16. CheckCode-aware verdicts (DETECTED / NO_CHECK) end-to-end ─────────────
class CodeEngine:
    """Engine returning the new check_code field per module."""
    def run_exploit(self, module, options, action):
        if 'vsftpd' in module:
            return {'status': 'launched', 'check_code': 'UNSUPPORTED',
                    'check_detail': 'Module has no check method'}
        if 'distcc' in module:
            return {'status': 'launched', 'check_code': 'DETECTED',
                    'check_detail': 'service running, not validated'}
        if 'eternalblue' in module:
            return {'status': 'launched', 'check_code': 'VULNERABLE',
                    'check_detail': 'confirmed'}
        return {'status': 'launched', 'check_code': 'UNKNOWN'}

vc = MsfValidator(CodeEngine(), Path(tempfile.mkdtemp()))
mt2 = [
    {'msf_module': 'exploit/unix/ftp/vsftpd_234_backdoor', 'msf_rport': 21, 'cve': 'X'},
    {'msf_module': 'exploit/unix/misc/distcc_exec', 'msf_rport': 3632, 'cve': 'Y'},
    {'msf_module': 'exploit/windows/smb/ms17_010_eternalblue', 'msf_rport': 445, 'cve': 'Z'},
]
run_and_wait(vc, '10.0.0.50', mt2)
vv = vc.get_verdicts_for_host('10.0.0.50')
got = {m.split('/')[-1]: vv.get(m, {}).get('verdict') for m in
       [c['msf_module'] for c in mt2]}
if (got.get('vsftpd_234_backdoor') == NO_CHECK
        and got.get('distcc_exec') == DETECTED
        and got.get('ms17_010_eternalblue') == VULNERABLE):
    ok("CheckCode mapping: vsftpd→NO_CHECK, distcc→DETECTED, EternalBlue→VULNERABLE")
else:
    fail(f"CheckCode verdict mapping wrong: {got}")

# NO_CHECK must NOT be a dead end — validate.html offers go-to-exploit for it
if "counts.NO_CHECK" in val_html and "NEED EXPLOIT TO CONFIRM" in val_html:
    ok("validate.html treats NO_CHECK/DETECTED as 'confirm by exploiting', not a dead end")
else:
    fail("validate.html does not surface NO_CHECK/DETECTED as actionable")

# ── 17. Scanner separation — recon scanners moved Validate → Enumerate ────────
from modules.scanner_runner import ScannerRunner, is_scanner_module

# 17a. Classification is correct (auxiliary/scanner/* only; case/slash robust).
_scan_ok = (is_scanner_module('auxiliary/scanner/smb/smb_version')
            and is_scanner_module('/Auxiliary/Scanner/SSH/ssh_version')
            and not is_scanner_module('exploit/unix/misc/distcc_exec')
            and not is_scanner_module('auxiliary/admin/http/tomcat')
            and not is_scanner_module(''))
if _scan_ok:
    ok("is_scanner_module classifies auxiliary/scanner/* only (exploits/admin excluded)")
else:
    fail("is_scanner_module misclassifies modules")

# 17b. validate/start filters scanners out of the candidate set.
if ('is_scanner_module' in h3x_src and 'scanner_count' in h3x_src
        and 'not is_scanner_module' in h3x_src):
    ok("validate/start excludes auxiliary/scanner/* from feasibility candidates")
else:
    fail("validate/start does not filter scanner modules")

# 17c. ScannerRunner runs scanners with action='run' and skips non-scanners.
class _ScanEng:
    def __init__(self): self.calls = []
    def run_exploit(self, module, options, action=None):
        self.calls.append((module, dict(options), action))
        return {'status': 'launched', 'console_output': f'[*] {module} ran\nfound: x'}
_se = _ScanEng()
_sr = ScannerRunner(_se)
_mods = [
    {'msf_module': 'auxiliary/scanner/smb/smb_version', 'msf_rport': 445},
    {'msf_module': 'exploit/unix/misc/distcc_exec', 'msf_rport': 3632},  # must be skipped
]
_results = {}
_sr.run('10.0.0.7', _mods, on_result=lambda s: _results.update({s['module']: s}),
        on_complete=lambda r: _results.update({'__done__': r}))
for _ in range(200):
    if not _sr.is_running(): break
    time.sleep(0.02)
time.sleep(0.05)
ran_mods = [c[0] for c in _se.calls]
if (ran_mods == ['auxiliary/scanner/smb/smb_version']
        and all(c[2] == 'run' for c in _se.calls)
        and _results.get('auxiliary/scanner/smb/smb_version', {}).get('state') == 'ran'):
    ok("ScannerRunner runs ONLY scanners with action='run' (exploit candidate skipped)")
else:
    fail(f"ScannerRunner misbehaved: calls={_se.calls}")

# 17d. Scanner concurrent-run guard.
class _SlowEng:
    def run_exploit(self, module, options, action=None):
        time.sleep(0.3); return {'status': 'launched', 'console_output': 'ok'}
_sr2 = ScannerRunner(_SlowEng())
_first = _sr2.run('1.1.1.1', [{'msf_module': 'auxiliary/scanner/ftp/ftp_version'}])
_second = _sr2.run('1.1.1.1', [{'msf_module': 'auxiliary/scanner/ftp/ftp_version'}])
for _ in range(200):
    if not _sr2.is_running(): break
    time.sleep(0.02)
if _first and _second is False:
    ok("ScannerRunner blocks a concurrent run while one is active")
else:
    fail(f"ScannerRunner concurrency guard failed: first={_first}, second={_second}")

# 17e. App registers the scanner routes + instantiates the runner.
need_scan_routes = {'/api/msf/scanners/list', '/api/msf/scanners/start',
                    '/api/msf/scanners/stream'}
missing_scan = need_scan_routes - routes
if not missing_scan and isinstance(getattr(h3x, 'scanner_runner', None), ScannerRunner):
    ok("Scanner routes registered + scanner_runner instantiated in app")
else:
    fail(f"Scanner wiring incomplete: missing={missing_scan}")

# 17f. Enumerate page hosts the MSF Scanner Modules section + SSE consumption.
enum_html = Path('templates/enumerate.html').read_text()
for needle, desc in [
    ('MSF SCANNER MODULES', 'scanner section header'),
    ('/api/msf/scanners/list', 'scanner list fetch'),
    ('/api/msf/scanners/start', 'scanner start call'),
    ('/api/msf/scanners/stream', 'scanner SSE stream'),
    ('runScanners', 'run handler'),
]:
    if needle in enum_html:
        ok(f"enumerate.html has {desc}")
    else:
        fail(f"enumerate.html missing {desc} ({needle})")

# 17g. Validate page advertises that scanners moved to Enumerate.
if 'Enumerate' in val_html and 'auxiliary/scanner' in val_html:
    ok("validate.html notes scanners now live under Enumerate")
else:
    fail("validate.html does not point scanners to Enumerate")

# ── 18. Validate console is fixed/sticky ABOVE the verdicts (10-line view) ────
# Console card must appear before the verdict strip/table in source order and be
# position:sticky so it stays in view while the verdicts scroll below it.
console_idx = val_html.find('VALIDATION CONSOLE')
strip_idx   = val_html.find('id="verdict-strip"')
table_idx   = val_html.find('FEASIBILITY VERDICTS')
if (0 < console_idx < strip_idx and console_idx < table_idx
        and 'position:sticky' in val_html and 'val-console-card' in val_html):
    ok("Validation console is sticky + positioned ABOVE the feasibility verdicts")
else:
    fail("Validation console not reordered/sticky above verdicts")

# ── 19. Shell-tab tidy: collapsible advanced launcher section ─────────────────
if ('adv-launch' in exploit_html and '<details' in exploit_html
        and 'SESSION HARDENING' in exploit_html and '_revealAdvanced' in exploit_html):
    ok("Shell launcher tidied: payload/callback/hardening in a collapsible section")
else:
    fail("Shell launcher advanced-collapse missing")

# ── Summary ─────────────────────────────────────────────────────────────────────
print("\n" + "═" * 72)
print(f" VALIDATION STAGE AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:"); [print(f"  ✓ {m}") for m in OK]
sys.exit(1 if FAIL else 0)
