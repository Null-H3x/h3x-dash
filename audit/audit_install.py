#!/usr/bin/env python3
"""
audit_install.py — Verify install.py's method-aware tool dispatch.

Runs offline. Validates:
  - ENUM_TOOLS specs are well-formed (every tool has method + needed fields)
  - droopescan/sslyze are correctly tagged as pipx
  - kerbrute is correctly tagged as binary with url_template + dest
  - detect_arch() returns sensible values
  - check_enum_tools() populates install_spec
  - install_missing() correctly groups checks by method
  - Modal handlers are inside <script> block (regression guard for last fix)
"""
import sys
import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


# ── 1. install.py imports cleanly ─────────────────────────────────────────────
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location('install_mod', 'install.py')
    install = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(install)
    ok("install.py imports without syntax errors")
except Exception as e:
    fail(f"install.py import failed: {e}")
    print(f"\n  Cannot continue — install.py has a syntax error.")
    sys.exit(1)


# ── 2. ENUM_TOOLS spec hygiene ────────────────────────────────────────────────
required_per_method = {
    'apt':    {'pkg'},
    'pipx':   {'pkg'},
    'binary': {'url_template', 'dest'},
}

malformed = []
for tool, sp in install.ENUM_TOOLS.items():
    if not isinstance(sp, dict):
        malformed.append(f'{tool} (not a dict)')
        continue
    method = sp.get('method')
    if method not in ('apt', 'pipx', 'binary'):
        malformed.append(f'{tool} (bad method: {method!r})')
        continue
    missing = required_per_method[method] - set(sp.keys())
    if missing:
        malformed.append(f'{tool} ({method} missing: {missing})')

if not malformed:
    ok(f"All {len(install.ENUM_TOOLS)} ENUM_TOOLS entries are well-formed")
else:
    fail(f"Malformed entries: {malformed}")


# ── 3. droopescan + sslyze use pipx, kerbrute uses binary ─────────────────────
expectations = [
    ('droopescan', 'pipx'),
    ('sslyze',     'pipx'),
    ('kerbrute',   'binary'),
    ('nikto',      'apt'),
    ('wpscan',     'apt'),
]
all_correct = True
for tool, expected in expectations:
    spec = install.ENUM_TOOLS.get(tool, {})
    actual = spec.get('method')
    if actual != expected:
        fail(f"{tool}: expected method={expected}, got {actual}")
        all_correct = False
if all_correct:
    ok("droopescan + sslyze tagged pipx; kerbrute tagged binary; "
       "apt-installable tools still apt")


# ── 4. kerbrute binary spec has working URL template ─────────────────────────
kb = install.ENUM_TOOLS['kerbrute']
url = kb['url_template'].format(arch='amd64')
if (url.startswith('https://github.com/ropnop/kerbrute/releases/')
    and url.endswith('kerbrute_linux_amd64')
    and kb['dest'] == '/usr/local/bin/kerbrute'):
    ok(f"kerbrute binary spec: {url}")
else:
    fail(f"kerbrute spec malformed: url={url}, dest={kb['dest']}")


# ── 5. detect_arch returns a known string ────────────────────────────────────
arch = install.detect_arch()
if arch in ('amd64', 'arm64', '386'):
    ok(f"detect_arch returns valid arch: {arch}")
else:
    fail(f"detect_arch returned unexpected value: {arch}")


# ── 6. ENUM_FALLBACKS hints exist for the three problem tools ────────────────
if all(t in install.ENUM_FALLBACKS for t in ('droopescan', 'sslyze', 'kerbrute')):
    ok("ENUM_FALLBACKS has apt-available alternatives noted for all 3 tools")
else:
    fail(f"Missing fallback hints: "
         f"{set(['droopescan','sslyze','kerbrute']) - set(install.ENUM_FALLBACKS)}")


# ── 7. Check class supports install_spec field ────────────────────────────────
c = install.Check('test', 'pass', 'msg',
                   install_spec={'method': 'pipx', 'pkg': 'foo'})
if c.install_spec and c.install_spec['method'] == 'pipx':
    ok("Check class carries install_spec correctly")
else:
    fail("Check class doesn't accept install_spec")


# ── 8. install_missing groups checks correctly ────────────────────────────────
# Build a synthetic mix of checks and stub the three installer helpers.
calls = {'apt': None, 'pipx': None, 'binary': []}
def _stub_apt(pkgs):     calls['apt'] = sorted(pkgs); return True
def _stub_pipx(pkgs):    calls['pipx'] = sorted(pkgs); return True
def _stub_binary(n, u, d): calls['binary'].append((n, u, d)); return True

orig_apt    = install._install_apt_batch
orig_pipx   = install._install_pipx_pkgs
orig_binary = install._install_binary
install._install_apt_batch  = _stub_apt
install._install_pipx_pkgs  = _stub_pipx
install._install_binary     = _stub_binary
# Auto-confirm "install now? y"
import builtins
orig_input = builtins.input
builtins.input = lambda *a, **kw: 'y'

try:
    test_checks = [
        install.Check('nikto', 'warn', 'missing',
                       install_spec={'method': 'apt',  'pkg': 'nikto'}),
        install.Check('wpscan', 'warn', 'missing',
                       install_spec={'method': 'apt',  'pkg': 'wpscan'}),
        install.Check('sslyze', 'warn', 'missing',
                       install_spec={'method': 'pipx', 'pkg': 'sslyze'}),
        install.Check('droopescan', 'warn', 'missing',
                       install_spec={'method': 'pipx', 'pkg': 'droopescan'}),
        install.Check('kerbrute', 'warn', 'missing',
                       install_spec={'method': 'binary',
                                     'url_template':
                                     'https://example/kerbrute_linux_{arch}',
                                     'dest': '/usr/local/bin/kerbrute'}),
        # Already-installed PASS should be ignored
        install.Check('gobuster', 'pass', 'found',
                       install_spec={'method': 'apt', 'pkg': 'gobuster'}),
    ]
    install.install_missing(test_checks)

    if calls['apt'] == ['nikto', 'wpscan']:
        ok("install_missing batches apt packages correctly")
    else:
        fail(f"apt batching wrong: {calls['apt']}")

    if calls['pipx'] == ['droopescan', 'sslyze']:
        ok("install_missing routes Python tools to pipx")
    else:
        fail(f"pipx routing wrong: {calls['pipx']}")

    if (len(calls['binary']) == 1
        and calls['binary'][0][0] == 'kerbrute'
        and 'kerbrute_linux_' in calls['binary'][0][1]
        and calls['binary'][0][2] == '/usr/local/bin/kerbrute'):
        ok("install_missing routes binary downloads with arch substituted")
    else:
        fail(f"binary routing wrong: {calls['binary']}")

finally:
    install._install_apt_batch  = orig_apt
    install._install_pipx_pkgs  = orig_pipx
    install._install_binary     = orig_binary
    builtins.input              = orig_input


# ── 9. check_enum_tools populates install_spec on every Check ────────────────
checks = install.check_enum_tools()
specs_missing = [c.name for c in checks if not c.install_spec]
if not specs_missing:
    ok(f"check_enum_tools sets install_spec on all {len(checks)} checks")
else:
    fail(f"Checks missing install_spec: {specs_missing}")


# ── 10. Modal handlers still inside <script> block (regression guard) ───────
from pathlib import Path
base_html = Path('templates/base.html').read_text()
# Find every <script> ... </script> region and check that
# h3xToggleAck is inside one
in_script = False
handler_in_script = False
for line in base_html.split('\n'):
    if '<script' in line and 'src=' not in line:
        in_script = True
    elif '</script>' in line:
        in_script = False
    elif 'function h3xToggleAck' in line:
        handler_in_script = in_script
        break
if handler_in_script:
    ok("Modal handlers (h3xToggleAck) inside <script> — last fix holds")
else:
    fail("REGRESSION: modal handlers orphaned outside <script> again")


# ── 11. Decline redirects to hackthebox ───────────────────────────────────────
if 'hackthebox.com' in base_html and 'window.location.replace' in base_html:
    ok("Decline button redirects to hackthebox.com via window.location.replace")
else:
    fail("Decline → hackthebox redirect missing")


# ── 12. addEventListener fallback bindings present ───────────────────────────
expected_bindings = ["addEventListener('change'", "addEventListener('click'",
                     "addEventListener('input'"]
missing = [b for b in expected_bindings if b not in base_html]
if not missing:
    ok("Belt-and-suspenders addEventListener bindings all present")
else:
    fail(f"Missing event bindings: {missing}")


# ── 13. Template <script> tag balance — every key function inside one ───────
# Regression guard: in prior turns the modal handlers and the clock function
# both got orphaned when a str_replace closed </script> too early. Walk the
# file linearly and assert each key function lives inside a <script> block.
in_script = False
funcs_in_script = {'h3xToggleAck': False, 'tick': False, 'pollMsf': False}
for line in base_html.split('\n'):
    if '<script' in line and 'src=' not in line:
        in_script = True
        continue
    if '</script>' in line:
        in_script = False
        continue
    for fname in funcs_in_script:
        if f'function {fname}' in line:
            funcs_in_script[fname] = in_script

orphans = [f for f, ok_ in funcs_in_script.items() if not ok_]
if not orphans:
    ok("All key JS functions (modal handlers, clock, MSF poll) inside <script>")
else:
    fail(f"REGRESSION: functions outside <script> tags: {orphans}")


# ── 14. Context processor exists and injects msf_conn ────────────────────────
import importlib.util as _ilu
spec = _ilu.spec_from_file_location('h3x_dash_mod', 'h3x-dash.py')
h3x  = _ilu.module_from_spec(spec)
spec.loader.exec_module(h3x)

# Find context processors registered on the Flask app
context_funcs = h3x.app.template_context_processors[None]    # global scope
injects = {}
for fn in context_funcs:
    try:
        result = fn()
    except Exception:
        continue
    if isinstance(result, dict):
        injects.update(result)

if 'msf_conn' in injects:
    ok(f"Context processor auto-injects msf_conn into every template "
       f"(value: {injects['msf_conn']}, type: {type(injects['msf_conn']).__name__})")
else:
    fail(f"Context processor does NOT inject msf_conn. "
         f"Available keys: {list(injects.keys())}")


# ── 15. MSF status endpoint exists for the live poll ─────────────────────────
routes = {r.rule for r in h3x.app.url_map.iter_rules()}
if '/api/msf/status' in routes:
    ok("/api/msf/status endpoint exists for the badge's live poll")
else:
    fail("/api/msf/status endpoint missing — live badge poll will 404")


# ── 16. MSF badge in base.html has the IDs the poll JS looks for ─────────────
required_ids = ['id="msf-badge"', 'id="msf-badge-val"']
missing = [i for i in required_ids if i not in base_html]
if not missing:
    ok("MSF badge has IDs the poll JS targets (live updates will land)")
else:
    fail(f"MSF badge missing required IDs: {missing}")


# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" INSTALL AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
