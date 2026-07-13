#!/usr/bin/env python3
"""
audit_classifier.py — Verify host classification gives correct verdicts on
canonical target shapes. Run after touching modules/host_classifier.py.

Tests use synthetic host dicts that match what scan_engine produces — so this
runs offline and doesn't need a live target.
"""
import sys
import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

from modules import host_classifier as hc

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


def host(ip, os_str, *port_specs):
    """Helper: synthesize host dict from (port, service, [product]) tuples."""
    ports = []
    for spec in port_specs:
        port, svc = spec[0], spec[1]
        product = spec[2] if len(spec) > 2 else ''
        ports.append({'port': port, 'state': 'open',
                       'service': svc, 'product': product})
    return {'ip': ip, 'os': os_str, 'ports': ports}


def assert_top(host_dict, expected_class, min_confidence=30):
    matches = hc.classify(host_dict)
    if not matches:
        fail(f"{host_dict.get('ip')}: no class matches at all")
        return
    top = matches[0]
    if top['class_id'] != expected_class:
        fail(f"{host_dict.get('ip')}: expected {expected_class}, "
             f"got {top['class_id']} ({top['confidence']}%)")
        return
    if top['confidence'] < min_confidence:
        fail(f"{host_dict.get('ip')}: {expected_class} confidence "
             f"{top['confidence']} < {min_confidence}")
        return
    return top


def assert_not_match(host_dict, forbidden_class):
    matches = hc.classify(host_dict)
    for m in matches:
        if m['class_id'] == forbidden_class and m['confidence'] >= 30:
            fail(f"{host_dict.get('ip')}: should NOT match {forbidden_class} "
                 f"but got {m['confidence']}%")
            return
    return True


# ── 1. Windows workstation (Win 10) ──────────────────────────────────────────
h = host('10.0.0.10', 'Windows 10 Pro',
         (135, 'msrpc'), (139, 'netbios-ssn'), (445, 'microsoft-ds'),
         (3389, 'ms-wbt-server'), (5985, 'wsman'))
if assert_top(h, 'windows_workstation', min_confidence=80):
    ok("Windows 10 endpoint (135/139/445/3389/5985) → windows_workstation HIGH")

# ── 2. Domain controller — workstation should be ruled out ───────────────────
h = host('10.0.0.1', 'Windows Server 2019 Domain Controller',
         (53, 'domain'), (88, 'kerberos-sec'), (135, 'msrpc'),
         (139, 'netbios-ssn'), (389, 'ldap'), (445, 'microsoft-ds'),
         (464, 'kpasswd5'), (636, 'ldapssl'), (3268, 'globalcatldap'),
         (3389, 'ms-wbt-server'), (5985, 'wsman'))
if assert_top(h, 'windows_dc', min_confidence=80):
    ok("Windows DC (88+389+445 + AD ports) → windows_dc HIGH")
assert_not_match(h, 'windows_workstation')   # forbidden_ports kicks in (88)
ok("DC correctly NOT classified as windows_workstation (port 88 disqualifies)")

# ── 3. Metasploitable 2 — Linux Samba host ───────────────────────────────────
h = host('10.0.0.50', 'Linux 2.6.x',
         (21, 'ftp', 'vsftpd 2.3.4'), (22, 'ssh', 'OpenSSH 4.7p1'),
         (23, 'telnet'), (25, 'smtp'), (80, 'http', 'Apache httpd 2.2.8'),
         (139, 'netbios-ssn', 'Samba smbd 3.X'),
         (445, 'microsoft-ds', 'Samba smbd 3.X'),
         (3306, 'mysql'), (5432, 'postgresql'))
top = assert_top(h, 'linux_samba_host', min_confidence=50)
if top:
    ok("Metasploitable 2 (vsftpd + Samba 3.X + Apache) → linux_samba_host")

# ── 4. Pure Linux web server ──────────────────────────────────────────────────
h = host('10.0.0.20', 'Ubuntu 22.04 Linux',
         (22, 'ssh', 'OpenSSH 8.9'),
         (80, 'http', 'nginx 1.18'),
         (443, 'ssl/http', 'nginx 1.18'))
matches = hc.classify(h)
top_ids = [m['class_id'] for m in matches[:3]]
if 'linux_server' in top_ids and 'web_application' in top_ids:
    ok(f"Linux web server matches both linux_server + web_application: {top_ids}")
else:
    fail(f"Linux web server should match linux_server AND web_application, "
         f"got top-3: {top_ids}")

# ── 5. Network device (router) ───────────────────────────────────────────────
h = host('10.0.0.254', 'Cisco IOS 15.4',
         (22, 'ssh'), (23, 'telnet'),
         (80, 'http', 'Cisco IOS http config'),
         (161, 'snmp'))
if assert_top(h, 'network_device', min_confidence=50):
    ok("Cisco router (SSH+telnet+SNMP, Cisco OS) → network_device")

# ── 6. Printer ───────────────────────────────────────────────────────────────
h = host('10.0.0.99', 'HP JetDirect',
         (80, 'http'), (443, 'ssl/http'),
         (515, 'printer'), (631, 'ipp'), (9100, 'jetdirect'))
if assert_top(h, 'printer', min_confidence=50):
    ok("Network printer (515+631+9100) → printer")

# ── 7. Database server (only DB ports + SSH) ─────────────────────────────────
h = host('10.0.0.30', 'Linux',
         (22, 'ssh'), (3306, 'mysql', 'MySQL 5.7'),
         (5432, 'postgresql'))
matches = hc.classify(h)
top = matches[0] if matches else {}
if top.get('class_id') == 'database_server':
    ok("DB-focused server (mysql+postgres+ssh) → database_server")
elif top.get('class_id') == 'linux_server' and any(m['class_id'] == 'database_server' for m in matches):
    ok("DB-focused server matches both linux_server + database_server")
else:
    fail(f"DB-focused server class unexpected: {top}")

# ── 8. ESXi hypervisor ───────────────────────────────────────────────────────
h = host('10.0.0.5', 'VMware ESXi 7.0',
         (22, 'ssh'), (80, 'http'), (443, 'https', 'VMware ESXi'),
         (902, 'vmware-auth'), (5988, 'wbem-http'), (5989, 'wbem-https'))
if assert_top(h, 'hypervisor_esxi', min_confidence=50):
    ok("ESXi hypervisor (902+5988+5989, VMware OS) → hypervisor_esxi")

# ── 9. Mail server ───────────────────────────────────────────────────────────
h = host('10.0.0.25', 'Linux',
         (22, 'ssh'), (25, 'smtp', 'Postfix'),
         (143, 'imap'), (587, 'submission'), (993, 'imaps'))
matches = hc.classify(h)
top_ids = [m['class_id'] for m in matches[:2]]
if 'mail_server' in top_ids:
    ok(f"Postfix mail server → mail_server in top-2: {top_ids}")
else:
    fail(f"Mail server should classify as mail_server, got {top_ids}")

# ── 10. Unknown / empty host ─────────────────────────────────────────────────
h = {'ip': '10.0.0.0', 'os': '', 'ports': []}
matches = hc.classify(h)
if matches and matches[0]['class_id'] == 'unknown':
    ok("Empty host returns 'unknown' class without crashing")
else:
    fail(f"Empty host should return unknown, got: {matches}")

# ── 11. Module-to-class filtering ────────────────────────────────────────────
# Simulate suggestions for a Linux Samba host — eternalblue should be filtered OUT,
# samba_usermap should stay.
suggestions = [
    {'msf_module': 'exploit/windows/smb/ms17_010_eternalblue', 'severity': 'CRITICAL'},
    {'msf_module': 'exploit/multi/samba/usermap_script',       'severity': 'CRITICAL'},
    {'msf_module': 'exploit/unix/ftp/vsftpd_234_backdoor',     'severity': 'CRITICAL'},
    {'msf_module': 'auxiliary/scanner/smb/smb_enumshares',     'severity': 'MEDIUM'},
    {'msf_module': None, 'severity': 'INFO'},                  # info-only, must pass through
]
filtered = hc.filter_modules(suggestions, ['linux_samba_host'])
fm = {s.get('msf_module') for s in filtered}
if ('exploit/windows/smb/ms17_010_eternalblue' not in fm
    and 'exploit/multi/samba/usermap_script' in fm
    and 'exploit/unix/ftp/vsftpd_234_backdoor' in fm
    and None in fm):                                            # info-only kept
    ok("filter_modules hides Windows-only exploits from a Linux Samba host; "
       "Samba + vsftpd kept; info-only (msf_module=None) kept")
else:
    fail(f"filter_modules wrong output for linux_samba_host: {fm}")

# Reverse: filtering for windows_workstation should hide samba_usermap
filtered = hc.filter_modules(suggestions, ['windows_workstation'])
fm = {s.get('msf_module') for s in filtered}
if ('exploit/windows/smb/ms17_010_eternalblue' in fm
    and 'exploit/multi/samba/usermap_script' not in fm):
    ok("filter_modules hides Linux exploits from a Windows workstation host")
else:
    fail(f"filter_modules wrong for windows_workstation: {fm}")

# Modules without a class mapping should pass through (universal)
suggestions_with_unknown = [
    {'msf_module': 'exploit/some/never/mapped/module', 'severity': 'HIGH'},
]
filtered = hc.filter_modules(suggestions_with_unknown, ['windows_workstation'])
if len(filtered) == 1:
    ok("Unmapped modules pass through filter (no false-negative hiding)")
else:
    fail("Unmapped module incorrectly filtered out")

# ── 12. SMB ambiguity — multi-class list must not leak cross-platform modules ─
# Port 445 alone scores both linux_samba_host AND windows_workstation. Filtering
# must use the primary class only, not any() across alternates.
smb_sugs = [
    {'msf_module': 'exploit/windows/smb/ms17_010_eternalblue'},
    {'msf_module': 'exploit/multi/samba/usermap_script'},
]
# Linux Samba is primary even when Windows alternates are present
filtered = hc.filter_modules(smb_sugs,
    ['linux_samba_host', 'windows_workstation', 'windows_server'])
fm = {s.get('msf_module') for s in filtered}
if 'exploit/multi/samba/usermap_script' in fm and \
   'exploit/windows/smb/ms17_010_eternalblue' not in fm:
    ok("SMB ambiguity: primary linux_samba_host hides EternalBlue despite "
       "Windows alternates in class list")
else:
    fail(f"SMB ambiguity leak on linux_samba_host primary: {fm}")

filtered = hc.filter_modules(smb_sugs,
    ['windows_workstation', 'windows_server', 'linux_samba_host'])
fm = {s.get('msf_module') for s in filtered}
if 'exploit/windows/smb/ms17_010_eternalblue' in fm and \
   'exploit/multi/samba/usermap_script' not in fm:
    ok("SMB ambiguity: primary windows_workstation hides usermap despite "
       "linux_samba_host alternate in class list")
else:
    fail(f"SMB ambiguity leak on windows_workstation primary: {fm}")

# ── 13. Metasploitable classics survive linux_samba_host filter ──────────────
mt2_lab_sugs = [
    {'msf_module': 'exploit/unix/misc/distcc_exec'},
    {'msf_module': 'exploit/unix/irc/unreal_ircd_3281_backdoor'},
    {'msf_module': 'exploit/multi/misc/java_rmi_server'},
    {'msf_module': 'exploit/unix/ftp/vsftpd_234_backdoor'},
]
filtered = hc.filter_modules(mt2_lab_sugs, ['linux_samba_host'])
fm = {s.get('msf_module') for s in filtered}
need = {s['msf_module'] for s in mt2_lab_sugs}
if need <= fm:
    ok("linux_samba_host filter keeps MT2 classics (distcc, IRC, RMI, vsftpd)")
else:
    fail(f"MT2 classics dropped on linux_samba_host: missing {need - fm}")

# distcc must appear even when only linux_server is in MODULE_CLASSES mapping
# via CLASS_EXPANSION (linux_samba_host inherits linux_server)
distcc_only = [{'msf_module': 'exploit/unix/misc/distcc_exec'}]
filtered = hc.filter_modules(distcc_only, ['linux_samba_host'])
if filtered and filtered[0].get('msf_module') == 'exploit/unix/misc/distcc_exec':
    ok("distcc_exec passes filter via linux_samba_host → linux_server expansion")
else:
    fail("distcc_exec incorrectly filtered out for linux_samba_host primary")

# ── 14. best_class returns confident pick or None ────────────────────────────
h = host('10.0.0.10', 'Windows 10 Pro',
         (135, 'msrpc'), (445, 'microsoft-ds'), (3389, 'ms-wbt-server'))
if hc.best_class(h) == 'windows_workstation':
    ok("best_class() returns the top confident match")

h = {'ip': '10.0.0.0', 'os': '', 'ports': []}
if hc.best_class(h) is None:
    ok("best_class() returns None for unclassifiable hosts")
else:
    fail(f"best_class() should return None for empty host")


# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" HOST CLASSIFIER AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
