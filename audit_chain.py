#!/usr/bin/env python3
"""Paranoia audit for modules/cve_chain.py — internal consistency + behavior."""
import sys; sys.path.insert(0, '.')
from modules.cve_chain import (
    CVE_MAP, PORT_TO_SERVICE, SERVICE_ALIAS,
    MSF_PORT_OVERRIDES, MSF_MODULE_RANK, MSF_RANK_SCORE,
    MSF_PLATFORM_PAYLOAD, SEVERITY_ORDER, CveChain, _module_platform,
)

FAIL, WARN, OK, INFO = [], [], [], []
def fail(m): FAIL.append(m)
def warn(m): WARN.append(m)
def ok(m):   OK.append(m)
def info(m): INFO.append(m)

# ── 1. Shape & severity discipline ────────────────────────────────────────────
bad_shapes = 0
for key, entries in CVE_MAP.items():
    for i, e in enumerate(entries):
        if not isinstance(e, tuple) or len(e) != 4:
            fail(f"{key}[{i}] not a 4-tuple"); bad_shapes += 1; continue
        cve, mod, desc, sev = e
        if sev not in SEVERITY_ORDER:
            fail(f"{key}[{i}] unknown severity {sev!r}")
        if not desc:
            fail(f"{key}[{i}] empty description")
        if cve and not cve.startswith("CVE-"):
            fail(f"{key}[{i}] malformed CVE: {cve!r}")
        if mod and not mod.startswith(("exploit/", "auxiliary/", "post/")):
            fail(f"{key}[{i}] module path doesn't start with exploit/auxiliary/post: {mod}")
if bad_shapes == 0:
    ok(f"All {sum(len(v) for v in CVE_MAP.values())} CVE_MAP entries pass shape/severity checks")

# ── 2. No dead PORT_TO_SERVICE routes ─────────────────────────────────────────
dead_ports = [p for p, s in PORT_TO_SERVICE.items() if s not in CVE_MAP]
if dead_ports:
    fail(f"PORT_TO_SERVICE has dead routes: {dead_ports}")
else:
    ok(f"All {len(PORT_TO_SERVICE)} port mappings target an existing CVE_MAP key")

# ── 3. No dead SERVICE_ALIAS routes ───────────────────────────────────────────
dead_aliases = [a for a, s in SERVICE_ALIAS.items() if s not in CVE_MAP]
if dead_aliases:
    fail(f"SERVICE_ALIAS has dead routes: {dead_aliases}")
else:
    ok(f"All {len(SERVICE_ALIAS)} banner aliases target an existing CVE_MAP key")

# ── 4. No orphan CVE_MAP keys (unreachable from any port or alias) ────────────
reachable_keys = set(PORT_TO_SERVICE.values()) | set(SERVICE_ALIAS.values())
orphans = [k for k in CVE_MAP if k not in reachable_keys]
if orphans:
    fail(f"Orphan CVE_MAP keys (no port/alias routes to them): {orphans}")
else:
    ok(f"All {len(CVE_MAP)} service keys reachable from port or alias")

# ── 5. PORT_OVERRIDE/RANK references valid modules ────────────────────────────
referenced = {m for v in CVE_MAP.values() for _, m, _, _ in v if m}
for mod in MSF_PORT_OVERRIDES:
    if mod not in referenced:
        warn(f"MSF_PORT_OVERRIDES has unused module: {mod}")
for mod in MSF_MODULE_RANK:
    if mod not in referenced:
        warn(f"MSF_MODULE_RANK has unused module: {mod}")

# ── 6. All ranks are valid score keys ─────────────────────────────────────────
bad_ranks = [(m, r) for m, r in MSF_MODULE_RANK.items() if r not in MSF_RANK_SCORE]
if bad_ranks:
    fail(f"Bad ranks: {bad_ranks}")
else:
    ok(f"All {len(MSF_MODULE_RANK)} ranks resolve to a valid score")

# ── 7. No (cve, module) duplicates across keys — would confuse dedup ──────────
seen = {}
dups = []
for key, entries in CVE_MAP.items():
    for cve, mod, _, _ in entries:
        uid = (cve, mod)
        if uid in seen and (cve or mod):
            dups.append((uid, seen[uid], key))
        seen[uid] = key
if dups:
    fail(f"Duplicate (cve, module) tuples (will dedupe in UI but signals data issue): {dups}")
else:
    ok(f"No duplicate (CVE, module) tuples across all {len(seen)} entries")

# ── 8. SMB-pipe DCERPC modules must override to 445, not 135 ──────────────────
smb_pipe = {
    'auxiliary/admin/dcerpc/cve_2020_1472_zerologon',
    'exploit/windows/dcerpc/cve_2021_1675_printnightmare',
}
for m in smb_pipe:
    if MSF_PORT_OVERRIDES.get(m) != 445:
        fail(f"{m} should override RPORT→445 (SMB pipe), found {MSF_PORT_OVERRIDES.get(m)}")
    else:
        ok(f"{m} correctly overrides to 445")

# ── 9. ms17_010 family must override to 445 ───────────────────────────────────
for m in ['exploit/windows/smb/ms17_010_eternalblue',
          'exploit/windows/smb/ms17_010_psexec',
          'exploit/windows/smb/cve_2020_0796_smbghost']:
    if MSF_PORT_OVERRIDES.get(m) != 445:
        fail(f"{m} should override to 445, found {MSF_PORT_OVERRIDES.get(m)}")
ok("All SMB exploit-class modules correctly pinned to RPORT 445")

# ── 10. Every exploit-class module is reachable from at least one port ────────
mod_to_keys = {}
for key, entries in CVE_MAP.items():
    for _, m, _, _ in entries:
        if m: mod_to_keys.setdefault(m, []).append(key)
key_to_ports = {}
for p, s in PORT_TO_SERVICE.items():
    key_to_ports.setdefault(s, []).append(p)
unreachable = []
for mod, keys in mod_to_keys.items():
    if not any(key_to_ports.get(k) for k in keys):
        # Could still be reachable via SERVICE_ALIAS — check
        alias_keys = {s for a, s in SERVICE_ALIAS.items() if s in keys}
        if not alias_keys:
            unreachable.append(mod)
if unreachable:
    fail(f"Modules with no port path: {unreachable}")
else:
    ok(f"All {len(mod_to_keys)} module paths reachable from at least one port")

# ── 11. Multi-platform exploits that aren't scanners — payload sanity ─────────
# 'multi' platform falls back to a Windows payload by default. That's fine for
# scanners, but for actual exploit-class multi modules the suggestion may not
# match a Linux target.
multi_exploits_no_arch_hint = []
for mod in referenced:
    if not mod.startswith('exploit/'): continue
    plat = _module_platform(mod)
    if plat == 'multi' and '/http/' in mod and 'webapp' not in mod:
        multi_exploits_no_arch_hint.append(mod)
if multi_exploits_no_arch_hint:
    info(f"{len(multi_exploits_no_arch_hint)} multi/http/* exploits default to a "
         f"Windows payload via MSF_PLATFORM_PAYLOAD['multi']. Operator should "
         f"manually pick a Linux payload when targeting Linux services.")

# ── 11b. Payload architecture — x64-native exploits MUST get x64 payloads ─────
from modules.cve_chain import smart_payload, MSF_MODULE_PAYLOAD_OVERRIDE

# eternalblue is x64-native — must never get the x86 payload regardless of
# whether arch was detected. This is the exact "not compatible payloads" bug.
eb = smart_payload('exploit/windows/smb/ms17_010_eternalblue', 'Windows 7', '')
if eb == 'windows/x64/meterpreter/reverse_tcp':
    ok("eternalblue gets x64 payload even when arch undetected (override forces it)")
else:
    fail(f"eternalblue payload wrong: {eb} (must be windows/x64/meterpreter/reverse_tcp)")

# Even with arch explicitly x86 in the host data, the override wins because the
# MODULE itself is x64-only — you cannot run it x86.
eb2 = smart_payload('exploit/windows/smb/ms17_010_eternalblue', 'Windows 7', 'x86')
if eb2 == 'windows/x64/meterpreter/reverse_tcp':
    ok("eternalblue override beats even an x86 arch hint (module is x64-only)")
else:
    fail(f"eternalblue override didn't win over x86 hint: {eb2}")

# SMBGhost likewise x64-native
sg = smart_payload('exploit/windows/smb/cve_2020_0796_smbghost', 'Windows 10', '')
if sg == 'windows/x64/meterpreter/reverse_tcp':
    ok("SMBGhost gets x64 payload (x64-native vuln)")
else:
    fail(f"SMBGhost payload wrong: {sg}")

# Generic Windows exploit with NO arch detected → default x64 (modern reality)
gen = smart_payload('exploit/windows/rdp/cve_2019_0708_bluekeep_rce', 'Windows 7', '')
if 'x64' in gen:
    ok("Generic Windows exploit defaults to x64 when arch undetected")
else:
    fail(f"Generic Windows exploit defaulted to x86 (wrong default): {gen}")

# Explicit x86 detection → x86 payload (respect a genuinely 32-bit target)
x86 = smart_payload('exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
                    'Windows XP', 'x86')
if x86 == 'windows/meterpreter/reverse_tcp':
    ok("Explicitly-detected x86 target correctly gets x86 payload")
else:
    fail(f"x86 target didn't get x86 payload: {x86}")

# ── 12. Suggestion field shape — what the HTML expects ────────────────────────
ch = CveChain()
sugs = ch.suggest({'ip':'1.1.1.1'},
    [{'port':445,'service':'smb','version':''},
     {'port':3389,'service':'rdp','version':''},
     {'port':8080,'service':'http','version':''}])
needed = {'port','service','version','cve','msf_module','msf_rport',
          'msf_rank','msf_platform','msf_payload','msf_payload_fallback',
          'description','severity','enum_confirmed','host_ip'}
sample = sugs[0] if sugs else {}
missing = needed - set(sample.keys())
extra   = set(sample.keys()) - needed
if missing: fail(f"suggestion missing fields the HTML expects: {missing}")
if extra:   info(f"suggestion has extra fields (harmless): {extra}")
if not missing and not extra:
    ok(f"Suggestion dict shape matches HTML expectations ({len(needed)} fields)")

# ── 13. Auto-confirmation paths still wire correctly post-expansion ───────────
ef = [{'title':'SMBv1 protocol is enabled', 'cve':None, 'msf_module':None}]
sugs = ch.suggest({'ip':'1'}, [{'port':445,'service':'smb','version':''}], ef)
need = {'exploit/windows/smb/ms17_010_eternalblue',
        'exploit/windows/smb/ms17_010_psexec',
        'auxiliary/scanner/smb/smb_ms17_010'}
got = {s['msf_module'] for s in sugs if s['enum_confirmed']}
if need <= got:
    ok("SMBv1-enabled title auto-confirms the EternalBlue family")
else:
    fail(f"SMBv1 auto-confirm missing: {need - got}")

ef = [{'title':'Redis unauthenticated access', 'cve':None, 'msf_module':None}]
sugs = ch.suggest({'ip':'1'}, [{'port':6379,'service':'redis','version':''}], ef)
need = {'exploit/linux/redis/redis_replication_cmd_exec'}
got = {s['msf_module'] for s in sugs if s['enum_confirmed']}
if need <= got:
    ok("Redis-unauth title auto-confirms the Redis exploit")
else:
    fail(f"Redis auto-confirm missing: {need - got}")

# ── 14. CVE-based auto-confirm covers new modules transparently ───────────────
ef = [{'title':'Log4j JNDI lookup vulnerable', 'cve':'CVE-2021-44228', 'msf_module':None}]
sugs = ch.suggest({'ip':'1'}, [{'port':8080,'service':'http','version':''}], ef)
log4 = [s for s in sugs
        if s['msf_module']=='exploit/multi/http/log4shell_header_injection']
if log4 and log4[0]['enum_confirmed']:
    ok("CVE-2021-44228 in enum_findings auto-confirms Log4Shell module")
else:
    warn("Log4Shell CVE-based auto-confirm did not fire — verify path string")

ef = [{'title':'Drupal vulnerable', 'cve':'CVE-2018-7600', 'msf_module':None}]
sugs = ch.suggest({'ip':'1'}, [{'port':80,'service':'http','version':''}], ef)
drup = [s for s in sugs if s['msf_module']=='exploit/unix/webapp/drupal_drupalgeddon2']
if drup and drup[0]['enum_confirmed']:
    ok("CVE-2018-7600 in enum_findings auto-confirms Drupalgeddon2")
else:
    warn("Drupalgeddon2 CVE-based auto-confirm did not fire")

# ── 15. Dedup uid behavior — same vuln from two ports should appear once ──────
# Port 139 and 445 both route to 'smb'. ms17_010_eternalblue should suggest ONCE.
sugs = ch.suggest({'ip':'1'},
    [{'port':139,'service':'smb','version':''},
     {'port':445,'service':'smb','version':''}])
eternal = [s for s in sugs
           if s['msf_module']=='exploit/windows/smb/ms17_010_eternalblue']
if len(eternal) == 1:
    ok("Dedup correct: EternalBlue appears once despite both 139 and 445 open")
else:
    fail(f"Dedup broken: EternalBlue appears {len(eternal)} times")

# ── 16. Metasploitable port classics surface in suggestions ───────────────────
_ms2_lab_ports = [
    {'port': 3632, 'service': 'distccd', 'version': ''},
    {'port': 6667, 'service': 'irc', 'version': 'UnrealIRCd 3.2.8.1'},
    {'port': 1099, 'service': 'rmiregistry', 'version': ''},
]
_ms2_lab_sugs = ch.suggest({'ip': '10.0.0.50', 'os': 'Linux 2.6.x'}, _ms2_lab_ports)
_ms2_lab_mods = {s['msf_module'] for s in _ms2_lab_sugs}
_need_lab = {
    'exploit/unix/misc/distcc_exec',
    'exploit/unix/irc/unreal_ircd_3281_backdoor',
    'exploit/multi/misc/java_rmi_server',
}
if _need_lab <= _ms2_lab_mods:
    ok("Port 3632/6667/1099 suggest distcc, UnrealIRCd, and Java RMI modules")
else:
    fail(f"MT2 lab ports missing suggestions: {_need_lab - _ms2_lab_mods}")

# distcc enum title auto-confirms the module
ef = [{'title': 'distccd v1 exposed on 3632', 'cve': None, 'msf_module': None}]
_sugs = ch.suggest({'ip': '1'}, [{'port': 3632, 'service': 'distccd', 'version': ''}], ef)
_distcc = [s for s in _sugs if s['msf_module'] == 'exploit/unix/misc/distcc_exec']
if _distcc and _distcc[0]['enum_confirmed']:
    ok("distccd enum title auto-confirms distcc_exec module")
else:
    fail("distccd enum title did not auto-confirm distcc_exec")

# ── 17. End-to-end chain + class-filter integration ─────────────────────────
from modules import host_classifier as _hc

_ms2 = {'ip': '10.0.0.50', 'os': 'Linux 2.6.x', 'arch': ''}
_ms2_ports = [
    {'port': 445, 'service': 'microsoft-ds', 'version': 'Samba smbd 3.X'},
]
_ms2_classes = [c['class_id'] for c in _hc.classify({**_ms2, 'ports': _ms2_ports})
                if c['confidence'] >= 30]
_ms2_all = ch.suggest(_ms2, _ms2_ports)
_ms2_filt = ch.suggest(_ms2, _ms2_ports, host_classes=_ms2_classes)
if any('ms17_010' in (s.get('msf_module') or '') for s in _ms2_filt):
    fail("Class-filtered Linux Samba host still suggests EternalBlue")
else:
    ok("Class-filtered Linux Samba host hides EternalBlue family")

_win = {'ip': '10.0.0.10', 'os': 'Windows 10 Pro', 'arch': ''}
_win_ports = [{'port': 445, 'service': 'microsoft-ds', 'version': ''}]
_win_classes = [c['class_id'] for c in _hc.classify({**_win, 'ports': _win_ports})
                if c['confidence'] >= 30]
_win_filt = ch.suggest(_win, _win_ports, host_classes=_win_classes)
if any('usermap_script' in (s.get('msf_module') or '') for s in _win_filt):
    fail("Class-filtered Windows workstation still suggests Samba usermap_script")
else:
    ok("Class-filtered Windows workstation hides Samba usermap_script")

if len(_ms2_filt) < len(_ms2_all):
    ok(f"Class filter reduces suggestion count ({len(_ms2_filt)} of {len(_ms2_all)})")
else:
    warn("Class filter did not reduce Linux Samba suggestion count — verify primary class")

# MT2 / Linux 2.6 — reverse_bash /dev/tcp fails; netcat_gaping is the lab default
_distcc_pl = smart_payload('exploit/unix/misc/distcc_exec', 'Linux 2.6.x', '')
if _distcc_pl == 'cmd/unix/reverse_perl':
    ok("distcc_exec on Linux 2.6 gets reverse_perl (MSF-compatible, no /dev/tcp)")
else:
    fail(f"distcc_exec on Linux 2.6 wrong payload: {_distcc_pl}")

_samba_pl = smart_payload('exploit/multi/samba/usermap_script', 'Linux 2.6.x', '')
if _samba_pl == 'cmd/unix/reverse_perl':
    ok("usermap_script on Linux 2.6 gets reverse_perl")
else:
    fail(f"usermap_script on Linux 2.6 wrong payload: {_samba_pl}")

# Modern Linux still gets reverse_bash for generic unix/multi when no override
_mod_pl = smart_payload('exploit/multi/http/log4shell_header_injection',
                        'Ubuntu 22.04 Linux', '')
if _mod_pl == 'cmd/unix/reverse_bash':
    ok("Modern Ubuntu Log4Shell still defaults to reverse_bash")
else:
    fail(f"Modern Linux unix exploit unexpected payload: {_mod_pl}")

# Legacy Linux downgrades reverse_bash overrides (redis, etc.) to reverse_perl
_redis_pl = smart_payload('exploit/linux/redis/redis_replication_cmd_exec',
                          'Linux 2.6.x', '')
if _redis_pl == 'cmd/unix/reverse_perl':
    ok("Redis exploit on Linux 2.6 downgrades reverse_bash override to reverse_perl")
else:
    fail(f"Redis on Linux 2.6 wrong payload: {_redis_pl}")

# Every exploit-class module must resolve a non-empty payload
empty_payload = []
for key, entries in CVE_MAP.items():
    for _cve, mod, _desc, _sev in entries:
        if mod and mod.startswith('exploit/'):
            p = smart_payload(mod, 'Linux 2.6', '')
            if not p:
                empty_payload.append(mod)
if empty_payload:
    fail(f"Exploit modules with empty smart_payload: {empty_payload[:5]}")
else:
    ok("Every exploit-class module resolves a non-empty smart_payload")

# ── Report ────────────────────────────────────────────────────────────────────
print("\n" + "═" * 72)
print(f" PARANOIA AUDIT — {len(FAIL)} FAIL · {len(WARN)} WARN · "
      f"{len(INFO)} INFO · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:");  [print(f"  ✗ {m}") for m in FAIL]
if WARN:
    print("\nWARN:");  [print(f"  ! {m}") for m in WARN]
if INFO:
    print("\nINFO:");  [print(f"  i {m}") for m in INFO]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
print()
sys.exit(1 if FAIL else 0)
