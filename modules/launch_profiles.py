"""
launch_profiles.py — Module-aware launch configuration.

The Exploit launcher historically assumed every exploit is a reverse-callback
exploit: it gated on callback-path verification, auto-filled LHOST, and defaulted
LPORT to 4444. That is wrong for whole classes of modules:

  - vsftpd_234_backdoor   → cmd/unix/interact, lands a bind shell on target :6200,
                            NO LHOST/LPORT, no reverse callback at all
  - distcc / UnrealIRCd    → reverse cmd payload, but on a FIXED service port
  - ms17_010 / SMBGhost    → meterpreter reverse on 445 (not 139)

A launch profile resolves, from the module name, exactly how the launcher should
behave so the operator can't misfire (reverse payload + LPORT 4444 at an interact
backdoor, scanning a single-shot bind port, wrong RPORT, etc.).

This is pure data + string matching — no MSF/RPC dependency — so it is fully
unit-testable (audit_launch_profiles.py) and shared by the backend (RPORT
auto-correct, curated payload) and the frontend (field enable/disable, gate).

Fields
──────
  force_rport     : int | None  — auto-correct RPORT to the module's real port
  payload_mode    : 'interact' | 'reverse' | 'bind' | 'meterpreter' | 'auto'
  default_payload : str | None  — what a blank payload resolves to (UI hint)
  needs_callback  : bool        — reverse callback applies → gate + require LHOST
  uses_lhost      : bool        — whether LHOST is meaningful for this module
  uses_lport      : bool        — whether LPORT is meaningful
  automigrate     : bool        — sensible auto-migrate default
  single_shot     : bool        — bind port serves one connection (don't scan it)
  lands_on        : str         — human description of where the shell appears
  requires        : list[str]   — datastore options the operator must set
  notes           : str         — operator-facing one-liner
"""
from __future__ import annotations

from typing import Any

_BASE: dict[str, Any] = {
    'id':              'generic',
    'label':           'Generic exploit',
    'force_rport':     None,
    'payload_mode':    'auto',
    'default_payload': None,
    'needs_callback':  True,    # safe default: gate on, require LHOST
    'uses_lhost':      True,
    'uses_lport':      True,
    'automigrate':     False,
    'single_shot':     False,
    'lands_on':        'reverse callback to LHOST:LPORT',
    'requires':        [],
    'notes':           'Standard reverse-payload exploit.',
}


# Ordered list of (needle, profile-overrides). First substring match wins, so
# put more specific needles before broader ones.
_PROFILES: list[tuple[str, dict[str, Any]]] = [
    # ── vsftpd 2.3.4 backdoor — interact, bind shell on :6200, no callback ────
    ('vsftpd_234_backdoor', {
        'id':              'vsftpd_234_backdoor',
        'label':           'vsftpd 2.3.4 backdoor',
        'force_rport':     21,
        'payload_mode':    'interact',
        'default_payload': 'cmd/unix/interact',
        'needs_callback':  False,
        'uses_lhost':      False,
        'uses_lport':      False,
        'automigrate':     False,
        'single_shot':     True,
        'lands_on':        'root shell the module connects to on target :6200',
        'requires':        [],
        'notes':           ('Backdoor triggers via the FTP :) smiley and binds a '
                            'root shell on :6200. No LHOST/LPORT, no reverse '
                            'callback. Single-shot — do NOT scan 6200 (a scan '
                            'consumes it); let MSF connect via cmd/unix/interact.'),
    }),
    # ── distcc — reverse cmd, handler-first, port 3632 ────────────────────────
    ('distcc_exec', {
        'id':              'distcc_exec',
        'label':           'distccd command exec',
        'force_rport':     3632,
        'payload_mode':    'reverse',
        'default_payload': 'cmd/unix/reverse_perl',
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'reverse callback (handler-first)',
        'notes':           'reverse_perl + handler-first. Needs LHOST routable to target.',
    }),
    # ── UnrealIRCd backdoor — reverse cmd, port 6667 ──────────────────────────
    ('unreal_ircd_3281_backdoor', {
        'id':              'unreal_ircd_3281_backdoor',
        'label':           'UnrealIRCd 3.2.8.1 backdoor',
        'force_rport':     6667,
        'payload_mode':    'reverse',
        'default_payload': 'cmd/unix/reverse_perl',
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'reverse callback (handler-first)',
        'notes':           'reverse_perl + handler-first on IRC 6667.',
    }),
    # ── Samba usermap_script — reverse cmd, port 139 ──────────────────────────
    ('usermap_script', {
        'id':              'usermap_script',
        'label':           'Samba usermap_script',
        'force_rport':     139,
        'payload_mode':    'reverse',
        'default_payload': 'cmd/unix/reverse_perl',
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'reverse callback',
        'notes':           'reverse_perl. Samba username-map command injection on 139.',
    }),
    # ── Java RMI — meterpreter reverse, port 1099 ─────────────────────────────
    ('java_rmi_server', {
        'id':              'java_rmi_server',
        'label':           'Java RMI server',
        'force_rport':     1099,
        'payload_mode':    'meterpreter',
        'default_payload': 'java/meterpreter/reverse_tcp',
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'Java Meterpreter reverse callback',
        'notes':           'Java Meterpreter. Needs LHOST routable to target.',
    }),
    # ── MS17-010 family — meterpreter reverse on 445 ──────────────────────────
    ('ms17_010', {
        'id':              'ms17_010',
        'label':           'MS17-010 EternalBlue family',
        'force_rport':     445,
        'payload_mode':    'meterpreter',
        'default_payload': 'windows/x64/meterpreter/reverse_tcp',
        'needs_callback':  True,
        'automigrate':     True,
        'lands_on':        'x64 Meterpreter reverse callback',
        'notes':           'SMBv1 on 445. Auto-migrate ON (fragile kernel session).',
    }),
    ('cve_2020_0796', {
        'id':              'smbghost',
        'label':           'SMBGhost (CVE-2020-0796)',
        'force_rport':     445,
        'payload_mode':    'meterpreter',
        'default_payload': 'windows/x64/meterpreter/reverse_tcp',
        'needs_callback':  True,
        'automigrate':     True,
        'lands_on':        'x64 Meterpreter reverse callback',
        'notes':           'SMBv3 compression on 445. Auto-migrate ON.',
    }),
    # ── Jenkins script console — web RCE, needs TARGETURI ─────────────────────
    ('jenkins_script_console', {
        'id':              'jenkins_script_console',
        'label':           'Jenkins script console RCE',
        'force_rport':     8080,
        'payload_mode':    'reverse',
        'default_payload': None,
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'reverse callback after Groovy exec',
        'requires':        ['TARGETURI'],
        'notes':           ('Web RCE via Groovy console. Set TARGETURI (often "/"); '
                            'may need USERNAME/PASSWORD if the console is secured.'),
    }),
    # ── Drupalgeddon family — web RCE, version-specific, needs TARGETURI ──────
    ('drupalgeddon', {
        'id':              'drupalgeddon',
        'label':           'Drupalgeddon family',
        'force_rport':     None,
        'payload_mode':    'reverse',
        'default_payload': None,
        'needs_callback':  True,
        'automigrate':     False,
        'lands_on':        'reverse callback / PHP exec',
        'requires':        ['TARGETURI'],
        'notes':           ('Version-specific: Drupalgeddon 1 vs 2 vs 3 are '
                            'different modules — match the detected Drupal version. '
                            'Set TARGETURI to the Drupal root.'),
    }),
]


def resolve_launch_profile(module: str | None) -> dict[str, Any]:
    """Resolve the launch profile for a module name. Returns a fresh copy."""
    m = (module or '').lower()
    profile = dict(_BASE)
    for needle, overrides in _PROFILES:
        if needle in m:
            profile.update(overrides)
            break
    profile['module'] = module or ''
    return profile
