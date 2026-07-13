"""
handoff.py — Flexible, profile-driven post-exploit shell handoff.

The handoff problem has three independent concerns:

  1. Delivery     — did the shell reach Kali?  (handled at launch: handler-first,
                    ExitOnSession, callback verify)
  2. Confirmation — is the session actually alive in msfrpcd, not just printed
                    to the console?  (probe it before trusting it)
  3. Hardening    — should we migrate / background / run recon?  (depends on the
                    session type and the exploit that produced it)

This module owns concerns (2) and (3) as DATA, not tribal knowledge. A profile
is resolved from (module, payload, session_type) and tells the engine + UI:

  - confirm_cmds : probes that prove the session responds (L2 liveness)
  - harden_cmds  : migrate/background steps (Meterpreter only, usually)
  - recon_cmds   : quick situational-awareness commands surfaced to the operator
  - session_expected : False for auxiliary/post modules (ghostcat) — no shell
  - background   : whether the session should be backgrounded after hardening
  - skip_migrate_if_launch_migrated : avoid double-migrate that kills fragile
                                       kernel sessions
  - notes        : operator-facing one-liner

Everything here is pure Python with no MSF RPC dependency so it can be unit
tested offline (see audit_handoff.py).
"""
from __future__ import annotations

from typing import Any

# ── Markers ───────────────────────────────────────────────────────────────────
# Module-name needles that change handoff behaviour. Kept lowercase; matched as
# substrings against the module path.
_FRAGILE_MODULE_MARKERS = (
    'ms17_010', 'eternalblue', 'eternalromance', 'bluekeep',
    'cve_2020_0796', 'smbghost', 'ms08_067',
)
_AUX_NO_SESSION_MARKERS = (
    'ghostcat', 'auxiliary/', 'scanner/', '/admin/',
)
_INTERACT_BACKDOOR_MARKERS = (
    'vsftpd_234', 'vsftpd', 'unix/ftp/vsftpd',
)


def _is_meterpreter(session_type: str | None) -> bool:
    return 'meter' in (session_type or '').lower()


def _is_powershell(session_type: str | None) -> bool:
    return (session_type or '').lower() == 'powershell'


def _is_shell(session_type: str | None) -> bool:
    t = (session_type or '').lower()
    return t == 'shell' or t == 'cmd'


def _is_interact_payload(payload: str | None) -> bool:
    return bool(payload and 'interact' in payload.lower())


def _is_bind_payload(payload: str | None) -> bool:
    return bool(payload and 'bind' in payload.lower())


def _is_reverse_cmd_payload(payload: str | None) -> bool:
    pl = (payload or '').lower()
    return pl.startswith('cmd/') and 'reverse' in pl


def _module_has(module: str | None, markers: tuple[str, ...]) -> bool:
    m = (module or '').lower()
    return any(marker in m for marker in markers)


def _is_aux_module(module: str | None, module_type: str | None) -> bool:
    if (module_type or '').lower() in ('auxiliary', 'post'):
        return True
    return _module_has(module, _AUX_NO_SESSION_MARKERS)


# ── Profile catalog ────────────────────────────────────────────────────────────
# Each profile is a plain dict. resolve_profile() returns a *copy* so callers can
# safely mutate (e.g. inject session_id-specific notes) without corrupting the
# catalog.

_BASE_PROFILE: dict[str, Any] = {
    'id':                 'generic',
    'label':              'Generic session',
    'session_expected':   True,
    'confirm_cmds':       ['echo H3X_HANDOFF_OK'],
    'harden_cmds':        [],
    'recon_cmds':         [],
    'background':         False,
    'skip_migrate_if_launch_migrated': False,
    'auto_harden':        False,
    'notes':              'Session landed. Verify liveness before interacting.',
}

HANDOFF_PROFILES: dict[str, dict[str, Any]] = {
    # ── Generic fallback ─────────────────────────────────────────────────────
    'generic': dict(_BASE_PROFILE),

    # ── No-session modules (ghostcat etc.) ───────────────────────────────────
    'no_session': {
        **_BASE_PROFILE,
        'id':               'no_session',
        'label':            'Auxiliary / no shell expected',
        'session_expected': False,
        'confirm_cmds':     [],
        'recon_cmds':       [],
        'notes':            ('Auxiliary/post module — no interactive session is '
                             'created. Review the module output for findings '
                             '(file reads, scan results).'),
    },

    # ── Linux cmd/unix shells ────────────────────────────────────────────────
    'linux_cmd_reverse': {
        **_BASE_PROFILE,
        'id':           'linux_cmd_reverse',
        'label':        'Linux cmd shell (reverse)',
        'confirm_cmds': ['id', 'uname -a'],
        'harden_cmds':  [],                 # no migrate for cmd/unix shells
        'recon_cmds':   ['id', 'uname -a', 'sudo -l', 'cat /etc/passwd'],
        'background':   False,
        'auto_harden':  True,               # run confirm+recon automatically
        'notes':        ('distcc/IRC/Samba cmd shell. No migrate available — '
                         'keep interactive. If it dies, re-verify the handler '
                         'is listening or switch to a bind payload.'),
    },
    'linux_cmd_interact': {
        **_BASE_PROFILE,
        'id':           'linux_cmd_interact',
        'label':        'Linux cmd shell (interact backdoor)',
        'confirm_cmds': ['id', 'uname -a'],
        'harden_cmds':  [],
        'recon_cmds':   ['id', 'uname -a', 'cat /etc/passwd'],
        'background':   False,
        'auto_harden':  True,
        'notes':        ('vsftpd-style backdoor shell (cmd/unix/interact, lands '
                         'on target :6200). No reverse handler involved; do not '
                         'migrate. Often already root.'),
    },
    'linux_cmd_bind': {
        **_BASE_PROFILE,
        'id':           'linux_cmd_bind',
        'label':        'Linux cmd shell (bind)',
        'confirm_cmds': ['id', 'uname -a'],
        'harden_cmds':  [],
        'recon_cmds':   ['id', 'uname -a', 'sudo -l'],
        'background':   False,
        'auto_harden':  True,
        'notes':        ('Bind shell — MSF connected out to the target listener. '
                         'No migrate; keep interactive.'),
    },

    # ── Windows Meterpreter ──────────────────────────────────────────────────
    'windows_meterpreter_fragile': {
        **_BASE_PROFILE,
        'id':           'windows_meterpreter_fragile',
        'label':        'Windows Meterpreter (fragile kernel exploit)',
        'confirm_cmds': ['sysinfo'],
        'harden_cmds':  ['migrate -n notepad.exe', 'background'],
        'recon_cmds':   ['getuid', 'sysinfo'],
        'background':   True,
        'skip_migrate_if_launch_migrated': True,
        'auto_harden':  True,
        'notes':        ('Kernel-injection exploit (EternalBlue/SMBGhost). The '
                         'host process can die fast — migrate to a stable '
                         'process unless launch already migrated, then '
                         'background.'),
    },
    'windows_meterpreter': {
        **_BASE_PROFILE,
        'id':           'windows_meterpreter',
        'label':        'Windows Meterpreter',
        'confirm_cmds': ['sysinfo'],
        'harden_cmds':  ['background'],
        'recon_cmds':   ['getuid', 'sysinfo'],
        'background':   True,
        'skip_migrate_if_launch_migrated': True,
        'auto_harden':  True,
        'notes':        ('Stable Meterpreter. Background it so it survives '
                         'console detach; migrate manually if the host process '
                         'looks volatile.'),
    },
    'windows_powershell': {
        **_BASE_PROFILE,
        'id':           'windows_powershell',
        'label':        'Windows PowerShell session',
        'confirm_cmds': ['whoami'],
        'harden_cmds':  [],
        'recon_cmds':   ['whoami', 'hostname'],
        'background':   False,
        'auto_harden':  True,
        'notes':        'PowerShell session — no migrate. Run recon, then pivot.',
    },
}


def resolve_profile(module: str | None,
                    payload: str | None,
                    session_type: str | None,
                    module_type: str | None = None) -> dict[str, Any]:
    """
    Pick the handoff profile for a session.

    Resolution priority (most specific first):
      1. Auxiliary/post modules     -> no_session
      2. Meterpreter sessions       -> fragile vs normal
      3. PowerShell sessions        -> windows_powershell
      4. cmd/unix shells            -> interact | bind | reverse | generic-cmd
      5. fallback                   -> generic

    Returns a fresh copy of the matched profile, annotated with the resolution
    inputs so the UI can explain why a profile was chosen.
    """
    # 1. No-session modules win regardless of (absent) session type.
    if _is_aux_module(module, module_type):
        profile = dict(HANDOFF_PROFILES['no_session'])
        return _annotate(profile, module, payload, session_type)

    # 2. Meterpreter.
    if _is_meterpreter(session_type):
        key = ('windows_meterpreter_fragile'
               if _module_has(module, _FRAGILE_MODULE_MARKERS)
               else 'windows_meterpreter')
        return _annotate(dict(HANDOFF_PROFILES[key]),
                         module, payload, session_type)

    # 3. PowerShell.
    if _is_powershell(session_type):
        return _annotate(dict(HANDOFF_PROFILES['windows_powershell']),
                         module, payload, session_type)

    # 4. cmd/unix shells — sub-classify by payload delivery style.
    if _is_shell(session_type) or _is_reverse_cmd_payload(payload) \
            or _is_interact_payload(payload) or _is_bind_payload(payload):
        if _is_interact_payload(payload) or _module_has(module, _INTERACT_BACKDOOR_MARKERS):
            key = 'linux_cmd_interact'
        elif _is_bind_payload(payload):
            key = 'linux_cmd_bind'
        else:
            key = 'linux_cmd_reverse'
        return _annotate(dict(HANDOFF_PROFILES[key]),
                         module, payload, session_type)

    # 5. Fallback.
    return _annotate(dict(HANDOFF_PROFILES['generic']),
                     module, payload, session_type)


def _annotate(profile: dict[str, Any], module, payload, session_type) -> dict[str, Any]:
    profile['resolved_from'] = {
        'module':       module or '',
        'payload':      payload or '',
        'session_type': session_type or '',
    }
    return profile


def confirm_output_is_alive(profile: dict[str, Any], output: str) -> bool:
    """
    Decide whether confirmation-probe output indicates a live session.

    A session is considered alive if the probe produced any non-empty,
    non-error output. For the generic echo probe we look for the sentinel.
    """
    text = (output or '').strip()
    if not text:
        return False
    low = text.lower()
    # Hard failure signals from MSF / dead pipes.
    dead_signals = (
        'session id', 'does not exist', 'unknown session',
        'session is not valid', 'invalid session', 'session closed',
    )
    if any(sig in low for sig in dead_signals):
        return False
    # Generic echo probe — require the sentinel to actually round-trip.
    if profile.get('id') == 'generic':
        return 'h3x_handoff_ok' in low
    return True
