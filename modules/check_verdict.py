"""
check_verdict.py — CheckCode-aware parsing of MSF `check` console output.

Metasploit's `check` method returns a structured CheckCode, but over RPC we only
see the human-readable line it prints. The old detector recognised exactly one
phrasing (a line containing the literal word "vulnerable" with a `[+]`), so any
module whose check reported a *different* CheckCode — Detected, Safe-by-other-
wording, or "does not support check" — fell through to a single ambiguous
UNKNOWN. On Metasploitable2 that is most of the classic modules, which is why
green verdicts looked like they "turned into" unknowns.

This module maps the full CheckCode vocabulary to fine-grained codes and the
validator-facing verdict buckets:

  CODE         VERDICT          meaning
  ───────────  ───────────────  ────────────────────────────────────────────────
  VULNERABLE   VULNERABLE       MSF confirmed the target is vulnerable
  APPEARS      VULNERABLE       version/banner indicates vulnerable (Appears)
  DETECTED     DETECTED         service present, exploitability NOT confirmed
  SAFE         NOT_VULNERABLE   target reported not exploitable / patched
  UNSUPPORTED  NO_CHECK         module has no check method (expected for many
                                MT2 backdoors — confirm by exploiting)
  UNREACHABLE  ERROR            could not connect / timed out / refused
  UNKNOWN      UNKNOWN          ran but gave no usable signal

Pure-string logic, no MSF dependency → fully unit-testable (audit_check_verdict).
"""
from __future__ import annotations

from typing import Any

# Verdict buckets (kept in sync with msf_validator constants).
VULNERABLE     = 'VULNERABLE'
NOT_VULNERABLE = 'NOT_VULNERABLE'
DETECTED       = 'DETECTED'
NO_CHECK       = 'NO_CHECK'
UNKNOWN        = 'UNKNOWN'
ERROR          = 'ERROR'

# Fine-grained CheckCode-style codes.
CODE_VULNERABLE  = 'VULNERABLE'
CODE_APPEARS     = 'APPEARS'
CODE_DETECTED    = 'DETECTED'
CODE_SAFE        = 'SAFE'
CODE_UNSUPPORTED = 'UNSUPPORTED'
CODE_UNREACHABLE = 'UNREACHABLE'
CODE_UNKNOWN     = 'UNKNOWN'

_CODE_TO_VERDICT = {
    CODE_VULNERABLE:  VULNERABLE,
    CODE_APPEARS:     VULNERABLE,
    CODE_DETECTED:    DETECTED,
    CODE_SAFE:        NOT_VULNERABLE,
    CODE_UNSUPPORTED: NO_CHECK,
    CODE_UNREACHABLE: ERROR,
    CODE_UNKNOWN:     UNKNOWN,
}

# Human details per code (overridden by the matched source line when available).
_CODE_DETAIL = {
    CODE_VULNERABLE:  'MSF check confirms the target is vulnerable',
    CODE_APPEARS:     'MSF check: target appears vulnerable (version/banner match)',
    CODE_DETECTED:    'Service detected but exploitability could not be validated '
                      '— confirm by exploiting',
    CODE_SAFE:        'MSF check reports the target is not exploitable',
    CODE_UNSUPPORTED: 'Module has no check method — expected for many backdoor/'
                      'cmd-exec modules; confirm by exploiting',
    CODE_UNREACHABLE: 'Check could not reach the target service',
    CODE_UNKNOWN:     'Module ran but returned no definitive verdict',
}

# ── Signature phrases (lowercased substrings) ─────────────────────────────────
# Ordered evaluation in parse_check_verdict(); negatives are guarded explicitly.
_SAFE_SIGNS = (
    'not exploitable',
    'is not vulnerable',
    'not be vulnerable',
    'target is safe',
    'is safe.',
    'does not appear to be vulnerable',
)
_UNSUPPORTED_SIGNS = (
    'does not support check',
    'check is not supported',
    'no check',                       # "This module does not support check" variants
    'check is not implemented',
)
_APPEARS_SIGNS = (
    'appears to be vulnerable',
    'appears vulnerable',
    'may be vulnerable',
    'might be vulnerable',
)
# MS17-010's scanner prints "Host is likely VULNERABLE to MS17-010!" which MSF
# classifies as CheckCode::Vulnerable — so "likely vulnerable" is a confirmed
# positive, not the softer Appears bucket.
_VULNERABLE_SIGNS = (
    'the target is vulnerable',
    'is vulnerable.',
    'is likely vulnerable',
    'likely vulnerable',
    'host is vulnerable',
    'target vulnerable',
    'confirmed vulnerable',
)
_DETECTED_SIGNS = (
    'could not be validated',
    'service is running, but',
    'cannot be validated',
    'detected but',
    'the service is running',
)
_UNREACHABLE_SIGNS = (
    'connection refused',
    'could not connect',
    'failed to connect',
    'connection timed out',
    'timed out',
    'no route to host',
    'unable to connect',
    'rport.*closed',          # not a regex here — substring 'rport' style msgs
    'is unreachable',
    'host unreachable',
)
_UNKNOWN_SIGNS = (
    'cannot reliably check',
    'cannot check',
    'could not determine',
    'unable to determine',
    'check failed',
    'check did not return',
)


def _first_matching_line(text: str, needle: str) -> str:
    """Return the first source line (original case) containing needle."""
    low_needle = needle.lower()
    for line in text.splitlines():
        if low_needle in line.lower():
            return line.strip()
    return ''


def parse_check_verdict(console_text: str | None,
                        engine_status: str | None = None,
                        engine_message: str | None = None) -> dict[str, Any]:
    """
    Map MSF check console output to {code, verdict, detail, source}.

    engine_status/engine_message let callers fold an upstream transport error
    (status == 'error') into the verdict without losing the console signal.
    """
    if engine_status == 'error':
        return {
            'code':    CODE_UNREACHABLE,
            'verdict': ERROR,
            'detail':  engine_message or _CODE_DETAIL[CODE_UNREACHABLE],
            'source':  engine_message or '',
        }

    text = console_text or ''
    low = text.lower()

    if not low.strip():
        return {
            'code':    CODE_UNKNOWN,
            'verdict': UNKNOWN,
            'detail':  'No check output captured (console returned nothing)',
            'source':  '',
        }

    # Priority order matters: SAFE and UNSUPPORTED are checked before the
    # positive "vulnerable" signs because a "not vulnerable" line contains the
    # token "vulnerable", and "does not support check" must never be read as a
    # verdict. APPEARS is distinguished from VULNERABLE for operator nuance.
    def _hit(signs):
        for s in signs:
            if s in low:
                return s
        return None

    s = _hit(_SAFE_SIGNS)
    if s:
        return _verdict(CODE_SAFE, _first_matching_line(text, s))

    s = _hit(_UNSUPPORTED_SIGNS)
    if s:
        return _verdict(CODE_UNSUPPORTED, _first_matching_line(text, s))

    s = _hit(_APPEARS_SIGNS)
    if s:
        return _verdict(CODE_APPEARS, _first_matching_line(text, s))

    # Positive vulnerable — accept either an explicit phrase or a [+] line that
    # mentions "vulnerable" (MSF print_good), but never "not vulnerable".
    s = _hit(_VULNERABLE_SIGNS)
    if s and 'not vulnerable' not in low:
        return _verdict(CODE_VULNERABLE, _first_matching_line(text, s))
    if ('vulnerable' in low and 'not vulnerable' not in low
            and _line_with_both(text, '[+]', 'vulnerable')):
        return _verdict(CODE_VULNERABLE, _line_with_both(text, '[+]', 'vulnerable'))

    s = _hit(_DETECTED_SIGNS)
    if s:
        return _verdict(CODE_DETECTED, _first_matching_line(text, s))

    s = _hit(_UNREACHABLE_SIGNS)
    if s:
        return _verdict(CODE_UNREACHABLE, _first_matching_line(text, s))

    s = _hit(_UNKNOWN_SIGNS)
    if s:
        return _verdict(CODE_UNKNOWN, _first_matching_line(text, s))

    return {
        'code':    CODE_UNKNOWN,
        'verdict': UNKNOWN,
        'detail':  _CODE_DETAIL[CODE_UNKNOWN],
        'source':  '',
    }


def _line_with_both(text: str, a: str, b: str) -> str:
    for line in text.splitlines():
        ll = line.lower()
        if a in ll and b in ll:
            return line.strip()
    return ''


def _verdict(code: str, source_line: str) -> dict[str, Any]:
    detail = _CODE_DETAIL.get(code, _CODE_DETAIL[CODE_UNKNOWN])
    if source_line:
        # Prefer the actual MSF line — it's the most precise operator signal.
        detail = f'{detail} ({source_line})' if code in (
            CODE_DETECTED, CODE_UNREACHABLE, CODE_UNKNOWN) else source_line
    return {
        'code':    code,
        'verdict': _CODE_TO_VERDICT[code],
        'detail':  detail,
        'source':  source_line,
    }
