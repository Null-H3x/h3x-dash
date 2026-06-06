"""
credentials.py — Central credential store for H3x-Dash.

Captured creds (passwords, NTLM hashes, Kerberos tickets, SSH keys, tokens,
session cookies, confirmed-valid usernames) live here so they can flow between
phases. Findings with credential indicators auto-populate the store via
creds_from_finding() — called from enum_engine's finding closure.

File-backed at config.LOOT_DIR / 'credentials.json' by default. Schema is
intentionally generous to cover every cred type a pentest produces.

Public API:
  CredentialStore(path)
    .add(cred)              -> uuid
    .get(id)                -> dict | None
    .list(**filters)        -> list[dict] (sorted by timestamp desc)
    .remove(id)             -> bool
    .mark_verified(id, ok)  -> bool
    .tag(id, tag)           -> bool
    .stats()                -> dict
    .clear()

  creds_from_finding(finding) -> list[dict]
    Extract credential indicators from a finding dict (explicit 'creds' list
    and 'ad_users'/'web_users' type findings).
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Credential type taxonomy — kept tight; new types require a code change
# so storage stays predictable for reporting / cracking pipelines.
CRED_TYPES = (
    'password',          # plaintext value
    'ntlm_hash',         # LM:NTLM hex or NTLM-only
    'kerberos_ticket',   # TGT/TGS kirbi blob (base64-encoded in `value`)
    'kerberos_spn',      # SPN string — kerberoasting candidate
    'ssh_key',           # private SSH key (PEM-encoded in `value`)
    'token',             # session token, API key, JWT
    'cookie',            # session cookie name=value pair
    'username_only',     # confirmed-valid username without password
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CredentialStore:
    """Thread-safe, file-backed credential store. Last-write-wins; atomic save."""

    def __init__(self, path: str | Path):
        self.path  = Path(path)
        self._lock = threading.RLock()
        self._creds: dict[str, dict] = {}
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self._creds = data.get('credentials', {})
            log.info(f"credential store loaded: {len(self._creds)} entries")
        except Exception as exc:
            log.warning(f"credential store load failed: {exc} — starting empty")
            self._creds = {}

    def _save(self) -> None:
        """Atomic write: tmp file → rename. Survives mid-write crashes."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(
                {'credentials': self._creds,
                 'saved_at':    _utcnow_iso(),
                 'count':       len(self._creds)},
                indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            log.error(f"credential store save failed: {exc}")

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add(self, cred: dict) -> str:
        """
        Add a credential. Returns the assigned UUID (or existing UUID on dedup).

        Dedup key: (type, username.lower(), value, host_ip).
        Duplicates short-circuit without modifying timestamps.
        """
        cred = dict(cred)   # don't mutate caller's dict
        ctype = cred.get('type')
        if ctype not in CRED_TYPES:
            raise ValueError(
                f"invalid cred type: {ctype!r} (must be one of {CRED_TYPES})")

        cred.setdefault('id',                str(uuid.uuid4()))
        cred.setdefault('username',          '')
        cred.setdefault('domain',            None)
        cred.setdefault('value',             '')
        cred.setdefault('service',           '')
        cred.setdefault('host_ip',           None)
        cred.setdefault('host_port',         None)
        cred.setdefault('source_tool',       'unknown')
        cred.setdefault('source_finding_id', None)
        cred.setdefault('timestamp',         _utcnow_iso())
        cred.setdefault('verified',          False)
        cred.setdefault('verified_at',       None)
        cred.setdefault('tags',              [])

        dedup_key = (ctype,
                     (cred['username'] or '').lower(),
                     cred['value'],
                     cred.get('host_ip'))

        with self._lock:
            for existing_id, existing in self._creds.items():
                e_key = (existing['type'],
                         (existing.get('username') or '').lower(),
                         existing.get('value', ''),
                         existing.get('host_ip'))
                if e_key == dedup_key:
                    return existing_id
            self._creds[cred['id']] = cred
            self._save()
        return cred['id']

    def get(self, cred_id: str) -> dict | None:
        with self._lock:
            c = self._creds.get(cred_id)
            return dict(c) if c else None

    def list(self, **filters: Any) -> list[dict]:
        """
        Filter and return creds. Filters are exact-match on top-level fields.
        Common: type='ntlm_hash', verified=True, host_ip='10.0.0.5'.
        """
        with self._lock:
            results = list(self._creds.values())
        for k, v in filters.items():
            results = [c for c in results if c.get(k) == v]
        results.sort(key=lambda c: c.get('timestamp', ''), reverse=True)
        return [dict(c) for c in results]

    def remove(self, cred_id: str) -> bool:
        with self._lock:
            if cred_id not in self._creds:
                return False
            del self._creds[cred_id]
            self._save()
        return True

    def mark_verified(self, cred_id: str, success: bool = True) -> bool:
        with self._lock:
            if cred_id not in self._creds:
                return False
            self._creds[cred_id]['verified']    = success
            self._creds[cred_id]['verified_at'] = _utcnow_iso()
            self._save()
        return True

    def tag(self, cred_id: str, tag: str) -> bool:
        with self._lock:
            if cred_id not in self._creds:
                return False
            tags = self._creds[cred_id].setdefault('tags', [])
            if tag not in tags:
                tags.append(tag)
                self._save()
        return True

    # ── Aggregate ─────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            creds = list(self._creds.values())
        by_type   = {t: 0 for t in CRED_TYPES}
        by_source: dict[str, int] = {}
        for c in creds:
            by_type[c['type']] = by_type.get(c['type'], 0) + 1
            src = c.get('source_tool', 'unknown')
            by_source[src] = by_source.get(src, 0) + 1
        return {
            'total':         len(creds),
            'verified':      sum(1 for c in creds if c.get('verified')),
            'with_password': sum(1 for c in creds
                                 if c['type'] == 'password' and c['value']),
            'with_hash':     sum(1 for c in creds if c['type'] == 'ntlm_hash'),
            'by_type':       by_type,
            'by_source':     by_source,
        }

    def clear(self) -> None:
        with self._lock:
            self._creds.clear()
            self._save()


# ── Finding → credential extractor ────────────────────────────────────────────

def creds_from_finding(finding: dict) -> list[dict]:
    """
    Inspect a finding dict and return any embedded credential records.

    Recognises:
      1. Explicit `creds` key — a list of cred dicts (richest, preferred)
      2. `type` in ('ad_users', 'web_users') with usernames in `detail`
         — produces username_only entries (no password)

    Caller is responsible for handing the returned list to CredentialStore.add().
    Returns an empty list if no creds were found — never raises.
    """
    out: list[dict] = []

    # 1. Explicit creds list — runners may populate this directly
    explicit = finding.get('creds')
    if isinstance(explicit, list):
        for c in explicit:
            if not isinstance(c, dict):
                continue
            cred = dict(c)
            cred.setdefault('host_ip',           finding.get('host_ip'))
            cred.setdefault('host_port',         finding.get('port'))
            cred.setdefault('source_tool',       finding.get('tool', 'unknown'))
            cred.setdefault('source_finding_id', finding.get('id'))
            cred.setdefault('service',           finding.get('tool', ''))
            out.append(cred)

    # 2. Enumerated usernames in 'ad_users' / 'web_users' findings
    ftype  = finding.get('type', '')
    detail = (finding.get('detail') or '').strip()
    if ftype in ('ad_users', 'web_users') and detail:
        # detail is typically "user1, user2, user3 + 5 more"
        head = detail.split(' + ')[0]
        for u in head.split(','):
            u = u.strip()
            if not u or len(u) > 64:    # bogus / overlong — skip
                continue
            if '@' in u:
                user, domain = u.split('@', 1)
            else:
                user, domain = u, None
            out.append({
                'type':              'username_only',
                'username':          user,
                'domain':            domain,
                'value':             '',
                'service':           finding.get('tool', ftype),
                'host_ip':           finding.get('host_ip'),
                'host_port':         finding.get('port'),
                'source_tool':       finding.get('tool', 'unknown'),
                'source_finding_id': finding.get('id'),
            })

    return out


# ── Session-output parsers ────────────────────────────────────────────────────
# When the operator runs `hashdump`, `creds_all`, etc. through the Shell tab,
# these helpers parse the raw output into structured cred dicts ready for
# CredentialStore.add(). Pure-stdlib regex; tolerate junk lines.

import re as _re

# Meterpreter hashdump:  Administrator:500:LM_HASH:NTLM_HASH:::
_HASHDUMP_RE = _re.compile(
    r'^([^:\s]+):(\d+):([a-fA-F0-9]{32}|aad3b435b51404eeaad3b435b51404ee):'
    r'([a-fA-F0-9]{32}):::\s*$', _re.MULTILINE)

# Mimikatz / kiwi: "username : password" or "NTLM    : hash"
_KIWI_USER_RE = _re.compile(
    r'\*\s*Username\s*:\s*(\S+).*?\*\s*Domain\s*:\s*(\S+).*?'
    r'\*\s*(?:Password|NTLM)\s*:\s*([^\s\n]+)',
    _re.DOTALL | _re.IGNORECASE)

# Linux /etc/shadow: user:$6$salt$hash:lastchg:min:max:warn:inactive:expire:
_SHADOW_RE = _re.compile(
    r'^([a-z_][a-z0-9_-]*):(\$\d[a-z]?\$[^:]+):', _re.MULTILINE | _re.IGNORECASE)


def parse_hashdump_output(output: str, host_ip: str = '',
                           source_tool: str = 'hashdump') -> list[dict]:
    """
    Parse Meterpreter hashdump output. Each line:
        user:RID:LM_HASH:NTLM_HASH:::

    Returns one cred dict per parsed line — type='ntlm_hash', value is the
    concatenated 'LM:NTLM' which is the format pass-the-hash modules expect.
    """
    if not output:
        return []
    creds = []
    for m in _HASHDUMP_RE.finditer(output):
        user, rid, lm_hash, ntlm_hash = m.group(1), m.group(2), m.group(3), m.group(4)
        creds.append({
            'type':        'ntlm_hash',
            'username':    user,
            'domain':      None,
            'value':       f'{lm_hash}:{ntlm_hash}',
            'service':     'smb',
            'host_ip':     host_ip or None,
            'host_port':   445,
            'source_tool': source_tool,
            'verified':    False,
            'tags':        ['rid:' + rid] if rid else [],
        })
    return creds


def parse_kiwi_creds(output: str, host_ip: str = '') -> list[dict]:
    """
    Parse mimikatz/kiwi credential dump output. Looks for blocks containing
    Username + Domain + (Password or NTLM hash).
    """
    if not output:
        return []
    creds = []
    for m in _KIWI_USER_RE.finditer(output):
        username, domain, secret = m.group(1), m.group(2), m.group(3)
        if secret.lower() in ('(null)', '', 'n.a.'):
            continue
        is_hash = bool(_re.match(r'^[a-fA-F0-9]{32}$', secret))
        creds.append({
            'type':        'ntlm_hash' if is_hash else 'password',
            'username':    username,
            'domain':      domain if domain and domain != '(null)' else None,
            'value':       secret,
            'service':     'kerberos' if domain and domain != '(null)' else 'smb',
            'host_ip':     host_ip or None,
            'source_tool': 'kiwi',
            'verified':    False,
        })
    return creds


def parse_shadow_output(output: str, host_ip: str = '') -> list[dict]:
    """
    Parse Linux /etc/shadow content. Returns one cred per user with a
    non-empty hash. The value is the full crypt() hash string — directly
    usable by hashcat with the right mode.
    """
    if not output:
        return []
    creds = []
    for m in _SHADOW_RE.finditer(output):
        username, hash_str = m.group(1), m.group(2)
        creds.append({
            'type':        'unix_hash',
            'username':    username,
            'domain':      None,
            'value':       hash_str,
            'service':     'shadow',
            'host_ip':     host_ip or None,
            'source_tool': 'shadow_dump',
            'verified':    False,
            'tags':        ['hashcat:' + ('1800' if hash_str.startswith('$6$')
                                            else '500'  if hash_str.startswith('$1$')
                                            else '7400' if hash_str.startswith('$5$')
                                            else 'unknown')],
        })
    return creds


def parse_session_output(output: str, host_ip: str = '',
                          source_tool: str = 'session') -> list[dict]:
    """
    Composite parser — try every format. Useful when you don't know what kind
    of dump the operator just pasted in. Returns combined results.
    """
    return (parse_hashdump_output(output, host_ip, source_tool) +
            parse_kiwi_creds(output, host_ip) +
            parse_shadow_output(output, host_ip))