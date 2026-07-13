#!/usr/bin/env python3
"""
H3x-Dash — Adversary Emulation Engine (the purple-team side of the house).

Wraps the *real* detection-validation tooling — Invoke-AtomicRedTeam (Atomic
Red Team) and MITRE CALDERA — to fire benign, ATT&CK-mapped test cases against
a lab host. Every technique that fires is written to a persistent
``DetectionLedger`` (the red-side ground truth). Blue-side detections are then
ingested from a Security Onion export and correlated back to those fired
techniques by ID within a lag window, producing the red-vs-blue reconciliation
that closes the report section.

Design rules
------------
* **No synthetic emission.** If Invoke-AtomicRedTeam isn't importable or CALDERA
  isn't reachable, a run *refuses* rather than faking telemetry. Availability is
  surfaced up front (same discipline as the enum tool chips) so the operator
  knows what's wired before pressing go.
* **Stdlib only.** CALDERA is driven over ``urllib`` — no ``requests`` dep — to
  keep with the framework's self-contained ethos.
* **Testable seams.** Command / request construction lives in pure functions
  (``build_atomic_cmd``, ``build_caldera_op_body``, ``extract_technique``,
  ``correlate``) so the integration is verifiable without the tools installed.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib import request as _urlreq
from urllib import error as _urlerr

try:
    from modules import mitre_mapping
except Exception:                                    # pragma: no cover
    import mitre_mapping                              # type: ignore


# ═══════════════════════════════════════════════════════════════════════════
#  TECHNIQUE CATALOG  (aligned to mitre_mapping.ATTACK_TECHNIQUES so the
#  Coverage matrix lines up 1:1 with what fires here)
# ═══════════════════════════════════════════════════════════════════════════

# technique_id -> ATT&CK tactic bucket (for the tactic-grouped reconcile view)
TACTICS = {
    'T1595.002': 'reconnaissance',
    'T1592':     'reconnaissance',
    'T1190':     'initial-access',
    'T1133':     'initial-access',
    'T1078.002': 'initial-access',
    'T1059.001': 'execution',
    'T1059':     'execution',
    'T1505.003': 'persistence',
    'T1068':     'privilege-escalation',
    'T1557.001': 'credential-access',
    'T1558.003': 'credential-access',
    'T1110.003': 'credential-access',
    'T1003.006': 'credential-access',
    'T1003.001': 'credential-access',
    'T1552.001': 'credential-access',
    'T1212':     'credential-access',
    'T1087.002': 'discovery',
    'T1087.001': 'discovery',
    'T1018':     'discovery',
    'T1135':     'discovery',
    'T1083':     'discovery',
    'T1021.001': 'lateral-movement',
    'T1021.002': 'lateral-movement',
    'T1021.006': 'lateral-movement',
    'T1210':     'lateral-movement',
    'T1499':     'impact',
}

# One representative Atomic test per technique. `num` is the Atomic test index
# passed to Invoke-AtomicTest via -TestNumbers. `hint` describes the artifact a
# detection SHOULD catch — surfaced in the UI so operators know what to tune.
ATOMIC_TESTS = {
    'T1059.001': {'num': 1, 'name': 'PowerShell — download cradle',        'executor': 'powershell', 'hint': 'ScriptBlock logging (4104) / IEX net client'},
    'T1087.002': {'num': 1, 'name': 'Domain account discovery (net user)', 'executor': 'command_prompt', 'hint': 'net.exe /domain, 4661 DS access'},
    'T1087.001': {'num': 1, 'name': 'Local account discovery',            'executor': 'command_prompt', 'hint': 'net user / whoami enumeration'},
    'T1018':     {'num': 1, 'name': 'Remote system discovery (net view)', 'executor': 'command_prompt', 'hint': 'net view / ARP sweep'},
    'T1135':     {'num': 1, 'name': 'Network share discovery',            'executor': 'command_prompt', 'hint': 'net share / SMB tree connect 5140'},
    'T1558.003': {'num': 1, 'name': 'Kerberoast (Rubeus/PowerView)',      'executor': 'powershell', 'hint': 'TGS-REQ RC4 (4769 enc 0x17) spike'},
    'T1003.006': {'num': 1, 'name': 'DCSync (replication)',               'executor': 'powershell', 'hint': 'DRSGetNCChanges / 4662 replicating-directory GUID'},
    'T1003.001': {'num': 1, 'name': 'LSASS memory dump',                  'executor': 'command_prompt', 'hint': 'lsass handle 4656 / comsvcs MiniDump'},
    'T1557.001': {'num': 1, 'name': 'LLMNR/NBT-NS poisoning',             'executor': 'powershell', 'hint': 'UDP 5355/137 responder traffic'},
    'T1110.003': {'num': 1, 'name': 'Password spraying',                  'executor': 'powershell', 'hint': '4625 burst, distinct users, single pw'},
    'T1021.001': {'num': 1, 'name': 'RDP lateral movement',              'executor': 'command_prompt', 'hint': '4624 type 10 / 1149 TS'},
    'T1021.002': {'num': 1, 'name': 'SMB/admin-share exec',              'executor': 'command_prompt', 'hint': '5140 ADMIN$ + 7045 service install'},
    'T1021.006': {'num': 1, 'name': 'WinRM lateral movement',            'executor': 'powershell', 'hint': 'WSMan 5985 / 4688 wsmprovhost'},
    'T1505.003': {'num': 1, 'name': 'Web shell drop',                    'executor': 'command_prompt', 'hint': 'w3wp/httpd child process, file write to webroot'},
    'T1190':     {'num': 1, 'name': 'Exploit public-facing app',         'executor': 'sh', 'hint': 'WAF/IDS sig, anomalous request → shell'},
    'T1068':     {'num': 1, 'name': 'Priv-esc exploitation',            'executor': 'command_prompt', 'hint': 'token manip / 4673 privilege use'},
    'T1552.001': {'num': 1, 'name': 'Credentials in files',            'executor': 'command_prompt', 'hint': 'findstr password / recursive grep'},
    'T1083':     {'num': 1, 'name': 'File and directory discovery',     'executor': 'command_prompt', 'hint': 'dir /s enumeration'},
}

# Named scenario chains. Steps are technique IDs run in order through the
# selected real runner (atomic by default; caldera adversary if mapped).
PLAYBOOKS = [
    {
        'id': 'spectre-ransomware-precursor',
        'name': 'SPECTRE :: Ransomware Precursor',
        'desc': 'Discovery → credential access → lateral staging — the noisy pre-encryption window most EDRs get a shot at.',
        'steps': ['T1087.002', 'T1135', 'T1558.003', 'T1003.006', 'T1021.002', 'T1059.001'],
    },
    {
        'id': 'ad-intrusion-chain',
        'name': 'GHOST :: AD Intrusion Chain',
        'desc': 'Poison → spray → roast → replicate → move. End-to-end domain compromise path.',
        'steps': ['T1557.001', 'T1110.003', 'T1558.003', 'T1003.006', 'T1021.006'],
    },
    {
        'id': 'web-to-foothold',
        'name': 'BREACH :: Web-to-Foothold',
        'desc': 'Exploit a public app, drop a shell, run discovery — the classic external → internal pivot.',
        'steps': ['T1190', 'T1505.003', 'T1059.001', 'T1083'],
    },
]

_PLAYBOOK_BY_ID = {p['id']: p for p in PLAYBOOKS}
_ISO = '%Y-%m-%dT%H:%M:%S%z'


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S+0000')


def _parse_ts(val) -> float | None:
    """Best-effort parse of a timestamp (ISO string or epoch) → epoch seconds."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        # ms epoch?  normalise to seconds
        return float(val) / 1000.0 if val > 1e12 else float(val)
    s = str(val).strip()
    if not s:
        return None
    # try epoch-in-string
    try:
        f = float(s)
        return f / 1000.0 if f > 1e12 else f
    except ValueError:
        pass
    s = s.replace('Z', '+0000')
    for fmt in (_ISO, '%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    # ISO with colon in offset (e.g. +00:00)
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  PURE HELPERS  (testable without any tool installed)
# ═══════════════════════════════════════════════════════════════════════════

_TECH_RX = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.I)


def base_technique(tid: str) -> str:
    """T1003.006 -> T1003 (sub-technique stripped)."""
    return (tid or '').split('.')[0].upper()


def build_atomic_cmd(technique_id: str, test_num: int, atomics_path: str,
                     pwsh: str = 'pwsh', mode: str = 'run',
                     target: str | None = None, input_args: dict | None = None) -> list[str]:
    """Construct the pwsh argv for Invoke-AtomicTest.

    mode: 'run' | 'check' (-CheckPrereqs) | 'cleanup' (-Cleanup).
    Kept pure so tests can assert exact argument shaping.
    """
    ps = [
        "Import-Module Invoke-AtomicRedTeam -ErrorAction Stop;",
        f"$PSDefaultParameterValues=@{{'Invoke-AtomicTest:PathToAtomicsFolder'='{atomics_path}'}};",
    ]
    call = f"Invoke-AtomicTest {technique_id} -TestNumbers {int(test_num)}"
    if mode == 'check':
        call += " -CheckPrereqs"
    elif mode == 'cleanup':
        call += " -Cleanup"
    else:
        call += " -TimeoutSeconds 120"
    if target:
        call += f" -Session (New-PSSession -ComputerName '{target}')"
    if input_args:
        pairs = ';'.join(f"'{k}'='{v}'" for k, v in input_args.items())
        call += f" -InputArgs @{{{pairs}}}"
    ps.append(call + ';')
    return [pwsh, '-NoProfile', '-NonInteractive', '-Command', ' '.join(ps)]


def build_caldera_op_body(name: str, adversary_id: str, group: str = 'red',
                          planner_id: str = 'atomic',
                          source_id: str = 'basic') -> dict:
    """Body for POST /api/v2/operations."""
    return {
        'name': name,
        'adversary': {'adversary_id': adversary_id},
        'planner': {'id': planner_id},
        'source': {'id': source_id},
        'group': group,
        'state': 'running',
        'autonomous': 1,
        'auto_close': True,
    }


# Candidate fields a Security Onion / Elastic export may carry a technique in.
_TECH_FIELDS = (
    'threat.technique.id', 'technique_id', 'mitre_technique', 'mitre.technique',
    'rule.mitre.id', 'signal.rule.threat.technique.id', 'attack.id',
)
_TS_FIELDS = ('@timestamp', 'timestamp', 'event.created', 'time', 'ts')
_RULE_FIELDS = ('rule.name', 'signal.rule.name', 'event.module', 'rule_name',
                'source.rule', 'message')


def _dig(event: dict, dotted: str):
    """Fetch a possibly-dotted / possibly-nested key from an event dict."""
    if dotted in event:
        return event[dotted]
    cur = event
    for part in dotted.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def extract_technique(event: dict, rule_map: dict | None = None) -> str | None:
    """Pull an ATT&CK technique id out of a heterogeneous SIEM event.

    Order: explicit technique fields → regex over rule/message text →
    rule-name lookup in an operator-supplied rule_map. Returns upper-cased id
    (e.g. 'T1558.003') or None.
    """
    for f in _TECH_FIELDS:
        v = _dig(event, f)
        if isinstance(v, list):
            v = v[0] if v else None
        if v and _TECH_RX.fullmatch(str(v).strip()):
            return str(v).strip().upper()
    # regex sweep across rule/message text
    for f in _RULE_FIELDS:
        v = _dig(event, f)
        if v:
            m = _TECH_RX.search(str(v))
            if m:
                return m.group(0).upper()
    # operator-supplied rule → technique map
    if rule_map:
        for f in _RULE_FIELDS:
            v = _dig(event, f)
            if v and str(v) in rule_map:
                return str(rule_map[str(v)]).upper()
    return None


def _extract_ts(event: dict) -> float | None:
    for f in _TS_FIELDS:
        v = _dig(event, f)
        t = _parse_ts(v)
        if t is not None:
            return t
    return None


def _extract_detector(event: dict) -> str:
    for f in _RULE_FIELDS:
        v = _dig(event, f)
        if v:
            return str(v)[:160]
    return 'unnamed detection'


def correlate(fired: list[dict], detections: list[dict],
              window_s: int = 900) -> dict:
    """Match blue-side detections to fired ledger entries by technique + time.

    A detection matches a fired entry when their technique ids agree (exact, or
    base-technique fallback) and the detection timestamp lands within
    [fired_start - 60s, fired_start + window_s]. When the detection carries no
    parseable timestamp, technique agreement alone is accepted (time-agnostic).

    Returns {matches: {ledger_id: {detected_by, detection_ts, latency_s}},
             unmatched_detections: [...]}  (pure — mutates nothing).
    """
    # index fired entries by exact + base technique
    by_exact: dict[str, list[dict]] = {}
    by_base: dict[str, list[dict]] = {}
    for e in fired:
        tid = (e.get('technique_id') or '').upper()
        if not tid:
            continue
        by_exact.setdefault(tid, []).append(e)
        by_base.setdefault(base_technique(tid), []).append(e)

    matches: dict[str, dict] = {}
    unmatched: list[dict] = []
    for d in detections:
        tid = (d.get('technique_id') or '').upper()
        dts = d.get('_ts')
        cands = by_exact.get(tid) or by_base.get(base_technique(tid)) or []
        hit = None
        for c in cands:
            fstart = _parse_ts(c.get('started') or c.get('timestamp'))
            if dts is None or fstart is None:
                hit = c
                break
            if (fstart - 60) <= dts <= (fstart + window_s):
                hit = c
                break
        if hit is not None:
            lid = hit.get('id')
            fstart = _parse_ts(hit.get('started') or hit.get('timestamp'))
            latency = (dts - fstart) if (dts is not None and fstart is not None) else None
            # keep the earliest / lowest-latency match per ledger entry
            prev = matches.get(lid)
            if prev is None or (latency is not None and (prev.get('latency_s') is None or latency < prev['latency_s'])):
                matches[lid] = {
                    'detected_by': d.get('detected_by', 'Security Onion'),
                    'detection_ts': dts,
                    'latency_s': latency,
                }
        else:
            unmatched.append({'technique_id': tid, 'detected_by': d.get('detected_by')})
    return {'matches': matches, 'unmatched_detections': unmatched}


# ═══════════════════════════════════════════════════════════════════════════
#  DETECTION LEDGER  (JSON-backed, mirrors CredentialStore)
# ═══════════════════════════════════════════════════════════════════════════

class DetectionLedger:
    """Persistent record of every technique fired + its blue-side verdict."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        self._ingest_meta: dict = {'last_ingest': None, 'events': 0, 'unmatched': 0}
        self._load()

    def _load(self):
        try:
            if self.path.is_file():
                data = json.loads(self.path.read_text())
                self._entries = data.get('entries', [])
                self._ingest_meta = data.get('ingest_meta', self._ingest_meta)
        except Exception:
            self._entries = []

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(
                {'entries': self._entries, 'ingest_meta': self._ingest_meta}, indent=2))
            tmp.replace(self.path)
        except Exception:
            pass

    def add(self, entry: dict) -> dict:
        with self._lock:
            entry.setdefault('id', 'em_' + uuid.uuid4().hex[:12])
            entry.setdefault('fired', True)
            entry.setdefault('detected', None)
            entry.setdefault('detected_by', None)
            entry.setdefault('detection_ts', None)
            entry.setdefault('timestamp', _now_iso())
            self._entries.append(entry)
            self._save()
            return entry

    def list(self, source: str | None = None, technique: str | None = None) -> list[dict]:
        with self._lock:
            out = list(self._entries)
        if source:
            out = [e for e in out if e.get('source') == source]
        if technique:
            t = technique.upper()
            out = [e for e in out if (e.get('technique_id') or '').upper() == t]
        return out

    def apply_correlation(self, corr: dict) -> int:
        """Stamp detected=True on ledger entries matched by correlate()."""
        matches = corr.get('matches', {})
        n = 0
        with self._lock:
            for e in self._entries:
                m = matches.get(e.get('id'))
                if m:
                    e['detected'] = True
                    e['detected_by'] = m['detected_by']
                    e['detection_ts'] = m['detection_ts']
                    e['latency_s'] = m.get('latency_s')
                    n += 1
                elif e.get('detected') is None:
                    # a firing that this ingest didn't catch stays "not yet seen"
                    pass
            self._ingest_meta = {
                'last_ingest': _now_iso(),
                'events': self._ingest_meta.get('events', 0),
                'unmatched': len(corr.get('unmatched_detections', [])),
            }
            self._save()
        return n

    def mark_undetected_fired(self):
        """After an ingest pass, any still-null firing is a confirmed miss."""
        with self._lock:
            for e in self._entries:
                if e.get('detected') is None:
                    e['detected'] = False
            self._save()

    def note_ingest(self, event_count: int):
        with self._lock:
            self._ingest_meta['events'] = self._ingest_meta.get('events', 0) + event_count
            self._save()

    def stats(self) -> dict:
        with self._lock:
            entries = list(self._entries)
            meta = dict(self._ingest_meta)
        techs = {e.get('technique_id') for e in entries if e.get('technique_id')}
        det = {e.get('technique_id') for e in entries if e.get('detected') is True}
        return {
            'fired_events': len(entries),
            'fired_techniques': len(techs),
            'detected_techniques': len(det),
            'blind_spots': len(techs - det),
            'last_ingest': meta.get('last_ingest'),
            'ingest_events': meta.get('events', 0),
        }

    def clear(self):
        with self._lock:
            self._entries = []
            self._ingest_meta = {'last_ingest': None, 'events': 0, 'unmatched': 0}
            self._save()


# ═══════════════════════════════════════════════════════════════════════════
#  EMULATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class EmulationEngine:
    def __init__(self, ledger: DetectionLedger, config):
        self.ledger = ledger
        self.cfg = config
        self._running = False
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ── availability ────────────────────────────────────────────────────────
    def tool_status(self) -> dict:
        pwsh = shutil.which(getattr(self.cfg, 'PWSH_BIN', 'pwsh'))
        atomics = Path(getattr(self.cfg, 'ATOMICS_PATH', ''))
        atomic_ok = bool(pwsh) and atomics.is_dir()
        atomic_detail = (
            'ready' if atomic_ok else
            ('pwsh not found on PATH' if not pwsh else f'atomics folder missing: {atomics}')
        )
        cal_url = getattr(self.cfg, 'CALDERA_URL', '')
        cal_key = getattr(self.cfg, 'CALDERA_API_KEY', '')
        cal_ok, cal_detail = self._caldera_ping(cal_url, cal_key)
        return {
            'atomic': {'available': atomic_ok, 'detail': atomic_detail,
                       'pwsh': pwsh or None, 'atomics_path': str(atomics)},
            'caldera': {'available': cal_ok, 'detail': cal_detail, 'url': cal_url,
                        'has_key': bool(cal_key)},
        }

    def running(self) -> bool:
        return self._running

    # ── catalog ─────────────────────────────────────────────────────────────
    def catalog(self, source: str) -> dict:
        if source == 'playbook':
            return {'playbooks': [
                {**p, 'labels': [mitre_mapping.technique_label(t) for t in p['steps']]}
                for p in PLAYBOOKS]}
        if source == 'caldera':
            return {'adversaries': self._caldera_adversaries()}
        # atomic (default)
        tests = []
        for tid, spec in ATOMIC_TESTS.items():
            tests.append({
                'technique_id': tid,
                'label': mitre_mapping.technique_label(tid),
                'tactic': TACTICS.get(tid, 'unknown'),
                'test_name': spec['name'],
                'test_num': spec['num'],
                'executor': spec['executor'],
                'detection_hint': spec['hint'],
            })
        tests.sort(key=lambda t: (t['tactic'], t['technique_id']))
        return {'atomics': tests}

    # ── run orchestration ───────────────────────────────────────────────────
    def start_run(self, spec: dict, on_output, on_fired, on_complete) -> tuple[bool, str]:
        with self._lock:
            if self._running:
                return False, 'An emulation run is already in progress'
            self._running = True
            self._stop.clear()

        t = threading.Thread(target=self._run, args=(spec, on_output, on_fired, on_complete), daemon=True)
        t.start()
        return True, 'started'

    def stop(self):
        self._stop.set()

    def _finish(self, on_complete, fired_count, errors):
        self._running = False
        try:
            on_complete({'fired_count': fired_count, 'errors': errors})
        except Exception:
            pass

    def _run(self, spec, on_output, on_fired, on_complete):
        source = spec.get('source', 'atomic')
        host = spec.get('host') or 'localhost'
        fired = 0
        errors = []
        try:
            if source == 'atomic':
                techs = spec.get('techniques') or list(ATOMIC_TESTS.keys())
                fired, errors = self._run_atomic_set(techs, host, 'atomic', None, on_output, on_fired)
            elif source == 'playbook':
                pb = _PLAYBOOK_BY_ID.get(spec.get('scenario'))
                if not pb:
                    on_output(f"[!] Unknown playbook: {spec.get('scenario')}")
                    errors.append('unknown playbook')
                else:
                    on_output(f"[*] Playbook :: {pb['name']}")
                    fired, errors = self._run_atomic_set(pb['steps'], host, 'playbook', pb['id'], on_output, on_fired)
            elif source == 'caldera':
                fired, errors = self._run_caldera(spec, host, on_output, on_fired)
            else:
                errors.append(f'unknown source {source}')
                on_output(f"[!] Unknown emulation source: {source}")
        except Exception as exc:                             # pragma: no cover
            errors.append(str(exc))
            on_output(f"[!] Emulation aborted: {exc}")
        finally:
            self._finish(on_complete, fired, errors)

    # ── Atomic Red Team runner (real) ───────────────────────────────────────
    def _run_atomic_set(self, techniques, host, source, scenario, on_output, on_fired):
        st = self.tool_status()['atomic']
        if not st['available']:
            on_output(f"[!] Atomic Red Team unavailable — {st['detail']}. Refusing to fake it.")
            return 0, ['atomic unavailable: ' + st['detail']]

        atomics_path = st['atomics_path']
        pwsh = st['pwsh']
        fired = 0
        errors = []
        for tid in techniques:
            if self._stop.is_set():
                on_output('[*] Stop requested — halting run.')
                break
            spec = ATOMIC_TESTS.get(tid)
            if not spec:
                on_output(f"[~] No atomic mapped for {tid} — skipping.")
                continue
            label = mitre_mapping.technique_label(tid)
            on_output(f"[►] {tid} · {label} — {spec['name']}")
            started = _now_iso()
            cmd = build_atomic_cmd(tid, spec['num'], atomics_path, pwsh,
                                   mode='run', target=(host if host not in ('localhost', '127.0.0.1') else None))
            rc, tail = self._stream_proc(cmd, on_output)
            status = 'ran' if rc == 0 else 'error'
            if rc != 0:
                errors.append(f'{tid} rc={rc}')
            entry = self.ledger.add({
                'technique_id': tid, 'technique_name': label,
                'tactic': TACTICS.get(tid, 'unknown'),
                'source': source, 'scenario': scenario, 'host': host,
                'executor': spec['executor'], 'test_num': spec['num'],
                'detection_hint': spec['hint'],
                'started': started, 'finished': _now_iso(),
                'status': status, 'return_code': rc,
            })
            fired += 1
            try:
                on_fired(entry)
            except Exception:
                pass
            on_output(f"[✓] {tid} fired ({status}) → ledger {entry['id']}")
        return fired, errors

    def _stream_proc(self, cmd, on_output):
        """Run a subprocess, stream stdout line-by-line, return (rc, tail)."""
        tail = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
        except FileNotFoundError:
            on_output(f"[!] Executable not found: {cmd[0]}")
            return 127, tail
        try:
            for line in iter(proc.stdout.readline, ''):
                if self._stop.is_set():
                    proc.terminate()
                    break
                line = line.rstrip('\n')
                if line.strip():
                    on_output('    ' + line)
                    tail.append(line)
                    if len(tail) > 40:
                        tail.pop(0)
            proc.stdout.close()
        finally:
            rc = proc.wait()
        return rc, tail

    # ── CALDERA runner (real, over urllib) ──────────────────────────────────
    def _caldera_headers(self, key):
        h = {'Content-Type': 'application/json'}
        if key:
            h['KEY'] = key
        return h

    def _caldera_ping(self, url, key):
        if not url:
            return False, 'no CALDERA_URL configured'
        if not key:
            return False, 'no CALDERA_API_KEY configured'
        try:
            req = _urlreq.Request(url.rstrip('/') + '/api/v2/health',
                                  headers=self._caldera_headers(key))
            with _urlreq.urlopen(req, timeout=4) as r:
                return (r.status == 200), ('reachable' if r.status == 200 else f'HTTP {r.status}')
        except _urlerr.HTTPError as e:
            # health may 404 on older builds; try agents as a liveness probe
            if e.code in (401, 403):
                return False, 'auth rejected (check API key)'
            return self._caldera_probe_agents(url, key)
        except Exception as e:
            return False, f'unreachable: {e.__class__.__name__}'

    def _caldera_probe_agents(self, url, key):
        try:
            req = _urlreq.Request(url.rstrip('/') + '/api/v2/agents',
                                  headers=self._caldera_headers(key))
            with _urlreq.urlopen(req, timeout=4) as r:
                return (r.status == 200), ('reachable' if r.status == 200 else f'HTTP {r.status}')
        except Exception as e:
            return False, f'unreachable: {e.__class__.__name__}'

    def _caldera_adversaries(self):
        st = self.tool_status()['caldera'] if False else None  # avoid recursion
        url = getattr(self.cfg, 'CALDERA_URL', '')
        key = getattr(self.cfg, 'CALDERA_API_KEY', '')
        if not (url and key):
            return []
        try:
            req = _urlreq.Request(url.rstrip('/') + '/api/v2/adversaries',
                                  headers=self._caldera_headers(key))
            with _urlreq.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode() or '[]')
            return [{'adversary_id': a.get('adversary_id'), 'name': a.get('name'),
                     'atomic_ordering': len(a.get('atomic_ordering', []))} for a in data]
        except Exception:
            return []

    def _run_caldera(self, spec, host, on_output, on_fired):
        url = getattr(self.cfg, 'CALDERA_URL', '').rstrip('/')
        key = getattr(self.cfg, 'CALDERA_API_KEY', '')
        ok, detail = self._caldera_ping(url, key)
        if not ok:
            on_output(f"[!] CALDERA unavailable — {detail}. Refusing to fake it.")
            return 0, ['caldera unavailable: ' + detail]

        adversary = spec.get('adversary_id')
        if not adversary:
            on_output('[!] No adversary_id selected for CALDERA operation.')
            return 0, ['no adversary_id']

        op_name = spec.get('op_name') or f"h3x-{uuid.uuid4().hex[:6]}"
        body = build_caldera_op_body(op_name, adversary,
                                     planner_id=spec.get('planner', 'atomic'),
                                     source_id=spec.get('source_id', 'basic'))
        on_output(f"[*] Launching CALDERA operation '{op_name}' (adversary {adversary})")
        try:
            data = json.dumps(body).encode()
            req = _urlreq.Request(url + '/api/v2/operations', data=data,
                                  headers=self._caldera_headers(key), method='POST')
            with _urlreq.urlopen(req, timeout=10) as r:
                op = json.loads(r.read().decode() or '{}')
            op_id = op.get('id')
        except Exception as e:
            on_output(f"[!] Failed to start operation: {e}")
            return 0, [f'op start failed: {e}']

        fired = 0
        errors = []
        seen = set()
        deadline = time.time() + int(spec.get('max_wait', 300))
        while time.time() < deadline and not self._stop.is_set():
            time.sleep(5)
            try:
                req = _urlreq.Request(url + f'/api/v2/operations/{op_id}/links',
                                      headers=self._caldera_headers(key))
                with _urlreq.urlopen(req, timeout=8) as r:
                    links = json.loads(r.read().decode() or '[]')
            except Exception as e:
                on_output(f"[~] Poll error: {e}")
                continue
            done = 0
            for link in links:
                lid = link.get('id') or link.get('unique')
                status = link.get('status')
                if status in (0, '0', 'success', 'done') or link.get('finish'):
                    done += 1
                if lid in seen or status in (None, -3, '-3'):    # -3 = queued
                    continue
                ability = link.get('ability', {}) or {}
                tid = ability.get('technique_id') or ability.get('tactic')
                if not tid:
                    continue
                seen.add(lid)
                label = ability.get('technique_name') or mitre_mapping.technique_label(tid)
                entry = self.ledger.add({
                    'technique_id': tid, 'technique_name': label,
                    'tactic': (ability.get('tactic') or TACTICS.get(tid, 'unknown')),
                    'source': 'caldera', 'scenario': op_name, 'host': host,
                    'ability': ability.get('name'), 'link_id': lid,
                    'started': _now_iso(), 'finished': _now_iso(),
                    'status': 'ran', 'return_code': 0,
                })
                fired += 1
                on_output(f"[✓] CALDERA {tid} · {label} → ledger {entry['id']}")
                try:
                    on_fired(entry)
                except Exception:
                    pass
            if links and done >= len(links):
                on_output('[*] Operation complete.')
                break
        return fired, errors

    # ── SIEM ingest + reconcile ─────────────────────────────────────────────
    def ingest_siem(self, payload) -> dict:
        """Ingest a Security Onion export, correlate, stamp the ledger."""
        rule_map = None
        events = payload
        if isinstance(payload, dict):
            rule_map = payload.get('rule_map')
            events = (payload.get('detections') or payload.get('events')
                      or payload.get('hits') or payload.get('results') or [])
        if not isinstance(events, list):
            return {'status': 'error', 'message': 'expected a list of detection events'}

        detections = []
        parsed = 0
        for ev in events:
            if not isinstance(ev, dict):
                continue
            tid = extract_technique(ev, rule_map)
            if not tid:
                continue
            detections.append({
                'technique_id': tid,
                '_ts': _extract_ts(ev),
                'detected_by': _extract_detector(ev),
            })
            parsed += 1

        fired = self.ledger.list()
        window = int(getattr(self.cfg, 'RECONCILE_WINDOW_S', 900))
        corr = correlate(fired, detections, window_s=window)
        self.ledger.note_ingest(len(events))
        matched = self.ledger.apply_correlation(corr)
        # everything that fired but wasn't matched this pass = confirmed miss
        self.ledger.mark_undetected_fired()
        return {
            'status': 'ok',
            'events_received': len(events),
            'detections_parsed': parsed,
            'ledger_entries_matched': matched,
            'unmatched_detections': len(corr['unmatched_detections']),
        }

    def reconcile(self) -> dict:
        """The red-vs-blue roll-up that closes the report section."""
        entries = self.ledger.list()
        # group by technique
        by_tech: dict[str, list[dict]] = {}
        for e in entries:
            tid = (e.get('technique_id') or '').upper()
            if tid:
                by_tech.setdefault(tid, []).append(e)

        techniques = []
        for tid, es in by_tech.items():
            fired_n = len(es)
            det = [e for e in es if e.get('detected') is True]
            miss = [e for e in es if e.get('detected') is False]
            pending = [e for e in es if e.get('detected') is None]
            if det and not miss and not pending:
                status = 'DETECTED'
            elif det:
                status = 'PARTIAL'
            elif pending and not det:
                status = 'PENDING'
            else:
                status = 'BLIND SPOT'
            lat = [e.get('latency_s') for e in det if e.get('latency_s') is not None]
            techniques.append({
                'technique_id': tid,
                'label': mitre_mapping.technique_label(tid),
                'tactic': TACTICS.get(tid, es[0].get('tactic', 'unknown')),
                'fired': fired_n,
                'detected': len(det),
                'status': status,
                'detected_by': (det[0].get('detected_by') if det else None),
                'mean_latency_s': (round(sum(lat) / len(lat), 1) if lat else None),
                'hint': es[0].get('detection_hint'),
                'sources': sorted({e.get('source') for e in es if e.get('source')}),
            })

        order = {'BLIND SPOT': 0, 'PENDING': 1, 'PARTIAL': 2, 'DETECTED': 3}
        techniques.sort(key=lambda t: (order.get(t['status'], 9), t['tactic'], t['technique_id']))

        fired_tech = len(by_tech)
        detected_tech = sum(1 for t in techniques if t['status'] in ('DETECTED', 'PARTIAL'))
        blind = sum(1 for t in techniques if t['status'] == 'BLIND SPOT')
        catalog_n = len(ATOMIC_TESTS)
        st = self.ledger.stats()

        # tactic-grouped matrix
        matrix: dict[str, list[dict]] = {}
        for t in techniques:
            matrix.setdefault(t['tactic'], []).append(t)

        return {
            'techniques': techniques,
            'matrix': matrix,
            'summary': {
                'fired_techniques': fired_tech,
                'fired_events': st['fired_events'],
                'detected_techniques': detected_tech,
                'blind_spots': blind,
                'detection_rate': round(detected_tech / fired_tech, 3) if fired_tech else 0.0,
                'emulated_pct': round(fired_tech / catalog_n, 3) if catalog_n else 0.0,
                'catalog_techniques': catalog_n,
                'last_ingest': st['last_ingest'],
                'ingest_events': st['ingest_events'],
            },
        }
