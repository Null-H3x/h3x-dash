"""
ops_log.py — Persistent operational logs for chain-to-shell debugging.

Writes timestamped artifacts under logs/ (gitignored):
  logs/exploit/       — every MSF module run (wrapper + console + metadata)
  logs/sessions/      — shell/Meterpreter commands (JSONL per session)
  logs/enumeration/   — enum job transcripts + findings summary
  logs/scans/         — scan job transcripts (nmap/web output; XML stays in scans/)
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import H3xConfig

_SENSITIVE_KEYS = frozenset({
    'PASSWORD', 'PASS', 'SMBPASS', 'BINDPASS', 'FTPPASS', 'SSH_PASS',
    'HttpPassword', 'PASSWORD_HASH',
})


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')


def _slug(text: str, max_len: int = 48) -> str:
    s = re.sub(r'[^a-zA-Z0-9._-]+', '_', (text or 'unknown').strip())
    return (s[:max_len] or 'unknown').strip('_')


def _sanitize_mapping(data: dict | None) -> dict:
    if not data:
        return {}
    out = {}
    for k, v in data.items():
        key = str(k)
        if any(s in key.upper() for s in _SENSITIVE_KEYS):
            out[key] = '********'
        else:
            out[key] = v
    return out


class OpsLogger:
    """Thread-safe filesystem logger for operator troubleshooting."""

    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or (H3xConfig.BASE_DIR / 'logs')
        self._lock = threading.Lock()
        self._enum_jobs: dict[str, Path] = {}
        self._scan_jobs: dict[str, Path] = {}

    def ensure_dirs(self) -> None:
        for name in ('exploit', 'sessions', 'enumeration', 'scans'):
            (self.base_dir / name).mkdir(parents=True, exist_ok=True)

    def _write_json(self, path: Path, payload: dict) -> Path | None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, default=str) + '\n',
                            encoding='utf-8')
            return path
        except OSError:
            return None

    def _append_line(self, path: Path, line: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a', encoding='utf-8') as fh:
                fh.write(line.rstrip('\n') + '\n')
        except OSError:
            pass

    def _append_jsonl(self, path: Path, record: dict) -> None:
        record = dict(record)
        record.setdefault('ts', datetime.now(timezone.utc).isoformat())
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps(record, default=str) + '\n')
        except OSError:
            pass

    # ── Exploit / MSF module runs ─────────────────────────────────────────────

    def log_exploit_run(self, *, module: str, options: dict, payload: str | None,
                        target: int | None, action: str, auto_migrate: bool | None,
                        poll_timeout: int, result: dict) -> Path | None:
        """Persist one run_exploit() outcome (run, check, or error)."""
        with self._lock:
            self.ensure_dirs()
            mod_slug = _slug((module or 'module').replace('/', '_'))
            rhost = _slug(str((options or {}).get('RHOSTS', 'unknown')).split(',')[0])
            fname = f'{_utc_stamp()}_{action}_{mod_slug}_{rhost}'
            out_dir = self.base_dir / 'exploit'

            meta = {
                'ts': datetime.now(timezone.utc).isoformat(),
                'module': module,
                'action': action,
                'payload': payload,
                'target_index': target,
                'auto_migrate': auto_migrate,
                'poll_timeout': poll_timeout,
                'options': _sanitize_mapping(options),
                'status': result.get('status'),
                'session_opened': result.get('session_opened'),
                'exploit_failed': result.get('exploit_failed'),
                'check_vulnerable': result.get('check_vulnerable'),
                'check_safe': result.get('check_safe'),
                'sessions': result.get('sessions'),
                'missing_required': result.get('missing_required'),
                'message': result.get('message'),
            }
            json_path = self._write_json(out_dir / f'{fname}.json', meta)

            lines = [result.get('result') or '', '', '═══ MSF CONSOLE OUTPUT ═══',
                     result.get('console_output') or '']
            try:
                (out_dir / f'{fname}.txt').write_text('\n'.join(lines).strip() + '\n',
                                                      encoding='utf-8')
            except OSError:
                pass
            return json_path

    # ── Shell / Meterpreter session events ────────────────────────────────────

    def log_session_event(self, session_id: str, event: str, *,
                          command: str | None = None,
                          result: dict | None = None) -> None:
        """Append one session interaction to logs/sessions/session_<id>.jsonl."""
        sid = str(session_id).strip()
        if not sid:
            return
        with self._lock:
            self.ensure_dirs()
            path = self.base_dir / 'sessions' / f'session_{sid}.jsonl'
            record: dict[str, Any] = {
                'event': event,
                'session_id': sid,
            }
            if command is not None:
                record['command'] = command
            if result:
                record['status'] = result.get('status')
                record['session_dead'] = result.get('session_dead')
                record['session_type'] = result.get('session_type')
                if result.get('message'):
                    record['message'] = result.get('message')
                out = result.get('output') or ''
                if out:
                    record['output'] = out[:8192]
                    if len(out) > 8192:
                        record['output_truncated'] = True
            self._append_jsonl(path, record)

    # ── Enumeration jobs ──────────────────────────────────────────────────────

    def begin_enum_job(self, client_id: str, hosts: list, params: dict) -> Path | None:
        ips = '_'.join(_slug(h.get('ip', '')) for h in (hosts or [])[:3])
        if len(hosts or []) > 3:
            ips += f'_plus{len(hosts) - 3}'
        path = self.base_dir / 'enumeration' / f'{_utc_stamp()}_{ips or "hosts"}.log'
        with self._lock:
            self.ensure_dirs()
            self._enum_jobs[str(client_id)] = path
            meta = {
                'ts': datetime.now(timezone.utc).isoformat(),
                'client_id': client_id,
                'hosts': [h.get('ip') for h in (hosts or [])],
                'params': _sanitize_mapping(params),
            }
            self._write_json(path.with_suffix('.json'), meta)
            self._append_line(path, f'[{meta["ts"]}] Enumeration started — '
                              f'{len(hosts or [])} host(s)')
        return path

    def append_enum_line(self, client_id: str, line: str) -> None:
        with self._lock:
            path = self._enum_jobs.get(str(client_id))
        if path and line:
            self._append_line(path, line)

    def finish_enum_job(self, client_id: str, findings: dict) -> None:
        with self._lock:
            path = self._enum_jobs.pop(str(client_id), None)
        if not path:
            return
        total = sum(len(v) for v in (findings or {}).values())
        self._append_line(path, f'[{datetime.now(timezone.utc).isoformat()}] '
                          f'Enumeration complete — {total} finding(s)')
        summary = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'finding_count': total,
            'findings_by_host': {
                ip: len(lst) for ip, lst in (findings or {}).items()
            },
        }
        self._write_json(path.with_suffix('.summary.json'), summary)

    # ── Scan jobs (transcript only — XML artifacts stay in scans/) ────────────

    def begin_scan_job(self, client_id: str, target: str, params: dict) -> Path | None:
        path = (self.base_dir / 'scans'
                / f'{_utc_stamp()}_{_slug(target)}.log')
        with self._lock:
            self.ensure_dirs()
            self._scan_jobs[str(client_id)] = path
            meta = {
                'ts': datetime.now(timezone.utc).isoformat(),
                'client_id': client_id,
                'target': target,
                'params': _sanitize_mapping(params),
            }
            self._write_json(path.with_suffix('.json'), meta)
            self._append_line(path, f'[{meta["ts"]}] Scan started — target {target}')
        return path

    def append_scan_line(self, client_id: str, line: str) -> None:
        with self._lock:
            path = self._scan_jobs.get(str(client_id))
        if path and line:
            self._append_line(path, line)

    def finish_scan_job(self, client_id: str, *, host_count: int = 0,
                        status: str = 'complete') -> None:
        with self._lock:
            path = self._scan_jobs.pop(str(client_id), None)
        if not path:
            return
        self._append_line(path,
                          f'[{datetime.now(timezone.utc).isoformat()}] '
                          f'Scan {status} — {host_count} host(s)')

    # ── Query / UI helpers ────────────────────────────────────────────────────

    def list_exploit_logs(self, rhost: str | None = None,
                          limit: int = 10) -> list[dict]:
        """Recent exploit runs, newest first. Optional filter by RHOSTS slug."""
        self.ensure_dirs()
        out_dir = self.base_dir / 'exploit'
        if not out_dir.is_dir():
            return []
        rslug = _slug(str(rhost).split(',')[0]) if rhost else None
        entries: list[dict] = []
        for jp in sorted(out_dir.glob('*.json'), reverse=True):
            try:
                data = json.loads(jp.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                continue
            opts = data.get('options') or {}
            rh = str(opts.get('RHOSTS', '')).split(',')[0].strip()
            if rslug and _slug(rh) != rslug:
                continue
            txt = jp.with_suffix('.txt')
            entries.append({
                'file':      jp.name,
                'ts':        data.get('ts', ''),
                'module':    data.get('module', ''),
                'action':    data.get('action', ''),
                'payload':   data.get('payload'),
                'rhost':     rh,
                'status':    data.get('status'),
                'session_opened': data.get('session_opened'),
                'exploit_failed': data.get('exploit_failed'),
                'has_txt':   txt.is_file(),
            })
            if len(entries) >= max(1, min(limit, 50)):
                break
        return entries

    def read_exploit_artifact(self, filename: str) -> dict | None:
        """Load one exploit log by basename (no path traversal)."""
        name = Path(filename).name
        if not name.endswith('.json') and not name.endswith('.txt'):
            return None
        path = (self.base_dir / 'exploit' / name).resolve()
        root = (self.base_dir / 'exploit').resolve()
        if not str(path).startswith(str(root)) or not path.is_file():
            return None
        if name.endswith('.json'):
            try:
                return {'type': 'json', 'name': name,
                        'data': json.loads(path.read_text(encoding='utf-8'))}
            except (OSError, json.JSONDecodeError):
                return None
        try:
            return {'type': 'txt', 'name': name,
                    'text': path.read_text(encoding='utf-8')[-32000:]}
        except OSError:
            return None


ops_log = OpsLogger()
