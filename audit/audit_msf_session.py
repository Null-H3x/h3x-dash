#!/usr/bin/env python3
"""Offline audit — MSF session listing robustness + RPC serialization.

Regression-guards the Shell bug "session is in msfrpcd but the browser panel is
empty". Root cause: the shared pymetasploit3 client is not thread-safe, so
concurrent RPC (sessions poll + read poll + health-check + a running console)
corrupted responses, the health-check flipped the link to lost, and
list_sessions() returned []. Fixes verified here (no pymetasploit3 required):
  * connect() wraps client.call so every RPC is serialized (one lock)
  * list_sessions() decodes bytes, skips junk, and retries once before blanking
  * the reconnect health-check tolerates a single transient failure
"""
import sys
import threading

import os as _bd; _bd_root = _bd.path.dirname(_bd.path.dirname(_bd.path.abspath(__file__))); _bd.chdir(_bd_root); sys.path.insert(0, _bd_root)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.msf_engine import MsfEngine


# ── Fake pymetasploit3 client ─────────────────────────────────────────────────
class _FakeSessions:
    def __init__(self, data, raise_times=0):
        self._data = data
        self._raise_times = raise_times
        self.access_count = 0

    @property
    def list(self):
        self.access_count += 1
        if self.access_count <= self._raise_times:
            raise RuntimeError('transient msgpack/transport error')
        return self._data


class _FakeClient:
    def __init__(self, sessions_data, raise_times=0):
        self.sessions = _FakeSessions(sessions_data, raise_times)
        self.call_count = 0

    def call(self, method, opts=None):
        self.call_count += 1
        if method == 'session.list':
            return self.sessions.list
        return {'ok': True}


# ── 1. decode + happy path ────────────────────────────────────────────────────
eng = MsfEngine()
eng._connected = True
# int key + bytes values — the awkward shapes pymetasploit3 can return.
eng._client = _FakeClient({
    1: {b'type': b'shell', b'target_host': b'10.0.0.5', b'username': b'root'},
    2: {'type': 'meterpreter', 'target_host': '10.0.0.6', 'username': 'SYSTEM',
        'tunnel_local': '10.0.0.1:4444'},
})
rows = eng.list_sessions()
ids = {r['id'] for r in rows}
if ids == {'1', '2'}:
    ok('list_sessions returns both sessions with string ids (int+bytes keys)')
else:
    fail(f'list_sessions ids wrong: {ids}')
r1 = next((r for r in rows if r['id'] == '1'), {})
if r1.get('type') == 'shell' and r1.get('target') == '10.0.0.5' and r1.get('user') == 'root':
    ok('bytes-valued session fields are decoded to str')
else:
    fail(f'bytes decode wrong: {r1}')
# newest-first ordering
if [r['id'] for r in rows] == ['2', '1']:
    ok('sessions are sorted newest-id first')
else:
    fail(f'sort order wrong: {[r["id"] for r in rows]}')

# ── 2. junk entries skipped ───────────────────────────────────────────────────
eng._client = _FakeClient({1: {'type': 'shell'}, 2: 'not-a-dict', 3: None})
rows = eng.list_sessions()
if {r['id'] for r in rows} == {'1'}:
    ok('non-dict session info entries are skipped, not fatal')
else:
    fail(f'junk handling wrong: {[r.get("id") for r in rows]}')

# ── 3. retry-once before blanking ─────────────────────────────────────────────
eng._client = _FakeClient({1: {'type': 'shell'}}, raise_times=1)
rows = eng.list_sessions()
if len(rows) == 1:
    ok('list_sessions retries once on a transient error (panel not blanked)')
else:
    fail(f'retry did not recover: {rows}')

# Hard failure (always raises) → returns [] without throwing.
eng._client = _FakeClient({1: {'type': 'shell'}}, raise_times=99)
try:
    rows = eng.list_sessions()
    ok('list_sessions returns [] on a hard RPC failure (never raises)') if rows == [] \
        else fail(f'expected [] on hard failure, got {rows}')
except Exception as exc:
    fail(f'list_sessions raised on hard failure: {exc}')

# ── 4. RPC serialization wrapper ──────────────────────────────────────────────
eng2 = MsfEngine()
fake = _FakeClient({})
eng2._serialize_client_rpc(fake)
if getattr(fake, '_h3x_serialized', False):
    ok('_serialize_client_rpc marks the client wrapped')
else:
    fail('client not marked serialized')

# Calls still work and go through the lock; wrap is idempotent.
fake.call('core.version')
eng2._serialize_client_rpc(fake)     # second call must not double-wrap
fake.call('core.version')
if fake.call_count == 2:
    ok('wrapped client.call still executes; re-wrap is idempotent')
else:
    fail(f'call_count unexpected: {fake.call_count}')

# Concurrency: the lock serializes overlapping calls.
eng3 = MsfEngine()
overlaps = {'max': 0, 'cur': 0}
lock = threading.Lock()


class _ConcurrentClient:
    _h3x_serialized = False
    def call(self, method, opts=None):
        with lock:
            overlaps['cur'] += 1
            overlaps['max'] = max(overlaps['max'], overlaps['cur'])
        import time; time.sleep(0.01)
        with lock:
            overlaps['cur'] -= 1
        return None


cc = _ConcurrentClient()
eng3._serialize_client_rpc(cc)
threads = [threading.Thread(target=lambda: cc.call('x')) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()
if overlaps['max'] == 1:
    ok('serialized client.call never runs concurrently (max overlap = 1)')
else:
    fail(f'RPC calls overlapped (max={overlaps["max"]}) — lock not effective')

# ── 5. source-scan: health-check tolerance + connect() wraps ──────────────────
import pathlib
eng_src = pathlib.Path('modules/msf_engine.py').read_text(encoding='utf-8')
if 'health_fails' in eng_src and 'health_fails >= 2' in eng_src:
    ok('reconnect health-check requires two consecutive failures before lost')
else:
    fail('health-check still flips connection on a single transient failure')
if '_serialize_client_rpc(client)' in eng_src:
    ok('connect() serializes the client RPC on connect')
else:
    fail('connect() does not call _serialize_client_rpc')

# ── 6. int-key session id resolution (listed but "does not exist" bug) ───────
class _IntKeyClient:
    """Simulates Kali apt pymetasploit3: session.list returns int keys."""
    def __init__(self):
        self.call_count = 0

    def call(self, method, args=None):
        self.call_count += 1
        args = args if args is not None else []
        if method == 'session.list':
            return {1: {'type': 'shell', 'target_host': '10.0.0.5',
                        'username': 'root'}}
        if method == 'session.shell_read' and args and args[0] == 1:
            return {'data': 'probe-ok\n'}
        if method == 'session.shell_write':
            return {}
        raise KeyError(f'Session ID ({args[0] if args else "?"}) does not exist')


eng4 = MsfEngine()
eng4._connected = True
eng4._client = _IntKeyClient()
r = eng4.session_read('1')
if r.get('status') == 'ok' and 'probe-ok' in (r.get('output') or ''):
    ok('_sid_param resolves int-keyed msfrpcd sessions (string UI id → live read)')
else:
    fail(f'int-key session read failed (regression): {r}')

# Per-session I/O lock: concurrent read must not overlap with command I/O.
eng5 = MsfEngine()
eng5._connected = True
eng5._client = _IntKeyClient()
lock_a = eng5._sid_io_lock('1')
lock_b = eng5._sid_io_lock('1')
if lock_a is lock_b:
    ok('_sid_io_lock returns the same RLock per session id')
else:
    fail('_sid_io_lock created duplicate locks for the same session')

# ── Summary ────────────────────────────────────────────────────────────────────
print()
print('═' * 72)
print(f' MSF-SESSION AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
