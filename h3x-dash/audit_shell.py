#!/usr/bin/env python3
"""
audit_shell.py — Verify the Shell page's session-interaction backend.

Mocks the pymetasploit3 client so this runs offline. Exercises:
  - session_read non-blocking buffer pull
  - session_write raw data send
  - session_meterpreter_run uses run_with_output when available
  - session_run dispatches correctly by session type
  - hashdump output parser → cred dicts
  - shadow file parser → cred dicts
  - kiwi output parser → cred dicts
  - capture_creds API: hashdump output flows to cred_store
"""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, '.')

from modules.credentials import (CredentialStore,
                                  parse_hashdump_output,
                                  parse_kiwi_creds,
                                  parse_shadow_output,
                                  parse_session_output)

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


# ── Mock pymetasploit3 client ────────────────────────────────────────────────

class MockSession:
    """Stand-in for client.sessions.session(sid) — behaves like a shell or meter."""
    def __init__(self, sid, stype='shell', canned_output='', run_output=''):
        self.sid           = sid
        self.stype         = stype
        self.written       = []
        self.canned_output = canned_output   # what read() returns once
        self.run_output    = run_output      # what run_with_output returns
        self._read_count   = 0

    def write(self, data):
        self.written.append(data)

    def read(self):
        # First call returns canned, subsequent return empty (simulates buffer drain)
        if self._read_count == 0:
            self._read_count += 1
            return self.canned_output
        return ''

    def run_with_output(self, cmd, timeout=15):
        return self.run_output


class MockSessions:
    def __init__(self, sessions: dict):
        self._sessions = sessions
        self.list = {sid: {'type': s.stype, 'target_host': '10.0.0.5',
                            'username': 'tester', 'platform': 'linux',
                            'arch': 'x64', 'info': 'mock', 'tunnel_local': ''}
                      for sid, s in sessions.items()}

    def session(self, sid):
        return self._sessions[str(sid)]


class MockClient:
    def __init__(self, sessions):
        self.sessions = MockSessions(sessions)


# Build a MsfEngine that uses the mock client
import threading
from modules import msf_engine as msfe

class MockMsfEngine(msfe.MsfEngine):
    """MsfEngine with _client_ref pointing at a fixed mock."""
    def __init__(self, mock_client):
        # Skip parent __init__ — we don't need RPC daemon setup for the audit
        self._mock_client = mock_client
        self._connected = True
        self._lock = threading.RLock()
    def _client_ref(self):
        return self._mock_client
    def is_connected(self):
        return True


# ── Tests: parsers ────────────────────────────────────────────────────────────

# 1. hashdump parser
HASHDUMP_RAW = """
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e1487a9ccb9b3e3a3e1a8ed85d54bcbe:::
[junk line]
"""
creds = parse_hashdump_output(HASHDUMP_RAW, host_ip='10.0.0.5')
if (len(creds) == 3
    and creds[0]['username'] == 'Administrator'
    and creds[0]['type']     == 'ntlm_hash'
    and ':31d6cfe0d16ae931b73c59d7e0c089c0' in creds[0]['value']
    and creds[0]['host_ip']  == '10.0.0.5'
    and creds[0]['host_port'] == 445):
    ok(f"hashdump parser extracts {len(creds)} NTLM hashes from canonical output")
else:
    fail(f"hashdump parser wrong: {creds}")

# 2. hashdump parser ignores garbage
creds = parse_hashdump_output("nothing useful here\nsome line", host_ip='1.1.1.1')
if len(creds) == 0:
    ok("hashdump parser returns empty list on garbage input")
else:
    fail(f"hashdump parser greedy: {creds}")

# 3. shadow parser
SHADOW_RAW = """
root:$6$abc$xyzhash1:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
www-data:$1$salt$hash2:19000:0:99999:7:::
nobody:!:19000:0:99999:7:::
"""
creds = parse_shadow_output(SHADOW_RAW, host_ip='10.0.0.6')
if (len(creds) == 2     # daemon/* and nobody/! are non-hashes, skipped
    and creds[0]['username'] == 'root'
    and creds[0]['type']     == 'unix_hash'
    and creds[0]['value'].startswith('$6$')
    and 'hashcat:1800' in creds[0]['tags']):     # $6$ → SHA-512crypt
    ok(f"shadow parser extracts {len(creds)} valid hashes + tags hashcat mode")
else:
    fail(f"shadow parser wrong: {creds}")

# 4. composite parser
combined_raw = HASHDUMP_RAW + '\n' + SHADOW_RAW
creds = parse_session_output(combined_raw, host_ip='10.0.0.7')
if len(creds) == 5:     # 3 NTLM + 2 unix
    ok(f"composite parser handles mixed output ({len(creds)} creds)")
else:
    fail(f"composite parser wrong count: {len(creds)}")


# ── Tests: session API ───────────────────────────────────────────────────────

# 5. session_read non-blocking
mock_session = MockSession('1', stype='shell',
                            canned_output='hello from shell\n')
client = MockClient({'1': mock_session})
engine = MockMsfEngine(client)
result = engine.session_read('1')
if result['status'] == 'ok' and 'hello from shell' in result['output']:
    ok("session_read returns buffer non-blocking")
else:
    fail(f"session_read wrong: {result}")

# 6. session_read on subsequent call returns empty (buffer drained)
result2 = engine.session_read('1')
if result2['status'] == 'ok' and result2['output'] == '':
    ok("session_read second call returns empty (buffer drained, no blocking)")
else:
    fail(f"session_read second call: {result2}")

# 7. session_write
result = engine.session_write('1', 'ls\n')
if result['status'] == 'ok' and 'ls\n' in mock_session.written:
    ok("session_write delivers raw data to the session")
else:
    fail(f"session_write wrong: written={mock_session.written}")

# 8. session_meterpreter_run uses run_with_output
mock_meter = MockSession('2', stype='meterpreter',
                          run_output='Server username: NT AUTHORITY\\SYSTEM')
client2 = MockClient({'2': mock_meter})
engine2 = MockMsfEngine(client2)
result = engine2.session_meterpreter_run('2', 'getuid')
if result['status'] == 'ok' and 'NT AUTHORITY' in result['output']:
    ok("session_meterpreter_run uses run_with_output for synchronous capture")
else:
    fail(f"meterpreter_run wrong: {result}")

# 9. session_run dispatches to meterpreter_run for meterpreter sessions
result = engine2.session_run('2', 'getuid')
if (result['status'] == 'ok'
    and 'NT AUTHORITY' in result['output']
    and result['session_type'] == 'meterpreter'):
    ok("session_run dispatches Meterpreter commands via run_with_output")
else:
    fail(f"session_run meterpreter dispatch wrong: {result}")

# 10. session_run dispatches to write+read for shell sessions
mock_shell = MockSession('3', stype='shell', canned_output='uid=0(root)\n')
client3 = MockClient({'3': mock_shell})
engine3 = MockMsfEngine(client3)
result = engine3.session_run('3', 'id')
if (result['status'] == 'ok'
    and 'uid=0(root)' in result['output']
    and result['session_type'] == 'shell'
    and 'id\n' in mock_shell.written):
    ok("session_run dispatches shell commands via write+read")
else:
    fail(f"session_run shell dispatch wrong: written={mock_shell.written}, result={result}")

# 11. _session_type identifies session by id
stype = engine2._session_type('2')
if stype == 'meterpreter':
    ok("_session_type correctly identifies meterpreter")
else:
    fail(f"_session_type returned {stype}")

# 12. _session_type returns empty for unknown sid
stype = engine._session_type('999')
if stype == '':
    ok("_session_type returns empty string for unknown session id")
else:
    fail(f"_session_type leak on unknown sid: {stype}")


# ── Tests: capture_creds integration ─────────────────────────────────────────

# 13. End-to-end hashdump capture: Meterpreter run → parse → cred_store
with tempfile.TemporaryDirectory() as tmp:
    store = CredentialStore(Path(tmp) / 'creds.json')
    mock_meter = MockSession('5', stype='meterpreter',
                              run_output=HASHDUMP_RAW)
    client = MockClient({'5': mock_meter})
    engine = MockMsfEngine(client)

    # Simulate what /api/msf/session/<sid>/capture_creds does
    result = engine.session_meterpreter_run('5', 'hashdump', timeout=30)
    captured = parse_hashdump_output(result['output'], host_ip='10.0.0.5')
    for c in captured:
        store.add(c)

    saved = store.list()
    if (len(captured) == 3
        and len(saved) == 3
        and any(c['username'] == 'krbtgt' for c in saved)):
        ok("End-to-end hashdump → parse → cred_store: 3 hashes captured + saved")
    else:
        fail(f"End-to-end capture wrong: captured={len(captured)}, saved={len(saved)}")


# ── Tests: Flask integration ─────────────────────────────────────────────────

# 14. /shell route registers + the new API endpoints exist
import importlib.util
spec = importlib.util.spec_from_file_location('h3x_dash', 'h3x-dash.py')
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
routes = [r.rule for r in mod.app.url_map.iter_rules()]
expected_routes = {
    '/shell',
    '/api/msf/session/<sid>/read',
    '/api/msf/session/<sid>/write',
    '/api/msf/session/<sid>/run',
    '/api/msf/session/<sid>/capture_creds',
}
missing = expected_routes - set(routes)
if not missing:
    ok(f"All 5 new Shell routes registered with Flask")
else:
    fail(f"Missing routes: {missing}")

# 15. Shell partial has the expected anchors (shared by shell + exploit pages)
shell_panel = Path('templates/partials/shell_panel.html').read_text()
shell_script = Path('templates/partials/shell_script.html').read_text()
required_anchors = ['session-tabs', 'shell-term', 'shortcut-bank',
                     'cmd-input', 'CAPTURE CREDS', 'SHELL_STATE']
missing = [a for a in required_anchors
           if a not in shell_panel and a not in shell_script]
if not missing:
    ok("Shell partial contains all expected anchors (tabs, terminal, shortcuts, cred capture)")
else:
    fail(f"Shell partial missing anchors: {missing}")

# 16. Standalone Shell nav removed — sessions live on Exploit page only
base_html = Path('templates/base.html').read_text()
if 'href="/exploit#shell-panel"' not in base_html and \
   "active == 'shell'" not in base_html:
    ok("Standalone Shell nav removed from sidebar (sessions on Exploit page)")
else:
    fail("Shell nav link still present in base.html — should be removed")

# 17. Exploit page embeds shell between host-class and CVE panels
exploit_html = Path('templates/exploit.html').read_text()
host_idx = exploit_html.find('host-class-panel')
shell_idx = exploit_html.find("partials/shell_panel.html")
cve_idx = exploit_html.find('id="cve-panel"')
if host_idx != -1 and shell_idx != -1 and cve_idx != -1 and host_idx < shell_idx < cve_idx:
    ok("Exploit page places shell panel between host-class-panel and cve-panel")
else:
    fail("Exploit page shell panel not positioned between host-class and CVE panels")

if 'focusShellPanel' in exploit_html and 'closeSession' in shell_script and \
   '_dropSessionLocally' in shell_script and 'syncSessionStrip' in shell_script and \
   '_clearShellArea' in shell_script and 'SHELL_STATE.closing' in shell_script:
    ok("Exploit page close/kill removes session tabs from shell-area immediately")
else:
    fail("Exploit page close-session UI cleanup missing")

if 'handoff-banner' in shell_panel and 'runHandoffStep' in shell_script and \
   'runAutoHandoff' in shell_script and 'migrate -n notepad.exe' in shell_script:
    ok("Post-land handoff banner + auto-handoff + migrate shortcut wired")
else:
    fail("Post-connection persistence handoff layer missing")

if 'h3x-autohandoff-cb' in exploit_html and 'opt-autohandoff' in shell_panel:
    ok("Auto-handoff checkbox on Exploit launcher and session panel")
else:
    fail("Auto-handoff checkbox missing")

if ('h3x_last_launch' in exploit_html and '_getLaunchContext' in shell_script and
        'skipMigrate' in shell_script and 'HANDOFF_STABILIZE_MS' in shell_script):
    ok("Auto-handoff reads launch context and skips double-migrate after stabilize delay")
else:
    fail("Auto-handoff missing launch-context / stabilize / skip-migrate guards")

if ('_scheduleHandoff' in shell_script and '_drainHandoffQueue' in shell_script and
        'duplicate session' in shell_script):
    ok("Auto-handoff serializes queue and only handoffs primary Meterpreter session")
else:
    fail("Auto-handoff queue / primary-session selection missing")


# ── Dead-session classifier ────────────────────────────────────────────────────
from modules.msf_engine import MsfEngine

_eng = MsfEngine()

# The exact MSF error for a session that opened then died
dead = _eng._classify_session_error(
    Exception("Session ID (3) does not exist"), '3')
if dead.get('session_dead') is True and 'died' in dead.get('message', '').lower():
    ok("Dead-session error ('does not exist') classified as session_dead with "
       "a clear operator message")
else:
    fail(f"Dead-session not classified correctly: {dead}")

# Unknown-session phrasing also caught
dead2 = _eng._classify_session_error(Exception("Unknown session 5"), '5')
if dead2.get('session_dead') is True:
    ok("'Unknown session' phrasing also classified as session_dead")
else:
    fail(f"'Unknown session' not classified as dead: {dead2}")

# A genuinely different error must NOT be flagged as a dead session
other = _eng._classify_session_error(Exception("connection reset by peer"), '3')
if not other.get('session_dead') and other.get('status') == 'error':
    ok("Non-dead-session errors are NOT mislabeled session_dead (stay raw)")
else:
    fail(f"Non-dead error wrongly flagged session_dead: {other}")

# Shell tab acts on the flag
if ('session_dead' in shell_script and 'refreshSessions(true)' in shell_script):
    ok("Shell tab acts on session_dead — shows clear message + refreshes list")
else:
    fail("Shell tab does not handle session_dead flag")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" SHELL AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
