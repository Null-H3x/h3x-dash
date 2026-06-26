#!/usr/bin/env python3
"""Offline audit — operational logging under logs/."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, '.')

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)

from modules.ops_log import OpsLogger

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp) / 'logs'
    log = OpsLogger(root)
    log.ensure_dirs()

    for sub in ('exploit', 'sessions', 'enumeration', 'scans'):
        if (root / sub).is_dir():
            ok(f'logs/{sub}/ created')
        else:
            fail(f'logs/{sub}/ missing')

    ep = log.log_exploit_run(
        module='exploit/windows/smb/ms17_010_eternalblue',
        options={'RHOSTS': '192.168.56.101', 'LHOST': '192.168.56.1',
                 'SMBPass': 'secret'},
        payload='windows/x64/meterpreter/reverse_tcp',
        target=0,
        action='run',
        auto_migrate=True,
        poll_timeout=90,
        result={
            'status': 'launched',
            'result': '[*] test wrapper',
            'console_output': '[+] Meterpreter session 1 opened',
            'sessions': [{'id': '1'}],
            'session_opened': True,
        },
    )
    if ep and ep.suffix == '.json' and (ep.with_suffix('.txt')).exists():
        data = json.loads(ep.read_text())
        if data.get('options', {}).get('SMBPass') == '********':
            ok('log_exploit_run writes json+txt and sanitizes secrets')
        else:
            fail(f'exploit log did not sanitize SMBPass: {data.get("options")}')
    else:
        fail('log_exploit_run did not write expected files')

    log.log_session_event('7', 'command', command='sysinfo',
                          result={'status': 'ok', 'output': 'OS: Windows 7'})
    sj = root / 'sessions' / 'session_7.jsonl'
    if sj.exists() and 'sysinfo' in sj.read_text():
        ok('log_session_event appends JSONL per session')
    else:
        fail('session JSONL log missing or empty')

    log.begin_enum_job('cid-1', [{'ip': '10.0.0.5'}], {'tier': 1})
    log.append_enum_line('cid-1', '[*] enum line')
    log.finish_enum_job('cid-1', {'10.0.0.5': [{'title': 'smbv1'}]})
    enum_logs = list((root / 'enumeration').glob('*.log'))
    if enum_logs and enum_logs[0].read_text().count('enum line'):
        ok('enum job transcript + summary written')
    else:
        fail('enum job log missing')

    log.begin_scan_job('cid-2', '10.0.0.0/24', {'mode': 'network'})
    log.append_scan_line('cid-2', '[*] nmap output line')
    log.finish_scan_job('cid-2', host_count=3)
    scan_logs = list((root / 'scans').glob('*.log'))
    if scan_logs and 'nmap output' in scan_logs[0].read_text():
        ok('scan job transcript written')
    else:
        fail('scan job log missing')

print()
print('═' * 72)
print(f' OPS LOG AUDIT — {len(FAIL)} FAIL · {len(OK)} OK')
print('═' * 72)
if FAIL:
    print('\nFAIL:')
    for m in FAIL:
        print(f'  ✗ {m}')
print('\nPASSED:')
for m in OK:
    print(f'  ✓ {m}')
sys.exit(1 if FAIL else 0)
