"""
H3x-Dash PreflightChecker
Validates the environment before any operations run.
Called on startup and exposed via /api/preflight.
"""

import importlib
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path


class Check:
    """Single pre-flight result."""
    def __init__(self, name: str, status: str, message: str, fix: str = ''):
        self.name    = name
        self.status  = status   # 'pass' | 'warn' | 'fail'
        self.message = message
        self.fix     = fix      # suggested remedy

    def to_dict(self) -> dict:
        return {
            'name':    self.name,
            'status':  self.status,
            'message': self.message,
            'fix':     self.fix,
        }

    def __repr__(self):
        icon = {'pass': '✓', 'warn': '⚠', 'fail': '✗'}.get(self.status, '?')
        return f'[{icon}] {self.name}: {self.message}'


class PreflightChecker:

    def run_all(self) -> list[Check]:
        runners = [
            self._check_python,
            self._check_root,
            self._check_nmap,
            self._check_configurobulator,
            self._check_metasploit,
            self._check_flask,
            self._check_pymetasploit3,
            self._check_output_dirs,
            self._check_disk_space,
            self._check_port_5000,
            self._check_listen_address,
            self._check_enum_tools,
        ]
        results = []
        for fn in runners:
            try:
                results.append(fn())
            except Exception as exc:
                results.append(Check(fn.__name__, 'warn',
                                     f'Check crashed: {exc}'))
        return results

    def summary(self) -> dict:
        checks  = self.run_all()
        statuses = [c.status for c in checks]
        overall = ('fail' if 'fail' in statuses
                   else 'warn' if 'warn' in statuses
                   else 'pass')
        return {
            'overall': overall,
            'checks':  [c.to_dict() for c in checks],
            'fail':    sum(1 for s in statuses if s == 'fail'),
            'warn':    sum(1 for s in statuses if s == 'warn'),
            'pass':    sum(1 for s in statuses if s == 'pass'),
        }

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_python(self) -> Check:
        v = sys.version_info
        ver = f'{v.major}.{v.minor}.{v.micro}'
        if v < (3, 10):
            return Check('Python version', 'fail',
                         f'Python {ver} — H3x-Dash requires 3.10+ (union type hints)',
                         'Upgrade: sudo apt-get install python3.10')
        return Check('Python version', 'pass', f'Python {ver}')

    def _check_root(self) -> Check:
        if os.geteuid() == 0:
            return Check('Privileges', 'pass', 'Running as root — nmap SYN scans enabled')
        return Check('Privileges', 'warn',
                     'Not running as root — nmap SYN/OS scans will be limited',
                     'Launch with: sudo python3 h3x-dash.py')

    def _check_nmap(self) -> Check:
        path = shutil.which('nmap')
        if not path:
            return Check('nmap', 'fail', 'nmap not found',
                         'sudo apt-get install nmap')
        try:
            out = subprocess.check_output(['nmap', '--version'],
                                          stderr=subprocess.STDOUT,
                                          text=True, timeout=5)
            ver_m = re.search(r'Nmap version ([\d.]+)', out)
            ver = ver_m.group(1) if ver_m else 'unknown'
            maj = int(ver.split('.')[0]) if ver != 'unknown' else 0
            if maj < 7:
                return Check('nmap', 'warn', f'nmap {ver} — version 7+ recommended',
                             'sudo apt-get install nmap')
            return Check('nmap', 'pass', f'nmap {ver} at {path}')
        except Exception as e:
            return Check('nmap', 'warn', f'nmap found but version check failed: {e}')

    def _check_configurobulator(self) -> Check:
        candidates = [
            Path(__file__).parent.parent / 'Nmap-Configurabulator.py',
            Path.cwd() / 'Nmap-Configurabulator.py',
        ]
        for p in candidates:
            if p.exists():
                size = p.stat().st_size
                if size < 100:
                    return Check('Configurobulator', 'warn',
                                 f'Found at {p} but file is suspiciously small ({size}B)')
                return Check('Configurobulator', 'pass', f'Found at {p}')
        return Check('Configurobulator', 'fail',
                     'Nmap-Configurabulator.py not found in project root',
                     'Nmap-Configurabulator.py should be bundled in the project root — check your installation')

    def _check_metasploit(self) -> Check:
        msf_paths = [
            Path('/usr/share/metasploit-framework'),
            Path('/opt/metasploit-framework'),
        ]
        for p in msf_paths:
            if p.exists():
                modules = p / 'modules'
                exploit_count = len(list(modules.glob('exploits/**/*.rb'))) if modules.exists() else 0
                return Check('Metasploit Framework', 'pass',
                             f'Found at {p} — ~{exploit_count} exploit modules')
        msfconsole = shutil.which('msfconsole')
        if msfconsole:
            return Check('Metasploit Framework', 'warn',
                         f'msfconsole at {msfconsole} but module tree not found at expected paths')
        return Check('Metasploit Framework', 'fail',
                     'Metasploit Framework not found',
                     'sudo apt-get install metasploit-framework')

    def _check_flask(self) -> Check:
        try:
            import flask
            try:
                import importlib.metadata as _im
                _fver = _im.version('flask')
            except Exception:
                _fver = getattr(flask, '__version__', 'installed')
            return Check('Flask', 'pass', f'Flask {_fver}')
        except ImportError:
            return Check('Flask', 'fail', 'Flask not installed',
                         'sudo apt-get install python3-flask')

    def _check_pymetasploit3(self) -> Check:
        try:
            import pymetasploit3
            ver = getattr(pymetasploit3, '__version__', 'installed')
            return Check('pymetasploit3', 'pass', f'pymetasploit3 {ver}')
        except ImportError:
            return Check('pymetasploit3', 'warn',
                         'pymetasploit3 not installed — MSF RPC unavailable',
                         'sudo apt-get install python3-pymetasploit3')

    def _check_output_dirs(self) -> Check:
        from config import H3xConfig
        dirs    = [H3xConfig.LOOT_DIR, H3xConfig.REPORT_DIR, H3xConfig.NMAP_DIR]
        failed  = []
        for d in dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                test = d / '.h3x_write_test'
                test.write_text('ok')
                test.unlink()
            except Exception as e:
                failed.append(f'{d.name}: {e}')
        if failed:
            return Check('Output dirs', 'fail',
                         f'Not writable: {", ".join(failed)}',
                         'Check directory permissions')
        return Check('Output dirs', 'pass',
                     f'{len(dirs)} directories writable: scans/, reports/, loot/')

    def _check_disk_space(self) -> Check:
        try:
            stat  = os.statvfs('/')
            free  = stat.f_bavail * stat.f_frsize
            free_mb = free // (1024 * 1024)
            if free_mb < 200:
                return Check('Disk space', 'fail',
                             f'Only {free_mb} MB free — scans and reports may fail',
                             'Free up disk space before running scans')
            if free_mb < 1024:
                return Check('Disk space', 'warn',
                             f'{free_mb} MB free — consider freeing space for large engagements')
            return Check('Disk space', 'pass', f'{free_mb} MB free')
        except Exception as e:
            return Check('Disk space', 'warn', f'Could not check disk space: {e}')

    def _check_port_5000(self) -> Check:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', 5000))
            s.close()
            return Check('Port 5000', 'pass', 'Port 5000 available')
        except OSError:
            # Already bound — could be our own server (if checking after start)
            return Check('Port 5000', 'warn',
                         'Port 5000 already in use — H3x-Dash may already be running')

    def _check_listen_address(self) -> Check:
        return Check('Listen address', 'warn',
                     'H3x-Dash binds to 0.0.0.0:5000 — visible on all interfaces. '
                     'On a test network this is fine; on shared infrastructure, restrict to 127.0.0.1.',
                     "In h3x-dash.py: app.run(..., host='127.0.0.1')")

    def _check_enum_tools(self) -> Check:
        tools = {
            'nikto':        'sudo apt-get install nikto',
            'whatweb':      'sudo apt-get install whatweb',
            'gobuster':     'sudo apt-get install gobuster',
            'sslyze':       'sudo apt-get install sslyze',
            'enum4linux-ng':'sudo apt-get install enum4linux-ng',
            'smbmap':       'sudo apt-get install smbmap',
            'netexec':      'sudo apt-get install netexec',
            'onesixtyone':  'sudo apt-get install onesixtyone',
            'snmpwalk':     'sudo apt-get install snmp',
            'dnsrecon':     'sudo apt-get install dnsrecon',
            'ldapsearch':   'sudo apt-get install ldap-utils',
            'ssh-audit':    'sudo apt-get install ssh-audit',
            'searchsploit': 'sudo apt-get install exploitdb',
        }
        missing = [t for t in tools if not shutil.which(t)]
        present = len(tools) - len(missing)
        if not missing:
            return Check('Enum tools', 'pass',
                         f'All {present} enumeration tools present')
        if present == 0:
            return Check('Enum tools', 'fail',
                         'No enumeration tools found',
                         'sudo apt-get install nikto whatweb gobuster sslyze '
                         'enum4linux-ng smbmap netexec onesixtyone snmp '
                         'dnsrecon ldap-utils ssh-audit exploitdb')
        return Check('Enum tools', 'warn',
                     f'{present}/{len(tools)} tools present. Missing: {", ".join(missing)}',
                     'sudo apt-get install ' + ' '.join(
                         tools[t].split()[-1] for t in missing))


# ── Convenience ───────────────────────────────────────────────────────────────

def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate that a scan target is safe to pass to nmap.
    Accepts: single IP, CIDR, hyphen-range, hostname, comma-separated mix.
    Rejects: shell metacharacters, empty strings, path-like input.
    """
    if not target or not target.strip():
        return False, 'Target cannot be empty'

    target = target.strip()

    # Hard reject: shell metacharacters that could escape subprocess args
    if re.search(r'[;&|`$(){}[\]<>\\\'"]', target):
        return False, 'Target contains shell metacharacters'

    # Split on comma for multi-target
    parts = [p.strip() for p in target.split(',')]
    if not parts or any(not p for p in parts):
        return False, 'Empty component in target list'

    for part in parts:
        if len(part) > 255:
            return False, f'Target component too long: {part[:30]}...'
        # Allow: IPv4, IPv4/CIDR, IPv4-range, IPv6, hostnames
        if not re.fullmatch(r'[a-zA-Z0-9.\-:/_]+', part):
            return False, f'Invalid characters in target component: {part}'
        # Reject directory traversal attempts
        if '..' in part or part.startswith('/'):
            return False, f'Path traversal detected in target: {part}'

    return True, 'Valid'


def validate_ip(ip: str) -> bool:
    """Strict IP address validation for tool runner arguments."""
    ip = ip.strip()
    # IPv4
    ipv4 = re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', ip)
    if ipv4:
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 (basic)
    if re.fullmatch(r'[0-9a-fA-F:]+', ip) and ':' in ip:
        return True
    # Hostname (letters, digits, dots, hyphens)
    if re.fullmatch(r'[a-zA-Z0-9.\-]+', ip) and len(ip) <= 255:
        return True
    return False
