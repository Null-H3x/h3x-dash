# H3x-Dash — Installation Guide
### Kali GNU/Linux 2026.1 Rolling (and compatible versions)

`// AUTHORIZED USE ONLY — READ SECURITY.md BEFORE PROCEEDING //`

---

## Before You Start

**Time required:** ~10 minutes for dependencies, 30–90 seconds for first launch (MSF module index build).

**You will need:**
- Kali GNU/Linux 2026.1 or later (rolling)
- Internet connection for package installation
- A terminal with sudo/root access
- The [Nmap Configurobulator](https://github.com/Null-H3x/nmap-configurobulator) — download separately

---

## Step 1 — System Check

Verify your environment meets the requirements before installing anything.

```bash
# Python version — must be 3.10 or later (Kali 2026.1 ships 3.12)
python3 --version

# nmap — must be 7.x or later
nmap --version | head -1

# Disk space — at minimum 500 MB free recommended
df -h /

# Confirm you are running as root (required for nmap SYN scans)
whoami
```

If Python is below 3.10:
```bash
sudo apt-get install -y python3.12
```

---

## Step 2 — Clone the Repository

```bash
git clone https://github.com/Null-H3x/h3x-dash.git
cd h3x-dash
```

---

## Step 3 — Verify the Nmap Configurabulator is Present

The Configurabulator is H3x-Dash's enumeration engine. It ships **bundled in the project** — no manual download required.

```bash
# Confirm it's in the project root next to h3x-dash.py
ls -la Nmap-Configurabulator.py

# Quick sanity check
wc -l Nmap-Configurabulator.py   # should be ~2345 lines
python3 -c "import ast; ast.parse(open('Nmap-Configurabulator.py').read()); print('OK')"
```

If it's missing for any reason, download it from the [Nmap Configurabulator repo](https://github.com/Null-H3x/nmap-configurobulator) and place it in the project root.

---

## Step 4 — Install Core Dependencies

> **Kali-specific note:** `pip install` is blocked for system Python packages on Kali 2024+.
> All packages must be installed via `apt-get`. Do **not** run bare `pip install` commands.

```bash
sudo apt-get update

# Flask and Metasploit Python bindings
sudo apt-get install -y python3-flask python3-pymetasploit3
```

**If `python3-pymetasploit3` is not found** in your Kali version's repos:

```bash
# Check if it exists first
apt-cache search pymetasploit3

# If not available via apt, use pip with the system-packages override
pip install pymetasploit3 --break-system-packages
```

Verify both are importable:
```bash
python3 -c "import flask; print('Flask OK')"
python3 -c "import pymetasploit3; print('pymetasploit3 OK')"
```

---

## Step 5 — Install Enumeration Tools

These tools power the Enumerate tab. Install all of them for full coverage.
Missing tools are shown as red badges in the tool availability panel — H3x-Dash will skip them gracefully if absent.

```bash
sudo apt-get install -y \
  nikto \
  whatweb \
  gobuster \
  sslyze \
  enum4linux-ng \
  smbmap \
  netexec \
  onesixtyone \
  snmp \
  dnsrecon \
  ldap-utils \
  ssh-audit \
  exploitdb
```

> **Note on `exploitdb`:** This provides the `searchsploit` command.
> If the package name differs in your Kali version try `sudo apt-get install exploitdb` or `sudo apt-get install kali-tools-exploitation`.

Verify the critical ones:
```bash
which nikto whatweb gobuster enum4linux-ng smbmap searchsploit
```

---

## Step 6 — Verify Metasploit Framework

Metasploit ships pre-installed on Kali. Confirm it's present and locate the RPC daemon:

```bash
# Confirm msfconsole is present
which msfconsole

# Confirm msfrpcd is present (the RPC daemon H3x-Dash connects to)
which msfrpcd

# Check the module tree exists
ls /usr/share/metasploit-framework/modules/exploits | head -5
```

If Metasploit is missing:
```bash
sudo apt-get install -y metasploit-framework
```

---

## Step 7 — Verify the Full Installation

Run the built-in environment check before first launch:

```bash
# From the h3x-dash directory
sudo python3 -c "
from modules.preflight import PreflightChecker
checker = PreflightChecker()
result  = checker.summary()
print(f'Overall: {result[\"overall\"].upper()}')
for c in result['checks']:
    icon = {'pass':'✓','warn':'⚠','fail':'✗'}.get(c['status'],'?')
    print(f'  [{icon}] {c[\"name\"]}: {c[\"message\"]}')
"
```

Expected output (all checks should be ✓ or ⚠ at worst):
```
Overall: PASS
  [✓] Python version: Python 3.12.x
  [✓] Privileges: Running as root
  [✓] nmap: nmap 7.9x at /usr/bin/nmap
  [✓] Configurobulator: Found at /path/to/h3x-dash/Nmap-Configurabulator.py
  [✓] Metasploit Framework: Found at /usr/share/metasploit-framework
  [✓] Flask: Flask 3.x
  [✓] pymetasploit3: pymetasploit3 installed
  [✓] Output dirs: 3 directories writable
  [✓] Disk space: XXXX MB free
  [⚠] Port 5000: ...
  [⚠] Listen address: ...
  [⚠] Enum tools: X/13 tools present
```

Warnings (`⚠`) are acceptable. Failures (`✗`) must be resolved before proceeding.

---

## Step 8 — Validate & Launch

The bundled installer validates every dependency in the scan → enumerate →
exploit chain, offers to install anything missing, and can launch H3x-Dash
for you once all critical checks pass.

```bash
# Recommended — runs full pre-flight validation
sudo python3 install.py
```

The installer checks the OS, Python, privileges, nmap, the Configurabulator,
all 13 enumeration tools, Metasploit, msfrpcd, pymetasploit3, Flask, and the
project files. Missing apt packages can be installed directly from the prompt.
When all critical checks pass it asks `Run H3x-Dash now? [y/N]`.

To skip the validator and launch directly:

```bash
sudo python3 h3x-dash.py
```

H3x-Dash manages `msfrpcd` automatically — you do not need to start it manually.

On first launch you will see:
```
  ██╗  ██╗██████╗ ██╗  ██╗  ...
  // AUTOMATED PENETRATION FRAMEWORK // AUTHORIZED USE ONLY //

  Usage:  sudo python3 h3x-dash.py [--no-msf]
  ...

[H3x-Dash] msfrpcd: [CHECKING] Probing 127.0.0.1:55553...
[H3x-Dash] msfrpcd: [STARTING] Launching: msfrpcd -P msfrpc -p 55553 -a 127.0.0.1 -S
[H3x-Dash] msfrpcd: [STARTING] First run may take 30–90s while MSF loads modules...
 * Running on http://0.0.0.0:5000
[H3x-Dash] msfrpcd starting... (3s / 120s)
[H3x-Dash] msfrpcd starting... (6s / 120s)
...
[H3x-Dash] msfrpcd: [READY] msfrpcd ready after 45s — PID 12345
[H3x-Dash] MSF RPC connected (no-SSL) — Metasploit v6.x
```

Open the dashboard:
```
http://127.0.0.1:5000
```

---

## Step 9 — Accept the Authorization Statement

An authorization modal appears on every new browser session. Read all three conditions, check the acknowledgment box, and click **I ACKNOWLEDGE AND PROCEED**.

You cannot use any feature until the modal is accepted. Clicking **DECLINE & EXIT** wipes the page.

---

## Operational Notes

### Running in the Background

```bash
# Run H3x-Dash in the background with output to a log
sudo python3 h3x-dash.py &> /tmp/h3x-dash.log &
echo "H3x-Dash PID: $!"

# Follow the log
tail -f /tmp/h3x-dash.log
```

### Skip msfrpcd Auto-Start

If you want to manage `msfrpcd` yourself (e.g. with different credentials or SSL):

```bash
# Start msfrpcd manually
msfrpcd -P msfrpc -S -f

# Then launch H3x-Dash without auto-start
sudo python3 h3x-dash.py --no-msf
```

### MSF Log and PID

```bash
# msfrpcd output log
cat /tmp/h3x_msfrpcd.log

# msfrpcd PID (if started by H3x-Dash)
cat /tmp/h3x_msfrpcd.pid

# Stop msfrpcd started by H3x-Dash
kill $(cat /tmp/h3x_msfrpcd.pid)
```

### Change Credentials or Port

Override via environment variables — no need to edit source files:

```bash
MSF_PASS=yourpassword MSF_PORT=55553 sudo python3 h3x-dash.py
```

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_HOST` | `127.0.0.1` | msfrpcd host |
| `MSF_PORT` | `55553` | msfrpcd port |
| `MSF_PASS` | `msfrpc` | msfrpcd password |
| `MSF_SSL` | `false` | Set `true` if msfrpcd started with SSL |
| `H3X_SECRET` | *(dev key)* | Flask session secret — change in production |

---

## Troubleshooting

### "pymetasploit3 not installed"

```bash
# Try apt first
sudo apt-get install python3-pymetasploit3

# If not in repos
pip install pymetasploit3 --break-system-packages

# Verify
python3 -c "import pymetasploit3; print('OK')"
```

### "Configurobulator not found"

The file ships with H3x-Dash and should not be missing. If it is:

```bash
# Confirm you're in the right directory
ls h3x-dash.py Nmap-Configurabulator.py

# If missing, re-clone the repo or download it directly
git clone https://github.com/Null-H3x/nmap-configurobulator.git /tmp/cfgr
cp /tmp/cfgr/Nmap-Configurabulator.py .
```

### "msfrpcd did not start within 120s"

First-run initialization loads all Metasploit modules and can take up to 2 minutes on slower hardware.

```bash
# Check msfrpcd log
cat /tmp/h3x_msfrpcd.log

# Try starting manually to see the error
msfrpcd -P msfrpc -p 55553 -a 127.0.0.1 -S -f
```

### "Permission denied launching msfrpcd"

```bash
# H3x-Dash must run as root
sudo python3 h3x-dash.py
```

### "Port 5000 already in use"

```bash
# Find what's using it
sudo lsof -i :5000

# Kill it
sudo fuser -k 5000/tcp

# Or run H3x-Dash on a different port (edit h3x-dash.py line: app.run(port=5001,...))
```

### "MSF RPC connection keeps failing"

```bash
# Check if msfrpcd is actually running
ps aux | grep msfrpcd

# Check port is open
ss -tlnp | grep 55553

# Test connectivity manually
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 55553), timeout=3)
print('Port open')
s.close()
"
```

### Scan runs but shows no results

```bash
# nmap requires root for SYN scans
sudo python3 h3x-dash.py   # not just python3 h3x-dash.py

# Confirm the Configurobulator loaded
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('c', 'Nmap-Configurabulator.py')
mod  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print('Configurobulator loaded OK')
print('Port profiles:', list(mod.PORT_PROFILES.keys()))
"
```

### Enumerate tab crashes with Jinja2 error

```bash
# Ensure you have the latest version — render_findings bug was fixed
grep -n "render_findings" templates/enumerate.html
# Should return nothing if on the current version
```

---

## File Locations Reference

| Path | Purpose |
|------|---------|
| `install.py` | Dependency validator & installer — run this first |
| `h3x-dash.py` | Main Flask application |
| `Nmap-Configurabulator.py` | Enumeration engine — must be here |
| `modules/` | Backend engines |
| `templates/` | HTML templates |
| `static/h3x-dash.js` | Client-side JS |
| `scans/` | Nmap XML output (auto-created, gitignored) |
| `reports/` | Generated loot reports (auto-created, gitignored) |
| `loot/` | Loot staging (auto-created, gitignored) |
| `msf_modules_cache.json.gz` | MSF module index cache (auto-created, gitignored) |
| `/tmp/h3x_msfrpcd.log` | msfrpcd startup log |
| `/tmp/h3x_msfrpcd.pid` | msfrpcd PID file |

---

## Quick Reference

```bash
# Full install (copy-paste)
sudo apt-get update && sudo apt-get install -y \
  python3-flask python3-pymetasploit3 \
  nikto whatweb gobuster sslyze enum4linux-ng \
  smbmap netexec onesixtyone snmp dnsrecon \
  ldap-utils ssh-audit exploitdb nmap

# Place Configurobulator, then:
sudo python3 h3x-dash.py

# Open: http://127.0.0.1:5000
```

---

`H3x-Dash // Kali GNU/Linux 2026.1 // Authorized Use Only`
