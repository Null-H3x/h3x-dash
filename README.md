```
  ██╗  ██╗██████╗ ██╗  ██╗      ██████╗  █████╗ ███████╗██╗  ██╗
  ██║  ██║╚════██╗╚██╗██╔╝      ██╔══██╗██╔══██╗██╔════╝██║  ██║
  ███████║ █████╔╝ ╚███╔╝ █████╗██║  ██║███████║███████╗███████║
  ██╔══██║ ╚═══██╗ ██╔██╗ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║
  ██║  ██║██████╔╝██╔╝ ██╗      ██████╔╝██║  ██║███████║██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

<div align="center">

**Automated Penetration Testing Framework**

`// SCAN → ENUMERATE → EXPLOIT → LOOT // AUTHORIZED USE ONLY //`

![Python](https://img.shields.io/badge/Python-3.10%2B-0ff0fc?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-9b30ff?style=flat-square&logo=flask&logoColor=white)
![Metasploit](https://img.shields.io/badge/Metasploit-RPC-39ff14?style=flat-square)
![Nmap](https://img.shields.io/badge/Nmap-7.x%2B-39ff14?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-0ff0fc?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-9b30ff?style=flat-square&logo=kalilinux&logoColor=white)

</div>

---

## What It Is

H3x-Dash is a Flask-based web dashboard that automates the full penetration testing pipeline — from network discovery through exploitation to loot reporting — in a single, self-contained interface.

It wraps the **Nmap Configurobulator** for intelligent network enumeration, connects to Metasploit Framework via its MSGRPC API for exploit automation, and maps discovered services to known CVEs and MSF modules automatically. Results persist across the session so you're never clicking back to an empty tab.

It is **not** a toy. It is **not** a script kiddie tool. It is built for operators who already know what they're doing and want the repetitive parts handled while they focus on what matters. If you're here looking for a one-click root, you are going to have a very educational day on your own lab machine before you figure out that penetration testing is actually hard.

---

## What It Is Not

- A replacement for understanding what you're running
- Authorized to use on networks you don't own or have written permission to test
- Responsible for your decisions
- Going to open a shell on a patched, hardened, modern system without you understanding the exploit chain first

---

## Features

### Enumeration
- Full Nmap integration via the **Nmap Configurobulator** (https://github.com/Null-H3x/Nmap-Configurobulator) — port profiles (`driveby`, `spyglass`, `full`), timing templates T1–T5, NSE script profiles from banner-only to full vuln sweep
- Live PTY output stream — scan progress feeds directly into the dashboard terminal in real time, filtered to relevant findings only
- Host classification by device type (gateway, server, workstation, IoT), OS detection, port risk scoring (danger / warning / info)
- Timestamped HTML topology reports generated automatically per scan

### Exploit
- Metasploit RPC auto-connect on startup with background retry loop — if `msfrpcd` isn't running yet, H3x-Dash keeps trying until it is
- Automatic CVE and MSF module mapping from scan results — select a host and the exploit panel populates with every relevant finding, severity-scored and sorted
- Module search, full options form, payload selection
- Verbose launch output: pre-flight log, option confirmation, session baseline, post-launch session polling

### Loot
- Timestamped HTML and JSON reports in the H3x-Dash theme
- Active session management with inline command execution
- One-click report download

### Dashboard
- Live stats across all four panels — hosts, danger ports, sessions, scans
- Scan history with target, host count, and status
- MSF RPC connection management with last-error display
- Quick scan launch without leaving the dashboard

---

## Built-In CVE Coverage

| Service | Coverage |
|---------|----------|
| SMB | EternalBlue (MS17-010), SMBGhost (CVE-2020-0796), EternalRomance, PrintNightmare, share/user enum |
| RDP | BlueKeep (CVE-2019-0708), DejaBlue, NLA check |
| FTP | vsftpd 2.3.4 backdoor, ProFTPD buffer overflow, anonymous access |
| SSH | Username enumeration, ssh-agent RCE (CVE-2023-38408), brute-force |
| HTTP/S | Shellshock, Apache 2.4.49/50 path traversal, Spring4Shell, Struts2 OGNL, PHP-FPM |
| MSSQL | xp_cmdshell RCE, hash dump, SA brute-force |
| MySQL | Auth bypass (CVE-2012-2122), hash dump, FILE privilege check |
| Redis | Unauthenticated RCE via replication, Lua sandbox escape (CVE-2022-0543) |
| Elasticsearch | Groovy RCE (CVE-2014-3120), MVEL sandbox bypass (CVE-2015-1427) |
| VNC | No-auth detection, brute-force |
| SNMP | Community string enum, Cisco IOS RCE (CVE-2017-6736) |
| PostgreSQL | Brute-force, COPY PROGRAM RCE, hash dump |
| LDAP | Anonymous bind, directory enumeration |
| NFS | World-readable export enumeration |
| MongoDB | Unauthenticated access, JS injection |
| Telnet | BSD telnetd overflow (CVE-2011-4862), brute-force |

---

## Prerequisites

- **Kali Linux** (or any Debian-based distro — Kali recommended)
- **Python 3.10+**
- **nmap >= 7.x** — `sudo apt-get install nmap`
- **Metasploit Framework** — pre-installed on Kali
- **Nmap Configurobulator** — place `Nmap-Configurobulator.py` in the project root (sibling of `app.py`)

---

## Installation

### Kali Linux

`pip` is no longer supported for system packages on Kali. Use `apt-get`:

```bash
sudo apt-get update
sudo apt-get install -y python3-flask
sudo apt-get install -y python3-pymetasploit3
```

### Other Debian / Ubuntu

```bash
pip install -r requirements.txt
```

---

## Setup & Launch

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/h3x-dash.git
cd h3x-dash

# 2. Drop the Nmap Configurobulator into the project root
#    ***https://github.com/Null-H3x/Nmap-Configurobulator***
#    It should sit next to app.py:
ls Nmap-Configurobulator.py

# 3. Start Metasploit RPC daemon
#    -P  password
#    -S  no SSL (plain HTTP on loopback — fine for local use)
#    -f  foreground
msfrpcd -P msfrpc -S -f

# 4. In a second terminal, launch H3x-Dash
sudo python3 app.py

# 5. Open a modern browser
#    http://127.0.0.1:5000
```

H3x-Dash will auto-connect to MSF RPC in the background. If `msfrpcd` isn't running yet, it retries every 10 seconds until it is. You don't have to time the startup sequence.

---

## Configuration

All defaults work out of the box. Override via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `H3X_SECRET` | `(dev key)` | Flask session secret — change in production |
| `MSF_HOST` | `127.0.0.1` | msfrpcd host |
| `MSF_PORT` | `55553` | msfrpcd port |
| `MSF_PASS` | `msfrpc` | msfrpcd password |
| `MSF_SSL` | `false` | Set `true` if msfrpcd was started with SSL |

```bash
MSF_PASS=strongerpassword sudo python3 app.py
```

---

## Workflow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   DASHBOARD │    │    SCAN     │    │   EXPLOIT   │    │    LOOT     │
│             │    │             │    │             │    │             │
│  Live stats │ →  │ Configurob- │ →  │ CVE mapper  │ →  │  Session    │
│  MSF status │    │ ulator UI   │    │ MSF launcher│    │  commands   │
│  Scan hist  │    │ Live term   │    │ Verbose out │    │  Reports    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

1. **Dashboard** — Connect MSF RPC, review stats, quick-launch a scan
2. **Scan** — Configure target, port scope, timing, NSE scripts. Watch live filtered output. Results persist when you switch tabs.
3. **Exploit** — Select a discovered host. CVE suggestions auto-populate from port data, severity-scored and sorted. Fill options, select payload, launch. Output shows pre-flight config, execution, and session status.
4. **Loot** — Generate a timestamped HTML or JSON report. Run commands against active sessions directly from the UI.

---

## Project Structure

```
h3x-dash/
├── app.py                     Flask core — routes, SSE, API endpoints
├── config.py                  Configuration and path management
├── requirements.txt           pip dependencies (non-Kali environments)
├── Nmap-Configurobulator.py   ← place here (not bundled in repo)
│
├── modules/
│   ├── nmap_engine.py         Configurobulator wrapper, scan state machine
│   ├── msf_engine.py          Metasploit RPC wrapper, auto-reconnect loop
│   ├── cve_chain.py           Port → CVE → MSF module mapping table
│   └── loot.py                HTML/JSON report generation
│
├── templates/
│   ├── base.html              H3x-Dash theme, sidebar, layout
│   ├── dashboard.html         Live stats, MSF connect, quick scan
│   ├── scan.html              Configurobulator UI, live terminal, results
│   ├── exploit.html           CVE suggestions, MSF launcher, output
│   └── loot.html              Sessions, report generation, downloads
│
├── static/
│   └── h3x-dash.js            SSE client, shared UI utilities
│
├── scans/                     Nmap XML output — gitignored
├── reports/                   Generated reports — gitignored
└── loot/                      Loot staging — gitignored
```

---

## Building a Lab

Your home network is not a lab. If you want to exercise the exploit chain end-to-end, here are purpose-built environments that exist specifically to be compromised:

| Target | Why It's Good |
|--------|---------------|
| **Metasploitable 2** | Classic — covers nearly every MSF module in the CVE map |
| **Metasploitable 3** | Windows and Linux builds, more modern vuln surface |
| **VulnHub** | Library of downloadable CTF-style VMs at all difficulty levels |
| **HackTheBox** | Realistic machines, guided and unguided — solid for validating technique |
| **DVWA** | Web app focused — good for HTTP module testing |
| **TryHackMe** | Guided rooms from beginner to advanced, browser-based |

All of them exist to be broken. Your production environment does not.

---

## Security & Responsible Use

This tool is built for authorized penetration testing only. See [SECURITY.md](SECURITY.md) for the full policy.

The short version: if you don't have written permission to test the target, you don't have permission to run this tool against it. The Computer Fraud and Abuse Act does not care how curious you are.

---

## Contributing

PRs welcome. Areas of active interest:

- **Impacket integration** — AD/Windows lateral movement (Pass-the-Hash, Kerberoasting, DCSync)
- **Credential tracking** — capture and organize creds harvested across the engagement
- **SOCKS proxy / pivot management** — route traffic through compromised hosts
- **Additional CVE mappings** — `cve_chain.py` is deliberately extensible; include a source reference
- **Export formats** — PPTX/DOCX report templates for client deliverables

If you're adding CVE mappings, include a source reference. If you're adding exploit logic, test it against Metasploitable before opening the PR.

---

## Acknowledgements

- **Nmap** — the reason any of this is possible
- **Metasploit Framework** — the reason the second half is possible
- **pymetasploit3** — the Python bridge that ties it together
- **Nmap Configurobulator** — the enumeration engine under the hood
- Every CVE researcher whose work is represented in the mapping table — you found the holes; this tool just connects the dots

---

<div align="center">

`H3x-Dash // Automated Penetration Framework`
`// Built for operators who know what they're doing //`
`// Authorized use only. Always. //`

</div>
