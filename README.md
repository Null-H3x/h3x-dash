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

## Overview

H3x-Dash is a Flask-based penetration testing dashboard that automates the full offensive security pipeline in a single browser interface. It integrates network enumeration, vulnerability identification, exploit execution, and loot reporting into a cohesive workflow — with state that persists across tabs so you're never clicking back into an empty screen.

Built by a U.S. Army communications and cybersecurity professional. Designed for operators who understand the tools they're running.

**It is not** a one-click root machine. **It is not** authorized for use outside explicitly controlled environments. It connects real tools, executes real commands, and produces real results against real systems.

---

## Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        H3x-Dash Pipeline                        │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│   DASHBOARD  │     SCAN     │  ENUMERATE   │      EXPLOIT       │
│              │              │              │                    │
│ Live stats   │ Nmap Config- │ 20 service-  │ CVE → MSF module   │
│ MSF connect  │ robulator    │ specific     │ mapping            │
│ Scan history │ PTY stream   │ tool runners │ Module launcher    │
│ Preflight    │ Risk scoring │ Parallel     │ Verbose output     │
│ Quick launch │ Host classify│ per-host     │ Session polling    │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│                           LOOT                                   │
│  Session management · Command relay · HTML/JSON report export    │
├─────────────────────────────────────────────────────────────────┤
│                       MSF MODULES                                │
│  3,000+ local modules indexed · CVE cross-reference · Search    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Dashboard
- Live stat cards — hosts found, danger ports, active sessions, scans run — auto-refresh every 4 seconds without a page reload
- Metasploit RPC connection panel with auto-connect on startup, background retry loop, and last-error display
- Scan history table with target, host count, and status
- Quick scan launcher — driveby / T4 / banner without leaving the dashboard
- **Pre-flight status panel** — 12 environment checks run on every startup, displayed with pass/warn/fail and fix commands (see [Pre-flight Checks](#pre-flight-checks))
- **Authorization modal** — liability statement gating every session with a mandatory checkbox acknowledgment; decline wipes the page

### Scan
- Full integration with **Nmap Configurobulator** — port profiles (`driveby`, `spyglass`, `full`), timing templates T1–T5, NSE script profiles from banner-only to full vulnerability sweep
- Live PTY output stream — filtered to relevant findings only (host discovery headers, open port lines, NSE output, scan completion stats; banners, spinners, and blank lines dropped)
- Host classification by device type (gateway, server, workstation, IoT, switch), OS detection, and port risk scoring (danger / warning / info)
- Results persist on tab navigation — revisiting the Scan page restores the last scan without re-running
- Target validation — shell metacharacters and path traversal patterns rejected server-side before any subprocess runs

### Enumerate
- **20 tool runners** dispatched automatically based on discovered open ports
- Runs up to 8 hosts in parallel with a semaphore cap; tools run serially per host with timer-based hard kill on timeout
- Structured findings output — severity-scored (CRITICAL / HIGH / MEDIUM / LOW / INFO), CVE-tagged, cross-referenced to locally installed MSF modules in real time
- Full-width findings table with a `LOCAL MSF MODULES` column — matching modules appear inline, clicking any sends it directly to the Exploit tab via sessionStorage
- Tool availability displayed as pass/fail badges on page load; missing tools show the exact `apt-get install` command

**Tool dispatch by port:**

| Port(s) | Tools Triggered |
|---------|----------------|
| 80 / 443 / 8080 / 8443 | WhatWeb → Nikto → GoBuster |
| 139 / 445 | enum4linux-ng → smbmap → NetExec |
| 161 | onesixtyone → snmpwalk |
| 389 / 636 | ldapsearch |
| 53 | dnsrecon |
| 22 | ssh-audit |
| 21 | ftplib anonymous login probe |
| 3389 | nmap `rdp-enum-encryption` NSE |
| 5900 | nmap `vnc-auth-bypass` NSE |
| 6379 | raw socket PING → PONG (unauthenticated Redis detection) |
| 9200 | HTTP probe → Elasticsearch cluster version |
| 27017 | TCP reachability → MongoDB auth warning |
| Any port with version string | searchsploit → ExploitDB CVE/module lookup |

### Exploit
- Host selector pre-populated from scan results; selecting a host auto-fetches CVE suggestions
- **CveChain** maps every discovered port/service to known CVEs and Metasploit modules from a local lookup table — 20 service families, no internet required
- MSF module search queries the live RPC connection and renders results with rank, type, and description
- Exploit launcher with full options form: RHOST, RPORT, LHOST, LPORT, payload
- Verbose launch output: pre-flight logging → option confirmation → session baseline → execution → post-launch session polling (10s)
- `USE ▶` buttons in CVE suggestions and MSF module search pre-fill the launcher in one click
- MSF RPC connection status polled every 5 seconds; launch button disables automatically when RPC goes offline

### Loot
- Active session table with inline command relay — send commands to Meterpreter or shell sessions directly from the browser
- Report generation: timestamped HTML or JSON, saved to `./reports/`
- HTML reports rendered in full H3x-Dash theme with host cards, port risk tables, session records, and CVE stats
- All user-controlled data HTML-escaped in reports — no injection surface
- Report list refreshes every 6 seconds; one-click download via secure path-validated endpoint

### MSF Modules
- Walks `/usr/share/metasploit-framework/modules/` on startup, parsing each `.rb` file with regex (no Ruby required)
- Indexes exploits, auxiliary, and post modules — skips payloads, encoders, nops
- Extracts: full module name, display name, description, CVE references, MSBulletin IDs, rank, platform, architecture
- Builds a `CVE → [modules]` index for real-time cross-reference in the Enumerate findings table
- Gzip-compressed JSON cache (~2 MB); auto-rebuilds if older than 24 hours
- Searchable in the browser by fullname path, display name, CVE, MSBulletin, description, or platform — all simultaneously
- **USE ▶** sends any module directly to the Exploit tab
- Accepts `?q=` URL parameter for deep-link from CVE findings (e.g. `/modules?q=CVE-2017-0144`)

---

## CVE Coverage

20 service families, local lookup — no internet required.

| Service | CVEs / Checks |
|---------|---------------|
| **SMB** | EternalBlue (CVE-2017-0144), EternalRomance (CVE-2017-0145), SMBGhost (CVE-2020-0796), PrintNightmare (CVE-2021-34527), share enum, user enum, SMBv1 detection, relay check |
| **RDP** | BlueKeep (CVE-2019-0708), DejaBlue (CVE-2019-1182), MS12-020 DoS, NLA/CredSSP detection |
| **HTTP/S** | Shellshock (CVE-2014-6271), Apache 2.4.49/50 path traversal (CVE-2021-41773/42013), Spring4Shell (CVE-2022-22965), Struts2 OGNL (CVE-2017-5638), PHP-FPM (CVE-2019-11043) |
| **FTP** | vsftpd 2.3.4 backdoor (CVE-2011-2523), ProFTPD buffer overflow (CVE-2010-4221), anonymous access |
| **SSH** | ssh-agent RCE (CVE-2023-38408), username enumeration (CVE-2018-15473), brute-force |
| **MSSQL** | xp_cmdshell RCE, hash dump, SA brute-force, enumeration |
| **MySQL** | Auth bypass (CVE-2012-2122), hash dump, FILE privilege check |
| **Redis** | Unauthenticated RCE via replication, Lua sandbox escape (CVE-2022-0543) |
| **Elasticsearch** | Groovy RCE (CVE-2014-3120), MVEL sandbox bypass (CVE-2015-1427), open cluster detection |
| **VNC** | No-auth detection, brute-force |
| **SNMP** | Community string enumeration, share enum, Cisco IOS RCE (CVE-2017-6736) |
| **PostgreSQL** | Brute-force, COPY PROGRAM RCE (CVE-2019-9193), hash dump |
| **LDAP** | Anonymous bind, directory enumeration, brute-force |
| **NFS** | World-readable export enumeration |
| **MongoDB** | Unauthenticated access detection, JS injection |
| **Oracle** | Login brute-force, enumeration |
| **Telnet** | BSD telnetd overflow (CVE-2011-4862), brute-force |
| **SMTP** | User enumeration (VRFY/EXPN/RCPT), open relay check |
| **RPC/NetBIOS** | Portmapper enumeration, NFS mount discovery |
| **Backdoor** | Port 4444 detection → multi/handler suggestion |

---

## Pre-flight Checks

12 checks run at startup in a background thread. Results cached and displayed on the Dashboard.

| Check | Pass Condition |
|-------|---------------|
| Python version | ≥ 3.10 |
| Privileges | Running as root (required for nmap SYN scans) |
| nmap | Installed and version ≥ 7 |
| Configurobulator | `Nmap-Configurobulator.py` present in project root |
| Metasploit Framework | Module tree found at `/usr/share/metasploit-framework` |
| Flask | Importable |
| pymetasploit3 | Importable (warns if absent, MSF RPC features unavailable) |
| Output directories | `scans/`, `reports/`, `loot/` exist and are writable |
| Disk space | ≥ 200 MB free |
| Port 5000 | Available (warns if already bound) |
| Listen address | Warns that `0.0.0.0:5000` is visible on all interfaces |
| Enum tools | Reports which of the 13 enumeration tools are installed |

Available via `GET /api/preflight`. Force-refresh via `POST /api/preflight/refresh`.

---

## Requirements

- **Kali Linux** (recommended) or any Debian-based distribution
- **Python 3.10+**
- **nmap 7.x+** — `sudo apt-get install nmap`
- **Metasploit Framework** — pre-installed on Kali
- **Nmap Configurobulator** — `Nmap-Configurobulator.py` placed in the project root

---

## Installation

### Kali Linux

`pip` is no longer supported for system packages on Kali. Use `apt-get`:

```bash
# Core dependencies
sudo apt-get install -y python3-flask python3-pymetasploit3

# Enumeration tools (install all for full coverage)
sudo apt-get install -y \
  nikto whatweb gobuster sslyze \
  enum4linux-ng smbmap netexec \
  onesixtyone snmp dnsrecon \
  ldap-utils ssh-audit exploitdb
```

### Other Debian / Ubuntu

```bash
pip install -r requirements.txt
```

---

## Setup & Launch

```bash
# 1. Clone the repository
git clone https://github.com/Null-H3x/h3x-dash.git
cd h3x-dash

# 2. Place the Nmap Configurobulator in the project root
ls Nmap-Configurobulator.py   # confirm it's present next to app.py

# 3. Start Metasploit RPC daemon
#    -P  RPC password
#    -S  disable SSL (plain HTTP on loopback)
#    -f  foreground
msfrpcd -P msfrpc -S -f

# 4. Launch H3x-Dash in a second terminal
sudo python3 app.py

# 5. Open the dashboard
#    http://127.0.0.1:5000
```

H3x-Dash auto-connects to Metasploit RPC on startup. If `msfrpcd` isn't running yet, a background thread retries every 10 seconds until it is — you don't need to time the startup sequence. The MSF module index builds in the background and is ready within 30–90 seconds depending on hardware.

---

## Configuration

All defaults work out of the box. Override via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `H3X_SECRET` | *(dev key)* | Flask session secret — **change this in any non-local deployment** |
| `MSF_HOST` | `127.0.0.1` | msfrpcd host |
| `MSF_PORT` | `55553` | msfrpcd port |
| `MSF_PASS` | `msfrpc` | msfrpcd password |
| `MSF_SSL` | `false` | Set `true` if msfrpcd was started without `-S` |

```bash
MSF_PASS=strongpassword H3X_SECRET=changeme sudo python3 app.py
```

---

## Project Structure

```
h3x-dash/
├── app.py                         Flask core — 36 routes, SSE endpoints, API
├── config.py                      Path and connection configuration
├── requirements.txt               pip dependencies (non-Kali environments)
├── Nmap-Configurobulator.py       ← place here (not bundled — separate project)
│
├── modules/
│   ├── preflight.py               12-check environment validator
│   ├── nmap_engine.py             Configurobulator wrapper + scan state machine
│   ├── enum_engine.py             20-tool enumeration dispatcher (port-triggered)
│   ├── cve_chain.py               Port/service → CVE → MSF module lookup table
│   ├── msf_engine.py              Metasploit RPC wrapper with auto-reconnect
│   ├── msf_scanner.py             Local MSF module filesystem scanner + CVE index
│   └── loot.py                    HTML/JSON report generation
│
├── templates/
│   ├── base.html                  H3x-Dash theme, sidebar, authorization modal
│   ├── dashboard.html             Stats, MSF connect, preflight, quick scan
│   ├── scan.html                  Configurobulator UI, live terminal, results
│   ├── enumerate.html             Tool dispatch, live output, findings table
│   ├── exploit.html               CVE suggestions, MSF launcher, session output
│   ├── loot.html                  Session relay, report generation, downloads
│   └── modules.html               Local MSF module browser with CVE search
│
├── static/
│   └── h3x-dash.js                SSE client, shared fetch utilities
│
├── scans/                         Nmap XML output — gitignored
├── reports/                       Generated reports — gitignored
├── loot/                          Loot staging — gitignored
└── msf_modules_cache.json.gz      MSF module index cache — gitignored
```

---

## API Reference

H3x-Dash exposes 36 endpoints. Key groups:

| Group | Endpoints |
|-------|-----------|
| Scan | `POST /api/scan/start` · `POST /api/scan/stop` · `GET /api/scan/status` · `GET /api/scan/results` · `GET /api/scan/history` · `GET /api/scan/stream` |
| CVE | `POST /api/cve/suggest` · `GET /api/cve/all` |
| Metasploit | `POST /api/msf/connect` · `POST /api/msf/disconnect` · `GET /api/msf/status` · `POST /api/msf/search` · `POST /api/msf/run` · `GET /api/msf/sessions` · `POST /api/msf/session/cmd` |
| Enumerate | `POST /api/enum/start` · `GET /api/enum/stream` · `GET /api/enum/status` · `GET /api/enum/findings` · `GET /api/enum/tools` |
| Loot | `POST /api/loot/generate` · `GET /api/loot/reports` · `GET /api/loot/download/<filename>` |
| Modules | `GET /api/modules/search` · `GET /api/modules/cve/<cve>` · `POST /api/modules/match` · `GET /api/modules/stats` · `POST /api/modules/rescan` |
| Preflight | `GET /api/preflight` · `POST /api/preflight/refresh` |

All SSE endpoints (`/api/scan/stream`, `/api/enum/stream`) accept a `client_id` parameter. The server-assigned ID from the corresponding `start` response is authoritative — use `d.client_id` from the API response rather than a locally-generated value.

---

## Building a Lab

Your home network is not a lab. Before running H3x-Dash against any target, you need a purpose-built vulnerable environment. These are designed to be compromised:

| Platform | Focus |
|----------|-------|
| **Metasploitable 2** | Classic — covers the bulk of this tool's CVE map |
| **Metasploitable 3** | Windows and Linux, more modern attack surface |
| **VulnHub** | Downloadable CTF-style VMs at all difficulty levels |
| **HackTheBox** | Realistic machines — guided and open-ended |
| **DVWA** | Web application testing |
| **TryHackMe** | Guided rooms from beginner through advanced |

Metasploitable 2 and 3 will validate essentially every module in the CVE chain. Run through both before pointing H3x-Dash at a client network.

---

## Security & Legal

This tool is built exclusively for authorized penetration testing. See [SECURITY.md](SECURITY.md) for the full responsible use policy and vulnerability disclosure process.

Three rules, no exceptions:

1. **Closed environment only** — lab networks, air-gapped ranges, and purpose-built vulnerable systems. Not production. Not shared infrastructure. Not cloud environments without explicit provider authorization.

2. **Systems you own** — hardware, lease, or service agreement in your name. "I have admin credentials" is not ownership.

3. **Written permission required** — a current, signed penetration testing agreement for any system you do not personally own. Verbal consent is not an agreement. Expired agreements are not agreements.

Unauthorized use of this tool is a federal crime under **18 U.S.C. § 1030** (Computer Fraud and Abuse Act) and equivalent legislation in most jurisdictions. The developer accepts no liability for unauthorized use. All consequences are the sole responsibility of the operator.

An authorization acknowledgment modal is displayed at the start of every browser session and requires explicit confirmation before the tool is accessible.

---

## Contributing

Pull requests welcome. The codebase is structured so new modules drop in cleanly.

**High-value additions:**
- **Impacket integration** — AD/Windows lateral movement: Pass-the-Hash, Kerberoasting, DCSync, secretsdump. Slot in as a new engine module alongside `msf_engine.py`.
- **Credential tracking** — capture, organize, and deduplicate credentials harvested across the engagement. The loot module has the scaffolding.
- **SOCKS proxy / pivot management** — route traffic through compromised hosts. Session data from `msf_engine.list_sessions()` is already available.
- **Additional CVE mappings** — `cve_chain.py` is a plain dict. Add entries and include a source reference. Consistent format: `(CVE_string_or_None, msf_module_or_None, description, severity)`.
- **Report templates** — the loot module's HTML renderer is self-contained. Alternative formats (PPTX, DOCX, PDF) for client deliverables would be a direct addition to `loot.py`.

**Before submitting:**
- Test exploit logic against Metasploitable before opening a PR
- CVE additions require a source reference in the comment
- Run the Python syntax check: `python3 -c "import ast; ast.parse(open('modules/your_module.py').read())"`

---

## Acknowledgements

- **Nmap** — without it, none of phase one works
- **Metasploit Framework** — without it, none of phase two works
- **pymetasploit3** — the Python bridge between them
- **Nmap Configurobulator** — the enumeration engine under the hood, where the scan intelligence actually lives
- Every CVE researcher whose work appears in the mapping table — the vulnerability was found by someone else; this tool just connects the dots to the module that exploits it

---

<div align="center">

`H3x-Dash // Automated Penetration Framework`
`// Built by Null-H3x // Authorized Use Only // Always //`

</div>
