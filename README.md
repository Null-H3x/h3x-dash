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
![Kali](https://img.shields.io/badge/Kali-Supported-9b30ff?style=flat-square&logo=kalilinux&logoColor=white)
![Parrot](https://img.shields.io/badge/Parrot-Supported-9b30ff?style=flat-square)

</div>

---

## Overview

H3x-Dash is a Flask-based penetration testing dashboard that automates the full offensive security pipeline in a single browser interface. It integrates network enumeration, vulnerability identification, exploit execution, and loot reporting into a cohesive workflow — with state that persists across tabs so you're never clicking back into an empty screen.

Built by a U.S. Army communications and cybersecurity professional. Designed for operators who understand the tools they're running.

**It is not** a one-click root machine. **It is not** authorized for use outside explicitly controlled environments. It connects real tools, executes real commands, and produces real results against real systems.

---

## Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                         H3x-Dash Pipeline                            │
├──────────────┬──────────────┬──────────────┬─────────────────────────┤
│   DASHBOARD  │     SCAN     │  ENUMERATE   │        EXPLOIT          │
│              │              │              │                         │
│ Live stats   │ Configura-   │ 35 tool      │ CVE → MSF module        │
│ MSF connect  │ bulator      │ runners      │ chain (96 entries)      │
│ Scan history │ + web_scan   │ across 3     │ Auto-confirmation       │
│ Preflight    │ (L7 module)  │ sweep tiers  │ Verbose runner          │
│ Quick launch │ PTY stream   │ Parallel     │ Session polling         │
├──────────────┴──────────────┴──────────────┴─────────────────────────┤
│                              LOOT                                    │
│   Session management · Command relay · HTML/JSON report export       │
├──────────────────────────────────────────────────────────────────────┤
│                          MSF MODULES                                 │
│  3,000+ local modules indexed · CVE cross-reference · Search         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Dashboard
- Live stat cards — hosts found, danger ports, active sessions, scans run — auto-refresh every 4 seconds without a page reload
- Metasploit RPC connection panel with auto-connect on startup, background retry loop, and last-error display
- Scan history table with target, host count, and status
- Quick scan launcher — driveby / T4 / banner without leaving the dashboard
- **Pre-flight status panel** — environment checks run on every startup, displayed with pass/warn/fail and fix commands (see [Pre-flight Checks](#pre-flight-checks))
- **Authorization modal** — liability statement gating every session with a mandatory checkbox acknowledgment; decline wipes the page

### Scan
- Full integration with the **Nmap Configurabulator** — port profiles (`driveby`, `spyglass`, `full`), timing templates T1–T5, NSE script profiles from banner-only to full vulnerability sweep
- Bundled **Layer 7 web scanner** (`web_scan.py`) — auto-runs on discovered web ports for HTTP fingerprinting, TLS/cert inspection, content surface, and optional nmap http-NSE orchestration (see [Web Scanning](#web-scanning))
- Live PTY output stream — filtered to relevant findings only (host discovery headers, open port lines, NSE output, scan completion stats; banners, spinners, and blank lines dropped)
- Host classification by device type (gateway, server, workstation, IoT, switch), OS detection, and port risk scoring (danger / warning / info)
- Results persist on tab navigation — revisiting the Scan page restores the last scan without re-running
- Target validation — shell metacharacters and path traversal patterns rejected server-side before any subprocess runs

### Enumerate
- **35 tool runners** across three operator-selectable sweep tiers (see [Sweep Depth Tiers](#sweep-depth-tiers))
- Dispatched automatically based on discovered open ports — runs up to 8 hosts in parallel with a semaphore cap; tools run serially per host with timer-based hard kill on timeout
- Structured findings output — severity-scored (CRITICAL / HIGH / MEDIUM / LOW / INFO), CVE-tagged, cross-referenced to locally installed MSF modules in real time
- Full-width findings table with a `LOCAL MSF MODULES` column — matching modules appear inline; clicking any sends it directly to the Exploit tab via sessionStorage
- Tool availability displayed as pass/fail badges on page load; missing tools show the exact `apt-get install` command
- Findings auto-promote chain entries via the `enum_confirmed` system — a Log4Shell CVE-2021-44228 hit, a Drupal banner, an SMBv1-enabled flag, etc., all elevate the matching MSF module to the top of the exploit suggestions

**Tool dispatch by port:**

| Port(s) | Tools Triggered |
|---------|----------------|
| 21 | ftplib anonymous probe · searchsploit |
| 22 | ssh-audit · searchsploit |
| 25 / 110 | smtp-user-enum |
| 53 | dnsrecon · dnsenum |
| 80 / 8080 | httpx · wafw00f · WhatWeb · Nikto · WPScan · droopescan · GoBuster · ffuf · feroxbuster · nuclei |
| 88 | kerbrute (Kerberos user enum) |
| 137 | nbtscan |
| 139 / 445 | nbtscan · smbclient (null) · rpcclient (null) · enum4linux-ng · smbmap · NetExec |
| 161 | onesixtyone · snmpwalk |
| 389 / 636 | ldapsearch · ldapdomaindump · sslscan (LDAPS) |
| 443 / 8443 | httpx · wafw00f · sslscan · SSLyze · testssl.sh · WhatWeb · Nikto · WPScan · droopescan · GoBuster · ffuf · feroxbuster · nuclei |
| 1099 | (CVE chain only — Java RMI Server) |
| 3306 / 1433 / 5432 | searchsploit (DB version sweep) |
| 3389 | nmap `rdp-enum-encryption` NSE |
| 3632 | (CVE chain only — distcc) |
| 5900 | nmap `vnc-auth-bypass` NSE |
| 5985 / 5986 | (CVE chain only — WinRM) |
| 6379 | raw socket PING → PONG (unauthenticated Redis detection) |
| 6667 | (CVE chain only — UnrealIRCd) |
| 8009 | (CVE chain only — Tomcat AJP / Ghostcat) |
| 9200 | HTTP probe → Elasticsearch cluster version · nuclei |
| 27017 | TCP reachability → MongoDB auth warning |
| Any port with version string | searchsploit → ExploitDB CVE/module lookup |

### Sweep Depth Tiers

Every enumeration tool is mapped to a tier; the operator selects the maximum tier per sweep. Tools above the selected depth are *gated* — they don't run.

| Tier | Tools | Profile |
|------|-------|---------|
| **1 — Recon** | httpx, nbtscan, wafw00f, sslscan, ftp_anon, vnc_check, redis_check, elastic_check, mongo_check, smbclient (null), rpcclient (null), searchsploit | Fast, low-noise. Service probes, HTTP triage, banner grabs, null-session checks. |
| **2 — Standard** *(default)* | WhatWeb, Nikto, GoBuster, SSLyze, enum4linux-ng, smbmap, NetExec, snmp_check, smtp_enum, ldapsearch, ldapdomaindump, dnsrecon, dnsenum, ssh-audit, rdp_check, WPScan, droopescan, ffuf, kerbrute | The default working depth. Preserves prior behaviour — everything except slow/loud tools. |
| **3 — Deep** | nuclei, feroxbuster, testssl.sh | Slow / loud / opt-in. Runs only when explicitly requested. |

### Exploit
- Host selector pre-populated from scan results; selecting a host auto-fetches CVE suggestions from the chain
- **CveChain** maps every discovered port/service to known CVEs and Metasploit modules from a local lookup table — **96 entries across 29 service families**, no internet required (see [CVE Coverage](#cve-coverage))
- Module suggestions ranked: enum-confirmed first, then severity, then MSF rank (excellent / great / good / normal / average / low / manual)
- MSF module search queries the live RPC connection and renders results with rank, type, and description
- Exploit launcher with full options form: RHOST, RPORT, LHOST, LPORT, payload
- Verbose launch output: pre-flight logging → option confirmation → session baseline → execution → post-launch session polling
- Module-aware launcher — **auxiliary and post modules no longer attach payloads silently**; the runner detects the module class, logs the reason a payload is being stripped, and writes "Scanner dispatched" instead of "Exploit dispatched" for clarity
- Falsy-return guards on `client.modules.use()` — invalid module/payload paths return a clean error instead of `'bool' object is not subscriptable`
- `USE ▶` buttons in CVE suggestions and MSF module search pre-fill the launcher in one click
- MSF RPC connection status polled every 5 seconds; launch button disables automatically when RPC goes offline

### Loot
- Active session table with inline command relay — send commands to Meterpreter or shell sessions directly from the browser
- Report generation: timestamped HTML or JSON, saved to `./reports/`
- HTML reports rendered in full H3x-Dash theme with host cards, port risk tables, session records, web-scan overlay, and CVE stats
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

## Web Scanning

`web_scan.py` is a Layer 7 scanner that attaches to the Configurabulator and produces a dedicated section in the topology report. Pure stdlib — no pip dependencies — to preserve the Configurabulator's single-file, zero-dependency footprint.

**Capabilities:**

| Capability | Details |
|------------|---------|
| Fingerprint & headers | Redirect chain, status, Server / X-Powered-By, page title, tech detection (signature table), security-header audit (HSTS, CSP, X-Frame-Options, etc.), cookie flag analysis (Secure / HttpOnly / SameSite) |
| TLS & certificate | Subject / issuer / SAN, validity window, self-signed / hostname-mismatch detection, negotiated protocol & cipher, TLS 1.0 / 1.1 legacy probe |
| Content surface | robots.txt, sitemap.xml, HTTP methods (incl. active TRACE / XST check), short signature-confirmed path probe (catches `/.git/HEAD`, `/.env`, `/server-status`, etc. — soft-404 aware) |
| nmap http-NSE | Optional orchestration of `http-enum`, `http-headers`, `http-methods`, `http-title`, `http-vuln*` against the web port — gated behind `--web-nse` for tier discipline |

**Attach modes:**
- *Auto-run* — every open web port on every discovered host (default behaviour)
- *Direct* — `--web https://target` runs a web-only scan with no nmap topology

**Standalone use:**

```bash
python3 web_scan.py https://example.com --nse  # JSON to stdout
```

Findings land in a clickable header pill (`WEB ◇ N`) on the Configurabulator's HTML report. One card per scanned target, severity-colour-coded by the report's own palette.

---

## CVE Coverage

**29 service families · 96 entries · 37 exploit-class MSF modules · 48 auxiliary scanners** — local lookup, no internet required.

| Service | Highlights |
|---------|------------|
| **SMB / Samba** | EternalBlue (CVE-2017-0144), EternalRomance (CVE-2017-0145), SMBGhost (CVE-2020-0796), SambaCry (CVE-2017-7494), Samba usermap (CVE-2007-2447), share / user / SMBv1 enum |
| **DCERPC** *(port 135)* | Zerologon (CVE-2020-1472), PrintNightmare (CVE-2021-1675/34527), MS03-026 DCOM, endpoint auditor |
| **WinRM** *(5985/5986)* | Auth-method enum, login brute, WinRM command exec, script exec with valid credentials |
| **RDP** | BlueKeep (CVE-2019-0708), DejaBlue (CVE-2019-1182), MS12-020 DoS, NLA / CredSSP detection |
| **HTTP/S** | Shellshock (CVE-2014-6271), Apache path traversal (CVE-2021-41773/42013), Spring4Shell (CVE-2022-22965), Struts2 OGNL (CVE-2017-5638), PHP-FPM (CVE-2019-11043), **Log4Shell (CVE-2021-44228)**, **Confluence OGNL (CVE-2022-26134)**, **GitLab RCE (CVE-2021-22205)**, Jenkins, Tomcat Manager / JSP bypass, **Drupalgeddon2 (CVE-2018-7600)**, WordPress, JBoss, WebDAV |
| **AJP** *(8009)* | Ghostcat (CVE-2020-1938) |
| **Java RMI** *(1099)* | Insecure default config RCE |
| **IRC** *(6667)* | UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) — Metasploitable classic |
| **distcc** *(3632)* | distccd v1 command exec (CVE-2004-2687) — Metasploitable classic |
| **FTP** | vsftpd 2.3.4 backdoor (CVE-2011-2523), ProFTPD overflow (CVE-2010-4221), anonymous access |
| **SSH** | ssh-agent RCE (CVE-2023-38408), username enum (CVE-2018-15473), brute-force |
| **MSSQL / MySQL** | xp_cmdshell RCE, hash dump, brute, FILE-privilege check, auth bypass (CVE-2012-2122) |
| **PostgreSQL** | COPY PROGRAM RCE (CVE-2019-9193), brute, hash dump |
| **Redis** | Unauthenticated replication RCE, Lua sandbox escape (CVE-2022-0543), no-auth config check |
| **Elasticsearch** | Groovy RCE (CVE-2014-3120), MVEL bypass (CVE-2015-1427), open-cluster detection |
| **MongoDB** | Unauthenticated access, JS injection / collection enum |
| **VNC** | No-auth detection, brute-force |
| **SNMP** | Community string enum, share enum, Cisco IOS RCE (CVE-2017-6736) |
| **LDAP** | Anonymous bind, directory enumeration, brute |
| **DNS** | Zone transfer / AXFR / subdomain harvest |
| **NFS** | World-readable export enumeration |
| **Oracle** | Login brute, enumeration |
| **POP3 / IMAP** | Login brute (POP3), version enum (IMAP) — previously mis-routed to SMTP, now corrected |
| **Telnet** | BSD telnetd overflow (CVE-2011-4862), cleartext credential warning |
| **SMTP** | User enum (VRFY / EXPN / RCPT), open relay check |
| **RPC / NetBIOS** | Portmapper enumeration, NFS mount discovery |
| **Backdoor** *(4444)* | Port 4444 detection → multi/handler suggestion |

Run `python3 validate_chain.py` against your local msfrpcd to verify every module path in the chain exists in your MSF install — see [Validation Tools](#validation-tools).

---

## Pre-flight Checks

Checks run at startup in a background thread. Results cached and displayed on the Dashboard.

| Check | Pass Condition |
|-------|---------------|
| Python version | ≥ 3.10 |
| Privileges | Running as root (required for nmap SYN scans) |
| nmap | Installed and version ≥ 7 |
| Configurabulator | `Nmap-Configurabulator.py` present in project root |
| Web scan module | `web_scan.py` present (warns if absent — Layer 7 features disabled) |
| Metasploit Framework | Module tree found at `/usr/share/metasploit-framework` |
| Flask | Importable |
| pymetasploit3 | Importable (warns if absent, MSF RPC features unavailable) |
| Output directories | `scans/`, `reports/`, `loot/` exist and are writable |
| Disk space | ≥ 200 MB free |
| Port 5000 | Available (warns if already bound) |
| Listen address | Warns that `0.0.0.0:5000` is visible on all interfaces |
| Enum tools | Reports which of the 25 binary-tracked enumeration tools are installed |
| SecLists wordlists | Present at `/usr/share/seclists/` (required for ffuf, feroxbuster, kerbrute) |

Available via `GET /api/preflight`. Force-refresh via `POST /api/preflight/refresh`.

---

## Requirements

- **Kali Linux** or **Parrot Security** (recommended) — or any Debian-based distribution
- **Python 3.10+**
- **nmap 7.x+** — `sudo apt-get install nmap`
- **Metasploit Framework** — pre-installed on both Kali and Parrot Security
- **SecLists** — `sudo apt-get install seclists` (required for ffuf / feroxbuster / kerbrute)

---

## Installation

### Kali Linux / Parrot Security

`pip` is no longer supported for system packages on either distribution. Use `apt-get`:

```bash
# Core dependencies
sudo apt-get install -y python3-flask python3-pymetasploit3

# Enumeration tools — full coverage (Kali and Parrot apt-installable)
sudo apt-get install -y \
  nikto whatweb gobuster sslyze sslscan \
  enum4linux-ng smbmap netexec smbclient samba-common-bin \
  onesixtyone snmp dnsrecon dnsenum \
  ldap-utils ldapdomaindump ssh-audit exploitdb \
  httpx-toolkit nbtscan feroxbuster nuclei testssl.sh \
  wpscan droopescan wafw00f ffuf kerbrute seclists
```

### Other Debian / Ubuntu

```bash
pip install -r requirements.txt
```

Parrot Security ships most of these tools by default — `sudo apt install parrot-tools-full` pulls the complete set on a fresh Home edition install.

---

## Setup & Launch

```bash
# 1. Clone — both the Configurabulator and web_scan are bundled, nothing to place manually
git clone https://github.com/Null-H3x/h3x-dash.git
cd h3x-dash

# 2. Install dependencies
sudo apt-get install -y python3-flask python3-pymetasploit3

# 3. Validate dependencies & launch
sudo python3 install.py

# 4. Open the dashboard
#    http://127.0.0.1:5000
```

**That's it.** H3x-Dash manages `msfrpcd` automatically:

1. On startup, it checks whether `msfrpcd` is already listening on `127.0.0.1:55553`
2. If not, it launches `msfrpcd` in a background daemon thread with the configured credentials
3. Flask starts immediately — the browser opens while `msfrpcd` initialises in the background
4. The Dashboard shows a live `msfrpcd` status strip (checking → starting → ready) that updates every 4 seconds
5. Once the port opens, the MSF RPC auto-connect loop connects and MSF features become available

First startup may take 30–90 seconds while Metasploit loads its module tree. Subsequent starts are faster. The MSF module index also builds in the background and is ready within 30–90 seconds.

**To skip auto-start** (when managing `msfrpcd` externally or via a supervisor):

```bash
sudo python3 h3x-dash.py --no-msf
```

**To stop the `msfrpcd` instance H3x-Dash started:**

```bash
kill $(cat /tmp/h3x_msfrpcd.pid)
```

Or via the API: `POST /api/msf/daemon/stop`

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
MSF_PASS=strongpassword H3X_SECRET=changeme sudo python3 h3x-dash.py
```

---

## Validation Tools

Three offline / online checks ship with the codebase. Run them after any change to the chain or enum runners to catch regressions before they hit the dashboard.

| Script | Mode | What it checks |
|--------|------|----------------|
| `python3 audit_chain.py` | Offline | Internal consistency of `modules/cve_chain.py` — entry shape, severity discipline, no dead routes / orphan keys / duplicate (CVE, module) tuples, SMB-pipe DCERPC port-override correctness, suggestion-dict shape matches HTML expectations, auto-confirmation regressions |
| `python3 audit_enum.py` | Offline | Every TOOL_LABELS entry has a backing `_run_<id>` method (and vice-versa), every tier-mapped tool is labeled, port/service references resolve, `available_tools()` covers every dispatchable tool, dispatch simulation against representative hosts |
| `python3 validate_chain.py` | Online | Connects to your local msfrpcd and verifies every module path in the chain actually exists in your MSF install — catches renames, version drift, and typos that offline audits can't see |

**Typical workflow when extending the chain:**

```bash
python3 audit_chain.py          # internal consistency — 0 FAIL required
python3 validate_chain.py       # MSF reality check — 0 missing required
python3 audit_enum.py           # only if you touched enum_engine.py
```

---

## Project Structure

```
h3x-dash/
├── h3x-dash.py                       Flask core — 36 routes, SSE endpoints, API
├── config.py                         Path and connection configuration
├── requirements.txt                  pip dependencies (non-Kali environments)
├── Nmap-Configurabulator.py          ← bundled enumeration engine (Layer 3/4)
├── web_scan.py                       ← bundled Layer 7 web scanner
├── audit_chain.py                    CVE chain internal-consistency audit
├── audit_enum.py                     Enum-engine wiring audit
├── validate_chain.py                 Online msfrpcd module-path validator
│
├── modules/
│   ├── preflight.py                  Environment validator
│   ├── nmap_engine.py                Configurabulator wrapper + scan state machine
│   ├── enum_engine.py                35-tool enumeration dispatcher (tiered)
│   ├── cve_chain.py                  Port/service → CVE → MSF module lookup table
│   ├── msf_engine.py                 Metasploit RPC wrapper with auto-reconnect
│   ├── msf_scanner.py                Local MSF module filesystem scanner + CVE index
│   └── loot.py                       HTML/JSON report generation
│
├── templates/
│   ├── base.html                     H3x-Dash theme, sidebar, authorization modal
│   ├── dashboard.html                Stats, MSF connect, preflight, quick scan
│   ├── scan.html                     Configurabulator UI, live terminal, results
│   ├── enumerate.html                Tool dispatch, live output, findings table
│   ├── exploit.html                  CVE suggestions, MSF launcher, session output
│   ├── loot.html                     Session relay, report generation, downloads
│   └── modules.html                  Local MSF module browser with CVE search
│
├── static/
│   └── h3x-dash.js                   SSE client, shared fetch utilities
│
├── scans/                            Nmap XML output — gitignored
├── reports/                          Generated reports — gitignored
├── loot/                             Loot staging — gitignored
└── msf_modules_cache.json.gz         MSF module index cache — gitignored
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
| **Metasploitable 2** | Classic — covers the bulk of this tool's CVE map (Samba usermap, vsftpd, UnrealIRCd, distcc, Java RMI) |
| **Metasploitable 3** | Windows and Linux, more modern attack surface |
| **VulnHub** | Downloadable CTF-style VMs at all difficulty levels |
| **HackTheBox** | Realistic machines — guided and open-ended |
| **DVWA** | Web application testing |
| **TryHackMe** | Guided rooms from beginner through advanced |

Metasploitable 2 alone validates roughly half the CVE chain — every exploit marked `excellent` rank in the chain has a working target somewhere in that VM. Pair with Metasploitable 3 for Windows-side coverage (Zerologon, PrintNightmare, EternalBlue, WinRM).

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
- **Impacket integration** — AD/Windows lateral movement: Pass-the-Hash, Kerberoasting (GetUserSPNs), DCSync, secretsdump. Slot in as a new engine module alongside `msf_engine.py`. Pairs with the WinRM and DCERPC chain entries already in place.
- **Credential tracking** — capture, organize, and deduplicate credentials harvested across the engagement. The loot module has the scaffolding.
- **SOCKS proxy / pivot management** — route traffic through compromised hosts. Session data from `msf_engine.list_sessions()` is already available.
- **Title-pattern auto-confirmation** — extend the `enum_confirmed` system in `cve_chain.suggest()` to recognise more banner / version strings (Tomcat manager exposed → tomcat_mgr_upload, Drupal 7 banner → drupalgeddon2, etc.).
- **Additional CVE mappings** — `cve_chain.py` is a plain dict. Add entries and include a source reference. Consistent format: `(CVE_string_or_None, msf_module_or_None, description, severity)`.
- **Report templates** — the loot module's HTML renderer is self-contained. Alternative formats (PPTX, DOCX, PDF) for client deliverables would be a direct addition to `loot.py`.

**Before submitting:**
- Run the audit trio — every PR that touches `cve_chain.py` or `enum_engine.py` must pass `audit_chain.py` and `audit_enum.py` clean
- Run `validate_chain.py` against a live msfrpcd if you added MSF module paths
- Test exploit logic against Metasploitable 2/3 before opening a PR
- CVE additions require a source reference in the description field

---

## Acknowledgements

- **Nmap** — without it, none of phase one works
- **Metasploit Framework** — without it, none of phase two works
- **pymetasploit3** — the Python bridge between them
- **[Nmap Configurabulator](https://github.com/Null-H3x/nmap-configurobulator)** — the Layer 3/4 enumeration engine under the hood
- **Project Discovery** — `httpx`, `nuclei`, `ffuf` family that anchor modern web triage
- **SecLists** — the wordlists every content discovery / brute-force tool in this stack relies on
- **Impacket** maintainers, **enum4linux-ng**, **NetExec** (formerly CrackMapExec), **WPScan**, **kerbrute**, **ldapdomaindump** — every tool wired into the enum engine
- Every CVE researcher whose work appears in the mapping table — the vulnerability was found by someone else; this tool just connects the dots to the module that exploits it

---

<div align="center">

`H3x-Dash // Automated Penetration Framework`
`// Built by Null-H3x // Authorized Use Only // Always //`

</div>
