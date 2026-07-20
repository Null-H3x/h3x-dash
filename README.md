```
  ██╗  ██╗██████╗ ██╗  ██╗      ██████╗  █████╗ ███████╗██╗  ██╗
  ██║  ██║╚════██╗╚██╗██╔╝      ██╔══██╗██╔══██╗██╔════╝██║  ██║
  ███████║ █████╔╝ ╚███╔╝ █████╗██║  ██║███████║███████╗███████║
  ██╔══██║ ╚═══██╗ ██╔██╗ ╚════╝██║  ██║██╔══██║╚════██║██╔══██║
  ██║  ██║██████╔╝██╔╝ ██╗      ██████╔╝██║  ██║███████║██║  ██║
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

<div align="center">

**Offensive Security and Purple-Team Operations Console**

`// RECON > ACCESS > CREDS > LATERAL > EMULATE > RECONCILE // AUTHORIZED USE ONLY //`

![Python](https://img.shields.io/badge/Python-3.10%2B-0ff0fc?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-9b30ff?style=flat-square&logo=flask&logoColor=white)
![Metasploit](https://img.shields.io/badge/Metasploit-RPC-39ff14?style=flat-square)
![Nmap](https://img.shields.io/badge/Nmap-7.x%2B-39ff14?style=flat-square)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK--mapped-9b30ff?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-0ff0fc?style=flat-square)
![Kali](https://img.shields.io/badge/Kali-Supported-9b30ff?style=flat-square&logo=kalilinux&logoColor=white)
![Parrot](https://img.shields.io/badge/Parrot-Supported-9b30ff?style=flat-square)

</div>

---

## Overview

H3x-Dash is a Flask-based console that drives an entire offensive and purple-team pipeline from one browser tab. It wires together network discovery, deep enumeration, vulnerability identification, exploitation, credential capture, Active Directory attack paths, lateral movement, adversary emulation, and detection reconciliation, with state that persists across panes so you are never clicking back into an empty screen.

The default interface is the **Purple Ops Console**, a single-page live UI that talks to a JSON API of real engines. It does not invent capability. Every action is carried out by a standard, separately installed tool (nmap, netexec, Impacket, Responder, Certipy, BloodHound, CALDERA, Atomic Red Team, Metasploit, and the rest). The console schedules those tools, streams their real output, stores their real findings, and reconciles them against detections. There is no synthetic telemetry. If a tool is not installed or not reachable, the pane shows a clear "TOOL NOT ON PATH" state instead of faking a result.

Built for people who already understand the tools they are running and just want them in one place that does not fight back. Scan, enumerate, get access, capture credentials, move, emulate, then reconcile what fired against what did not.

**It is not** a one-click root button. **It is not** authorized for use outside explicitly controlled environments. It connects real tools, executes real commands, and produces real results against real systems. The console is friendly. The consequences of pointing it at the wrong network are not.

---

## The Console

The Purple Ops Console (`templates/console.html`) is served at `/` and `/console`. It is one page, grouped into workspaces, over the same `/api/*` endpoints the rest of the app exposes.

```
OVERVIEW      Dashboard
EXERCISE      Scenario Scheduler (timed / manual events)
RECON & ENUM  Scan · Topology · Web Scan · Enum Suite · MSF Scanners
ACCESS        Exploit · Validate · Sessions / Shell · Payloads · Spectrum
CREDS & AD    Loot · Responder+Relay · Kerberoast/AS-REP · BloodHound ·
              Impacket-AD · Certipy/ADCS · Coercion
LATERAL / C2  Lateral Movement · C2 Beacon Emulator
EMULATION     Atomic Red Team · CALDERA · Scenario Playbooks
REPORT        Engagement Report · Detection Coverage
```

Two console-wide features:

- **Global halt.** A stop control is present on every screen. One confirm halts every active subsystem at once (scan, enumeration, all Metasploit sessions, emulation, beacons, and the scheduler), then shows an honest per-subsystem report of what stopped. When in doubt, hit it.
- **Fixed scale.** The UI renders at a consistent apparent size across resolutions, so a 4K workstation and a 1280x800 VM show the same proportions rather than a layout that looks tiny on one and cramped on the other. A single design-width constant tunes it.

The legacy multi-page interface (`/dashboard`, `/scan`, `/enumerate`, `/exploit`, `/shell`, `/loot`, `/modules`, and friends) remains available and runs over the same API, so nothing you built against it breaks.

---

## Operating Principles

Four rules govern safe use, and they are enforced in the code, not just written here:

1. **Authorized scope only.** Run H3x-Dash only against systems you are cleared to assess, on the network and ports named in your authorization. The scenario timeline records every target you touch.
2. **Captured credentials only.** The Active Directory and lateral movement panes pull secrets from the loot store. There is no free-text secret entry. You capture or extract a credential first, then reuse it.
3. **The beacon is a detection emitter, not real command and control.** The C2 pane sends known-signature callbacks so defenders can practice catching them. It is scoped for detection validation, not stealth, and has no post-exploitation capability.
4. **Real tools or an honest gap.** Missing tooling surfaces as a clear "not on path" state. The console never fabricates telemetry to paper over an absent binary.

---

## Capabilities by Workspace

### Exercise: Scenario Scheduler

Fires timed or manual events on an exercise clock and records a ground-truth timeline of what happened and when. Each event type dispatches to a real engine already wired in the console (scan, enumeration, and beacon are wired out of the box). Unwired types fail honestly rather than reporting a fake success. Arm, pause, resume, abort, reset, save, and load control the run. The append-only timeline under `logs/` is the authoritative record for the debrief and for detection reconciliation.

### Recon and Enum

- **Scan.** Port and service discovery built on the bundled **Nmap Configurabulator**: port profiles (`driveby`, `spyglass`, `web`, `full`), timing templates T1 to T5, NSE script profiles from banner-only to full vulnerability sweep, three scan modes (network, web services, Layer-7 only), and stealth levels 0 to 3 that layer evasion flags. Live PTY output filtered to real findings, host classification by device type, and port risk scoring. Results persist across tab navigation.
- **Topology.** A live D3 graph of discovered hosts, risk-tiered ports, and their relationships. The same graphic embeds into the engagement report.
- **Web Scan.** The bundled Layer-7 scanner (`web_scan.py`): redirect chain, headers, tech fingerprint, TLS and certificate inspection, content surface, and optional nmap http-NSE. See [Web Scanning](#web-scanning).
- **Enum Suite.** 35 tool runners across three operator-selectable sweep tiers, dispatched automatically by discovered port, up to 8 hosts in parallel with a hard per-tool timeout. Structured, severity-scored, CVE-tagged findings cross-referenced to your local Metasploit modules in real time. See [Sweep Depth Tiers](#sweep-depth-tiers) and the dispatch table.
- **MSF Scanners.** Metasploit auxiliary scanner modules for post-recon confirmation over the live RPC connection.

### Access

- **Exploit.** Maps discovered services to CVEs and Metasploit modules from a local lookup table (see [CVE Coverage](#cve-coverage)), ranks suggestions enum-confirmed first, and launches with a full options form and verbose output. Session-survival hardening for fragile kernel exploits, module-aware payload handling, and RPC status polling that disables the launch button the moment the connection drops.
- **Validate.** Confirms outcomes and assigns verdicts (confirmed, unconfirmed, failed) with supporting evidence, so a real foothold is separated from a false positive before you build on it. Verdicts flow into the report and the coverage reconciliation.
- **Sessions / Shell.** Live session management with inline command relay, per-session tabs, command history, and a kill-all control.
- **Payloads.** Payload generation and a vetted-source library. See [Vetted Payload Sources](#vetted-payload-sources).
- **Spectrum.** Radio and wireless operations: device control, recon sweeps, and handshake capture across the supported capture and monitor hardware.

### Creds and AD

The loot store is the single source of truth. Capture or extract a secret, then select it in a downstream pane. Every technique below is mapped to MITRE ATT&CK and wraps its standard tool.

| Pane | What it does | Tools | ATT&CK |
|------|--------------|-------|--------|
| **Loot** | Captured credential store that every AD and lateral pane draws from | internal store | - |
| **Responder + Relay** | LLMNR / NBT-NS / mDNS poisoning with SMB / LDAP / ADCS relay | Responder, ntlmrelayx | T1557.001, T1187 |
| **Kerberoast / AS-REP** | Request roastable tickets, hand RC4 material to hashcat | impacket GetUserSPNs / GetNPUsers, hashcat | T1558.003, T1558.004 |
| **BloodHound** | Collect AD data and map attack paths | bloodhound-python, SharpHound, neo4j | T1087.002, T1482 |
| **Impacket-AD** | secretsdump / DCSync credential extraction against a DC | impacket secretsdump | T1003.006 |
| **Certipy / ADCS** | Enumerate and abuse ESC1 through ESC8 certificate misconfigurations | Certipy | T1649 |
| **Coercion** | Force machine authentication via PetitPotam (EFSRPC) or PrinterBug (MS-RPRN) | PetitPotam, printerbug | T1187 |

### Lateral and C2

- **Lateral Movement.** psexec, smbexec, wmiexec, dcomexec, atexec, and evil-winrm, plus pass-the-hash and pass-the-ticket, using credentials drawn only from loot. Tools: impacket exec family, evil-winrm, netexec. ATT&CK T1021.002, T1047, T1053.005, T1550.002.
- **C2 Beacon Emulator.** Synthetic jittered HTTP, HTTPS, and DNS callbacks with a tunable sleep interval, malleable profiles, and a bounded callback count. It exists so defenders can practice detecting beaconing. It is not a real implant. ATT&CK T1071.001, T1571, T1573.

### Emulation

- **Atomic Red Team.** Runs Invoke-AtomicRedTeam atomics, small portable ATT&CK-mapped tests built for detection validation. Refuses to fake execution if the framework is not installed.
- **CALDERA.** Autonomous, chained adversary emulation across the ATT&CK matrix via a server and agents.
- **Scenario Playbooks.** Named-actor and ransomware-precursor chains that sequence an end-to-end emulation. Impact stages stop short of real destruction.

### Report

- **Engagement Report.** A client-deliverable report pulling scan inventory, captured credentials, exploit outcomes, verdicts, and ATT&CK coverage into one document with the topology graphic embedded, exported as HTML or JSON.
- **Detection Coverage.** Reconciles what you did against what was detected. It maps your actions to ATT&CK techniques and compares them against the detection ledger and SIEM ingest, producing a per-technique verdict of hit, partial, or miss with the source signals listed. A miss is a finding, not an error. That loop is the point of the whole console.

---

## Sweep Depth Tiers

Every enumeration tool is mapped to a tier; the operator selects the maximum tier per sweep. Tools above the selected depth are gated. The philosophy is simple: quality and speed of information beat throwing five tools at the same question.

| Tier | Tools | Profile |
|------|-------|---------|
| **1 - Recon** | httpx, whatweb, wafw00f, sslscan, nbtscan, smbclient (null), rpcclient (null), ftp_anon, vnc_check, redis_check, elastic_check, mongo_check, searchsploit | Fast, low-noise. Service probes, HTTP triage, banner grabs, null-session checks. The polite knock before the door comes off. |
| **2 - Standard** *(default)* | Nikto, GoBuster, SSLyze, enum4linux-ng, smbmap, NetExec, snmp_check, smtp_enum, ldapsearch, ldapdomaindump, dnsrecon, ssh-audit, rdp_check, kerbrute | The default working depth. One quality tool per question, no redundant noise. |
| **3 - Deep** | nuclei, feroxbuster, testssl.sh, WPScan, droopescan, ffuf, dnsenum | Slow, loud, opt-in. Runs only when explicitly requested. This is the tier the blue team writes tickets about. |

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
| 1099 | (CVE chain only: Java RMI Server) |
| 3306 / 1433 / 5432 | searchsploit (DB version sweep) |
| 3389 | nmap `rdp-enum-encryption` NSE |
| 3632 | (CVE chain only: distcc) |
| 5900 | nmap `vnc-auth-bypass` NSE |
| 5985 / 5986 | (CVE chain only: WinRM) |
| 6379 | raw socket PING to PONG (unauthenticated Redis detection) |
| 6667 | (CVE chain only: UnrealIRCd) |
| 8009 | (CVE chain only: Tomcat AJP / Ghostcat) |
| 9200 | HTTP probe to Elasticsearch cluster version · nuclei |
| 27017 | TCP reachability to MongoDB auth warning |
| Any port with version string | searchsploit to ExploitDB CVE/module lookup |

---

## Web Scanning

`web_scan.py` is a Layer-7 scanner that attaches to the Configurabulator and produces a dedicated section in the topology report. Pure stdlib, no pip dependencies, to preserve the Configurabulator's single-file, zero-dependency footprint. Nmap maps the ports; this maps the website living behind them.

| Capability | Details |
|------------|---------|
| Fingerprint and headers | Redirect chain, status, Server / X-Powered-By, page title, tech detection, security-header audit (HSTS, CSP, X-Frame-Options), cookie flag analysis (Secure / HttpOnly / SameSite) |
| TLS and certificate | Subject / issuer / SAN, validity window, self-signed and hostname-mismatch detection, negotiated protocol and cipher, TLS 1.0 / 1.1 legacy probe |
| Content surface | robots.txt, sitemap.xml, HTTP methods (including active TRACE / XST check), short signature-confirmed path probe (`/.git/HEAD`, `/.env`, `/server-status`, soft-404 aware) |
| nmap http-NSE | Optional orchestration of `http-enum`, `http-headers`, `http-methods`, `http-title`, `http-vuln*`, gated behind `--web-nse` for tier discipline |

**Standalone use:**

```bash
python3 web_scan.py https://example.com --nse  # JSON to stdout
```

---

## CVE Coverage

**29 service families · 96 entries · 37 exploit-class MSF modules · 48 auxiliary scanners.** Local lookup, no internet required.

| Service | Highlights |
|---------|------------|
| **SMB / Samba** | EternalBlue (CVE-2017-0144), EternalRomance (CVE-2017-0145), SMBGhost (CVE-2020-0796), SambaCry (CVE-2017-7494), Samba usermap (CVE-2007-2447) |
| **DCERPC** *(135)* | Zerologon (CVE-2020-1472), PrintNightmare (CVE-2021-1675/34527), MS03-026 DCOM |
| **WinRM** *(5985/5986)* | Auth-method enum, login brute, command exec, script exec with valid credentials |
| **RDP** | BlueKeep (CVE-2019-0708), DejaBlue (CVE-2019-1182), MS12-020 DoS, NLA / CredSSP detection |
| **HTTP/S** | Shellshock (CVE-2014-6271), Apache path traversal (CVE-2021-41773/42013), Spring4Shell (CVE-2022-22965), Struts2 OGNL (CVE-2017-5638), PHP-FPM (CVE-2019-11043), **Log4Shell (CVE-2021-44228)**, **Confluence OGNL (CVE-2022-26134)**, **GitLab RCE (CVE-2021-22205)**, Jenkins, Tomcat, **Drupalgeddon2 (CVE-2018-7600)**, WordPress, JBoss, WebDAV |
| **AJP** *(8009)* | Ghostcat (CVE-2020-1938) |
| **Java RMI** *(1099)* | Insecure default config RCE |
| **IRC** *(6667)* | UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) |
| **distcc** *(3632)* | distccd command exec (CVE-2004-2687) |
| **FTP** | vsftpd 2.3.4 backdoor (CVE-2011-2523), ProFTPD overflow (CVE-2010-4221), anonymous access |
| **SSH** | ssh-agent RCE (CVE-2023-38408), username enum (CVE-2018-15473), brute-force |
| **MSSQL / MySQL** | xp_cmdshell RCE, hash dump, brute, FILE-privilege check, auth bypass (CVE-2012-2122) |
| **PostgreSQL** | COPY PROGRAM RCE (CVE-2019-9193), brute, hash dump |
| **Redis** | Unauthenticated replication RCE, Lua sandbox escape (CVE-2022-0543) |
| **Elasticsearch** | Groovy RCE (CVE-2014-3120), MVEL bypass (CVE-2015-1427) |
| **MongoDB** | Unauthenticated access, JS injection / collection enum |
| **VNC** | No-auth detection, brute-force |
| **SNMP** | Community string enum, share enum, Cisco IOS RCE (CVE-2017-6736) |
| **LDAP** | Anonymous bind, directory enumeration, brute |
| **DNS** | Zone transfer / AXFR / subdomain harvest |
| **NFS** | World-readable export enumeration |
| **Oracle** | Login brute, enumeration |
| **POP3 / IMAP** | Login brute (POP3), version enum (IMAP) |
| **Telnet** | BSD telnetd overflow (CVE-2011-4862), cleartext credential warning |
| **SMTP** | User enum (VRFY / EXPN / RCPT), open relay check |
| **RPC / NetBIOS** | Portmapper enumeration, NFS mount discovery |

Run `python3 validate_chain.py` against your local msfrpcd to verify every module path in the chain exists in your install.

---

## Pre-flight Checks

Checks run at startup in a background thread and display on the Dashboard.

| Check | Pass Condition |
|-------|---------------|
| Python version | 3.10 or newer |
| Privileges | Running as root (required for nmap SYN scans) |
| nmap | Installed and version 7 or newer |
| Configurabulator | `Nmap-Configurabulator.py` present in project root |
| Web scan module | `web_scan.py` present |
| Metasploit Framework | Module tree found at `/usr/share/metasploit-framework` |
| Flask | Importable |
| pymetasploit3 | Importable |
| Output directories | `scans/`, `reports/`, `loot/` exist and are writable |
| Disk space | 200 MB or more free |
| Port 5000 | Available |
| Listen address | Warns that `0.0.0.0:5000` is visible on all interfaces |
| Enum tools | Reports which enumeration tools are installed |
| SecLists wordlists | Present at `/usr/share/seclists/` |

Available via `GET /api/preflight`. Force-refresh via `POST /api/preflight/refresh`.

---

## Requirements

- **Kali Linux** or **Parrot Security** (recommended), or any Debian-based distribution
- **Python 3.10+**
- **nmap 7.x+**: `sudo apt-get install nmap`
- **Metasploit Framework**: pre-installed on Kali and Parrot
- **SecLists**: `sudo apt-get install seclists`

The Active Directory, lateral, emulation, and detection panes each wrap their own standard tool (Impacket, Responder, netexec, Certipy, bloodhound-python, hashcat, Invoke-AtomicRedTeam, CALDERA). Install the ones you intend to use; any that are absent surface as a "not on path" state in their pane rather than breaking the console.

---

## Installation

### Kali Linux / Parrot Security

`pip` is no longer supported for system packages on either distribution. Use `apt-get`:

```bash
# Core dependencies
sudo apt-get install -y python3-flask python3-pymetasploit3

# Enumeration tools, full coverage
sudo apt-get install -y \
  nikto whatweb gobuster sslyze sslscan \
  enum4linux-ng smbmap netexec smbclient samba-common-bin \
  onesixtyone snmp dnsrecon dnsenum \
  ldap-utils ldapdomaindump ssh-audit exploitdb \
  httpx-toolkit nbtscan feroxbuster nuclei testssl.sh \
  wpscan droopescan wafw00f ffuf kerbrute seclists

# Active Directory / lateral / cracking (install what you will use)
sudo apt-get install -y impacket-scripts responder certipy-ad \
  bloodhound.py hashcat evil-winrm
```

### Other Debian / Ubuntu

```bash
pip install -r requirements.txt
```

---

## Setup and Launch

```bash
# 1. Clone. The Configurabulator and web_scan are bundled.
git clone https://github.com/Null-H3x/h3x-dash.git
cd h3x-dash

# 2. Install dependencies
sudo apt-get install -y python3-flask python3-pymetasploit3

# 3. Validate dependencies and launch
sudo python3 install.py

# 4. Open the console
#    http://127.0.0.1:5000
```

H3x-Dash manages `msfrpcd` automatically:

1. On startup it checks whether `msfrpcd` is already listening on `127.0.0.1:55553`
2. If not, it launches `msfrpcd` in a background daemon thread with the configured credentials
3. Flask starts immediately, so the browser opens while `msfrpcd` initialises in the background
4. The Dashboard shows a live `msfrpcd` status strip (checking, starting, ready)
5. Once the port opens, the RPC auto-connect loop connects and MSF features become available

First startup may take 30 to 90 seconds while Metasploit loads its module tree and the module index builds in the background. Subsequent starts are faster.

**To skip auto-start** (when managing `msfrpcd` externally):

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

All defaults work out of the box. Settings are read from real environment variables, a local **`.env`** file, or the defaults, in that order (a real env var always wins over `.env`).

`install.py` pre-builds a `.env` on first run with a randomly generated `H3X_SECRET` (and the MSF and GitHub-token settings below), `chmod 600` and owned by the invoking user. It never clobbers an existing `.env`, and `.env` is gitignored.

| Variable | Default | Description |
|----------|---------|-------------|
| `H3X_SECRET` | *(random in `.env`)* | Flask session secret |
| `MSF_HOST` | `127.0.0.1` | msfrpcd host |
| `MSF_PORT` | `55553` | msfrpcd port |
| `MSF_PASS` | `msfrpc` | msfrpcd password |
| `MSF_SSL` | `false` | Set `true` if msfrpcd was started without `-S` |
| `GITHUB_TOKEN` | *(empty)* | Optional. Raises the GitHub API rate limit for the Payload page's vetted-source updater. |

```bash
MSF_PASS=strongpassword H3X_SECRET=changeme sudo python3 h3x-dash.py
```

---

## Validation Tools

Offline and online checks ship with the codebase. Run them after any change to the chain, enum runners, or exploit engine to catch regressions before they reach the console.

| Script | Mode | What it checks |
|--------|------|----------------|
| `python3 audit/audit_all.py` | Offline | Runs the full audit suite |
| `python3 audit/audit_chain.py` | Offline | Internal consistency of `modules/cve_chain.py` |
| `python3 audit/audit_enum.py` | Offline | Enum runner and tier-dispatch integrity |
| `python3 audit/audit_exploit.py` | Offline | Exploit session-survival wiring |
| `python3 audit/audit_msf_runner.py` | Offline | Mock-RPC exercise of the exploit runner |
| `python3 audit/audit_scan.py` | Offline | Scan-mode wiring |
| `python3 audit/audit_payload_sources.py` | Offline | Vetted payload allowlist and access flows |
| `python3 audit/audit_credentials.py` | Offline | Credential store and parsers |
| `python3 audit/audit_loot.py` | Offline | Loot report generation and download safety |
| `python3 audit/audit_msf_session.py` | Offline | Shell session listing robustness |
| `python3 validate_chain.py` | Online | Verifies every chain module path exists in your live MSF install |
| `python3 shell_doctor.py` | Online | Live Shell/session diagnostic across stages |

**Typical workflow when extending the chain:**

```bash
python3 audit/audit_chain.py     # internal consistency, 0 FAIL required
python3 validate_chain.py        # MSF reality check, 0 missing required
python3 audit/audit_enum.py      # only if you touched enum_engine.py
```

---

## Session Troubleshooting (`session.py`)

A standalone, clean-terminal tool for inspecting and interacting with the MSF sessions H3x-Dash creates. It talks directly to `msfrpcd` (ground truth) and cross-checks the console's API, so you can tell a hidden-but-live shell apart from a zombie tab without guessing. It imports nothing from the app, so it works even when the web UI is misbehaving.

```bash
python3 session.py list         # live sessions plus diff against the UI
python3 session.py doctor       # full msfrpcd, API, jobs/handlers report
python3 session.py watch 2      # flag sessions opening/dying in real time
python3 session.py info 1       # everything msfrpcd knows about session 1
python3 session.py run 1 id     # run one command, print the output
python3 session.py interact 1   # interactive prompt (:info  :raw  :quit)
```

Connection uses the same defaults as H3x-Dash (`MSF_HOST` `MSF_PORT` `MSF_PASS` `MSF_SSL`), overridable with `--host/--port/--password/--ssl`. Add `--no-api` to skip the console comparison entirely.

---

## Project Structure

```
h3x-dash/
├── h3x-dash.py                       Flask core: routes, SSE endpoints, JSON API
├── config.py                         Path and connection configuration
├── requirements.txt                  pip dependencies (non-Kali environments)
├── Nmap-Configurabulator.py          bundled enumeration engine (Layer 3/4)
├── web_scan.py                       bundled Layer 7 web scanner
├── validate_chain.py                 online msfrpcd module-path validator
├── session.py                        standalone MSF session inspector
├── shell_doctor.py                   live session diagnostic
├── audit/                            offline audit suite (audit_all.py runs them all)
├── docs/
│   └── H3x-Dash-Operator-Guide.md    module-by-module operator guide
│
├── modules/
│   ├── preflight.py                  environment validator
│   ├── nmap_engine.py                Configurabulator wrapper + scan state machine
│   ├── enum_engine.py                35-tool enumeration dispatcher (tiered)
│   ├── cve_chain.py                  port/service to CVE to MSF module lookup
│   ├── cve_intel.py                  CVE intelligence lookups
│   ├── msf_engine.py                 Metasploit RPC wrapper with auto-reconnect
│   ├── msf_scanner.py                local MSF module scanner + CVE index
│   ├── ad_engine.py                  Active Directory attack paths (Responder,
│   │                                 Kerberoast, BloodHound, Impacket, Certipy, Coercion)
│   ├── c2_engine.py                  synthetic beacon emitter (detection validation)
│   ├── emulation_engine.py           Atomic Red Team / CALDERA / playbook runner
│   ├── msel.py                       scenario scheduler engine + /api/msel blueprint
│   ├── cease.py                      global halt coordinator + /api/cease blueprint
│   ├── mitre_mapping.py              action to ATT&CK technique mapping
│   ├── implant_engine.py             device registry + payload library
│   ├── payload_sources.py            vetted GitHub payload-source allowlist
│   ├── report_engine.py              engagement report generation
│   └── loot.py                       loot store + HTML/JSON reports
│
├── templates/
│   ├── console.html                  Purple Ops Console (primary single-page UI)
│   ├── base.html                     legacy theme, sidebar, authorization modal
│   ├── dashboard.html  scan.html  enumerate.html  exploit.html
│   ├── shell.html  loot.html  modules.html  payload.html  spectrum.html
│   ├── validate.html  credentials.html   (legacy multi-page views)
│   └── partials/
│
├── static/
│   ├── scale.js                      uniform fixed-scale zoom
│   ├── cease.js                      global halt control
│   └── h3x-dash.js                   SSE client, shared fetch utilities
│
├── scans/    reports/    loot/    logs/     runtime output, gitignored
└── msf_modules_cache.json.gz         MSF module index cache, gitignored
```

---

## API Reference

H3x-Dash exposes its functionality over a JSON API. Both the console and the legacy pages run over these endpoints. Key groups:

| Group | Purpose |
|-------|---------|
| `scan` | Start / stop / status / results / history / stream |
| `enum` | Start / stream / status / findings / tools |
| `cve`, `cve_intel` | Chain suggestions and CVE intelligence lookups |
| `modules` | Local MSF module search, CVE match, stats, rescan |
| `msf` | Connect, status, search, run, sessions, session commands, daemon control |
| `creds` | Captured credential store |
| `ad` | Active Directory panes (Responder, Kerberoast, BloodHound, Impacket, Certipy, Coercion) |
| `c2` | Synthetic beacon control |
| `emulation` | Atomic Red Team, CALDERA, and playbook runs |
| `mitre` | ATT&CK technique mapping and coverage |
| `msel` | Scenario scheduler (blueprint) |
| `cease` | Global halt and status (blueprint) |
| `implants`, `wireless` | Payload devices and Spectrum hardware |
| `report`, `loot` | Report generation and downloads |
| `preflight`, `ops`, `network`, `evasion`, `classify`, `plugins` | Health, activity log, helpers |

SSE endpoints (`/api/scan/stream`, `/api/enum/stream`) accept a `client_id`; use the server-assigned ID from the corresponding `start` response.

---

## Vetted Payload Sources

The Payload page ships a curated baseline catalog. The **LIBRARY** sub-tab extends it with an access update that pulls payloads from a strict allowlist of vetted GitHub repositories and merges them into the library.

| Source | Repository | Products |
|--------|------------|----------|
| Hak5 USB Rubber Ducky | `hak5/usbrubberducky-payloads` | Rubber Ducky |
| Hak5 Bash Bunny | `hak5/bashbunny-payloads` | Bash Bunny |
| Hak5 Shark Jack | `hak5/sharkjack-payloads` | Shark Jack |
| Hak5 LAN Turtle | `hak5/lanturtle-modules` | LAN Turtle |
| Hak5 Packet Squirrel | `hak5/packetsquirrel-payloads` | Packet Squirrel |
| Hak5 Key Croc | `hak5/keycroc-payloads` | Key Croc |
| Hak5 Signal Owl | `hak5/signalowl-payloads` | Signal Owl |
| O.MG | `hak5/omg-payloads` | O.MG Plug / Adapter / UnBlocker / Cable |

The allowlist is the security boundary, enforced in depth:

- The update endpoint refuses any source not on the allowlist.
- Every outbound request URL is built solely from a vetted entry's `org`/`repo`; no operator-supplied string ever reaches the URL.
- The fetcher re-validates that the host is exactly `api.github.com` and the path targets the expected `/repos/<org>/<repo>/` prefix before any byte is sent, and re-checks after any redirect.
- STDLIB-only pull via `urllib`, no new pip dependency. An unreachable source is reported, not fatal.
- Synced payloads default to `callback: none`; a freshly pulled payload never auto-stages a handler. The operator reviews the source and wires the callback deliberately.

Run `python3 audit/audit_payload_sources.py` to verify the allowlist shape, URL validation, tree-parsing, and library merge offline.

---

## Building a Lab

Your home network is not a lab. Before running H3x-Dash against any target, build a purpose-built vulnerable environment.

| Platform | Focus |
|----------|-------|
| **Metasploitable 2** | Covers the bulk of this tool's CVE map (Samba usermap, vsftpd, UnrealIRCd, distcc, Java RMI) |
| **Metasploitable 3** | Windows and Linux, more modern attack surface, plus AD-side coverage |
| **GOAD (Game of Active Directory)** | Purpose-built vulnerable AD forest for the Creds and AD, lateral, and coercion panes |
| **VulnHub** | Downloadable CTF-style VMs at all difficulty levels |
| **DVWA** | Web application testing |

Metasploitable 2 alone validates roughly half the CVE chain. Pair it with Metasploitable 3 for Windows-side coverage, and a vulnerable AD lab such as GOAD to exercise the Kerberoast, BloodHound, DCSync, ADCS, coercion, and lateral panes end to end.

---

## Security and Legal

This tool is built exclusively for authorized security testing. See [SECURITY.md](SECURITY.md) for the full responsible-use policy and vulnerability disclosure process.

Three rules, no exceptions:

1. **Closed environment only.** Lab networks, air-gapped ranges, and purpose-built vulnerable systems. Not production. Not shared infrastructure. Not cloud environments without explicit provider authorization.
2. **Systems you own.** Hardware, lease, or service agreement in your name. "I have admin credentials" is not ownership.
3. **Written permission required.** A current, signed testing agreement for any system you do not personally own. Verbal consent is not an agreement. Expired agreements are not agreements.

Unauthorized use of this tool is a federal crime under **18 U.S.C. § 1030** (Computer Fraud and Abuse Act) and equivalent legislation in most jurisdictions. The developer accepts no liability for unauthorized use. Every consequence is the sole responsibility of the operator.

An authorization acknowledgment is presented at the start of every browser session and requires explicit confirmation before the tool is accessible.

---

## Contributing

Pull requests welcome. The codebase is structured so new engines drop in cleanly alongside the existing `modules/`.

**High-value additions:**

- **More ATT&CK coverage in the reconciliation layer.** Extend `mitre_mapping.py` so more actions resolve to techniques, tightening the hit / partial / miss picture in Detection Coverage.
- **Additional CVE mappings.** `cve_chain.py` is a plain dict. Add entries as `(CVE_string_or_None, msf_module_or_None, description, severity)` and include a source reference.
- **Title-pattern auto-confirmation.** Teach `cve_chain.suggest()` to recognise more banner and version strings so the matching module auto-promotes.
- **New emulation content.** Additional playbook chains or CALDERA adversary profiles for the Emulation workspace.
- **Report templates.** The report engine's HTML renderer is self-contained. Alternative formats (PDF, DOCX, PPTX) would be a direct addition.

**Before submitting:**

- Run the audit suite. Every PR that touches `cve_chain.py` or `enum_engine.py` must pass `audit_chain.py` and `audit_enum.py` clean; exploit changes must pass `audit_exploit.py` and `audit_msf_runner.py`.
- Run `validate_chain.py` against a live msfrpcd if you added MSF module paths.
- Test against Metasploitable 2/3 (or a vulnerable AD lab for the AD panes) before opening a PR.

---

## Acknowledgements

- **Nmap** and **Metasploit Framework**, the foundation of phases one and two, with **pymetasploit3** as the Python bridge
- **[Nmap Configurabulator](https://github.com/Null-H3x/nmap-configurobulator)**, the Layer 3/4 enumeration engine under the hood
- **Project Discovery**, for the `httpx`, `nuclei`, `ffuf` family that anchors modern web triage
- **SecLists**, the wordlists the content-discovery and brute-force tools rely on
- **Impacket**, **Responder**, **NetExec** (formerly CrackMapExec), **enum4linux-ng**, **Certipy**, **BloodHound**, **kerbrute**, **hashcat**, and **ldapdomaindump** for the credential and Active Directory tooling
- **MITRE**, for **ATT&CK**, **CALDERA**, and the **Atomic Red Team** project that make the emulation and coverage work possible
- Every CVE researcher whose work appears in the mapping table. The vulnerability was found by someone else; this tool just connects the dots to the module that exploits it.

---

<div align="center">

`H3x-Dash // Offensive Security and Purple-Team Console`
`// Built by Null-H3x // Authorized Use Only // Always //`

</div>
