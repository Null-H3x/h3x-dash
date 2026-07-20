# H3x-Dash Operator Guide

Version 0.9.90.70 "Purple Ops Console"

This guide is a module-by-module reference for operating H3x-Dash during an authorized assessment or field exercise. It explains what each tool does, the parameters you set, where the tool fits in the kill chain, what a good result looks like, and how to tell success from failure. Read the Operating Model section first. Everything after it is organized to match the console tab layout.

---

## Operating Model (read this first)

H3x-Dash is an orchestration console. It does not invent capability. Every action is carried out by a standard, separately installed tool (nmap, netexec, Impacket, Responder, Certipy, BloodHound, CALDERA, Atomic Red Team, Metasploit, and so on). The console schedules those tools, streams their real output, stores their real findings, and reconciles them against detections. There is no synthetic telemetry. If a tool is not installed or not reachable, the pane shows a clear "TOOL NOT ON PATH" state rather than faking a result.

Four rules govern safe use:

1. **Authorized scope only.** Run H3x-Dash only against systems you are cleared to assess, on the network and ports named in your authorization. The MSEL timeline records every target you touch so the record doubles as a deconfliction log.
2. **Captured credentials only.** The Active Directory and lateral movement panes pull secrets from the loot store. There is no free-text secret entry. You capture or extract a credential first, then reuse it.
3. **The beacon is a detection emitter, not real command and control.** The C2 pane sends known-signature callbacks so defenders can practice catching them. It is scoped for detection validation, not stealth.
4. **The Cease Buzzer is your stop control.** It is present on every screen. When in doubt, hit it.

---

## Global Control: Cease Buzzer (ENDEX)

**Purpose and function.** The red pulsing button at the top of the left sidebar is a single global halt. One click opens a confirmation modal. "CEASE ALL" invokes every registered stop path at once: the active scan, the enumeration suite, all Metasploit sessions, the emulation engine, all beacon jobs, and the MSEL scheduler. It then shows a per-subsystem report with a green check or a red mark for each, so you know exactly what stopped. An optional "Shut Down Server" action stops the console process itself.

**Parameters.** None to configure. It writes an append-only ENDEX record to `logs/cease.log.jsonl` with a timestamp, the reason, and the per-subsystem outcome.

**In the chain.** It sits outside the chain by design. It is the emergency brake for any state.

**Expected results.** The report lists each subsystem and whether its halt succeeded. Enumeration reports the number of in-flight tool processes it killed. Beacons report the number of jobs signaled. Metasploit reports killed and failed session counts.

**Success vs failure.** Success is every row green and, where relevant, honest nonzero counts (for example "enum: 3 killed"). A red row means that subsystem reported an error while stopping. It is still logged truthfully rather than masked.

**Notes.** The halt is the safety-critical part and works independently of the shutdown action. Under a development reloader the shutdown behavior can vary, but the halt always fires.

---

## EXERCISE Workspace

### MSEL Scheduler

**Purpose and function.** The Master Scenario Events List drives a scripted exercise. It fires timed or manual injects and records a ground-truth timeline of what happened and when. An inject is a noticeable event meant to provoke a defender reaction (a ping, a scan, an enumeration pass, a beacon, and so on). Each inject type dispatches to an adapter that calls a real engine already wired in the console. Unwired types fail honestly with HANDLER_NOT_REGISTERED and are never faked as success.

**Parameters per inject.** Name, type (scan, enum, beacon are wired out of the box; ping, shell, pivot, custom are available to wire), target (an in-scope host or range), unit (the subordinate element the inject belongs to), phase (recon, delivery, lateral, and so on), and a trigger. Trigger options are manual (fires only when you click Fire), offset (fires at exercise T plus N seconds), absolute (fires at a wall-clock time), and after (fires a set delay after another inject completes).

**Controls.** Arm starts the exercise clock. Pause and Resume gate firing without losing state. Abort is the scheduler-level master stop. Reset clears runtime state while keeping the authored list and the timeline. Save and Load persist the list to disk.

**In the chain.** The MSEL sits on top of the recon and access tooling. It is how you sequence a repeatable scenario so the blue team sees the same stimulus at the same relative time on every run.

**Expected results.** As injects fire, the timeline appends fire, complete, error, and abort events with timestamps and durations. Scan injects return host counts, enum injects return finding counts, beacon injects return the number of callbacks sent.

**Success vs failure.** Success is an inject moving from armed to firing to complete with a real result attached. Failure is a red status with the reason recorded (for example a scan that could not start, or an unwired type). The append-only timeline is the authoritative record for the after-action review.

**Notes.** Beacon injects are bounded (a maximum callback count) so they complete rather than run forever. The timeline file under `logs/msel/` is your attacker ground truth for reconciliation.

---

## OVERVIEW Workspace

### Dashboard

**Purpose and function.** The landing view. It summarizes current posture: discovered host count, recent activity, loot totals, and the live Metasploit RPC connection state shown in the top status dock.

**Parameters.** None. It reads state from the other engines.

**In the chain.** Start and end here. It is the situational-awareness view between actions.

**Expected results.** Counts and recent-event lists that match what you have actually run this session.

**Success vs failure.** If the dashboard shows zero hosts after a scan you expected to succeed, treat the scan as the thing to investigate, not the dashboard.

**Notes.** The top status dock also shows the SIEM monitoring indicator and the current target range.

---

## RECON & ENUM Workspace

### Scan (Nmap Configurabulator)

**Purpose and function.** Port and service discovery built on nmap. It produces the host and open-port inventory that the rest of the console consumes.

**Parameters.**
- **Scan mode:** network (multi-service port discovery), web (HTTP and HTTPS ports plus a Layer-7 fingerprint), or web_only (skip nmap and profile a URL or IP at Layer-7 only).
- **Port profile:** driveby (high-value ports across common services, a fast default), spyglass (top 1024 plus database, RDP, and web extras for a balanced internal sweep), web (HTTP and alternate web ports only), or full (all 65535 ports, slow, use on single hosts or tiny ranges).
- **Timing:** T1 through T5. T1 is slow and evasive, T3 is nmap default, T4 is fast and reliable on a LAN and is the general recommendation, T5 is maximum speed and may drop packets.
- **Script profile:** none, banner, default, safe, vuln, or full. Higher profiles run more NSE scripts and take longer.
- **Stealth level 0 to 3:** layers evasion flags (timing, fragmentation, decoys). Level 0 adds nothing. Operator-supplied extra arguments always win over the evasion flags.

**In the chain.** This is step one. Its results feed Topology, Web Scan, Enum Suite, the CVE chain, and every downstream access module.

**Expected results.** A streamed nmap run followed by a parsed host list with per-host open ports and service guesses. The banner lines echo the port profile, timing, and any stealth profile in effect.

**Success vs failure.** Success is a nonempty host list with the ports you expected on known hosts. Failure modes are an empty result (wrong target, host down, or ports filtered) and a "nmap not found" preflight failure (install nmap on the box).

**Notes.** Root or equivalent privilege enables SYN scanning. On a large range, prefer driveby or spyglass over full.

### Topology

**Purpose and function.** A live D3 graph of discovered hosts, their open ports tiered by risk, and the relationships between them. It turns the scan inventory into a picture.

**Parameters.** None to run. It renders whatever the current scan produced.

**In the chain.** Read it right after a scan to pick targets and to spot high-value services quickly.

**Expected results.** Nodes for hosts, edges and port markers colored by risk tier.

**Success vs failure.** An empty graph means no hosts have been discovered yet. Run a scan first.

**Notes.** The same topology graphic is embedded in the engagement report.

### Web Scan

**Purpose and function.** A Layer-7 look at web services: response headers, technology fingerprint, page titles and TLS details, and an http-focused NSE surface.

**Parameters.** Target URL or host, and whether to pair with the scan web mode. It draws candidate web ports from the scan results when available.

**In the chain.** Run after the scan flags web ports, and before you decide which web hosts warrant deeper enumeration or exploitation.

**Expected results.** Per-host web profiles: server and framework fingerprints, headers, TLS posture, and notable findings.

**Success vs failure.** Success is a populated fingerprint for each live web host. A host that returns nothing is either not serving on the tested ports or is filtering the probes.

**Notes.** Pairs naturally with the web-oriented enumeration tools below (whatweb, nikto, and the fuzzers).

### Enum Suite

**Purpose and function.** Service-specific enumeration that runs the right Kali tools for each open port in parallel per host, streams their output, and builds structured findings that enrich the CVE chain. It is the deepest recon step.

**Parameters.** Target hosts (drawn from scan results by default) and per-tool options. Tool selection is driven by the ports found. The suite wraps a broad tool set, including web (whatweb, nikto, wpscan, droopescan, gobuster, feroxbuster, ffuf, httpx, nuclei, wafw00f), TLS (sslyze, sslscan, testssl), SMB and Windows (enum4linux-ng, smbmap, smbclient, rpcclient, nbtscan, netexec or nxc, crackmapexec), directory and LDAP (ldapsearch, ldapdomaindump), Kerberos pre-auth (kerbrute), SNMP (onesixtyone, snmpwalk), DNS (dnsrecon, dnsenum), SSH (ssh-audit), SMTP (smtp-user-enum), and local exploit search (searchsploit).

**In the chain.** Runs after the scan and web scan. Its findings feed the CVE chain and the exploit resolver, and its SMB, LDAP, and Kerberos output seeds the Active Directory panes.

**Expected results.** A live stream per tool and a growing findings list per host. Findings are categorized so downstream panes can consume them.

**Success vs failure.** Success is findings attached to hosts and a clean completion state. A tool that is not installed prints a SKIP line and is passed over rather than failing the whole run. If enumeration hangs against a Windows host, the process-group kill path clears it, and you can also use the operator stop.

**Notes.** Enumeration honors a hard stop. The Cease Buzzer and the enum stop control both suppress pending tool launches and kill in-flight process trees, so runaway tools against a domain controller can always be halted.

### MSF Scanners

**Purpose and function.** Metasploit auxiliary scanner modules used to confirm and characterize services after initial recon (for example version and configuration checks).

**Parameters.** Module selection and standard Metasploit options (RHOSTS drawn from discovered hosts, thread count, module-specific settings). Requires a live msfrpcd connection.

**In the chain.** Runs after the scan to confirm findings before you commit to exploitation.

**Expected results.** Per-module output confirming or ruling out a condition on the target set.

**Success vs failure.** Success is a module completing with a clear positive or negative on each host. Failure is usually a missing Metasploit install or an unavailable RPC connection, both shown in the status dock.

**Notes.** Uses the low-level Metasploit RPC interface, so mocked test runs must model that interface faithfully.

---

## ACCESS Workspace

### Exploit

**Purpose and function.** Turns recon into access. It builds a CVE chain from findings, resolves candidate Metasploit modules, and runs the chosen exploit against a target.

**Parameters.** Target host and port, the resolved module, and its options (payload, LHOST, LPORT, and module settings). Candidate modules come from the CVE chain and the exploit resolver.

**In the chain.** Runs after enumeration and MSF scanning have identified a likely vulnerability. On success it produces a session that the Sessions pane manages.

**Expected results.** A streamed exploitation attempt ending in a session opened or a clean miss.

**Success vs failure.** Success is "session opened" and a new entry in Sessions. Failure is a module that runs but does not land, which is normal and expected against patched or hardened targets. Read the module output to understand why.

**Notes.** Exploitation depends on a working Metasploit install and RPC connection.

### Validate

**Purpose and function.** Confirms outcomes and assigns verdicts. It checks that an exploit actually produced the access it claimed and records a verdict for the report.

**Parameters.** The host or finding to validate, and the verdict criteria.

**In the chain.** Runs right after Exploit to separate a real foothold from a false positive before you build on it.

**Expected results.** A verdict per checked item (for example confirmed, unconfirmed, or failed) with supporting evidence.

**Success vs failure.** Success is a confirmed verdict backed by evidence. An unconfirmed verdict is a signal to revisit the exploit step, not to proceed as if you have access.

**Notes.** Verdicts flow into the engagement report and the coverage reconciliation.

### Sessions / Shell

**Purpose and function.** Manages live sessions and gives you an interactive shell. It handles session listing, selection, and the handoff needed to keep a shell stable.

**Parameters.** Session id selection and the commands you issue in the shell.

**In the chain.** Runs after a successful exploit. It is where you operate on a foothold and where lateral movement often begins.

**Expected results.** A responsive shell tied to a session, with output streamed back to the console.

**Success vs failure.** Success is a stable, responsive session. A session that dies or thrashes points to a handoff or stability issue on the target side.

**Notes.** Sessions can be killed individually, and the Cease Buzzer kills them all at once.

### Payloads

**Purpose and function.** Generates and manages payloads and payload sources for use in exploitation and access.

**Parameters.** Payload type, format, and connection settings (LHOST, LPORT, encoders where applicable).

**In the chain.** Prepared before or alongside exploitation, then consumed by the Exploit pane.

**Expected results.** A generated payload artifact or a selected payload ready for a module.

**Success vs failure.** Success is a payload that matches your listener and target. A mismatch between payload architecture and target is the common failure.

**Notes.** Keep payload connection settings consistent with your listener configuration.

### Spectrum

**Purpose and function.** Radio frequency and wireless operations: device control, recon sweeps, and handshake capture. This is the spectrum-side workflow.

**Parameters.** Interface and device selection, sweep parameters, and capture settings.

**In the chain.** A parallel recon track for wireless targets rather than a step in the wired chain.

**Expected results.** Device and signal discovery output and captured handshakes where applicable.

**Success vs failure.** Success is a controllable interface and usable captures. Failure is usually a missing or unsupported adapter.

**Notes.** Wireless work has its own authorization considerations. Confirm your spectrum authorization separately.

---

## CREDS & AD Workspace

### Loot Creds

**Purpose and function.** The captured credential store. Every credential the console captures or extracts lands here, and every AD and lateral pane draws from it.

**Parameters.** Filtering and selection. Credentials carry a type (for example password or NTLM hash) that downstream tools use.

**In the chain.** Central. Capture or extract a secret, then select it in a downstream pane. There is no manual secret entry, so this store is the single source.

**Expected results.** A list of captured credentials with type, source, and associated principal.

**Success vs failure.** Success is a growing store as capture and extraction succeed. An empty store means no capture step has landed yet.

**Notes.** Treat this store as sensitive. It holds real captured material during a live assessment.

### Responder + Relay

**Purpose and function.** Poisons LLMNR, NBT-NS, and mDNS to capture authentication, and relays it with ntlmrelayx to SMB, LDAP, or ADCS targets. Maps to ATT&CK T1557.001 (LLMNR/NBT-NS poisoning) and T1187 (forced authentication).

**Parameters.** Interface, poisoning toggles, and relay target and protocol.

**Tools.** Responder and ntlmrelayx from Impacket.

**In the chain.** An early credential-access play on an internal network. Captured hashes land in Loot, and relayed sessions can enable movement.

**Expected results.** Captured NetNTLM hashes and, when relayed, actions against the relay target.

**Success vs failure.** Success is captured authentication in the loot store and a completed relay. Detection-wise, expect the ET LLMNR and NBT-NS poisoning signatures and the Sigma Responder capture rule to fire, with unexpected machine-account logons as a partial indicator.

**Notes.** Poisoning is loud by design. In an exercise that is the point.

### Kerberoast / AS-REP

**Purpose and function.** Requests service tickets (GetUserSPNs) and AS-REP roastable tickets (GetNPUsers), then hands the RC4 material to hashcat for offline cracking. Maps to T1558.003 (Kerberoasting) and T1558.004 (AS-REP roasting).

**Parameters.** Domain and credential context (from Loot for GetUserSPNs), target user lists where relevant, and the hashcat mode.

**Tools.** Impacket GetUserSPNs and GetNPUsers, and hashcat.

**In the chain.** A credential-access step once you have any domain foothold or a valid low-privilege account. Cracked passwords return to Loot for reuse.

**Expected results.** Roastable hashes exported and, after cracking, plaintext passwords added to Loot.

**Success vs failure.** Success is recovered credentials. Detection-wise, the 4769 RC4 ticket request pattern and the Sigma Kerberoasting rule should fire.

**Notes.** RC4 ticket requests are the detection signature. Expect them to light up the SIEM in a well-instrumented environment.

### BloodHound

**Purpose and function.** Collects Active Directory data with SharpHound or bloodhound-python and maps attack paths to high-value targets in neo4j. Maps to T1087.002 (domain account discovery) and T1482 (domain trust discovery).

**Parameters.** Domain, collection method and scope, and a credential from Loot.

**Tools.** bloodhound-python, SharpHound, and neo4j.

**In the chain.** Runs once you have a domain credential. Its paths tell you which coercion, roasting, or movement play to run next.

**Expected results.** A collected dataset and a graph of principals, sessions, and privileges revealing paths.

**Success vs failure.** Success is a complete collection and a usable graph. A large 4662 event volume and Zeek LDAP activity are the detection surface, so expect a partial hit on the SharpHound burst rule.

**Notes.** Collection is bursty and visible in LDAP and directory-access telemetry.

### Impacket-AD (secretsdump / DCSync)

**Purpose and function.** Extracts credential material from a domain controller, including DCSync-style replication of secrets. Maps to T1003.006 (DCSync).

**Parameters.** DC target and a privileged credential from Loot (a DCSync-capable principal).

**Tools.** Impacket secretsdump.

**In the chain.** A late credential-access step that typically requires elevated domain rights, often obtained through the earlier AD plays. Extracted hashes return to Loot.

**Expected results.** Extracted account hashes and secrets from the target.

**Success vs failure.** Success is a full extraction. The DRSUAPI replication pattern is a strong detection signal, so expect the Sigma DCSync rule to fire on a monitored DC.

**Notes.** This is one of the loudest and highest-impact actions in the suite. Confirm it is in scope.

### Certipy / ADCS

**Purpose and function.** Enumerates and abuses Active Directory Certificate Services misconfigurations across the ESC1 through ESC8 classes. Maps to T1649 (steal or forge certificates).

**Parameters.** CA and template targets, the ESC technique, and a credential from Loot.

**Tools.** Certipy.

**In the chain.** A privilege-escalation and persistence path once you can reach ADCS. Certificate-based authentication material feeds back into access.

**Expected results.** Enumerated vulnerable templates and, on abuse, a certificate usable for authentication.

**Success vs failure.** Success is a usable certificate or confirmed misconfiguration. Certificate enrollment events (4886 and 4887) are the detection surface, and these techniques are frequently under-detected, so treat a miss on the enrollment rules as a coverage gap to report.

**Notes.** ADCS abuse is a common gap in blue-team coverage. Document what did and did not alert.

### Coercion

**Purpose and function.** Forces a target machine to authenticate to a host you control, using PetitPotam (EFSRPC) or the PrinterBug (MS-RPRN). Maps to T1187 (forced authentication).

**Parameters.** Coercion target, the listener you are coercing toward (often a relay), and the method.

**Tools.** PetitPotam and printerbug (dementor).

**In the chain.** Pairs with Responder and Relay. Coerce a machine account, relay its authentication, and gain the access that enables further movement or extraction.

**Expected results.** Inbound authentication from the coerced machine account at your listener.

**Success vs failure.** Success is the target authenticating on cue. Detection-wise, the Sigma PetitPotam EFSRPC rule should fire, with the PrinterBug path as a partial indicator.

**Notes.** Highly effective as a relay trigger. Sequence it with the relay running first.

---

## LATERAL / C2 Workspace

### Lateral Movement

**Purpose and function.** Moves between hosts using the Impacket exec family and related tools, with pass-the-hash and pass-the-ticket support. Maps to T1021.002 (SMB admin shares), T1047 (WMI), T1053.005 (scheduled task), and T1550.002 (pass the hash).

**Parameters.** Target host, execution method (psexec, smbexec, wmiexec, dcomexec, atexec, or evil-winrm), and a credential from Loot (a password, an NTLM hash for pass-the-hash, or a ticket for pass-the-ticket).

**Tools.** Impacket exec modules, evil-winrm, and netexec.

**In the chain.** Runs after you hold a reusable credential. It is how a single foothold becomes domain-wide reach.

**Expected results.** Command execution or an interactive session on the remote host.

**Success vs failure.** Success is execution on the target. Detection-wise, expect service-creation event 7045 for psexec, WMI process-create for wmiexec, and SMB pipe activity, with the Sigma PsExec and SMBExec rules firing on a monitored host.

**Notes.** Credentials come only from Loot. Capture or extract first, then move.

### C2 Beacon Emulator

**Purpose and function.** Emits synthetic command-and-control beacons: jittered HTTP, HTTPS, or DNS callbacks with a tunable sleep interval and malleable profiles. It exists so defenders can practice detecting beaconing. It is not a real implant and has no post-exploitation capability. Maps to T1071.001 (web protocols), T1571 (non-standard port), and T1573 (encrypted channel).

**Parameters.** Callback sink (URL or domain), transport (http, https, or dns), profile, sleep interval, jitter percentage, and a maximum callback count so a run terminates.

**Tools.** The built-in synthetic beacon emitter.

**In the chain.** Runs standalone for detection validation, or as an MSEL inject so the beacon fires on the exercise clock. It is intentionally not integrated into the exploitation chain.

**Expected results.** A series of callbacks at the configured cadence, visible in your own logs and to the blue team's network sensors.

**Success vs failure.** Success is the callbacks being sent and, from the blue-team side, being detected. Expect a RITA interval-beacon hit and a partial Suricata JA3 hit, with a Zeek long-connection indicator pending on longer runs.

**Notes.** Because it uses known signatures, treat a detection miss here as a coverage finding, not a stealth win.

---

## EMULATION Workspace

### Atomic Red Team

**Purpose and function.** Runs Invoke-AtomicRedTeam atomics, which are small, portable, ATT&CK-mapped tests built specifically for detection validation. Example coverage includes T1218.011 (rundll32), T1059.001 (PowerShell), and T1547.001 (run-key persistence).

**Parameters.** Technique or atomic selection and any input arguments the atomic requires. Requires Invoke-AtomicRedTeam installed. The pane refuses to fake execution if it is not present.

**Tools.** Invoke-AtomicRedTeam.

**In the chain.** A targeted way to test one technique's detection without running a full intrusion.

**Expected results.** The atomic executes and produces the artifact it is designed to produce (a process, a registry write, a script block), which the SIEM should catch.

**Success vs failure.** Success is the atomic running and the matching detection firing (for example the Sigma rundll32 LOLBAS, PowerShell script-block, or run-key rules). A missed detection is a coverage gap to record.

**Notes.** Atomics are the cleanest way to fill specific squares of the ATT&CK matrix on demand.

### CALDERA

**Purpose and function.** MITRE CALDERA runs autonomous, chained adversary emulation across the ATT&CK matrix using a server and agents. Example coverage includes T1059 (command interpreters), T1053 (scheduled tasks), and T1105 (ingress tool transfer).

**Parameters.** Adversary profile selection, agent and group targeting, and run controls. Requires a reachable CALDERA server and deployed agents.

**Tools.** MITRE CALDERA server and agents.

**In the chain.** A hands-off way to run a multi-step scenario so the blue team faces a realistic sequence rather than isolated actions.

**Expected results.** Agents beacon in and execute abilities in sequence, generating endpoint and network telemetry.

**Success vs failure.** Success is abilities executing and the expected detections firing. Expect a partial hit on agent-beacon detection and a hit on ability-execution rules.

**Notes.** CALDERA is autonomous once started. Keep the Cease Buzzer in reach.

### Scenario Playbooks

**Purpose and function.** Named-actor and ransomware-precursor scenario chains that sequence an end-to-end intrusion emulation. Example coverage includes T1486 (data encrypted for impact, emulated), T1490 (inhibit system recovery), and T1070.001 (clear Windows event logs).

**Parameters.** Playbook selection and scope. The chain runner sequences the steps.

**Tools.** The built-in chained scenario runner.

**In the chain.** The most complete emulation option. Use it to exercise the full detection and response pipeline against a known adversary pattern.

**Expected results.** A sequenced run with each stage generating its telemetry, ending in the impact-emulation stage.

**Success vs failure.** Success is the chain completing and the high-value detections firing (shadow-copy deletion, event-log clearing at 1102, and mass file rename as a partial indicator for ransomware precursors).

**Notes.** Ransomware-precursor emulation stops short of real destruction. Confirm the scope of any impact stage before running.

---

## REPORT & PURPLE Workspace

### Engagement Report

**Purpose and function.** Builds a client-deliverable report that pulls the scan inventory, captured credentials, exploit outcomes, verdicts, and ATT&CK coverage into one document, with the topology graphic embedded.

**Parameters.** Report scope and inclusion options. It reads from the engines rather than requiring manual entry.

**In the chain.** Runs at the end, or at any milestone you want to capture.

**Expected results.** A structured report reflecting exactly what you ran and found this engagement.

**Success vs failure.** Success is a report whose contents match your session activity. If a section is empty, the underlying step did not run or did not produce results.

**Notes.** This is the deliverable. Review it before it leaves your hands.

### Detection Coverage

**Purpose and function.** Reconciles what you did against what was detected. It maps your actions to ATT&CK techniques and compares them against the detection ledger and SIEM ingest, so the output is a coverage picture: which techniques alerted, which partially alerted, and which were missed.

**Parameters.** The reconciliation scope. It joins the attacker timeline (including the MSEL ground truth) against detections.

**In the chain.** Runs after the offensive and emulation work. This is the purple-team payoff.

**Expected results.** A per-technique verdict of hit, partial, or miss, with the source signals listed.

**Success vs failure.** There is no fail state for the reconciliation itself. A "miss" is a finding, not an error. It is the exact gap the exercise exists to surface.

**Notes.** Feed misses back to the detection engineers. That loop is the point of the whole console.

---

## The Chain End to End

A typical run flows top to bottom through the tabs:

1. **Scan** builds the host and port inventory.
2. **Topology** and **Web Scan** turn that inventory into targets.
3. **Enum Suite** and **MSF Scanners** deepen the picture and seed the CVE chain and the AD panes.
4. **Exploit** turns a finding into a session, **Validate** confirms it, and **Sessions** operates it.
5. On an internal network, **Responder**, **Coercion**, **Kerberoast**, **BloodHound**, **Impacket-AD**, and **Certipy** capture and extract credentials into **Loot**, which **Lateral Movement** reuses to spread.
6. **C2**, **Atomic Red Team**, **CALDERA**, and **Playbooks** generate detection-validation activity.
7. **Engagement Report** captures the outcome and **Detection Coverage** reconciles it against the blue team's detections.

The **MSEL Scheduler** scripts any of these as timed injects for a repeatable exercise, and the **Cease Buzzer** halts everything at any moment.

---

## Preflight and Health

Before an assessment, confirm the console preflight is clean. It checks Python, privileges, nmap, Metasploit, the enumeration tools, output directories, disk space, and the listen address. A tool shown as absent will surface as a "TOOL NOT ON PATH" state in its pane rather than a silent failure, so install what the preflight flags before you rely on that pane.

---

<img src="sfc-insignia.jpg" alt="U.S. Army Sergeant First Class insignia" height="52" align="left" style="margin-right:12px"/>

**SFC Bartunek**

*H3x-Dash Operator Guide. Prepared for authorized assessment and exercise use.*
