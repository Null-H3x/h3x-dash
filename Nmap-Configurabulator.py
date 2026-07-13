#!/usr/bin/env python3
"""
nmap_topology.py — Network Scanner → Timestamped HTML Topology Report

Run with no arguments to launch the interactive configurator.
Run with arguments to scan non-interactively (CI/cron/pipe-friendly).

Requirements:
    nmap >= 7.x  (apt install nmap | brew install nmap | pacman -S nmap)
    Python >= 3.9 — stdlib only, no pip needed

Examples:
    sudo python3 nmap_topology.py                        # interactive TUI
    sudo python3 nmap_topology.py 192.168.1.0/24         # quick scan, defaults
    sudo python3 nmap_topology.py 10.0.0.0/24 --ports spyglass --timing T3
    sudo python3 nmap_topology.py 192.168.1.0/24 --out-dir /var/reports
    python3 nmap_topology.py 192.168.1.0/24 --no-sudo   # no root, TCP connect

Web scanning (Layer 7 — requires web_scan.py beside this script):
    sudo python3 nmap_topology.py 192.168.1.0/24         # auto-scans web ports
    sudo python3 nmap_topology.py 192.168.1.0/24 --web-nse   # + nmap http-NSE
    sudo python3 nmap_topology.py 10.0.0.0/24 --no-web   # disable web scanning
    python3 nmap_topology.py --web https://example.com   # web-only, no nmap
"""

import sys
import subprocess
import xml.etree.ElementTree as ET
import json
import argparse
import re
import os
import shutil
import threading
import time
import itertools
import random
import tempfile
import pty
import select
import errno
import socket
from datetime import datetime
from pathlib import Path

# ── Optional web scanning module ──────────────────────────────────────────────
# web_scan.py is a sibling module providing Layer-7 web scanning (fingerprint,
# TLS, content surface, nmap http-NSE). It is imported best-effort: if absent,
# the Configurabulator still runs and web features are simply unavailable.
# sys.path is nudged so the import resolves whether this file is run directly
# or imported by H3x-Dash via importlib.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import web_scan
except Exception:
    web_scan = None


# ─── ANSI colours — cyberpunk neon palette ───────────────────────────────────

def _ansi(*codes): return f"\033[{';'.join(str(c) for c in codes)}m" if sys.stdout.isatty() else ""

RST  = _ansi(0);   BOLD = _ansi(1);   DIM  = _ansi(2)
# Neon brights — swap dull ANSI standards for their vivid 90-series equivalents
GRN  = _ansi(92)   # acid green     (was 32)
YLW  = _ansi(93)   # electric yellow (was 33)
RED  = _ansi(91)   # hot red        (was 31)
CYN  = _ansi(96)   # neon cyan      (was 36)
MGT  = _ansi(95)   # hot magenta    (was 35)
BLU  = _ansi(94)   # electric blue  (new)
WHT  = _ansi(97)   # white          (unchanged)

ERR_CODE = "Internal Error Code: XD-MBYG04K-URS3LF"

def _err(msg: str, file=None):
    """Print an error prefixed with the internal error code."""
    import sys as _sys
    f = file or _sys.stderr
    print(f"{RED}[!]{RST} {ERR_CODE}\n    {msg}", file=f)

# Detect at startup whether we are already running as root.
# If True, we skip adding 'sudo' to the nmap command — a double sudo
# (root → sudo → nmap) behaves differently per distro and commonly exits 1.
IS_ROOT = (os.getuid() == 0)


# ─── Port classification ───────────────────────────────────────────────────────

PORT_RISK = {
    21:    ("ftp",           "danger"),
    22:    ("ssh",           "info"),
    23:    ("telnet",        "danger"),
    25:    ("smtp",          "warning"),
    53:    ("dns",           "info"),
    80:    ("http",          "info"),
    110:   ("pop3",          "warning"),
    111:   ("rpcbind",       "warning"),
    135:   ("msrpc",         "warning"),
    139:   ("netbios",       "danger"),
    161:   ("snmp",          "warning"),
    389:   ("ldap",          "warning"),
    443:   ("https",         "info"),
    445:   ("smb",           "danger"),
    512:   ("rexec",         "danger"),
    513:   ("rlogin",        "danger"),
    514:   ("rsh",           "danger"),
    554:   ("rtsp",          "info"),
    631:   ("ipp",           "warning"),
    1433:  ("mssql",         "danger"),
    1521:  ("oracle",        "danger"),
    1723:  ("pptp",          "warning"),
    1883:  ("mqtt",          "info"),
    2049:  ("nfs",           "warning"),
    3306:  ("mysql",         "warning"),
    3389:  ("rdp",           "danger"),
    4444:  ("backdoor",      "danger"),
    5432:  ("psql",          "warning"),
    5900:  ("vnc",           "warning"),
    6379:  ("redis",         "danger"),
    8080:  ("http-alt",      "info"),
    8443:  ("https-alt",     "info"),
    9200:  ("elasticsearch", "danger"),
    27017: ("mongodb",       "danger"),
}

DEVICE_COLORS = {
    "gateway":     "#D85A30",
    "switch":      "#534AB7",
    "server":      "#1D9E75",
    "workstation": "#378ADD",
    "iot":         "#BA7517",
    "unknown":     "#888780",
    "scanner":     "#D4537E",   # this machine — distinct magenta-pink
}
DEVICE_RADII  = {"gateway":22,"switch":15,"server":13,"workstation":11,
                  "iot":10,"unknown":9,"scanner":14}
DEVICE_LABELS = {"gateway":"GATEWAY","switch":"SWITCH","server":"SERVER",
                  "workstation":"WKSTN","iot":"IoT","unknown":"UNKNOWN",
                  "scanner":"SCANNER"}

PORT_PROFILES = {
    "driveby":  ("21-25,53,80,110-111,135,139,161,389,443,445,512-514,554,631,"
               "1099,1433,1521,1723,1883,2049,3306,3389,3632,4444,5432,5900,"
               "6379,6667,8080,8443,9200,27017"),
    "spyglass": "1-1024,1433,1521,1723,1883,2049,3306,3389,4444,5432,5900,6379,8080,8443,9200,27017",
    "web":      "80,443,8000,8008,8080,8443,8888,3000,5000,9443",
    "full":   "1-65535",
}

TIMING_DESC = {
    "T1": "Sneaky Ninja     — very slow, IDS evasion",
    "T2": "Polite Brit      — slow, low bandwidth",
    "T3": "Boringly Average — default nmap timing",
    "T4": "Antagonistic     — fast, reliable on LAN  (recommended)",
    "T5": "Roid Rage        — maximum speed, may drop packets",
}

SCRIPT_PROFILES = {
    "none":    [],
    "banner":  ["banner"],
    "default": ["default", "banner"],
    "safe":    ["safe", "banner"],
    "vuln":    ["vuln", "default", "banner"],
    "full":    ["vuln", "auth", "discovery", "default", "banner"],
}
SCRIPT_DESC = {
    "none":    "No scripts                (fastest — recommended for large subnets)",
    "banner":  "Banner grab only          (port service banners, minimal overhead)",
    "default": "Default + banner          (slow on firewalled hosts)",
    "safe":    "Safe scripts              (SLOW: runs 30s pre-scan broadcast NSE)",
    "vuln":    "Vulnerability scan        (loud, slow — use on confirmed hosts only)",
    "full":    "Full suite                (very slow — targeted use only)",
}


# ─── Config dataclass ─────────────────────────────────────────────────────────

class Config:
    def __init__(self):
        self.target       = ""
        self.use_sudo     = True
        self.timing       = "T4"
        self.port_profile = "driveby"
        self.scripts      = "banner"
        self.out_dir      = str(Path(__file__).parent)
        self.extra_args   = []
        self.web_scan     = True      # auto-scan discovered web ports
        self.web_nse      = False     # include nmap http-NSE (slower)
        self.web_targets  = []        # explicit URLs for direct web scanning


# ─── Interactive TUI ──────────────────────────────────────────────────────────

def _w() -> int:
    return shutil.get_terminal_size((80, 24)).columns

def _clear():
    os.system("clear" if os.name == "posix" else "cls")

def _banner():
    """
    Cyberpunk ASCII-art banner for the interactive configurator.
    NMAP in block letters (ANSI Shadow font), CONFIGUROBULATOR in big block letters.
    """
    NMAP = [
        "███╗   ██╗███╗   ███╗ █████╗ ██████╗ ",
        "████╗  ██║████╗ ████║██╔══██╗██╔══██╗",
        "██╔██╗ ██║██╔████╔██║███████║██████╔╝",
        "██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ",
        "██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ",
        "╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ",
    ]
    # CONFIGUROBULATOR in double-stroke block letters (no v1.0 — font has no
    # lowercase or period glyph; version is rendered as plain text below)
    CFG = [
        "╔═╗╔═╗╔╗╔╔═╗╦╔═╗╦ ╦╦═╗╔═╗╔╗ ╦ ╦╦  ╔═╗╔╦╗╔═╗╦═╗",
        "║  ║ ║║║║╠╣ ║║ ╦║ ║╠╦╝║ ║╠╩╗║ ║║  ╠═╣ ║ ║ ║╠╦╝",
        "╚═╝╚═╝╝╚╝╚  ╩╚═╝╚═╝╩╚═╚═╝╚═╝╚═╝╩═╝╩ ╩ ╩ ╚═╝╩╚═",
    ]
    ART_W = max(len(NMAP[0]), len(CFG[0]))
    W     = max(_w() - 2, ART_W + 6)

    def _row(txt="", col="", left=2):
        vis = left + len(txt)
        pad = " " * max(0, W - vis)
        print(f"{CYN}║{RST}{' ' * left}{col}{txt}{RST}{pad}{CYN}║{RST}")

    print(f"\n{CYN}╔{'═' * W}╗{RST}")
    _row()
    for line in NMAP:
        _row(line, BOLD + CYN)
    _row()
    _row("─" * (W - 4), CYN)
    _row()
    for line in CFG:
        _row(line, BOLD + MGT)
    _row("v1.0", MGT, left=4)
    _row()
    _row("─" * (W - 4), CYN)
    _row("NETWORK RECONNAISSANCE  &  VISUALIZER", DIM)
    _row()
    print(f"{CYN}╚{'═' * W}╝{RST}\n")

def _section(n: str, title: str):
    w = _w()
    rule = f"  {CYN}{'┄' * (w - 4)}{RST}"
    print(f"\n{rule}")
    print(f"  {CYN}◈{RST}  {BOLD}{MGT}{n}{RST}  {BOLD}{WHT}{title}{RST}  {DIM}◈{RST}")
    print(f"{rule}\n")

def _prompt(label: str, default: str, hint: str = "") -> str:
    dflt = f" {DIM}[{default}]{RST}" if default else ""
    hnt  = f"  {DIM}{hint}{RST}"     if hint    else ""
    raw  = input(f"  {GRN}{label:<18}{RST}{dflt}{hnt}\n  {CYN}▶{RST} ").strip()
    return raw if raw else default

def _yn(label: str, default: bool) -> bool:
    tag = "Y/n" if default else "y/N"
    raw = input(f"  {GRN}{label:<18}{RST} {DIM}[{tag}]{RST}\n  {CYN}▶{RST} ").strip().lower()
    return default if not raw else raw in ("y", "yes", "1")

def _menu(label: str, options: dict, current: str, hint: str = "") -> str:
    keys = list(options.keys())
    print(f"  {GRN}{label}{RST}  {DIM}(current: {current}){RST}")
    if hint:
        print(f"  {DIM}{hint}{RST}")
    print()
    for i, (k, desc) in enumerate(options.items(), 1):
        marker = f"{YLW}▶{RST}" if k == current else " "
        print(f"   {marker} {BOLD}{i}{RST}  {WHT}{k:<12}{RST}{DIM}{desc}{RST}")
    print()
    while True:
        raw = input(f"  {CYN}▶{RST} ").strip()
        if not raw:                                        return current
        if raw.isdigit() and 1 <= int(raw) <= len(keys):  return keys[int(raw) - 1]
        if raw in keys:                                    return raw
        print(f"  {RED}Enter a number 1–{len(keys)} or a key name.{RST}")


def interactive_config() -> Config:
    """Full-screen terminal configurator. Returns a populated Config."""
    cfg = Config()
    _clear()
    _banner()

    # 01 — Target
    _section("01", "TARGET")
    print(f"  {DIM}CIDR, IP range, hostname, or single address.{RST}")
    print(f"  {DIM}Examples:  192.168.1.0/24   10.0.0.1-50   scanme.nmap.org{RST}\n")
    while not cfg.target:
        cfg.target = _prompt("Target", "", "required")
        if not cfg.target:
            print(f"  {RED}A target is required.{RST}")

    # 02 — Output directory
    _section("02", "OUTPUT DIRECTORY")
    print(f"  {DIM}Each report is saved with a timestamp in the filename:{RST}")
    print(f"  {DIM}  topology_<subnet>_YYYYMMDD_HHMMSS.html{RST}\n")
    cfg.out_dir = _prompt("Directory", cfg.out_dir, "Enter to use script directory")

    # 03 — Sudo
    _section("03", "SCAN MODE")
    print(f"  {DIM}Sudo enables SYN scan (-sS) and OS fingerprinting (-O).{RST}")
    print(f"  {DIM}Without sudo: TCP connect (-sT), no OS detection.{RST}\n")
    cfg.use_sudo = _yn("Run with sudo", True)

    # 04 — Port scope
    _section("04", "PORT SCOPE")
    cfg.port_profile = _menu(
        "Port profile",
        {
            "driveby":  "~30 high-value ports    (fast, recommended for first scan)",
            "spyglass": "ports 1-1024 + extras   (balanced — good for known networks)",
            "full":   "all 65535 ports         (very slow — targeted hosts only)",
        },
        cfg.port_profile,
    )
    if cfg.port_profile == "full":
        print(f"  {YLW}⚑  Warning:{RST} {DIM}Full scan (65535 ports) on a /24 takes hours.{RST}")
        print(f"     {DIM}The 5-minute host-timeout is NOT applied to full scans because{RST}")
        print(f"     {DIM}it causes nmap to abandon hosts before writing port data to XML.{RST}")
        print(f"     {DIM}Recommended: run Spyglass first, then full on specific IPs only.{RST}\n")

    # 05 — Timing
    _section("05", "TIMING TEMPLATE")
    cfg.timing = _menu("Timing", TIMING_DESC, cfg.timing)

    # 06 — Scripts
    _section("06", "NSE SCRIPT PROFILE")
    cfg.scripts = _menu("Scripts", SCRIPT_DESC, cfg.scripts)
    if cfg.scripts in ("default", "vuln", "full"):
        print(f"  {YLW}⚑  Warning:{RST} {DIM}'{cfg.scripts}' scripts have no built-in timeout cap.{RST}")
        print(f"     {DIM}On firewalled hosts or with -Pn each script waits the full TCP timeout.{RST}")
        print(f"     {DIM}--script-timeout 30s is enforced to limit the damage.{RST}\n")
    elif cfg.scripts == "safe":
        print(f"  {YLW}⚑  Warning:{RST} {DIM}'safe' runs broadcast pre-scan scripts that take 30+ seconds{RST}")
        print(f"     {DIM}and fill the XML with prescript data before any host elements are written.{RST}")
        print(f"     {DIM}This can cause the host elements to appear missing. Use 'banner' instead.{RST}\n")

    # 07 — Skip ping sweep (-Pn)
    _section("07", "HOST DISCOVERY")
    print(f"  {DIM}By default nmap does a ping sweep first and skips hosts that don't respond.{RST}")
    print(f"  {DIM}If hosts are firewalled against ICMP (ping), they appear as 'down' even{RST}")
    print(f"  {DIM}when they're up — and are completely missing from results.{RST}")
    print(f"  {DIM}Enabling -Pn skips the ping sweep and scans every address unconditionally.{RST}")
    print(f"  {DIM}Slower but more complete, especially on restrictive networks.{RST}\n")
    skip_ping = _yn("Skip ping sweep (-Pn)", False)
    if skip_ping:
        if "-Pn" not in cfg.extra_args:
            cfg.extra_args.append("-Pn")

    # 08 — Extra args
    _section("08", "EXTRA NMAP ARGUMENTS  (optional)")
    print(f"  {DIM}Appended verbatim after all other flags.{RST}")
    print(f"  {DIM}Examples:  --exclude 192.168.1.50   -e eth0   --defeat-rst-ratelimit{RST}\n")
    raw = _prompt("Extra args", " ".join(cfg.extra_args) if cfg.extra_args else "",
                  "leave blank to skip")
    cfg.extra_args = raw.split() if raw else []

    # 08b — Web scanning
    if web_scan is not None:
        print()
        cfg.web_scan = _yn("Scan discovered web services (HTTP/HTTPS)", True)
        if cfg.web_scan:
            cfg.web_nse = _yn("  Include nmap http-NSE (slower, noisier)", False)
    else:
        cfg.web_scan = False

    # 09 — Confirm
    _section("09", "REVIEW & CONFIRM")
    w = _w()
    # Truncate long values so the table never wraps on narrow terminals
    def _trunc(s, n=50): return s if len(s) <= n else s[:n-1] + "…"
    timing_name = TIMING_DESC.get(cfg.timing, '').split(' — ')[0].strip()
    script_name = SCRIPT_DESC.get(cfg.scripts, '').split(' ')[0].strip()
    rows = [
        ("Target",          _trunc(cfg.target, 55)),
        ("Dir",             _trunc(cfg.out_dir, 55)),
        ("Sudo",            "yes (SYN + OS)" if cfg.use_sudo else "no (TCP connect)"),
        ("Port Scope",      cfg.port_profile),
        ("Timing",          f"{cfg.timing}  —  {timing_name}"),
        ("NSE Profile",     cfg.scripts),
        ("Host Discovery",  "no (-Pn)" if "-Pn" in cfg.extra_args else "yes (ping sweep)"),
        ("Extra Args",      " ".join(a for a in cfg.extra_args if a != "-Pn") or "—"),
    ]
    print(f"  {CYN}{'┄' * (w - 4)}{RST}")
    for k, v in rows:
        print(f"  {DIM}{k:<16}{RST} {WHT}{v}{RST}")
    print(f"  {CYN}{'┄' * (w - 4)}{RST}\n")

    if not _yn("Start scan?", True):
        print(f"\n  {YLW}Aborted.{RST}\n")
        sys.exit(0)

    print()
    return cfg



# ─── Live scan monitor ────────────────────────────────────────────────────────

class ScanMonitor:
    """
    Streams nmap verbose stderr in real time.

    Architecture
    ────────────
    • A spinner thread wakes every 100 ms and rewrites the bottom status bar
      in-place using \r (carriage return).
    • _log() clears the current status-bar line (\r\033[2K), prints the event,
      then the spinner redraws the bar on its next tick.
    • A threading.Lock serialises all writes so the two threads never interleave.

    Nmap verbose lines parsed (nmap is invoked with -v)
    ─────────────────────────────────────────────────────
      Initiating <Phase> at HH:MM         → phase update
      Scanning N hosts [P ports/host]     → host-count hint
      Completed <Phase> … N.Ns elapsed    → phase-complete event
      Discovered open port P/tcp on IP    → port event + risk flag
      Nmap scan report for IP             → host-up event
      Host is up (Xs latency)             → latency annotation
      OS details: …                       → OS guess
    """

    _BAR_WIDTH = 78
    _FRAMES    = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.phase        = "Initialising"
        self.phase_done   = False
        self.hosts_up     = 0
        self.hosts_total  = 0
        self.ports_open   = 0
        self.ports_danger = 0
        self.start_time   = time.time()
        # Ports discovered live over the PTY stream, keyed by IP.
        # Used to enrich hosthint-recovered hosts when the XML is truncated
        # during NSE (the <host> element is never written in that case).
        self.discovered_ports: dict[str, list[dict]] = {}
        # Rolling buffer of the last 10 raw stderr lines — used by the
        # failure diagnostic to show nmap's actual error message.
        self.last_lines: list[str] = []

        self._lock        = threading.Lock()
        self._stop        = threading.Event()
        self._spinner     = itertools.cycle(self._FRAMES)
        self._spinner_thr = threading.Thread(target=self._spin_loop, daemon=True)
        self._last_host   = ""

        self._print_header()
        self._spinner_thr.start()

    # ── Header ───────────────────────────────────────────────────────────────

    def _print_header(self):
        w  = self._BAR_WIDTH
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{CYN}{'─' * w}{RST}")
        print(f"{BOLD}{CYN}  ◈  CONFIGUROBULATOR v1.0{RST}  {DIM}◈  LIVE SCAN ◈{RST}  {MGT}{ts}{RST}")
        print(f"{CYN}{'─' * w}{RST}")
        print(f"{DIM}  Events scroll below — Ctrl-C aborts and saves partial results{RST}")
        print(f"{CYN}{'─' * w}{RST}\n")

    # ── Status bar ───────────────────────────────────────────────────────────

    def _status_bar(self) -> str:
        s         = int(time.time() - self.start_time)
        elapsed   = f"{s // 60:02d}:{s % 60:02d}"
        spin      = next(self._spinner)
        hosts_str = f"{self.hosts_up}/{self.hosts_total}" if self.hosts_total else str(self.hosts_up)
        danger_s  = f"  {RED}⚠ {self.ports_danger}{RST}" if self.ports_danger else ""
        pcol      = DIM if self.phase_done else CYN
        return (
            f"{CYN}{spin}{RST} {pcol}{self.phase:<34}{RST}"
            f"  {GRN}hosts {hosts_str:<8}{RST}"
            f"  {YLW}ports {self.ports_open}{RST}{danger_s}"
            f"  {DIM}{elapsed}{RST}"
        )

    def _redraw_bar(self):
        print(f"\r\033[2K{self._status_bar()}", end="", flush=True)

    def _spin_loop(self):
        while not self._stop.is_set():
            with self._lock:
                self._redraw_bar()
            time.sleep(0.1)

    # ── Event logger ─────────────────────────────────────────────────────────

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            print(f"\r\033[2K{DIM}[{ts}]{RST}  {msg}", flush=True)

    # ── Nmap stderr parser ───────────────────────────────────────────────────

    def feed(self, raw: str):
        """Parse one line of nmap verbose output and update live state."""
        line = raw.strip()
        if not line:
            return

        # Keep a rolling buffer of raw lines for post-mortem diagnostics
        self.last_lines.append(line)
        if len(self.last_lines) > 10:
            self.last_lines.pop(0)

        # Phase start
        m = re.match(r"Initiating (.+?) (?:Scan |scan )?(?:against .+?)?at \d+:\d+", line)
        if m:
            self.phase      = m.group(1).strip()[:34]
            self.phase_done = False
            self._log(f"{CYN}▶  PHASE      {self.phase}{RST}")
            return

        # Host count — "Scanning 256 hosts [2 ports/host]"
        m = re.match(r"Scanning (\d+) hosts?(?:\s|$)", line)
        if m and "services" not in line:
            self.hosts_total = int(m.group(1))
            return

        # Phase complete
        m = re.match(r"Completed (.+?) (?:[Ss]can )?at \d+:\d+.*?([\d.]+)s elapsed", line)
        if m:
            # Strip trailing "scan"/"Scan" that slipped into the capture group
            phase = re.sub(r"\s+[Ss]can$", "", m.group(1).strip())[:34]
            self.phase      = phase
            self.phase_done = True
            self._log(f"{DIM}✓  COMPLETE   {phase}  ({m.group(2)}s){RST}")
            return

        # Discovered open port
        m = re.search(r"Discovered open port (\d+)/(\w+) on ([\d.]+)", line)
        if m:
            port, proto, ip = int(m.group(1)), m.group(2), m.group(3)
            self.ports_open += 1
            name, risk = PORT_RISK.get(port, ("", "info"))
            svc = name or proto
            if risk == "danger":
                self.ports_danger += 1
                rtag = f"  {RED}{BOLD}⚠  CRITICAL{RST}"
            elif risk == "warning":
                rtag = f"  {YLW}△  WARN{RST}"
            else:
                rtag = ""
            self._log(
                f"{CYN}↳  OPEN PORT  {WHT}{ip:<17}{RST}"
                f"{YLW}{port:<6}{RST}{DIM}/{proto}  {svc:<12}{RST}{rtag}"
            )
            # Store for hosthint enrichment — if the XML is truncated during
            # NSE the <host> element is never written, but these live PTY
            # events are the ground truth for what ports are open.
            entry = {"port": port, "state": "open",
                     "service": svc, "version": "", "risk": risk}
            self.discovered_ports.setdefault(ip, [])
            # Deduplicate (retransmission can cause duplicate port events)
            if not any(p["port"] == port for p in self.discovered_ports[ip]):
                self.discovered_ports[ip].append(entry)
            return

        # Nmap scan report (host up)
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            host = m.group(1).strip()
            self._last_host = host
            self.hosts_up  += 1
            self._log(f"{GRN}●  HOST UP    {WHT}{host}{RST}")
            return

        # Latency
        m = re.search(r"Host is up \(([\d.]+)s latency\)", line)
        if m:
            self._log(f"{DIM}             latency {m.group(1)}s{RST}")
            return

        # OS details
        m = re.search(r"OS details: (.+)", line)
        if m:
            self._log(f"{DIM}   OS GUESS  {m.group(1)[:60]}{RST}")
            return

        # Service scan start
        m = re.search(r"Scanning (\d+) services? on (\d+) hosts?", line)
        if m:
            self._log(f"{DIM}↳  SVC SCAN   {m.group(1)} services on {m.group(2)} hosts{RST}")
            return

        # Warnings
        if line.lower().startswith(("warning:", "note:")):
            self._log(f"{YLW}⚑  {line[:80]}{RST}")
            return

    # ── Teardown ──────────────────────────────────────────────────────────────

    def stop(self):
        if self._stop.is_set():   # guard: safe to call multiple times
            return
        self._stop.set()
        self._spinner_thr.join(timeout=0.5)
        with self._lock:
            print("\r\033[2K", end="", flush=True)

    def summary(self):
        s       = int(time.time() - self.start_time)
        elapsed = f"{s // 60:02d}:{s % 60:02d}"
        w       = self._BAR_WIDTH
        print(f"{CYN}{'─' * w}{RST}")
        print(
            f"  {GRN}Scan complete{RST}  "
            f"hosts {GRN}{self.hosts_up}{RST}  "
            f"open ports {YLW}{self.ports_open}{RST}  "
            f"critical {RED}{self.ports_danger}{RST}  "
            f"elapsed {DIM}{elapsed}{RST}"
        )
        print(f"{CYN}{'─' * w}{RST}\n")


# ─── Timestamped output path ──────────────────────────────────────────────────

def make_output_path(target: str, out_dir: str) -> Path:
    """
    Returns  <out_dir>/topology_<safe_target>_YYYYMMDD_HHMMSS.html
    Creates the directory if it doesn't exist.
    """
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w.\-]", "_", target).strip("_")
    d    = Path(out_dir).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d / f"topology_{safe}_{ts}.html"


# ─── Pre-flight checks & diagnostics ─────────────────────────────────────────

def preflight_check(cfg: Config) -> None:
    """
    Run fast sanity checks before touching nmap.
    Every subprocess call has an explicit timeout so this function
    always completes in under 15 seconds regardless of system state.
    """
    w = 78
    print(f"{CYN}╔{'═' * w}╗{RST}")
    print(f"{CYN}║{RST}  {BOLD}{MGT}◈  PRE-FLIGHT CHECKS{RST}{' ' * (w - 20)}{CYN}║{RST}")
    print(f"{CYN}╚{'═' * w}╝{RST}")

    def ok(label: str):
        print(f"  {GRN}✓{RST}  {label}")

    def fail(label: str, detail: str, fix: str):
        print(f"  {RED}✗{RST}  {RED}{BOLD}{label}{RST}")
        print(f"     {DIM}Detail : {detail}{RST}")
        print(f"     {YLW}Fix    : {fix}{RST}\n")
        sys.exit(1)

    def run(cmd: list, timeout: int, **kw):
        """
        subprocess.run wrapper that always has a timeout.
        Returns the CompletedProcess or exits with a clear message.
        """
        try:
            return subprocess.run(cmd, timeout=timeout, **kw)
        except subprocess.TimeoutExpired:
            fail(
                f"command timed out after {timeout}s",
                " ".join(cmd[:6]) + ("…" if len(cmd) > 6 else ""),
                "Check for hung sudo/LDAP auth, DNS issues, or a locked nmap binary",
            )
        except FileNotFoundError:
            fail(
                f"command not found: {cmd[0]}",
                f"{cmd[0]} is not in PATH",
                f"apt install {cmd[0]}",
            )

    # ── 1. nmap installed? ────────────────────────────────────────────────────
    if not shutil.which("nmap"):
        fail("nmap not found",
             "nmap binary is not in PATH",
             "apt install nmap  |  brew install nmap  |  pacman -S nmap")
    ver = run(["nmap", "--version"], timeout=5, capture_output=True, text=True)
    ver_line = ver.stdout.splitlines()[0] if ver.stdout else "unknown version"
    ok(f"nmap          →  {ver_line}")

    # ── 2. Privilege check ────────────────────────────────────────────────────
    if IS_ROOT:
        ok("privileges     →  running as root (sudo not needed)")
    elif cfg.use_sudo:
        r = run(["sudo", "-n", "true"], timeout=5, capture_output=True)
        if r.returncode != 0:
            fail("sudo credential not cached",
                 "`sudo -n true` failed — password required but not cached",
                 "Run `sudo -v` to cache the credential, then retry")
        ok("privileges     →  sudo credential active")
    else:
        ok("privileges     →  unprivileged (TCP connect scan)")

    # ── 3. Privilege summary (no probe — trust the OS) ────────────────────────
    # We do not run a test nmap scan here. Every attempt at a "raw socket
    # sanity probe" has produced false negatives — the probe itself fails for
    # loopback / interface / timing reasons unrelated to the real scan.
    # If nmap cannot open a raw socket on the real target, it will say so
    # immediately and the diagnostic block will show the exact error.
    if IS_ROOT or cfg.use_sudo:
        mode = "root" if IS_ROOT else "sudo"
        ok(f"scan mode     →  SYN + OS detection ({mode})")

    # ── 4. Target format ──────────────────────────────────────────────────────
    t = cfg.target.strip()
    if not t or not re.match(r"^[\w./:\-]+$", t):
        fail("target looks wrong",
             f"Got: {t!r}",
             "Use CIDR (192.168.1.0/24), range (10.0.0.1-50), or hostname")
    ok(f"target        →  {t}")

    # ── 5. Output directory writable? ─────────────────────────────────────────
    out_dir = Path(cfg.out_dir).expanduser().resolve()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        probe_f = out_dir / ".nmap_write_test"
        probe_f.write_text("x")
        probe_f.unlink()
    except OSError as e:
        fail("output directory not writable", str(e),
             f"Check permissions on {out_dir}  or use --out-dir /tmp")
    ok(f"output dir    →  {out_dir}")

    print(f"{CYN}{'─' * w}{RST}\n")


def _diagnose_nmap_failure(returncode: int, cmd_str: str,
                            cfg: Config, monitor=None) -> None:
    """
    Print a structured post-mortem when nmap exits non-zero.
    Shows nmap's actual last stderr lines if the monitor captured them.
    """
    w = 78
    print(f"\n{RED}{'─' * w}{RST}")
    print(f"{RED}{BOLD}  NMAP FAILED  —  exit code {returncode}{RST}")
    print(f"{RED}{'─' * w}{RST}\n")

    # ── Show nmap's actual error output ───────────────────────────────────────
    if monitor and monitor.last_lines:
        print(f"  {BOLD}Last output from nmap:{RST}")
        for ln in monitor.last_lines[-6:]:
            print(f"  {RED}│{RST} {DIM}{ln}{RST}")
        print()

    # ── Full command (un-truncated) ───────────────────────────────────────────
    print(f"  {BOLD}Full command:{RST}")
    # Word-wrap at terminal width
    words, line_buf = cmd_str.split(), []
    for word in words:
        line_buf.append(word)
        if len(" ".join(line_buf)) > 72:
            print(f"  {DIM}{' '.join(line_buf[:-1])}{RST}")
            line_buf = [word]
    if line_buf:
        print(f"  {DIM}{' '.join(line_buf)}{RST}")
    print()

    # ── Root cause table ──────────────────────────────────────────────────────
    sudo_prefix = "" if IS_ROOT else "sudo "
    print(f"  {BOLD}Common causes of exit code {returncode}:{RST}\n")
    causes = [
        (
            "Running as root but script also adds sudo",
            f"IS_ROOT={IS_ROOT}. When the script runs as root it no longer "
            "adds sudo, so this should not apply. If you invoked it with "
            "`sudo python3 nmap_topology.py`, that is correct.",
            "Confirmed: script auto-detects root and skips sudo"
        ) if IS_ROOT else (
            "Double-sudo / permission denied",
            "The script adds sudo to nmap only when not already root. "
            "If your sudo rule restricts which commands are allowed, "
            "nmap may be blocked.",
            "Run the entire script as root:\n"
            "           sudo python3 nmap_topology.py"
        ),
        (
            "sudo credential expired during a long scan",
            "sudo -v caches the credential, but scans >15 min can outlast it.",
            "Add to /etc/sudoers (visudo):\n"
            f"           {os.getenv('USER','user')} ALL=(ALL) NOPASSWD: /usr/bin/nmap"
        ),
        (
            "Network interface not found / no route to host",
            "nmap cannot determine which interface to use for the target.",
            f"Add  -e eth0  (or your interface name) under Extra Args\n"
            f"           Check with: ip addr"
        ),
        (
            "Target subnet unreachable",
            "The subnet is not reachable from this machine.",
            f"Ping test: ping -c1 {cfg.target.split('/')[0]}"
        ),
        (
            "nmap too old for --stats-every",
            "--stats-every requires nmap >= 6.00.",
            "apt upgrade nmap  |  brew upgrade nmap"
        ),
    ]
    for i, (title, detail, fix) in enumerate(causes, 1):
        print(f"  {YLW}{i}.{RST} {BOLD}{title}{RST}")
        print(f"     {DIM}{detail}{RST}")
        print(f"     {YLW}Fix:{RST} {fix}\n")

    print(f"  {BOLD}Reproduce manually:{RST}")
    print(f"  {CYN}{sudo_prefix}nmap -v --reason -p 22,80,443 {cfg.target}{RST}")
    print(f"  {DIM}(this shows nmap's raw error without any script involvement){RST}\n")
    print(f"{RED}{'─' * w}{RST}\n")


# ─── Nmap runner ──────────────────────────────────────────────────────────────

def run_nmap(cfg: Config) -> tuple[str, str]:
    """
    Execute nmap and stream verbose progress in real time.

    PTY design
    ──────────
    nmap detects whether its stdout is a TTY. When it is, glibc uses
    line-buffering and every \n flushes immediately. When stdout is a PIPE,
    glibc switches to 4-8 KB block-buffering and events stop arriving until
    the buffer fills — which looks like a hang.

    We attach a PTY slave to nmap's stdout AND stderr so glibc line-buffers.
    We read from the PTY master in a single loop that runs for the entire
    lifetime of the nmap process.

    SIGHUP fix
    ──────────
    Closing master_fd while nmap is still alive sends SIGHUP to nmap,
    killing it before it can finish writing the XML file. The fix:
    master_fd is closed ONLY after proc.wait() confirms nmap has exited.
    The read loop itself keeps draining the PTY buffer so nmap never blocks
    on a full buffer — even during the final "write 256 scan reports" phase.
    """
    ports       = PORT_PROFILES.get(cfg.port_profile, PORT_PROFILES["driveby"])
    script_list = SCRIPT_PROFILES.get(cfg.scripts, SCRIPT_PROFILES["default"])

    # ── Privilege setup ───────────────────────────────────────────────────────
    need_sudo = cfg.use_sudo and not IS_ROOT
    if need_sudo:
        print(f"{CYN}[*]{RST} Refreshing sudo credentials (enter password if prompted)\u2026")
        ret = subprocess.run(["sudo", "-v"], check=False, timeout=60)
        if ret.returncode != 0:
            _err('sudo authentication failed.', file=sys.stderr)
            sys.exit(1)
        print(f"{GRN}[\u2713]{RST} sudo ready\n")
    elif IS_ROOT and cfg.use_sudo:
        print(f"{CYN}[*]{RST} Running as root \u2014 skipping sudo prefix\n")

    # ── Temp file for XML ─────────────────────────────────────────────────────
    tf = tempfile.NamedTemporaryFile(
        suffix=".xml", prefix="nmap_topo_", dir="/tmp", delete=False
    )
    tf.close()
    xml_path = Path(tf.name)
    xml_path.chmod(0o666)

    # ── Build command ─────────────────────────────────────────────────────────
    want_root_scan = cfg.use_sudo or IS_ROOT
    cmd  = (["sudo"] if need_sudo else []) + ["nmap"]
    cmd += ["-sS", "-O"] if want_root_scan else ["-sT"]
    cmd += [
        "-sV", "--version-intensity", "5",
        "-v", "--stats-every", "10s",
        f"-{cfg.timing}",
        "--script-timeout", "30s",
        "-oX", str(xml_path),
        "-p", ports,
    ]
    # host-timeout must scale with port scope.
    # With --ports full (65535 ports), a 5-minute timeout expires during the
    # SYN scan phase itself, causing nmap to write empty <ports> to the XML
    # even though it found ports live. Drive By/Spyglass are fast enough that 5m
    # is a reasonable upper bound per host.
    if cfg.port_profile != "full":
        cmd += ["--host-timeout", "5m"]
    if script_list:
        cmd += [f"--script={','.join(script_list)}"]
    cmd += cfg.extra_args
    cmd.append(cfg.target)

    cmd_str = " ".join(cmd)

    # Word-wrap the command at terminal width so it doesn't scroll off-screen
    tw = shutil.get_terminal_size((80, 24)).columns - 14
    words, lines_out, cur = cmd_str.split(), [], []
    for w_tok in words:
        if cur and sum(len(x)+1 for x in cur) + len(w_tok) > tw:
            lines_out.append(" ".join(cur)); cur = []
        cur.append(w_tok)
    if cur: lines_out.append(" ".join(cur))
    prefix = f"{CYN}[*]{RST} {BOLD}Command :{RST} "
    print(prefix + lines_out[0])
    for extra_line in lines_out[1:]:
        print(f"{' ' * 14}{extra_line}")

    print(f"{CYN}[*]{RST} Target       : {cfg.target}")
    print(f"{CYN}[*]{RST} Port Scope   : {cfg.port_profile}")
    print(f"{CYN}[*]{RST} Timing       : -{cfg.timing}  ({TIMING_DESC.get(cfg.timing,'').split(' — ')[0].strip()})")
    print(f"{CYN}[*]{RST} NSE Profile  : {cfg.scripts}")
    print(f"{CYN}[*]{RST} XML tmp      : {xml_path}")

    # ── Open PTY ─────────────────────────────────────────────────────────────
    try:
        master_fd, slave_fd = pty.openpty()
        use_pty = True
    except (AttributeError, OSError):
        master_fd = slave_fd = None
        use_pty = False

    # ── Launch nmap ───────────────────────────────────────────────────────────
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=slave_fd if use_pty else subprocess.PIPE,
            stderr=slave_fd if use_pty else subprocess.PIPE,
            close_fds=True,
        )
    except FileNotFoundError:
        _err('nmap not found.  apt install nmap | brew install nmap', file=sys.stderr)
        xml_path.unlink(missing_ok=True)
        sys.exit(1)

    # Parent closes slave_fd — only nmap (child) should hold it.
    # If the parent keeps slave_fd open, os.read(master_fd) never gets EIO
    # even after nmap exits, so the read loop would hang forever.
    if use_pty:
        os.close(slave_fd)

    # ── Single unified PTY read loop ──────────────────────────────────────────
    # This loop is the heart of the monitor.  It runs for the ENTIRE lifetime
    # of the nmap process — not just until nmap closes its stdout.
    #
    # Why a single loop instead of main-loop + bg_drain?
    # When nmap finishes scanning it writes a scan report for every host
    # (potentially 256 of them) to stdout. This can be many KB. If any
    # earlier loop exited and nobody was reading master_fd, the 4 KB PTY
    # kernel buffer would fill, nmap would block on write, and our
    # proc.wait(120) would eventually kill nmap — truncating the XML.
    #
    # By keeping one loop running until proc.poll() returns non-None AND
    # select reports no more data, we guarantee:
    #   1. The PTY buffer never fills (nmap never blocks).
    #   2. master_fd is not closed until after nmap exits (no SIGHUP).
    #   3. The XML file is complete when we read it.
    monitor = ScanMonitor()
    buf     = ""

    def _pty_read_loop():
        nonlocal buf
        while True:
            alive = proc.poll() is None

            # Wait up to 1 s for data on the PTY master
            try:
                r, _, _ = select.select([master_fd], [], [], 1.0)
            except (OSError, ValueError):
                if not alive:
                    break        # fd is bad and nmap exited — done
                time.sleep(0.1)  # transient error, retry
                continue

            if r:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    # EIO: slave_fd was closed (nmap exited).
                    # If nmap is still "alive" per proc.poll() there is a tiny
                    # race — sleep briefly and check again before giving up.
                    if alive:
                        time.sleep(0.05)
                        if proc.poll() is None:
                            continue   # genuinely transient, keep trying
                    break

                if chunk:
                    buf += chunk.decode("utf-8", errors="replace")
                    # Feed complete lines to the monitor
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        monitor.feed(line)
                else:
                    # Empty read = EOF
                    if not alive:
                        break

            else:
                # select timed out — no data
                if not alive:
                    break   # nmap exited and nothing to read → done

    try:
        if use_pty:
            _pty_read_loop()
        else:
            # PIPE fallback (no PTY available)
            for line in proc.stdout:
                monitor.feed(line.rstrip())

    except KeyboardInterrupt:
        proc.terminate()
        monitor.stop()
        print(f"\n{YLW}[!]{RST} Scan interrupted \u2014 saving partial results\u2026\n")

    # ── Wait for nmap to finish (it may still be writing the XML) ─────────────
    # Do NOT close master_fd before proc.wait() — that would send SIGHUP.
    #
    # The NSE phase runs AFTER the PTY loop exits (nmap closes its stdout when
    # it hands control to NSE worker threads). With aggressive script profiles,
    # NSE can run for tens of minutes on a single host. proc.wait() must give
    # it enough rope:
    #   none / banner          →   2 min   (little/no NSE)
    #   default / safe         →  15 min   (bounded scripts)
    #   vuln / full            →  90 min   (vulnerability scripts take time)
    _nse_timeout = {
        "none":    120,
        "banner":  120,
        "default": 900,
        "safe":    900,
        "vuln":    5400,
        "full":    5400,
    }.get(cfg.scripts, 900)

    try:
        proc.wait(timeout=_nse_timeout)
    except subprocess.TimeoutExpired:
        elapsed_str = f"{_nse_timeout // 60}m"
        print(f"{YLW}[!]{RST} nmap still running {elapsed_str} after PTY closed — terminating",
              file=sys.stderr)
        proc.terminate()
        proc.wait(timeout=30)

    # Now nmap has fully exited — safe to close the PTY master
    if use_pty:
        try:
            os.close(master_fd)
        except OSError:
            pass

    monitor.stop()
    monitor.summary()

    # ── Read XML from temp file ───────────────────────────────────────────────
    xml_str = ""
    try:
        xml_str = xml_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        try:
            r2 = subprocess.run(["sudo", "cat", str(xml_path)],
                                capture_output=True, text=True, timeout=15)
            xml_str = r2.stdout
        except Exception as e:
            _err(f'Cannot read XML output: {e}', file=sys.stderr)
            sys.exit(1)
    finally:
        try:
            xml_path.unlink()
        except OSError:
            subprocess.run(["sudo", "rm", "-f", str(xml_path)],
                           check=False, timeout=10)

    if proc.returncode not in (0, None) and not xml_str.strip().startswith("<?xml"):
        _diagnose_nmap_failure(proc.returncode, cmd_str, cfg, monitor)
        sys.exit(1)

    return xml_str, cmd_str, monitor


# ─── XML parser ───────────────────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    """Return True if s looks like a dotted-quad IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _ip_sort_key(ip: str) -> tuple:
    """Sort key that works for both IPs and hostnames (hostnames sort last)."""
    if _is_ip(ip):
        return (0,) + tuple(int(x) for x in ip.split("."))
    return (1, ip)


def expand_target(target: str) -> list[str]:
    """
    Return every host address implied by the target expression.
    Supports CIDR (192.168.1.0/24) and last-octet dash range (192.168.1.0-50).
    Returns an empty list for hostnames and single IPs — those have no
    meaningful range to enumerate, so down_ips will be empty.
    Capped at 4096 addresses so a typo doesn't freeze the process.
    """
    try:
        if "/" in target:
            net, bits = target.split("/")
            bits = int(bits)
            p = [int(x) for x in net.split(".")]
            base = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            net_addr = base & mask
            count = min(2 ** (32 - bits), 4096)
            ips = []
            for i in range(1, count - 1):
                n = net_addr + i
                ips.append(f"{(n>>24)&255}.{(n>>16)&255}.{(n>>8)&255}.{n&255}")
            return ips
        if "-" in target.split(".")[-1] and _is_ip(target.split("-")[0]):
            prefix = ".".join(target.split(".")[:3])
            lo, hi  = target.split(".")[-1].split("-")
            return [f"{prefix}.{i}"
                    for i in range(int(lo), min(int(hi) + 1, int(lo) + 4096))]
    except Exception:
        pass
    # Hostname or single IP — no range to enumerate
    return []


def parse_nmap_xml(xml_str: str, target: str = "") -> tuple[list[dict], dict, list[str], list[str]]:
    """
    Parse nmap XML.

    Returns (live_hosts, meta, down_ips, no_port_ips):
      live_hosts  — hosts with status=up (all of them, ports may be empty)
      meta        — runstats dict
      down_ips    — IPs in the target range that were NOT found as up
      no_port_ips — IPs that were up but had zero open ports detected
    """
    xml_str = xml_str.strip()
    empty_meta = {"hosts_up": 0, "hosts_down": 0, "elapsed": "", "command": "", "start": ""}
    if not xml_str:
        return [], empty_meta, [], []

    def _try_parse(s):
        try:    return ET.fromstring(s), None
        except ET.ParseError as e: return None, e

    root, err = _try_parse(xml_str)
    if root is None and not xml_str.endswith("</nmaprun>"):
        root, err = _try_parse(xml_str + "\n</nmaprun>")
    if root is None:
        lc = xml_str.rfind("</host>")
        if lc != -1:
            root, err = _try_parse(xml_str[:lc + len("</host>")] + "\n</nmaprun>")
    if root is None:
        blocks = re.findall(r"<host\b.*?</host>", xml_str, re.DOTALL)
        prolog = re.match(r"(<\?xml[^?]*\?>)", xml_str)
        ps = prolog.group(1) if prolog else '<?xml version="1.0"?>'
        if blocks:
            root, err = _try_parse(ps + '<nmaprun>' + "".join(blocks) + '</nmaprun>')
    if root is None:
        _err(f'XML parse error: {err}', file=sys.stderr)
        sys.exit(1)

    meta = {
        "command":    root.get("args", ""),
        "start":      root.get("startstr", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "elapsed":    "",
        "hosts_up":   0,
        "hosts_down": 0,
    }
    fin  = root.find("runstats/finished")
    summ = root.find("runstats/hosts")
    if fin  is not None: meta["elapsed"]    = f"{float(fin.get('elapsed', 0)):.1f}s"
    if summ is not None:
        meta["hosts_up"]   = int(summ.get("up",   0))
        meta["hosts_down"] = int(summ.get("down", 0))

    # Use iter() not findall("host") — iter() searches recursively at any
    # depth. findall("host") only finds direct children of the root element.
    # If nmap wraps hosts in another element, or if the XML schema changes,
    # iter() still finds them. The performance difference is negligible.
    all_els   = list(root.iter("host"))
    up_hosts  = []    # status=up, parsed fully
    drop_down = 0
    drop_noip = 0

    for host_el in all_els:
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            drop_down += 1
            continue

        ip = mac = vendor = ""
        for addr in host_el.findall("address"):
            t = addr.get("addrtype", "")
            if   t == "ipv4": ip     = addr.get("addr", "")
            elif t == "mac":  mac    = addr.get("addr", "")
            if   t == "mac":  vendor = addr.get("vendor", "")
        if not ip:
            drop_noip += 1
            continue

        hostname = ip
        hn_el = host_el.find("hostnames")
        if hn_el is not None:
            for hn in hn_el.findall("hostname"):
                if hn.get("type") in ("user", "PTR"):
                    hostname = hn.get("name", ip)
                    break

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p_el in ports_el.findall("port"):
                st = p_el.find("state")
                if st is None or st.get("state") != "open":
                    continue
                num    = int(p_el.get("portid", 0))
                svc_el = p_el.find("service")
                service = version = ""
                if svc_el is not None:
                    service = svc_el.get("name", "")
                    version = f"{svc_el.get('product','')} {svc_el.get('version','')}".strip()
                name, risk = PORT_RISK.get(num, (service or "unknown", "info"))
                ports.append({"port": num, "state": "open",
                               "service": service or name,
                               "version": version, "risk": risk})

        os_name = ""; os_acc = 0
        os_el = host_el.find("os")
        if os_el is not None:
            for osm in os_el.findall("osmatch"):
                acc = int(osm.get("accuracy", 0))
                if acc > os_acc:
                    os_acc = acc; os_name = osm.get("name", "")

        uptime = ""
        ut_el = host_el.find("uptime")
        if ut_el is not None:
            secs = int(ut_el.get("seconds", 0))
            if secs:
                uptime = f"{secs // 86400}d {(secs % 86400) // 3600}h"

        scripts = {}
        hs_el = host_el.find("hostscript")
        if hs_el is not None:
            for sc in hs_el.findall("script"):
                out = sc.get("output", "").strip()
                if out:
                    scripts[sc.get("id", "")] = out

        # Parse round-trip time (srtt is in microseconds in nmap XML)
        srtt_us = 0
        times_el = host_el.find("times")
        if times_el is not None:
            try:
                srtt_us = int(times_el.get("srtt", 0))
            except (ValueError, TypeError):
                srtt_us = 0

        up_hosts.append({
            "id": ip, "ip": ip, "hostname": hostname, "mac": mac,
            "vendor": vendor, "os": os_name, "os_accuracy": os_acc,
            "ports": ports, "uptime": uptime, "scripts": scripts,
            "_pn_reason": status.get("reason", ""),
            "_srtt_us":   srtt_us,
        })

    # ── Filter -Pn phantoms ───────────────────────────────────────────────────
    # When -Pn is used, nmap marks ALL addresses as status="up" with
    # reason="user-set" regardless of whether anything responded.
    # Hosts that are genuine have at least one of: open ports, a MAC address
    # (ARP reply on LAN), or a resolved PTR hostname.
    # Hosts with reason="user-set" and none of the above are phantoms.
    drop_phantom = 0
    real_hosts = []
    for h in up_hosts:
        if h["_pn_reason"] == "user-set":
            has_evidence = bool(h["ports"] or h["mac"] or h["hostname"] != h["ip"])
            if not has_evidence:
                drop_phantom += 1
                continue
        real_hosts.append(h)

    if drop_phantom:
        print(f"{DIM}     -Pn phantoms     : {drop_phantom} (no ports/MAC/hostname){RST}")

    up_hosts = real_hosts

    # ── Filter proxy-ARP ghost hosts ─────────────────────────────────────────
    # Some routers use proxy ARP — they answer ARP for every IP on the subnet,
    # making nmap report all 256 addresses as "up". The giveaway is the
    # round-trip time: real LAN devices respond in 300μs–100ms; proxy ARP
    # responses from the router arrive in <200μs because they're the same
    # device. Filter hosts that have ALL of: sub-200μs srtt, no open ports,
    # and no MAC address (an actual ARP reply gives us the MAC).
    # Hosts that genuinely respond fast (e.g. loopback, VMs) will have either
    # a real MAC or open ports, so they're kept.
    drop_arp_ghost = 0
    filtered_hosts = []
    for h in up_hosts:
        srtt = h.get("_srtt_us", 0)
        is_ghost = (
            srtt > 0 and srtt < 200         # sub-200μs — impossibly fast for real LAN
            and not h["ports"]              # no open ports found
            and not h["mac"]               # no ARP reply (no real MAC)
        )
        if is_ghost:
            drop_arp_ghost += 1
        else:
            filtered_hosts.append(h)

    if drop_arp_ghost:
        print(f"{YLW}[!]{RST} Proxy-ARP ghost filter: removed {drop_arp_ghost} host(s) "
              f"with sub-200μs latency and no ports/MAC")
        print(f"    {DIM}(your gateway is likely responding to ARP for all subnet IPs){RST}")

    up_hosts = filtered_hosts

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"{CYN}[*]{RST} XML host elements  : {len(all_els)}")
    print(f"{CYN}[*]{RST} Hosts up (status)  : {len(up_hosts)}")
    if drop_down: print(f"{DIM}     status=down      : {drop_down}{RST}")
    if drop_noip: print(f"{DIM}     no IPv4 addr     : {drop_noip}{RST}")

    # ── hosthint fallback ─────────────────────────────────────────────────────
    # nmap writes <hosthint> elements early in the scan (when it confirms a
    # host is up) but only writes the full <host> element AFTER all scanning
    # (SYN, service detection, NSE) is complete. If the scan was killed during
    # a long NSE phase, we have hosthints but no host elements.
    # Recover what we can: IP, status, hostname — no ports or OS, but the host
    # will at least appear in the topology so the user knows it was alive.
    if not up_hosts:
        hints = list(root.iter("hosthint"))
        if hints:
            print(f"{YLW}[!]{RST} No complete <host> elements found — XML was truncated during NSE.")
            print(f"    {DIM}Recovering {len(hints)} live host(s) from <hosthint> records.{RST}")
            print(f"    {DIM}Re-run with a lighter script profile for full port/OS data.{RST}")
            for hint in hints:
                st = hint.find("status")
                if st is None or st.get("state") != "up":
                    continue
                ip = ""
                for addr in hint.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr", "")
                if not ip:
                    continue
                hn = ip
                hn_el = hint.find("hostnames")
                if hn_el is not None:
                    for h in hn_el.findall("hostname"):
                        if h.get("type") in ("user", "PTR"):
                            hn = h.get("name", ip); break
                up_hosts.append({
                    "id": ip, "ip": ip, "hostname": hn,
                    "mac": "", "vendor": "", "os": "", "os_accuracy": 0,
                    "ports": [], "uptime": "", "scripts": {},
                    "_pn_reason": st.get("reason", ""),
                    "_srtt_us": 0,
                    "_from_hint": True,   # flag: no port data
                })
        elif len(all_els) == 0:
            # No hosts and no hints — show what IS in the XML
            child_tags = [c.tag for c in root]
            print(f"{YLW}[!]{RST} Root element children: {child_tags}")
            all_tags: dict[str, int] = {}
            for el in root.iter():
                all_tags[el.tag] = all_tags.get(el.tag, 0) + 1
            print(f"{YLW}[!]{RST} All element tags in XML: {dict(sorted(all_tags.items()))}")
            if xml_str:
                snippet = xml_str[-300:].strip().replace('\n', ' ')
                print(f"{YLW}[!]{RST} Last 300 chars of XML: {DIM}{snippet}{RST}")

    # ── Compute down_ips and no_port_ips from target range ────────────────────
    up_ip_set   = {h["ip"] for h in up_hosts}
    no_port_ips = sorted([h["ip"] for h in up_hosts if not h["ports"]],
                         key=_ip_sort_key)

    down_ips: list[str] = []
    if target:
        all_range = expand_target(target)
        if all_range and len(all_range) <= 2048:
            down_ips = sorted(
                [ip for ip in all_range if ip not in up_ip_set],
                key=_ip_sort_key,
            )

    return up_hosts, meta, down_ips, no_port_ips


def get_local_ips() -> list[str]:
    """
    Return all non-loopback IPv4 addresses assigned to this machine.
    nmap never scans the host it is running on, so we inject these
    manually so the scanner itself appears in the topology.
    """
    ips = []
    try:
        # Works on Linux / macOS
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", result.stdout):
            ip = m.group(1)
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass

    if not ips:
        # Fallback: UDP trick — connect to a routable address (no packet sent)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                ips.append(ip)
        except Exception:
            pass

    return list(dict.fromkeys(ips))   # deduplicate, preserve order


def inject_local_host(hosts: list[dict], target: str) -> list[dict]:
    """
    Add the scanning machine to the host list if it falls inside the
    target range and isn't already present (nmap skips itself by default).
    """
    local_ips = get_local_ips()
    if not local_ips:
        return hosts

    existing_ips = {h["ip"] for h in hosts}

    # Parse the target to check membership.
    # Supports CIDR (192.168.1.0/24) and dash-range (192.168.1.0-50).
    def in_target(ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
            ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

            if "/" in target:
                net, bits = target.split("/")
                nparts    = [int(x) for x in net.split(".")]
                net_int   = (nparts[0]<<24)|(nparts[1]<<16)|(nparts[2]<<8)|nparts[3]
                mask      = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
                return (ip_int & mask) == (net_int & mask)

            if "-" in target.split(".")[-1]:
                # e.g. 192.168.1.0-50
                base = ".".join(target.split(".")[:3])
                lo, hi = target.split(".")[-1].split("-")
                base_p = [int(x) for x in base.split(".")]
                lo_int = (base_p[0]<<24)|(base_p[1]<<16)|(base_p[2]<<8)|int(lo)
                hi_int = (base_p[0]<<24)|(base_p[1]<<16)|(base_p[2]<<8)|int(hi)
                return lo_int <= ip_int <= hi_int
        except Exception:
            pass
        return False

    added = []
    for lip in local_ips:
        if lip in existing_ips:
            continue
        if not in_target(lip):
            continue
        # Get hostname
        try:
            hn = socket.gethostname()
        except Exception:
            hn = lip
        added.append({
            "id": lip, "ip": lip, "hostname": hn,
            "mac": "", "vendor": "local machine",
            "os": "", "os_accuracy": 0,
            "ports": [], "uptime": "", "scripts": {},
            "_local": True,    # flag for display
        })
        print(f"{GRN}[+]{RST} Injected local host: {lip} ({hn})")

    return hosts + added


# ─── Device classifier ────────────────────────────────────────────────────────

def classify_device(host: dict) -> str:
    # Local machine injected by inject_local_host — always "scanner"
    if host.get("_local"):
        return "scanner"

    os_l = host["os"].lower()
    pts  = {p["port"] for p in host["ports"]}
    last = int(host["ip"].split(".")[-1])

    if any(k in os_l for k in ["router","cisco ios","juniper","junos","vyos","openwrt",
                                 "pfsense","mikrotik","fortinet","checkpoint","asa",
                                 "firewall","edgeos","routeros"]):        return "gateway"
    if any(k in os_l for k in ["switch","catalyst","procurve","nexus","powerconnect"]):
                                                                           return "switch"
    if last in (1, 254) and ({23, 161} & pts or not pts):                 return "gateway"
    if {23, 161} <= pts:                                                   return "gateway"
    if any(k in os_l for k in ["embedded","rtos","freertos","vxworks",
                                 "uclinux","busybox","contiki","mbed"]):   return "iot"
    if {1883, 5683} & pts or (554 in pts and len(pts) <= 4):              return "iot"
    if any(k in os_l for k in ["windows 10","windows 11","windows 7",
                                 "windows 8","macos","mac os x"]):         return "workstation"
    if {3389, 139, 135} & pts:                                             return "workstation"
    if any(k in os_l for k in ["server","centos","rhel","debian",
                                 "ubuntu","freebsd","linux"]):             return "server"
    if {80, 443, 22, 8080} & pts and not ({3389, 139} & pts):            return "server"
    return "unknown"


# ─── Topology builder ─────────────────────────────────────────────────────────

def build_topology(hosts: list[dict]) -> tuple[list[dict], list[dict]]:
    rng = random.Random(42)

    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    for h in hosts:
        h["type"] = classify_device(h)

    gw = next((h for h in hosts if h["type"] == "gateway"), None)
    if gw is None and hosts:
        # Only auto-promote to gateway when no gateway was found AND the
        # candidate actually looks like a network device. Never force-promote
        # workstations, servers, IoT devices, or the scanner.
        # On a single-host targeted scan this prevents mislabelling a Windows
        # box with RDP/SMB as a gateway just because it's the only node.
        non_gw_types = {"workstation", "server", "iot", "scanner"}
        candidates = [h for h in hosts if h["type"] not in non_gw_types]
        if candidates:
            gw = candidates[0]; gw["type"] = "gateway"
        # If all hosts are workstations/servers/IoT, leave them as-is.
        # Links won't be drawn but the nodes are correctly labelled.

    sw = next((h for h in hosts if h["type"] == "switch"), None)

    nodes = []
    for h in hosts:
        ports      = sorted(h["ports"], key=lambda p: p["port"])
        risk_count = sum(1 for p in ports if p["risk"] == "danger")
        nodes.append({
            "id":         h["ip"],
            "ip":         h["ip"],
            "hostname":   h["hostname"],
            "type":       h["type"],
            "typeLabel":  DEVICE_LABELS.get(h["type"], h["type"].upper()),
            "mac":        h["mac"],
            "vendor":     h.get("vendor", ""),
            "os":         h["os"],
            "osAccuracy": h["os_accuracy"],
            "uptime":     h["uptime"],
            "ports":      ports,
            "portCount":  len(ports),
            "riskCount":  risk_count,
            "scripts":    h["scripts"],
            "color":      DEVICE_COLORS.get(h["type"], DEVICE_COLORS["unknown"]),
            "radius":     DEVICE_RADII.get(h["type"],  DEVICE_RADII["unknown"]),
            "isLocal":    bool(h.get("_local")),
        })

    links = []
    if gw:
        for h in hosts:
            if h["ip"] == gw["ip"]:
                continue
            if h["type"] in ("switch",):
                links.append({"source": gw["ip"], "target": h["ip"]})
                continue
            # Scanner connects to gateway directly — it is the origin
            if h["type"] == "scanner":
                links.append({"source": h["ip"], "target": gw["ip"]})
                continue
            src = sw["ip"] if sw and rng.random() > 0.3 else gw["ip"]
            links.append({"source": src, "target": h["ip"]})

    return nodes, links


# ─── HTML template ────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configurobulator v1.0 &mdash; __TARGET__ &mdash; __TIMESTAMP__</title>
<style>
/*
 * All layout dimensions are expressed in rem.
 * JS sets document root font-size based on viewport width,
 * so every rem unit scales proportionally on every screen size.
 *
 * Scale targets (logical px → root font-size):
 *   ≤1280px  (small laptop 15.4")  →  11px
 *    1920px  (desktop / 24")       →  13px
 *    2560px  (QHD / 32")           →  16px
 *    3840px  (4K / 55")            →  20px
 *
 * Sidebar, header, panels, fonts all derive from rem so
 * the proportions stay identical at every size.
 */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  /* colours — never change with screen size */
  --bg:  #0c0c10; --bg2: #111116; --bg3: #16161c;
  --br:  #252530; --br2: #303040;
  --t:   #d8d6cc; --t2:  #888880; --t3:  #444448;
  --grn: #1D9E75; --amb: #BA7517; --red: #D85A30;
  --blu: #378ADD; --pur: #534AB7; --pnk: #D4537E;
  --mono: 'Courier New', Courier, monospace;
  /* layout in rem — all driven by root font-size set by JS */
  --hdr-h:    3.6rem;
  --ftr-h:    2.6rem;
  --panel-h: 13rem;
  --sidebar-w: 22rem;
  --gap:       1rem;
  --pad:       0.9rem;
  --radius:    0.2rem;
}

html { font-size: 13px; }   /* JS overrides this */
html, body { width: 100%; height: 100%; }

body {
  background: var(--bg); color: var(--t);
  font-family: var(--mono); font-size: 1rem;
  height: 100vh; overflow: hidden;
  display: grid;
  grid-template-rows: var(--hdr-h) 1fr var(--panel-h) var(--ftr-h);
  grid-template-columns: 1fr var(--sidebar-w);
}

/* ── Header ─────────────────────────────────────────────── */
header {
  grid-column: 1 / -1; grid-row: 1;
  display: flex; align-items: center; gap: 1rem;
  padding: 0 1.2rem;
  background: var(--bg2); border-bottom: 0.5px solid var(--br);
  overflow: hidden;
}
.brand {
  font-size: 1rem; font-weight: bold;
  color: var(--grn); letter-spacing: .08em; flex-shrink: 0;
}
.pill {
  display: flex; align-items: center; gap: 0.3rem;
  padding: 0.2rem 0.6rem;
  background: var(--bg3); border: 0.5px solid var(--br);
  border-radius: var(--radius);
  font-size: 0.77rem; color: var(--t2); white-space: nowrap; flex-shrink: 0;
}
.pill .v     { color: var(--t); }
.pill .v.ok  { color: var(--grn); }
.pill .v.bad { color: var(--red); }
.legend {
  margin-left: auto; display: flex; gap: 0.8rem;
  font-size: 0.77rem; color: var(--t2); flex-shrink: 0;
}
.legend span { display: flex; align-items: center; gap: 0.3rem; }
.dot { width: 0.6rem; height: 0.6rem; border-radius: 50%; flex-shrink: 0; }

/* ── Canvas ─────────────────────────────────────────────── */
#canvas {
  grid-column: 1; grid-row: 2;
  position: relative; overflow: hidden; background: var(--bg);
}
#canvas svg { width: 100%; height: 100%; }
.empty {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  color: var(--t3); pointer-events: none;
}

/* ── Sidebar ─────────────────────────────────────────────── */
#sidebar {
  grid-column: 2; grid-row: 2;
  background: var(--bg2); border-left: 0.5px solid var(--br);
  overflow-y: auto; padding: var(--pad);
}
.placeholder {
  color: var(--t3); font-size: 0.85rem;
  text-align: center; margin-top: 3.5rem; line-height: 1.8;
}
.dev-header {
  display: flex; align-items: center; gap: 0.7rem;
  padding-bottom: 0.7rem; margin-bottom: 0.7rem;
  border-bottom: 0.5px solid var(--br);
}
.tdot  { width: 0.85rem; height: 0.85rem; border-radius: 50%; flex-shrink: 0; }
.dname { font-size: 0.85rem; color: var(--t); font-weight: bold; word-break: break-all; }
.dtype { font-size: 0.69rem; color: var(--t3); letter-spacing: .06em; margin-top: 0.15rem; }
.field {
  display: flex; justify-content: space-between; align-items: baseline;
  padding: 0.25rem 0; border-bottom: 0.5px solid var(--br); gap: 0.6rem;
}
.flbl { font-size: 0.69rem; color: var(--t3); letter-spacing: .05em; flex-shrink: 0; }
.fval {
  font-size: 0.77rem; color: var(--t); text-align: right;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  max-width: 13rem;
}
.sec  { font-size: 0.69rem; color: var(--t3); letter-spacing: .06em; margin: 0.65rem 0 0.3rem; }

/* ── Port tags ──────────────────────────────────────────── */
.ports-wrap { display: flex; flex-wrap: wrap; gap: 0.2rem; margin-bottom: 0.3rem; }
.pt {
  font-size: 0.69rem; padding: 0.15rem 0.45rem;
  border-radius: 0.15rem; cursor: default;
  background: #1a1a22; border: 0.5px solid #252530; color: #888880;
}
.pt.info    { background: #001a12; border-color: #00321e; color: #1D9E75; }
.pt.warning { background: #1e1700; border-color: #3d2e00; color: #BA7517; }
.pt.danger  { background: #1e0a00; border-color: #3d1500; color: #D85A30; }

.banner {
  margin-top: 0.55rem; padding: 0.4rem 0.55rem;
  border-radius: var(--radius); font-size: 0.69rem; line-height: 1.6;
}
.banner.danger  { background: #1e0a00; border: 0.5px solid #3d1500; color: #D85A30; }
.banner.warning { background: #1e1700; border: 0.5px solid #3d2e00; color: #BA7517; }
.script-out {
  font-size: 0.69rem; color: var(--t2);
  background: var(--bg3); border: 0.5px solid var(--br);
  border-radius: var(--radius);
  padding: 0.35rem 0.5rem; white-space: pre-wrap; word-break: break-all;
  max-height: 5.5rem; overflow-y: auto; margin-top: 0.2rem;
}

/* ── Bottom panels ──────────────────────────────────────── */
#bottom-row {
  grid-column: 1 / -1; grid-row: 3;
  display: grid; grid-template-columns: minmax(14rem, 18rem) 1fr 1fr 1fr;
  border-top: 0.5px solid var(--br);
}
.ip-panel { display: flex; flex-direction: column; background: var(--bg2); overflow: hidden; }
.ip-panel + .ip-panel { border-left: 0.5px solid var(--br); }
.ip-panel-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.35rem 0.9rem;
  background: var(--bg3); border-bottom: 0.5px solid var(--br);
  font-size: 0.77rem; font-weight: bold; flex-shrink: 0;
}
.ip-panel-header .count {
  font-size: 0.69rem; font-weight: normal; color: var(--t3);
}
.ip-list { overflow-y: auto; flex: 1; }
.ip-row {
  display: flex; align-items: center; gap: 0.55rem;
  padding: 0.18rem 0.9rem;
  font-size: 0.77rem; color: var(--t2);
  border-bottom: 0.5px solid var(--br);
}
.ip-row:hover { background: var(--bg3); color: var(--t); }
.ip-dot { width: 0.45rem; height: 0.45rem; border-radius: 50%; flex-shrink: 0; }
.ip-empty { padding: 1rem 0.9rem; font-size: 0.77rem; color: var(--t3); text-align: center; }

/* ── Scan config panel ───────────────────────────────────── */
#scan-config { overflow-y: auto; padding: 0.3rem 0; flex: 1; }
.cfg-row {
  display: flex; gap: 0.4rem;
  padding: 0.18rem 0.9rem;
  font-size: 0.75rem;
  border-bottom: 0.5px solid var(--br);
}
.cfg-row:last-child { border-bottom: none; }
.cfg-key  { color: var(--t3); flex-shrink: 0; width: 8rem; }
.cfg-val  { color: var(--t);  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── Footer ─────────────────────────────────────────────── */
footer {
  grid-column: 1 / -1; grid-row: 4;
  display: flex; align-items: center; gap: 1.2rem;
  padding: 0 1rem;
  background: var(--bg2); border-top: 0.5px solid var(--br);
  font-size: 0.77rem; color: var(--t3); overflow: hidden;
}
.fst { display: flex; align-items: center; gap: 0.3rem; white-space: nowrap; }
.fst .v     { color: var(--t2); }
.fst .v.grn { color: var(--grn); }
.fst .v.red { color: var(--red); }
.fst .v.amb { color: var(--amb); }
.fcmd {
  margin-left: auto; font-size: 0.69rem; color: var(--t3);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* ── Graph nodes ─────────────────────────────────────────── */
.net-node { cursor: pointer; }
.net-node circle { transition: stroke-width .12s, filter .12s; }
.net-node:hover circle { filter: brightness(1.3); }

/* ── Scrollbar ───────────────────────────────────────────── */
::-webkit-scrollbar { width: 0.3rem; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--br2); border-radius: 0.15rem; }
/* ── Web scan overlay ──────────────────────────────────────────────────── */
.webpill { cursor: pointer; transition: border-color .12s, color .12s; }
.webpill:hover { border-color: var(--blu); }
.webpill.has-crit .v { color: var(--red); }
#web-overlay {
  position: fixed; inset: 0; z-index: 2000;
  background: rgba(6,6,9,.93);
  display: none; padding: 2rem 1.5rem; overflow-y: auto;
}
#web-overlay.open { display: block; }
.web-wrap { max-width: 62rem; margin: 0 auto; }
.web-head {
  display: flex; justify-content: space-between; align-items: baseline;
  border-bottom: 1px solid var(--br2); padding-bottom: .6rem; margin-bottom: 1rem;
}
.web-head h2 { font-size: 1.05rem; color: var(--blu); letter-spacing: .1em; }
.web-close {
  cursor: pointer; color: var(--t2); border: 1px solid var(--br2);
  padding: .25rem .7rem; border-radius: var(--radius); font-size: .8rem;
}
.web-close:hover { color: var(--t); border-color: var(--red); }
.web-card {
  background: var(--bg2); border: 1px solid var(--br);
  border-radius: var(--radius); margin-bottom: 1rem; padding: .9rem 1.05rem;
}
.web-card.crit { border-left: 3px solid var(--red); }
.web-card-url { color: var(--t); font-size: .95rem; word-break: break-all; }
.web-card-url .status { color: var(--grn); }
.web-meta { color: var(--t2); font-size: .8rem; margin: .35rem 0 .2rem; }
.web-sec { margin-top: .7rem; }
.web-sec-h {
  color: var(--t3); font-size: .68rem; letter-spacing: .12em;
  text-transform: uppercase; margin-bottom: .35rem;
  border-bottom: 1px dotted var(--br); padding-bottom: .15rem;
}
.chip {
  display: inline-block; background: var(--bg3); border: 1px solid var(--br2);
  color: var(--t2); font-size: .72rem; padding: .1rem .45rem;
  border-radius: var(--radius); margin: .12rem .2rem .12rem 0;
}
.kv { font-size: .8rem; color: var(--t2); line-height: 1.55; }
.kv b { color: var(--t); font-weight: normal; }
.web-card-detail {
  color: var(--t3); font-size: .74rem; white-space: pre-wrap;
  margin: .1rem 0 .4rem .6rem;
}
.finding {
  font-size: .8rem; padding: .2rem 0 .2rem .6rem;
  border-left: 2px solid var(--t3); margin: .25rem 0; color: var(--t2);
}
.finding .sv {
  display: inline-block; width: 5rem; font-size: .67rem; letter-spacing: .06em;
}
.sev-CRITICAL, .sev-HIGH { border-left-color: var(--red); }
.sev-CRITICAL .sv, .sev-HIGH .sv { color: var(--red); }
.sev-MEDIUM { border-left-color: var(--amb); }
.sev-MEDIUM .sv { color: var(--amb); }
.sev-LOW { border-left-color: var(--blu); }
.sev-LOW .sv { color: var(--blu); }
.sev-INFO .sv { color: var(--t2); }
.web-empty { color: var(--t3); font-size: .82rem; }
</style>
</head>
<body>

<header>
  <span class="brand">⬡ CONFIGUROBULATOR v1.0</span>
  <div class="pill">TARGET&nbsp;<span class="v">__TARGET__</span></div>
  <div class="pill">SCAN&nbsp;<span class="v">__TIMESTAMP__</span></div>
  <div class="pill">ELAPSED&nbsp;<span class="v">__ELAPSED__</span></div>
  <div class="pill">HOSTS&nbsp;<span class="v ok">__HOSTS_UP__ up</span></div>
  <div class="pill">CRITICAL&nbsp;<span class="v bad" id="hdr-crit">—</span></div>
  <div class="pill webpill" id="web-pill" title="Open web scan results">WEB&nbsp;<span class="v" id="web-count">0</span></div>
  <div class="legend">
    <span><span class="dot" style="background:#D85A30"></span>GW</span>
    <span><span class="dot" style="background:#534AB7"></span>SW</span>
    <span><span class="dot" style="background:#1D9E75"></span>SRV</span>
    <span><span class="dot" style="background:#378ADD"></span>WS</span>
    <span><span class="dot" style="background:#BA7517"></span>IoT</span>
    <span><span class="dot" style="background:#888780"></span>UNK</span>
    <span><span class="dot" style="background:#D4537E"></span>YOU</span>
  </div>
</header>

<div id="canvas">
  <svg id="graph"></svg>
  <div class="empty" id="empty">Initialising graph...</div>
</div>

<div id="sidebar">
  <div class="placeholder">Click any node<br>to inspect device</div>
</div>

<div id="bottom-row">
  <!-- Scan config — column 1 -->
  <div class="ip-panel">
    <div class="ip-panel-header" style="color:var(--pnk)">
      Scan Config
    </div>
    <div id="scan-config">__SCAN_CONFIG_HTML__</div>
  </div>
  <!-- No response — column 2 -->
  <div class="ip-panel">
    <div class="ip-panel-header" style="color:var(--t3)">
      No response
      <span class="count" id="down-count">0 addresses</span>
    </div>
    <div class="ip-list" id="down-list"></div>
  </div>
  <div class="ip-panel">
    <div class="ip-panel-header" style="color:var(--amb)">
      Up — no open ports
      <span class="count" id="noport-count">0 hosts</span>
    </div>
    <div class="ip-list" id="noport-list"></div>
  </div>
  <div class="ip-panel">
    <div class="ip-panel-header" style="color:var(--grn)">
      Up — open ports
      <span class="count" id="active-count">0 hosts</span>
    </div>
    <div class="ip-list" id="active-list"></div>
  </div>
</div>

<footer>
  <div class="fst">LIVE&nbsp;<span class="v grn" id="ft-live">—</span></div>
  <div class="fst">CRITICAL&nbsp;<span class="v red" id="ft-danger">—</span></div>
  <div class="fst">WARNING&nbsp;<span class="v amb" id="ft-warn">—</span></div>
  <div class="fst">HIGH-RISK&nbsp;<span class="v red" id="ft-risky">—</span></div>
  <span class="fcmd" title="__NMAP_CMD__">__NMAP_CMD__</span>
</footer>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
'use strict';

const NODES    = __NODES_JSON__;
const LINKS    = __LINKS_JSON__;
const DOWN_IPS = __DOWN_IPS__;
const NOPORT   = __NOPORT_IPS__;
const ACTIVE   = __ACTIVE_IPS__;

// ── Responsive scaling ───────────────────────────────────────────────────────
//
// Computes a root font-size in px based on the logical viewport width.
// Every rem unit in the CSS then scales proportionally, so the layout
// keeps the same proportions on a 15.4" laptop and a 55" display.
//
// Scale table (logical viewport width → root font size):
//   ≤1280px  →  11px   (small laptop)
//    1920px  →  13px   (standard desktop / 24")
//    2560px  →  16px   (QHD / 32")
//    3840px  →  20px   (4K / 55" at native res)
//
// If the OS scales the display (e.g. 200% on a 4K screen) the browser
// reports a smaller logical width (e.g. 1920px instead of 3840px) — this
// is correct behaviour; the OS has already handled readability.

function computeFontPx(logicalWidth) {
  // Piecewise linear interpolation between breakpoints
  const bp = [
    [0,    11],
    [1280, 11],
    [1920, 13],
    [2560, 16],
    [3840, 20],
    [5120, 24],
  ];
  for (let i = 1; i < bp.length; i++) {
    if (logicalWidth <= bp[i][0]) {
      const t = (logicalWidth - bp[i-1][0]) / (bp[i][0] - bp[i-1][0]);
      return bp[i-1][1] + t * (bp[i][1] - bp[i-1][1]);
    }
  }
  return bp[bp.length - 1][1];
}

function applyScale() {
  const px = computeFontPx(window.innerWidth);
  document.documentElement.style.fontSize = px + 'px';
}

applyScale();
window.addEventListener('resize', applyScale);

// Scale factor relative to 1920px baseline — used to scale D3 radii
function getScale() {
  return computeFontPx(window.innerWidth) / 13;
}

// ── Bottom panels ────────────────────────────────────────────────────────────
function fillPanel(listId, countId, items, dotColor, emptyMsg) {
  const el = document.getElementById(listId);
  const ct = document.getElementById(countId);
  ct.textContent = items.length + (items.length === 1 ? ' address' : ' addresses');
  el.innerHTML = items.length
    ? items.map(ip =>
        `<div class="ip-row">
           <span class="ip-dot" style="background:${dotColor}"></span>
           <span>${ip}</span>
         </div>`
      ).join('')
    : `<div class="ip-empty">${emptyMsg}</div>`;
}

fillPanel('down-list',   'down-count',   DOWN_IPS, '#444448', 'All addresses responded');
fillPanel('noport-list', 'noport-count', NOPORT,   '#BA7517', 'All live hosts have open ports');
fillPanel('active-list', 'active-count', ACTIVE,   '#1D9E75', 'No hosts with open ports found');

// ── Footer stats ──────────────────────────────────────────────────────────────
let dangerTotal = 0, warnTotal = 0, riskyHosts = 0;
for (const n of NODES) {
  let hd = 0;
  for (const p of n.ports) {
    if (p.risk === 'danger')  { dangerTotal++; hd++; }
    if (p.risk === 'warning')   warnTotal++;
  }
  if (hd > 0) riskyHosts++;
}
document.getElementById('ft-live').textContent   = NODES.length;
document.getElementById('ft-danger').textContent = dangerTotal;
document.getElementById('ft-warn').textContent   = warnTotal;
document.getElementById('ft-risky').textContent  = riskyHosts;
document.getElementById('hdr-crit').textContent  = dangerTotal;

// ── D3 force graph ───────────────────────────────────────────────────────────
const canvas = document.getElementById('canvas');
const getWH   = () => ({ W: canvas.clientWidth, H: canvas.clientHeight });
let { W, H }  = getWH();

const svg = d3.select('#graph').attr('width', W).attr('height', H);
document.getElementById('empty').style.display = 'none';

const g = svg.append('g');
svg.call(d3.zoom().scaleExtent([0.08, 10]).on('zoom', e => g.attr('transform', e.transform)));

// Node radii scaled for the current display size
function scaledR(baseR) {
  return baseR * Math.max(0.7, getScale());
}

function setForces() {
  const sc = getScale();
  sim
    .force('link',   d3.forceLink(LINKS).id(d => d.id)
                       .distance(d => 90 * Math.max(0.8, sc)).strength(0.7))
    .force('charge', d3.forceManyBody().strength(-300 * Math.max(0.8, sc)))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('coll',   d3.forceCollide().radius(d => scaledR(d.radius) + 14 * Math.max(0.8, sc)));
}

const sim = d3.forceSimulation(NODES).on('tick', tick);
setForces();

new ResizeObserver(() => {
  const d = getWH();
  if (d.W === W && d.H === H) return;
  W = d.W; H = d.H;
  svg.attr('width', W).attr('height', H);
  setForces();
  sim.alpha(0.3).restart();
}).observe(canvas);

const link = g.append('g').selectAll('line').data(LINKS).join('line')
  .attr('stroke', '#252530').attr('stroke-width', 0.5).attr('opacity', 0.7);

const node = g.append('g').selectAll('g').data(NODES).join('g')
  .attr('class', 'net-node')
  .call(d3.drag()
    .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
  )
  .on('click', (e, d) => { e.stopPropagation(); showDetail(d); });

// Base circle — radius scaled for screen size
node.append('circle')
  .attr('r',    d => scaledR(d.radius))
  .attr('fill', d => d.color)
  .attr('stroke', '#0c0c10').attr('stroke-width', 1.5);

// Risk glow ring
node.filter(d => d.riskCount > 0).append('circle')
  .attr('r',    d => scaledR(d.radius) + 5 * getScale())
  .attr('fill', 'none')
  .attr('stroke', '#D85A30').attr('stroke-width', 0.8).attr('opacity', 0.35);

// Icons — scale with node size
node.filter(d => d.type === 'gateway').append('text')
  .text('◈').attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
  .attr('font-size', d => scaledR(d.radius) * 0.75)
  .attr('fill', '#fff').attr('opacity', 0.85).attr('pointer-events', 'none');

node.filter(d => d.type === 'scanner').append('text')
  .text('⊕').attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
  .attr('font-size', d => scaledR(d.radius) * 0.72)
  .attr('fill', '#fff').attr('opacity', 0.9).attr('pointer-events', 'none');

// IP labels — scale with node size
node.append('text')
  .text(d => d.type === 'scanner' ? d.ip + ' (you)' : d.ip)
  .attr('text-anchor', 'middle')
  .attr('dy', d => scaledR(d.radius) + 9 * getScale())
  .attr('font-family', 'Courier New, monospace')
  .attr('font-size', d => Math.max(8, 8 * getScale()))
  .attr('fill', d => d.type === 'scanner' ? '#D4537E' : '#444448')
  .attr('pointer-events', 'none');

function tick() {
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${d.x},${d.y})`);
}

svg.on('click', () => {
  node.selectAll('circle:first-child').attr('stroke', '#0c0c10').attr('stroke-width', 1.5);
  document.getElementById('sidebar').innerHTML =
    '<div class="placeholder">Click any node<br>to inspect device</div>';
});

// ── Detail sidebar ────────────────────────────────────────────────────────────
function showDetail(d) {
  node.selectAll('circle:first-child')
    .attr('stroke',       n => n.id === d.id ? '#fff' : '#0c0c10')
    .attr('stroke-width', n => n.id === d.id ? 2.5   : 1.5);

  if (d.type === 'scanner') {
    document.getElementById('sidebar').innerHTML = `
      <div class="dev-header">
        <div class="tdot" style="background:${d.color}"></div>
        <div><div class="dname">${esc(d.hostname)}</div>
             <div class="dtype">SCANNER — this machine</div></div>
      </div>
      <div class="field"><span class="flbl">IP ADDRESS</span>
        <span class="fval" style="color:${d.color}">${d.ip}</span></div>
      <div class="field"><span class="flbl">ROLE</span>
        <span class="fval">Scanning host</span></div>
      <div style="margin-top:0.7rem;padding:0.4rem 0.55rem;border-radius:var(--radius);
          font-size:0.69rem;background:var(--bg3);border:0.5px solid var(--br);
          color:var(--t2);line-height:1.7">
        This machine ran the scan. nmap skips its own host, so no port or
        OS data is available. Run a targeted scan against this IP if needed.
      </div>`;
    return;
  }

  const danger  = d.ports.filter(p => p.risk === 'danger');
  const warning = d.ports.filter(p => p.risk === 'warning');

  const portHTML = d.ports.length
    ? `<div class="sec">OPEN PORTS (${d.ports.length})</div>
       <div class="ports-wrap">
         ${d.ports.map(p =>
           `<span class="pt ${p.risk}" title="${esc(p.version || p.service)}">${p.port}/${p.service}</span>`
         ).join('')}
       </div>`
    : `<div class="sec">OPEN PORTS</div>
       <div style="font-size:0.69rem;color:var(--t3);padding:0.3rem 0">
         None detected in scanned range
       </div>`;

  const riskHTML = danger.length
    ? `<div class="banner danger">⚠ CRITICAL — ${danger.length} high-risk port(s):<br>
         ${danger.map(p => p.port + '/' + p.service).join(', ')}</div>`
    : warning.length
    ? `<div class="banner warning">△ MEDIUM — ${warning.length} notable port(s) open</div>`
    : '';

  const scriptKeys = Object.keys(d.scripts || {}).filter(k => d.scripts[k]);
  const scriptHTML = scriptKeys.length
    ? `<div class="sec">SCRIPT OUTPUT</div>` +
      scriptKeys.slice(0, 4).map(k =>
        `<div style="font-size:0.69rem;color:var(--t3);margin-top:0.35rem">${esc(k)}</div>
         <div class="script-out">${esc(d.scripts[k])}</div>`
      ).join('')
    : '';

  document.getElementById('sidebar').innerHTML = `
    <div class="dev-header">
      <div class="tdot" style="background:${d.color}"></div>
      <div><div class="dname">${esc(d.hostname)}</div>
           <div class="dtype">${d.typeLabel}</div></div>
    </div>
    <div class="field"><span class="flbl">IP ADDRESS</span>
      <span class="fval" style="color:${d.color}">${d.ip}</span></div>
    ${d.mac    ? `<div class="field"><span class="flbl">MAC</span>
                  <span class="fval">${d.mac}</span></div>` : ''}
    ${d.vendor ? `<div class="field"><span class="flbl">VENDOR</span>
                  <span class="fval">${esc(d.vendor)}</span></div>` : ''}
    ${d.os     ? `<div class="field"><span class="flbl">OS</span>
                  <span class="fval" title="${esc(d.os)}">
                    ${esc(d.os)}${d.osAccuracy ? ' (' + d.osAccuracy + '%)' : ''}
                  </span></div>` : ''}
    ${d.uptime ? `<div class="field"><span class="flbl">UPTIME</span>
                  <span class="fval">${d.uptime}</span></div>` : ''}
    <div class="field"><span class="flbl">PORTS FOUND</span>
      <span class="fval">${d.portCount}</span></div>
    <div class="field"><span class="flbl">RISK FLAGS</span>
      <span class="fval" style="color:${d.riskCount > 0 ? 'var(--red)' : 'var(--t3)'}">
        ${d.riskCount} critical</span></div>
    ${portHTML}
    ${riskHTML}
    ${scriptHTML}
  `;
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
<div id="web-overlay">
  <div class="web-wrap">
    <div class="web-head">
      <h2>&#9671; WEB SCAN RESULTS</h2>
      <span class="web-close" id="web-close">CLOSE &#10005;</span>
    </div>
    <div id="web-body"></div>
  </div>
</div>

<script>
const WEB_DATA = __WEB_JSON__;
(function(){
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;')
    .replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

  const pill    = document.getElementById('web-pill');
  const overlay = document.getElementById('web-overlay');
  const body    = document.getElementById('web-body');
  const cnt     = document.getElementById('web-count');

  if(!WEB_DATA || !WEB_DATA.length){ if(pill) pill.style.display='none'; return; }

  cnt.textContent = WEB_DATA.length;
  let critTotal = 0;
  WEB_DATA.forEach(r=>{ const s=r.severity_counts||{};
    critTotal += (s.CRITICAL||0)+(s.HIGH||0); });
  if(critTotal>0) pill.classList.add('has-crit');

  function sect(t,inner){
    return '<div class="web-sec"><div class="web-sec-h">'+t+'</div>'+inner+'</div>';
  }

  function card(r){
    const fp=r.fingerprint||{}, tls=r.tls||null, c=r.content||{}, nse=r.nse||null;
    const sc=r.severity_counts||{}, crit=(sc.CRITICAL||0)+(sc.HIGH||0);
    let h='<div class="web-card'+(crit?' crit':'')+'">';
    h+='<div class="web-card-url"><b>'+esc(r.url)+'</b> '+
       '<span class="status">['+esc(fp.status||'\u2014')+']</span></div>';

    if(!r.reachable){
      h+='<div class="web-empty">Unreachable \u2014 '+esc(r.error||'no response')+'</div></div>';
      return h;
    }

    let meta=[];
    if(fp.server)               meta.push('Server: '+esc(fp.server));
    if(fp.powered_by)           meta.push('X-Powered-By: '+esc(fp.powered_by));
    if(fp.title)                meta.push('Title: '+esc(fp.title));
    if(fp.content_length!=null) meta.push(fp.content_length+' bytes');
    h+='<div class="web-meta">'+(meta.join('  \u00b7  ')||'no banner data')+'</div>';

    if(fp.technologies && fp.technologies.length){
      h+=sect('Technology', fp.technologies.map(t=>
        '<span class="chip">'+esc(t)+'</span>').join(''));
    }

    if(tls){
      if(tls.reachable){
        let kv='<div class="kv">'+
          '<div>Protocol: <b>'+esc(tls.protocol||'?')+'</b> &nbsp;\u00b7&nbsp; Cipher: <b>'+esc(tls.cipher||'?')+'</b></div>'+
          (tls.subject?'<div>Subject: <b>'+esc(tls.subject)+'</b></div>':'')+
          (tls.issuer ?'<div>Issuer: <b>'+esc(tls.issuer)+'</b></div>':'')+
          (tls.days_left!=null?'<div>Expires in: <b>'+tls.days_left+' day(s)</b></div>':'')+
          '<div>Self-signed: <b>'+(tls.self_signed?'yes':'no')+'</b> &nbsp;\u00b7&nbsp; '+
          'Hostname match: <b>'+(tls.hostname_match===false?'NO':'yes')+'</b></div>'+
          (tls.legacy_protocols&&tls.legacy_protocols.length?
            '<div>Legacy protocols: <b>'+esc(tls.legacy_protocols.join(', '))+'</b></div>':'')+
          '</div>';
        h+=sect('TLS / Certificate', kv);
      } else {
        h+=sect('TLS / Certificate',
          '<div class="web-empty">Handshake failed \u2014 '+esc(tls.error||'n/a')+'</div>');
      }
    }

    let cb=[];
    if(c.robots&&c.robots.length)   cb.push('robots.txt: <b>'+c.robots.length+'</b> path(s)');
    if(c.sitemap&&c.sitemap.length) cb.push('sitemap.xml: <b>'+c.sitemap.length+'</b> URL(s)');
    if(c.methods&&c.methods.length) cb.push('methods: <b>'+esc(c.methods.join(', '))+'</b>');
    if(c.risky_methods&&c.risky_methods.length)
      cb.push('risky methods: <b>'+esc(c.risky_methods.join(', '))+'</b>');
    if(c.interesting_paths&&c.interesting_paths.length){
      cb.push('paths: '+c.interesting_paths.map(p=>
        esc(p.path)+' ['+p.status+(p.confirmed?'\u2713':'')+']').join('  '));
    }
    if(cb.length) h+=sect('Content Surface',
      '<div class="kv">'+cb.map(x=>'<div>'+x+'</div>').join('')+'</div>');

    if(nse){
      const keys=Object.keys(nse).filter(k=>k!=='_error');
      if(nse._error){
        h+=sect('nmap http-NSE','<div class="web-empty">'+esc(nse._error)+'</div>');
      } else if(keys.length){
        h+=sect('nmap http-NSE', keys.map(k=>
          '<div class="kv"><b>'+esc(k)+'</b></div><div class="web-card-detail">'+
          esc(String(nse[k]).slice(0,500))+'</div>').join(''));
      }
    }

    const F=r.findings||[];
    if(F.length){
      const ord={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
      const sorted=F.slice().sort((a,b)=>
        (ord[a.severity]==null?9:ord[a.severity])-(ord[b.severity]==null?9:ord[b.severity]));
      h+=sect('Findings ('+F.length+')', sorted.map(f=>
        '<div class="finding sev-'+esc(f.severity)+'" title="'+esc(f.detail||'')+'">'+
        '<span class="sv">'+esc(f.severity)+'</span>'+esc(f.title)+'</div>').join(''));
    } else {
      h+=sect('Findings','<div class="web-empty">No findings</div>');
    }
    return h+'</div>';
  }

  body.innerHTML = WEB_DATA.map(card).join('');

  function open(){ overlay.classList.add('open'); }
  function close(){ overlay.classList.remove('open'); }
  pill.addEventListener('click', open);
  document.getElementById('web-close').addEventListener('click', close);
  overlay.addEventListener('click', e=>{ if(e.target===overlay) close(); });
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') close(); });
})();
</script>
</body>
</html>
"""


# ─── HTML renderer ────────────────────────────────────────────────────────────

def render_html(nodes: list[dict], links: list[dict],
                meta: dict, target: str, nmap_cmd: str,
                timestamp: str,
                down_ips: list[str],
                no_port_ips: list[str],
                active_ips: list[str],
                scan_config_html: str = "",
                web_records: list[dict] | None = None) -> str:
    html = HTML_TEMPLATE
    web_records = web_records or []
    for k, v in {
        "__TARGET__":          target,
        "__TIMESTAMP__":       timestamp,
        "__ELAPSED__":         meta.get("elapsed", ""),
        "__HOSTS_UP__":        str(meta.get("hosts_up", len(nodes))),
        "__NMAP_CMD__":        nmap_cmd.replace('"', "&quot;"),
        "__NODES_JSON__":      json.dumps(nodes,      indent=2),
        "__LINKS_JSON__":      json.dumps(links,      indent=2),
        "__DOWN_IPS__":        json.dumps(down_ips),
        "__NOPORT_IPS__":      json.dumps(no_port_ips),
        "__ACTIVE_IPS__":      json.dumps(active_ips),
        "__SCAN_CONFIG_HTML__": scan_config_html,
        "__WEB_JSON__":        json.dumps(web_records, default=str).replace("</", "<\\/"),
    }.items():
        html = html.replace(k, v)
    return html


# ─── Web scanning orchestration ───────────────────────────────────────────────

def _print_web_summary(rec: dict) -> None:
    """One-glance console summary of a single web record."""
    if not rec.get("reachable"):
        print(f"    {DIM}\u2514 {rec.get('url','?')} \u2014 unreachable "
              f"({rec.get('error','no response')}){RST}")
        return
    fp   = rec.get("fingerprint", {})
    sc   = rec.get("severity_counts", {})
    crit = sc.get("CRITICAL", 0) + sc.get("HIGH", 0)
    tag  = (f"{RED}{crit} high/crit{RST}" if crit
            else f"{DIM}{rec.get('finding_count',0)} findings{RST}")
    srv  = fp.get("server") or "server n/d"
    print(f"    {GRN}\u2514{RST} {rec.get('url')}  "
          f"[{fp.get('status','?')}]  {DIM}{srv}{RST}  {tag}")
    tls = rec.get("tls")
    if tls and tls.get("reachable"):
        dl = tls.get("days_left")
        print(f"      {DIM}TLS {tls.get('protocol','?')} \u00b7 cert "
              f"{dl if dl is not None else '?'}d left{RST}")


def collect_web_records(cfg: "Config", hosts: list[dict]) -> list[dict]:
    """
    Run Layer-7 web scans and return a combined list of web records.

    Two sources, matching the two attach modes:
      - auto-run  : every open web port on every discovered host
      - direct    : each explicit cfg.web_targets URL
    """
    if web_scan is None:
        if cfg.web_targets or cfg.web_scan:
            print(f"{YLW}[!]{RST} web_scan module not found \u2014 web scanning "
                  f"skipped (expected web_scan.py beside this script)")
        return []

    records: list[dict] = []

    # ── Auto-run on discovered web ports ──────────────────────────────────────
    if cfg.web_scan:
        web_hosts = [h for h in hosts
                     if any(p.get("port") in web_scan.WEB_PORTS
                            or "http" in (p.get("service") or "").lower()
                            for p in h.get("ports", []))]
        if web_hosts:
            note = "  (with http-NSE)" if cfg.web_nse else ""
            print(f"\n{CYN}[*]{RST} Web scanning {len(web_hosts)} host(s) "
                  f"with web services{note}\u2026")
            for h in web_hosts:
                try:
                    recs = web_scan.scan_configurabulator_host(
                        h, include_nse=cfg.web_nse)
                except Exception as exc:
                    _err(f"web scan failed for {h.get('ip','?')}: {exc}")
                    continue
                for rec in recs:
                    records.append(rec)
                    _print_web_summary(rec)

    # ── Direct URL targets ────────────────────────────────────────────────────
    if cfg.web_targets:
        print(f"\n{CYN}[*]{RST} Web scanning {len(cfg.web_targets)} "
              f"explicit URL target(s)\u2026")
        for url in cfg.web_targets:
            try:
                rec = web_scan.scan_target(url, include_nse=cfg.web_nse)
            except Exception as exc:
                _err(f"web scan failed for {url}: {exc}")
                continue
            records.append(rec)
            _print_web_summary(rec)

    if records:
        total_crit = sum(r.get("severity_counts", {}).get("CRITICAL", 0)
                         + r.get("severity_counts", {}).get("HIGH", 0)
                         for r in records)
        flag = f"  {RED}[{total_crit} high/critical]{RST}" if total_crit else ""
        print(f"{GRN}[+]{RST} Web scan complete \u2014 "
              f"{len(records)} web service(s) profiled{flag}")
    return records


def _web_only_main(args) -> None:
    """Web-only run: scan explicit --web URLs, render a report, skip nmap."""
    if web_scan is None:
        _err("web_scan module not available")
        print(f"  {DIM}web_scan.py must be present beside "
              f"Nmap-Configurabulator.py{RST}")
        return

    out_dir   = args.out_dir or str(Path(__file__).parent)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label     = (args.web[0] if len(args.web) == 1
                 else f"{len(args.web)} web targets")
    out_path  = make_output_path("webscan_" + label, out_dir)

    print(f"{CYN}[*]{RST} Report   : {BOLD}{out_path}{RST}")
    print(f"{CYN}[*]{RST} Timestamp: {timestamp}")
    print(f"{CYN}[*]{RST} Web-only scan \u2014 {len(args.web)} target(s)"
          f"{'  (with http-NSE)' if args.web_nse else ''}\n")

    records: list[dict] = []
    for i, url in enumerate(args.web, 1):
        print(f"{CYN}[*]{RST} ({i}/{len(args.web)}) scanning {BOLD}{url}{RST}")
        try:
            rec = web_scan.scan_target(url, include_nse=args.web_nse)
        except Exception as exc:
            _err(f"web scan failed for {url}: {exc}")
            continue
        records.append(rec)
        _print_web_summary(rec)

    meta = {"elapsed": "", "hosts_up": 0}
    html = render_html([], [], meta, label, "(web-only scan \u2014 no nmap)",
                       timestamp, [], [], [], "", records)
    try:
        out_path.write_text(html, encoding="utf-8")
    except OSError as exc:
        _err(f"could not write report: {exc}")
        return

    total_crit = sum(r.get("severity_counts", {}).get("CRITICAL", 0)
                     + r.get("severity_counts", {}).get("HIGH", 0)
                     for r in records)
    print(f"\n{GRN}[\u2713]{RST} Saved \u2192 {BOLD}{out_path}{RST}  "
          f"({len(html) // 1024}KB)")
    if total_crit:
        print(f"{RED}[!]{RST} {total_crit} high/critical web finding(s)")
    print(f"{CYN}[*]{RST} Open in any modern browser\n")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="nmap → timestamped HTML network topology report  "
                    "(run with no arguments for interactive mode)",
        add_help=True,
    )
    parser.add_argument("target", nargs="?", default=None,
        help="Target subnet/IP — omit to launch interactive configurator")
    parser.add_argument("--no-sudo",  action="store_true",
        help="TCP connect scan only (no root, no OS detection)")
    parser.add_argument("--timing",   default="T4",
        choices=["T1","T2","T3","T4","T5"], metavar="T1-T5")
    parser.add_argument("--ports",    default="driveby",
        choices=["driveby","spyglass","full"])
    parser.add_argument("--scripts",  default="banner",
        choices=list(SCRIPT_PROFILES))
    parser.add_argument("--out-dir",  default=None,
        help="Directory for HTML reports (default: script directory)")
    parser.add_argument("--nmap-args", nargs=argparse.REMAINDER, default=[],
        help="Extra flags forwarded verbatim to nmap (place after --)")
    parser.add_argument("--web", action="append", default=[], metavar="URL",
        help="Web-scan an explicit URL/host directly (repeatable). With no "
             "target argument, runs a web-only scan.")
    parser.add_argument("--no-web", action="store_true",
        help="Disable automatic web scanning of discovered web ports")
    parser.add_argument("--web-nse", action="store_true",
        help="Include nmap http-NSE in web scans (slower, noisier)")
    args = parser.parse_args()

    # Web-only mode — explicit --web URLs with no target: skip nmap entirely.
    if args.target is None and args.web:
        return _web_only_main(args)

    # Interactive mode
    if args.target is None:
        cfg = interactive_config()
        # --web URLs supplied alongside interactive mode still apply
        if args.web:
            cfg.web_targets = list(args.web)
    else:
        cfg              = Config()
        cfg.target       = args.target
        cfg.use_sudo     = not args.no_sudo
        cfg.timing       = args.timing
        cfg.port_profile = args.ports
        cfg.scripts      = args.scripts
        cfg.out_dir      = args.out_dir or str(Path(__file__).parent)
        cfg.extra_args   = [a for a in args.nmap_args if a != "--"]
        cfg.web_scan     = not args.no_web
        cfg.web_nse      = args.web_nse
        cfg.web_targets  = list(args.web or [])

    # Build output path before scanning so we can show it up front
    out_path  = make_output_path(cfg.target, cfg.out_dir)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{CYN}[*]{RST} Report   : {BOLD}{out_path}{RST}")
    print(f"{CYN}[*]{RST} Timestamp: {timestamp}\n")

    # Sanity-check nmap, permissions, and target before committing to a scan
    preflight_check(cfg)

    # Run
    xml_str, nmap_cmd, monitor = run_nmap(cfg)

    # Parse — returns live hosts, meta, down IPs, and no-port IPs
    hosts, meta, down_ips, no_port_ips = parse_nmap_xml(xml_str, cfg.target)

    meta["command"] = nmap_cmd

    # ── Enrich hosthint-recovered hosts with monitor port data ────────────────
    # When the XML is truncated during NSE, hosthint recovery gives us the IP
    # but no ports. The monitor captured every open port live from the PTY
    # stream — those are the ground truth. Inject them now.
    if monitor.discovered_ports:
        enriched = 0
        for h in hosts:
            if not h.get("_from_hint"):
                continue
            live_ports = monitor.discovered_ports.get(h["ip"], [])
            if live_ports:
                h["ports"] = sorted(live_ports, key=lambda p: p["port"])
                enriched += 1
        if enriched:
            print(f"{GRN}[+]{RST} Injected live PTY port data into {enriched} "
                  f"hosthint-recovered host(s)")

    # Recompute no_port_ips after port injection — the parse result is stale
    # if hosthint hosts were enriched above. Also build active_ips (hosts with
    # open ports) for the third bottom panel.
    no_port_ips = sorted(
        [h["ip"] for h in hosts if not h["ports"] and not h.get("_local")],
        key=_ip_sort_key,
    )

    # nmap never scans the machine it's running on — inject it if in range
    hosts = inject_local_host(hosts, cfg.target)

    # ── Web scanning (Layer 7) ────────────────────────────────────────────────
    # Auto-scans discovered web ports and any explicit --web URLs. Returns a
    # list of self-contained web records rendered in the report's web section.
    web_records = collect_web_records(cfg, hosts)

    if not hosts:
        w = 78
        print(f"\n{YLW}{'─' * w}{RST}")
        print(f"{YLW}{BOLD}  NO LIVE HOSTS IN SCAN RESULTS{RST}")
        print(f"{YLW}{'─' * w}{RST}\n")

        xml_bytes = len(xml_str.encode())
        hosts_up   = meta.get("hosts_up",   0)
        hosts_down = meta.get("hosts_down", 0)
        elapsed    = meta.get("elapsed",    "?")

        print(f"  {BOLD}nmap runstats:{RST}")
        print(f"    XML size    : {xml_bytes} bytes")
        print(f"    Elapsed     : {elapsed}")
        print(f"    Hosts up    : {GRN}{hosts_up}{RST}")
        print(f"    Hosts down  : {hosts_down}")
        print()

        if hosts_up > 0:
            print(f"  {YLW}⚑  nmap found {hosts_up} host(s) up but none appeared in results.{RST}")
            print(f"\n  Likely causes:")
            print(f"    1. Port range too narrow — try --ports spyglass or --ports full")
            print(f"    2. Scan was interrupted before results were written")
        else:
            print(f"  {RED}✗  nmap reported 0 responding hosts.{RST}")
            print(f"\n  Likely causes:")
            print(f"    1. Target range wrong — you used: {YLW}{cfg.target}{RST}")
            print(f"    2. ICMP blocked — re-run with Skip ping (-Pn) enabled")
            print(f"    3. Wrong interface — check with: {CYN}ip addr{RST}")

        # Save raw nmap XML for diagnosis — as .txt so browser doesn't try to parse it
        raw_file = out_path.parent / (out_path.stem + "_nmap_raw.txt")
        try:
            raw_file.write_text(xml_str, encoding="utf-8")
            print(f"\n  {DIM}Raw nmap XML saved (text): {raw_file}{RST}")
        except OSError:
            pass

        print(f"\n{YLW}{'─' * w}{RST}\n")

        # Always write an HTML file even on failure so the user always
        # gets their expected output format. The topology will be empty
        # but the bottom panels will show the full range as "no response."
        print(f"{YLW}[!]{RST} Writing empty topology report…")

    else:
        print(f"\n{GRN}[+]{RST} {len(hosts)} host(s) found:\n")

    # Split hosts into two groups BEFORE building the topology:
    #   graph_hosts — up AND have at least one open port (become bubbles)
    #   no_port hosts — up but no open ports (panel only, not in the graph)
    # The scanner (local machine) always goes to the graph regardless of ports.
    graph_hosts = [
        h for h in hosts
        if h["ports"] or h.get("_local")
    ]

    # Classify & build graph from graph_hosts only
    nodes, links = build_topology(graph_hosts) if graph_hosts else ([], [])

    # active_ips: hosts in graph with open ports (excludes scanner)
    active_ips = sorted(
        [n["ip"] for n in nodes if n["portCount"] > 0 and n["type"] != "scanner"],
        key=_ip_sort_key,
    )

    if graph_hosts:
        col = max(len(n["ip"]) for n in nodes) if nodes else 15
        print(f"  {DIM}{'IP':<{col}}  {'TYPE':<12}  {'OS':<40}  PORTS{RST}")
        print(f"  {DIM}{'─'*col}  {'─'*12}  {'─'*40}  {'─'*20}{RST}")
        for n in nodes:
            crits = [f"{p['port']}/{p['service']}" for p in n["ports"] if p["risk"] == "danger"]
            flag  = f"{RED}⚠ {' '.join(crits)}{RST}" if crits else f"{DIM}—{RST}"
            print(f"  {WHT}{n['ip']:<{col}}{RST}  {CYN}{n['type']:<12}{RST}"
                  f"  {DIM}{n['os'][:40]:<40}{RST}  {flag}")
    if no_port_ips:
        print(f"\n  {YLW}Up — no open ports ({len(no_port_ips)}): "
              f"{', '.join(no_port_ips[:8])}{'…' if len(no_port_ips) > 8 else ''}{RST}")

    # Build scan config panel HTML
    def _cfg_row(key, val):
        return (f'<div class="cfg-row">'
                f'<span class="cfg-key">{key}</span>'
                f'<span class="cfg-val" title="{val}">{val}</span>'
                f'</div>')

    timing_label = TIMING_DESC.get(cfg.timing, cfg.timing).split(' — ')[0].strip()
    pn_flag = "-Pn" in cfg.extra_args
    extra   = " ".join(a for a in cfg.extra_args if a != "-Pn") or ""
    scan_config_html = "".join([
        _cfg_row("Target:",       cfg.target),
        _cfg_row("Dir:",          cfg.out_dir),
        _cfg_row("Sudo:",         "yes" if cfg.use_sudo else "no"),
        _cfg_row("Port Scope:",   cfg.port_profile),
        _cfg_row("Timing:",       f"{cfg.timing}  —  {timing_label}"),
        _cfg_row("NSE Profile:",  cfg.scripts),
        _cfg_row("Host Disc.:",   "no (-Pn)" if pn_flag else "yes (ping)"),
        _cfg_row("Extra Args:",   extra if extra else "—"),
    ])

    # Always render and save the HTML report
    html = render_html(nodes, links, meta, cfg.target, nmap_cmd, timestamp,
                       down_ips, no_port_ips, active_ips, scan_config_html,
                       web_records)
    out_path.write_text(html, encoding="utf-8")

    risky = [n["ip"] for n in nodes if n["riskCount"] > 0]
    print(f"\n{GRN}[✓]{RST} Saved → {BOLD}{out_path}{RST}  ({len(html) // 1024}KB)")
    if risky:
        print(f"{RED}[!]{RST} High-risk hosts : {', '.join(risky)}")
    print(f"{CYN}[*]{RST} Open in any modern browser (D3.js CDN required)\n")


if __name__ == "__main__":
    main()
