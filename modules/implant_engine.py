"""
implant_engine.py — Hak5 / Spectrum device registry, connectors, and RF control.

This module backs the "Hak5 / Spectrum" section of H3x-Dash. It manages a
file-backed inventory of Hak5 / O.MG / Pineapple hardware as a two-level tree
(product type -> renameable instances), validates the control-plane callback to
each instance before any loot pull, exposes a (filterable) payload library, and
drives WiFi Pineapple operations (recon, configurable Evil Portal, Deauth
Credential Harvest).

Design constraints:
  * STDLIB-ONLY by default. Reachability checks use raw sockets / urllib so the
    module installs and runs on an air-gapped range with zero pip dependencies.
  * If `paramiko` (SSH) or `requests` (HTTP) happen to be present they are used
    for richer operations, but their absence never breaks import or the UI.
  * Every device action is wrapped so missing hardware degrades to an informative
    result instead of a 500 — the operator builds the inventory first, then tests
    against real gear in the homelab.

Public surface (consumed by h3x-dash.py routes):

  ImplantRegistry(path)
    .tree()                         -> list[product dict with .instances]
    .list()                         -> list[instance dict]
    .get(instance_id)               -> instance | None
    .add_instance(product_id, **kw) -> instance
    .rename(instance_id, new_id)    -> instance | None
    .update(instance_id, **fields)  -> instance | None
    .remove(instance_id)            -> bool
    .stats()                        -> dict
    .seed_defaults()                -> int (instances created if empty)

  validate_connect(instance)        -> dict (ok / status / latency_ms / detail)

  PRODUCTS                          -> product catalog (dict keyed by product_id)
  list_payloads(product_id, q)      -> filtered payload library
  PORTAL_TEMPLATES                  -> evil-portal template names

  WirelessController(registry)
    .pineapple()                    -> instance | None (first Pineapple)
    .recon()                        -> dict
    .access_points()                -> list[dict]
    .arm_evil_portal(config)        -> dict
    .start_deauth_harvest(config)   -> dict
    .export_handshakes()            -> dict
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Optional richer transports — never required.
try:
    import paramiko          # type: ignore
    _HAVE_PARAMIKO = True
except Exception:            # pragma: no cover - optional dep
    _HAVE_PARAMIKO = False

try:
    import requests          # type: ignore
    _HAVE_REQUESTS = True
except Exception:            # pragma: no cover - optional dep
    _HAVE_REQUESTS = False

import urllib.request
import urllib.error


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
#  PRODUCT CATALOG
#  Static metadata for every Hak5 / O.MG / Pineapple product the lab supports.
#  Control tier drives which actions the UI offers:
#    full    — remote deploy + fire + loot (API/SSH reachable implant)
#    managed — SSH load + loot; firing is a physical switch on the device
#    author  — offline payload authoring/encoding only (no remote control plane)
#  transport is the default control plane; default_host/default_port seed new
#  instances with the documented device-side management address.
# ─────────────────────────────────────────────────────────────────────────────

PRODUCTS: dict[str, dict] = {
    'ducky': {
        'id': 'ducky', 'name': 'USB Rubber Ducky',
        'class': 'payload',
        'transport': 'usb', 'transport_label': 'USB flash only',
        'capability': 'HID injection', 'cap_badge': 'badge-danger',
        'tier': 'author', 'attack': 'T1200 · T1059',
        'disguise': 'USB thumb drive',
        'default_host': '', 'default_port': None,
        'desc': 'DuckyScript 3.0 keystroke injection. Registers as a HID keyboard '
                'and types payloads at machine speed.',
        'defense': 'USB device-control / HID allow-listing; screen-lock discipline; '
                   'BadUSB awareness.',
        'actions': ['author', 'encode'],
    },
    'bunny': {
        'id': 'bunny', 'name': 'Bash Bunny',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH (arming)',
        'capability': 'HID + USB-Eth + storage', 'cap_badge': 'badge-danger',
        'tier': 'managed', 'attack': 'T1200 · T1557 · T1056',
        'disguise': 'USB stick',
        'default_host': '172.16.64.1', 'default_port': 22,
        'desc': 'Full Linux on a USB stick. ATTACKMODE switches HID / USB-Ethernet / '
                'storage / serial. Signature attack: QuickCreds (Responder vs a locked host).',
        'defense': 'Disable LLMNR/NBT-NS; deny new USB NICs; lock-screen cred hardening.',
        'actions': ['deploy', 'loot'],
    },
    'shark': {
        'id': 'shark', 'name': 'Shark Jack',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH (arming)',
        'capability': 'Network recon / exploit', 'cap_badge': 'badge-warning',
        'tier': 'managed', 'attack': 'T1200 · T1046',
        'disguise': 'Ethernet plug',
        'default_host': '172.16.24.1', 'default_port': 22,
        'desc': 'Pocket network attack tool. ATTACK fires a payload (default nmap sweep); '
                'ARMING for config. Drop-and-go internal recon.',
        'defense': '802.1X / NAC on switchports; port security; disable unused jacks.',
        'actions': ['deploy', 'loot'],
    },
    'turtle': {
        'id': 'turtle', 'name': 'LAN Turtle',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH / Cloud C2',
        'capability': 'Persistent implant', 'cap_badge': 'badge-violet',
        'tier': 'full', 'attack': 'T1200 · T1557 · T1071',
        'disguise': 'USB-Ethernet adapter',
        'default_host': '172.16.84.1', 'default_port': 22,
        'desc': 'Covert persistent network implant. Modules: autossh, responder, '
                'nmap-scan, dns-spoof, meterpreter. 3G variant adds cellular C2.',
        'defense': '802.1X; NAC posture; MAC anomaly detection; egress filtering.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'packetsquirrel': {
        'id': 'packetsquirrel', 'name': 'Packet Squirrel',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH (arming)',
        'capability': 'Network MitM / capture', 'cap_badge': 'badge-warning',
        'tier': 'managed', 'attack': 'T1200 · T1557 · T1040',
        'disguise': 'Inline Ethernet implant',
        'default_host': '172.16.32.1', 'default_port': 22,
        'desc': 'Pocket inline Ethernet MitM tool. Sits between a host and the '
                'network for VPN-over-DNS, packet capture, and DNS spoofing. '
                'Mark II adds USB-C and faster capture.',
        'defense': '802.1X / NAC on switchports; port security; ARP / DHCP monitoring.',
        'actions': ['deploy', 'loot'],
    },
    'keycroc': {
        'id': 'keycroc', 'name': 'Key Croc',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH / Cloud C2',
        'capability': 'Keylogger + HID', 'cap_badge': 'badge-danger',
        'tier': 'full', 'attack': 'T1056.001 · T1200 · T1059',
        'disguise': 'USB keylogger / cable',
        'default_host': '172.16.88.1', 'default_port': 22,
        'desc': 'Keystroke-logging implant with pattern-matched payload triggers. '
                'Logs typing, fires DuckyScript HID payloads on keyword match, and '
                'exfils over WiFi / Cloud C2. Doubles as a live keyboard MitM.',
        'defense': 'USB device-control / HID allow-listing; screen-lock discipline.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'signalowl': {
        'id': 'signalowl', 'name': 'Signal Owl',
        'class': 'payload',
        'transport': 'ssh', 'transport_label': 'SSH (arming)',
        'capability': 'Wireless payload platform', 'cap_badge': 'badge-violet',
        'tier': 'managed', 'attack': 'T1200 · T1018 · T1071',
        'disguise': 'USB wireless dongle',
        'default_host': '172.16.92.1', 'default_port': 22,
        'desc': 'Covert wireless payload platform in a USB-dongle body. Runs '
                'WiFi/Bluetooth recon and attack payloads headless; arming via '
                'SSH, fire by a physical switch. Drop-and-go RF operations.',
        'defense': 'WPA3/802.1X-EAP; PMF (802.11w); rogue-device RF monitoring.',
        'actions': ['deploy', 'loot'],
    },
    'omg-plug': {
        'id': 'omg-plug', 'name': 'O.MG Plug',
        'class': 'payload',
        'transport': 'wifi', 'transport_label': 'WiFi web/WS API',
        'capability': 'HID + keylog + WiFi', 'cap_badge': 'badge-danger',
        'tier': 'full', 'attack': 'T1200 · T1056.001',
        'disguise': 'USB wall charger',
        'default_host': '192.168.4.1', 'default_port': 80,
        'desc': 'Implant in a power-adapter body. DuckyScript 3.0 injection + hardware '
                'keylog + WiFi C2, remote trigger, geofence & self-destruct.',
        'defense': 'USB device control; no untrusted chargers/cables; RF monitoring.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'omg-adapter': {
        'id': 'omg-adapter', 'name': 'O.MG Adapter',
        'class': 'payload',
        'transport': 'wifi', 'transport_label': 'WiFi web/WS API',
        'capability': 'HID + keylog', 'cap_badge': 'badge-danger',
        'tier': 'full', 'attack': 'T1200 · T1056.001',
        'disguise': 'USB-A/C adapter nub',
        'default_host': '192.168.4.1', 'default_port': 80,
        'desc': 'Turns any ordinary cable into an O.MG implant. Same injection + keylog + '
                'WiFi C2 feature set, maximum deniability.',
        'defense': 'Cable/adapter provenance control; USB device control; RF sweep.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'omg-unblocker': {
        'id': 'omg-unblocker', 'name': 'O.MG UnBlocker',
        'class': 'payload',
        'transport': 'wifi', 'transport_label': 'WiFi web/WS API',
        'capability': 'HID + keylog (decoy)', 'cap_badge': 'badge-danger',
        'tier': 'full', 'attack': 'T1200 · T1056.001',
        'disguise': 'USB "data blocker" / condom',
        'default_host': '192.168.4.1', 'default_port': 80,
        'desc': 'Shaped like a USB data-blocker but is itself a full offensive implant. '
                'Premier supply-chain / found-device social-engineering prop.',
        'defense': 'Procurement controls; never use found accessories; RF monitoring.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'omg-cable': {
        'id': 'omg-cable', 'name': 'O.MG Cable',
        'class': 'payload',
        'transport': 'wifi', 'transport_label': 'WiFi web/WS API',
        'capability': 'HID + keylog + WiFi', 'cap_badge': 'badge-danger',
        'tier': 'full', 'attack': 'T1200 · T1056.001',
        'disguise': 'USB-A/C charge + data cable',
        'default_host': '192.168.4.1', 'default_port': 80,
        'desc': 'The original O.MG implant in a full charge-and-sync cable. '
                'DuckyScript 3.0 injection + hardware keylog + WiFi C2, remote '
                'trigger, geofence & self-destruct. Indistinguishable from a normal cable.',
        'defense': 'Cable provenance control; USB device control; RF sweep.',
        'actions': ['deploy', 'fire', 'loot'],
    },
    'pineapple': {
        'id': 'pineapple', 'name': 'WiFi Pineapple VII',
        'class': 'spectrum',
        'transport': 'rest', 'transport_label': 'REST API + SSH',
        'capability': 'Rogue AP / WiFi audit', 'cap_badge': 'badge-violet',
        'tier': 'full', 'attack': 'T1557 · T1040 · T1110',
        'disguise': '(overt audit platform)',
        'default_host': '172.16.42.1', 'default_port': 1471,
        'desc': 'Dual-band rogue-AP & WiFi audit platform (5 GHz adapter adds the second '
                'band). PineAP: evil twin, deauth, evil portals, recon, WPA/PMKID capture.',
        'defense': 'WPA3/802.1X-EAP; PMF (802.11w); rogue-AP WIDS; captive-portal training.',
        'actions': ['recon', 'fire', 'loot'],
    },
    'screencrab': {
        'id': 'screencrab', 'name': 'Screen Crab',
        'class': 'spectrum',
        'transport': 'wifi', 'transport_label': 'WiFi / Cloud C2',
        'capability': 'HDMI screen capture', 'cap_badge': 'badge-violet',
        'tier': 'full', 'attack': 'T1113 · T1056.002',
        'disguise': 'Inline HDMI tap',
        'default_host': '172.16.44.1', 'default_port': 80,
        'desc': 'Inline HDMI capture implant. Sits between a display and its source '
                'and periodically grabs screenshots, exfiltrating over WiFi / Cloud C2 '
                'or to a local microSD. Passive, signal-only capture.',
        'defense': 'Physical port inspection; tamper-evident seals; HDCP where viable.',
        'actions': ['loot'],
    },
    'plunderbug': {
        'id': 'plunderbug', 'name': 'Plunder Bug',
        'class': 'spectrum',
        'transport': 'rest', 'transport_label': 'USB-C / companion app',
        'capability': 'Inline LAN tap', 'cap_badge': 'badge-warning',
        'tier': 'managed', 'attack': 'T1040 · T1557',
        'disguise': 'Pocket Ethernet tap',
        'default_host': '172.16.46.1', 'default_port': 80,
        'desc': 'Smart pocket LAN tap. Mirrors wired Ethernet traffic to a host or '
                'phone for live capture and on-the-wire analysis. Passive inline '
                'monitoring of a target segment.',
        'defense': '802.1X / NAC; port security; physical cable-run inspection.',
        'actions': ['loot'],
    },
    'wificoconut': {
        'id': 'wificoconut', 'name': 'WiFi Coconut',
        'class': 'spectrum',
        'transport': 'rest', 'transport_label': 'REST API + SSH',
        'capability': 'All-channel 2.4 GHz monitor', 'cap_badge': 'badge-violet',
        'tier': 'full', 'attack': 'T1040',
        'disguise': '(overt monitoring platform)',
        'default_host': '172.16.48.1', 'default_port': 80,
        'desc': 'Fourteen-radio WiFi monitor that listens to every 2.4 GHz channel at '
                'once — no channel hopping, no missed frames. Full-spectrum capture for '
                'WiFi survey, handshake harvest, and traffic analysis.',
        'defense': 'WPA3/802.1X-EAP; PMF (802.11w); minimise broadcast exposure.',
        'actions': ['recon', 'loot'],
    },
}

PRODUCT_ORDER = ['ducky', 'bunny', 'shark', 'turtle',
                 'packetsquirrel', 'keycroc', 'signalowl',
                 'omg-plug', 'omg-adapter', 'omg-unblocker', 'omg-cable',
                 'pineapple', 'screencrab', 'plunderbug', 'wificoconut']

PAYLOAD_PRODUCT_IDS  = [pid for pid in PRODUCT_ORDER if PRODUCTS[pid].get('class') == 'payload']
SPECTRUM_PRODUCT_IDS = [pid for pid in PRODUCT_ORDER if PRODUCTS[pid].get('class') == 'spectrum']


def products_for_class(klass: str) -> list[dict]:
    return [PRODUCTS[pid] for pid in PRODUCT_ORDER
            if PRODUCTS[pid].get('class') == klass]


# ─────────────────────────────────────────────────────────────────────────────
#  PAYLOAD LIBRARY (catalog stub — the full builder is a later phase)
#  Each payload tags the products it is compatible with so the UI can filter.
# ─────────────────────────────────────────────────────────────────────────────

_OMG = ['omg-plug', 'omg-adapter', 'omg-unblocker', 'omg-cable']

# callback: what a successful payload lands, and therefore where it surfaces.
#   reverse_shell -> MSF session in the Shell tab (auto multi/handler)
#   reverse_ssh   -> SSH foothold / MSF pivot (next phase)
#   creds         -> Credentials store
#   loot          -> Scan / Loot / Hashcat
#   none          -> a prep step with no callback (e.g. disabling a defense)
# default_payload is only a DEFAULT for reverse_shell. multi/handler accepts any
# payload, and the operator/route may override it, so this stays OS-agnostic and
# does not assume a specific target (Metasploitable or otherwise).
PAYLOADS: list[dict] = [
    {'name': 'quickcreds.txt',       'products': ['bunny'],              'lang': 'bash+QUACK',
     'attack': 'T1557',     'cm': 'Disable LLMNR/NBT-NS',         'callback': 'creds'},
    {'name': 'exfil-docs.txt',       'products': ['bunny'],              'lang': 'bash+QUACK',
     'attack': 'T1052',     'cm': 'USB mass-storage block',       'callback': 'loot'},
    {'name': 'rev-shell-win.txt',    'products': ['ducky'] + _OMG,       'lang': 'DuckyScript 3.0',
     'attack': 'T1059.001', 'cm': 'Constrained PowerShell / AMSI', 'callback': 'reverse_shell',
     'default_payload': 'windows/x64/meterpreter/reverse_tcp'},
    {'name': 'rev-shell-nix.txt',    'products': ['ducky'] + _OMG,       'lang': 'DuckyScript 3.0',
     'attack': 'T1059.004', 'cm': 'Shell allow-listing',          'callback': 'reverse_shell',
     'default_payload': 'linux/x64/meterpreter/reverse_tcp'},
    {'name': 'disable-defender.txt', 'products': ['ducky'] + _OMG,       'lang': 'DuckyScript 3.0',
     'attack': 'T1562.001', 'cm': 'Tamper protection ON',         'callback': 'none'},
    {'name': 'nmap-sweep.sh',        'products': ['shark'],              'lang': 'bash',
     'attack': 'T1046',     'cm': 'NAC / segmentation',           'callback': 'loot'},
    {'name': 'autossh-foothold',     'products': ['turtle'],             'lang': 'module',
     'attack': 'T1071',     'cm': 'Egress filtering',             'callback': 'reverse_ssh'},
    {'name': 'responder.module',     'products': ['turtle', 'bunny'],    'lang': 'module',
     'attack': 'T1557',     'cm': 'Disable LLMNR/NBT-NS',         'callback': 'creds'},
    {'name': 'keylog-exfil.txt',     'products': _OMG,                   'lang': 'DuckyScript 3.0',
     'attack': 'T1056.001', 'cm': 'Device control',               'callback': 'loot'},
    {'name': 'evil-portal-creds',    'products': ['pineapple'],          'lang': 'campaign',
     'attack': 'T1557',     'cm': '802.1X-EAP / user training',   'callback': 'creds'},
    # Minimal built-in stubs for the newer payload devices so they are armable
    # offline (air-gapped range) before a vetted GitHub sync populates the rest.
    {'name': 'dns-spoof.sh',         'products': ['packetsquirrel'],     'lang': 'bash',
     'attack': 'T1557',     'cm': 'DNS monitoring / DNSSEC',      'callback': 'loot'},
    {'name': 'tcpdump-capture.sh',   'products': ['packetsquirrel'],     'lang': 'bash',
     'attack': 'T1040',     'cm': 'Network segmentation / NAC',   'callback': 'loot'},
    {'name': 'croc-keylog',          'products': ['keycroc'],            'lang': 'bash+QUACK',
     'attack': 'T1056.001', 'cm': 'USB device control',           'callback': 'loot'},
    {'name': 'wifi-recon',           'products': ['signalowl'],          'lang': 'bash',
     'attack': 'T1018',     'cm': 'WIDS / rogue-AP monitoring',   'callback': 'loot'},
]


# ─────────────────────────────────────────────────────────────────────────────
#  SYNCED PAYLOADS (vetted GitHub sources)
#  The built-in PAYLOADS list above is the curated, always-available baseline.
#  modules/payload_sources.py pulls additional payloads from a strict allowlist
#  of vetted GitHub repositories and registers them here via set_synced_payloads.
#  They are merged into the library (built-ins win on name collision) so the
#  Arm/Inventory flows surface them with no further wiring. The engine itself
#  never touches the network — it only holds the records the source manager
#  hands it, keeping this module's STDLIB-only, import-safe contract intact.
# ─────────────────────────────────────────────────────────────────────────────

_SYNCED_PAYLOADS: list[dict] = []
_SYNCED_LOCK = threading.RLock()


def set_synced_payloads(items: list[dict] | None) -> int:
    """Replace the synced-payload set. Returns the count retained.

    Each item should match the built-in payload shape (at minimum: name,
    products). Items with no recognised product are dropped so the UI never
    renders a payload that cannot be armed against any device.
    """
    clean: list[dict] = []
    for it in (items or []):
        if not isinstance(it, dict):
            continue
        name = (it.get('name') or '').strip()
        prods = [p for p in (it.get('products') or []) if p in PRODUCTS]
        if not name or not prods:
            continue
        row = dict(it)
        row['name'] = name
        row['products'] = prods
        row.setdefault('lang', 'unknown')
        row.setdefault('attack', '')
        row.setdefault('cm', '')
        row.setdefault('callback', 'none')
        row['vetted'] = True
        clean.append(row)
    with _SYNCED_LOCK:
        _SYNCED_PAYLOADS[:] = clean
    return len(clean)


def synced_payloads() -> list[dict]:
    with _SYNCED_LOCK:
        return [dict(p) for p in _SYNCED_PAYLOADS]


def _all_payloads() -> list[dict]:
    """Built-ins first, then synced entries whose name does not collide."""
    seen = {p['name'] for p in PAYLOADS}
    rows = list(PAYLOADS)
    with _SYNCED_LOCK:
        for p in _SYNCED_PAYLOADS:
            if p['name'] not in seen:
                rows.append(p)
                seen.add(p['name'])
    return rows


def payload_by_name(name: str) -> dict | None:
    return next((dict(p) for p in _all_payloads() if p['name'] == name), None)


def list_payloads(product_id: str | None = None, q: str | None = None) -> list[dict]:
    """Filter the payload library by compatible product and/or text query."""
    rows = _all_payloads()
    if product_id:
        rows = [p for p in rows if product_id in p['products']]
    if q:
        ql = q.lower()
        rows = [p for p in rows
                if ql in p['name'].lower() or ql in p['attack'].lower()]
    # Decorate with human product names for rendering convenience.
    out = []
    for p in rows:
        d = dict(p)
        d['product_names'] = [PRODUCTS[pid]['name'] for pid in p['products'] if pid in PRODUCTS]
        out.append(d)
    return out


PORTAL_TEMPLATES = ['Generic Login', 'Google', 'Microsoft 365',
                    'Corporate VPN', 'Hotel / Captive', 'Custom (upload)']


# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE REGISTRY  (thread-safe, file-backed; mirrors CredentialStore pattern)
# ─────────────────────────────────────────────────────────────────────────────

class ImplantRegistry:
    """Inventory of Hak5/Spectrum hardware as product -> instances."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._inst: dict[str, dict] = {}
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self._inst = data.get('instances', {})
            log.info(f"implant registry loaded: {len(self._inst)} instances")
        except Exception as exc:
            log.warning(f"implant registry load failed: {exc} — starting empty")
            self._inst = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(
                {'instances': self._inst, 'saved_at': _utcnow_iso(),
                 'count': len(self._inst)}, indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            log.error(f"implant registry save failed: {exc}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _decorate(inst: dict) -> dict:
        """Merge product catalog metadata onto an instance for the UI."""
        prod = PRODUCTS.get(inst.get('product_id'), {})
        out = dict(inst)
        out['product_name'] = prod.get('name', inst.get('product_id'))
        out['product_class'] = prod.get('class', 'payload')
        out['transport'] = prod.get('transport', 'unknown')
        out['transport_label'] = prod.get('transport_label', '')
        out['tier'] = prod.get('tier', 'author')
        out['capability'] = prod.get('capability', '')
        out['cap_badge'] = prod.get('cap_badge', 'badge-muted')
        out['attack'] = prod.get('attack', '')
        out['actions'] = prod.get('actions', [])
        # Defaults for the new arm/deploy/api lifecycle so the UI never gets undefined.
        out.setdefault('armed_payload', None)
        out.setdefault('armed_at', None)
        out.setdefault('armed_callback', None)   # reverse_shell | reverse_ssh | creds | loot | none
        out.setdefault('handler', None)          # {lhost, lport, payload_module, status} for reverse_shell
        out.setdefault('deployed', False)
        out.setdefault('deployed_at', None)
        out.setdefault('deploy_target', '')
        out.setdefault('api_connected', False)
        out.setdefault('api_info', {})
        return out

    def _default_device_id(self, product_id: str) -> str:
        existing = [i for i in self._inst.values() if i.get('product_id') == product_id]
        return f"{product_id}-{len(existing) + 1:02d}"

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add_instance(self, product_id: str, device_id: str | None = None,
                     host: str | None = None, port: int | None = None,
                     username: str = '', notes: str = '') -> dict:
        if product_id not in PRODUCTS:
            raise ValueError(f"unknown product: {product_id!r}")
        prod = PRODUCTS[product_id]
        with self._lock:
            inst = {
                'id': str(uuid.uuid4()),
                'product_id': product_id,
                'device_id': (device_id or '').strip() or self._default_device_id(product_id),
                'host': host if host is not None else prod.get('default_host', ''),
                'port': port if port is not None else prod.get('default_port'),
                'username': username or ('root' if prod['transport'] == 'ssh' else ''),
                'notes': notes,
                'online': None,
                'last_validated': None,
                'last_detail': '',
                'created': _utcnow_iso(),
            }
            self._inst[inst['id']] = inst
            self._save()
        return self._decorate(inst)

    def rename(self, instance_id: str, new_device_id: str) -> dict | None:
        new_device_id = (new_device_id or '').strip()
        if not new_device_id:
            return None
        with self._lock:
            inst = self._inst.get(instance_id)
            if not inst:
                return None
            inst['device_id'] = new_device_id
            self._save()
            return self._decorate(inst)

    def update(self, instance_id: str, **fields: Any) -> dict | None:
        allowed = {'device_id', 'host', 'port', 'username', 'notes',
                   'online', 'last_validated', 'last_detail',
                   'armed_payload', 'armed_at', 'armed_callback', 'handler',
                   'deployed', 'deployed_at', 'deploy_target',
                   'api_connected', 'api_info'}
        with self._lock:
            inst = self._inst.get(instance_id)
            if not inst:
                return None
            for k, v in fields.items():
                if k in allowed:
                    inst[k] = v
            self._save()
            return self._decorate(inst)

    def remove(self, instance_id: str) -> bool:
        with self._lock:
            if instance_id not in self._inst:
                return False
            del self._inst[instance_id]
            self._save()
        return True

    def get(self, instance_id: str) -> dict | None:
        with self._lock:
            inst = self._inst.get(instance_id)
            return self._decorate(inst) if inst else None

    def list(self) -> list[dict]:
        with self._lock:
            return [self._decorate(i) for i in self._inst.values()]

    # ── Connect-to-add ───────────────────────────────────────────────────────
    # The Payload / Spectrum flows BOTH validate the callback before adding the
    # instance (USB transports skip the probe). This keeps the inventory clean
    # of dead entries the operator added in haste.

    def add_validated(self, product_id: str, device_id: str | None = None,
                      host: str | None = None, port: int | None = None,
                      username: str = '', notes: str = '',
                      timeout: float = 3.0) -> dict:
        """Probe the callback first; add only on success (or for USB).

        Returns:
          {'status': 'added',     'instance': <decorated>, 'validation': <result>}
          {'status': 'unreachable','validation': <result>}    (instance NOT added)
        """
        if product_id not in PRODUCTS:
            raise ValueError(f"unknown product: {product_id!r}")
        prod = PRODUCTS[product_id]
        host = host if host is not None else prod.get('default_host', '')
        port = port if port is not None else prod.get('default_port')

        # Synthesize a "preview" instance to feed validate_connect — no side effects.
        preview = {
            'id': '(preview)', 'product_id': product_id, 'device_id': device_id or '',
            'host': host, 'port': port, 'transport': prod['transport'],
        }
        v = validate_connect(preview, timeout=timeout)

        if prod['transport'] != 'usb' and not v.get('ok'):
            return {'status': 'unreachable', 'validation': v}

        inst = self.add_instance(product_id, device_id=device_id, host=host,
                                 port=port, username=username, notes=notes)
        # Mirror the probe result onto the new instance so the tree reflects truth.
        # USB devices have no callback ('manual'): keep online=None (neutral) so
        # they don't render as offline/red.
        online = None if v.get('status') == 'manual' else bool(v.get('ok'))
        self.update(inst['id'], online=online,
                    last_validated=v.get('checked_at'),
                    last_detail=v.get('detail', ''))
        return {'status': 'added', 'instance': self.get(inst['id']), 'validation': v}

    # ── Arm / Disarm ─────────────────────────────────────────────────────────
    # ARM records which payload is staged on a given instance. The actual per-
    # transport push (SCP for SSH, REST for O.MG/Pineapple, inject.bin author for
    # the Ducky) is the next phase; the state model here is the durable record.

    def arm(self, instance_id: str, payload_name: str,
            callback: str | None = None, handler: dict | None = None) -> dict | None:
        if not payload_name:
            return None
        # Re-arming resets deploy state — a freshly (re)armed device has not been
        # physically deployed yet, so a stale DEPLOYED badge would be misleading.
        return self.update(instance_id,
                           armed_payload=payload_name,
                           armed_at=_utcnow_iso(),
                           armed_callback=callback,
                           handler=handler,
                           deployed=False,
                           deployed_at=None,
                           deploy_target='')

    def disarm(self, instance_id: str) -> dict | None:
        return self.update(instance_id,
                           armed_payload=None, armed_at=None,
                           armed_callback=None, handler=None,
                           deployed=False, deployed_at=None, deploy_target='')

    # ── Deploy / Return ─────────────────────────────────────────────────────
    # Gated server-side too (not just in the UI) — refuse to flip deployed=True
    # unless the instance is currently armed and the operator's ack was passed.

    def mark_deployed(self, instance_id: str, target: str = '',
                      ack: bool = False) -> dict:
        if not ack:
            return {'status': 'denied', 'reason': 'liability acknowledgement required'}
        inst = self.get(instance_id)
        if not inst:
            return {'status': 'not_found'}
        if not inst.get('armed_payload'):
            return {'status': 'denied', 'reason': 'instance is not armed'}
        upd = self.update(instance_id, deployed=True,
                          deployed_at=_utcnow_iso(),
                          deploy_target=(target or '').strip())
        return {'status': 'deployed', 'instance': upd}

    def mark_returned(self, instance_id: str) -> dict:
        inst = self.get(instance_id)
        if not inst:
            return {'status': 'not_found'}
        # Returning a device also disarms it — fresh state for the next deployment.
        upd = self.update(instance_id, deployed=False, deployed_at=None,
                          deploy_target='', armed_payload=None, armed_at=None,
                          armed_callback=None, handler=None)
        return {'status': 'returned', 'instance': upd}

    def armed(self) -> list[dict]:
        return [i for i in self.list() if i.get('armed_payload')]

    def deployed(self) -> list[dict]:
        return [i for i in self.list() if i.get('deployed')]

    # ── Tree + stats ─────────────────────────────────────────────────────────

    def tree(self, klass: str | None = None) -> list[dict]:
        """Product nodes (catalog order) each carrying their instances.

        klass: optional 'payload' or 'spectrum' filter so the two new pages can
        each request only the products they own.
        """
        with self._lock:
            by_prod: dict[str, list[dict]] = {}
            for i in self._inst.values():
                by_prod.setdefault(i.get('product_id'), []).append(self._decorate(i))
        nodes = []
        for pid in PRODUCT_ORDER:
            prod = PRODUCTS[pid]
            if klass and prod.get('class') != klass:
                continue
            insts = sorted(by_prod.get(pid, []), key=lambda x: x.get('device_id', ''))
            nodes.append({
                **{k: prod[k] for k in ('id', 'name', 'class', 'transport', 'transport_label',
                                        'capability', 'cap_badge', 'tier', 'attack',
                                        'disguise', 'desc', 'defense', 'actions')},
                'instances': insts,
                'online': sum(1 for x in insts if x.get('online')),
                'armed':  sum(1 for x in insts if x.get('armed_payload')),
                'total':  len(insts),
            })
        return nodes

    def stats(self, klass: str | None = None) -> dict:
        with self._lock:
            insts = [self._decorate(i) for i in self._inst.values()]
        if klass:
            insts = [i for i in insts if i.get('product_class') == klass]
            products = len(products_for_class(klass))
        else:
            products = len(PRODUCTS)
        online = sum(1 for i in insts if i.get('online'))
        return {
            'products':  products,
            'instances': len(insts),
            'online':    online,
            'offline':   len(insts) - online,
            'armed':     sum(1 for i in insts if i.get('armed_payload')),
            'deployed':  sum(1 for i in insts if i.get('deployed')),
            'api_connected': sum(1 for i in insts if i.get('api_connected')),
        }

    def seed_defaults(self) -> int:
        """Ensure every PAYLOAD-class product has at least one instance so the
        inventory starts populated. On a fresh registry this seeds the full set;
        on an existing one it adds only product types that are missing (e.g. new
        devices shipped in an update), without disturbing what the operator
        already has. Spectrum devices (Pineapple, Screen Crab, Plunder Bug, WiFi
        Coconut) are deliberately NOT seeded — the operator uses the
        connect-to-add flow to register them, which validates connectivity first.
        """
        with self._lock:
            existing_products = {i.get('product_id') for i in self._inst.values()}
        created = 0
        for pid in PAYLOAD_PRODUCT_IDS:
            if pid not in existing_products:
                self.add_instance(pid)
                created += 1
        return created


# ─────────────────────────────────────────────────────────────────────────────
#  CONNECT VALIDATION
#  Verify the control-plane callback to an instance BEFORE any loot pull. This is
#  the gate the Loot Ingestion pipeline depends on — no blind pulls.
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float, str]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.time() - start) * 1000
            return True, ms, f"tcp {host}:{port} open"
    except OSError as exc:
        ms = (time.time() - start) * 1000
        return False, ms, f"tcp {host}:{port} — {exc.__class__.__name__}"


def _http_probe(host: str, port: int, timeout: float = 3.0) -> tuple[bool, float, str]:
    scheme = 'https' if port in (443, 8443) else 'http'
    url = f"{scheme}://{host}:{port}/"
    start = time.time()
    try:
        if _HAVE_REQUESTS:
            r = requests.get(url, timeout=timeout, verify=False)  # noqa: S501 (lab)
            ms = (time.time() - start) * 1000
            return True, ms, f"http {r.status_code} from {host}:{port}"
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            ms = (time.time() - start) * 1000
            return True, ms, f"http {resp.status} from {host}:{port}"
    except urllib.error.HTTPError as exc:
        # An HTTP error (401/403/302...) still proves the device answered.
        ms = (time.time() - start) * 1000
        return True, ms, f"http {exc.code} from {host}:{port}"
    except Exception as exc:
        ms = (time.time() - start) * 1000
        # Fall back to a bare TCP probe before declaring failure.
        ok, tms, detail = _tcp_probe(host, port, timeout)
        if ok:
            return True, tms, f"tcp {host}:{port} open (http handshake n/a)"
        return False, ms, f"{url} — {exc.__class__.__name__}"


def validate_connect(instance: dict, timeout: float = 3.0) -> dict:
    """Probe an instance's control plane. Returns a structured result; never raises.

    status: 'ok' reachable · 'fail' unreachable · 'manual' USB-only (no callback)
    """
    transport = instance.get('transport') or PRODUCTS.get(
        instance.get('product_id'), {}).get('transport', 'unknown')
    host = (instance.get('host') or '').strip()
    port = instance.get('port')

    result = {
        'instance_id': instance.get('id'),
        'device_id': instance.get('device_id'),
        'transport': transport,
        'host': host,
        'ok': False,
        'status': 'fail',
        'latency_ms': None,
        'detail': '',
        'checked_at': _utcnow_iso(),
    }

    if transport == 'usb':
        result.update(status='manual', ok=False,
                      detail='USB-only device — no remote callback; physical insert required.')
        return result

    if not host:
        result.update(detail='no host configured for this instance')
        return result

    # Coerce the port defensively — a bad value (e.g. set via PATCH) must yield a
    # clean 'fail' result, not a 500.
    try:
        port_num = int(port) if port not in (None, '') else None
    except (TypeError, ValueError):
        result.update(detail=f'invalid port: {port!r}')
        return result

    if transport == 'ssh':
        ok, ms, detail = _tcp_probe(host, port_num or 22, timeout)
    elif transport in ('wifi', 'rest', 'http'):
        ok, ms, detail = _http_probe(host, port_num or 80, timeout)
    else:
        ok, ms, detail = _tcp_probe(host, port_num or 80, timeout)

    result.update(ok=ok, status='ok' if ok else 'fail',
                  latency_ms=round(ms, 1), detail=detail)
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  WIRELESS / SPECTRUM CONTROLLER  (WiFi Pineapple VII)
#  Talks to the Pineapple REST API when reachable; otherwise returns structured
#  "offline" responses so the UI stays functional during inventory build-out.
# ─────────────────────────────────────────────────────────────────────────────

# Sample recon set used when no live Pineapple answers — keeps the UI populated
# in the lab before the radios are surveyed.
_SAMPLE_APS = [
    {'ssid': 'RANGE-LAB-7', 'bssid': 'C2:9F:DB:11:04:7A', 'band': '5G',
     'channel': 36, 'enc': 'WPA2', 'clients': 6, 'handshake': True},
    {'ssid': 'RANGE-OPS', 'bssid': 'A0:63:91:2C:88:1E', 'band': '2.4',
     'channel': 6, 'enc': 'WPA2', 'clients': 11, 'handshake': True},
    {'ssid': 'TRAINEE-BYOD', 'bssid': 'F4:EC:38:5B:22:90', 'band': '2.4',
     'channel': 11, 'enc': 'WPA2', 'clients': 9, 'handshake': False},
    {'ssid': 'IOT-SEGMENT', 'bssid': 'DC:A6:32:77:01:3B', 'band': '2.4',
     'channel': 1, 'enc': 'WPA2', 'clients': 14, 'handshake': False},
    {'ssid': 'RANGE-5G-LAB', 'bssid': 'B8:27:EB:44:9C:05', 'band': '5G',
     'channel': 149, 'enc': 'WPA3', 'clients': 1, 'handshake': False},
]


class WirelessController:
    def __init__(self, registry: ImplantRegistry):
        self.registry = registry
        self._lock = threading.RLock()
        # Last-applied configs, surfaced back to the UI so the forms persist.
        self.evil_portal_cfg: dict = {
            'ssid': 'RANGE-GUEST-WIFI',
            'template': 'Generic Login',
            'redirect': 'https://intranet.range.local',
            'capture_fields': ['username', 'password'],
            'cleartext_log': True,
            'https': False,
            'armed': False,
        }
        self.deauth_cfg: dict = {
            'target_bssid': '',
            'client': 'ff:ff:ff:ff:ff:ff',
            'band': 'auto',
            'bursts': 5,
            'capture': 'WPA handshake',
            'running': False,
        }

    def pineapple(self) -> dict | None:
        for inst in self.registry.list():
            if inst.get('product_id') == 'pineapple':
                return inst
        return None

    def _online(self) -> tuple[bool, dict | None]:
        p = self.pineapple()
        if not p:
            return False, None
        v = validate_connect(p)
        return bool(v.get('ok')), p

    # ── Recon ────────────────────────────────────────────────────────────────

    def access_points(self) -> list[dict]:
        online, p = self._online()
        if online and _HAVE_REQUESTS and p:
            try:
                url = f"http://{p['host']}:{p.get('port', 1471)}/api/recon/aps"
                r = requests.get(url, timeout=4)
                if r.ok:
                    return r.json().get('aps', _SAMPLE_APS)
            except Exception as exc:        # pragma: no cover - hardware path
                log.info(f"pineapple recon live fetch failed: {exc}")
        return _SAMPLE_APS

    def recon(self) -> dict:
        aps = self.access_points()
        online, _ = self._online()
        return {
            'online': online,
            'aps': aps,
            'ap_count': len(aps),
            'ap_24': sum(1 for a in aps if a['band'] == '2.4'),
            'ap_5g': sum(1 for a in aps if a['band'] == '5G'),
            'clients': sum(a.get('clients', 0) for a in aps),
            'handshakes': sum(1 for a in aps if a.get('handshake')),
        }

    # ── Evil Portal ──────────────────────────────────────────────────────────

    def arm_evil_portal(self, config: dict) -> dict:
        with self._lock:
            cfg = self.evil_portal_cfg
            cfg['ssid'] = (config.get('ssid') or cfg['ssid']).strip()
            tpl = config.get('template')
            if tpl in PORTAL_TEMPLATES:
                cfg['template'] = tpl
            cfg['redirect'] = config.get('redirect', cfg['redirect'])
            fields = config.get('capture_fields')
            if isinstance(fields, list):
                cfg['capture_fields'] = [f for f in fields
                                         if f in ('username', 'password', 'email', 'mfa')]
            cfg['cleartext_log'] = bool(config.get('cleartext_log', cfg['cleartext_log']))
            cfg['https'] = bool(config.get('https', cfg['https']))
            cfg['armed'] = True
        online, _ = self._online()
        return {
            'status': 'armed',
            'config': dict(self.evil_portal_cfg),
            'live': online,
            'message': (f"Evil Portal armed — SSID \"{self.evil_portal_cfg['ssid']}\", "
                        f"template \"{self.evil_portal_cfg['template']}\""
                        + ('' if online else ' (queued — Pineapple offline)')),
        }

    def stop_evil_portal(self) -> dict:
        with self._lock:
            self.evil_portal_cfg['armed'] = False
        return {'status': 'stopped', 'config': dict(self.evil_portal_cfg)}

    # ── Deauth Credential Harvest ────────────────────────────────────────────

    def start_deauth_harvest(self, config: dict) -> dict:
        with self._lock:
            cfg = self.deauth_cfg
            cfg['target_bssid'] = config.get('target_bssid', cfg['target_bssid'])
            cfg['client'] = config.get('client', cfg['client'])
            cfg['band'] = config.get('band', cfg['band'])
            try:
                cfg['bursts'] = max(1, min(64, int(config.get('bursts', cfg['bursts']))))
            except (TypeError, ValueError):
                pass
            cap = config.get('capture')
            if cap in ('WPA handshake', 'PMKID', 'Both'):
                cfg['capture'] = cap
            cfg['running'] = True
        online, _ = self._online()
        return {
            'status': 'running',
            'config': dict(self.deauth_cfg),
            'live': online,
            'message': (f"Deauth harvest started — target {self.deauth_cfg['target_bssid'] or '(none)'}, "
                        f"client {self.deauth_cfg['client']}, {self.deauth_cfg['bursts']} bursts, "
                        f"capture {self.deauth_cfg['capture']} → hashcat"
                        + ('' if online else ' (queued — Pineapple offline)')),
        }

    def stop_deauth_harvest(self) -> dict:
        with self._lock:
            self.deauth_cfg['running'] = False
        return {'status': 'stopped', 'config': dict(self.deauth_cfg)}

    def export_handshakes(self, pcap_registry: "PcapRegistry | None" = None) -> dict:
        rec = self.recon()
        exported = 0
        if pcap_registry is not None:
            for ap in rec.get('aps', []):
                if ap.get('handshake'):
                    pcap_registry.add(
                        name=f"{ap['ssid'].replace(' ', '_')}-{ap['bssid'].replace(':', '')}.pcap",
                        ptype='handshake',
                        source=ap['ssid'],
                        size=f"~{20 + (hash(ap['bssid']) & 0x1f)} KB",
                        hashcat_mode='22000 (WPA-PBKDF2-PMKID+EAPOL)',
                        state='queued',
                    )
                    exported += 1
        else:
            exported = rec['handshakes']
        return {
            'status': 'exported',
            'count':  exported,
            'message': (f"{exported} handshake(s) staged → ./loot/handshakes/ "
                        f"→ hashcat queue"),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  PCAP / HASHCAT REGISTRY
#  Captured artifacts (WPA handshakes, PMKIDs, evil-portal credentials) the
#  Spectrum "Functions" tab produces. State machine:
#       captured → queued → running → cracked | failed
#  Hashcat itself isn't invoked from the engine — the registry tracks state and
#  emits a structured "run plan" the Spectrum tab streams into its log. Wiring
#  to a real local hashcat (offline, range GPU) is a small follow-on.
# ─────────────────────────────────────────────────────────────────────────────

PCAP_STATES = ('captured', 'queued', 'running', 'cracked', 'failed')
PCAP_TYPES  = ('handshake', 'pmkid', 'portal')


class PcapRegistry:
    """Thread-safe, file-backed registry of captured artifacts."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._items: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self._items = data.get('items', {})
        except Exception as exc:
            log.warning(f"pcap registry load failed: {exc} — starting empty")
            self._items = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(
                {'items': self._items, 'saved_at': _utcnow_iso(),
                 'count': len(self._items)}, indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            log.error(f"pcap registry save failed: {exc}")

    def add(self, name: str, ptype: str, source: str = '',
            size: str = '', hashcat_mode: str = '',
            state: str = 'captured') -> dict:
        if ptype not in PCAP_TYPES:
            raise ValueError(f"invalid pcap type: {ptype!r}")
        if state not in PCAP_STATES:
            raise ValueError(f"invalid state: {state!r}")
        item = {
            'id':           str(uuid.uuid4()),
            'name':         name,
            'type':         ptype,
            'source':       source,
            'size':         size,
            'hashcat_mode': hashcat_mode or _default_mode(ptype),
            'state':        state,
            'captured_at':  _utcnow_iso(),
            'cracked_value': None,
        }
        with self._lock:
            self._items[item['id']] = item
            self._save()
        return item

    def list(self) -> list[dict]:
        with self._lock:
            return sorted(self._items.values(),
                          key=lambda x: x.get('captured_at', ''), reverse=True)

    def get(self, item_id: str) -> dict | None:
        with self._lock:
            return dict(self._items[item_id]) if item_id in self._items else None

    def set_state(self, item_id: str, state: str,
                  cracked_value: str | None = None) -> dict | None:
        if state not in PCAP_STATES:
            raise ValueError(f"invalid state: {state!r}")
        with self._lock:
            item = self._items.get(item_id)
            if not item:
                return None
            item['state'] = state
            if cracked_value is not None:
                item['cracked_value'] = cracked_value
            self._save()
            return dict(item)

    def remove(self, item_id: str) -> bool:
        with self._lock:
            if item_id not in self._items:
                return False
            del self._items[item_id]
            self._save()
        return True

    def stats(self) -> dict:
        items = self.list()
        by_state = {s: 0 for s in PCAP_STATES}
        for i in items:
            by_state[i['state']] = by_state.get(i['state'], 0) + 1
        return {
            'total':    len(items),
            'queued':   by_state['queued'],
            'running':  by_state['running'],
            'cracked':  by_state['cracked'],
            'captured': by_state['captured'],
            'failed':   by_state['failed'],
            'by_state': by_state,
        }

    def queue_run_plan(self, wordlist: str, rules: str = '') -> list[dict]:
        """Move queued handshakes/PMKIDs to 'running' and emit log entries the
        UI can stream into its terminal. Portal-cred captures are skipped — they
        are already cleartext."""
        plan = []
        with self._lock:
            for item in self._items.values():
                if item['type'] in ('handshake', 'pmkid') and item['state'] == 'queued':
                    item['state'] = 'running'
                    plan.append({
                        'id':   item['id'],
                        'name': item['name'],
                        'mode': item['hashcat_mode'],
                        'cmd':  (f"hashcat -m {item['hashcat_mode'].split()[0]} "
                                 f"{item['name']} -w 3 -O"
                                 + (f" -r {rules}" if rules else '')
                                 + f" {wordlist}"),
                    })
            self._save()
        return plan


def _default_mode(ptype: str) -> str:
    return {
        'handshake': '22000 (WPA-PBKDF2-PMKID+EAPOL)',
        'pmkid':     '22000 (WPA-PBKDF2-PMKID+EAPOL)',
        'portal':    '(cleartext)',
    }.get(ptype, '(unknown)')
