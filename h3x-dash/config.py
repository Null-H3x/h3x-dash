"""
H3x-Dash configuration.
Override via environment variables or edit directly.
"""
import os
from pathlib import Path


class H3xConfig:

    # ── Flask ─────────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('H3X_SECRET', 'h3x-dash-change-this-in-prod')

    # ── Metasploit RPC ────────────────────────────────────────────────────────
    MSF_HOST = os.environ.get('MSF_HOST', '127.0.0.1')
    MSF_PORT = int(os.environ.get('MSF_PORT', 55553))
    MSF_PASS = os.environ.get('MSF_PASS', 'msfrpc')
    MSF_SSL  = os.environ.get('MSF_SSL', 'false').lower() == 'true'

    # ── Paths ─────────────────────────────────────────────────────────────────
    BASE_DIR   = Path(__file__).parent
    LOOT_DIR   = BASE_DIR / 'loot'
    REPORT_DIR = BASE_DIR / 'reports'
    NMAP_DIR   = BASE_DIR / 'scans'

    # ── Scan defaults ─────────────────────────────────────────────────────────
    DEFAULT_TIMING  = 'T4'
    DEFAULT_PORTS   = 'driveby'
    DEFAULT_SCRIPTS = 'banner'

    @classmethod
    def init_dirs(cls):
        for d in [cls.LOOT_DIR, cls.REPORT_DIR, cls.NMAP_DIR]:
            d.mkdir(parents=True, exist_ok=True)
