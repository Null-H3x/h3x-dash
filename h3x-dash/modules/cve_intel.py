"""
cve_intel.py — Live CVE intelligence aggregator.

Pulls from authoritative sources to keep the chain current:

  CISA KEV    — Known Exploited Vulnerabilities catalog. "What's being
                exploited in the wild RIGHT NOW." Free JSON feed, no auth.
                Daily-ish updates.
  NVD         — NIST National Vulnerability Database. CVSS v3.1 vectors,
                descriptions, references. Free JSON REST API. Rate-limited
                to 5 req/30s without a key.
  Local MSF   — what MsfScanner already indexes from your installation.
                The authoritative answer to "do we have a module for this?"

Cross-references all three so the operator sees the actionable subset:

  KEV CVEs ∩ local MSF modules = "actively exploited AND we can fire it"

That intersection is the prioritization signal the chain has been missing.
A CVSS 9.8 vuln nobody is exploiting matters less than a CVSS 8.1 vuln
that ransomware crews ran against three Fortune 500s last week — KEV
captures that distinction.

Pure stdlib (urllib.request). Graceful offline: returns cached data when
network fails. Atomic-write cache so partial sync doesn't corrupt state.

Public API:
  CveIntel(cache_path)
    .sync_kev()              -> dict      # fetch + return {added, removed, total}
    .lookup_nvd(cve_id)      -> dict      # CVSS + description, cached
    .annotate_cve(cve_id)    -> dict      # combined intel for one CVE
    .cross_reference_msf(msf_scanner) -> dict  # KEV CVEs with local modules
    .recent_kev(days, limit) -> list      # KEV entries added in last N days
    .status()                -> dict      # cache stats for UI
    .chain_candidates(msf_scanner, existing_chain_cves) -> list
        # New CVEs that have MSF modules but aren't in the chain yet.
        # The "what should we add" review queue.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


# ── External sources ──────────────────────────────────────────────────────────

CISA_KEV_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
                'known_exploited_vulnerabilities.json')
NVD_CVE_URL  = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}'

USER_AGENT      = 'H3x-Dash/1.0 (CVE Intelligence Aggregator)'
DEFAULT_TIMEOUT = 20


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CveIntel:
    """Maintains a local JSON cache of CVE intel with on-demand refresh."""

    def __init__(self, cache_path):
        self.cache_path = Path(cache_path)
        self._lock      = threading.RLock()
        self.cache      = self._load_cache()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_cache(self) -> dict:
        """Load cache from disk. Returns empty skeleton if missing/corrupt."""
        skeleton = {
            'kev':             {},
            'nvd':             {},
            'kev_last_sync':   None,
            'kev_version':     None,
            'kev_release':     None,
        }
        if not self.cache_path.exists():
            return skeleton
        try:
            data = json.loads(self.cache_path.read_text())
            # Merge missing keys from skeleton (forward-compat)
            for k, v in skeleton.items():
                data.setdefault(k, v)
            log.info(f"cve_intel cache loaded: "
                     f"{len(data['kev'])} KEV entries, "
                     f"{len(data['nvd'])} NVD cached")
            return data
        except Exception as exc:
            log.warning(f"cve_intel cache load failed ({exc}) — starting empty")
            return skeleton

    def _save_cache(self) -> None:
        """Atomic write — survives mid-write crash."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self.cache, indent=2, default=str))
            tmp.replace(self.cache_path)
        except Exception as exc:
            log.error(f"cve_intel cache save failed: {exc}")

    # ── Sync — CISA KEV ───────────────────────────────────────────────────────

    def sync_kev(self, timeout: int = DEFAULT_TIMEOUT,
                  _http_fn=None) -> dict:
        """
        Fetch + cache the CISA KEV catalog. Returns sync stats.

        Args:
            _http_fn: optional injected fetch function (for tests). Signature:
                      fn(url, timeout) -> bytes
        """
        fetch = _http_fn or self._default_fetch
        try:
            raw = fetch(CISA_KEV_URL, timeout)
            data = json.loads(raw)
        except (urllib.error.URLError, OSError) as exc:
            return {
                'status':       'error',
                'message':      f'CISA KEV fetch failed: {exc}',
                'fallback':     'using cached data',
                'kev_count':    len(self.cache.get('kev', {})),
            }
        except json.JSONDecodeError as exc:
            return {
                'status':    'error',
                'message':   f'CISA KEV JSON malformed: {exc}',
                'kev_count': len(self.cache.get('kev', {})),
            }

        with self._lock:
            existing = set(self.cache.get('kev', {}).keys())
            new_kev: dict[str, dict] = {}
            for v in data.get('vulnerabilities', []):
                cve_id = (v.get('cveID') or '').upper()
                if not cve_id:
                    continue
                new_kev[cve_id] = {
                    'cve':               cve_id,
                    'vendor':            v.get('vendorProject', ''),
                    'product':           v.get('product', ''),
                    'name':              v.get('vulnerabilityName', ''),
                    'date_added':        v.get('dateAdded', ''),
                    'short_description': v.get('shortDescription', ''),
                    'required_action':   v.get('requiredAction', ''),
                    'due_date':          v.get('dueDate', ''),
                    'ransomware_use':    v.get('knownRansomwareCampaignUse',
                                                 'Unknown'),
                    'cwe_ids':           v.get('cwes', []) or [],
                }
            new_cves     = sorted(set(new_kev.keys()) - existing)
            removed_cves = sorted(existing - set(new_kev.keys()))

            self.cache['kev']           = new_kev
            self.cache['kev_last_sync'] = _utcnow_iso()
            self.cache['kev_version']   = data.get('catalogVersion', '')
            self.cache['kev_release']   = data.get('dateReleased', '')
            self._save_cache()

        return {
            'status':          'ok',
            'total_kev':       len(new_kev),
            'new_cves':        new_cves[:100],
            'new_count':       len(new_cves),
            'removed_count':   len(removed_cves),
            'catalog_version': data.get('catalogVersion', ''),
            'date_released':   data.get('dateReleased', ''),
        }

    @staticmethod
    def _default_fetch(url: str, timeout: int) -> bytes:
        """Plain urllib fetch — separated so tests can inject a mock."""
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    # ── NVD lookup (single CVE, cached) ───────────────────────────────────────

    def lookup_nvd(self, cve_id: str, timeout: int = DEFAULT_TIMEOUT,
                    use_cache: bool = True, _http_fn=None) -> dict:
        """
        Fetch one CVE's NVD detail. Cached after first lookup so subsequent
        annotate_cve() calls are free.
        """
        cve_id = cve_id.upper()
        with self._lock:
            if use_cache and cve_id in self.cache.get('nvd', {}):
                return self.cache['nvd'][cve_id]

        fetch = _http_fn or self._default_fetch
        try:
            raw  = fetch(NVD_CVE_URL.format(cve_id), timeout)
            data = json.loads(raw)
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return {'cve': cve_id, 'error': str(exc)}

        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return {'cve': cve_id, 'error': 'not in NVD'}

        v          = vulns[0].get('cve', {})
        metrics    = v.get('metrics', {})
        # NVD CVSS v3.1 first; fall back to v3.0; then v2.
        cvss_list  = (metrics.get('cvssMetricV31') or
                      metrics.get('cvssMetricV30') or [])
        cvss_data  = cvss_list[0].get('cvssData', {}) if cvss_list else {}
        descs      = v.get('descriptions', [])
        desc_en    = next((d.get('value', '') for d in descs
                           if d.get('lang') == 'en'), '')

        result = {
            'cve':           cve_id,
            'description':   desc_en,
            'cvss_v31':      cvss_data.get('baseScore'),
            'cvss_vector':   cvss_data.get('vectorString', ''),
            'severity':      cvss_data.get('baseSeverity', ''),
            'published':     v.get('published', ''),
            'last_modified': v.get('lastModified', ''),
            'cached_at':     _utcnow_iso(),
        }

        with self._lock:
            self.cache.setdefault('nvd', {})[cve_id] = result
            self._save_cache()
        return result

    # ── Cross-reference + annotation ──────────────────────────────────────────

    def cross_reference_msf(self, msf_scanner) -> dict:
        """
        For each cached KEV CVE, find matching MSF modules from the local
        install. The intersection is the actionable subset.

        msf_scanner: MsfScanner instance with .by_cve(cve) method.
        """
        if not msf_scanner:
            return {'with_msf': [], 'without_msf': [],
                    'msf_unavailable': True}

        with self._lock:
            kev_entries = list(self.cache.get('kev', {}).values())

        with_msf:    list[dict] = []
        without_msf: list[dict] = []

        for kev in kev_entries:
            cve_id  = kev['cve']
            modules = []
            try:
                if hasattr(msf_scanner, 'by_cve'):
                    modules = msf_scanner.by_cve(cve_id) or []
                elif hasattr(msf_scanner, 'modules_for_cve'):
                    modules = msf_scanner.modules_for_cve(cve_id) or []
            except Exception:
                modules = []
            if modules:
                # Normalize: just keep fullname + rank for the response
                mod_summary = [{
                    'fullname': m.get('fullname', ''),
                    'rank':     m.get('rank', ''),
                    'type':     m.get('type', ''),
                } for m in modules if isinstance(m, dict)]
                with_msf.append({**kev, 'msf_modules': mod_summary})
            else:
                without_msf.append(kev)

        return {
            'with_msf':       with_msf,
            'without_msf':    without_msf,
            'total':          len(kev_entries),
            'kev_with_msf':   len(with_msf),
            'kev_no_module':  len(without_msf),
        }

    def annotate_cve(self, cve_id: str) -> dict:
        """Return all cached intel for a CVE (KEV + NVD)."""
        cve_id = cve_id.upper()
        with self._lock:
            kev = self.cache.get('kev', {}).get(cve_id)
            nvd = self.cache.get('nvd', {}).get(cve_id)
        return {
            'cve':           cve_id,
            'kev_listed':    kev is not None,
            'kev_data':      kev,
            'nvd_data':      nvd,
        }

    def chain_candidates(self, msf_scanner,
                          existing_chain_cves: set[str]) -> list[dict]:
        """
        The 'what should we add' review queue.

        Returns CVEs where ALL of the following are true:
          1. CISA KEV-listed (actively exploited)
          2. Local MSF has an exploit/auxiliary module for it
          3. CVE is NOT already in the curated chain

        Sorted by KEV date_added (newest first). This is the prioritized
        list of additions the chain should consider for next curation pass.
        """
        if not msf_scanner:
            return []

        xref = self.cross_reference_msf(msf_scanner)
        existing_upper = {c.upper() for c in (existing_chain_cves or set())}

        candidates = []
        for entry in xref['with_msf']:
            if entry['cve'].upper() in existing_upper:
                continue
            candidates.append(entry)

        # Sort newest KEV-added first
        def _sort_key(c):
            return c.get('date_added', '') or ''
        candidates.sort(key=_sort_key, reverse=True)
        return candidates

    # ── Queries ───────────────────────────────────────────────────────────────

    def recent_kev(self, days: int = 30, limit: int = 50) -> list[dict]:
        """KEV entries with date_added within the last N days."""
        today = datetime.now(timezone.utc).date()
        with self._lock:
            kev_list = list(self.cache.get('kev', {}).values())
        out = []
        for entry in kev_list:
            try:
                added    = datetime.fromisoformat(entry['date_added']).date()
                age_days = (today - added).days
                if 0 <= age_days <= days:
                    out.append({**entry, 'age_days': age_days})
            except (ValueError, KeyError, TypeError):
                continue
        out.sort(key=lambda e: e.get('age_days', 999))
        return out[:limit]

    def status(self) -> dict:
        """Snapshot for the dashboard UI."""
        with self._lock:
            return {
                'kev_count':       len(self.cache.get('kev', {})),
                'nvd_cached':      len(self.cache.get('nvd', {})),
                'kev_last_sync':   self.cache.get('kev_last_sync'),
                'kev_version':     self.cache.get('kev_version'),
                'kev_release':     self.cache.get('kev_release'),
                'cache_path':      str(self.cache_path),
                'cache_size_kb':   (self.cache_path.stat().st_size // 1024
                                    if self.cache_path.exists() else 0),
            }
