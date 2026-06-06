#!/usr/bin/env python3
"""
audit_cve_intel.py — Verify CVE intelligence aggregator behavior.

Runs offline — all HTTP fetches are mocked via the _http_fn injection
parameter. Exercises:
  - Cache load/save round-trip
  - KEV sync parses + stores + computes added/removed deltas
  - NVD lookup parses CVSS + caches
  - Cross-reference with mock MsfScanner finds intersections
  - Chain candidate review queue surfaces only new (not-in-chain) hits
  - Graceful failure on bad JSON / network errors
  - annotate_cve combines KEV + NVD correctly
"""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, '.')

from modules.cve_intel import CveIntel

FAIL, OK = [], []
fail = lambda m: FAIL.append(m)
ok   = lambda m: OK.append(m)


# ── Mock fixtures ─────────────────────────────────────────────────────────────

KEV_RESPONSE_1 = json.dumps({
    'catalogVersion': '2026.01.10',
    'dateReleased':   '2026-01-10T12:00:00.000Z',
    'vulnerabilities': [
        {
            'cveID':                          'CVE-2024-21887',
            'vendorProject':                  'Ivanti',
            'product':                        'Connect Secure',
            'vulnerabilityName':              'Ivanti Connect Secure Command Injection',
            'dateAdded':                      '2024-01-10',
            'shortDescription':               'Command injection in Ivanti Connect Secure',
            'requiredAction':                 'Apply mitigations.',
            'dueDate':                        '2024-01-22',
            'knownRansomwareCampaignUse':     'Known',
            'cwes':                           ['CWE-77'],
        },
        {
            'cveID':                          'CVE-2021-44228',
            'vendorProject':                  'Apache',
            'product':                        'Log4j2',
            'vulnerabilityName':              'Apache Log4j2 RCE',
            'dateAdded':                      '2021-12-10',
            'shortDescription':               'Log4Shell — JNDI lookup RCE',
            'requiredAction':                 'Patch immediately.',
            'dueDate':                        '2021-12-24',
            'knownRansomwareCampaignUse':     'Known',
            'cwes':                           ['CWE-20', 'CWE-400', 'CWE-502'],
        },
        {
            'cveID':                          'CVE-2024-1709',
            'vendorProject':                  'ConnectWise',
            'product':                        'ScreenConnect',
            'vulnerabilityName':              'ScreenConnect Auth Bypass',
            'dateAdded':                      '2024-02-22',
            'shortDescription':               'Authentication bypass',
            'requiredAction':                 'Update to fixed version.',
            'dueDate':                        '2024-02-29',
            'knownRansomwareCampaignUse':     'Known',
            'cwes':                           ['CWE-288'],
        },
    ],
}).encode('utf-8')

# Updated KEV with one entry removed + one added — simulates a real sync
KEV_RESPONSE_2 = json.dumps({
    'catalogVersion': '2026.01.20',
    'dateReleased':   '2026-01-20T12:00:00.000Z',
    'vulnerabilities': [
        {
            'cveID':                          'CVE-2024-21887',
            'vendorProject':                  'Ivanti',
            'product':                        'Connect Secure',
            'vulnerabilityName':              'Ivanti Connect Secure Command Injection',
            'dateAdded':                      '2024-01-10',
            'shortDescription':               'Command injection',
            'knownRansomwareCampaignUse':     'Known',
        },
        # CVE-2024-1709 removed
        # CVE-2021-44228 removed
        {
            'cveID':                          'CVE-2024-3400',     # NEW
            'vendorProject':                  'Palo Alto',
            'product':                        'PAN-OS',
            'vulnerabilityName':              'PAN-OS GlobalProtect Command Injection',
            'dateAdded':                      '2024-04-12',
            'shortDescription':               'Command injection in PAN-OS GlobalProtect',
            'knownRansomwareCampaignUse':     'Unknown',
        },
    ],
}).encode('utf-8')

NVD_RESPONSE = json.dumps({
    'vulnerabilities': [{
        'cve': {
            'id':           'CVE-2021-44228',
            'published':    '2021-12-10T10:15:09.143',
            'lastModified': '2024-04-03T17:15:35.220',
            'descriptions': [
                {'lang': 'en', 'value': 'Apache Log4j2 JNDI features...'},
            ],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore':     10.0,
                        'baseSeverity':  'CRITICAL',
                        'vectorString':  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                    },
                }],
            },
        },
    }],
}).encode('utf-8')


def make_fetch(*responses):
    """Return a fetcher function that yields the given responses in order."""
    state = {'i': 0}
    responses = list(responses)
    def fetch(url, timeout):
        if state['i'] >= len(responses):
            raise OSError('mock exhausted')
        resp = responses[state['i']]
        state['i'] += 1
        if isinstance(resp, Exception):
            raise resp
        return resp
    return fetch


# ── Mock MsfScanner ───────────────────────────────────────────────────────────

class MockMsfScanner:
    def __init__(self, cve_map):
        # cve_map: dict[cve_id, list of module dicts]
        self._map = {c.upper(): mods for c, mods in cve_map.items()}
    def by_cve(self, cve):
        return self._map.get(cve.upper(), [])


# ── Tests ─────────────────────────────────────────────────────────────────────

with tempfile.TemporaryDirectory() as tmp:
    cache_path = Path(tmp) / 'cve_intel.json'

    # 1. Construction works on empty path
    intel = CveIntel(cache_path)
    status = intel.status()
    if status['kev_count'] == 0 and status['kev_last_sync'] is None:
        ok("Empty cache initializes with zeros")
    else:
        fail(f"Empty cache state unexpected: {status}")

    # 2. KEV sync — first time
    result = intel.sync_kev(_http_fn=make_fetch(KEV_RESPONSE_1))
    if (result['status'] == 'ok' and result['total_kev'] == 3
        and result['new_count'] == 3
        and result['catalog_version'] == '2026.01.10'):
        ok("First KEV sync parses + stores all 3 entries")
    else:
        fail(f"First KEV sync wrong: {result}")

    # 3. Persistence — reload from disk
    intel2 = CveIntel(cache_path)
    if intel2.status()['kev_count'] == 3:
        ok("KEV cache persists to disk and reloads")
    else:
        fail(f"KEV reload failed: {intel2.status()}")

    # 4. KEV sync — delta detection (1 added, 2 removed)
    result = intel.sync_kev(_http_fn=make_fetch(KEV_RESPONSE_2))
    if (result['new_count'] == 1 and 'CVE-2024-3400' in result['new_cves']
        and result['removed_count'] == 2 and result['total_kev'] == 2):
        ok("Delta sync correctly identifies 1 added + 2 removed")
    else:
        fail(f"Delta sync wrong: {result}")

    # 5. Graceful failure on network error
    result = intel.sync_kev(_http_fn=make_fetch(OSError('Connection refused')))
    if (result['status'] == 'error' and 'Connection refused' in result['message']
        and result['kev_count'] == 2):
        ok("Network error returns error status + falls back to cached data")
    else:
        fail(f"Network error handling wrong: {result}")

    # 6. Malformed JSON handled
    result = intel.sync_kev(_http_fn=make_fetch(b'not json'))
    if result['status'] == 'error' and 'malformed' in result['message']:
        ok("Malformed JSON handled cleanly")
    else:
        fail(f"Bad JSON: {result}")

    # Reset to known good state for remaining tests
    intel.sync_kev(_http_fn=make_fetch(KEV_RESPONSE_1))

    # 7. NVD lookup parses + caches
    nvd = intel.lookup_nvd('CVE-2021-44228',
                            _http_fn=make_fetch(NVD_RESPONSE))
    if (nvd['cvss_v31'] == 10.0 and nvd['severity'] == 'CRITICAL'
        and 'log4j' in (nvd.get('description', '') or '').lower()):
        ok("NVD lookup parses CVSS v3.1 + severity + description")
    else:
        fail(f"NVD parse wrong: {nvd}")

    # 8. NVD cache hit — second call shouldn't fetch
    fetch = make_fetch(OSError('should not be called'))
    nvd2 = intel.lookup_nvd('CVE-2021-44228', _http_fn=fetch)
    if nvd2['cvss_v31'] == 10.0:
        ok("NVD cache hit returns cached without fetching")
    else:
        fail(f"NVD cache miss: {nvd2}")

    # 9. annotate_cve combines KEV + NVD
    ann = intel.annotate_cve('CVE-2021-44228')
    if (ann['kev_listed'] is True
        and ann['kev_data']['vendor'] == 'Apache'
        and ann['nvd_data']['cvss_v31'] == 10.0):
        ok("annotate_cve combines KEV + NVD correctly")
    else:
        fail(f"annotate wrong: {ann}")

    # 10. annotate_cve handles unknown CVE gracefully
    ann = intel.annotate_cve('CVE-9999-99999')
    if ann['kev_listed'] is False and ann['kev_data'] is None and ann['nvd_data'] is None:
        ok("annotate_cve handles unknown CVE gracefully")
    else:
        fail(f"Unknown CVE annotate: {ann}")

    # 11. Cross-reference with MSF scanner
    msf = MockMsfScanner({
        'CVE-2021-44228': [
            {'fullname': 'exploit/multi/http/log4shell_header_injection',
             'rank': 'excellent', 'type': 'exploit'},
            {'fullname': 'auxiliary/scanner/http/log4shell_scanner',
             'rank': 'normal', 'type': 'auxiliary'},
        ],
        'CVE-2024-1709': [],
    })
    xref = intel.cross_reference_msf(msf)
    if (xref['kev_with_msf'] == 1
        and xref['kev_no_module'] == 2
        and xref['with_msf'][0]['cve'] == 'CVE-2021-44228'
        and len(xref['with_msf'][0]['msf_modules']) == 2):
        ok("Cross-reference: KEV ∩ local MSF identifies actionable subset")
    else:
        fail(f"Cross-reference wrong: kev_with_msf={xref.get('kev_with_msf')}, "
             f"no_module={xref.get('kev_no_module')}")

    # 12. Cross-reference handles no scanner gracefully
    xref_none = intel.cross_reference_msf(None)
    if xref_none.get('msf_unavailable') is True:
        ok("Cross-reference handles no MSF scanner gracefully")
    else:
        fail(f"Null scanner handling: {xref_none}")

    # 13. Chain candidates — KEV CVEs with MSF NOT in existing chain
    existing_chain = {'CVE-2021-44228'}    # already curated
    candidates = intel.chain_candidates(msf, existing_chain)
    candidate_cves = {c['cve'] for c in candidates}
    if 'CVE-2021-44228' not in candidate_cves:
        ok("chain_candidates excludes CVEs already in the curated chain")
    else:
        fail(f"chain_candidates leaked already-curated CVE")

    # 14. Chain candidates sorted by recency (newest KEV first)
    candidates = intel.chain_candidates(msf, set())
    # All 3 KEV entries should be candidates; CVE-2024-1709 (2024-02-22) is
    # newest, then CVE-2024-21887 (2024-01-10), then CVE-2021-44228 (2021-12-10)
    # But CVE-2024-1709 has no MSF modules in our mock so it's filtered.
    # That leaves: CVE-2024-21887 and CVE-2021-44228 ordered by date.
    # CVE-2024-21887 has no modules either — only CVE-2021-44228 stays.
    # Let me add MSF coverage for the others and retest:
    msf_full = MockMsfScanner({
        'CVE-2021-44228':   [{'fullname': 'exploit/multi/http/log4shell_header_injection', 'rank':'excellent','type':'exploit'}],
        'CVE-2024-1709':    [{'fullname': 'exploit/multi/http/screenconnect_authbypass',  'rank':'great','type':'exploit'}],
        'CVE-2024-21887':   [{'fullname': 'exploit/linux/http/ivanti_connect_rce',         'rank':'good','type':'exploit'}],
    })
    candidates = intel.chain_candidates(msf_full, set())
    if (len(candidates) == 3
        and candidates[0]['cve']  == 'CVE-2024-1709'      # 2024-02-22 newest
        and candidates[-1]['cve'] == 'CVE-2021-44228'):   # 2021-12-10 oldest
        ok("chain_candidates sorted by KEV date_added (newest first)")
    else:
        fail(f"Candidate order wrong: {[c['cve'] for c in candidates]}")

    # 15. status() returns expected shape
    s = intel.status()
    expected_keys = {'kev_count', 'nvd_cached', 'kev_last_sync',
                      'kev_version', 'cache_path', 'cache_size_kb'}
    if expected_keys.issubset(set(s.keys())) and s['cache_size_kb'] > 0:
        ok(f"status() returns expected shape; cache is {s['cache_size_kb']}KB")
    else:
        fail(f"status() unexpected: missing {expected_keys - set(s.keys())}")

    # 16. recent_kev filters by age
    recent = intel.recent_kev(days=10000)   # all should match
    if len(recent) == 3:
        ok(f"recent_kev returns all entries when days window large enough")
    else:
        fail(f"recent_kev returned {len(recent)}, expected 3")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 72)
print(f" CVE INTEL AUDIT — {len(FAIL)} FAIL · {len(OK)} OK")
print("═" * 72)
if FAIL:
    print("\nFAIL:"); [print(f"  ✗ {m}") for m in FAIL]
print("\nPASSED:")
for m in OK: print(f"  ✓ {m}")
sys.exit(1 if FAIL else 0)
