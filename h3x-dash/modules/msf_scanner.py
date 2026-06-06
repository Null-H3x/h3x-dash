"""
H3x-Dash MsfScanner
Walks the local Metasploit Framework module tree, parses Ruby metadata from
each .rb file without executing Ruby, and builds a CVE-indexed JSON cache.
Works fully offline — no msfrpcd required.

Module tree: /usr/share/metasploit-framework/modules/
Cache file:  ./msf_modules_cache.json   (auto-refreshes if > 24h old)
"""

import gzip
import json
import re
import threading
import time
from datetime import datetime
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

MSF_PATHS = [
    Path('/usr/share/metasploit-framework/modules'),
    Path('/opt/metasploit-framework/modules'),          # some installs
    Path.home() / '.msf4' / 'modules',                 # custom user modules
]

CACHE_FILE = Path(__file__).parent.parent / 'msf_modules_cache.json.gz'

CACHE_MAX_AGE = 86400   # seconds — rebuild if older than 24 h
INTERESTING_TYPES = {'exploits', 'auxiliary', 'post'}   # skip payloads/encoders

RANK_ORDER = {
    'manual': 0, 'low': 1, 'average': 2, 'normal': 3,
    'good': 4, 'great': 5, 'excellent': 6,
}


# ── Ruby parser ───────────────────────────────────────────────────────────────

def _parse_module_file(rb_path: Path, base: Path) -> dict | None:
    """
    Extract metadata from a Metasploit Ruby module without running Ruby.
    Returns a dict or None if parsing fails / file is not a module.
    """
    try:
        # Skip files over 512KB — legitimate MSF modules are never this large
        if rb_path.stat().st_size > 524288:
            return None
        text = rb_path.read_text(encoding='utf-8', errors='replace')

        # Must look like a module class definition
        if 'Msf::Module' not in text and 'Msf::Exploit' not in text \
                and 'Msf::Auxiliary' not in text and 'Msf::Post' not in text:
            return None

        # ── Name ──────────────────────────────────────────────────────────────
        name_m = re.search(r"['\"]Name['\"\s]*=>['\s]*['\"]([^'\"]{3,})['\"]", text)
        name = name_m.group(1).strip() if name_m else rb_path.stem

        # ── Description ───────────────────────────────────────────────────────
        # Handles: 'Description' => 'short', 'Description' => %q{ multi }, etc.
        desc = ''
        desc_m = re.search(
            r"['\"]Description['\"\s]*=>['\s]*(?:%q[{(](.+?)[})]\s*,|['\"]([^'\"]+)['\"])",
            text, re.DOTALL
        )
        if desc_m:
            raw = (desc_m.group(1) or desc_m.group(2) or '').strip()
            desc = ' '.join(raw.split())[:300]

        # ── CVE references ────────────────────────────────────────────────────
        cves = [f"CVE-{c}" for c in re.findall(r"\['CVE',\s*'([\d-]+)'\]", text)]
        # Also catch inline CVE mentions in description
        extra = re.findall(r'\bCVE-(\d{4}-\d+)\b', text)
        for c in extra:
            tag = f'CVE-{c}'
            if tag not in cves:
                cves.append(tag)
        cves = list(dict.fromkeys(cves))   # deduplicate, preserve order

        # ── Other references ──────────────────────────────────────────────────
        msbs  = re.findall(r"\['MSB',\s*'([^']+)'\]", text)
        edb   = re.findall(r"\['EDB',\s*'([^']+)'\]", text)
        urls  = re.findall(r"\['URL',\s*'([^']+)'\]", text)

        # ── Rank ──────────────────────────────────────────────────────────────
        rank = 'normal'
        rank_m = re.search(r'Rank\s*=\s*(\w+)Ranking', text)
        if rank_m:
            rank = rank_m.group(1).lower()
        else:
            rank_m2 = re.search(r"['\"]Rank['\"\s]*=>['\s]*(\w+)Ranking", text)
            if rank_m2:
                rank = rank_m2.group(1).lower()

        # ── Platform ──────────────────────────────────────────────────────────
        plat_m = re.search(
            r"['\"]Platform['\"\s]*=>['\s]*(?:\[([^\]]+)\]|['\"]([^'\"]+)['\"])",
            text
        )
        platform = ''
        if plat_m:
            platform = (plat_m.group(1) or plat_m.group(2) or '').strip()
            platform = re.sub(r"['\"\s]", '', platform)

        # ── Arch ──────────────────────────────────────────────────────────────
        arch_m = re.search(r"['\"]Arch['\"\s]*=>['\s]*(?:ARCH_(\w+)|\[([^\]]+)\])", text)
        arch = ''
        if arch_m:
            arch = (arch_m.group(1) or arch_m.group(2) or '').strip()
            arch = re.sub(r"['\"\s]", '', arch)

        # ── Full module name from path ─────────────────────────────────────────
        # /usr/share/metasploit-framework/modules/exploits/windows/smb/ms17_010_eternalblue.rb
        # → exploits/windows/smb/ms17_010_eternalblue
        rel   = rb_path.relative_to(base).with_suffix('')
        parts = rel.parts
        mtype = parts[0] if parts else 'unknown'

        # Normalise type label (exploits → exploit for MSF convention)
        mtype_label = mtype.rstrip('s') if mtype.endswith('s') else mtype

        # Full name as used in MSF: type/path
        fullname = f"{mtype_label}/{'/'.join(parts[1:])}"

        return {
            'fullname':    fullname,
            'name':        name,
            'type':        mtype_label,
            'description': desc,
            'cves':        cves,
            'msbs':        msbs,
            'edb':         edb,
            'urls':        urls[:3],     # cap URL list
            'rank':        rank,
            'platform':    platform,
            'arch':        arch,
            'path':        str(rb_path),
        }

    except Exception:
        return None


# ── MsfScanner ────────────────────────────────────────────────────────────────

class MsfScanner:

    def __init__(self):
        self._modules:    list[dict]       = []
        self._cve_index:  dict[str, list]  = {}   # CVE → [module, ...]
        self._name_index: dict[str, dict]  = {}   # fullname → module
        self._lock        = threading.Lock()
        self._ready       = False
        self._scan_time:  float | None     = None
        self._module_base: Path | None     = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        """Load from cache or start background scan."""
        if self._load_cache():
            return
        threading.Thread(target=self._scan, daemon=True, name='h3x-msf-scanner').start()

    def is_ready(self) -> bool:
        return self._ready

    def total(self) -> int:
        return len(self._modules)

    def last_scan(self) -> str | None:
        if self._scan_time:
            return datetime.fromtimestamp(self._scan_time).strftime('%Y-%m-%d %H:%M')
        return None

    def search(self, query: str, mtype: str = '', limit: int = 100) -> list[dict]:
        """Full-text search across name, description, CVEs, fullname."""
        if not self._ready:
            return []
        q = query.lower().strip()
        results = []
        with self._lock:
            for m in self._modules:
                if mtype and m.get('type') != mtype:
                    continue
                score = 0
                fn  = m.get('fullname', '').lower()
                nm  = m.get('name', '').lower()
                dsc = m.get('description', '').lower()
                cvs = ' '.join(m.get('cves', [])).lower()
                if q in fn:                score += 30
                if q in nm:                score += 20
                if q in cvs:               score += 15
                if q in dsc:               score += 5
                if any(q in c.lower() for c in m.get('msbs', [])): score += 10
                if score > 0:
                    results.append((score, m))
        results.sort(key=lambda x: (-x[0], -RANK_ORDER.get(x[1].get('rank','normal'), 3)))
        return [m for _, m in results[:limit]]

    def by_cve(self, cve: str) -> list[dict]:
        """Return all modules that reference a given CVE."""
        cve = cve.upper().strip()
        with self._lock:
            return list(self._cve_index.get(cve, []))

    def by_fullname(self, fullname: str) -> dict | None:
        with self._lock:
            return self._name_index.get(fullname)

    def match_findings(self, findings: list[dict]) -> dict[str, list[dict]]:
        """
        For a list of enum findings, return a dict mapping each finding's
        CVE to locally installed MSF modules.
        { 'CVE-2017-0144': [{module}, ...], ... }
        """
        out = {}
        seen_cves = set()
        for f in findings:
            cve = (f.get('cve') or '').strip().upper()
            if cve and cve not in seen_cves:
                seen_cves.add(cve)
                matches = self.by_cve(cve)
                if matches:
                    out[cve] = matches
        return out

    def stats(self) -> dict:
        with self._lock:
            types = {}
            for m in self._modules:
                t = m.get('type', 'unknown')
                types[t] = types.get(t, 0) + 1
        return {
            'total':     len(self._modules),
            'types':     types,
            'cve_count': len(self._cve_index),
            'ready':     self._ready,
            'last_scan': self.last_scan(),
            'base':      str(self._module_base) if self._module_base else None,
        }

    def trigger_rescan(self):
        """Force a fresh filesystem scan in the background."""
        self._ready = False
        threading.Thread(target=self._scan, daemon=True, name='h3x-msf-rescan').start()

    # ── Cache ──────────────────────────────────────────────────────────────────

    def _load_cache(self) -> bool:
        if not CACHE_FILE.exists():
            return False
        try:
            age = time.time() - CACHE_FILE.stat().st_mtime
            if age > CACHE_MAX_AGE:
                print('[H3x-Dash] MSF module cache expired — rescanning')
                return False
            with gzip.open(CACHE_FILE, 'rt', encoding='utf-8') as fh:
                data = json.load(fh)
            modules = data.get('modules', [])
            if not modules:
                return False
            self._build_indexes(modules)
            self._scan_time = data.get('scan_time', time.time())
            self._ready     = True
            print(f'[H3x-Dash] MSF module cache loaded — {len(modules)} modules, '
                  f'{len(self._cve_index)} CVE(s)')
            return True
        except Exception as e:
            print(f'[H3x-Dash] Cache load failed: {e}')
            return False

    def _save_cache(self, modules: list[dict]):
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = {'modules': modules, 'scan_time': time.time()}
            with gzip.open(CACHE_FILE, 'wt', encoding='utf-8') as fh:
                json.dump(payload, fh)
        except Exception as e:
            print(f'[H3x-Dash] Cache save failed: {e}')

    # ── Scanner ────────────────────────────────────────────────────────────────

    def _scan(self):
        base = None
        for candidate in MSF_PATHS:
            if candidate.exists():
                base = candidate
                break

        if base is None:
            print('[H3x-Dash] MSF module directory not found — '
                  'Metasploit Framework may not be installed')
            self._ready = True   # mark ready (empty) so API doesn't hang
            return

        self._module_base = base
        print(f'[H3x-Dash] Scanning MSF modules at {base} ...')
        t0      = time.time()
        modules = []
        rb_files = list(base.rglob('*.rb'))
        total    = len(rb_files)

        for i, rb in enumerate(rb_files):
            # Skip non-interesting module types (payloads, encoders, nops)
            top = rb.relative_to(base).parts[0] if rb.relative_to(base).parts else ''
            if top not in INTERESTING_TYPES and top + 's' not in INTERESTING_TYPES:
                continue

            m = _parse_module_file(rb, base)
            if m:
                modules.append(m)

            if (i + 1) % 500 == 0:
                print(f'[H3x-Dash] MSF scan progress: {i+1}/{total} files, '
                      f'{len(modules)} modules parsed')

        elapsed = time.time() - t0
        print(f'[H3x-Dash] MSF scan complete — {len(modules)} modules in {elapsed:.1f}s')

        self._build_indexes(modules)
        self._scan_time = time.time()
        self._save_cache(modules)
        self._ready = True

        cve_count = len(self._cve_index)
        print(f'[H3x-Dash] CVE index: {cve_count} unique CVE(s) mapped to local modules')

    def _build_indexes(self, modules: list[dict]):
        cve_index  = {}
        name_index = {}
        for m in modules:
            fn = m.get('fullname', '')
            if fn:
                name_index[fn] = m
            for cve in m.get('cves', []):
                cve_index.setdefault(cve, []).append(m)
        with self._lock:
            self._modules    = modules
            self._cve_index  = cve_index
            self._name_index = name_index
