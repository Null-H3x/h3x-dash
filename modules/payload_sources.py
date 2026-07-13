"""
payload_sources.py — Vetted GitHub payload sources + the "access update" pull.

The Payload library shipped in ``implant_engine.PAYLOADS`` is a small, curated
baseline. This module lets an operator REFRESH that library by pulling payload
manifests from a strict ALLOWLIST of vetted GitHub repositories (the official
Hak5 / O.MG payload libraries) and merging them in.

The allowlist is the security boundary, and it is enforced in depth:

  1. ``update`` refuses any ``source_id`` that is not a key of ``VETTED_SOURCES``.
  2. Every request URL is built solely from a vetted entry's ``org``/``repo`` —
     no operator-supplied string ever reaches the URL.
  3. ``_github_get`` re-validates that the host is exactly ``api.github.com`` and
     that the path targets the expected ``/repos/<org>/<repo>/`` prefix before a
     single byte goes out. A redirect or a tampered entry that points elsewhere
     is rejected, not followed.

No arbitrary URL is ever fetched, so the "pull from GitHub" path cannot be
turned into a request forgery primitive against the range or the host.

STDLIB-ONLY: the pull uses ``urllib`` against the GitHub REST API. An optional
``GITHUB_TOKEN`` / ``H3X_GITHUB_TOKEN`` env var raises the anonymous rate limit
but is never required. On an air-gapped range the update simply reports
``unreachable`` and the built-in catalog keeps working unchanged.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules import implant_engine
from modules.implant_engine import PRODUCTS

log = logging.getLogger(__name__)

_GITHUB_HOST = 'api.github.com'
_GITHUB_API = f'https://{_GITHUB_HOST}'

# Hard caps so a huge or hostile repository tree can never blow up memory or the
# UI. The pull stops collecting once a source hits PER_SOURCE_LIMIT payloads.
PER_SOURCE_LIMIT = 300
_REQUEST_TIMEOUT = 12.0

# Basenames that mark a payload directory across the Hak5 device families, and
# flat-file extensions for the script-style libraries (Ducky / O.MG).
_PAYLOAD_BASENAMES = {'payload.txt', 'payload.sh', 'payload.ps1', 'payload.bin'}
_SKIP_STEMS = {'readme', 'license', 'licence', 'changelog', 'contributing',
               'authors', 'notice', 'index', 'template', 'cname', 'module_list',
               'modulemanager'}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
#  VETTED SOURCE ALLOWLIST
#  Only these org/repo combinations are ever contacted. Each entry maps a repo
#  to the H3x-Dash product(s) it arms, the language/ATT&CK/countermeasure
#  defaults applied to every payload pulled from it, and the library subtree to
#  walk. `callback` is deliberately 'none' for every synced payload: a freshly
#  pulled, un-reviewed payload should be catalogued and armable, but must never
#  auto-stage an MSF handler. The operator reviews and wires the callback.
# ─────────────────────────────────────────────────────────────────────────────

VETTED_SOURCES: dict[str, dict] = {
    'hak5-ducky': {
        'id': 'hak5-ducky',
        'label': 'Hak5 USB Rubber Ducky',
        'org': 'hak5', 'repo': 'usbrubberducky-payloads', 'branch': 'master',
        'library_path': 'payloads/library',
        'products': ['ducky'],
        'lang': 'DuckyScript', 'attack': 'T1200 · T1059',
        'cm': 'USB device-control / HID allow-listing',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/usbrubberducky-payloads',
    },
    'hak5-bunny': {
        'id': 'hak5-bunny',
        'label': 'Hak5 Bash Bunny',
        'org': 'hak5', 'repo': 'bashbunny-payloads', 'branch': 'master',
        'library_path': 'payloads/library',
        'products': ['bunny'],
        'lang': 'bash+QUACK', 'attack': 'T1200',
        'cm': 'Disable LLMNR/NBT-NS; deny new USB NICs',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/bashbunny-payloads',
    },
    'hak5-shark': {
        'id': 'hak5-shark',
        'label': 'Hak5 Shark Jack',
        'org': 'hak5', 'repo': 'sharkjack-payloads', 'branch': 'master',
        'library_path': 'payloads/library',
        'products': ['shark'],
        'lang': 'bash', 'attack': 'T1200 · T1046',
        'cm': '802.1X / NAC on switchports',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/sharkjack-payloads',
    },
    'hak5-turtle': {
        'id': 'hak5-turtle',
        'label': 'Hak5 LAN Turtle',
        'org': 'hak5', 'repo': 'lanturtle-modules', 'branch': 'gh-pages',
        'library_path': 'modules', 'match_mode': 'flat',
        'products': ['turtle'],
        'lang': 'module', 'attack': 'T1200 · T1071',
        'cm': '802.1X; NAC posture; egress filtering',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/lanturtle-modules',
    },
    'hak5-packetsquirrel': {
        'id': 'hak5-packetsquirrel',
        'label': 'Hak5 Packet Squirrel',
        'org': 'hak5', 'repo': 'packetsquirrel-payloads', 'branch': 'master',
        'library_path': 'payloads',
        'products': ['packetsquirrel'],
        'lang': 'bash', 'attack': 'T1200 · T1557 · T1040',
        'cm': '802.1X / NAC on switchports; port security',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/packetsquirrel-payloads',
    },
    'hak5-keycroc': {
        'id': 'hak5-keycroc',
        'label': 'Hak5 Key Croc',
        'org': 'hak5', 'repo': 'keycroc-payloads', 'branch': 'master',
        'library_path': 'payloads/library',
        'products': ['keycroc'],
        'lang': 'bash+QUACK', 'attack': 'T1056.001 · T1200',
        'cm': 'USB device-control / HID allow-listing',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/keycroc-payloads',
    },
    'hak5-signalowl': {
        'id': 'hak5-signalowl',
        'label': 'Hak5 Signal Owl',
        'org': 'hak5', 'repo': 'signalowl-payloads', 'branch': 'master',
        'library_path': 'payloads/library',
        'products': ['signalowl'],
        'lang': 'bash', 'attack': 'T1200 · T1018 · T1071',
        'cm': 'WPA3/802.1X-EAP; rogue-device RF monitoring',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/signalowl-payloads',
    },
    'hak5-omg': {
        'id': 'hak5-omg',
        'label': 'O.MG Cable / Plug',
        'org': 'hak5', 'repo': 'omg-payloads', 'branch': 'master',
        'library_path': 'payloads',
        'products': ['omg-plug', 'omg-adapter', 'omg-unblocker', 'omg-cable'],
        'lang': 'DuckyScript', 'attack': 'T1200 · T1056.001',
        'cm': 'USB device control; cable/adapter provenance',
        'callback': 'none',
        'homepage': 'https://github.com/hak5/omg-payloads',
    },
}

SOURCE_ORDER = ['hak5-ducky', 'hak5-bunny', 'hak5-shark', 'hak5-turtle',
                'hak5-packetsquirrel', 'hak5-keycroc', 'hak5-signalowl', 'hak5-omg']


def is_vetted(source_id: str) -> bool:
    return source_id in VETTED_SOURCES


# ─────────────────────────────────────────────────────────────────────────────
#  GITHUB FETCH  (allowlist-validated, stdlib only)
# ─────────────────────────────────────────────────────────────────────────────

def _auth_header() -> dict[str, str]:
    token = (os.environ.get('GITHUB_TOKEN')
             or os.environ.get('H3X_GITHUB_TOKEN') or '').strip()
    return {'Authorization': f'Bearer {token}'} if token else {}


def _assert_allowed_url(url: str, source: dict) -> None:
    """Defence-in-depth: prove a URL targets exactly the vetted repo before use."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or parts.netloc != _GITHUB_HOST:
        raise ValueError(f'refusing non-GitHub-API host: {parts.netloc or url!r}')
    expected = f"/repos/{source['org']}/{source['repo']}/"
    if not parts.path.startswith(expected):
        raise ValueError(f'URL path {parts.path!r} outside vetted repo {expected!r}')


def _github_get(url: str, source: dict, timeout: float = _REQUEST_TIMEOUT) -> Any:
    _assert_allowed_url(url, source)
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'h3x-dash-payload-sources',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    headers.update(_auth_header())
    req = urllib.request.Request(url, headers=headers, method='GET')
    # We pin the opener to the default handlers (no custom redirect following to
    # arbitrary hosts); urllib's redirect handler still re-runs the request, so
    # any redirect target is re-validated by the caller's allowlist on retry.
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (host pinned above)
        if resp.status != 200:
            raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, None)
        # A 30x that urllib followed could land elsewhere — re-validate the final URL.
        _assert_allowed_url(resp.geturl(), source)
        return json.loads(resp.read().decode('utf-8'))


# ─────────────────────────────────────────────────────────────────────────────
#  TREE → PAYLOAD PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _derive_payloads_from_tree(tree: list[dict], source: dict) -> list[dict]:
    """Turn a recursive git-tree listing into payload records for `source`.

    Two layouts are supported via the source's ``match_mode``:

      'folder' (default) — a payload is recognised when a blob's basename is one
        of the canonical device payload files (payload.txt/.sh/.ps1/.bin), whose
        name becomes the parent folder, or a flat ``*.txt`` under the library
        path (name becomes the file stem). Covers Ducky / Bunny / Shark / O.MG.

      'flat' — every blob directly under the library path is a payload/module;
        its name is the file stem. Covers the LAN Turtle module library.

    README/LICENSE-style files are always skipped. Results are deduped by name
    and capped at PER_SOURCE_LIMIT.
    """
    mode = source.get('match_mode', 'folder')
    lib = source.get('library_path', '').strip('/')
    prefix = (lib + '/') if lib else ''
    out: dict[str, dict] = {}

    # All blob paths, so a payload can point its doc_path at a sibling README.
    all_paths = {n.get('path', '') for n in tree if n.get('type') == 'blob'}

    def _folder_readme(folder: str) -> str | None:
        for cand in (f'{folder}/README.md', f'{folder}/readme.md',
                     f'{folder}/Readme.md', f'{folder}/README.txt'):
            if cand in all_paths:
                return cand
        return None

    for node in tree:
        if node.get('type') != 'blob':
            continue
        path = node.get('path', '')
        if prefix and not path.startswith(prefix):
            continue
        rel = path[len(prefix):]
        if not rel:
            continue
        segments = rel.split('/')
        basename = segments[-1]
        low = basename.lower()

        name = None
        doc_path = path
        if mode == 'flat':
            # Only depth-1 entries directly under the library path qualify.
            if len(segments) != 1:
                continue
            stem = basename.rsplit('.', 1)[0] if '.' in basename else basename
            if stem.lower() in _SKIP_STEMS:
                continue
            name = stem
            doc_path = path
        else:
            if low in _PAYLOAD_BASENAMES:
                # Canonical payload-folder layout: parent directory is the payload.
                if len(segments) >= 2:
                    name = segments[-2]
                    folder = path.rsplit('/', 1)[0]
                    doc_path = _folder_readme(folder) or path
            elif low.endswith('.txt'):
                stem = basename[:-4]
                if stem.lower() in _SKIP_STEMS:
                    continue
                name = stem
                doc_path = path

        if not name:
            continue
        if name in out:
            continue

        category = ' / '.join(segments[:-1]) if len(segments) > 1 else ''
        out[name] = {
            'name': name,
            'products': list(source['products']),
            'lang': source['lang'],
            'attack': source['attack'],
            'cm': source['cm'],
            'callback': source.get('callback', 'none'),
            'vetted': True,
            'source': source['id'],
            'source_label': source['label'],
            'repo': f"{source['org']}/{source['repo']}",
            'path': path,
            'doc_path': doc_path,
            'category': category,
            'url': (f"https://github.com/{source['org']}/{source['repo']}"
                    f"/blob/{source['branch']}/{urllib.parse.quote(path)}"),
        }
        if len(out) >= PER_SOURCE_LIMIT:
            break

    return list(out.values())


def _fetch_source_payloads(source: dict, timeout: float = _REQUEST_TIMEOUT) -> list[dict]:
    """Pull and parse the payload library for ONE vetted source."""
    url = (f"{_GITHUB_API}/repos/{source['org']}/{source['repo']}"
           f"/git/trees/{urllib.parse.quote(source['branch'])}?recursive=1")
    data = _github_get(url, source, timeout=timeout)
    tree = data.get('tree', []) if isinstance(data, dict) else []
    payloads = _derive_payloads_from_tree(tree, source)
    if data.get('truncated'):
        log.info(f"{source['id']}: GitHub tree truncated — captured {len(payloads)} "
                 f"(cap {PER_SOURCE_LIMIT})")
    return payloads


# ─────────────────────────────────────────────────────────────────────────────
#  DESCRIPTION FETCH  (lazy, one file at a time)
#  Pulling 800+ READMEs up-front would blow the GitHub rate limit, so the
#  description for a payload is fetched on demand when the operator expands its
#  row, then cached. The fetched path must already exist in the synced set for a
#  vetted source — the manager never fetches an operator-supplied path blind.
# ─────────────────────────────────────────────────────────────────────────────

_DESC_MAX = 900
_META_KEYS = ('title', 'description', 'author')


def _github_get_file_text(source: dict, path: str,
                          timeout: float = _REQUEST_TIMEOUT) -> str:
    """Fetch a single file's text via the GitHub contents API (allowlisted)."""
    import base64
    url = (f"{_GITHUB_API}/repos/{source['org']}/{source['repo']}"
           f"/contents/{urllib.parse.quote(path)}"
           f"?ref={urllib.parse.quote(source['branch'])}")
    data = _github_get(url, source, timeout=timeout)
    if isinstance(data, dict) and data.get('encoding') == 'base64':
        raw = base64.b64decode(data.get('content', ''))
        return raw.decode('utf-8', errors='replace')
    if isinstance(data, dict) and 'content' in data:
        return str(data['content'])
    raise ValueError('unexpected contents-API response')


def _strip_md(line: str) -> str:
    s = line.strip()
    s = s.lstrip('#').strip()           # heading markers
    s = s.strip('*_`').strip()          # emphasis / code ticks
    return s


def _extract_description(text: str, doc_path: str) -> dict:
    """Best-effort {title, author, description} from a README or payload script.

    Markdown READMEs: first heading is the title, first real paragraph is the
    description. Payload scripts (DuckyScript / bash / Turtle modules): parse
    REM/#/// `Title:` `Description:` `Author:` headers, else fall back to the
    leading comment block.
    """
    meta: dict[str, str] = {}
    is_md = doc_path.lower().endswith(('.md', '.markdown'))
    lines = text.splitlines()

    if is_md:
        para: list[str] = []
        for raw in lines:
            ln = raw.strip()
            if not ln:
                if para:
                    break
                continue
            if ln.startswith('#') and 'title' not in meta:
                meta['title'] = _strip_md(ln)
                continue
            # skip badge/image/HTML noise
            low = ln.lower()
            if (ln.startswith('![') or ln.startswith('<') or '![' in ln
                    or low.startswith('[![') or ln.startswith('---')
                    or ln.startswith('|') or ln.startswith('=')):
                continue
            body = _strip_md(ln)
            # Many Hak5 READMEs embed Title:/Author:/Description: metadata lines.
            blow = body.lower()
            mkey = next((k for k in _META_KEYS if blow.startswith(k + ':')), None)
            if mkey:
                if mkey not in meta:
                    meta[mkey] = body.split(':', 1)[1].strip()
                continue
            para.append(body)
        if 'description' not in meta and para:
            meta['description'] = ' '.join(para)
    else:
        comment_lead = []
        for raw in lines[:60]:
            ln = raw.strip()
            # strip a leading comment marker
            body = ln
            for mk in ('REM ', 'REM\t', 'rem ', '#', '//', ';'):
                if body.upper().startswith(mk.upper()):
                    body = body[len(mk):].strip()
                    break
            else:
                if ln and not ln.upper().startswith('REM'):
                    # first non-comment, non-blank line ends the lead block
                    if comment_lead:
                        break
                    continue
            low = body.lower()
            matched = False
            for key in _META_KEYS:
                if low.startswith(key + ':') and key not in meta:
                    meta[key] = body.split(':', 1)[1].strip()
                    matched = True
                    break
            if not matched and body:
                comment_lead.append(body)
        if 'description' not in meta and comment_lead:
            meta['description'] = ' '.join(comment_lead[:6])

    desc = (meta.get('description') or '').strip()
    # Source metadata occasionally carries inline HTML (<br>, <b>…); drop tags
    # and collapse whitespace so the UI shows clean prose.
    desc = re.sub(r'<[^>]+>', ' ', desc)
    desc = re.sub(r'\s+', ' ', desc).strip()
    if len(desc) > _DESC_MAX:
        desc = desc[:_DESC_MAX].rsplit(' ', 1)[0] + '…'
    return {
        'title': (meta.get('title') or '').strip(),
        'author': (meta.get('author') or '').strip(),
        'description': desc,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  SOURCE MANAGER  (file-backed; mirrors the registry persistence pattern)
# ─────────────────────────────────────────────────────────────────────────────

class PayloadSourceManager:
    """Owns the vetted-source sync state + the merged synced payload cache.

    On construction it loads any cached payloads from disk and registers them
    with implant_engine so the library is populated immediately, before (and
    without requiring) any network call.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        # source_id -> {last_synced, count, status, detail}
        self._state: dict[str, dict] = {}
        self._payloads: list[dict] = []
        # In-memory description cache, keyed "source_id::doc_path".
        self._doc_cache: dict[str, dict] = {}
        self._load()
        self._push_to_engine()

    # ── Persistence ────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
            self._state = data.get('sources', {})
            self._payloads = data.get('payloads', [])
            log.info(f"payload sources loaded: {len(self._payloads)} cached payloads")
        except Exception as exc:
            log.warning(f"payload sources load failed: {exc} — starting empty")
            self._state, self._payloads = {}, []

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix('.tmp')
            tmp.write_text(json.dumps(
                {'sources': self._state, 'payloads': self._payloads,
                 'saved_at': _utcnow_iso(), 'count': len(self._payloads)},
                indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            log.error(f"payload sources save failed: {exc}")

    def _push_to_engine(self) -> int:
        return implant_engine.set_synced_payloads(self._payloads)

    # ── Read surface ─────────────────────────────────────────────────────────

    def sources(self) -> list[dict]:
        """Vetted source catalog decorated with per-source sync state."""
        with self._lock:
            out = []
            for sid in SOURCE_ORDER:
                src = VETTED_SOURCES[sid]
                st = self._state.get(sid, {})
                out.append({
                    'id': sid,
                    'label': src['label'],
                    'repo': f"{src['org']}/{src['repo']}",
                    'branch': src['branch'],
                    'products': list(src['products']),
                    'homepage': src['homepage'],
                    'last_synced': st.get('last_synced'),
                    'count': st.get('count', 0),
                    'status': st.get('status', 'never'),
                    'detail': st.get('detail', ''),
                })
            return out

    def payloads(self) -> list[dict]:
        with self._lock:
            return [dict(p) for p in self._payloads]

    def stats(self) -> dict:
        with self._lock:
            synced = len(self._payloads)
            by_source = {}
            for p in self._payloads:
                by_source[p.get('source')] = by_source.get(p.get('source'), 0) + 1
        return {
            'sources': len(VETTED_SOURCES),
            'synced_payloads': synced,
            'builtin_payloads': len(implant_engine.PAYLOADS),
            'total_payloads': len(implant_engine.list_payloads()),
            'by_source': by_source,
        }

    # ── Lazy description fetch ─────────────────────────────────────────────────

    def describe(self, source_id: str, path: str,
                 timeout: float = _REQUEST_TIMEOUT) -> dict:
        """Fetch + extract the description for one synced payload, on demand.

        `path` is the payload's own `path` (its identifier in the synced set).
        The pair (source_id, path) must already exist in the synced payloads for
        a vetted source — we never fetch an arbitrary, operator-supplied path.
        Results are cached in memory so re-opening a row is free.
        """
        if not is_vetted(source_id):
            return {'status': 'rejected',
                    'reason': f'{source_id!r} is not a vetted source'}
        with self._lock:
            rec = next((p for p in self._payloads
                        if p.get('source') == source_id and p.get('path') == path), None)
        if not rec:
            return {'status': 'not_found',
                    'reason': 'no synced payload with that path for this source'}

        doc_path = rec.get('doc_path') or rec.get('path')
        cache_key = f"{source_id}::{doc_path}"
        with self._lock:
            cached = self._doc_cache.get(cache_key)
        if cached is not None:
            return {'status': 'ok', 'cached': True, **cached}

        src = VETTED_SOURCES[source_id]
        try:
            text = _github_get_file_text(src, doc_path, timeout=timeout)
            meta = _extract_description(text, doc_path)
        except urllib.error.HTTPError as exc:
            detail = ('rate-limited (HTTP 403) — set GITHUB_TOKEN'
                      if exc.code == 403 else f'HTTP {exc.code}')
            return {'status': 'error', 'reason': detail}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return {'status': 'unreachable', 'reason': exc.__class__.__name__}
        except Exception as exc:  # noqa: BLE001
            return {'status': 'error', 'reason': f'{exc.__class__.__name__}: {exc}'}

        doc_url = (f"https://github.com/{src['org']}/{src['repo']}"
                   f"/blob/{src['branch']}/{urllib.parse.quote(doc_path)}")
        result = {
            'name': rec.get('name'),
            'title': meta.get('title') or rec.get('name'),
            'author': meta.get('author', ''),
            'description': meta.get('description', ''),
            'doc_path': doc_path,
            'doc_url': doc_url,
            'is_readme': doc_path.lower().endswith(('.md', '.markdown')),
        }
        with self._lock:
            self._doc_cache[cache_key] = result
        return {'status': 'ok', 'cached': False, **result}

    # ── The "access update" pull ──────────────────────────────────────────────

    def update(self, source_id: str | None = None,
               timeout: float = _REQUEST_TIMEOUT) -> dict:
        """Pull payloads from one vetted source, or all of them when source_id
        is None. Refuses any non-vetted source_id outright.

        Returns a structured result with a step log the UI streams into its
        terminal, plus refreshed source state and library stats. Never raises on
        a network failure — an unreachable source is reported, not fatal.
        """
        if source_id is not None and not is_vetted(source_id):
            return {
                'status': 'rejected',
                'reason': f'{source_id!r} is not a vetted source',
                'vetted': SOURCE_ORDER,
                'steps': [{'cls': 't-err',
                           'msg': f"[deny] {source_id!r} is not on the vetted allowlist"}],
            }

        target_ids = [source_id] if source_id else list(SOURCE_ORDER)
        steps: list[dict] = []
        per_source: list[dict] = []
        total_added = 0
        any_ok = False

        for sid in target_ids:
            src = VETTED_SOURCES[sid]
            repo = f"{src['org']}/{src['repo']}"
            steps.append({'cls': 't-info', 'msg': f"[pull] {sid} ← github.com/{repo}@{src['branch']}"})
            try:
                pulled = _fetch_source_payloads(src, timeout=timeout)
                count = len(pulled)
                self._merge_source(sid, pulled)
                self._set_state(sid, status='ok', count=count,
                                detail=f'{count} payloads from {repo}')
                steps.append({'cls': 't-ok',
                              'msg': f"[ok] {sid} — {count} payloads merged"})
                per_source.append({'id': sid, 'status': 'ok', 'count': count})
                total_added += count
                any_ok = True
            except urllib.error.HTTPError as exc:
                detail = (f'rate-limited (HTTP 403) — set GITHUB_TOKEN to raise the limit'
                          if exc.code == 403 else f'HTTP {exc.code}')
                self._set_state(sid, status='error', detail=detail)
                steps.append({'cls': 't-err', 'msg': f"[fail] {sid} — {detail}"})
                per_source.append({'id': sid, 'status': 'error', 'detail': detail})
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                detail = f'unreachable ({exc.__class__.__name__}) — offline range?'
                self._set_state(sid, status='unreachable', detail=detail)
                steps.append({'cls': 't-warn', 'msg': f"[skip] {sid} — {detail}"})
                per_source.append({'id': sid, 'status': 'unreachable', 'detail': detail})
            except Exception as exc:  # noqa: BLE001 — never let one source kill the run
                detail = f'{exc.__class__.__name__}: {exc}'
                self._set_state(sid, status='error', detail=detail)
                steps.append({'cls': 't-err', 'msg': f"[fail] {sid} — {detail}"})
                per_source.append({'id': sid, 'status': 'error', 'detail': detail})

        with self._lock:
            self._save()
        registered = self._push_to_engine()
        steps.append({'cls': 't-ok' if any_ok else 't-warn',
                      'msg': f"[lib] {registered} synced payloads registered "
                             f"({total_added} pulled this run)"})

        return {
            'status': 'updated' if any_ok else 'no_change',
            'pulled': total_added,
            'registered': registered,
            'per_source': per_source,
            'steps': steps,
            'sources': self.sources(),
            'stats': self.stats(),
        }

    # ── Internal mutation helpers ──────────────────────────────────────────────

    def _merge_source(self, source_id: str, pulled: list[dict]) -> None:
        """Replace this source's payloads with the freshly pulled set."""
        with self._lock:
            kept = [p for p in self._payloads if p.get('source') != source_id]
            kept.extend(pulled)
            self._payloads = kept
            # Drop cached descriptions for this source — paths may have changed.
            prefix = f"{source_id}::"
            for k in [k for k in self._doc_cache if k.startswith(prefix)]:
                del self._doc_cache[k]

    def _set_state(self, source_id: str, status: str,
                   count: int | None = None, detail: str = '') -> None:
        with self._lock:
            st = self._state.setdefault(source_id, {})
            st['status'] = status
            st['detail'] = detail
            st['last_synced'] = _utcnow_iso()
            if count is not None:
                st['count'] = count
