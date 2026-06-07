#!/home/h3x/.venvs/eyestat/bin/python3
"""eyestat_html_report.py — generate an interactive HTML viewer for results.

Reads bruteforce_results.txt (the merged ranked output from eyestat_runner.py)
and emits a self-contained HTML file with:

  - Sortable columns (click any heading to toggle asc/desc)
  - Multi-axis filters: mode, prng, cipher family, best-language, min max_hits
  - Free-text search across mode/prng/key/hit_words
  - Per-row expansion: full hit-words list + decrypted text per language,
    with dictionary matches highlighted inline
  - CSV export of the currently filtered view

The HTML is fully self-contained — no external CDN, no internet required.
Embed your favorite font via fonts.googleapis.com if online; otherwise it
falls back to your system monospace.

USAGE
=====
    # Default: read ./bruteforce_results.txt → ./bruteforce_report.html
    python3 eyestat_html_report.py

    # Explicit paths
    python3 eyestat_html_report.py --input results_v1/bruteforce_results.txt \\
                              --output report.html

    # Scan an entire output dir's results_*.txt shards directly (no need to
    # have run merge_results first)
    python3 eyestat_html_report.py --scan-dir results_v1/ --output report.html
"""

from __future__ import annotations

import argparse
import gzip
import html
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Header line:  === mode=ctak_right prng=park_miller key=SEED:842194 max_hits=17 ===
RE_HEADER = re.compile(
    r"^===\s+mode=(?P<mode>\S+)\s+prng=(?P<prng>\S+)\s+key=(?P<key>\S+)"
    r"\s+max_hits=(?P<max_hits>\d+)\s+===\s*$"
)
# Per-language stats:  [fi] hits=22 zipf_score=3.95
RE_LANG = re.compile(
    r"^\s*\[(?P<lang>[a-z]+)\]\s+hits=(?P<hits>\d+)\s+"
    r"zipf_score=(?P<zipf>-?\d+(?:\.\d+)?)\s*$"
)
# Hit words list:  hit_words (22): tokkura, hakija, paula, ...
RE_HITWORDS = re.compile(
    r"^\s*hit_words\s+\(\d+\):\s*(?P<words>.*)$"
)
# Decrypted text:  text: tiixelpyeänumootegudnoamn...
RE_TEXT = re.compile(r"^\s*text:\s*(?P<text>.*)$")


# Mode → family (matches eyestat_runner.MODE_REGISTRY)
MODE_FAMILY: Dict[str, str] = {
    "ctak_right": "gak/xgak", "ctak_left": "gak/xgak",
    "ptak_right": "gak/xgak", "ptak_left": "gak/xgak",
    "xgak_sum_right": "gak/xgak", "xgak_sum_left": "gak/xgak",
    "xgak_diff_right": "gak/xgak", "xgak_diff_left": "gak/xgak",
    "kak_right": "kak", "kak_left": "kak",
    "cfb_mod": "cfb", "cfb_sub": "cfb",
    "ofb": "ofb",
    "vigenere_plain": "vigenere", "vigenere_pt_auto": "vigenere",
    "vigenere_ct_auto": "vigenere",
    "pontifex": "card", "mirdek": "card", "card_chameleon": "card",
}


@dataclass
class LangResult:
    hits: int
    zipf_score: float
    hit_words: List[str]
    text: str

@dataclass
class Entry:
    rank: int
    mode: str
    family: str
    prng: str
    key: str
    key_kind: str       # "SEED" or "PHRASE"
    key_value: str      # numeric for seeds, raw for phrases
    max_hits: int
    languages: Dict[str, LangResult]  # "fi" / "krl" / "en"
    best_lang: str       # lang with highest hits in this entry

    @property
    def hits_fi(self) -> int: return self.languages.get("fi", LangResult(0,0,[],"")).hits
    @property
    def hits_krl(self) -> int: return self.languages.get("krl", LangResult(0,0,[],"")).hits
    @property
    def hits_en(self) -> int: return self.languages.get("en", LangResult(0,0,[],"")).hits
    @property
    def zipf_fi(self) -> float: return self.languages.get("fi", LangResult(0,0,[],"")).zipf_score
    @property
    def zipf_krl(self) -> float: return self.languages.get("krl", LangResult(0,0,[],"")).zipf_score
    @property
    def zipf_en(self) -> float: return self.languages.get("en", LangResult(0,0,[],"")).zipf_score


def parse_results_file(path: Path) -> Tuple[List[Entry], Dict[str, Any]]:
    """Parse a bruteforce_results.txt (or per-shard results_*.txt) into Entries.

    Returns (entries, metadata). Metadata captures the leading comment lines
    if present (threshold, total count, etc.)."""
    opener = gzip.open if str(path).endswith(".gz") else open
    metadata: Dict[str, Any] = {"source_file": str(path)}
    entries: List[Entry] = []

    current_header: Optional[Dict[str, Any]] = None
    current_langs: Dict[str, LangResult] = {}
    pending_lang: Optional[str] = None
    pending_hits: int = 0
    pending_zipf: float = 0.0
    pending_words: List[str] = []
    rank = 0

    def flush_current() -> None:
        nonlocal current_header, current_langs, rank, pending_lang
        nonlocal pending_hits, pending_zipf, pending_words
        # Flush any pending language without text (defensive)
        if pending_lang is not None:
            current_langs[pending_lang] = LangResult(
                hits=pending_hits, zipf_score=pending_zipf,
                hit_words=pending_words, text="")
            pending_lang = None
        if current_header is None:
            return
        rank += 1
        # Best language by hit count (tiebreak: fi > krl > en)
        order = ["fi", "krl", "en"]
        best_lang = max(
            current_langs.keys(),
            key=lambda L: (current_langs[L].hits, -order.index(L) if L in order else -99),
            default="")
        # Parse key kind/value
        key = current_header["key"]
        if key.startswith("SEED:"):
            key_kind, key_value = "SEED", key[5:]
        elif key.startswith("PHRASE:"):
            key_kind, key_value = "PHRASE", key[7:]
        else:
            key_kind, key_value = "OTHER", key
        entries.append(Entry(
            rank=rank,
            mode=current_header["mode"],
            family=MODE_FAMILY.get(current_header["mode"], "unknown"),
            prng=current_header["prng"],
            key=key,
            key_kind=key_kind,
            key_value=key_value,
            max_hits=current_header["max_hits"],
            languages=current_langs,
            best_lang=best_lang,
        ))
        current_header = None
        current_langs = {}

    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            # Leading metadata comments
            if line.startswith("#"):
                if "threshold" in line and "threshold" not in metadata:
                    m = re.search(r"threshold\s*[≥>=]+\s*(\d+)", line)
                    if m:
                        metadata["threshold"] = int(m.group(1))
                if "total entries" in line and "total_entries" not in metadata:
                    m = re.search(r"(\d+)\s+total entries", line)
                    if m:
                        metadata["total_entries"] = int(m.group(1))
                continue

            m = RE_HEADER.match(line)
            if m:
                flush_current()
                current_header = {
                    "mode": m.group("mode"),
                    "prng": m.group("prng"),
                    "key": m.group("key"),
                    "max_hits": int(m.group("max_hits")),
                }
                pending_lang = None
                continue

            if current_header is None:
                continue

            m = RE_LANG.match(line)
            if m:
                # Flush previous language if it didn't have text
                if pending_lang is not None and pending_lang not in current_langs:
                    current_langs[pending_lang] = LangResult(
                        hits=pending_hits, zipf_score=pending_zipf,
                        hit_words=pending_words, text="")
                pending_lang = m.group("lang")
                pending_hits = int(m.group("hits"))
                pending_zipf = float(m.group("zipf"))
                pending_words = []
                continue

            m = RE_HITWORDS.match(line)
            if m and pending_lang is not None:
                raw = m.group("words").strip()
                pending_words = [w.strip() for w in raw.split(",") if w.strip()]
                continue

            m = RE_TEXT.match(line)
            if m and pending_lang is not None:
                txt = m.group("text")
                current_langs[pending_lang] = LangResult(
                    hits=pending_hits, zipf_score=pending_zipf,
                    hit_words=pending_words, text=txt)
                pending_lang = None
                continue

        flush_current()

    metadata["parsed_entries"] = len(entries)
    return entries, metadata


def scan_directory(dir_path: Path) -> Tuple[List[Entry], Dict[str, Any]]:
    """Aggregate all results_*.txt shards in a directory into one entry list.

    Layout-aware: looks for shards in <dir_path>/temp/ (new layout) first,
    then falls back to the flat layout (<dir_path>/) for legacy scan dirs.
    """
    temp_dir = dir_path / "temp"
    if temp_dir.is_dir():
        shards = sorted(temp_dir.glob("results_*.txt"))
        scan_root = temp_dir
    else:
        shards = sorted(dir_path.glob("results_*.txt"))
        scan_root = dir_path
    if not shards:
        return [], {"source_dir": str(scan_root), "shards_found": 0}
    all_entries: List[Entry] = []
    for shard in shards:
        entries, _ = parse_results_file(shard)
        all_entries.extend(entries)
    # Re-rank globally by max_hits desc (with zipf-sum tiebreak)
    all_entries.sort(
        key=lambda e: (-e.max_hits,
                       -(e.zipf_fi + e.zipf_krl + e.zipf_en)))
    for i, e in enumerate(all_entries):
        e.rank = i + 1
    return all_entries, {
        "source_dir": str(dir_path),
        "shards_found": len(shards),
        "total_entries": len(all_entries),
    }


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def entries_to_json(entries: List[Entry]) -> str:
    """Serialize entries as compact JSON for embedding in <script>."""
    out = []
    for e in entries:
        out.append({
            "r": e.rank,
            "m": e.mode,
            "fam": e.family,
            "p": e.prng,
            "k": e.key,
            "kk": e.key_kind,
            "kv": e.key_value,
            "mh": e.max_hits,
            "bl": e.best_lang,
            "L": {
                lang: {
                    "h": lr.hits,
                    "z": lr.zipf_score,
                    "w": lr.hit_words,
                    "t": lr.text,
                } for lang, lr in e.languages.items()
            }
        })
    return json.dumps(out, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Embedded eye icon (Noita iconography) — encoded as base64 so the report
# remains a single self-contained file with no external image dependencies.
# Source: user-supplied 54×36 JPEG. The CSS uses `image-rendering: pixelated`
# to preserve the crisp pixel-art look when scaled up in the toolbar.
# ---------------------------------------------------------------------------

EYE_ICON_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdC"
    "IFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAA"
    "AADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlk"
    "ZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAA"
    "ABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAA"
    "AAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAA"
    "AABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEA"
    "AAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAA"
    "ACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUG"
    "BwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUF"
    "BQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e"
    "Hh4eHh7/wAARCAAkADYDASIAAhEBAxEB/8QAFwABAQEBAAAAAAAAAAAAAAAAAAgGB//EAEIQAAAC"
    "BgQJCAUNAAAAAAAAAAARAgMHEhMVBQYUNAgWFxghJDEzQSImMkJjZIGDAQQjKPA1Vld4goSGkaKl"
    "xNLT/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhED"
    "EQA/ALLABMzTWpV7aVL81+nZrLouMGqKFMOI5Zr8giZuL92ZFyuqA7M01qVRGay/HWnZVMYtk1Re"
    "uiQ3H90gkRPobSM9HEYzOjYT8+f2n13/ABGMZky2vbSphnQUFNZdCxf1tQphxH7TcU0TNxRvDIuT"
    "1gZky3BOaVMMSqCmsuhWvW6UUw4j7m9TRM3E9hkWngApkBGfv2fElFMsyalURpUwxKp2ay6Fa9UX"
    "qYcR9zeoImbiewyLTwAbMAABxnCay7c38ineZrcuyg3nzej48AwZchPODIp3aa33tYN583o+PAdm"
    "EzNNZbXtmsvzX6ClUxi4wa2oXRIblmvyaRE+v3ZGfK6oDZ4TWXbm/kU7zNbl2UG8+b0fHgIzwZcu"
    "3ODIp3aa3LtYN583o+PAUyzJqVe2azDOgp2VTGFi/qihdEhv2m4oJET6jeEZ8nrAzJqWCczWYYlU"
    "7KpjCteqUouiQ33N6gkRPp7CM9PABTIjP6lX4r/h/Kf3rdfa6oe/Z8SUUyzJltRGazDEqgpVMYVr"
    "1teuiQ33N6mkRPp7CM9PABswAAAAABl6+M+qZXuxY31e9UpiwxLNHe9k+6+Ren0bXEfyGYzfWMfR"
    "9RP6/wCwAA6eAAAAAAP/2Q=="
)
EYE_ICON_DATA_URI = "data:image/jpeg;base64," + EYE_ICON_B64


CSS = r"""
:root {
  --bg-0: #07090d;
  --bg-1: #0c1218;
  --bg-2: #131b25;
  --bg-3: #1a2532;
  --border: #1f2d3d;
  --border-bright: #2b425b;
  --fg-0: #c8d1de;
  --fg-1: #8b97a8;
  --fg-2: #5a6678;
  --accent-cyan: #5ec5e0;
  --accent-cyan-bright: #00fff5;
  --accent-magenta: #ff3aa3;
  --accent-amber: #ffb454;
  --accent-green: #4dffa0;
  --accent-red: #ff5570;
  --severity-crit: #ff3aa3;
  --severity-high: #ffb454;
  --severity-med: #5ec5e0;
  --severity-low: #5a6678;
  --grid-line: rgba(94, 197, 224, 0.06);
}

* { box-sizing: border-box; }

html, body {
  margin: 0; padding: 0;
  background: var(--bg-0);
  color: var(--fg-0);
  font-family: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.45;
  min-height: 100vh;
}

body {
  background-image:
    linear-gradient(var(--grid-line) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid-line) 1px, transparent 1px),
    radial-gradient(ellipse at top, rgba(94,197,224,0.04), transparent 70%);
  background-size: 32px 32px, 32px 32px, 100% 100%;
}

/* ----- Top bar / banner ----- */
.banner {
  border-bottom: 1px solid var(--border);
  padding: 14px 22px;
  background: linear-gradient(180deg, var(--bg-1), var(--bg-0));
  display: flex; align-items: center; gap: 18px;
  position: sticky; top: 0; z-index: 50;
  backdrop-filter: blur(6px);
}
.banner .logo {
  font-weight: 700;
  letter-spacing: 0.18em;
  font-size: 14px;
  color: var(--accent-cyan-bright);
  text-shadow: 0 0 12px rgba(94,197,224,0.5);
}
.banner .logo .dot {
  display: inline-block; width: 8px; height: 8px;
  background: var(--accent-magenta);
  border-radius: 50%;
  margin-right: 8px;
  box-shadow: 0 0 10px var(--accent-magenta);
  animation: pulse 1.6s ease-in-out infinite;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
.banner .sub {
  color: var(--fg-2);
  font-size: 11px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.banner .spacer { flex: 1; }
.banner .stamp {
  color: var(--fg-2); font-size: 10px;
  letter-spacing: 0.1em; text-transform: uppercase;
}
.banner .eye {
  /* Pixel-art Noita eye icon. Scaled up from native 54×36 with crisp-edge
     rendering so the pixels stay sharp instead of going blurry. Sized to
     match the logo line-height and tinted with a subtle glow that matches
     the cyan accent palette of the rest of the banner. */
  height: 28px;
  width: auto;
  image-rendering: pixelated;
  image-rendering: crisp-edges;
  -ms-interpolation-mode: nearest-neighbor;
  filter: drop-shadow(0 0 6px rgba(255, 138, 86, 0.55));
  margin-right: 4px;
}

/* ----- Metrics row ----- */
.metrics {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 1px;
  background: var(--border);
  border-bottom: 1px solid var(--border);
}
.metric {
  background: var(--bg-1); padding: 12px 18px;
}
.metric .label {
  color: var(--fg-2); font-size: 10px;
  letter-spacing: 0.16em; text-transform: uppercase;
}
.metric .value {
  font-size: 22px; font-weight: 600;
  color: var(--accent-cyan-bright);
  margin-top: 2px;
  font-variant-numeric: tabular-nums;
}
.metric.alt .value { color: var(--accent-magenta); }
.metric.warn .value { color: var(--accent-amber); }
.metric.dim .value { color: var(--fg-1); }

/* ----- Per-scan config panel (only present when generated via runner) ----- */
.scan-info {
  background: var(--bg-1);
  border-bottom: 1px solid var(--border);
  padding: 14px 22px 16px 22px;
}
.scan-info-title {
  font-size: 10px;
  letter-spacing: 0.22em;
  text-transform: uppercase;
  color: var(--accent-amber);
  margin-bottom: 10px;
}
.scan-info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 6px 32px;
}
.scan-info-grid > div {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  border-bottom: 1px dashed var(--border);
  padding: 4px 0;
}
.scan-info-grid .k {
  color: var(--fg-2);
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.scan-info-grid .v {
  color: var(--accent-cyan-bright);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

/* ----- Filter bar ----- */
.filters {
  padding: 12px 22px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-1);
  display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
}
.filter-group { display: flex; flex-direction: column; gap: 4px; }
.filter-group label {
  font-size: 10px; color: var(--fg-2);
  letter-spacing: 0.14em; text-transform: uppercase;
}
.filter-group select, .filter-group input[type="number"], .filter-group input[type="text"] {
  background: var(--bg-2);
  color: var(--fg-0);
  border: 1px solid var(--border-bright);
  padding: 6px 9px;
  font: inherit; font-size: 12px;
  min-width: 130px;
  border-radius: 2px;
}
.filter-group select:focus, .filter-group input:focus {
  outline: none;
  border-color: var(--accent-cyan);
  box-shadow: 0 0 0 1px var(--accent-cyan);
}
.filter-group input[type="text"] { min-width: 240px; }

.filter-spacer { flex: 1; }

.btn {
  background: var(--bg-2);
  border: 1px solid var(--border-bright);
  color: var(--fg-0);
  padding: 6px 14px;
  font: inherit; font-size: 11px;
  letter-spacing: 0.1em; text-transform: uppercase;
  cursor: pointer; border-radius: 2px;
}
.btn:hover { border-color: var(--accent-cyan); color: var(--accent-cyan-bright); }
.btn.primary { border-color: var(--accent-cyan); color: var(--accent-cyan-bright); }

/* ----- Result count line ----- */
.result-count {
  padding: 8px 22px;
  font-size: 11px;
  color: var(--fg-2);
  letter-spacing: 0.1em; text-transform: uppercase;
  border-bottom: 1px solid var(--border);
}
.result-count .count { color: var(--accent-green); font-weight: 700; }

/* ----- Tabs ----- */
.tabs {
  display: flex;
  gap: 0;
  padding: 0 22px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-1);
}
.tab {
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--fg-2);
  font-family: inherit;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  padding: 12px 18px;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s;
}
.tab:hover { color: var(--fg-1); }
.tab.active {
  color: var(--accent-cyan-bright);
  border-bottom-color: var(--accent-cyan-bright);
}
.tab-panel.hidden { display: none; }

/* ----- Distribution panel ----- */
.dist-panel {
  padding: 22px;
  overflow-y: auto;
  height: calc(100vh - 380px);
  min-height: 360px;
}
.dist-section {
  margin-bottom: 32px;
  border: 1px solid var(--border);
  background: var(--bg-1);
}
.dist-section-head {
  padding: 10px 16px;
  background: var(--bg-2);
  border-bottom: 1px solid var(--border);
  font-size: 11px;
  letter-spacing: 0.12em;
  color: var(--accent-cyan);
  text-transform: uppercase;
}
.dist-section-body { padding: 16px; }

.dist-stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
}
.dist-stat {
  padding: 10px 12px;
  background: var(--bg-2);
  border-left: 2px solid var(--accent-green);
}
.dist-stat .lbl {
  font-size: 10px;
  color: var(--fg-2);
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.dist-stat .val {
  font-size: 18px;
  color: var(--fg-1);
  font-weight: 700;
  margin-top: 4px;
}

.dist-chart { background: var(--bg-0); }
.dist-chart svg { display: block; width: 100%; height: auto; }
.dist-chart .axis text { fill: var(--fg-2); font-size: 10px; }
.dist-chart .axis line, .dist-chart .axis path {
  stroke: var(--border); fill: none;
}
.dist-chart .bar {
  fill: var(--accent-cyan);
  fill-opacity: 0.75;
  transition: fill-opacity 0.1s;
}
.dist-chart .bar:hover {
  fill: var(--accent-cyan-bright);
  fill-opacity: 1.0;
}
.dist-chart .bar-outlier { fill: var(--accent-magenta, #ff5e9c); fill-opacity: 0.9; }
.dist-chart .bar-value {
  fill: #ffffff;
  font-size: 9px;
  font-weight: 600;
  pointer-events: none;
  /* Slight glow so the white pops over the bar fill or dark background. */
  text-shadow: 0 0 2px rgba(0, 0, 0, 0.85);
}
.dist-chart .chart-title {
  fill: var(--accent-cyan);
  font-size: 11px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.dist-words {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.dist-words th {
  text-align: left;
  padding: 6px 10px;
  background: var(--bg-2);
  color: var(--fg-2);
  font-size: 10px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  font-weight: 600;
}
.dist-words td {
  padding: 5px 10px;
  border-top: 1px solid var(--border);
}
.dist-words td.word { color: var(--accent-green); font-weight: 600; }
.dist-words td.num { text-align: right; color: var(--fg-1); }
.dist-words td.bar {
  width: 30%;
  padding: 0 10px;
}
.dist-words td.bar .b {
  height: 6px;
  background: var(--accent-cyan);
  opacity: 0.6;
}

.dist-empty {
  padding: 40px 24px;
  text-align: center;
  color: var(--fg-2);
  font-style: italic;
}

/* ----- Table ----- */
.table-wrap {
  padding: 0;
  overflow: auto;
  /* Fixed viewport height enables virtual scrolling — only visible rows
     are rendered, so the report stays responsive with 100k+ entries. */
  height: calc(100vh - 340px);
  min-height: 360px;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
tbody tr.v-spacer {
  border: none !important;
  background: transparent !important;
  cursor: default !important;
}
tbody tr.v-spacer:hover { background: transparent !important; }
tbody tr.v-spacer td { padding: 0 !important; height: inherit; }
tbody tr.selected { background: var(--bg-2); }
tbody tr.selected td:first-child {
  box-shadow: inset 3px 0 0 var(--accent-cyan-bright);
}

/* ----- Detail drawer ----- */
.detail-backdrop {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.55);
  opacity: 0; pointer-events: none;
  transition: opacity 0.16s ease-out;
  z-index: 99;
}
.detail-backdrop.open { opacity: 1; pointer-events: auto; }
.detail-drawer {
  position: fixed;
  top: 0; right: 0; bottom: 0;
  width: min(760px, 100vw);
  background: var(--bg-1);
  border-left: 1px solid var(--border-bright);
  box-shadow: -10px 0 30px rgba(0, 0, 0, 0.5);
  transform: translateX(100%);
  transition: transform 0.18s ease-out;
  z-index: 100;
  display: flex; flex-direction: column;
}
.detail-drawer.open { transform: translateX(0); }
.detail-drawer-head {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center;
  flex-shrink: 0;
  background: var(--bg-0);
}
.detail-drawer-head h3 {
  margin: 0;
  font-size: 12px; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--accent-cyan-bright);
}
.detail-drawer-head .sub {
  font-size: 10px; color: var(--fg-2); margin-top: 3px;
  font-family: "JetBrains Mono", ui-monospace, monospace;
}
.detail-nav { display: flex; gap: 4px; }
.detail-nav button {
  background: none; border: 1px solid var(--border);
  color: var(--fg-1);
  min-width: 32px; height: 28px;
  padding: 0 10px; cursor: pointer;
  font-family: inherit; font-size: 12px;
  letter-spacing: 0.08em;
  transition: all 0.1s;
}
.detail-nav button:hover {
  color: var(--accent-cyan-bright);
  border-color: var(--accent-cyan-bright);
}
.detail-nav button:disabled {
  opacity: 0.3; cursor: not-allowed;
}
.detail-nav button:disabled:hover {
  color: var(--fg-1); border-color: var(--border);
}
.detail-drawer-body {
  flex: 1; overflow-y: auto; padding: 14px 18px;
}
.detail-drawer-body .detail-grid {
  display: flex; flex-direction: column; gap: 12px;
}

table {
  width: 100%; border-collapse: collapse;
  font-variant-numeric: tabular-nums;
}
thead th {
  position: sticky; top: 0;
  background: var(--bg-1);
  border-bottom: 1px solid var(--border-bright);
  padding: 10px 12px;
  font-size: 10px; font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--fg-1);
  text-align: left;
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
  z-index: 5;
}
thead th:hover { color: var(--accent-cyan-bright); }
thead th.sorted {
  color: var(--accent-cyan-bright);
  background: var(--bg-2);
}
thead th .sort-ind { color: var(--accent-magenta); margin-left: 4px; }
tbody tr {
  border-bottom: 1px solid rgba(31, 45, 61, 0.5);
  cursor: pointer;
  transition: background 0.05s ease;
}
tbody tr:hover { background: var(--bg-2); }
tbody tr.expanded { background: var(--bg-2); }
tbody td {
  padding: 7px 12px;
  white-space: nowrap;
  vertical-align: middle;
}
tbody td.num { text-align: right; font-variant-numeric: tabular-nums; }
.severity-tag {
  display: inline-block;
  padding: 2px 7px;
  font-size: 10px;
  letter-spacing: 0.08em;
  border-radius: 2px;
  border: 1px solid currentColor;
}
.sev-crit { color: var(--severity-crit); }
.sev-high { color: var(--severity-high); }
.sev-med  { color: var(--severity-med);  }
.sev-low  { color: var(--severity-low);  }
.lang-tag {
  display: inline-block;
  padding: 1px 6px;
  font-size: 10px;
  letter-spacing: 0.1em;
  border-radius: 2px;
  background: var(--bg-3);
}
.lang-fi  { color: var(--accent-cyan); }
.lang-krl { color: var(--accent-magenta); }
.lang-en  { color: var(--accent-amber); }
.family-tag {
  display: inline-block; font-size: 10px;
  letter-spacing: 0.1em;
  color: var(--fg-2);
}

/* ----- Expanded row detail panel ----- */
tr.detail-row { background: var(--bg-1) !important; cursor: default; }
tr.detail-row > td {
  padding: 0;
  white-space: normal;
}
.detail {
  padding: 18px 24px;
  border-top: 1px solid var(--border-bright);
  border-bottom: 1px solid var(--border-bright);
  background:
    linear-gradient(180deg, rgba(94,197,224,0.03), transparent 40%),
    var(--bg-1);
}
.detail h3 {
  font-size: 11px; letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--fg-2);
  margin: 0 0 8px 0; font-weight: 600;
}
.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 18px;
}
.lang-panel {
  background: var(--bg-2);
  border: 1px solid var(--border-bright);
  border-left: 3px solid var(--accent-cyan);
  padding: 12px 14px;
}
.lang-panel.lang-fi { border-left-color: var(--accent-cyan); }
.lang-panel.lang-krl { border-left-color: var(--accent-magenta); }
.lang-panel.lang-en { border-left-color: var(--accent-amber); }
.lang-panel .head {
  display: flex; align-items: center; gap: 10px;
  margin-bottom: 8px;
  font-size: 11px; letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--fg-1);
}
.lang-panel .head .name {
  font-weight: 700;
  color: var(--fg-0);
}
.lang-panel .stat {
  color: var(--fg-2);
}
.lang-panel .stat b { color: var(--accent-cyan-bright); font-weight: 600; }
.lang-panel.lang-krl .stat b { color: var(--accent-magenta); }
.lang-panel.lang-en .stat b { color: var(--accent-amber); }

.hit-words {
  margin: 8px 0;
  display: flex; flex-wrap: wrap; gap: 4px;
}
.hit-words .w {
  display: inline-block;
  padding: 2px 7px;
  background: var(--bg-3);
  border: 1px solid var(--border-bright);
  color: var(--accent-green);
  font-size: 11px;
  border-radius: 2px;
}

.text-pane {
  margin-top: 8px;
  background: var(--bg-0);
  border: 1px solid var(--border);
  padding: 10px 12px;
  max-height: 260px;
  overflow-y: auto;
  font-size: 11.5px;
  line-height: 1.55;
  word-break: break-all;
  color: var(--fg-1);
  font-family: "JetBrains Mono", ui-monospace, monospace;
}
.text-pane mark {
  background: rgba(77, 255, 160, 0.18);
  color: var(--accent-green);
  text-shadow: 0 0 4px rgba(77, 255, 160, 0.4);
  padding: 0 1px;
  border-radius: 1px;
  font-weight: 700;
}

/* ----- Footer ----- */
.footer {
  padding: 18px 22px;
  text-align: center;
  color: var(--fg-2);
  font-size: 10px;
  letter-spacing: 0.14em; text-transform: uppercase;
  border-top: 1px solid var(--border);
}

/* ----- Scrollbar styling ----- */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg-1); }
::-webkit-scrollbar-thumb {
  background: var(--border-bright);
  border: 2px solid var(--bg-1);
  border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover { background: var(--accent-cyan); }

/* ----- Empty state ----- */
.empty-state {
  padding: 80px 22px;
  text-align: center;
  color: var(--fg-2);
}
.empty-state .big {
  font-size: 24px;
  color: var(--fg-1);
  margin-bottom: 12px;
  letter-spacing: 0.2em;
}
"""

JS = r"""
// ----- Length-weighted scoring -----
// Mirror of eyestat_scoring.length_weighted_score (Python). Computed client-side
// from the per-language hit_words array, so this works on existing shards
// without re-running the brute force. Default exponent = 2 (squared length).
//
// Rationale: chance substring matches in random text are dominated by short
// 4-letter words. Squared length suppresses noise contributions (4²=16) and
// amplifies real signal (7²=49, 10²=100). ~3-5x better signal-to-noise in
// practice than raw hit count.
const WSCORE_EXPONENT = 2;
function wscore(words) {
  if (!words || !words.length) return 0;
  let s = 0;
  for (const w of words) s += Math.pow(w.length, WSCORE_EXPONENT);
  return s;
}
function maxWscore(e) {
  return Math.max(
    wscore((e.L.fi || {}).w),
    wscore((e.L.krl || {}).w),
    wscore((e.L.en || {}).w));
}

const SORT_KEYS = {
  rank: { get: e => e.r, dir: 1 },
  mode: { get: e => e.m, dir: 1 },
  family: { get: e => e.fam, dir: 1 },
  prng: { get: e => e.p, dir: 1 },
  key: { get: e => e.kk === "SEED" ? parseInt(e.kv, 10) : e.kv, dir: 1 },
  max_hits: { get: e => e.mh, dir: -1 },
  wscore: { get: e => maxWscore(e), dir: -1 },
  best_lang: { get: e => e.bl, dir: 1 },
  hits_fi: { get: e => (e.L.fi || {h:0}).h, dir: -1 },
  hits_krl: { get: e => (e.L.krl || {h:0}).h, dir: -1 },
  hits_en: { get: e => (e.L.en || {h:0}).h, dir: -1 },
  zipf_fi: { get: e => (e.L.fi || {z:0}).z, dir: -1 },
  zipf_krl: { get: e => (e.L.krl || {z:0}).z, dir: -1 },
  zipf_en: { get: e => (e.L.en || {z:0}).z, dir: -1 },
};

const state = {
  sortKey: "max_hits",
  sortDir: -1,
  filterMode: "",
  filterPrng: "",
  filterFamily: "",
  filterBestLang: "",
  filterKeyKind: "",
  minHits: 0,
  search: "",
  // Virtualization + drawer state (was: expandedRanks for inline expand)
  selectedIdx: -1,         // index into currentItems; -1 = drawer closed
  currentItems: [],        // cached result of sortedFiltered()
  rowHeight: 36,           // measured at init
  rafPending: false,       // RAF debounce flag for scroll
  lastSignature: "",       // for detecting filter/sort changes
};

function severityClass(h) {
  if (h >= 18) return "sev-crit";
  if (h >= 15) return "sev-high";
  if (h >= 13) return "sev-med";
  return "sev-low";
}

function highlightHits(text, words) {
  if (!text || !words || words.length === 0) return escapeHtml(text);
  // Sort words by length desc so longer matches win over substrings
  const sorted = [...new Set(words)].sort((a,b) => b.length - a.length);
  // Build regex with escaped words. Word-boundary not reliable for non-ASCII,
  // so just match the literal substring (the parser produces them this way).
  const escaped = sorted.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp("(" + escaped.join("|") + ")", "g");
  return escapeHtml(text).replace(re, "<mark>$1</mark>");
}

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function applyFilters() {
  const q = state.search.toLowerCase().trim();
  return DATA.filter(e => {
    if (state.filterMode && e.m !== state.filterMode) return false;
    if (state.filterPrng && e.p !== state.filterPrng) return false;
    if (state.filterFamily && e.fam !== state.filterFamily) return false;
    if (state.filterBestLang && e.bl !== state.filterBestLang) return false;
    if (state.filterKeyKind && e.kk !== state.filterKeyKind) return false;
    if (e.mh < state.minHits) return false;
    if (q) {
      const hay = (e.m + " " + e.p + " " + e.k + " " +
        Object.values(e.L).map(L => (L.w || []).join(" ")).join(" ")).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function sortedFiltered() {
  const items = applyFilters();
  const sk = SORT_KEYS[state.sortKey];
  if (!sk) return items;
  items.sort((a, b) => {
    const va = sk.get(a), vb = sk.get(b);
    if (va < vb) return -1 * state.sortDir;
    if (va > vb) return  1 * state.sortDir;
    return 0;
  });
  return items;
}

function renderSignature() {
  return [state.sortKey, state.sortDir, state.filterMode, state.filterPrng,
    state.filterFamily, state.filterBestLang, state.filterKeyKind,
    state.minHits, state.search].join("|");
}

function render() {
  // Recompute the sorted+filtered view
  state.currentItems = sortedFiltered();
  document.getElementById("result-count").textContent =
    state.currentItems.length.toLocaleString() + " / " + DATA.length.toLocaleString();

  // If filters/sort changed, reset scroll to top and close drawer
  const sig = renderSignature();
  if (sig !== state.lastSignature) {
    const sc = document.querySelector(".table-wrap");
    if (sc) sc.scrollTop = 0;
    state.lastSignature = sig;
    // Selected item might no longer be in filtered set — close drawer to be safe
    if (state.selectedIdx >= 0) closeDetail();
  }

  virtualRender();
  // Update sort indicators in header
  document.querySelectorAll("thead th").forEach(th => {
    th.classList.remove("sorted");
    th.querySelector(".sort-ind").textContent = "";
    if (th.dataset.key === state.sortKey) {
      th.classList.add("sorted");
      th.querySelector(".sort-ind").textContent =
        state.sortDir === 1 ? "▲" : "▼";
    }
  });
}

function virtualRender() {
  const items = state.currentItems;
  const sc = document.querySelector(".table-wrap");
  const tbody = document.getElementById("tbody");
  if (!sc || !tbody) return;
  const rh = state.rowHeight;
  const overscan = 8;

  const scrollTop = sc.scrollTop;
  const viewHeight = sc.clientHeight;

  const firstIdx = Math.max(0, Math.floor(scrollTop / rh) - overscan);
  const lastIdx = Math.min(items.length,
    Math.ceil((scrollTop + viewHeight) / rh) + overscan);

  const topPad = firstIdx * rh;
  const bottomPad = Math.max(0, (items.length - lastIdx) * rh);

  const frag = document.createDocumentFragment();
  if (topPad > 0) {
    const tr = document.createElement("tr");
    tr.className = "v-spacer";
    tr.style.height = topPad + "px";
    const td = document.createElement("td");
    td.colSpan = 14;
    tr.appendChild(td);
    frag.appendChild(tr);
  }
  for (let i = firstIdx; i < lastIdx; i++) {
    frag.appendChild(makeRow(items[i], i));
  }
  if (bottomPad > 0) {
    const tr = document.createElement("tr");
    tr.className = "v-spacer";
    tr.style.height = bottomPad + "px";
    const td = document.createElement("td");
    td.colSpan = 14;
    tr.appendChild(td);
    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);
}

function scheduleVirtualRender() {
  if (state.rafPending) return;
  state.rafPending = true;
  requestAnimationFrame(() => {
    state.rafPending = false;
    virtualRender();
  });
}

function makeRow(e, idx) {
  const tr = document.createElement("tr");
  tr.dataset.idx = idx;
  if (idx === state.selectedIdx) tr.classList.add("selected");
  tr.innerHTML = `
    <td class="num">${e.r}</td>
    <td>${escapeHtml(e.m)}</td>
    <td><span class="family-tag">${escapeHtml(e.fam)}</span></td>
    <td>${escapeHtml(e.p)}</td>
    <td>${escapeHtml(e.kk === "SEED" ? "SEED:" + e.kv : (e.kk === "PHRASE" ? "PHR:" + (e.kv.length > 14 ? e.kv.slice(0,14) + "…" : e.kv) : e.k))}</td>
    <td class="num"><span class="severity-tag ${severityClass(e.mh)}">${e.mh}</span></td>
    <td class="num"><span class="lang-tag">${maxWscore(e).toFixed(0)}</span></td>
    <td><span class="lang-tag lang-${e.bl}">${e.bl}</span></td>
    <td class="num"><span class="lang-fi">${(e.L.fi||{h:0}).h}</span></td>
    <td class="num"><span class="lang-krl">${(e.L.krl||{h:0}).h}</span></td>
    <td class="num"><span class="lang-en">${(e.L.en||{h:0}).h}</span></td>
    <td class="num">${((e.L.fi||{z:0}).z).toFixed(2)}</td>
    <td class="num">${((e.L.krl||{z:0}).z).toFixed(2)}</td>
    <td class="num">${((e.L.en||{z:0}).z).toFixed(2)}</td>
  `;
  tr.addEventListener("click", () => openDetail(idx));
  return tr;
}

function makeDetailHtml(e) {
  const langOrder = ["fi", "krl", "en"];
  const panels = langOrder.filter(L => e.L[L]).map(L => {
    const lr = e.L[L];
    const wordsHtml = (lr.w || []).map(w =>
      `<span class="w">${escapeHtml(w)}</span>`).join("");
    const ws = wscore(lr.w);
    return `
      <div class="lang-panel lang-${L}">
        <div class="head">
          <span class="name">${L.toUpperCase()}</span>
          <span class="stat">hits <b>${lr.h}</b></span>
          <span class="stat">wscore <b>${ws.toFixed(0)}</b></span>
          <span class="stat">zipf <b>${lr.z.toFixed(2)}</b></span>
        </div>
        <div class="hit-words">${wordsHtml || '<span style="color:var(--fg-2)">none</span>'}</div>
        <div class="text-pane">${highlightHits(lr.t || "", lr.w || [])}</div>
      </div>`;
  }).join("");
  return `<div class="detail-grid">${panels}</div>`;
}

function openDetail(idx) {
  if (idx < 0 || idx >= state.currentItems.length) return;
  state.selectedIdx = idx;
  const e = state.currentItems[idx];

  document.getElementById("drawer-title").textContent =
    "Entry #" + e.r + " · " + e.m + " · " + e.p;
  document.getElementById("drawer-subtitle").textContent =
    "key=" + e.k + "  ·  max_hits=" + e.mh + "  ·  position " +
    (idx + 1) + " of " + state.currentItems.length.toLocaleString();
  document.getElementById("drawer-body").innerHTML = makeDetailHtml(e);

  document.getElementById("detail-drawer").classList.add("open");
  document.getElementById("detail-backdrop").classList.add("open");
  document.getElementById("drawer-prev").disabled = idx === 0;
  document.getElementById("drawer-next").disabled = idx >= state.currentItems.length - 1;

  virtualRender();  // refresh visible rows to update .selected highlight
}

function closeDetail() {
  document.getElementById("detail-drawer").classList.remove("open");
  document.getElementById("detail-backdrop").classList.remove("open");
  state.selectedIdx = -1;
  virtualRender();
}

function navDetail(delta) {
  const newIdx = state.selectedIdx + delta;
  if (newIdx < 0 || newIdx >= state.currentItems.length) return;
  // Scroll the row into view if needed
  const sc = document.querySelector(".table-wrap");
  const targetTop = newIdx * state.rowHeight;
  const targetBot = targetTop + state.rowHeight;
  if (targetTop < sc.scrollTop) {
    sc.scrollTop = targetTop - state.rowHeight * 3;
  } else if (targetBot > sc.scrollTop + sc.clientHeight) {
    sc.scrollTop = targetBot - sc.clientHeight + state.rowHeight * 3;
  }
  openDetail(newIdx);
}

function populateFilters() {
  const modes = [...new Set(DATA.map(e => e.m))].sort();
  const prngs = [...new Set(DATA.map(e => e.p))].sort();
  const fams = [...new Set(DATA.map(e => e.fam))].sort();
  const kinds = [...new Set(DATA.map(e => e.kk))].sort();
  fill("filter-mode", modes);
  fill("filter-prng", prngs);
  fill("filter-family", fams);
  fill("filter-key-kind", kinds);
  function fill(id, vals) {
    const sel = document.getElementById(id);
    for (const v of vals) {
      const opt = document.createElement("option");
      opt.value = v; opt.textContent = v;
      sel.appendChild(opt);
    }
  }
}

function attachHandlers() {
  document.querySelectorAll("thead th[data-key]").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (state.sortKey === key) state.sortDir *= -1;
      else { state.sortKey = key; state.sortDir = SORT_KEYS[key].dir; }
      render();
    });
  });
  document.getElementById("filter-mode").addEventListener("change", (e) => {
    state.filterMode = e.target.value; render();
  });
  document.getElementById("filter-prng").addEventListener("change", (e) => {
    state.filterPrng = e.target.value; render();
  });
  document.getElementById("filter-family").addEventListener("change", (e) => {
    state.filterFamily = e.target.value; render();
  });
  document.getElementById("filter-best-lang").addEventListener("change", (e) => {
    state.filterBestLang = e.target.value; render();
  });
  document.getElementById("filter-key-kind").addEventListener("change", (e) => {
    state.filterKeyKind = e.target.value; render();
  });
  document.getElementById("filter-min-hits").addEventListener("input", (e) => {
    state.minHits = parseInt(e.target.value, 10) || 0;
    document.getElementById("min-hits-display").textContent = state.minHits;
    render();
  });
  document.getElementById("filter-search").addEventListener("input", (e) => {
    state.search = e.target.value; render();
  });
  document.getElementById("btn-reset").addEventListener("click", () => {
    state.filterMode = state.filterPrng = state.filterFamily =
      state.filterBestLang = state.filterKeyKind = state.search = "";
    state.minHits = 0;
    state.sortKey = "max_hits"; state.sortDir = -1;
    if (state.selectedIdx >= 0) closeDetail();
    document.querySelectorAll("select").forEach(s => s.value = "");
    document.getElementById("filter-search").value = "";
    document.getElementById("filter-min-hits").value = 0;
    document.getElementById("min-hits-display").textContent = "0";
    render();
  });
  // Virtual scroll handler
  document.querySelector(".table-wrap").addEventListener("scroll", scheduleVirtualRender);
  window.addEventListener("resize", scheduleVirtualRender);
  // Detail drawer wiring
  document.getElementById("drawer-close").addEventListener("click", closeDetail);
  document.getElementById("detail-backdrop").addEventListener("click", closeDetail);
  document.getElementById("drawer-prev").addEventListener("click", () => navDetail(-1));
  document.getElementById("drawer-next").addEventListener("click", () => navDetail(1));
  // Keyboard nav: Esc closes, arrows move when drawer is open
  document.addEventListener("keydown", (ev) => {
    if (state.selectedIdx < 0) return;
    // Don't hijack arrows while typing in inputs
    const tag = (ev.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (ev.key === "Escape") { ev.preventDefault(); closeDetail(); }
    else if (ev.key === "ArrowDown" || ev.key === "ArrowRight" ||
             ev.key === "j" || ev.key === "n") {
      ev.preventDefault(); navDetail(1);
    }
    else if (ev.key === "ArrowUp" || ev.key === "ArrowLeft" ||
             ev.key === "k" || ev.key === "p") {
      ev.preventDefault(); navDetail(-1);
    }
  });
  document.getElementById("btn-csv").addEventListener("click", exportCsv);
}

function exportCsv() {
  const items = sortedFiltered();
  const cols = ["rank","mode","family","prng","key","key_kind","key_value",
    "max_hits","best_lang","hits_fi","hits_krl","hits_en",
    "zipf_fi","zipf_krl","zipf_en"];
  const rows = [cols.join(",")];
  for (const e of items) {
    const row = [
      e.r, e.m, e.fam, e.p,
      '"' + e.k.replace(/"/g, '""') + '"',
      e.kk, '"' + e.kv.replace(/"/g, '""') + '"',
      e.mh, e.bl,
      (e.L.fi||{h:0}).h, (e.L.krl||{h:0}).h, (e.L.en||{h:0}).h,
      ((e.L.fi||{z:0}).z).toFixed(2),
      ((e.L.krl||{z:0}).z).toFixed(2),
      ((e.L.en||{z:0}).z).toFixed(2),
    ];
    rows.push(row.join(","));
  }
  const blob = new Blob([rows.join("\n")], {type: "text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "eyestat_results_filtered.csv";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function init() {
  populateFilters();
  attachHandlers();
  // Measure actual row height with a sample render — keeps virtualization
  // accurate even if the user's font sizes / OS scaling differ from the default.
  const tbody = document.getElementById("tbody");
  const probe = document.createElement("tr");
  probe.innerHTML = "<td>0</td><td>x</td><td>x</td><td>x</td><td>x</td>" +
    "<td>0</td><td>x</td><td>0</td><td>0</td><td>0</td><td>0</td><td>0</td><td>0</td>";
  tbody.appendChild(probe);
  const measured = probe.getBoundingClientRect().height;
  tbody.removeChild(probe);
  if (measured > 0) state.rowHeight = measured;
  render();
}

// =============================================================================
// TABS + DISTRIBUTION VIEWS
// =============================================================================
//
// Goal: show statistical structure per language (FI/KRL/EN) so the user can
// see the noise floor and identify outliers worth investigating, separate from
// the row-by-row Results table.
//
// All distribution computation happens client-side from the embedded DATA.
// Renders lazily: the first click on a distribution tab triggers a one-time
// build, then it's cached. Subsequent tab switches are instant.

const distCache = {};   // lang → rendered HTMLDivElement payload, cached

function setActiveTab(tabName) {
  document.querySelectorAll(".tab").forEach(b => {
    const active = b.dataset.tab === tabName;
    b.classList.toggle("active", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
  });
  document.querySelectorAll(".tab-panel").forEach(p => {
    p.classList.toggle("hidden", p.id !== "panel-" + tabName);
  });
  // Lazy-render distribution view on first open
  if (tabName.startsWith("dist-")) {
    const lang = tabName.replace("dist-", "");
    const host = document.querySelector(`#panel-${tabName} .dist-panel`);
    if (!distCache[lang]) {
      host.innerHTML = renderDistribution(lang);
      distCache[lang] = true;
    }
  }
}

function initTabs() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => setActiveTab(btn.dataset.tab));
  });
}

// ---- Statistics helpers ----

function computeStats(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / n;
  const median = (n % 2)
    ? sorted[(n - 1) >> 1]
    : (sorted[(n >> 1) - 1] + sorted[n >> 1]) / 2;
  const variance = sorted.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
  const std = Math.sqrt(variance);
  const p = q => sorted[Math.min(n - 1, Math.floor(q * n))];
  return {
    n, sum, mean, median, std,
    min: sorted[0], max: sorted[n - 1],
    p25: p(0.25), p75: p(0.75),
    p95: p(0.95), p99: p(0.99),
  };
}

function histogram(values, nBins, minVal, maxVal) {
  if (minVal === undefined) minVal = Math.min(...values);
  if (maxVal === undefined) maxVal = Math.max(...values);
  if (maxVal === minVal) maxVal = minVal + 1;
  const width = (maxVal - minVal) / nBins;
  const bins = Array(nBins).fill(0);
  for (const v of values) {
    let idx = Math.floor((v - minVal) / width);
    if (idx < 0) idx = 0;
    if (idx >= nBins) idx = nBins - 1;
    bins[idx]++;
  }
  return { bins, minVal, maxVal, width };
}

// Integer-valued histogram (one bin per integer value).  Useful for hits where
// values are discrete and small range — gives a cleaner visualization than
// arbitrary bins.
function integerHistogram(values) {
  if (!values.length) return { bins: [], minVal: 0, maxVal: 0, width: 1 };
  const minVal = Math.floor(Math.min(...values));
  const maxVal = Math.ceil(Math.max(...values));
  const nBins = Math.max(1, maxVal - minVal + 1);
  const bins = Array(nBins).fill(0);
  for (const v of values) {
    bins[Math.round(v) - minVal]++;
  }
  return { bins, minVal, maxVal, width: 1 };
}

// ---- SVG histogram rendering ----
//
// Plot dimensions chosen to fit a typical desktop column. Bars use the cyan
// accent; the rightmost bins (low count, high value = outliers worth attention)
// get a different fill so they pop out at a glance.

function renderHistogramSVG(opts) {
  const {
    bins, minVal, maxVal, width,
    title, xLabel, integerX = false,
    outlierThresholdBin = -1,  // bins >= this index render as outlier color
  } = opts;
  const W = 720, H = 240;
  const margin = { top: 30, right: 16, bottom: 36, left: 50 };
  const plotW = W - margin.left - margin.right;
  const plotH = H - margin.top - margin.bottom;
  const nBins = bins.length;
  const maxCount = Math.max(1, ...bins);

  const barW = plotW / nBins;
  const x = i => margin.left + i * barW;
  const yScale = c => margin.top + plotH - (c / maxCount) * plotH;

  // Y-axis ticks: ~5 evenly spaced, integer counts
  const yTicks = [];
  for (let i = 0; i <= 5; i++) {
    const v = Math.round((maxCount * i) / 5);
    yTicks.push({ v, y: yScale(v) });
  }

  // X-axis ticks: show ~6-10 along the range. For integer histograms, label
  // each integer if the range is small enough.
  const xTicks = [];
  if (integerX && nBins <= 30) {
    for (let i = 0; i < nBins; i++) {
      xTicks.push({ label: String(Math.round(minVal + i)), x: x(i) + barW / 2 });
    }
  } else {
    const nTicks = Math.min(8, nBins);
    for (let i = 0; i <= nTicks; i++) {
      const idx = (i / nTicks) * nBins;
      const v = minVal + (idx / nBins) * (maxVal - minVal);
      xTicks.push({
        label: v.toFixed(v >= 100 ? 0 : 1),
        x: x(idx),
      });
    }
  }

  let bars = "";
  for (let i = 0; i < nBins; i++) {
    const c = bins[i];
    if (c === 0) continue;
    const xPos = x(i) + 0.5;
    const yPos = yScale(c);
    const w = Math.max(1, barW - 1);
    const h = (margin.top + plotH) - yPos;
    const cls = (outlierThresholdBin >= 0 && i >= outlierThresholdBin) ? "bar bar-outlier" : "bar";
    const binLo = (minVal + i * width).toFixed(integerX ? 0 : 1);
    const binHi = (minVal + (i + 1) * width).toFixed(integerX ? 0 : 1);
    const tipLabel = integerX
      ? `${Math.round(minVal + i)}: ${c.toLocaleString()} entries`
      : `[${binLo}, ${binHi}): ${c.toLocaleString()} entries`;
    bars += `<rect class="${cls}" x="${xPos}" y="${yPos}" width="${w}" height="${h}"><title>${tipLabel}</title></rect>`;

    // Value label in white above each non-zero bar. Two positioning regimes:
    //   - Tall bar (>= 22px): drop the label inside the top of the bar so it
    //     doesn't escape the chart area for max-height bars.
    //   - Short bar: float the label just above the bar (yPos - 4).
    // For very thin bars (< 18px wide), skip the label — text would be wider
    // than the bar and overlap neighbors illegibly.
    if (w >= 12) {
      const labelInside = h >= 22;
      const labelY = labelInside ? (yPos + 11) : Math.max(margin.top + 9, yPos - 4);
      bars += `<text class="bar-value" x="${xPos + w / 2}" y="${labelY}" text-anchor="middle">${c.toLocaleString()}</text>`;
    }
  }

  let yAxis = `<line x1="${margin.left}" y1="${margin.top}" x2="${margin.left}" y2="${margin.top + plotH}"/>`;
  for (const t of yTicks) {
    yAxis += `<line x1="${margin.left - 4}" y1="${t.y}" x2="${margin.left}" y2="${t.y}"/>`;
    yAxis += `<text x="${margin.left - 8}" y="${t.y + 4}" text-anchor="end">${t.v.toLocaleString()}</text>`;
  }

  let xAxis = `<line x1="${margin.left}" y1="${margin.top + plotH}" x2="${margin.left + plotW}" y2="${margin.top + plotH}"/>`;
  for (const t of xTicks) {
    xAxis += `<line x1="${t.x}" y1="${margin.top + plotH}" x2="${t.x}" y2="${margin.top + plotH + 4}"/>`;
    xAxis += `<text x="${t.x}" y="${margin.top + plotH + 18}" text-anchor="middle">${t.label}</text>`;
  }

  return `
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet"
         xmlns="http://www.w3.org/2000/svg">
      <text class="chart-title" x="${margin.left}" y="18">${title}</text>
      <g class="axis">${yAxis}${xAxis}</g>
      <g class="bars">${bars}</g>
      <text x="${margin.left + plotW / 2}" y="${H - 4}" text-anchor="middle"
            class="axis-label" style="fill: var(--fg-2); font-size: 10px;
            letter-spacing: 0.1em; text-transform: uppercase;">${xLabel}</text>
    </svg>`;
}

// ---- Top-words analysis ----
//
// Across all entries in a language, which hit-words appear most often?
// In CPU-bound regimes with large dictionaries, the most-common matches are
// usually short, high-frequency-letter words that hit by chance. This table
// is the easiest way to read the noise composition: if 'aita' shows up in
// 95% of entries, you know random matches dominate.

function topHitWords(lang, n = 20) {
  const counts = new Map();
  let totalEntries = 0;
  for (const e of DATA) {
    const ls = e.L[lang];
    if (!ls) continue;
    totalEntries++;
    const seen = new Set();
    for (const w of ls.w || []) {
      if (seen.has(w)) continue;
      seen.add(w);
      counts.set(w, (counts.get(w) || 0) + 1);
    }
  }
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  return { rows: sorted, totalEntries };
}

// ---- Full distribution panel render ----

function renderDistribution(lang) {
  // Gather per-language data
  const hits = [], wscores = [], zipfs = [];
  for (const e of DATA) {
    const ls = e.L[lang];
    if (!ls) continue;
    hits.push(ls.h);
    wscores.push(wscore(ls.w));
    zipfs.push(ls.z);
  }

  if (!hits.length) {
    return `<div class="dist-empty">No ${lang.toUpperCase()} entries in this dataset.</div>`;
  }

  const sHits = computeStats(hits);
  const sWs = computeStats(wscores);

  // Identify "outlier" bins for highlighting: anything above p95 of hits
  // visually gets the magenta treatment. This points the eye at the candidates
  // worth investigating amid the noise.
  const histHits = integerHistogram(hits);
  const outlierStartBin = Math.max(0, Math.round(sHits.p95 - histHits.minVal) + 1);

  const histWs = histogram(wscores, 40);
  const outlierStartBinWs = Math.floor(((sWs.p95 - histWs.minVal) / histWs.width) + 1);

  const tw = topHitWords(lang, 25);
  const maxTwCount = Math.max(1, ...tw.rows.map(r => r[1]));
  const twHtml = tw.rows.map(([word, count]) => {
    const pct = (100 * count / tw.totalEntries).toFixed(1);
    const barW = 100 * count / maxTwCount;
    return `
      <tr>
        <td class="word">${escapeHtml(word)}</td>
        <td class="num">${count.toLocaleString()}</td>
        <td class="num">${pct}%</td>
        <td class="bar"><div class="b" style="width:${barW}%"></div></td>
      </tr>`;
  }).join("");

  return `
    <div class="dist-section">
      <div class="dist-section-head">${lang.toUpperCase()} — Summary Statistics
        &nbsp;·&nbsp; ${hits.length.toLocaleString()} entries
      </div>
      <div class="dist-section-body">
        <div class="dist-stats-grid">
          <div class="dist-stat"><div class="lbl">Hits Mean</div><div class="val">${sHits.mean.toFixed(2)}</div></div>
          <div class="dist-stat"><div class="lbl">Hits Median</div><div class="val">${sHits.median.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">Hits Std</div><div class="val">${sHits.std.toFixed(2)}</div></div>
          <div class="dist-stat"><div class="lbl">Hits Max</div><div class="val">${sHits.max}</div></div>
          <div class="dist-stat"><div class="lbl">Hits p95</div><div class="val">${sHits.p95.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">Hits p99</div><div class="val">${sHits.p99.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">WScore Mean</div><div class="val">${sWs.mean.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">WScore Median</div><div class="val">${sWs.median.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">WScore p95</div><div class="val">${sWs.p95.toFixed(0)}</div></div>
          <div class="dist-stat"><div class="lbl">WScore Max</div><div class="val">${sWs.max.toFixed(0)}</div></div>
        </div>
      </div>
    </div>

    <div class="dist-section">
      <div class="dist-section-head">Hit Count Distribution
        &nbsp;·&nbsp; bars beyond p95 (${sHits.p95.toFixed(0)}) shown in magenta — visual outlier flag
      </div>
      <div class="dist-section-body dist-chart">
        ${renderHistogramSVG({
          ...histHits,
          title: lang.toUpperCase() + " hits per entry",
          xLabel: "max_hits",
          integerX: true,
          outlierThresholdBin: outlierStartBin,
        })}
      </div>
    </div>

    <div class="dist-section">
      <div class="dist-section-head">WScore Distribution
        &nbsp;·&nbsp; length-weighted score = Σ len(word)²
      </div>
      <div class="dist-section-body dist-chart">
        ${renderHistogramSVG({
          ...histWs,
          title: lang.toUpperCase() + " WScore per entry",
          xLabel: "wscore",
          integerX: false,
          outlierThresholdBin: outlierStartBinWs,
        })}
      </div>
    </div>

    <div class="dist-section">
      <div class="dist-section-head">Top Hit Words
        &nbsp;·&nbsp; words appearing in the most entries (high % = noise; rare/long words = signal)
      </div>
      <div class="dist-section-body">
        <table class="dist-words">
          <thead>
            <tr><th>Word</th><th>Entries</th><th>% of ${lang.toUpperCase()}</th><th></th></tr>
          </thead>
          <tbody>${twHtml || '<tr><td colspan="4" class="dist-empty">No hit words.</td></tr>'}</tbody>
        </table>
      </div>
    </div>`;
}

window.addEventListener("DOMContentLoaded", () => { init(); initTabs(); });
"""


def build_html(entries: List[Entry], metadata: Dict[str, Any]) -> str:
    """Assemble the full HTML document."""
    n = len(entries)
    n_modes = len({e.mode for e in entries})
    n_prngs = len({e.prng for e in entries if e.prng != "passphrase"})
    n_families = len({e.family for e in entries})
    max_hits = max((e.max_hits for e in entries), default=0)
    max_zipf = max(
        (e.zipf_fi + e.zipf_krl + e.zipf_en for e in entries), default=0.0)
    threshold = metadata.get("threshold", "?")
    source = metadata.get("source_file") or metadata.get("source_dir", "?")
    stamp = time.strftime("%Y-%m-%d %H:%M:%S %Z")

    # Optional per-scan metadata (only populated when generated by the
    # auto-HTML hook in eyestat_gpu_runner.py — for stand-alone CLI use
    # of this script these will be missing and the panel falls back).
    scan_mode    = metadata.get("mode")
    scan_prng    = metadata.get("prng")
    scan_seed_s  = metadata.get("seed_start")
    scan_seed_e  = metadata.get("seed_end")
    scan_langs   = metadata.get("languages")
    scan_chi2    = metadata.get("chi2_threshold")
    scan_tried   = metadata.get("total_seeds_tried")
    scan_hits    = metadata.get("total_hits")
    scan_shards  = metadata.get("shards_scanned")

    def _fmt_int(v):
        return f"{int(v):,}" if v is not None else "—"

    # Build the scan-info banner only when we have enough fields to fill it.
    # This appears above the standard metric cards and gives the per-scan
    # context that's otherwise invisible when entries == 0.
    if scan_mode and scan_prng:
        seed_range = f"{_fmt_int(scan_seed_s)} → {_fmt_int(scan_seed_e)}"
        scan_panel = f"""
<section class="scan-info">
  <div class="scan-info-title">SCAN CONFIGURATION</div>
  <div class="scan-info-grid">
    <div><span class="k">Mode</span><span class="v">{html.escape(str(scan_mode))}</span></div>
    <div><span class="k">PRNG</span><span class="v">{html.escape(str(scan_prng))}</span></div>
    <div><span class="k">Seed Range</span><span class="v">{seed_range}</span></div>
    <div><span class="k">Seeds Tried</span><span class="v">{_fmt_int(scan_tried)}</span></div>
    <div><span class="k">Total Hits</span><span class="v">{_fmt_int(scan_hits)}</span></div>
    <div><span class="k">Shards</span><span class="v">{_fmt_int(scan_shards)}</span></div>
    <div><span class="k">Languages</span><span class="v">{html.escape(str(scan_langs or '—'))}</span></div>
    <div><span class="k">Chi² Threshold</span><span class="v">{html.escape(str(scan_chi2 or '—'))}</span></div>
  </div>
</section>
"""
    else:
        scan_panel = ""

    data_json = entries_to_json(entries)

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EyeStat Results Viewer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>

<header class="banner">
  <img class="eye" src="{EYE_ICON_DATA_URI}" alt="" aria-hidden="true">
  <div class="logo"><span class="dot"></span>EYESTAT // RESULTS VIEWER</div>
  <div class="spacer"></div>
  <div class="stamp">Generated {html.escape(stamp)}</div>
</header>
{scan_panel}
<section class="metrics">
  <div class="metric">
    <div class="label">Entries Loaded</div>
    <div class="value">{n:,}</div>
  </div>
  <div class="metric alt">
    <div class="label">Top Max-Hits</div>
    <div class="value">{max_hits}</div>
  </div>
  <div class="metric warn">
    <div class="label">Threshold</div>
    <div class="value">≥ {html.escape(str(threshold))}</div>
  </div>
  <div class="metric dim">
    <div class="label">Modes Seen</div>
    <div class="value">{n_modes}</div>
  </div>
  <div class="metric dim">
    <div class="label">PRNGs Seen</div>
    <div class="value">{n_prngs}</div>
  </div>
  <div class="metric dim">
    <div class="label">Families</div>
    <div class="value">{n_families}</div>
  </div>
</section>

<section class="filters">
  <div class="filter-group">
    <label>Search</label>
    <input type="text" id="filter-search" placeholder="mode / prng / key / word">
  </div>
  <div class="filter-group">
    <label>Cipher Family</label>
    <select id="filter-family"><option value="">(all)</option></select>
  </div>
  <div class="filter-group">
    <label>Mode</label>
    <select id="filter-mode"><option value="">(all)</option></select>
  </div>
  <div class="filter-group">
    <label>PRNG</label>
    <select id="filter-prng"><option value="">(all)</option></select>
  </div>
  <div class="filter-group">
    <label>Best Language</label>
    <select id="filter-best-lang">
      <option value="">(any)</option>
      <option value="fi">fi</option>
      <option value="krl">krl</option>
      <option value="en">en</option>
    </select>
  </div>
  <div class="filter-group">
    <label>Key Type</label>
    <select id="filter-key-kind"><option value="">(any)</option></select>
  </div>
  <div class="filter-group">
    <label>Min Max-Hits: <span id="min-hits-display">0</span></label>
    <input type="range" id="filter-min-hits" min="0" max="{max_hits}" value="0" step="1">
  </div>
  <div class="filter-spacer"></div>
  <div class="filter-group">
    <label>&nbsp;</label>
    <button class="btn" id="btn-reset">Reset</button>
  </div>
  <div class="filter-group">
    <label>&nbsp;</label>
    <button class="btn primary" id="btn-csv">Export CSV</button>
  </div>
</section>

<section class="result-count">
  Showing <span class="count" id="result-count">{n:,} / {n:,}</span> entries
  &nbsp;·&nbsp; click headers to sort &nbsp;·&nbsp; click a row to inspect
  &nbsp;·&nbsp; ↑↓ to navigate, Esc to close
  &nbsp;·&nbsp; <b>WScore</b> = Σ len(w)² across hit words (3-5× better signal/noise than raw hits)
</section>

<nav class="tabs" role="tablist">
  <button class="tab active" data-tab="results"  role="tab" aria-selected="true">Results</button>
  <button class="tab"        data-tab="dist-fi"  role="tab">FI Distribution</button>
  <button class="tab"        data-tab="dist-krl" role="tab">KRL Distribution</button>
  <button class="tab"        data-tab="dist-en"  role="tab">EN Distribution</button>
</nav>

<section class="tab-panel" id="panel-results">

<div class="table-wrap">
<table>
<thead>
<tr>
  <th data-key="rank"     >Rank<span class="sort-ind"></span></th>
  <th data-key="mode"     >Mode<span class="sort-ind"></span></th>
  <th data-key="family"   >Family<span class="sort-ind"></span></th>
  <th data-key="prng"     >PRNG<span class="sort-ind"></span></th>
  <th data-key="key"      >Key<span class="sort-ind"></span></th>
  <th data-key="max_hits" >Max Hits<span class="sort-ind"></span></th>
  <th data-key="wscore"   >WScore<span class="sort-ind"></span></th>
  <th data-key="best_lang">Best<span class="sort-ind"></span></th>
  <th data-key="hits_fi"  >FI Hits<span class="sort-ind"></span></th>
  <th data-key="hits_krl" >KRL Hits<span class="sort-ind"></span></th>
  <th data-key="hits_en"  >EN Hits<span class="sort-ind"></span></th>
  <th data-key="zipf_fi"  >FI Zipf<span class="sort-ind"></span></th>
  <th data-key="zipf_krl" >KRL Zipf<span class="sort-ind"></span></th>
  <th data-key="zipf_en"  >EN Zipf<span class="sort-ind"></span></th>
</tr>
</thead>
<tbody id="tbody"></tbody>
</table>
</div>

</section>

<section class="tab-panel hidden" id="panel-dist-fi"  ><div class="dist-panel" data-lang="fi" ></div></section>
<section class="tab-panel hidden" id="panel-dist-krl" ><div class="dist-panel" data-lang="krl"></div></section>
<section class="tab-panel hidden" id="panel-dist-en"  ><div class="dist-panel" data-lang="en" ></div></section>

<div class="detail-backdrop" id="detail-backdrop"></div>
<aside class="detail-drawer" id="detail-drawer" role="dialog" aria-modal="true" aria-label="Entry detail">
  <header class="detail-drawer-head">
    <div>
      <h3 id="drawer-title">Entry Detail</h3>
      <div class="sub" id="drawer-subtitle"></div>
    </div>
    <div class="detail-nav">
      <button id="drawer-prev" title="Previous (↑ / ←)">↑</button>
      <button id="drawer-next" title="Next (↓ / →)">↓</button>
      <button id="drawer-close" title="Close (Esc)">close</button>
    </div>
  </header>
  <div class="detail-drawer-body" id="drawer-body"></div>
</aside>

<footer class="footer">
  Source: {html.escape(str(source))}
  &nbsp;·&nbsp; {n:,} entries parsed
  &nbsp;·&nbsp; eyestat_html_report.py
</footer>

<script>
const DATA = {data_json};
{JS}
</script>
</body>
</html>
"""
    return html_doc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", default="bruteforce_results.txt",
                   help="Merged results file (default: ./bruteforce_results.txt)")
    p.add_argument("--scan-dir", default=None,
                   help="Instead of --input, aggregate all results_*.txt "
                        "in this directory")
    p.add_argument("--output", default="bruteforce_report.html",
                   help="HTML output path (default: ./bruteforce_report.html)")
    args = p.parse_args(argv)

    if args.scan_dir:
        path = Path(args.scan_dir)
        if not path.is_dir():
            print(f"ERROR: --scan-dir {path} is not a directory", file=sys.stderr)
            return 2
        print(f"[eyestat_html_report] scanning {path}/results_*.txt ...")
        entries, metadata = scan_directory(path)
    else:
        path = Path(args.input)
        if not path.exists():
            print(f"ERROR: input file {path} not found", file=sys.stderr)
            return 2
        print(f"[eyestat_html_report] reading {path} ...")
        entries, metadata = parse_results_file(path)

    if not entries:
        print("WARNING: 0 entries parsed — output will be an empty report",
              file=sys.stderr)

    print(f"[eyestat_html_report] parsed {len(entries):,} entries")
    if metadata.get("threshold") is not None:
        print(f"[eyestat_html_report] source threshold: ≥{metadata['threshold']}")

    print(f"[eyestat_html_report] building HTML ...")
    doc = build_html(entries, metadata)
    out = Path(args.output)
    out.write_text(doc, encoding="utf-8")
    size_mb = out.stat().st_size / 1024**2
    print(f"[eyestat_html_report] wrote {out} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
