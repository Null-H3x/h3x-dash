#!/usr/bin/env python3
"""eyesieve_html_report.py — self-contained HTML report.

Renders the EyeSieve corpus as a single HTML file that opens in any
browser. No external dependencies (no CDN, no web fonts, no API calls);
all CSS and JavaScript are embedded.

CURRENT SCOPE (phase 1)
=======================
- Overview banner with key statistics
- Universal positions and prefix-group structural summary
- Aligned grid for all 9 messages (decimal / hex / glyph format toggle)
- Per-message frequency distributions
- All four east-west pairwise diffs with run-length detail
- Corpus-wide frequency distribution with color-coded glyphs

FUTURE SCOPE (phase 10)
=======================
This module will be extended to also render sieve results: hypothesis
explorer, per-stage telemetry waterfall, top-N candidates by score, and
per-candidate decryption detail panels. The current corpus sections will
remain at the top of the report as foundational context.

USAGE
=====
    ./eyesieve_html_report.py
    ./eyesieve_html_report.py --output eyesieve_corpus_report.html
    ./eyesieve_html_report.py --data noita_eye_data.json --output report.html
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import eyesieve_corpus as ec
import eyesieve_reader as er

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
REPORT_VERSION = "0.1.2"


# ---------------------------------------------------------------------------
# Embedded CSS — SPECTR-style cyberpunk
# ---------------------------------------------------------------------------

CSS = r"""
:root {
    --bg-0:        #07090c;
    --bg-1:        #0c1218;
    --bg-2:        #131c25;
    --bg-3:        #1a2532;
    --border:      #233141;
    --border-hot:  #2e4663;

    --fg-0:        #e5edf2;
    --fg-1:        #adc1cf;
    --fg-2:        #6f8395;
    --fg-3:        #4a5c6e;

    --accent-cyan:    #5fffff;
    --accent-magenta: #ff60c8;
    --accent-yellow:  #ffd75f;
    --accent-green:   #5fff87;
    --accent-red:     #ff6b87;
    --accent-blue:    #7ab8ff;
    --accent-amber:   #ffa657;

    --cell-univ:      #5fffff;
    --cell-3group:    #ff60c8;
    --cell-4group:    #ffd75f;
    --cell-6group:    #c2a14a;
    --cell-default:   var(--fg-1);
}

* { box-sizing: border-box; }

html, body {
    margin: 0;
    padding: 0;
    background: var(--bg-0);
    color: var(--fg-0);
    font-family: 'JetBrains Mono', 'Fira Code', 'Source Code Pro',
                 'Cascadia Code', Consolas, 'Liberation Mono', monospace;
    font-size: 13px;
    line-height: 1.5;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 24px 32px 64px;
}

h1, h2, h3 {
    font-weight: 600;
    letter-spacing: 0.02em;
}

h1 {
    font-size: 22px;
    color: var(--accent-cyan);
    margin: 0 0 4px;
    text-shadow: 0 0 12px rgba(95, 255, 255, 0.18);
}

h2 {
    font-size: 16px;
    color: var(--accent-cyan);
    margin: 32px 0 12px;
    padding: 6px 12px;
    background: linear-gradient(90deg,
                rgba(95, 255, 255, 0.08), transparent 80%);
    border-left: 3px solid var(--accent-cyan);
}

h3 {
    font-size: 13px;
    color: var(--fg-0);
    margin: 16px 0 8px;
    font-weight: 600;
}

.subtitle {
    color: var(--fg-2);
    font-size: 12px;
    margin-bottom: 18px;
}

.banner {
    background: linear-gradient(135deg, var(--bg-1) 0%, var(--bg-2) 100%);
    border: 1px solid var(--border);
    padding: 18px 22px;
    margin-bottom: 28px;
    position: relative;
}
.banner::before {
    content: '';
    position: absolute; left: 0; top: 0;
    width: 100%; height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent-cyan),
                transparent);
    opacity: 0.6;
}

.card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    padding: 18px 22px;
    margin-bottom: 18px;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 14px;
}

.stat {
    background: var(--bg-2);
    border: 1px solid var(--border);
    padding: 10px 14px;
}
.stat .label {
    color: var(--fg-2);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.stat .value {
    color: var(--accent-cyan);
    font-size: 20px;
    font-weight: 600;
    margin-top: 4px;
}
.stat.alt .value { color: var(--accent-magenta); }
.stat.warn .value { color: var(--accent-amber); }

table {
    border-collapse: collapse;
    margin: 8px 0;
    font-size: 12px;
}
th, td {
    padding: 4px 12px;
    text-align: left;
    border: 1px solid var(--border);
}
th {
    background: var(--bg-2);
    color: var(--fg-1);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 0.05em;
}
td { color: var(--fg-1); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.code { color: var(--accent-cyan); font-weight: 600; }
td.group3 { color: var(--cell-3group); }
td.group4 { color: var(--cell-4group); }
td.group6 { color: var(--cell-6group); }

pre {
    background: var(--bg-1);
    border: 1px solid var(--border);
    padding: 14px 16px;
    margin: 8px 0;
    overflow-x: auto;
    color: var(--fg-1);
    font-family: inherit;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre;
    tab-size: 4;
}

/* ===== aligned-grid cells ===== */

.grid-wrap { overflow-x: auto; }
.grid {
    font-family: inherit;
    font-size: 12px;
    line-height: 1.55;
    white-space: pre;
    color: var(--fg-1);
}
.grid .label { display: inline-block; width: 4ch; color: var(--accent-cyan); font-weight: 600; }
.grid .pos-header { color: var(--fg-3); }
.grid .pos-header.univ { color: var(--accent-cyan); font-weight: 700; }
.grid .cell { display: inline-block; }
.grid .cell.univ { color: var(--cell-univ); font-weight: 700;
                    text-shadow: 0 0 6px rgba(95, 255, 255, 0.25); }
.grid .cell.g3 { color: var(--cell-3group); }
.grid .cell.g4 { color: var(--cell-4group); }
.grid .cell.g6 { color: var(--cell-6group); }
.grid .cell.empty { color: var(--fg-3); }

/* ===== format toggle ===== */

.toggle-bar {
    display: flex;
    gap: 6px;
    margin: 6px 0 14px;
    align-items: center;
}
.toggle-bar .label-prefix {
    color: var(--fg-2);
    margin-right: 6px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.toggle-bar button {
    background: var(--bg-2);
    color: var(--fg-1);
    border: 1px solid var(--border);
    padding: 4px 12px;
    font-family: inherit;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.15s;
}
.toggle-bar button:hover {
    border-color: var(--accent-cyan);
    color: var(--accent-cyan);
}
.toggle-bar button.active {
    background: var(--bg-3);
    color: var(--accent-cyan);
    border-color: var(--accent-cyan);
    box-shadow: 0 0 8px rgba(95, 255, 255, 0.2);
}

/* ===== diff panel ===== */

details {
    background: var(--bg-1);
    border: 1px solid var(--border);
    margin: 8px 0;
}
details summary {
    cursor: pointer;
    padding: 10px 16px;
    color: var(--fg-1);
    font-weight: 600;
    background: var(--bg-2);
    user-select: none;
    list-style: none;
}
details summary::-webkit-details-marker { display: none; }
details summary::before {
    content: '▸';
    color: var(--accent-cyan);
    display: inline-block;
    width: 1.4em;
    transition: transform 0.15s;
}
details[open] summary::before { transform: rotate(90deg); }
details[open] summary {
    border-bottom: 1px solid var(--border);
    background: var(--bg-3);
    color: var(--accent-cyan);
}
details .content { padding: 12px 16px; }

.match-stats {
    display: inline-block;
    margin-left: 12px;
    color: var(--fg-2);
    font-weight: 400;
}
.match-stats .pct-good { color: var(--accent-green); }
.match-stats .pct-bad  { color: var(--accent-red); }
.match-stats .run      { color: var(--accent-yellow); }

.diff-table { font-size: 12px; max-width: 760px; }
.diff-table td.ok { color: var(--accent-green); }
.diff-table td.bad { color: var(--accent-red); }

/* ===== frequency table ===== */

.freq-table { font-size: 12px; }
.freq-table td.glyph { font-weight: 700; text-align: center; min-width: 40px; }

/* ===== footer ===== */

footer {
    margin-top: 48px;
    padding-top: 18px;
    border-top: 1px solid var(--border);
    color: var(--fg-3);
    font-size: 11px;
}
footer .code-line { color: var(--fg-2); }

/* scrollbar */
::-webkit-scrollbar { height: 8px; width: 8px; }
::-webkit-scrollbar-track { background: var(--bg-0); }
::-webkit-scrollbar-thumb { background: var(--border-hot); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-cyan); }
"""


# ---------------------------------------------------------------------------
# Embedded JS — format toggle, highlight toggle
# ---------------------------------------------------------------------------

JS = r"""
(function () {
    const FORMAT_KEY = 'eyesieve-format';
    const HL_KEY     = 'eyesieve-highlights';

    function applyFormat(fmt) {
        document.querySelectorAll('.cell').forEach(c => {
            const txt = c.dataset[fmt];
            if (txt !== undefined) c.textContent = txt;
        });
        document.querySelectorAll('[data-fmt-button]').forEach(b => {
            b.classList.toggle('active', b.dataset.fmtButton === fmt);
        });
        try { localStorage.setItem(FORMAT_KEY, fmt); } catch (_) {}
    }

    function applyHighlights(enabled) {
        document.body.classList.toggle('no-highlights', !enabled);
        document.querySelectorAll('[data-hl-button]').forEach(b => {
            const want = b.dataset.hlButton === (enabled ? 'on' : 'off');
            b.classList.toggle('active', want);
        });
        try { localStorage.setItem(HL_KEY, enabled ? '1' : '0'); } catch (_) {}
    }

    document.addEventListener('DOMContentLoaded', () => {
        let savedFmt, savedHL;
        try { savedFmt = localStorage.getItem(FORMAT_KEY); } catch (_) {}
        try { savedHL  = localStorage.getItem(HL_KEY); } catch (_) {}
        applyFormat(savedFmt || 'decimal');
        applyHighlights(savedHL === null || savedHL === undefined
                        ? true : savedHL === '1');

        document.querySelectorAll('[data-fmt-button]').forEach(b => {
            b.addEventListener('click', () => applyFormat(b.dataset.fmtButton));
        });
        document.querySelectorAll('[data-hl-button]').forEach(b => {
            b.addEventListener('click',
                () => applyHighlights(b.dataset.hlButton === 'on'));
        });
    });
})();

/* When highlights are off, override the cell-color classes via CSS. */
document.head.appendChild(Object.assign(document.createElement('style'), {
    textContent: `
        body.no-highlights .cell.univ,
        body.no-highlights .cell.g3,
        body.no-highlights .cell.g4,
        body.no-highlights .cell.g6 {
            color: var(--cell-default) !important;
            text-shadow: none !important;
            font-weight: normal !important;
        }
        body.no-highlights .pos-header.univ {
            color: var(--fg-3) !important;
            font-weight: normal !important;
        }
    `
}));
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _cell_class(code: str, position: int,
                highlights: er.HighlightMap) -> str:
    """Cell-class derivation using the same logic as the terminal reader."""
    if position in highlights.universal_positions:
        return "cell univ"
    group_size = highlights.group_membership.get(position, {}).get(code, 0)
    if group_size == 3:
        return "cell g3"
    if group_size == 4:
        return "cell g4"
    if group_size == 6:
        return "cell g6"
    return "cell"


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def render_banner(corpus: ec.Corpus, data_path: Path) -> str:
    sha = _file_sha256(data_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""
<div class="banner">
  <h1>EyeSieve // Corpus Report</h1>
  <div class="subtitle">
    Phase&nbsp;1 content view — structural analysis + aligned ciphertext display.
    Phase&nbsp;10 will extend this report with sieve results.
  </div>
  <div class="subtitle">
    Generated {_esc(now)} &nbsp;|&nbsp; data SHA-256
    <code style="color:var(--accent-cyan)">{_esc(sha[:16])}…{_esc(sha[-8:])}</code>
  </div>
</div>
"""


def render_overview(corpus: ec.Corpus) -> str:
    univ = ec.universal_positions(corpus)
    east_west_codes = ", ".join(corpus.short_codes)
    stats = [
        ("deck size",  corpus.deck_size,         ""),
        ("messages",   corpus.num_messages,      ""),
        ("symbols",    sum(corpus.lengths),      ""),
        ("east msgs",  len(corpus.east_codes()), "alt"),
        ("west msgs",  len(corpus.west_codes()), "alt"),
        ("longest",    max(corpus.lengths),      ""),
        ("shortest",   min(corpus.lengths),      ""),
        ("universal",  f"{len(univ)} pos",       ""),
    ]
    grid = "".join(
        f'<div class="stat {cls}"><div class="label">{_esc(lbl)}</div>'
        f'<div class="value">{_esc(val)}</div></div>'
        for lbl, val, cls in stats
    )

    # Per-message length rows
    rows = "".join(
        f'<tr><td class="code">{_esc(code)}</td>'
        f'<td>{_esc(label)}</td>'
        f'<td class="num">{length}</td></tr>'
        for code, label, length in zip(
            corpus.short_codes, corpus.labels, corpus.lengths)
    )

    # Universal positions table
    univ_rows = "".join(
        f'<tr><td class="num">{pos}</td>'
        f'<td class="num" style="color:var(--accent-cyan)">{sym}</td></tr>'
        for pos, sym in univ
    )

    return f"""
<h2>1. Overview</h2>
<div class="stats-grid">{grid}</div>

<h3 style="margin-top:24px">Per-message lengths</h3>
<table>
  <thead><tr><th>code</th><th>label</th><th>length</th></tr></thead>
  <tbody>{rows}</tbody>
</table>

<h3 style="margin-top:18px">Universal positions
  <span style="color:var(--fg-2);font-weight:400;">(all 9 messages share the same symbol)</span>
</h3>
<table>
  <thead><tr><th>position</th><th>symbol</th></tr></thead>
  <tbody>{univ_rows}</tbody>
</table>
"""


def render_structure(corpus: ec.Corpus) -> str:
    groups = ec.shared_prefix_groups(corpus, max_position=16, min_group_size=2)
    rows: list[str] = []
    for g in groups:
        if len(g.members) == corpus.num_messages:
            continue  # already shown in universal table
        size_cls = {3: "group3", 4: "group4", 6: "group6"}.get(
            len(g.members), ""
        )
        rows.append(
            f'<tr>'
            f'<td class="num">{g.position}</td>'
            f'<td class="num">{g.symbol}</td>'
            f'<td class="num {size_cls}">{len(g.members)}</td>'
            f'<td class="{size_cls}">{_esc(", ".join(g.members))}</td>'
            f'</tr>'
        )
    return f"""
<h2>2. Prefix groups (positions 0-15)</h2>
<p style="color:var(--fg-2);font-size:12px;">
  Members are colored by group size:
  <span class="group3">3-group {{E1,W1,E2}}</span> /
  <span class="group4">4-group {{E3,E4,W4,E5}}</span> /
  <span class="group6">6-group</span>.
</p>
<table>
  <thead><tr><th>position</th><th>symbol</th><th>size</th><th>members</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
"""


def render_grid(corpus: ec.Corpus, highlights: er.HighlightMap) -> str:
    """Aligned grid for all 9 messages with format toggle."""
    chunk_size = 32          # positions per row chunk
    chunks: list[str] = []
    max_len = max(corpus.lengths)

    for chunk_start in range(0, max_len, chunk_size):
        chunk_end = min(chunk_start + chunk_size, max_len)
        positions = range(chunk_start, chunk_end)

        # Position header line
        header_parts = ['<span class="label"></span> ']
        for pos in positions:
            cls = "pos-header univ" if pos in highlights.universal_positions \
                  else "pos-header"
            header_parts.append(
                f'<span class="{cls}">{pos:>3d}</span>'
            )
        header_line = " ".join(header_parts)

        # Per-message rows
        rows: list[str] = [header_line]
        for code, ct in zip(corpus.short_codes, corpus.ciphertexts):
            row_parts = [f'<span class="label">{_esc(code)}</span> ']
            for pos in positions:
                if pos < len(ct):
                    v = ct[pos]
                    dec = f"{v:>3d}"
                    hexv = f"  {v:02x}"
                    glyph = f"  {er.GLYPHS[v]}"
                    cls = _cell_class(code, pos, highlights)
                    row_parts.append(
                        f'<span class="{cls}" '
                        f'data-decimal="{dec}" '
                        f'data-hex="{hexv}" '
                        f'data-glyph="{glyph}">{dec}</span>'
                    )
                else:
                    row_parts.append('<span class="cell empty">   </span>')
            rows.append(" ".join(row_parts))
        chunks.append("\n".join(rows))

    body = "\n\n".join(chunks)

    return f"""
<h2>3. Aligned grid</h2>
<div class="toggle-bar">
  <span class="label-prefix">format:</span>
  <button data-fmt-button="decimal">decimal</button>
  <button data-fmt-button="hex">hex</button>
  <button data-fmt-button="glyph">glyph</button>
  <span class="label-prefix" style="margin-left:18px">highlights:</span>
  <button data-hl-button="on">on</button>
  <button data-hl-button="off">off</button>
</div>
<div class="card">
  <div class="grid-wrap">
    <pre class="grid">{body}</pre>
  </div>
</div>
"""


def render_diffs(corpus: ec.Corpus, highlights: er.HighlightMap) -> str:
    """All four east-west pairwise diffs in collapsible panels."""
    panels: list[str] = []
    for i in range(1, 5):
        ca, cb = f"E{i}", f"W{i}"
        a = corpus.by_short(ca)
        b = corpus.by_short(cb)
        compare_len = min(len(a), len(b))
        matches = 0
        longest_run = 0
        current_run = 0
        run_start = 0
        run_span: tuple[int, int] | None = None
        rows: list[str] = []
        for j in range(compare_len):
            va, vb = a[j], b[j]
            match = (va == vb)
            if match:
                matches += 1
                if current_run == 0:
                    run_start = j
                current_run += 1
                if current_run > longest_run:
                    longest_run = current_run
                    run_span = (run_start, j)
            else:
                current_run = 0
            cls_a = _cell_class(ca, j, highlights)
            cls_b = _cell_class(cb, j, highlights)
            mark_cls = "ok" if match else "bad"
            mark = "✓" if match else "✗"
            rows.append(
                f'<tr><td class="num">{j}</td>'
                f'<td class="num"><span class="{cls_a}">{va}</span></td>'
                f'<td class="num"><span class="{cls_b}">{vb}</span></td>'
                f'<td class="{mark_cls}">{mark}</td></tr>'
            )
        pct = 100.0 * matches / max(compare_len, 1)
        pct_cls = "pct-good" if pct >= 30 else "pct-bad"
        run_text = (f'{longest_run} (pos {run_span[0]}-{run_span[1]})'
                    if run_span else '0')
        summary = (
            f'<span class="match-stats">'
            f'<span class="{pct_cls}">{pct:.1f}%</span>'
            f' match / longest run '
            f'<span class="run">{run_text}</span>'
            f'</span>'
        )
        extra_note = ""
        if len(a) != len(b):
            longer = ca if len(a) > len(b) else cb
            extra = abs(len(a) - len(b))
            extra_note = (
                f'<p style="color:var(--fg-2);font-size:11px;">'
                f'{_esc(longer)} has {extra} extra symbols beyond the '
                f'shared {compare_len}-position prefix.</p>'
            )
        panels.append(f"""
<details>
  <summary>{_esc(ca)} ↔ {_esc(cb)}{summary}</summary>
  <div class="content">
    {extra_note}
    <table class="diff-table">
      <thead><tr><th>pos</th><th>{_esc(ca)}</th><th>{_esc(cb)}</th><th>match</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</details>
""")
    return f"""
<h2>4. Pairwise diffs (east ↔ west)</h2>
<p style="color:var(--fg-2);font-size:12px;">
  Click a row to expand the full position-by-position breakdown. Match
  percentage and longest matching run are surfaced in the header.
</p>
{''.join(panels)}
"""


def render_frequency(corpus: ec.Corpus, freq: er.FrequencyMap) -> str:
    """Corpus-wide rune frequency distribution with color-coded glyphs."""
    total = sum(freq.counts)
    sorted_runes = sorted(range(len(freq.counts)),
                          key=lambda r: (-freq.counts[r], r))
    rows: list[str] = []
    for rank, rune in enumerate(sorted_runes):
        cnt = freq.counts[rune]
        if cnt == 0:
            break
        pct = 100.0 * cnt / total
        # Convert the 256-color palette index into an approximate hex color
        color = _256_to_hex(freq.color_code(rune))
        rows.append(
            f'<tr>'
            f'<td class="num">{rank}</td>'
            f'<td class="num">{rune}</td>'
            f'<td class="glyph" style="color:{color}">{_esc(er.GLYPHS[rune])}</td>'
            f'<td class="num">{cnt}</td>'
            f'<td class="num">{pct:.2f}</td>'
            f'</tr>'
        )
    return f"""
<h2>5. Corpus-wide rune frequency</h2>
<p style="color:var(--fg-2);font-size:12px;">
  Sorted descending by count. Glyph color follows the same gradient as the
  terminal reader's <code>--freq-color</code> flag.
</p>
<div class="card">
  <table class="freq-table">
    <thead><tr><th>rank</th><th>rune</th><th>glyph</th><th>count</th><th>%</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""


def _256_to_hex(palette_index: int) -> str:
    """Approximate xterm-256 palette index -> #RRGGBB hex string."""
    if palette_index < 16:
        # Standard 16-color block — approximate values
        std = [
            (0, 0, 0), (170, 0, 0), (0, 170, 0), (170, 85, 0),
            (0, 0, 170), (170, 0, 170), (0, 170, 170), (170, 170, 170),
            (85, 85, 85), (255, 85, 85), (85, 255, 85), (255, 255, 85),
            (85, 85, 255), (255, 85, 255), (85, 255, 255), (255, 255, 255),
        ]
        r, g, b = std[palette_index]
        return f"#{r:02x}{g:02x}{b:02x}"
    if palette_index >= 232:
        # Grayscale ramp
        gray = 8 + (palette_index - 232) * 10
        return f"#{gray:02x}{gray:02x}{gray:02x}"
    # 6x6x6 color cube
    p = palette_index - 16
    r = (p // 36) % 6
    g = (p // 6) % 6
    b = p % 6
    levels = (0, 95, 135, 175, 215, 255)
    return f"#{levels[r]:02x}{levels[g]:02x}{levels[b]:02x}"


def render_footer() -> str:
    return f"""
<footer>
  <div>EyeSieve // <code class="code-line">eyesieve_html_report.py</code> v{REPORT_VERSION}</div>
  <div class="code-line" style="margin-top:4px">{_esc(ERROR_PREFIX)}</div>
</footer>
"""


# ---------------------------------------------------------------------------
# Top-level renderer
# ---------------------------------------------------------------------------

def render_html(corpus: ec.Corpus, data_path: Path) -> str:
    freq = er.FrequencyMap.from_corpus(corpus)
    highlights = er.HighlightMap.from_corpus(corpus, max_position=64)

    body = "\n".join([
        render_banner(corpus, data_path),
        render_overview(corpus),
        render_structure(corpus),
        render_grid(corpus, highlights),
        render_diffs(corpus, highlights),
        render_frequency(corpus, freq),
        render_footer(),
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EyeSieve // Corpus Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
{body}
</div>
<script>{JS}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Generate a self-contained HTML report for the corpus."
    )
    p.add_argument("--data", default="noita_eye_data.json",
                   help="Path to the corpus JSON (default: %(default)s)")
    p.add_argument("--output", default="eyesieve_corpus_report.html",
                   help="Output path (default: %(default)s)")
    args = p.parse_args(argv)

    try:
        corpus = ec.load_corpus(args.data)
    except ec.CorpusError as e:
        print(f"\033[91m{e}\033[0m", file=sys.stderr)
        return 2

    try:
        rendered = render_html(corpus, Path(args.data))
    except Exception as e:  # noqa: BLE001
        print(f"\033[91m{ERROR_PREFIX} :: html_report :: "
              f"{type(e).__name__}: {e}\033[0m", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.write_text(rendered, encoding="utf-8")
    print(f"\033[92mreport written: {out}\033[0m"
          f"  ({out.stat().st_size:,} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
