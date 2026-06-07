#!/usr/bin/env python3
"""eyesieve_run_report.py — phase 10: HTML report for run outputs.

Renders a self-contained HTML report from a runner output directory
(telemetry.json + survivors.jsonl + optional scored.jsonl). Reuses the
SPECTR cyberpunk palette from ``eyesieve_html_report`` so corpus reports
and run reports share visual identity.

SECTIONS
========
1. **Header**       Run identity (theory, config fingerprint, timestamps)
2. **Config**       All enumerator/scoring/runner knobs as a key-value grid
3. **Funnel**       Pipeline waterfall: total → exec_fail → kills/stage → survivors
4. **Timing**       Sieve vs scoring breakdown with hyps/sec derived rate
5. **Leaderboard**  Top scored candidates (if scoring was enabled)
6. **Breakdown**    Per-cipher survival rates (interesting structural pattern)

USAGE
=====
::

    eyesieve_run_report.py --run-dir runs/2026-05-14-203315-mono
    eyesieve_run_report.py --run-dir <dir> --output custom_report.html
    eyesieve_run_report.py --run-dir <dir> --top-n 50

The default output filename is ``run_report.html`` inside the run dir.

ERROR CONTRACT
==============
All failures raise ``RunReportError`` with the standard prefix
``Internal Error Code: XD-MBYG04K-URS3LF``.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import eyesieve_html_report as ehr  # for shared CSS palette

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"
REPORT_VERSION = "0.1.0"


class RunReportError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: run_report :: {msg}")


# ===========================================================================
# Data loading
# ===========================================================================

def _read_telemetry(run_dir: Path) -> dict:
    path = run_dir / "telemetry.json"
    if not path.exists():
        raise RunReportError(f"telemetry.json not found in {run_dir}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise RunReportError(f"telemetry.json malformed: {e}")


def _read_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path) as f:
        for i, line in enumerate(f):
            if limit is not None and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RunReportError(f"{path.name}:line {i+1}: malformed JSON: {e}")
    return out


# ===========================================================================
# Section renderers
# ===========================================================================

def _html_escape(s) -> str:
    return html.escape(str(s))


def render_header(telemetry: dict, run_dir: Path) -> str:
    cfg = telemetry.get("config", {})
    theory = cfg.get("theory", "theory1")
    fingerprint = telemetry.get("config_fingerprint", "—")
    totals = telemetry.get("totals", {})
    return f"""
<section class="hdr">
  <h1>
    <span class="brand-mark">EYESIEVE //</span>
    <span class="brand-sub">RUN REPORT</span>
  </h1>
  <div class="header-meta">
    <div><span class="key">run dir</span>
         <span class="val">{_html_escape(run_dir)}</span></div>
    <div><span class="key">theory</span>
         <span class="val">{_html_escape(theory)}</span></div>
    <div><span class="key">fingerprint</span>
         <span class="val mono">{_html_escape(fingerprint[:16])}…</span></div>
    <div><span class="key">total evaluated</span>
         <span class="val">{totals.get('total_evaluated', 0):,}</span></div>
    <div><span class="key">survivors</span>
         <span class="val accent-green">{totals.get('survivors', 0):,}</span></div>
  </div>
</section>
"""


def render_config(telemetry: dict) -> str:
    cfg = telemetry.get("config", {})
    rows = []

    def kv(k, v):
        rows.append(f'<tr><td class="k">{_html_escape(k)}</td>'
                    f'<td class="v">{_html_escape(v)}</td></tr>')

    kv("data_path", cfg.get("data_path", "—"))
    kv("theory", cfg.get("theory", "theory1"))
    # The single-process runner stores enumerator config differently; handle both.
    enum_cfg = cfg.get("theory1_config") or cfg.get("enumerator") or {}
    if enum_cfg:
        for k, v in enum_cfg.items():
            kv(f"  t1.{k}", v)
    t2 = cfg.get("theory2_config")
    if t2:
        for k, v in t2.items():
            if isinstance(v, list):
                v = "[" + ", ".join(map(str, v)) + "]"
            kv(f"  t2.{k}", v)
    if "n_workers" in cfg:
        kv("n_workers", cfg["n_workers"])
        kv("chunksize", cfg.get("chunksize", "—"))
    kv("scoring_enabled", cfg.get("scoring_enabled", "—"))
    if cfg.get("scoring_enabled"):
        kv("  n_mappings", cfg.get("scoring_n_mappings", "—"))

    return f"""
<section class="card">
  <h2>config</h2>
  <table class="kv-table">{''.join(rows)}</table>
</section>
"""


def render_funnel(telemetry: dict) -> str:
    """Pipeline waterfall: each cascade stage as a horizontal bar."""
    totals = telemetry.get("totals", {})
    total = totals.get("total_evaluated", 0) or 1
    exec_fail = totals.get("execute_failures", 0)
    survivors = totals.get("survivors", 0)
    killed = totals.get("killed_by_stage", {})

    # Build the funnel: total → after_exec → after_stage1 → … → survivors
    stages = []
    running = total
    stages.append(("input", running, total, "var(--accent-cyan)"))
    running -= exec_fail
    stages.append(("execute", running, total, "var(--accent-red)"))
    # Stages in the order they appear in the default cascade. "length" runs
    # first and MUST be included — omitting it made its kills invisible and
    # let the survivor bar disagree with the killed_by_stage totals. Any stage
    # name present in the telemetry but not listed here is appended afterwards
    # so custom cascades never silently drop kills from the waterfall.
    stage_order = ["length", "alphabet_closure", "ic", "distribution"]
    for extra in killed:
        if extra not in stage_order:
            stage_order.append(extra)
    for s in stage_order:
        n_killed = killed.get(s, 0)
        running -= n_killed
        stages.append((s, running, total, "var(--accent-amber)"))
    # Anything left is survivors
    stages.append(("survivors", survivors, total, "var(--accent-green)"))

    bars = []
    for label, n, denom, color in stages:
        pct = (n / denom * 100) if denom else 0
        bars.append(f"""
<div class="funnel-row">
  <div class="funnel-label">{_html_escape(label)}</div>
  <div class="funnel-bar-wrap">
    <div class="funnel-bar" style="width:{pct:.2f}%; background:{color};"></div>
  </div>
  <div class="funnel-count">{n:,}</div>
  <div class="funnel-pct">{pct:.1f}%</div>
</div>
""")

    death_table_rows = []
    for stage, n in sorted(killed.items(), key=lambda x: -x[1]):
        pct = n / total * 100 if total else 0
        death_table_rows.append(
            f'<tr><td>{_html_escape(stage)}</td>'
            f'<td class="r">{n:,}</td>'
            f'<td class="r">{pct:.2f}%</td></tr>'
        )

    return f"""
<section class="card">
  <h2>pipeline funnel</h2>
  <div class="funnel">{''.join(bars)}</div>
  <h3 class="sub">killed by stage</h3>
  <table class="num-table">
    <thead><tr><th>stage</th><th class="r">count</th><th class="r">%</th></tr></thead>
    <tbody>{''.join(death_table_rows)}</tbody>
  </table>
</section>
"""


def render_timing(telemetry: dict) -> str:
    timing = telemetry.get("timing_seconds", {})
    sieve = timing.get("sieve", 0)
    scoring = timing.get("scoring", 0)
    total_t = timing.get("total", sieve + scoring)
    n_hypos = telemetry.get("totals", {}).get("total_evaluated", 0)
    rate = n_hypos / sieve if sieve > 0 else 0
    n_scored = telemetry.get("scoring", {}).get("candidates_scored", 0)
    score_rate = n_scored / scoring if scoring > 0 else 0
    return f"""
<section class="card">
  <h2>timing</h2>
  <div class="stat-grid">
    <div class="stat"><div class="label">sieve pass</div>
         <div class="value">{sieve:.2f}<span class="unit">s</span></div></div>
    <div class="stat alt"><div class="label">hyps / sec</div>
         <div class="value">{rate:,.0f}</div></div>
    <div class="stat"><div class="label">scoring pass</div>
         <div class="value">{scoring:.2f}<span class="unit">s</span></div></div>
    <div class="stat alt"><div class="label">cands / sec</div>
         <div class="value">{score_rate:.1f}</div></div>
    <div class="stat warn"><div class="label">total</div>
         <div class="value">{total_t:.2f}<span class="unit">s</span></div></div>
  </div>
</section>
"""


def render_leaderboard(scored: list[dict], top_n: int) -> str:
    if not scored:
        return f"""
<section class="card">
  <h2>leaderboard</h2>
  <p class="note">no scored candidates — runner was launched with --no-score</p>
</section>
"""
    # Truncate
    rows = []
    for rank, entry in enumerate(scored[:top_n], 1):
        scoring = entry.get("scoring", {})
        best_lang = scoring.get("best_language", "—")
        best_score = scoring.get("best_score", 0.0)
        total_hits = scoring.get("total_hits", 0)
        # Get text from best language
        per_lang = scoring.get("per_language", [])
        text = ""
        for ls in per_lang:
            if ls.get("language") == best_lang:
                text = ls.get("decrypted_text", "")[:80]
                break
        # Per-language hits cells
        lang_cells = ""
        for ls in per_lang:
            zip_s = ls.get("zipf_score", 0)
            lang_cells += (f'<span class="lang-pill" title="{_html_escape(ls.get("language", ""))}">'
                           f'<span class="lang-name">{_html_escape(ls.get("language", ""))}</span>'
                           f'<span class="lang-score">{zip_s:.2f}</span>'
                           f'</span>')
        hypo_name = entry.get("hypothesis_name", "—")
        rows.append(f"""
<tr>
  <td class="rank">#{rank}</td>
  <td class="lang-cell">{lang_cells}</td>
  <td class="hits">{total_hits}</td>
  <td class="text"><code>{_html_escape(text)}</code></td>
  <td class="hypo-name"><code>{_html_escape(hypo_name)}</code></td>
</tr>
""")

    return f"""
<section class="card">
  <h2>leaderboard <span class="count-pill">top {min(top_n, len(scored))} of {len(scored)}</span></h2>
  <table class="leaderboard">
    <thead>
      <tr><th>rank</th><th>per-language zipf</th><th>hits</th>
          <th>best-language snippet</th><th>hypothesis</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
"""


def render_breakdown(survivors: list[dict], telemetry: dict) -> str:
    """Per-cipher and per-merge-op survival rates."""
    if not survivors:
        return ""
    cipher_count: Counter = Counter()
    merge_count: Counter = Counter()
    deriv_count: Counter = Counter()
    for s in survivors:
        name = s.get("hypothesis_name", "")
        # Parse the canonical hypothesis name format:
        # "input=merge(E1+W1,concat) | key=single(E5) | derive=identity | cipher=affine"
        for chunk in name.split("|"):
            chunk = chunk.strip()
            if chunk.startswith("input="):
                # Extract merge op name from input=merge(E1+W1,opname)
                inner = chunk[len("input=merge("):-1]
                # comma after the codes separates from the op
                comma = inner.find(",")
                if comma >= 0:
                    op_name = inner[comma+1:].strip()
                    merge_count[op_name] += 1
            elif chunk.startswith("cipher="):
                cipher_count[chunk[len("cipher="):]] += 1
            elif chunk.startswith("derive="):
                # Generalize: only show first prefix component for Theory 2
                d = chunk[len("derive="):]
                if d == "identity":
                    deriv_count["identity"] += 1
                elif d.startswith("self("):
                    deriv_count["self_merge"] += 1
                elif d.startswith("cross("):
                    deriv_count["cross_merge"] += 1
                elif d.startswith("const("):
                    deriv_count["constant_merge"] += 1
                else:
                    deriv_count[d] += 1

    def render_table(counter, title, top_n=20):
        if not counter: return ""
        items = counter.most_common(top_n)
        max_val = items[0][1] if items else 1
        rows = []
        for name, n in items:
            pct = n / sum(counter.values()) * 100
            bar_w = n / max_val * 100
            rows.append(f"""
<tr>
  <td class="bk-name"><code>{_html_escape(name)}</code></td>
  <td class="bk-bar">
    <div class="bk-bar-wrap"><div class="bk-bar-fill" style="width:{bar_w:.1f}%"></div></div>
  </td>
  <td class="r">{n:,}</td>
  <td class="r">{pct:.1f}%</td>
</tr>""")
        return f"""
<div class="bk-block">
  <h3 class="sub">{_html_escape(title)}</h3>
  <table class="bk-table">
    <thead><tr><th>name</th><th>bar</th><th class="r">survivors</th><th class="r">%</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
"""

    return f"""
<section class="card">
  <h2>survivor breakdown</h2>
  {render_table(cipher_count, 'by cipher')}
  {render_table(merge_count, 'by input merge op (top 20)')}
  {render_table(deriv_count, 'by key derivation family')}
</section>
"""


# ===========================================================================
# Run-report-specific CSS extensions
# ===========================================================================

RUN_REPORT_CSS = r"""
/* Run-report extensions on top of html_report.CSS palette */
.hdr {
    padding: 36px 32px 28px;
    background: linear-gradient(135deg, var(--bg-1) 0%, var(--bg-2) 100%);
    border-bottom: 2px solid var(--border-hot);
}
.hdr h1 {
    margin: 0 0 16px 0;
    letter-spacing: 0.05em;
}
.brand-mark { color: var(--accent-cyan); font-weight: 700; }
.brand-sub { color: var(--fg-2); font-weight: 400; font-size: 0.7em; }
.header-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px 24px;
    margin-top: 16px;
}
.header-meta .key {
    display: block;
    color: var(--fg-3);
    font-size: 0.7em;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}
.header-meta .val { color: var(--fg-0); font-weight: 500; }
.header-meta .val.mono { font-family: monospace; }
.header-meta .val.accent-green { color: var(--accent-green); }

.card {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin: 16px 32px;
    padding: 20px 24px;
}
.card h2 {
    margin-top: 0;
    color: var(--accent-cyan);
    font-size: 1.15em;
    letter-spacing: 0.04em;
    text-transform: lowercase;
}
.card h3.sub {
    margin-top: 18px;
    margin-bottom: 8px;
    color: var(--accent-magenta);
    font-size: 0.95em;
    font-weight: 500;
    letter-spacing: 0.04em;
    text-transform: lowercase;
}

.count-pill {
    background: var(--bg-3);
    color: var(--fg-2);
    font-size: 0.7em;
    padding: 3px 10px;
    border-radius: 10px;
    margin-left: 8px;
    font-weight: 400;
    letter-spacing: 0;
}

.kv-table { width: 100%; border-collapse: collapse; }
.kv-table td { padding: 4px 8px; border-bottom: 1px solid var(--bg-2); }
.kv-table td.k { color: var(--fg-2); font-family: monospace; width: 35%; }
.kv-table td.v { color: var(--fg-0); font-family: monospace; }

.funnel { margin: 10px 0; }
.funnel-row {
    display: grid;
    grid-template-columns: 130px 1fr 100px 65px;
    align-items: center;
    gap: 12px;
    margin-bottom: 6px;
    font-family: monospace;
    font-size: 0.9em;
}
.funnel-label { color: var(--fg-1); text-align: right; padding-right: 4px; }
.funnel-bar-wrap { background: var(--bg-3); height: 22px; border-radius: 3px;
                    overflow: hidden; border: 1px solid var(--border); }
.funnel-bar { height: 100%; transition: width 0.5s; }
.funnel-count { color: var(--fg-0); text-align: right; }
.funnel-pct { color: var(--fg-2); text-align: right; }

.num-table { width: 100%; border-collapse: collapse; margin-top: 8px; font-family: monospace; font-size: 0.9em; }
.num-table th, .num-table td { padding: 4px 10px; border-bottom: 1px solid var(--bg-2); text-align: left; }
.num-table .r, .num-table th.r { text-align: right; }
.num-table th { color: var(--fg-2); font-weight: 500; }

.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
}
.stat .label {
    color: var(--fg-2);
    font-size: 0.7em;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.stat .value {
    font-size: 1.6em;
    font-weight: 500;
    color: var(--accent-cyan);
    font-family: monospace;
}
.stat .value .unit { color: var(--fg-2); font-size: 0.6em; margin-left: 3px; }
.stat.alt .value { color: var(--accent-magenta); }
.stat.warn .value { color: var(--accent-amber); }

.leaderboard {
    width: 100%; border-collapse: collapse; font-family: monospace; font-size: 0.85em;
}
.leaderboard th, .leaderboard td {
    padding: 6px 10px; border-bottom: 1px solid var(--bg-2); text-align: left;
    vertical-align: top;
}
.leaderboard th { color: var(--fg-2); font-weight: 500; font-size: 0.85em;
                   text-transform: lowercase; letter-spacing: 0.04em; }
.leaderboard .rank { color: var(--accent-cyan); font-weight: 700; }
.leaderboard .text code { color: var(--fg-1); font-size: 0.95em; }
.leaderboard .hypo-name code { color: var(--fg-2); font-size: 0.85em; }
.leaderboard .hits { color: var(--accent-amber); text-align: right; }

.lang-pill {
    display: inline-block;
    background: var(--bg-3);
    border: 1px solid var(--border);
    padding: 1px 6px;
    margin: 1px 3px 1px 0;
    border-radius: 3px;
    font-size: 0.85em;
}
.lang-name { color: var(--fg-2); margin-right: 4px; }
.lang-score { color: var(--accent-green); font-weight: 500; }

.bk-block { margin-top: 16px; }
.bk-table { width: 100%; border-collapse: collapse;
            font-family: monospace; font-size: 0.85em; }
.bk-table th, .bk-table td { padding: 4px 10px; border-bottom: 1px solid var(--bg-2);
                              text-align: left; }
.bk-table th { color: var(--fg-2); font-weight: 500; }
.bk-table .r { text-align: right; }
.bk-name code { color: var(--fg-1); }
.bk-bar { width: 30%; }
.bk-bar-wrap { background: var(--bg-3); height: 14px; border-radius: 2px;
                overflow: hidden; border: 1px solid var(--border); }
.bk-bar-fill { background: var(--accent-cyan); height: 100%; opacity: 0.65; }

.note { color: var(--fg-2); font-style: italic; }
.footer { padding: 24px 32px; color: var(--fg-3); font-size: 0.8em;
          border-top: 1px solid var(--border); margin-top: 32px; }
"""


def render_html(run_dir: Path, top_n: int = 25) -> str:
    telemetry = _read_telemetry(run_dir)
    survivors_path = run_dir / "survivors.jsonl"
    scored_path = run_dir / "scored.jsonl"

    # Read survivors for breakdown; cap to avoid huge reports.
    survivors = _read_jsonl(survivors_path, limit=20000)
    scored = _read_jsonl(scored_path) if scored_path.exists() else []

    now = datetime.now().isoformat(timespec="seconds")
    css = ehr.CSS + "\n" + RUN_REPORT_CSS

    body = (
        render_header(telemetry, run_dir)
        + render_config(telemetry)
        + render_funnel(telemetry)
        + render_timing(telemetry)
        + render_leaderboard(scored, top_n)
        + render_breakdown(survivors, telemetry)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EyeSieve run report — {_html_escape(run_dir.name)}</title>
<style>{css}</style>
</head>
<body>
{body}
<footer class="footer">
  generated {_html_escape(now)} by eyesieve_run_report v{REPORT_VERSION}
</footer>
</body>
</html>
"""


# ===========================================================================
# CLI
# ===========================================================================

def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="EyeSieve HTML run report — phase 10")
    p.add_argument("--run-dir", required=True,
                   help="run output directory (must contain telemetry.json)")
    p.add_argument("--output", default=None,
                   help="output HTML path (default: <run-dir>/run_report.html)")
    p.add_argument("--top-n", type=int, default=25,
                   help="leaderboard size (default: 25)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    run_dir = Path(args.run_dir)
    if not run_dir.exists() or not run_dir.is_dir():
        print(f"{ERROR_PREFIX} :: run-dir not found: {run_dir}", file=sys.stderr)
        return 2

    out_path = (Path(args.output) if args.output
                else run_dir / "run_report.html")

    try:
        html_str = render_html(run_dir, top_n=args.top_n)
    except RunReportError as e:
        print(str(e), file=sys.stderr)
        return 2

    out_path.write_text(html_str)
    print(f"wrote {out_path} ({len(html_str):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
