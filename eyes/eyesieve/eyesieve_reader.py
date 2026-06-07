#!/usr/bin/env python3
"""eyesieve_reader.py — content reader and visual explorer for the corpus.

While ``eyesieve_corpus.py`` provides the structural summary (lengths,
universal positions, prefix groups), this module renders the actual rune
content in formats designed for hypothesis exploration by eye.

VIEW MODES (pick one per invocation)
====================================
  --show CODE [CODE ...]   one or more messages, full rune sequence
  --grid                   all 9 messages aligned by position (the killer view)
  --column N               one column across all 9 messages
  --columns LO:HI          range of columns across all 9 messages
  --prefix N               alias for --columns 0:N with header emphasis
  --diff A B               position-by-position diff of two messages
  --all                    runs grid + prefix + every diff in one report

DISPLAY FORMATS
===============
  --format decimal         "50 66  5 48 62 ..." — default, unambiguous
  --format hex             "32 42 05 30 3e ..." — compact, two-char fixed width
  --format glyph           "P%5Mt..." — single-char glyph per rune (83 distinct)
  --freq-color             color each rune by its corpus-wide frequency

HIGHLIGHTS (on by default; --no-highlights to disable)
====================================================
  Universal positions     — bright cyan + bold (positions 1, 2 in this corpus)
  3-group members         — magenta cells (the {E1,W1,E2} cluster)
  6-group / 4-group       — yellow cells (the larger structural group)

USAGE
=====
    ./eyesieve_reader.py --grid
    ./eyesieve_reader.py --show E1 E2 --format glyph
    ./eyesieve_reader.py --columns 0:20 --freq-color
    ./eyesieve_reader.py --diff E1 W1
    ./eyesieve_reader.py --all --format glyph > report.txt
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import eyesieve_corpus as ec

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"


# ---------------------------------------------------------------------------
# Glyph mapping: 83 distinct single-character glyphs covering the rune set
# ---------------------------------------------------------------------------
# Layout:
#   indices  0-9   -> '0'-'9'        (10 digits)
#   indices 10-35  -> 'A'-'Z'        (26 uppercase)
#   indices 36-61  -> 'a'-'z'        (26 lowercase)
#   indices 62-82  -> 21 punctuation chars, chosen to be unambiguous in
#                    monospace and free of shell-escape headaches

GLYPHS: str = (
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "!@#$%&*+-=<>?.,:;~^|/"
)
assert len(GLYPHS) == 83, f"GLYPHS length {len(GLYPHS)} != 83"


# ---------------------------------------------------------------------------
# Color handling — matches eyestat / eyesieve aesthetic
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _ansi(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def green(s: str) -> str:   return _ansi("92", s)
def red(s: str) -> str:     return _ansi("91", s)
def yellow(s: str) -> str:  return _ansi("93", s)
def cyan(s: str) -> str:    return _ansi("96", s)
def magenta(s: str) -> str: return _ansi("95", s)
def blue(s: str) -> str:    return _ansi("94", s)
def white(s: str) -> str:   return _ansi("97", s)
def dim(s: str) -> str:     return _ansi("90", s)
def bold(s: str) -> str:    return _ansi("1", s)


def _256color(code: int, s: str) -> str:
    """256-color foreground; ``code`` in [0, 255]."""
    return f"\033[38;5;{code}m{s}\033[0m" if USE_COLOR else s


# ---------------------------------------------------------------------------
# Frequency analysis + frequency-based coloring
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FrequencyMap:
    """Maps each rune (0..82) to a percentile rank in the corpus.

    rank 0   = most-frequent rune
    rank 82  = least-frequent (or unused) rune
    """
    rank: tuple[int, ...]          # rank[rune_value] = percentile rank
    counts: tuple[int, ...]        # counts[rune_value] = raw count

    @classmethod
    def from_corpus(cls, corpus: ec.Corpus) -> "FrequencyMap":
        usage = ec.alphabet_usage(corpus)
        counts = [usage.get(r, 0) for r in range(corpus.deck_size)]
        # Sort runes by descending count; ties broken by rune value (stable)
        order = sorted(range(corpus.deck_size),
                       key=lambda r: (-counts[r], r))
        rank = [0] * corpus.deck_size
        for r, rune in enumerate(order):
            rank[rune] = r
        return cls(rank=tuple(rank), counts=tuple(counts))

    def color_code(self, rune: int) -> int:
        """Map a rune to a 256-color palette index based on frequency rank.

        Uses the 6x6x6 color cube (indices 16-231) for a smooth gradient:
        bright reds/oranges for high-frequency, cools/blues for low.
        """
        n = len(self.rank)
        # Normalize rank to [0.0, 1.0]
        t = self.rank[rune] / max(n - 1, 1)
        # Build (r, g, b) each in [0, 5] across the gradient
        # Hot end (t=0): bright red-orange (5, 2, 0)
        # Mid (t=0.5):   yellow-green (4, 5, 1)
        # Cold end (t=1): cyan-blue (0, 3, 5)
        if t < 0.5:
            u = t * 2.0
            r = round(5 - u * 1)        # 5 -> 4
            g = round(2 + u * 3)        # 2 -> 5
            b = round(0 + u * 1)        # 0 -> 1
        else:
            u = (t - 0.5) * 2.0
            r = round(4 - u * 4)        # 4 -> 0
            g = round(5 - u * 2)        # 5 -> 3
            b = round(1 + u * 4)        # 1 -> 5
        r = max(0, min(5, r))
        g = max(0, min(5, g))
        b = max(0, min(5, b))
        return 16 + 36 * r + 6 * g + b


# ---------------------------------------------------------------------------
# Highlighting — universal positions and prefix groups
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HighlightMap:
    """Per-(message, position) coloring instructions for structural emphasis."""
    universal_positions: frozenset[int]
    # position -> {message_code: group_size}
    group_membership: dict[int, dict[str, int]]

    @classmethod
    def from_corpus(cls, corpus: ec.Corpus,
                    max_position: int = 32) -> "HighlightMap":
        univ = frozenset(p for p, _ in ec.universal_positions(corpus))
        membership: dict[int, dict[str, int]] = {}
        groups = ec.shared_prefix_groups(
            corpus, max_position=max_position, min_group_size=2,
        )
        for g in groups:
            pos_map = membership.setdefault(g.position, {})
            for code in g.members:
                pos_map[code] = len(g.members)
        return cls(universal_positions=univ, group_membership=membership)

    def cell_color(self, code: str, position: int) -> str | None:
        """Return an ANSI color code for the cell, or None for default."""
        if position in self.universal_positions:
            return "96;1"          # bright cyan, bold
        pos_groups = self.group_membership.get(position, {})
        group_size = pos_groups.get(code, 0)
        if group_size == 0:
            return None
        # 3-group is the (E1, W1, E2) cluster → magenta
        if group_size == 3:
            return "95"
        # 4-group (E3, E4, W4, E5 in later positions) → bright yellow
        if group_size == 4:
            return "93"
        # 6-group → yellow (dimmer than the 4-group for visual distinction)
        if group_size == 6:
            return "33"
        # Other group sizes
        return "94"  # blue


# ---------------------------------------------------------------------------
# Symbol formatting primitives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FormatConfig:
    """Display configuration for a single render call."""
    fmt: str                       # "decimal" | "hex" | "glyph"
    freq_color: bool               # color by corpus-wide frequency
    highlights: bool               # universal-position + group highlighting
    show_positions: bool           # render position-index header rows

    @property
    def cell_width(self) -> int:
        """Number of visible characters per rendered symbol (excluding sep)."""
        if self.fmt == "decimal":
            return 2
        if self.fmt == "hex":
            return 2
        if self.fmt == "glyph":
            return 1
        raise ValueError(f"unknown format: {self.fmt}")


def render_symbol(value: int, cfg: FormatConfig,
                  freq: FrequencyMap | None = None,
                  highlight_color: str | None = None,
                  width: int | None = None) -> str:
    """Render a single rune value as a colored, fixed-width string.

    ``width`` is the visible character width (excluding ANSI escapes). When
    None, falls back to the format's intrinsic minimum width.
    """
    if cfg.fmt == "decimal":
        w = max(width if width is not None else 2, 2)
        plain = f"{value:>{w}d}"
    elif cfg.fmt == "hex":
        w = max(width if width is not None else 2, 2)
        plain = f"{value:>{w}x}"
    elif cfg.fmt == "glyph":
        w = max(width if width is not None else 1, 1)
        plain = f"{GLYPHS[value]:>{w}}"
    else:
        raise ValueError(f"unknown format: {cfg.fmt}")

    if not USE_COLOR:
        return plain

    # Highlight wins over frequency coloring when both apply
    if cfg.highlights and highlight_color:
        return f"\033[{highlight_color}m{plain}\033[0m"

    if cfg.freq_color and freq is not None:
        return _256color(freq.color_code(value), plain)

    return plain


def render_blank(cfg: FormatConfig, width: int | None = None) -> str:
    """A blank cell of the requested visible width."""
    if width is not None:
        return " " * max(width, 1)
    return " " * cfg.cell_width


# ---------------------------------------------------------------------------
# Label helpers — consistent visible width regardless of ANSI escapes
# ---------------------------------------------------------------------------

LABEL_WIDTH = 9   # visible width for the row label column


def _label(code: str) -> str:
    """Format a message code as a fixed visible-width row label.

    ANSI escape sequences don't count toward Python's format-width padding,
    so we pad explicitly with spaces around the colored portion.
    """
    pad = max(LABEL_WIDTH - 2 - len(code), 0)
    return "  " + bold(code) + " " * pad


def _label_blank() -> str:
    return " " * LABEL_WIDTH


def _position_cell_width(positions: Iterable[int], cfg: FormatConfig) -> int:
    """Cell width that fits both the largest position number and the symbol."""
    max_pos = max(positions, default=0)
    pos_digits = max(len(str(max_pos)), 1)
    return max(cfg.cell_width, pos_digits)


def _format_position_header(positions: list[int], cell_w: int,
                            highlights: HighlightMap,
                            cfg: FormatConfig) -> str:
    """Format a row of position-index headers, optionally highlighting
    universal positions."""
    parts = [_label_blank()]
    for pos in positions:
        text = f"{pos:>{cell_w}d}"
        if cfg.highlights and pos in highlights.universal_positions:
            parts.append(bold(cyan(text)))
        else:
            parts.append(dim(text))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# View: --show
# ---------------------------------------------------------------------------

def view_show(corpus: ec.Corpus, codes: list[str], cfg: FormatConfig,
              freq: FrequencyMap | None,
              highlights: HighlightMap,
              term_width: int) -> str:
    """Render one or more full messages, line-wrapped to terminal width."""
    out: list[str] = []
    max_pos_global = max(corpus.lengths) - 1
    pos_digits = len(str(max_pos_global))
    cell_w = max(cfg.cell_width, pos_digits)

    avail = max(term_width - LABEL_WIDTH, 20)
    per_chunk = max(avail // (cell_w + 1), 1)

    for code in codes:
        try:
            ct = corpus.by_short(code)
        except ec.CorpusError as e:
            out.append(f"{red('[ERROR]')} {e}")
            continue
        label = corpus.short_to_label(code)
        out.append("")
        out.append(bold(cyan(
            f"== {code}  ({label})   length={len(ct)} =="
        )))

        for chunk_start in range(0, len(ct), per_chunk):
            chunk_end = min(chunk_start + per_chunk, len(ct))
            positions = list(range(chunk_start, chunk_end))
            if cfg.show_positions:
                out.append(_format_position_header(
                    positions, cell_w, highlights, cfg
                ))
            row_parts = [_label(code)]
            for pos in positions:
                hl = (highlights.cell_color(code, pos)
                      if cfg.highlights else None)
                row_parts.append(render_symbol(ct[pos], cfg, freq, hl, cell_w))
            out.append(" ".join(row_parts))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# View: --grid (all 9 messages aligned by position)
# ---------------------------------------------------------------------------

def view_grid(corpus: ec.Corpus, cfg: FormatConfig,
              freq: FrequencyMap | None,
              highlights: HighlightMap,
              term_width: int,
              position_range: tuple[int, int] | None = None) -> str:
    """All 9 messages aligned by position. Wraps to terminal width."""
    out: list[str] = []
    lo, hi = ((0, max(corpus.lengths)) if position_range is None
              else position_range)
    hi = min(hi, max(corpus.lengths))

    max_pos = hi - 1
    pos_digits = max(len(str(max_pos)), 1)
    cell_w = max(cfg.cell_width, pos_digits)

    avail = max(term_width - LABEL_WIDTH, 20)
    per_chunk = max(avail // (cell_w + 1), 1)

    out.append(bold(cyan(
        f"== Aligned grid, positions {lo}..{hi - 1} ({hi - lo} total) =="
    )))
    out.append("")

    for chunk_start in range(lo, hi, per_chunk):
        chunk_end = min(chunk_start + per_chunk, hi)
        positions = list(range(chunk_start, chunk_end))
        if cfg.show_positions:
            out.append(_format_position_header(
                positions, cell_w, highlights, cfg
            ))
        for code, ct in zip(corpus.short_codes, corpus.ciphertexts):
            row_parts = [_label(code)]
            for pos in positions:
                if pos < len(ct):
                    hl = (highlights.cell_color(code, pos)
                          if cfg.highlights else None)
                    row_parts.append(
                        render_symbol(ct[pos], cfg, freq, hl, cell_w)
                    )
                else:
                    row_parts.append(render_blank(cfg, cell_w))
            out.append(" ".join(row_parts))
        out.append("")
    return "\n".join(out).rstrip()


# ---------------------------------------------------------------------------
# View: --column / --columns
# ---------------------------------------------------------------------------

def view_columns(corpus: ec.Corpus, lo: int, hi: int,
                 cfg: FormatConfig,
                 freq: FrequencyMap | None,
                 highlights: HighlightMap,
                 term_width: int) -> str:
    """A slice [lo, hi) of positions across all 9 messages — same as grid
    but constrained to a range and with always-on position headers."""
    cfg2 = FormatConfig(fmt=cfg.fmt, freq_color=cfg.freq_color,
                        highlights=cfg.highlights, show_positions=True)
    out: list[str] = []
    out.append(bold(cyan(
        f"== Column slice {lo}..{hi - 1} ({hi - lo} positions) =="
    )))
    out.append("")

    # Re-use the grid renderer; suppress its own banner
    grid_body = view_grid(corpus, cfg2, freq, highlights, term_width,
                          position_range=(lo, hi))
    # The grid renderer adds its own banner; strip the first two lines
    body_lines = grid_body.splitlines()
    if body_lines and body_lines[0].lstrip().startswith("=="):
        body_lines = body_lines[2:]
    out.extend(body_lines)

    # Per-position commentary — derived directly from shared_prefix_groups
    # so distinct groups of the same size at the same position are not
    # accidentally merged.
    out.append("")
    out.append(bold(dim("─" * 56)))
    out.append(bold("Per-position structural notes:"))
    all_groups = ec.shared_prefix_groups(corpus, max_position=hi,
                                         min_group_size=2)
    for pos in range(lo, hi):
        notes: list[str] = []
        if pos in highlights.universal_positions:
            sym = corpus.ciphertexts[0][pos]
            notes.append(cyan(f"universal (all 9 share sym={sym})"))
        pos_groups = [g for g in all_groups
                      if g.position == pos and len(g.members) < corpus.num_messages]
        # Sort by size descending so the larger group reads first
        pos_groups.sort(key=lambda g: -len(g.members))
        for g in pos_groups:
            size = len(g.members)
            color = {3: magenta, 4: yellow, 6: yellow}.get(size, blue)
            notes.append(color(
                f"{size}-group {{{','.join(g.members)}}} (sym={g.symbol})"
            ))
        if notes:
            out.append(f"  pos {pos:>3}: " + ", ".join(notes))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# View: --diff (position-by-position pairwise diff)
# ---------------------------------------------------------------------------

def view_diff(corpus: ec.Corpus, code_a: str, code_b: str,
              cfg: FormatConfig,
              freq: FrequencyMap | None,
              highlights: HighlightMap) -> str:
    """Position-by-position diff with summary stats."""
    try:
        a = corpus.by_short(code_a)
        b = corpus.by_short(code_b)
    except ec.CorpusError as e:
        return f"{red('[ERROR]')} {e}"

    out: list[str] = []
    out.append(bold(cyan(
        f"== Diff: {code_a} ({len(a)}) vs {code_b} ({len(b)}) =="
    )))
    out.append("")

    compare_len = min(len(a), len(b))
    pos_digits = max(len(str(max(len(a), len(b)) - 1)), 1)
    cell_w = max(cfg.cell_width, pos_digits)

    matches = 0
    longest_run = 0
    current_run = 0
    run_start: int | None = None
    longest_run_span: tuple[int, int] | None = None

    # Header row
    out.append(f"  {bold('pos'):>{pos_digits + 3}}  "
               f"{bold(code_a):>{cell_w + 4}}  "
               f"{bold(code_b):>{cell_w + 4}}   match")
    out.append("  " + dim("─" * (pos_digits + cell_w * 2 + 22)))

    for i in range(compare_len):
        va, vb = a[i], b[i]
        match = (va == vb)
        if match:
            matches += 1
            if current_run == 0:
                run_start = i
            current_run += 1
            if current_run > longest_run:
                longest_run = current_run
                longest_run_span = (run_start or 0, i)
        else:
            current_run = 0

        hl_a = highlights.cell_color(code_a, i) if cfg.highlights else None
        hl_b = highlights.cell_color(code_b, i) if cfg.highlights else None
        sa = render_symbol(va, cfg, freq, hl_a, cell_w)
        sb = render_symbol(vb, cfg, freq, hl_b, cell_w)
        marker = green("✓") if match else red("✗")
        out.append(f"  {i:>{pos_digits + 3}d}  {sa:>{cell_w + 4}}  "
                   f"{sb:>{cell_w + 4}}    {marker}")

    if len(a) != len(b):
        out.append("  " + dim("─" * (pos_digits + cell_w * 2 + 22)))
        if len(a) > compare_len:
            out.append(f"  {code_a} has {len(a) - compare_len} extra symbols "
                       f"beyond the shared length")
        if len(b) > compare_len:
            out.append(f"  {code_b} has {len(b) - compare_len} extra symbols "
                       f"beyond the shared length")

    # Summary
    out.append("")
    out.append(bold(dim("─" * 56)))
    out.append(bold("Summary:"))
    out.append(f"  shared length      : {compare_len}")
    pct = 100.0 * matches / max(compare_len, 1)
    out.append(f"  matches            : {matches} ({pct:.1f}%)")
    out.append(f"  mismatches         : {compare_len - matches} "
               f"({100.0 - pct:.1f}%)")
    if longest_run > 0 and longest_run_span:
        out.append(f"  longest match run  : {longest_run} "
                   f"(positions {longest_run_span[0]}-{longest_run_span[1]})")
    else:
        out.append(f"  longest match run  : 0")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# View: --prefix (alias for --columns 0:N with extra emphasis)
# ---------------------------------------------------------------------------

def view_prefix(corpus: ec.Corpus, n: int, cfg: FormatConfig,
                freq: FrequencyMap | None,
                highlights: HighlightMap,
                term_width: int) -> str:
    return view_columns(corpus, 0, n, cfg, freq, highlights, term_width)


# ---------------------------------------------------------------------------
# View: --all (comprehensive report)
# ---------------------------------------------------------------------------

def view_all(corpus: ec.Corpus, cfg: FormatConfig,
             freq: FrequencyMap | None,
             highlights: HighlightMap,
             term_width: int) -> str:
    out: list[str] = []
    out.append(bold(cyan("═" * 64)))
    out.append(bold(cyan("EyeSieve corpus — comprehensive content report")))
    out.append(bold(cyan("═" * 64)))
    out.append("")
    out.append(view_grid(corpus, cfg, freq, highlights, term_width))
    out.append("")
    out.append(bold(cyan("═" * 64)))
    out.append(bold(cyan("Prefix (positions 0-15) with structural notes")))
    out.append(bold(cyan("═" * 64)))
    out.append(view_prefix(corpus, 16, cfg, freq, highlights, term_width))
    out.append("")
    out.append(bold(cyan("═" * 64)))
    out.append(bold(cyan("Pairwise diffs (4 east-west pairs)")))
    out.append(bold(cyan("═" * 64)))
    for i in range(1, 5):
        out.append(view_diff(corpus, f"E{i}", f"W{i}", cfg, freq, highlights))
        out.append("")
    out.append(bold(cyan("═" * 64)))
    out.append(bold(cyan("Per-message rune frequency distribution")))
    out.append(bold(cyan("═" * 64)))
    out.append(view_frequencies(corpus, freq))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Auxiliary: frequency table
# ---------------------------------------------------------------------------

def view_frequencies(corpus: ec.Corpus,
                     freq: FrequencyMap | None) -> str:
    """Per-rune frequency table, sorted descending by count."""
    if freq is None:
        freq = FrequencyMap.from_corpus(corpus)
    out: list[str] = []
    out.append("")
    out.append(f"  {bold('rank'):>5}  {bold('rune'):>5}  "
               f"{bold('glyph'):>6}  {bold('count'):>6}  {bold('%'):>5}")
    out.append("  " + dim("─" * 50))
    total = sum(freq.counts)
    sorted_runes = sorted(range(len(freq.counts)),
                          key=lambda r: (-freq.counts[r], r))
    for rank, rune in enumerate(sorted_runes):
        cnt = freq.counts[rune]
        if cnt == 0:
            continue
        pct = 100.0 * cnt / total
        color_code = freq.color_code(rune)
        glyph = _256color(color_code, GLYPHS[rune])
        out.append(f"  {rank:>5}  {rune:>5}  {glyph:>6}  "
                   f"{cnt:>6}  {pct:>5.2f}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_range(s: str) -> tuple[int, int]:
    """Parse 'LO:HI' into (lo, hi); HI is exclusive."""
    if ":" not in s:
        raise argparse.ArgumentTypeError(
            f"range must be LO:HI, got {s!r}"
        )
    lo_s, hi_s = s.split(":", 1)
    try:
        lo, hi = int(lo_s), int(hi_s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"range bounds must be integers, got {s!r}"
        )
    if lo < 0 or hi < lo:
        raise argparse.ArgumentTypeError(
            f"range {s!r} must satisfy 0 <= LO <= HI"
        )
    return lo, hi


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Content reader for the EyeSieve corpus.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Exactly one view mode must be selected: --show / --grid / "
                "--column / --columns / --prefix / --diff / --all."),
    )
    parser.add_argument("--data", default="noita_eye_data.json",
                        help="Path to the corpus JSON (default: %(default)s)")

    modes = parser.add_argument_group("view modes (pick one)")
    modes.add_argument("--show", nargs="+", metavar="CODE",
                       help="Render one or more messages by short code")
    modes.add_argument("--grid", action="store_true",
                       help="All 9 messages aligned by position")
    modes.add_argument("--column", type=int, metavar="N",
                       help="One column across all 9 messages")
    modes.add_argument("--columns", type=_parse_range, metavar="LO:HI",
                       help="Range of positions across all 9 messages")
    modes.add_argument("--prefix", type=int, metavar="N",
                       help="First N positions across all 9 messages")
    modes.add_argument("--diff", nargs=2, metavar=("A", "B"),
                       help="Position-by-position diff of two messages")
    modes.add_argument("--all", action="store_true", dest="all_view",
                       help="Comprehensive report: grid + prefix + diffs + "
                            "frequencies")

    fmts = parser.add_argument_group("display formatting")
    fmts.add_argument("--format", choices=("decimal", "hex", "glyph"),
                      default="decimal",
                      help="Symbol display format (default: %(default)s)")
    fmts.add_argument("--freq-color", action="store_true",
                      help="Color each rune by its corpus-wide frequency rank")
    fmts.add_argument("--no-highlights", action="store_true",
                      help="Disable universal-position and group highlights")
    fmts.add_argument("--no-positions", action="store_true",
                      help="Suppress position-index headers")
    fmts.add_argument("--no-color", action="store_true",
                      help="Disable all ANSI color output")
    fmts.add_argument("--width", type=int, default=None,
                      help="Override terminal width (default: auto-detect)")

    args = parser.parse_args(argv)

    if args.no_color:
        global USE_COLOR
        USE_COLOR = False

    # Determine which mode is selected (mutually exclusive but argparse can't
    # enforce that cleanly for this mix of arg types).
    mode_count = sum([
        bool(args.show),
        bool(args.grid),
        args.column is not None,
        args.columns is not None,
        args.prefix is not None,
        bool(args.diff),
        bool(args.all_view),
    ])
    if mode_count == 0:
        parser.error("a view mode is required (--show / --grid / --column / "
                     "--columns / --prefix / --diff / --all)")
    if mode_count > 1:
        parser.error("only one view mode may be selected per invocation")

    # Load corpus
    try:
        corpus = ec.load_corpus(args.data)
    except ec.CorpusError as e:
        print(red(str(e)), file=sys.stderr)
        return 2

    freq = FrequencyMap.from_corpus(corpus)
    highlights = HighlightMap.from_corpus(corpus, max_position=32)
    term_width = args.width or shutil.get_terminal_size((100, 24)).columns

    cfg = FormatConfig(
        fmt=args.format,
        freq_color=args.freq_color,
        highlights=not args.no_highlights,
        show_positions=not args.no_positions,
    )

    # Dispatch
    try:
        if args.show:
            output = view_show(corpus, args.show, cfg, freq, highlights,
                               term_width)
        elif args.grid:
            output = view_grid(corpus, cfg, freq, highlights, term_width)
        elif args.column is not None:
            output = view_columns(corpus, args.column, args.column + 1,
                                  cfg, freq, highlights, term_width)
        elif args.columns is not None:
            lo, hi = args.columns
            output = view_columns(corpus, lo, hi, cfg, freq, highlights,
                                  term_width)
        elif args.prefix is not None:
            output = view_prefix(corpus, args.prefix, cfg, freq, highlights,
                                 term_width)
        elif args.diff:
            output = view_diff(corpus, args.diff[0], args.diff[1],
                               cfg, freq, highlights)
        elif args.all_view:
            output = view_all(corpus, cfg, freq, highlights, term_width)
        else:
            # Shouldn't reach — mode_count check above guards this.
            return 2
    except ec.CorpusError as e:
        print(red(str(e)), file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(red(f"{ERROR_PREFIX} :: reader :: "
                  f"{type(e).__name__}: {e}"), file=sys.stderr)
        return 2

    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
