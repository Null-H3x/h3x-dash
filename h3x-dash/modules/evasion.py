"""
evasion.py — Stealth profiles for scan, enum, and exploit phases.

Wraps existing legitimate evasion features:
  - Nmap evasion flags (timing, fragmentation, decoys, source-port) — built into
    nmap since 1997, no novel capability added here
  - Metasploit's built-in encoders (shikata_ga_nai etc.) and stage encoding —
    standard MSF facilities, just exposed through the H3x-Dash UI
  - Per-tool delay/rate controls for enum runners

What this is NOT:
  - Custom AV/EDR bypass scripts
  - Anti-forensics or log tampering
  - Novel evasion techniques beyond mature open-source tools

Stealth levels cascade across phases — set once, applies everywhere:
  0  Normal   — fast and noisy. Default for lab work where IDS isn't relevant.
  1  Quiet    — reduced rate, modest stealth. Skips obvious IDS signatures.
  2  Stealth  — fragmented, slow timing, encoded payloads. Defeats most IDS.
  3  Paranoid — decoys, source-port spoof, max fragmentation, heavy encoding.
                Engagement-grade. Single scan may take hours.

Public API:
  get_level()                -> int (0–3)
  set_level(int)             -> int (clamps to valid range)
  nmap_flags_for(level)      -> list[str]
  msf_options_for(level)     -> dict
  enum_delay_ms_for(level)   -> int
  level_profile(level)       -> dict (full profile for UI)
  all_profiles()             -> list[dict] (all 4 levels for UI dropdown)
"""

from __future__ import annotations
import threading

# Levels 0–3, ordered from noisy to paranoid. The dict-of-dicts keeps the
# entire profile in one place so audit + UI + execution all reference the
# same source of truth.
STEALTH_LEVELS: dict[int, dict] = {
    0: {
        'name':        'Normal',
        'icon':        '⚡',
        'description': 'No evasion. Fast scans, default payloads, no delays. '
                       'Default for lab and authorized internal work.',
        'nmap_flags':                [],
        'msf_encoder':               None,
        'msf_encoder_iter':          0,
        'msf_stage_encoding':        False,
        'msf_stage_encoding_fallback': False,
        'enum_delay_ms':             0,
        'enum_max_rate':             None,
        'estimated_slowdown':        '1×',
    },
    1: {
        'name':        'Quiet',
        'icon':        '◇',
        'description': 'Reduced rate, T2 timing. Avoids triggering rate-based '
                       'detections. Suitable for shared corporate networks where '
                       'you don\'t want to spike port-scan alerts.',
        'nmap_flags':                ['-T2', '--max-rate', '100'],
        'msf_encoder':               None,
        'msf_encoder_iter':          0,
        'msf_stage_encoding':        False,
        'msf_stage_encoding_fallback': False,
        'enum_delay_ms':             200,
        'enum_max_rate':             50,
        'estimated_slowdown':        '~3×',
    },
    2: {
        'name':        'Stealth',
        'icon':        '◈',
        'description': 'Fragmented packets, T1 timing, length-randomized probes, '
                       'shikata_ga_nai-encoded payloads with stage encoding. '
                       'Defeats most IDS signatures (Snort default rules, basic '
                       'Suricata profiles).',
        'nmap_flags':                ['-T1', '-f', '--data-length', '24',
                                       '--randomize-hosts', '--max-rate', '50'],
        'msf_encoder':               'x86/shikata_ga_nai',
        'msf_encoder_iter':          3,
        'msf_stage_encoding':        True,
        'msf_stage_encoding_fallback': False,
        'enum_delay_ms':             500,
        'enum_max_rate':             20,
        'estimated_slowdown':        '~10×',
    },
    3: {
        'name':        'Paranoid',
        'icon':        '◉',
        'description': 'Maximum nmap evasion: T0 timing, decoy hosts, '
                       'source-port spoofing (DNS:53), heavy fragmentation. '
                       'Heavy MSF stage encoding with fallback chain. Built '
                       'for engagement work against tuned detection stacks. '
                       'A /24 sweep at this level can take hours.',
        'nmap_flags':                ['-T0', '-f', '-D', 'RND:10',
                                       '--data-length', '24',
                                       '--source-port', '53',
                                       '--randomize-hosts', '--max-rate', '10'],
        'msf_encoder':               'x86/shikata_ga_nai',
        'msf_encoder_iter':          5,
        'msf_stage_encoding':        True,
        'msf_stage_encoding_fallback': True,
        'enum_delay_ms':             1000,
        'enum_max_rate':             10,
        'estimated_slowdown':        '~60×+ (engagement-grade)',
    },
}

# ── Runtime state ─────────────────────────────────────────────────────────────
# Stealth level is a process-global setting. Threadsafe via lock so concurrent
# scan/exploit requests see a consistent value.

_lock           = threading.RLock()
_current_level  = 0


def get_level() -> int:
    """Return the current stealth level (0–3)."""
    with _lock:
        return _current_level


def set_level(level) -> int:
    """Set stealth level, clamping to valid range. Returns the new value."""
    global _current_level
    try:
        level = int(level)
    except (TypeError, ValueError):
        level = 0
    if level < 0:
        level = 0
    if level > 3:
        level = 3
    with _lock:
        _current_level = level
    return level


# ── Flag/option generators ────────────────────────────────────────────────────

def nmap_flags_for(level: int = None) -> list[str]:
    """Return a *copy* of nmap CLI flags for this stealth level."""
    if level is None:
        level = get_level()
    return list(STEALTH_LEVELS.get(level, STEALTH_LEVELS[0])['nmap_flags'])


def msf_options_for(level: int = None) -> dict:
    """
    Return MSF datastore options to inject when running an exploit.

    Keys map directly to Metasploit option names — the runner sets them via
    `set <KEY> <VALUE>` on the console.
    """
    if level is None:
        level = get_level()
    cfg = STEALTH_LEVELS.get(level, STEALTH_LEVELS[0])
    opts: dict = {}
    if cfg.get('msf_encoder'):
        opts['ENCODER']    = cfg['msf_encoder']
        opts['EncoderItr'] = cfg.get('msf_encoder_iter', 1)
    if cfg.get('msf_stage_encoding'):
        opts['EnableStageEncoding'] = True
    if cfg.get('msf_stage_encoding_fallback'):
        opts['StageEncodingFallbacks'] = True
    return opts


def enum_delay_ms_for(level: int = None) -> int:
    """Per-request delay (milliseconds) for enum tools that support it."""
    if level is None:
        level = get_level()
    return STEALTH_LEVELS.get(level, STEALTH_LEVELS[0])['enum_delay_ms']


def enum_max_rate_for(level: int = None) -> int | None:
    """Max requests/sec for enum tools that support rate limiting."""
    if level is None:
        level = get_level()
    return STEALTH_LEVELS.get(level, STEALTH_LEVELS[0])['enum_max_rate']


# ── UI helpers ────────────────────────────────────────────────────────────────

def level_profile(level: int = None) -> dict:
    """Full profile dict for one level (for UI rendering)."""
    if level is None:
        level = get_level()
    profile = dict(STEALTH_LEVELS.get(level, STEALTH_LEVELS[0]))
    profile['level'] = level
    return profile


def all_profiles() -> list[dict]:
    """All 4 profiles in order, for UI dropdowns."""
    return [{'level': lv, **dict(profile)}
            for lv, profile in sorted(STEALTH_LEVELS.items())]
