"""eyesieve_scoring.py — phase 7: dictionary scoring wrapper around eyestat.

Wraps ``eyestat_scoring`` to score sieve survivors against Finnish, Karelian,
and English dictionaries with Hungarian-optimal rune→letter mappings.

DESIGN
======
- ``ScoringConfig`` declares the eyestat directory, target languages, and
  the Hungarian-perturbation count (``n_mappings``).
- ``Scorer`` constructs Dictionary objects from the available wordlists
  on init, then exposes ``score(candidate, alphabet_size)`` which runs the
  candidate through eyestat's ``score_decryption``.
- ``ScoringResult`` is a frozen dataclass aggregating per-language results.

The eyestat dependency is OPTIONAL at import time — ``Scorer.__init__``
raises ``ScoringError`` if eyestat isn't reachable, but the module itself
imports cleanly so the rest of EyeSieve (the runner, the sieve, the
selftest) can run with or without scoring.

LANGUAGE CODES
==============
eyestat's ``LANG_ALPHABETS`` uses:
  ``fi``   — Finnish (29 chars including å, ä, ö)
  ``krl``  — Karelian (28 chars, simplified)
  ``en``   — English (26 chars)

n_mappings TRADEOFF
===================
Higher values explore more perturbations of the Hungarian optimum:
  100   — fast, ~0.2s per candidate
  1000  — eyestat default, ~1-2s per candidate
For the typical sieve-survivor set (~266 candidates), 100 is reasonable
for an exploratory pass and 1000 for a finalist re-rank.
"""

from __future__ import annotations
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ERROR_PREFIX = "Internal Error Code: XD-MBYG04K-URS3LF"


# Candidate locations searched when no explicit eyestat_dir is provided.
# The first one containing an importable ``eyestat_scoring.py`` wins.
# Users can override the whole list by setting $EYESTAT_DIR.
_EYESTAT_SEARCH_PATHS: tuple[Path, ...] = (
    # Explicit env var takes priority
    Path(os.environ["EYESTAT_DIR"]) if os.environ.get("EYESTAT_DIR") else None,
    # Conventional locations relative to a typical Noita project layout
    Path.home() / "Desktop" / "Noita" / "eyestat",
    Path.home() / "Noita" / "eyestat",
    Path.home() / "eyestat",
    Path("/root/Desktop/Noita/eyestat"),       # legacy root-user path
    Path("/home/claude/eyestat_ref/eyestat"),  # dev path (kept for backwards compat)
    # Sibling of the eyesieve checkout itself
    Path(__file__).resolve().parent.parent / "eyestat",
    # Inside the eyesieve checkout (vendored)
    Path(__file__).resolve().parent / "eyestat",
)
_EYESTAT_SEARCH_PATHS = tuple(p for p in _EYESTAT_SEARCH_PATHS if p is not None)


def discover_eyestat_dir() -> Optional[Path]:
    """Walk the candidate paths, return the first one that contains an
    importable eyestat_scoring module. Returns None if none found."""
    for cand in _EYESTAT_SEARCH_PATHS:
        if (cand / "eyestat_scoring.py").is_file():
            return cand
    return None


# Default eyestat_dir = discovered path, or first candidate as a placeholder.
# Using the discovered value lets ScoringConfig() construct without args on
# a clean install.
EYESTAT_DIR_DEFAULT = discover_eyestat_dir() or _EYESTAT_SEARCH_PATHS[0]


class ScoringError(Exception):
    def __init__(self, msg: str):
        super().__init__(f"{ERROR_PREFIX} :: scoring :: {msg}")


def _ensure_eyestat_on_path(eyestat_dir: Path) -> None:
    """Add the eyestat directory to sys.path so eyestat_scoring is importable."""
    p = str(eyestat_dir)
    if p not in sys.path:
        sys.path.insert(0, p)


@dataclass(frozen=True)
class ScoringConfig:
    """Configuration for the phase-7 scorer."""
    eyestat_dir: Path = EYESTAT_DIR_DEFAULT
    languages: tuple[str, ...] = ('fi', 'krl', 'en')
    n_mappings: int = 100


@dataclass(frozen=True)
class LanguageScore:
    """Per-language scoring outcome for one candidate."""
    language: str
    hits: int
    zipf_score: float
    decrypted_text: str
    best_mapping_pairs: tuple[tuple[int, str], ...]  # tuple-of-pairs for hashability

    @property
    def best_mapping(self) -> dict[int, str]:
        return dict(self.best_mapping_pairs)


@dataclass(frozen=True)
class ScoringResult:
    """Aggregate scoring result across languages for one candidate."""
    per_language: tuple[LanguageScore, ...]

    @property
    def best_score(self) -> float:
        if not self.per_language:
            return 0.0
        return max(ls.zipf_score for ls in self.per_language)

    @property
    def best_language(self) -> str:
        if not self.per_language:
            return ""
        return max(self.per_language, key=lambda ls: ls.zipf_score).language

    @property
    def total_hits(self) -> int:
        return sum(ls.hits for ls in self.per_language)


# Default wordlist layout (relative to eyestat_dir)
_DEFAULT_DICT_LAYOUT = {
    'fi':  ('extra_words_fi.txt', 'noita_wordlist.txt'),
    'krl': ('extra_words_krl.txt',),
    'en':  ('eng-wordlist.txt',),
}


class Scorer:
    """Loads dictionaries on init; scores candidates via eyestat."""

    def __init__(self, config: Optional[ScoringConfig] = None) -> None:
        self.config = config or ScoringConfig()
        _ensure_eyestat_on_path(self.config.eyestat_dir)
        try:
            import eyestat_scoring as _es
        except ImportError as e:
            raise ScoringError(
                f"eyestat_scoring not importable from "
                f"{self.config.eyestat_dir}: {e}"
            )
        self._es = _es
        self.dictionaries = self._load_dictionaries()

    def _load_dictionaries(self) -> dict:
        dicts = {}
        for lang in self.config.languages:
            layout = _DEFAULT_DICT_LAYOUT.get(lang)
            if layout is None:
                raise ScoringError(
                    f"no default dictionary layout for language {lang!r}"
                )
            d = self._es.Dictionary(lang)
            loaded_any = False
            for filename in layout:
                p = self.config.eyestat_dir / filename
                if p.exists():
                    d.load(p)
                    loaded_any = True
            if not loaded_any:
                raise ScoringError(
                    f"no dictionary files found for language {lang!r} "
                    f"under {self.config.eyestat_dir}"
                )
            dicts[lang] = d
        return dicts

    def score(self, candidate, alphabet_size: int = 83) -> ScoringResult:
        """Score one candidate via eyestat.score_decryption."""
        if not candidate:
            raise ScoringError("score: empty candidate")
        raw = self._es.score_decryption(
            decrypted_symbols=list(candidate),
            alphabet_size=alphabet_size,
            dictionaries=self.dictionaries,
            n_mappings=self.config.n_mappings,
        )
        per_lang = tuple(
            LanguageScore(
                language=lang,
                hits=raw[lang]['hits'],
                zipf_score=raw[lang]['zipf_score'],
                decrypted_text=raw[lang]['decrypted_text'] or "",
                best_mapping_pairs=tuple(
                    sorted((raw[lang]['best_mapping'] or {}).items())
                ),
            )
            for lang in self.config.languages
            if lang in raw
        )
        return ScoringResult(per_language=per_lang)


def is_eyestat_available(eyestat_dir: Path = EYESTAT_DIR_DEFAULT) -> bool:
    """Return True if eyestat_scoring can be imported from ``eyestat_dir``."""
    _ensure_eyestat_on_path(eyestat_dir)
    try:
        import eyestat_scoring  # noqa: F401
        return True
    except ImportError:
        return False
