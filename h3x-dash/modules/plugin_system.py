"""
plugin_system.py — Discovery and registration for plugin-defined enum tools.

A plugin lets a contributor add a new enumeration tool without editing
enum_engine.py, install.py, or any of the dispatch tables. Drop a Python
file in plugins/, define a Plugin subclass, restart H3x-Dash.

Plugin contract:
  - subclass Plugin
  - set class attrs: tool_id, label, tier, ports (or services), package, binary
  - implement run(self, ip, ctx, emit, finding, params)
    matches the same signature as EnumEngine._run_<tool> methods

The loader:
  - imports every plugins/*.py module
  - finds Plugin subclasses
  - validates the contract
  - returns a dict tool_id -> Plugin instance

The registrar:
  - extends enum_engine.TOOL_LABELS / TOOL_TIERS / PORT_TOOLS / SERVICE_TOOLS
  - binds plugin.run as EnumEngine._run_<tool_id> at runtime
  - existing built-in tools are untouched
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

TIER_RECON, TIER_STANDARD, TIER_DEEP = 1, 2, 3


class Plugin:
    """
    Base class for enum tool plugins. Subclasses set class attributes and
    implement run(). See plugins/README.md for the full contract.
    """
    tool_id:  str       = ''
    label:    str       = ''
    tier:     int       = TIER_STANDARD
    ports:    list[int] = []
    services: list[str] = []
    package:  str       = ''   # apt package name (for install.py / UI hint)
    binary:   str       = ''   # binary name for shutil.which() check; '' if pure-Python

    def run(self, ip: str, ctx: dict, emit, finding, params: dict) -> None:
        """
        Execute the tool against `ip` with port/service context `ctx`.

        Args mirror EnumEngine._run_* methods exactly:
          ip:       target IP (already validated)
          ctx:      {'port': int, 'service': str, 'version': str}
          emit:     callable(str) — log line to operator
          finding:  callable(dict) — submit a finding dict
          params:   request params (currently unused by most runners)
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement run()")

    @classmethod
    def validate(cls) -> list[str]:
        """Return a list of validation errors, or [] if the contract holds."""
        errs = []
        if not cls.tool_id or not isinstance(cls.tool_id, str):
            errs.append("tool_id must be a non-empty string")
        elif not cls.tool_id.replace('_', '').isalnum():
            errs.append(f"tool_id must be alphanumeric/underscore "
                        f"(got {cls.tool_id!r})")
        if not cls.label:
            errs.append("label must be non-empty")
        if cls.tier not in (TIER_RECON, TIER_STANDARD, TIER_DEEP):
            errs.append(f"tier must be 1, 2, or 3 (got {cls.tier!r})")
        if not isinstance(cls.ports, list):
            errs.append(f"ports must be a list of ints")
        if not isinstance(cls.services, list):
            errs.append(f"services must be a list of strings")
        if not cls.ports and not cls.services:
            errs.append("plugin must define at least one port OR service trigger")
        # run must be overridden
        if cls.run is Plugin.run:
            errs.append("plugin must override run()")
        return errs


# ── State ─────────────────────────────────────────────────────────────────────

_LOADED: dict[str, Plugin] = {}
_LOAD_ERRORS: list[dict]   = []  # [{plugin: name, error: str}]


def loaded_plugins() -> dict[str, Plugin]:
    """Return a copy of the currently-loaded plugin dict."""
    return dict(_LOADED)


def load_errors() -> list[dict]:
    """Return non-fatal errors encountered during load (for UI display)."""
    return list(_LOAD_ERRORS)


# ── Loader ────────────────────────────────────────────────────────────────────

def load_plugins(plugins_dir: Optional[Path] = None) -> dict[str, Plugin]:
    """
    Discover and load every plugins/*.py file. Returns {tool_id: Plugin}.
    Failed plugins are logged to _LOAD_ERRORS but don't halt loading.
    """
    if plugins_dir is None:
        plugins_dir = Path(__file__).resolve().parent.parent / 'plugins'

    _LOADED.clear()
    _LOAD_ERRORS.clear()

    if not plugins_dir.is_dir():
        log.info(f"plugins dir not found: {plugins_dir}")
        return {}

    for py_file in sorted(plugins_dir.glob('*.py')):
        if py_file.name.startswith('_'):
            continue
        _try_load_one(py_file)

    log.info(f"loaded {len(_LOADED)} plugin(s), {len(_LOAD_ERRORS)} error(s)")
    return loaded_plugins()


def _try_load_one(py_file: Path) -> None:
    """Import a single plugin file and register any Plugin subclasses."""
    mod_name = f"h3x_plugin_{py_file.stem}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, py_file)
        if spec is None or spec.loader is None:
            _LOAD_ERRORS.append({'plugin': py_file.name,
                                 'error': 'failed to create import spec'})
            return
        mod = importlib.util.module_from_spec(spec)
        # Register in sys.modules so relative imports in the plugin work
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    except Exception as exc:
        _LOAD_ERRORS.append({'plugin': py_file.name,
                             'error': f'import failed: {exc}'})
        return

    found_any = False
    for attr in dir(mod):
        obj = getattr(mod, attr)
        if not isinstance(obj, type):
            continue
        if obj is Plugin:
            continue
        try:
            if not issubclass(obj, Plugin):
                continue
        except TypeError:
            continue

        found_any = True
        errs = obj.validate()
        if errs:
            _LOAD_ERRORS.append({
                'plugin': f"{py_file.name}::{attr}",
                'error':  '; '.join(errs),
            })
            continue
        if obj.tool_id in _LOADED:
            _LOAD_ERRORS.append({
                'plugin': f"{py_file.name}::{attr}",
                'error':  f"tool_id {obj.tool_id!r} already registered",
            })
            continue
        try:
            instance = obj()
        except Exception as exc:
            _LOAD_ERRORS.append({
                'plugin': f"{py_file.name}::{attr}",
                'error':  f'instantiation failed: {exc}',
            })
            continue
        _LOADED[obj.tool_id] = instance
        log.info(f"plugin loaded: {obj.tool_id} ({obj.label}) "
                 f"tier={obj.tier} from {py_file.name}")

    if not found_any:
        _LOAD_ERRORS.append({
            'plugin': py_file.name,
            'error':  'no Plugin subclass found',
        })


# ── Registrar — wire plugins into enum_engine at runtime ──────────────────────

def register_with_enum_engine(enum_engine_module) -> int:
    """
    Extend enum_engine's dispatch tables with all loaded plugins.
    Returns the number of plugins registered. Idempotent: re-running
    won't double-register (dispatch tables become sets-of-tools per port).
    """
    plugins = loaded_plugins()
    if not plugins:
        return 0

    EnumEngine = enum_engine_module.EnumEngine

    for tid, plugin in plugins.items():
        # 1. TOOL_LABELS
        enum_engine_module.TOOL_LABELS[tid] = plugin.label

        # 2. TOOL_TIERS
        enum_engine_module.TOOL_TIERS[tid] = plugin.tier

        # 3. PORT_TOOLS (avoid duplicates if re-registered)
        for port in plugin.ports:
            bucket = enum_engine_module.PORT_TOOLS.setdefault(port, [])
            if tid not in bucket:
                bucket.append(tid)

        # 4. SERVICE_TOOLS
        for svc in plugin.services:
            bucket = enum_engine_module.SERVICE_TOOLS.setdefault(svc, [])
            if tid not in bucket:
                bucket.append(tid)

        # 5. Bind run method as EnumEngine._run_<tool_id>
        setattr(EnumEngine, f'_run_{tid}', _make_runner(plugin))

    return len(plugins)


def _make_runner(plugin: Plugin):
    """Wrap plugin.run so it's a proper bound method on EnumEngine."""
    def runner(self, ip, ctx, emit, finding, params):
        return plugin.run(ip, ctx, emit, finding, params)
    runner.__name__ = f"_run_{plugin.tool_id}"
    runner.__doc__  = f"Plugin runner: {plugin.label}"
    return runner


# ── Plugin manifest for UI / API ──────────────────────────────────────────────

def plugin_manifest() -> list[dict]:
    """Return JSON-serializable metadata for every loaded plugin."""
    return [
        {
            'tool_id':  p.tool_id,
            'label':    p.label,
            'tier':     p.tier,
            'ports':    list(p.ports),
            'services': list(p.services),
            'package':  p.package,
            'binary':   p.binary,
            'class':    type(p).__name__,
            'module':   type(p).__module__,
        }
        for p in _LOADED.values()
    ]
