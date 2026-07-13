"""
msf_capabilities.py — Phase 1 of the resolver: introspect MSF's own ground truth.

Instead of hardcoding per-module payloads / ports / options, we ask msfrpcd what
the module actually supports and let the resolver (exploit_resolver.py) decide.
MSF is authoritative; our hardcoded tables become a thin fallback.

get_module_capabilities() returns a normalized, cached CapabilitySet:

    {
      'module':              str,
      'available':           bool,   # could we introspect at all?
      'rank':                str,
      'options':             {NAME: {required, default, type, desc}},
      'required':            [NAME, ...],
      'compatible_payloads': [NAME, ...],   # [] if MSF/library couldn't enumerate
      'payloads_parseable':  bool,
      'targets':             [{index, name}],
      'default_rport':       int | None,
      'has_builtin_payload': bool,   # module ships its own (interact/find) default
      'notes':               [str],
    }

The pymetasploit3 library raises on .payloads / .compatible_payloads for some
modules (malformed metadata response). We degrade gracefully: capabilities are
still returned, just with compatible_payloads=[] and payloads_parseable=False,
and the resolver falls back to policy hints / module defaults.

The parsing logic is split from the RPC call so it can be unit-tested with a
mock module object (audit_capabilities.py).
"""
from __future__ import annotations

import threading
from typing import Any

# Payload names that indicate a module delivers its own shell (no explicit
# PAYLOAD should be set — MSF rejects an explicitly-set one).
_BUILTIN_PAYLOAD_MARKERS = ('cmd/unix/interact', 'interact')


def _normalize_options(raw_options: Any) -> dict[str, dict]:
    """Coerce module.options (dict or list) into {NAME: {meta}}."""
    out: dict[str, dict] = {}
    if isinstance(raw_options, dict):
        for name, meta in raw_options.items():
            if isinstance(meta, dict):
                out[str(name)] = {
                    'required': bool(meta.get('required', False)),
                    'default':  meta.get('default'),
                    'type':     meta.get('type'),
                    'desc':     meta.get('desc', ''),
                    # MSF marks transport/SSL/evasion options 'advanced'. Advanced
                    # options always carry framework defaults → never operator-
                    # required, regardless of how the default is (or isn't) surfaced.
                    'advanced': bool(meta.get('advanced', False)),
                    'evasion':  bool(meta.get('evasion', False)),
                }
            else:
                out[str(name)] = {'required': False, 'default': None,
                                  'type': None, 'desc': ''}
    elif isinstance(raw_options, (list, tuple, set)):
        for name in raw_options:
            out[str(name)] = {'required': False, 'default': None,
                              'type': None, 'desc': ''}
    return out


def parse_capabilities(module_name: str, mod: Any) -> dict[str, Any]:
    """
    Build a CapabilitySet from a (possibly quirky) pymetasploit3 module object.
    Pure parsing — no RPC — so it is unit-testable with a mock.
    """
    notes: list[str] = []

    if mod is None or not hasattr(mod, 'options'):
        return {
            'module': module_name, 'available': False, 'rank': 'unknown',
            'options': {}, 'required': [], 'compatible_payloads': [],
            'payloads_parseable': False, 'targets': [], 'default_rport': None,
            'has_builtin_payload': False,
            'notes': ['Module metadata unavailable — resolver will use policy '
                      'hints and module defaults.'],
        }

    options = _normalize_options(getattr(mod, 'options', {}))

    # Required: prefer the library's own missing/required view, else derive.
    required: list[str] = []
    try:
        req = getattr(mod, 'required', None)
        if req:
            required = [str(r) for r in req]
    except Exception:
        pass
    if not required:
        required = [n for n, m in options.items() if m.get('required')]

    # Compatible payloads — the call most likely to raise the library quirk.
    compatible: list[str] = []
    payloads_parseable = True
    try:
        raw = getattr(mod, 'payloads', None)
        if raw is None:
            payloads_parseable = False
        else:
            compatible = [str(p) for p in raw]
    except Exception as exc:                       # malformed metadata response
        payloads_parseable = False
        notes.append(f'compatible_payloads not enumerable ({type(exc).__name__}) '
                     f'— resolver falls back to policy/default payload.')

    # Targets (OS/arch selection material).
    targets: list[dict] = []
    try:
        tlist = list(getattr(mod, 'targets', []) or [])
        targets = [{'index': i, 'name': str(t)} for i, t in enumerate(tlist)]
    except Exception:
        pass

    # Default RPORT from the options schema.
    default_rport = None
    rp = options.get('RPORT')
    if rp and rp.get('default') not in (None, ''):
        try:
            default_rport = int(rp['default'])
        except (TypeError, ValueError):
            default_rport = None

    rank = 'unknown'
    try:
        rank = str(getattr(mod, 'rank', 'unknown'))
    except Exception:
        pass

    has_builtin = any(
        any(mk in p.lower() for mk in _BUILTIN_PAYLOAD_MARKERS)
        for p in compatible
    ) and len([p for p in compatible if 'interact' not in p.lower()]) == 0 \
        if compatible else False

    return {
        'module':              module_name,
        'available':           True,
        'rank':                rank,
        'options':             options,
        'required':            required,
        'compatible_payloads': compatible,
        'payloads_parseable':  payloads_parseable,
        'targets':             targets,
        'default_rport':       default_rport,
        'has_builtin_payload': has_builtin,
        'notes':               notes,
    }


class CapabilityCache:
    """Thread-safe per-module capability cache (metadata is static per MSF build)."""

    def __init__(self):
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, module_name: str):
        with self._lock:
            return self._cache.get(module_name)

    def put(self, module_name: str, caps: dict) -> None:
        with self._lock:
            self._cache[module_name] = caps

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


_cache = CapabilityCache()


def get_module_capabilities(client, module_name: str, *,
                            use_cache: bool = True) -> dict[str, Any]:
    """
    Introspect a module via msfrpcd and return a normalized CapabilitySet.

    `client` is a pymetasploit3 MsfRpcClient (or compatible mock exposing
    .modules.use(type, name)). Returns an 'available: False' set if the client
    is missing or the module can't be loaded — never raises.
    """
    if use_cache:
        cached = _cache.get(module_name)
        if cached is not None:
            return cached

    if client is None:
        caps = parse_capabilities(module_name, None)
        return caps

    parts = module_name.split('/')
    mtype = parts[0] if parts and parts[0] in (
        'exploit', 'auxiliary', 'post', 'payload', 'evasion') else 'exploit'
    mname = '/'.join(parts[1:]) if len(parts) > 1 else module_name

    mod = None
    try:
        mod = client.modules.use(mtype, mname)
    except Exception:
        mod = None

    caps = parse_capabilities(module_name, mod)
    if use_cache and caps.get('available'):
        _cache.put(module_name, caps)
    return caps
