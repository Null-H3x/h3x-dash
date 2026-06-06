# H3x-Dash Plugin System

Add a new enumeration tool without editing `enum_engine.py`. Drop a Python
file in this directory, define a `Plugin` subclass, restart H3x-Dash.

## Quick Start

```python
# plugins/my_tool.py
from modules.plugin_system import Plugin, TIER_RECON, TIER_STANDARD, TIER_DEEP


class MyToolPlugin(Plugin):
    tool_id  = 'my_tool'                    # unique, alphanumeric + underscore
    label    = 'my-tool (one-line desc)'    # shown in UI tool badges
    tier     = TIER_STANDARD                # 1=Recon, 2=Standard, 3=Deep
    ports    = [12345]                      # auto-dispatch when these ports open
    services = ['my-service']               # OR auto-dispatch by service name
    package  = 'my-tool-pkg'                # apt package (for missing-tool hint)
    binary   = 'my-tool'                    # binary for shutil.which() check

    def run(self, ip, ctx, emit, finding, params):
        # ctx = {'port': int, 'service': str, 'version': str}
        # emit('text')         → log line to operator console
        # finding({...})       → submit a finding dict (see below)
        ...
```

That's it. On startup the loader will:
1. Import the file
2. Find the `Plugin` subclass
3. Validate the contract
4. Register the tool into `TOOL_LABELS`, `TOOL_TIERS`, `PORT_TOOLS`, `SERVICE_TOOLS`
5. Bind `MyToolPlugin.run` as `EnumEngine._run_my_tool`

The next enum sweep that hits port 12345 (or service `my-service`) will fire your tool.

## Finding Dict Shape

```python
finding({
    'tool':       'my_tool',                # your tool_id
    'type':       'web_path',               # category — see below
    'severity':   'HIGH',                   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    'port':       ctx['port'],              # which port produced this
    'title':      'Short headline',         # primary text in findings table
    'detail':     'Longer explanation',     # optional
    'cve':        'CVE-2024-XXXX',          # optional — auto-promotes the chain
    'msf_module': 'exploit/.../some_mod',   # optional — wires up Exploit-tab USE button
    'creds':      [                         # optional — auto-stored in credential store
        {'type': 'password', 'username': 'admin',
         'value': 'hunter2', 'service': 'http'},
    ],
})
```

Common `type` values: `web_tech`, `web_vuln`, `web_dir`, `web_path`, `web_cms`,
`web_users`, `web_waf`, `web_plugin_vuln`, `ssl_vuln`, `tls_legacy`,
`tls_weak_cipher`, `ad_users`, `ad_enum`, `smb_shares`, `smb_share_listed`,
`smb_rpc_info`, `dns_zone_xfer`, `dns_subdomains`. New types are fine —
MITRE mapping in `modules/mitre_mapping.py` will fall back to MSF-module or
severity-based attribution.

## Contract Rules

The loader rejects a plugin if any of these fail:

- `tool_id` is empty, non-string, or contains characters other than letters,
  digits, and underscores
- `tool_id` collides with an existing tool (built-in or another plugin)
- `label` is empty
- `tier` is not 1, 2, or 3
- `ports` is not a list (must be `list[int]`) and `services` is also not a list
- Neither `ports` nor `services` is provided (need at least one trigger)
- `run()` is not overridden

Errors don't halt startup — failed plugins are recorded and shown in
`GET /api/plugins`. Other plugins continue loading.

## Tier Guidance

| Tier | Use For |
|------|---------|
| `TIER_RECON` (1) | Fast (<10s typical), low-noise, banner/probe-style. Always runs. |
| `TIER_STANDARD` (2) | Default working depth — the bulk of useful tools. |
| `TIER_DEEP` (3) | Slow / loud / opt-in only. Operator must explicitly request. |

The operator-selected sweep depth gates everything *above* the selected tier:
Tier 1 sweeps run only Tier 1 tools; Tier 2 runs Tier 1+2; Tier 3 runs everything.

## Subprocess Safety

If your plugin runs external commands, follow these rules:

1. **Always check the binary exists** before running — `shutil.which('my-tool')`
2. **Pass arguments as a list**, never a shell string — prevents injection
3. **Enforce a timeout** — never let a subprocess block forever
4. **Catch `subprocess.TimeoutExpired`** and emit a clean `[TIMEOUT]` line
5. **Use `errors='replace'`** on text decode to survive non-UTF-8 output

Reference any built-in runner in `modules/enum_engine.py` — they all follow
this pattern. The `self._run_cmd()` helper on `EnumEngine` does most of the
heavy lifting if you bind your plugin via the bound-method registrar.

## Pure-Python Plugins

You don't need an external binary. Set `binary = ''` and `package = ''` and
write the logic in Python. See `plugins/wellknown.py` for an example —
checks RFC 8615 well-known paths using only stdlib `urllib.request`.

## Listing Loaded Plugins

```bash
curl http://127.0.0.1:5000/api/plugins
```

Returns the manifest plus any load errors (failed plugins, validation errors,
tool_id collisions). Useful when a plugin doesn't show up — the error is in
the response.

## Disabling a Plugin

Rename the file to start with `_` (e.g. `_my_tool.py`) — the loader skips
underscore-prefixed files. Or delete it. No core code edits required either way.
