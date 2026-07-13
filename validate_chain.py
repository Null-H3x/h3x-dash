#!/usr/bin/env python3
"""
validate_chain.py — verify every cve_chain.py module path against a running
msfrpcd. The offline audit (audit_chain.py) covers internal consistency;
THIS script answers the only thing the offline audit can't: "do these
module names actually exist in MY Metasploit install?"

USAGE
    sudo msfrpcd -P msfrpc -S -a 127.0.0.1
    python3 validate_chain.py
    # or:
    python3 validate_chain.py --password mypass --port 55553

EXIT CODES
    0   every CVE_MAP module exists on msfrpcd
    1   at least one module missing (printed with its CVE_MAP key)
    2   could not connect to msfrpcd
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

# Allow running from anywhere — locate the modules package next to this file.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from modules.cve_chain import CVE_MAP        # noqa: E402
from modules.msf_engine import MsfEngine     # noqa: E402

_TYPE_MAP = {'exploit': 'exploits', 'auxiliary': 'auxiliary', 'post': 'post'}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host',     default='127.0.0.1')
    p.add_argument('--port',     default=55553, type=int)
    p.add_argument('--password', default='msfrpc',
                   help='msfrpcd password (default: msfrpc)')
    p.add_argument('--ssl', action='store_true',
                   help='msfrpcd was started WITHOUT -S (i.e. with SSL on)')
    p.add_argument('--offline', action='store_true',
                   help='Skip msfrpcd check; run audit_chain.py instead')
    args = p.parse_args()

    if args.offline:
        import subprocess
        print("[*] --offline: running audit_chain.py (internal consistency only)\n")
        rc = subprocess.call([sys.executable,
                              str(Path(__file__).resolve().parent
                                  / 'audit' / 'audit_chain.py')])
        return 0 if rc == 0 else 1

    eng = MsfEngine()
    res = eng.connect(host=args.host, port=args.port,
                      password=args.password, ssl=args.ssl)
    if res.get('status') != 'connected':
        print(f"[FAIL] could not connect to msfrpcd at "
              f"{args.host}:{args.port} — {res.get('message','?')}",
              file=sys.stderr)
        print("       is msfrpcd running?  e.g.  "
              "sudo msfrpcd -P msfrpc -S -a 127.0.0.1", file=sys.stderr)
        return 2

    client = eng._client_ref()
    catalog: dict[str, set[str]] = {}
    for cve_type, attr in _TYPE_MAP.items():
        try:
            catalog[cve_type] = set(getattr(client.modules, attr))
        except Exception as e:
            print(f"[FAIL] could not list {attr}: {e}", file=sys.stderr)
            return 2

    print(f"[*] msfrpcd connected — {len(catalog['exploit'])} exploits, "
          f"{len(catalog['auxiliary'])} aux, {len(catalog['post'])} post")
    print(f"[*] Checking every module path in cve_chain.CVE_MAP\u2026\n")

    missing: list[tuple[str, str, str]] = []
    present = 0
    for key, entries in CVE_MAP.items():
        for _cve, mod, _desc, _sev in entries:
            if not mod:
                continue
            parts = mod.split('/', 1)
            if len(parts) != 2:
                missing.append((key, mod, "malformed path"))
                continue
            mtype, mname = parts
            if mtype not in catalog:
                missing.append((key, mod, f"unknown module type '{mtype}'"))
                continue
            if mname in catalog[mtype]:
                present += 1
            else:
                missing.append((key, mod, "not in msfrpcd catalog"))

    print(f"[+] {present} module path(s) verified against msfrpcd")
    if missing:
        print(f"[!] {len(missing)} module path(s) NOT found on this msfrpcd:\n")
        width = max(len(m) for _, m, _ in missing)
        for key, mod, why in missing:
            print(f"    {key:<14}  {mod:<{width}}  \u2192  {why}")
        print("\n    Likely causes: module renamed, removed in your MSF version,")
        print("    or installed in a non-default path. Cross-check with:")
        print('      msfconsole -q -x "search <module-name>; exit"')
        return 1

    print("[\u2713] All module paths exist on this msfrpcd.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
