"""
wellknown.py — Example plugin: RFC 8615 well-known path enumeration.

Demonstrates the plugin pattern with no external binary dependency.
Probes for standardised /.well-known/ paths that often leak useful recon:

  - security.txt          (RFC 9116) — security contact + disclosure policy
  - openid-configuration  — OIDC issuer metadata (endpoints, supported scopes)
  - oauth-authorization-server — OAuth 2.0 metadata
  - host-meta             — host metadata
  - change-password       — password change endpoint convention
  - dnt                   — Do Not Track policy
  - matrix/client/v1      — Matrix homeserver advertisement
  - assetlinks.json       — mobile-app linkage
  - apple-app-site-association — iOS universal links

A response of HTTP 200 on any of these is interesting reconnaissance —
some reveal IdP names, OAuth endpoints, or trust boundaries that aren't
otherwise discoverable.

This plugin is pure-stdlib: no apt package, no external binary, no pip deps.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from modules.plugin_system import Plugin, TIER_RECON


WELL_KNOWN_PATHS = [
    ('/.well-known/security.txt',                 'RFC 9116 security contact'),
    ('/.well-known/openid-configuration',         'OIDC issuer metadata'),
    ('/.well-known/oauth-authorization-server',   'OAuth 2.0 metadata'),
    ('/.well-known/host-meta',                    'host metadata'),
    ('/.well-known/change-password',              'password change endpoint'),
    ('/.well-known/dnt-policy.txt',               'DNT policy'),
    ('/.well-known/matrix/client',                'Matrix homeserver discovery'),
    ('/.well-known/assetlinks.json',              'Android app linkage'),
    ('/.well-known/apple-app-site-association',   'iOS universal links'),
]


class WellKnownPlugin(Plugin):
    tool_id  = 'well_known'
    label    = 'well-known paths (RFC 8615)'
    tier     = TIER_RECON
    ports    = [80, 443, 8080, 8443]
    services = ['http', 'https', 'ssl/http']
    package  = ''     # pure-stdlib
    binary   = ''

    def run(self, ip, ctx, emit, finding, params):
        port   = ctx['port']
        scheme = 'https' if port in (443, 8443) else 'http'
        base   = f'{scheme}://{ip}:{port}'

        emit(f'well-known \u2192 {base}/.well-known/* '
             f'({len(WELL_KNOWN_PATHS)} candidates)')

        # disable cert verification — we're scanning, not transacting
        tls_ctx = ssl.create_default_context()
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE

        found: list[tuple[str, str, int]] = []  # [(path, label, status)]
        for path, descr in WELL_KNOWN_PATHS:
            url = base + path
            try:
                req = urllib.request.Request(
                    url, headers={'User-Agent': 'H3x-Dash/1.0 (+pentest)'})
                with urllib.request.urlopen(req, timeout=4,
                                             context=tls_ctx) as resp:
                    status = resp.status
                    if status == 200:
                        found.append((path, descr, status))
            except urllib.error.HTTPError as exc:
                # 404/403/401 — endpoint absent or restricted; not interesting
                if exc.code in (401, 403):
                    found.append((path, descr + ' (auth required)', exc.code))
            except (urllib.error.URLError, OSError, ssl.SSLError):
                # connection refused / TLS error / timeout — move on
                continue

        if not found:
            emit('well-known: no advertised endpoints')
            return

        for path, descr, status in found:
            emit(f'  [{status}] {path}  — {descr}')

        finding({
            'tool':     'well_known',
            'type':     'web_well_known',
            'severity': 'INFO',
            'port':     port,
            'title':    f'RFC 8615 well-known endpoints exposed ({len(found)})',
            'detail':   '; '.join(
                f'{path} [{status}]' for path, _, status in found[:6]),
        })

        # If OIDC config is present, escalate — that's a real trust boundary disclosure
        if any('openid-configuration' in p for p, _, _ in found):
            finding({
                'tool':     'well_known',
                'type':     'web_oidc_disclosed',
                'severity': 'LOW',
                'port':     port,
                'title':    'OIDC issuer metadata advertised',
                'detail':   f'{base}/.well-known/openid-configuration '
                            'discloses IdP endpoints, supported scopes, '
                            'and signing keys — review for trust-boundary exposure',
            })
