#!/usr/bin/env python3
"""
web_scan.py — Layer-7 web scanning module for the Nmap Configurabulator
═══════════════════════════════════════════════════════════════════════════════

WHY THIS MODULE EXISTS
    nmap (and the Configurabulator that wraps it) is a Layer 3/4 tool: it maps
    IPs and port state. A "website" is a Layer 7 target — feed nmap a URL and it
    fails to resolve it; feed it a bare hostname and you get port state with no
    HTTP-layer data. This module closes that gap.

CAPABILITIES
    1. Fingerprint & headers — status, redirect chain, Server/X-Powered-By,
       page title, technology detection, security-header audit, cookie flags.
    2. TLS & certificate inspection — subject/issuer/SAN, validity window,
       self-signed / hostname-mismatch detection, negotiated protocol & cipher,
       legacy-protocol (TLS 1.0/1.1) probe.
    3. Content surface — robots.txt, sitemap.xml, HTTP methods (incl. TRACE/XST),
       and a short high-signal probe of interesting paths.
    4. nmap http-NSE orchestration — runs http-enum / http-headers / http-methods
       / http-title / http-vuln* against the web port and parses the results.

DESIGN
    Pure standard library only — no pip dependencies — to preserve the
    Configurabulator's single-file, zero-dependency footprint. Targets
    Python 3.9+. Every probe is wrapped so a web scan can never crash its host.

STANDALONE USE
    python3 web_scan.py https://example.com            # JSON to stdout
    python3 web_scan.py example.com:8443 --nse         # include nmap http-NSE
"""

from __future__ import annotations

import http.client
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
import warnings
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# Private CPython helper that decodes a PEM cert file into the same dict
# getpeercert() returns — but works for INVALID certs too (self-signed /
# expired), which getpeercert() will not. Stable since Python 2.x; if it ever
# disappears the TLS section degrades gracefully to protocol/cipher only.
try:
    from _ssl import _test_decode_cert as _decode_cert      # type: ignore
except Exception:                                            # pragma: no cover
    _decode_cert = None


# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "1.0"
UA      = f"Mozilla/5.0 (X11; Linux x86_64) H3x-WebScan/{VERSION}"

# Ports the Configurabulator should auto-trigger a web scan on, and the scheme
# to assume for each. Service-name matching ("http" in service) supplements it.
WEB_PORTS: dict[int, str] = {
    80: "http", 8080: "http", 8000: "http", 8888: "http",
    3000: "http", 5000: "http", 8008: "http",
    443: "https", 8443: "https", 9443: "https",
}

# Security headers to audit. (finding title, severity, scope)
# scope "https" → only flagged on TLS sites; "any" → flagged everywhere.
_SEC_HEADERS = {
    "strict-transport-security": ("HSTS not set — TLS downgrade possible", "MEDIUM", "https"),
    "content-security-policy":   ("No Content-Security-Policy",            "MEDIUM", "any"),
    "x-frame-options":           ("X-Frame-Options missing — clickjacking exposure", "MEDIUM", "any"),
    "x-content-type-options":    ("X-Content-Type-Options missing — MIME sniffing",  "LOW",    "any"),
    "referrer-policy":           ("Referrer-Policy not set",               "LOW",    "any"),
    "permissions-policy":        ("Permissions-Policy not set",            "INFO",   "any"),
}

# Technology signatures: (label, where, regex). where ∈
# {"server", "x-powered-by", "x-aspnet-version", "cookie", "body"}.
_TECH_SIGS = [
    ("nginx",          "server",           r"nginx"),
    ("Apache httpd",   "server",           r"apache"),
    ("Microsoft IIS",  "server",           r"microsoft-iis"),
    ("Apache Tomcat",  "server",           r"tomcat|coyote"),
    ("Cloudflare",     "server",           r"cloudflare"),
    ("LiteSpeed",      "server",           r"litespeed"),
    ("Werkzeug/Flask", "server",           r"werkzeug"),
    ("PHP",            "x-powered-by",     r"php"),
    ("ASP.NET",        "x-powered-by",     r"asp\.net"),
    ("Express",        "x-powered-by",     r"express"),
    ("ASP.NET",        "x-aspnet-version", r".+"),
    ("Laravel",        "cookie",           r"laravel_session|xsrf-token"),
    ("Django",         "cookie",           r"csrftoken|sessionid"),
    ("PHP",            "cookie",           r"phpsessid"),
    ("Java EE",        "cookie",           r"jsessionid"),
    ("WordPress",      "body",             r"wp-content|wp-includes|/wp-json"),
    ("Drupal",         "body",             r"drupal|sites/default/files"),
    ("Joomla",         "body",             r"/media/jui/|joomla"),
    ("jQuery",         "body",             r"jquery[.\-]\d"),
    ("Bootstrap",      "body",             r"bootstrap[.\-]\d"),
    ("React",          "body",             r"__react|react-dom"),
    ("Vue.js",         "body",             r"vue(\.min)?\.js|data-v-"),
]

# Path probe table: (path, body-signature regex or None, severity-when-confirmed).
# A signature lets us content-confirm a hit instead of trusting the status code
# alone — essential on catch-all sites that answer 200 for everything.
_PROBE_PATHS = [
    ("/.git/HEAD",                r"ref:\s*refs/",                         "HIGH"),
    ("/.git/config",              r"\[core\]",                             "HIGH"),
    ("/.env",                     r"(?m)^[A-Z][A-Z0-9_]*=",                "HIGH"),
    ("/.svn/entries",             r"^(?:\d+|dir)",                         "MEDIUM"),
    ("/server-status",            r"Apache Server Status|Server uptime",   "HIGH"),
    ("/server-info",              r"Apache Server Information",            "HIGH"),
    ("/phpinfo.php",              r"phpinfo\(\)|PHP Version",              "HIGH"),
    ("/config.php.bak",           r"<\?php",                               "HIGH"),
    ("/web.config",               r"<configuration",                      "HIGH"),
    ("/crossdomain.xml",          r"cross-domain-policy",                  "MEDIUM"),
    ("/.well-known/security.txt", r"(?i)contact\s*:",                      "INFO"),
    ("/actuator",                 r'"_links"|/actuator/',                  "MEDIUM"),
    ("/actuator/health",          r'"status"',                             "MEDIUM"),
    ("/swagger-ui/",              r"(?i)swagger",                          "LOW"),
    ("/phpmyadmin/",              r"(?i)phpmyadmin",                       "MEDIUM"),
    ("/.DS_Store",                None,                                    "MEDIUM"),
    ("/.htaccess",                None,                                    "LOW"),
    ("/backup/",                  None,                                    "LOW"),
    ("/admin/",                   None,                                    "INFO"),
    ("/administrator/",           None,                                    "INFO"),
    ("/login",                    None,                                    "INFO"),
    ("/wp-login.php",             None,                                    "INFO"),
    ("/wp-admin/",                None,                                    "INFO"),
    ("/api/",                     None,                                    "INFO"),
]

_REDIRECT_CODES = {301, 302, 303, 307, 308}


# ── Small helpers ─────────────────────────────────────────────────────────────

def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def _fmt_url(scheme: str, host: str, port: int, path: str) -> str:
    hostport = host if _is_default_port(scheme, port) else f"{host}:{port}"
    return f"{scheme}://{hostport}{path or '/'}"


def normalize_target(raw: str, default_scheme: str = "") -> tuple[str, str, int, str]:
    """
    Turn a loose target ('example.com', 'example.com:8443', 'https://x/y')
    into (scheme, host, port, path). default_scheme overrides the http guess.
    """
    raw = (raw or "").strip()
    if "://" not in raw:
        # Bare host[:port][/path] — prepend a scheme so urlparse behaves.
        raw = "//" + raw
        parsed = urllib.parse.urlparse(raw, scheme=default_scheme or "http")
    else:
        parsed = urllib.parse.urlparse(raw)

    scheme = (parsed.scheme or default_scheme or "http").lower()
    host   = parsed.hostname or ""
    port   = parsed.port or (443 if scheme == "https" else 80)
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return scheme, host, int(port), path


def _headers_to_dict(raw_headers: list[tuple]) -> dict:
    """
    Lowercase-keyed header dict. Set-Cookie is special-cased into a list so
    multiple cookies survive (a plain dict would collapse them).
    """
    out: dict = {}
    cookies: list[str] = []
    for k, v in raw_headers:
        lk = k.lower()
        if lk == "set-cookie":
            cookies.append(v)
        else:
            out[lk] = v if lk not in out else f"{out[lk]}, {v}"
    if cookies:
        out["set-cookie"] = cookies
    return out


def _new_conn(scheme: str, host: str, port: int, timeout: float):
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False          # pentest context: scan invalid certs too
        ctx.verify_mode    = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


# ── 1. Fingerprint & headers ──────────────────────────────────────────────────

def fetch_chain(scheme: str, host: str, port: int, path: str,
                timeout: float = 10.0, max_redirects: int = 8,
                max_body: int = 262144) -> tuple[dict | None, list]:
    """
    GET the URL, follow redirects, return (final_response, redirect_chain).
    final_response = {scheme,host,port,path,status,headers,body} or None.
    """
    chain: list = []
    cur = (scheme, host, port, path)
    final = None
    seen: set = set()

    for _ in range(max_redirects + 1):
        s, h, pt, pa = cur
        if (s, h, pt, pa) in seen:          # redirect loop guard
            break
        seen.add((s, h, pt, pa))

        conn = _new_conn(s, h, pt, timeout)
        try:
            conn.request("GET", pa or "/",
                         headers={"User-Agent": UA, "Accept": "*/*",
                                  "Accept-Encoding": "identity",
                                  "Connection": "close"})
            resp    = conn.getresponse()
            status  = resp.status
            raw_hdr = resp.getheaders()
            body    = resp.read(max_body)
        except Exception as exc:
            chain.append({"url": _fmt_url(s, h, pt, pa), "status": 0,
                          "error": str(exc)})
            return final, chain
        finally:
            try:
                conn.close()
            except Exception:
                pass

        hdict = _headers_to_dict(raw_hdr)
        final = {"scheme": s, "host": h, "port": pt, "path": pa,
                 "status": status, "headers": hdict, "body": body}
        loc = hdict.get("location", "")
        chain.append({"url": _fmt_url(s, h, pt, pa), "status": status,
                      "location": loc if status in _REDIRECT_CODES else ""})

        if status in _REDIRECT_CODES and loc:
            nxt = _resolve_redirect(cur, loc)
            if not nxt or nxt == cur:
                break
            cur = nxt
            continue
        break

    return final, chain


def _resolve_redirect(cur: tuple, location: str) -> tuple | None:
    scheme, host, port, path = cur
    base   = _fmt_url(scheme, host, port, path)
    joined = urllib.parse.urljoin(base, location.strip())
    p      = urllib.parse.urlparse(joined)
    if p.scheme not in ("http", "https"):
        return None
    nhost = p.hostname or host
    nport = p.port or (443 if p.scheme == "https" else 80)
    npath = p.path or "/"
    if p.query:
        npath += "?" + p.query
    return (p.scheme, nhost, int(nport), npath)


def _extract_title(body: bytes) -> str:
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def detect_tech(headers: dict, body: bytes) -> list[str]:
    server   = str(headers.get("server", "")).lower()
    powered  = str(headers.get("x-powered-by", "")).lower()
    aspnet   = str(headers.get("x-aspnet-version", "")).lower()
    cookies  = " ".join(headers.get("set-cookie", [])).lower() \
               if isinstance(headers.get("set-cookie"), list) else \
               str(headers.get("set-cookie", "")).lower()
    body_txt = body[:262144].decode("utf-8", "replace").lower()

    sources = {"server": server, "x-powered-by": powered,
               "x-aspnet-version": aspnet, "cookie": cookies, "body": body_txt}
    found: list[str] = []
    for label, where, pattern in _TECH_SIGS:
        hay = sources.get(where, "")
        if hay and re.search(pattern, hay):
            if label not in found:
                found.append(label)
    return found


def audit_security_headers(headers: dict, scheme: str) -> tuple[list, list, list]:
    """Return (present, missing, findings)."""
    present, missing, findings = [], [], []
    for hk, (title, sev, scope) in _SEC_HEADERS.items():
        if scope == "https" and scheme != "https":
            continue
        if hk in headers:
            present.append(hk)
        else:
            missing.append(hk)
            findings.append({"severity": sev, "title": title,
                             "detail": f"Response header '{hk}' absent"})

    # Version / software disclosure
    srv = str(headers.get("server", ""))
    if re.search(r"\d", srv):
        findings.append({"severity": "LOW", "title": "Server version disclosed",
                         "detail": f"Server: {srv}"})
    if headers.get("x-powered-by"):
        findings.append({"severity": "LOW", "title": "X-Powered-By disclosed",
                         "detail": f"X-Powered-By: {headers['x-powered-by']}"})
    if headers.get("x-aspnet-version"):
        findings.append({"severity": "LOW", "title": "ASP.NET version disclosed",
                         "detail": f"X-AspNet-Version: {headers['x-aspnet-version']}"})
    return present, missing, findings


def parse_cookies(headers: dict, scheme: str) -> tuple[list, list]:
    """Return (cookies, findings). Flags missing Secure/HttpOnly/SameSite."""
    raw = headers.get("set-cookie")
    if raw is None:
        return [], []
    raw_list = raw if isinstance(raw, list) else [raw]
    cookies, findings = [], []
    for c in raw_list:
        name   = c.split("=", 1)[0].strip()
        low    = c.lower()
        secure = "secure" in low
        httpo  = "httponly" in low
        samem  = re.search(r"samesite=(\w+)", low)
        same   = samem.group(1) if samem else ""
        cookies.append({"name": name, "secure": secure,
                        "httponly": httpo, "samesite": same})
        if scheme == "https" and not secure:
            findings.append({"severity": "MEDIUM",
                             "title": f"Cookie '{name}' missing Secure flag",
                             "detail": "Cookie may be sent over cleartext HTTP"})
        if not httpo:
            findings.append({"severity": "LOW",
                             "title": f"Cookie '{name}' missing HttpOnly flag",
                             "detail": "Cookie is readable from JavaScript"})
        if not same:
            findings.append({"severity": "LOW",
                             "title": f"Cookie '{name}' has no SameSite attribute",
                             "detail": "CSRF exposure — no SameSite restriction"})
    return cookies, findings


# ── 2. TLS & certificate inspection ───────────────────────────────────────────

def _cert_names(cert: dict) -> list[str]:
    names: list[str] = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ == "DNS":
            names.append(val.lower())
    for rdn in cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                names.append(str(v).lower())
    return names


def _host_matches(host: str, names: list[str]) -> bool:
    host = (host or "").lower()
    for n in names:
        if n == host:
            return True
        if n.startswith("*."):                       # single-label wildcard
            if host.split(".", 1)[-1] == n[2:] and "." in host:
                return True
    return False


def _flatten_dn(dn) -> str:
    parts = []
    for rdn in dn or ():
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def inspect_tls(host: str, port: int, sni: str | None = None,
                timeout: float = 10.0) -> dict:
    """Negotiate TLS, pull the cert (valid or not), probe legacy protocols."""
    sni = sni or host
    out: dict = {"reachable": False, "findings": []}

    # Negotiate best protocol; capture cert in DER form (works for bad certs).
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                out["reachable"] = True
                out["protocol"]  = ssock.version() or ""
                cipher           = ssock.cipher()
                out["cipher"]    = cipher[0] if cipher else ""
                der              = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        out["error"] = str(exc)
        return out

    # Decode the certificate (DER → PEM → dict).
    cert: dict = {}
    if der and _decode_cert:
        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem",
                                             delete=True) as tf:
                tf.write(pem)
                tf.flush()
                cert = _decode_cert(tf.name) or {}
        except Exception:
            cert = {}

    if cert:
        out["subject"] = _flatten_dn(cert.get("subject"))
        out["issuer"]  = _flatten_dn(cert.get("issuer"))
        out["san"]     = [v for t, v in cert.get("subjectAltName", ())
                          if t == "DNS"]
        out["not_before"] = cert.get("notBefore", "")
        out["not_after"]  = cert.get("notAfter", "")

        # Validity window
        try:
            exp = ssl.cert_time_to_seconds(cert["notAfter"])
            now = datetime.now(timezone.utc).timestamp()
            days = int((exp - now) / 86400)
            out["days_left"] = days
            if days < 0:
                out["findings"].append(
                    {"severity": "HIGH", "title": "TLS certificate expired",
                     "detail": f"Expired {-days} day(s) ago ({cert['notAfter']})"})
            elif days < 21:
                out["findings"].append(
                    {"severity": "MEDIUM", "title": "TLS certificate expiring soon",
                     "detail": f"{days} day(s) until expiry"})
        except Exception:
            pass

        # Self-signed
        if out.get("subject") and out["subject"] == out.get("issuer"):
            out["self_signed"] = True
            out["findings"].append(
                {"severity": "MEDIUM", "title": "Self-signed TLS certificate",
                 "detail": "Subject equals issuer — not chained to a trusted CA"})
        else:
            out["self_signed"] = False

        # Hostname coverage
        names = _cert_names(cert)
        match = _host_matches(host, names) if names else True
        out["hostname_match"] = match
        if not match:
            out["findings"].append(
                {"severity": "MEDIUM", "title": "TLS hostname mismatch",
                 "detail": f"'{host}' not covered by cert names: "
                           f"{', '.join(names) or '(none)'}"})
    else:
        out["cert_parse"] = "unavailable"

    # Legacy protocol probe — TLS 1.0 / 1.1. A successful handshake proves the
    # server still offers it. (Modern OpenSSL may block the client side, which
    # only risks a false negative — never a false positive.)
    legacy: list[str] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")          # TLSv1/1.1 are deprecated names
        for label, ver in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
            if ver is None:
                continue
            try:
                lc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                lc.check_hostname = False
                lc.verify_mode    = ssl.CERT_NONE
                lc.minimum_version = ver
                lc.maximum_version = ver
                with socket.create_connection((host, port), timeout=6) as s:
                    with lc.wrap_socket(s, server_hostname=sni):
                        legacy.append(label)
            except Exception:
                pass
    out["legacy_protocols"] = legacy
    for proto in legacy:
        out["findings"].append(
            {"severity": "MEDIUM", "title": f"Legacy {proto} supported",
             "detail": f"Server negotiated deprecated {proto}"})

    return out


# ── 3. Content surface ────────────────────────────────────────────────────────

def _quick_get(scheme: str, host: str, port: int, path: str,
               timeout: float, method: str = "GET",
               max_body: int = 65536) -> dict | None:
    conn = _new_conn(scheme, host, port, timeout)
    try:
        conn.request(method, path,
                     headers={"User-Agent": UA, "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(max_body) if method != "HEAD" else b""
        return {"status": resp.status, "headers": _headers_to_dict(resp.getheaders()),
                "body": body}
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def content_surface(scheme: str, host: str, port: int,
                    timeout: float = 8.0) -> dict:
    out: dict = {"robots": [], "sitemap": [], "methods": [],
                 "risky_methods": [], "interesting_paths": [], "findings": []}

    # robots.txt — disclosed paths are reconnaissance gold.
    r = _quick_get(scheme, host, port, "/robots.txt", timeout)
    if r and r["status"] == 200:
        for line in r["body"].decode("utf-8", "replace").splitlines():
            m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
            if m and m.group(1) not in ("*", "/"):
                out["robots"].append(m.group(1))
        if out["robots"]:
            out["findings"].append(
                {"severity": "INFO", "title": "robots.txt discloses paths",
                 "detail": f"{len(out['robots'])} path(s): "
                           f"{', '.join(out['robots'][:8])}"})

    # sitemap.xml — enumerate <loc> entries.
    sm = _quick_get(scheme, host, port, "/sitemap.xml", timeout)
    if sm and sm["status"] == 200:
        for m in re.finditer(r"<loc>\s*(.*?)\s*</loc>",
                             sm["body"].decode("utf-8", "replace"), re.I | re.S):
            out["sitemap"].append(m.group(1).strip())

    # HTTP methods via OPTIONS.
    opt = _quick_get(scheme, host, port, "/", timeout, method="OPTIONS")
    if opt:
        allow = str(opt["headers"].get("allow", ""))
        out["methods"] = [m.strip().upper() for m in allow.split(",") if m.strip()]
        for risky in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH"):
            if risky in out["methods"]:
                out["risky_methods"].append(risky)
                out["findings"].append(
                    {"severity": "LOW", "title": f"HTTP {risky} method advertised",
                     "detail": f"OPTIONS Allow header lists {risky}"})

    # Active TRACE check — Cross-Site Tracing.
    tr = _quick_get(scheme, host, port, "/", timeout, method="TRACE")
    if tr and tr["status"] == 200 and b"TRACE" in tr["body"].upper():
        if "TRACE" not in out["risky_methods"]:
            out["risky_methods"].append("TRACE")
        out["findings"].append(
            {"severity": "MEDIUM", "title": "HTTP TRACE enabled (XST)",
             "detail": "Server echoes TRACE requests — Cross-Site Tracing risk"})

    # Short interesting-path probe.
    # First baseline a path that cannot exist — if the server answers 200 for
    # it, the site is catch-all and a bare 200 proves nothing. On such sites we
    # only trust content-confirmed hits and non-200 status codes.
    base = _quick_get(scheme, host, port,
                      "/h3xdash-nonexistent-baseline-7f3a9c2e/",
                      timeout, max_body=4096)
    catch_all = bool(base and base["status"] == 200)
    out["catch_all"] = catch_all
    if catch_all:
        out["findings"].append(
            {"severity": "INFO", "title": "Server returns 200 for missing paths",
             "detail": "Catch-all behaviour — path probing limited to "
                       "content-confirmed hits"})

    for path, sig, sev in _PROBE_PATHS:
        hit = _quick_get(scheme, host, port, path, timeout, max_body=8192)
        if not hit or hit["status"] == 404:
            continue
        s        = hit["status"]
        body_txt = hit["body"].decode("utf-8", "replace")

        if sig:
            # Signature path — confirm by content, never by status alone.
            if s == 200 and re.search(sig, body_txt):
                out["interesting_paths"].append(
                    {"path": path, "status": s, "confirmed": True})
                out["findings"].append(
                    {"severity": sev,
                     "title": f"Exposed: {path} (content-confirmed)",
                     "detail": f"{path} → HTTP {s}; body matches expected signature"})
            elif s in (401, 403):
                out["interesting_paths"].append({"path": path, "status": s})
                out["findings"].append(
                    {"severity": "INFO",
                     "title": f"Path present but protected: {path} [{s}]",
                     "detail": f"{path} → HTTP {s}"})
            # 200 without a signature match → soft-404 / catch-all; skip silently.
        else:
            # No signature (admin panels, login, api) — lower confidence.
            if s == 200 and not catch_all:
                out["interesting_paths"].append({"path": path, "status": s})
                out["findings"].append(
                    {"severity": sev,
                     "title": f"Path accessible: {path} [200]",
                     "detail": f"{path} → HTTP 200"})
            elif s in (401, 403):
                out["interesting_paths"].append({"path": path, "status": s})
                out["findings"].append(
                    {"severity": "INFO",
                     "title": f"Path present but protected: {path} [{s}]",
                     "detail": f"{path} → HTTP {s}"})
    return out


# ── 4. nmap http-NSE orchestration ────────────────────────────────────────────

def nmap_http_nse(host: str, port: int, timeout: int = 240) -> dict:
    """
    Run http-* NSE scripts against one web port and return {script_id: output}.
    Reuses nmap (already a Configurabulator dependency). Graceful if absent.
    """
    nmap = shutil.which("nmap")
    if not nmap:
        return {"_error": "nmap not found in PATH"}

    scripts = "http-enum,http-headers,http-methods,http-title,http-server-header,http-vuln*"
    xml_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_path = tf.name
        cmd = [nmap, "-Pn", "-sT", "-p", str(port), "--script", scripts,
               "--script-timeout", "30s", "-oX", xml_path, host]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        tree = ET.parse(xml_path)
        results: dict = {}
        for port_el in tree.getroot().iter("port"):
            if port_el.get("portid") != str(port):
                continue
            for sc in port_el.findall("script"):
                out = (sc.get("output") or "").strip()
                if out:
                    results[sc.get("id", "?")] = out
        return results
    except subprocess.TimeoutExpired:
        return {"_error": f"nmap http-NSE timed out after {timeout}s"}
    except Exception as exc:
        return {"_error": str(exc)}
    finally:
        if xml_path:
            try:
                Path(xml_path).unlink(missing_ok=True)
            except Exception:
                pass


# ── Orchestrator ──────────────────────────────────────────────────────────────

def scan_target(target: str, timeout: float = 10.0,
                include_nse: bool = False,
                default_scheme: str = "") -> dict:
    """
    Full Layer-7 scan of one web target. Returns a self-contained 'web record'.
    Never raises — failures are captured in the record.
    """
    scheme, host, port, path = normalize_target(target, default_scheme)
    record: dict = {
        "target": target, "url": _fmt_url(scheme, host, port, path),
        "scheme": scheme, "host": host, "port": port,
        "reachable": False, "findings": [],
    }
    if not host:
        record["error"] = "could not parse a hostname from target"
        return record

    # 1 — Fingerprint
    final, chain = fetch_chain(scheme, host, port, path, timeout=timeout)
    record["redirect_chain"] = chain
    if not final:
        record["error"] = "no HTTP response"
        return record
    record["reachable"] = True

    hdrs = final["headers"]
    record["fingerprint"] = {
        "status":         final["status"],
        "final_url":      _fmt_url(final["scheme"], final["host"],
                                   final["port"], final["path"]),
        "server":         hdrs.get("server", ""),
        "powered_by":     hdrs.get("x-powered-by", ""),
        "title":          _extract_title(final["body"]),
        "content_length": len(final["body"]),
        "technologies":   detect_tech(hdrs, final["body"]),
    }

    # Headers + cookies
    present, missing, sec_find = audit_security_headers(hdrs, final["scheme"])
    record["security_headers"] = {"present": present, "missing": missing}
    cookies, cookie_find = parse_cookies(hdrs, final["scheme"])
    record["cookies"] = cookies
    record["findings"].extend(sec_find)
    record["findings"].extend(cookie_find)

    # 2 — TLS — inspect whichever endpoint actually speaks TLS: the original
    # target if it was https, otherwise the final endpoint if a redirect
    # upgraded the connection to https.
    tls_host, tls_port = None, None
    if scheme == "https":
        tls_host, tls_port = host, port
    elif final["scheme"] == "https":
        tls_host, tls_port = final["host"], final["port"]
    if tls_host:
        tls = inspect_tls(tls_host, tls_port, sni=tls_host, timeout=timeout)
        record["tls"] = tls
        record["findings"].extend(tls.get("findings", []))

    # 3 — Content surface (against the final host after redirects)
    content = content_surface(final["scheme"], final["host"],
                              final["port"], timeout=min(timeout, 8.0))
    record["content"] = {k: v for k, v in content.items() if k != "findings"}
    record["findings"].extend(content["findings"])

    # 4 — nmap http-NSE (opt-in — it is the slow part)
    if include_nse:
        nse = nmap_http_nse(final["host"], final["port"])
        record["nse"] = nse
        for sid, out in nse.items():
            if sid == "_error":
                continue
            sev = "HIGH" if sid.startswith("http-vuln") else "INFO"
            record["findings"].append(
                {"severity": sev, "title": f"nmap {sid}",
                 "detail": out[:300]})

    record["finding_count"] = len(record["findings"])
    record["severity_counts"] = _severity_counts(record["findings"])
    return record


def scan_configurabulator_host(host: dict, timeout: float = 10.0,
                               include_nse: bool = False) -> list[dict]:
    """
    Auto-run helper: given a Configurabulator host dict, web-scan every open
    web port and return a list of web records (one per web port).
    """
    ip      = host.get("ip", "")
    records: list[dict] = []
    for p in host.get("ports", []):
        num = p.get("port")
        svc = (p.get("service") or "").lower()
        is_web = num in WEB_PORTS or "http" in svc
        if not is_web or not ip:
            continue
        scheme = WEB_PORTS.get(num, "https" if "ssl" in svc or "https" in svc
                               else "http")
        rec = scan_target(f"{ip}:{num}", timeout=timeout,
                          include_nse=include_nse, default_scheme=scheme)
        rec["host_ip"] = ip
        records.append(rec)
    return records


def _severity_counts(findings: list) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── Standalone CLI ────────────────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    if not argv:
        print("usage: python3 web_scan.py <url|host[:port]> [--nse]",
              file=sys.stderr)
        return 2
    include_nse = "--nse" in argv
    targets = [a for a in argv if not a.startswith("--")]
    out = [scan_target(t, include_nse=include_nse) for t in targets]
    print(json.dumps(out if len(out) > 1 else out[0], indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
