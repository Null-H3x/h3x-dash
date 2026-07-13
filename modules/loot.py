"""
H3x-Dash LootManager
Generates timestamped HTML and JSON penetration test reports.
"""
import html
import json
from datetime import datetime
from pathlib import Path

from config import H3xConfig


class LootManager:

    def __init__(self):
        H3xConfig.init_dirs()
        self._report_dir = H3xConfig.REPORT_DIR
        self._loot_dir   = H3xConfig.LOOT_DIR

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_report(self, scan_results: dict, sessions: list, fmt: str = 'html') -> dict:
        # Case-insensitive format; anything but 'json' renders the styled HTML.
        fmt = (fmt or 'html').strip().lower()
        if fmt not in ('html', 'json'):
            fmt = 'html'
        ts       = datetime.now()
        ts_str   = ts.strftime('%Y%m%d_%H%M%S')
        stem     = f'h3x-dash_report_{ts_str}'
        hosts    = scan_results.get('hosts', [])
        meta     = scan_results.get('meta', {})

        report = {
            'generated':    ts.isoformat(),
            'scan_target':  meta.get('target', 'unknown'),
            'scan_command': meta.get('command', ''),
            'hosts':        hosts,
            'sessions':     sessions,
            'vuln_summary': self._vuln_summary(hosts),
            'meta':         meta,
        }

        try:
            self._report_dir.mkdir(parents=True, exist_ok=True)
            # Always persist JSON
            json_path = self._report_dir / f'{stem}.json'
            json_path.write_text(json.dumps(report, indent=2, default=str))

            if fmt == 'html':
                html_path = self._report_dir / f'{stem}.html'
                html_path.write_text(self._render_html(report), encoding='utf-8')
                out_path = html_path
            else:
                out_path = json_path
        except OSError as exc:
            return {'status': 'error',
                    'message': f'report write failed: {exc}'}

        size_kb = round(out_path.stat().st_size / 1024, 1)
        return {
            'status':   'ok',
            'filename': out_path.name,
            'path':     str(out_path),
            'size_kb':  size_kb,
            'size':     out_path.stat().st_size,
        }

    def list_reports(self) -> list:
        reports = []
        for f in sorted(self._report_dir.glob('h3x-dash_report_*'), reverse=True):
            try:
                if not f.is_file():
                    continue
                stat = f.stat()
            except OSError:
                continue   # broken symlink / vanished mid-listing
            reports.append({
                'filename': f.name,
                'size_kb':  round(stat.st_size / 1024, 1),
                'created':  datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'format':   f.suffix.lstrip('.').upper(),
            })
        return reports

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _vuln_summary(self, hosts: list) -> dict:
        critical = warning = info = 0
        for h in hosts:
            for p in h.get('ports', []):
                r = p.get('risk', 'info')
                if r == 'danger':    critical += 1
                elif r == 'warning': warning  += 1
                else:                info     += 1
        return {'critical': critical, 'warning': warning, 'info': info,
                'total': critical + warning + info}

    # ── HTML report renderer ──────────────────────────────────────────────────

    def _render_html(self, data: dict) -> str:
        vs = data['vuln_summary']

        # ── Host cards ────────────────────────────────────────────────────────
        host_cards = ''
        for h in data['hosts']:
            ports_rows = ''
            for p in h.get('ports', []):
                rc = {'danger': '#ff4444', 'warning': '#ff8c00', 'info': '#0ff0fc'}.get(
                    p.get('risk', 'info'), '#888')
                badge_bg = {'danger': '#2a0000', 'warning': '#1a0f00', 'info': '#001a1f'}.get(
                    p.get('risk', 'info'), '#111')
                p_port    = html.escape(str(p.get('port', '')))
                p_proto   = html.escape(str(p.get('protocol','tcp')).upper())
                p_service = html.escape(str(p.get('service','')))
                p_version = html.escape(str(p.get('version','—')))
                p_risk    = html.escape(str(p.get('risk','info')).upper())
                ports_rows += f'''
                <tr>
                  <td style="color:{rc};font-weight:500">{p_port}</td>
                  <td style="color:#888">{p_proto}</td>
                  <td style="color:{rc}">{p_service}</td>
                  <td style="color:#aaa;font-size:11px">{p_version}</td>
                  <td><span style="background:{badge_bg};color:{rc};
                      border:1px solid {rc};font-size:10px;padding:1px 7px;
                      border-radius:3px;letter-spacing:.1em">{p_risk}</span></td>
                </tr>'''
            type_color = {
                'gateway': '#D85A30', 'server': '#1D9E75', 'workstation': '#378ADD',
                'iot': '#BA7517', 'switch': '#534AB7', 'scanner': '#D4537E',
            }.get(h.get('type', 'unknown'), '#888')
            h_ip   = html.escape(str(h.get('ip','')))
            h_type = html.escape(str(h.get('type','unknown')).upper())
            h_os   = html.escape(str(h.get('os','Unknown OS')))
            host_cards += f'''
            <div class="host-card">
              <div class="host-header">
                <span class="host-ip">{h_ip}</span>
                <span class="host-badge" style="border-color:{type_color};color:{type_color}">
                  {h_type}</span>
                <span class="host-os">{h_os}</span>
                <span class="host-portcount">{len(h.get("ports",[]))} port(s)</span>
              </div>
              {"<table class='port-table'><thead><tr><th>PORT</th><th>PROTO</th><th>SERVICE</th><th>VERSION</th><th>RISK</th></tr></thead><tbody>" + ports_rows + "</tbody></table>" if ports_rows else "<p class='no-ports'>No open ports recorded.</p>"}
            </div>'''

        if not host_cards:
            host_cards = '<p class="empty-msg">No hosts with open ports in this scan.</p>'

        # ── Session rows ──────────────────────────────────────────────────────
        session_rows = ''
        for s in data.get('sessions', []):
            # Session metadata (info/user/target) can carry attacker-controlled
            # strings from a compromised host — escape every field.
            s_id   = html.escape(str(s.get("id", "")))
            s_type = html.escape(str(s.get("type", "")))
            s_tgt  = html.escape(str(s.get("target", "")))
            s_user = html.escape(str(s.get("user", "")))
            s_plat = html.escape(f'{s.get("platform","")} {s.get("arch","")}'.strip())
            s_info = html.escape(str(s.get("info", "")))
            session_rows += f'''
            <tr>
              <td style="color:#39ff14">{s_id}</td>
              <td style="color:#9b30ff">{s_type}</td>
              <td style="color:#0ff0fc">{s_tgt}</td>
              <td>{s_user}</td>
              <td style="color:#888">{s_plat}</td>
              <td style="color:#555;font-size:11px">{s_info}</td>
            </tr>'''

        sessions_section = (
            f'<table class="data-table"><thead><tr>'
            f'<th>ID</th><th>TYPE</th><th>TARGET</th>'
            f'<th>USER</th><th>PLATFORM</th><th>INFO</th>'
            f'</tr></thead><tbody>{session_rows}</tbody></table>'
            if session_rows else
            '<p class="empty-msg">No active sessions captured.</p>'
        )

        # ── Escaped meta (scan_target / command come from user/XML input) ──────
        e_generated = html.escape(str(data["generated"]))
        e_target    = html.escape(str(data["scan_target"]))
        e_command   = html.escape(str(data.get("scan_command", "")))
        cmd_block   = (f"<div class='cmd-block'>$ {e_command}</div>"
                       if data.get("scan_command") else "")

        # ── Full HTML ─────────────────────────────────────────────────────────
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>H3x-Dash Report — {e_generated}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d12;color:#0ff0fc;font-family:"Share Tech Mono","Courier New",monospace;padding:2rem;line-height:1.6}}
h1{{font-family:"Rajdhani",sans-serif;font-size:32px;letter-spacing:.1em;color:#fff;margin-bottom:.25rem}}
h2{{font-size:12px;color:#9b30ff;letter-spacing:.25em;margin:2.5rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid #1e1e2e}}
.meta{{font-size:11px;color:#555;margin-bottom:2rem;letter-spacing:.05em}}
.meta span{{color:#888;margin-right:2rem}}
.stat-grid{{display:flex;gap:12px;margin-bottom:2.5rem;flex-wrap:wrap}}
.stat{{background:#13131a;border:1px solid #1e1e2e;padding:1rem 1.5rem;border-radius:6px;min-width:110px;text-align:center}}
.stat-val{{font-family:"Rajdhani",sans-serif;font-size:32px;font-weight:700;line-height:1}}
.stat-label{{font-size:9px;color:#555;letter-spacing:.2em;margin-top:4px}}
.host-card{{background:#13131a;border:1px solid #1e1e2e;border-radius:6px;margin-bottom:12px;overflow:hidden}}
.host-header{{display:flex;align-items:center;gap:12px;padding:.75rem 1rem;border-bottom:1px solid #1e1e2e;flex-wrap:wrap}}
.host-ip{{font-size:15px;color:#fff;font-weight:500}}
.host-badge{{font-size:10px;border:1px solid;padding:1px 8px;border-radius:3px;letter-spacing:.1em}}
.host-os{{font-size:11px;color:#555;margin-left:auto}}
.host-portcount{{font-size:11px;color:#9b30ff}}
.port-table,.data-table{{width:100%;border-collapse:collapse;font-size:12px}}
.port-table th,.data-table th{{padding:6px 12px;text-align:left;color:#444;font-size:9px;letter-spacing:.2em;border-bottom:1px solid #1e1e2e}}
.port-table td,.data-table td{{padding:7px 12px;border-bottom:1px solid #0d0d12}}
.no-ports,.empty-msg{{font-size:12px;color:#444;padding:1rem;text-align:center}}
.footer{{margin-top:3rem;font-size:10px;color:#2a2a2a;text-align:center;letter-spacing:.2em}}
.cmd-block{{background:#080810;border:1px solid #1a1a2e;border-left:3px solid #39ff14;
            border-radius:4px;padding:.75rem 1rem;font-size:11px;color:#39ff14;
            margin-bottom:2rem;word-break:break-all}}
</style>
</head>
<body>
<h1>// H3x-Dash //</h1>
<div class="meta">
  <span>GENERATED: {e_generated}</span>
  <span>TARGET: {e_target}</span>
  <span>HOSTS: {len(data["hosts"])}</span>
</div>

{cmd_block}

<div class="stat-grid">
  <div class="stat"><div class="stat-val" style="color:#fff">{len(data["hosts"])}</div><div class="stat-label">HOSTS FOUND</div></div>
  <div class="stat"><div class="stat-val" style="color:#ff4444">{vs["critical"]}</div><div class="stat-label">CRITICAL PORTS</div></div>
  <div class="stat"><div class="stat-val" style="color:#ff8c00">{vs["warning"]}</div><div class="stat-label">WARNING PORTS</div></div>
  <div class="stat"><div class="stat-val" style="color:#0ff0fc">{vs["info"]}</div><div class="stat-label">INFO PORTS</div></div>
  <div class="stat"><div class="stat-val" style="color:#39ff14">{len(data["sessions"])}</div><div class="stat-label">SESSIONS</div></div>
</div>

<h2>// HOST ENUMERATION</h2>
{host_cards}

<h2>// ACTIVE SESSIONS</h2>
{sessions_section}

<p class="footer">H3x-Dash // Automated Penetration Framework // Authorized Use Only // {e_generated}</p>
</body>
</html>'''
