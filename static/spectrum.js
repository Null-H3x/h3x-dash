/* ─────────────────────────────────────────────────────────────────────────
   spectrum.js — Spectrum flow: Inventory → Connect API → Functions → PCAP/Hashcat.
   ───────────────────────────────────────────────────────────────────────── */
(function () {
'use strict';

let TREE = [];
let PRODUCTS = [];
const expanded = {};

/* ── utils ──────────────────────────────────────────────────────────────── */
function ts() { return new Date().toISOString().slice(11, 19); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function logTo(id, cls, msg) {
  const el = document.getElementById(id); if (!el) return;
  el.innerHTML += `\n<span class="${cls}">[${ts()}] ${esc(msg)}</span>`;
  el.scrollTop = el.scrollHeight;
}
const slog  = (m, c = 't-info') => logTo('api-term', c, m);
const fnlog = (m, c = 't-info') => logTo('fn-term', c, m);
const hclog = (m, c = 't-info') => logTo('hc-term', c, m);

async function api(url, opts) {
  const r = await fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
  return body;
}
function dot(o) {
  return o === true ? '<span class="status-dot pulse"></span>'
    : o === false ? '<span class="status-dot red"></span>'
    : '<span class="status-dot orange"></span>';
}
function tierBadge(t) {
  return t === 'full' ? '<span class="badge badge-green">FULL REMOTE</span>'
    : '<span class="badge badge-warning">MANAGED</span>';
}

/* ── tabs ───────────────────────────────────────────────────────────────── */
window.sTab = function (t) {
  ['s-inv', 's-conn', 's-fn', 's-pcap'].forEach(x =>
    document.getElementById('view-' + x).classList.toggle('hidden', x !== t));
  document.querySelectorAll('.subtab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === t));
  if (t === 's-fn')  { fnRecon(true); }
  if (t === 's-conn'){ fillApiDevices(); }
  if (t === 's-pcap'){ loadPcaps(); }
};

/* ── inventory ──────────────────────────────────────────────────────────── */
async function loadTree() {
  try {
    const d = await api('/api/implants/tree?class=spectrum');
    TREE = d.tree || [];
    PRODUCTS = (d.products || []).filter(p => p.class === 'spectrum');
    fillSpProduct();
    renderTree();
    const s = d.stats || {};
    document.getElementById('ss-prod').textContent = s.instances ?? '—';
    document.getElementById('ss-conn').textContent = s.api_connected ?? '—';
    document.getElementById('ss-hs').textContent   = '—';
    document.getElementById('ss-qhc').textContent  = '—';
    // Pull live recon for HS count
    api('/api/wireless/recon').then(r => {
      document.getElementById('ss-hs').textContent = r.handshakes ?? 0;
    }).catch(() => {});
    api('/api/wireless/pcap').then(p => {
      const q = (p.items || []).filter(x => x.state === 'queued').length;
      document.getElementById('ss-qhc').textContent = q;
    }).catch(() => {});
    fillApiDevices();
  } catch (e) {
    document.getElementById('tree-s').innerHTML =
      '<div class="text-red" style="padding:1.5rem">load failed: ' + esc(e.message) + '</div>';
  }
}
function renderTree() {
  const root = document.getElementById('tree-s'); if (!root) return;
  root.innerHTML = TREE.map(p => {
    const open = !!expanded[p.id];
    const isPineapple = p.id === 'pineapple';
    const children = (p.instances || []).map(i => {
      const apiBadge = isPineapple
        ? (i.api_connected ? '<span class="badge badge-green">API</span>' : '<span class="badge badge-muted">no API</span>')
        : '<span class="badge badge-muted">capture</span>';
      const action = isPineapple
        ? `<button class="btn btn-cyan btn-sm" onclick="sGoConnect('${i.id}')">→ CONNECT API</button>`
        : `<button class="btn btn-cyan btn-sm" onclick="sValidate('${i.id}')">VALIDATE</button>`;
      return `
      <div class="tree-inst">
        ${dot(i.online)}
        <span class="inst-id" onclick="sEditInst('${i.id}', this)">${esc(i.device_id)}</span>
        <span class="text-muted" style="font-size:11px">${esc(i.host)}${i.port ? ':' + i.port : ''}</span>
        ${apiBadge}
        <span class="ml-auto flex gap-1">
          ${action}
          <button class="btn btn-red btn-sm" onclick="sRemove('${i.id}')">✕</button>
        </span>
      </div>`; }).join('');
    return `<div class="tree-product">
      <div class="tree-prod-row" onclick="sToggle('${p.id}')">
        <span class="tree-toggle">${open ? '－' : '＋'}</span>
        <span class="tree-prod-name">${esc(p.name)}</span>
        <span class="badge ${p.cap_badge}">${esc(p.capability)}</span>
        ${tierBadge(p.tier)}
        <span class="ml-auto tree-prod-meta">${p.total} unit(s) · ${esc(p.transport_label)}</span>
      </div>
      <div class="tree-children ${open ? '' : 'collapsed'}">
        ${children || '<div class="tree-inst text-muted">no units yet — connect &amp; add above</div>'}
      </div>
    </div>`;
  }).join('');
}
window.sToggle = function (pid) { expanded[pid] = !expanded[pid]; renderTree(); };
window.sRemove = async function (id) {
  if (!confirm('Remove this Pineapple from inventory?')) return;
  try { await api('/api/implants/instance/' + id, { method: 'DELETE' }); await loadTree(); }
  catch (e) { slog('remove failed: ' + e.message, 't-err'); }
};
window.sEditInst = function (id, el) {
  const cur = el.textContent;
  const inp = document.createElement('input'); inp.className = 'inst-id-input'; inp.value = cur;
  el.replaceWith(inp); inp.focus(); inp.select();
  let done = false;
  async function commit() {
    if (done) return; done = true;
    const v = inp.value.trim();
    if (v && v !== cur) {
      try { await api('/api/implants/instance/' + id, { method: 'PATCH', body: JSON.stringify({ device_id: v }) }); }
      catch (e) { slog('rename failed: ' + e.message, 't-err'); }
    }
    await loadTree();
  }
  inp.addEventListener('blur', commit);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') { done = true; loadTree(); } });
};
function fillSpProduct() {
  const sel = document.getElementById('sp-product'); if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = PRODUCTS.map(p =>
    `<option value="${esc(p.id)}" data-host="${esc(p.default_host || '')}" data-port="${p.default_port || ''}">${esc(p.name)}</option>`).join('');
  if (cur) sel.value = cur;
  spPrefill();
}
window.spPrefill = function () {
  const sel = document.getElementById('sp-product');
  const opt = sel && sel.options[sel.selectedIndex]; if (!opt) return;
  document.getElementById('sp-host').value = opt.dataset.host || '';
  document.getElementById('sp-port').value = opt.dataset.port || '';
};
window.connectSpectrumDevice = async function () {
  const sel = document.getElementById('sp-product');
  const body = {
    product_id: (sel && sel.value) || 'pineapple',
    host:       document.getElementById('sp-host').value.trim() || undefined,
    port:       parseInt(document.getElementById('sp-port').value, 10) || undefined,
    device_id:  document.getElementById('sp-name').value.trim() || undefined,
  };
  slog(`probing ${body.host}:${body.port}…`);
  try {
    const d = await api('/api/implants/connect-add', { method: 'POST', body: JSON.stringify(body) });
    if (d.status === 'added') {
      const next = body.product_id === 'pineapple' ? ' Proceed to CONNECT API.' : '';
      slog(`added ${d.instance.device_id} (${d.validation?.detail || ''}).${next}`, 't-ok');
      await loadTree();
    } else {
      slog(`add failed: ${d.validation?.detail || 'unreachable'}`, 't-err');
    }
  } catch (e) { slog('add failed: ' + e.message, 't-err'); }
};

/* ── Connect API ────────────────────────────────────────────────────────── */
function fillApiDevices() {
  const sel = document.getElementById('api-device'); if (!sel) return;
  // The REST API flow (recon / portal / deauth) is Pineapple-specific.
  const insts = TREE.filter(p => p.id === 'pineapple').flatMap(p => p.instances || []);
  sel.innerHTML = insts.length
    ? insts.map(i => `<option value="${i.id}">${esc(i.device_id)} (${esc(i.host)}:${i.port || ''})</option>`).join('')
    : '<option value="">no Pineapples yet</option>';
}
window.sGoConnect = function (id) { sTab('s-conn'); setTimeout(() => { const s = document.getElementById('api-device'); if (s) s.value = id; }, 50); };
window.sValidate = async function (id) {
  slog('validating callback…');
  try {
    const v = await api('/api/implants/instance/' + id + '/validate', { method: 'POST' });
    const r = v.result || {};
    slog(`${r.device_id} → ${r.detail || ''}${r.latency_ms ? ' · ' + r.latency_ms + 'ms' : ''}`,
         r.status === 'ok' ? 't-ok' : r.status === 'manual' ? 't-warn' : 't-err');
    await loadTree();
  } catch (e) { slog('validate failed: ' + e.message, 't-err'); }
};
window.apiConnect = async function () {
  const id = document.getElementById('api-device').value;
  if (!id) { slog('no device selected', 't-err'); return; }
  const body = {
    username: document.getElementById('api-user').value,
    password: document.getElementById('api-pass').value,
  };
  slog(`POST /api/login (user=${body.username})…`);
  try {
    const d = await api('/api/wireless/api-connect', { method: 'POST', body: JSON.stringify({ instance_id: id, ...body }) });
    if (d.status === 'connected') {
      slog('200 OK — session authenticated', 't-ok');
      const info = d.info || {};
      document.getElementById('api-info').innerHTML = `
        <div><span class="text-muted">model:</span> ${esc(info.model || 'WiFi Pineapple')} · <span class="text-muted">firmware:</span> ${esc(info.firmware || '—')} · <span class="text-muted">serial:</span> ${esc(info.serial || '—')}</div>
        <div class="mt-1"><span class="text-muted">radios:</span> ${esc(info.radios || '—')} · <span class="text-muted">PineAP:</span> ${esc(info.pineap || '—')}</div>
        <div class="mt-1"><span class="text-muted">session:</span> <span class="text-green">authenticated</span> · <span class="text-muted">at:</span> ${esc(info.connected_at || '')}</div>`;
      await loadTree();
    } else {
      slog('auth failed: ' + (d.message || ''), 't-err');
    }
  } catch (e) { slog('connect failed: ' + e.message, 't-err'); }
};
window.apiDisconnect = async function () {
  const id = document.getElementById('api-device').value;
  if (!id) return;
  try { await api('/api/wireless/api-disconnect', { method: 'POST', body: JSON.stringify({ instance_id: id }) });
    document.getElementById('api-info').innerHTML = '<span class="text-muted">not connected</span>';
    slog('session terminated', 't-warn'); await loadTree();
  } catch (e) { slog('disconnect failed: ' + e.message, 't-err'); }
};

/* ── Functions ──────────────────────────────────────────────────────────── */
async function loadWirelessConfig() {
  try {
    const d = await api('/api/wireless/config');
    const ep = d.evil_portal || {};
    const tpl = document.getElementById('ep-template');
    if (tpl) tpl.innerHTML = (d.templates || []).map(t => `<option ${t === ep.template ? 'selected' : ''}>${esc(t)}</option>`).join('');
    if (ep.ssid)     document.getElementById('ep-ssid').value = ep.ssid;
    if (ep.redirect) document.getElementById('ep-redirect').value = ep.redirect;
    if (Array.isArray(ep.capture_fields)) {
      document.getElementById('ep-f-user').checked  = ep.capture_fields.includes('username');
      document.getElementById('ep-f-pass').checked  = ep.capture_fields.includes('password');
      document.getElementById('ep-f-email').checked = ep.capture_fields.includes('email');
      document.getElementById('ep-f-mfa').checked   = ep.capture_fields.includes('mfa');
    }
    document.getElementById('ep-cleartext').checked = !!ep.cleartext_log;
    document.getElementById('ep-https').checked     = !!ep.https;
  } catch (e) { /* leave defaults */ }
}
window.fnRecon = async function (silent) {
  try {
    const d = await api('/api/wireless/recon');
    const aps = d.aps || [];
    document.getElementById('ap-tbody').innerHTML = aps.map(a => `
      <tr>
        <td class="text-cyan">${esc(a.ssid)}</td>
        <td class="text-muted mono">${esc(a.bssid)}</td>
        <td><span class="badge ${a.band === '5G' ? 'badge-violet' : 'badge-info'}">${esc(a.band)}</span></td>
        <td>${a.channel}</td>
        <td><span class="badge ${a.enc === 'WPA3' ? 'badge-green' : 'badge-warning'}">${esc(a.enc)}</span></td>
        <td>${a.clients}</td>
        <td>${a.handshake ? '<span class="badge badge-green">CAPTURED</span>' : '<span class="text-muted">—</span>'}</td>
      </tr>`).join('');
    const sel = document.getElementById('dh-target');
    if (sel) sel.innerHTML = aps.map(a => `<option value="${esc(a.bssid)}">${esc(a.ssid)} (${esc(a.bssid)}) · ${esc(a.band)} ch${a.channel}</option>`).join('');
    if (!silent) fnlog(`recon: ${d.ap_count} APs (${d.ap_24}×2.4 / ${d.ap_5g}×5G), ${d.clients} clients, ${d.handshakes} handshakes`, d.online ? 't-ok' : 't-warn');
  } catch (e) { fnlog('recon failed: ' + e.message, 't-err'); }
};
function epBody() {
  const fields = [];
  if (document.getElementById('ep-f-user').checked)  fields.push('username');
  if (document.getElementById('ep-f-pass').checked)  fields.push('password');
  if (document.getElementById('ep-f-email').checked) fields.push('email');
  if (document.getElementById('ep-f-mfa').checked)   fields.push('mfa');
  return {
    ssid:           document.getElementById('ep-ssid').value,
    template:       document.getElementById('ep-template').value,
    redirect:       document.getElementById('ep-redirect').value,
    capture_fields: fields,
    cleartext_log:  document.getElementById('ep-cleartext').checked,
    https:          document.getElementById('ep-https').checked,
  };
}
window.fnPortalArm = async function () {
  try { const d = await api('/api/wireless/evil-portal', { method: 'POST', body: JSON.stringify(epBody()) }); fnlog(d.message, d.live ? 't-ok' : 't-warn'); loadTree(); }
  catch (e) { fnlog('portal failed: ' + e.message, 't-err'); }
};
window.fnPortalStop = async function () {
  try { await api('/api/wireless/evil-portal/stop', { method: 'POST' }); fnlog('portal stopped', 't-warn'); }
  catch (e) { fnlog('stop failed: ' + e.message, 't-err'); }
};
window.fnDeauthStart = async function () {
  const body = {
    target_bssid: document.getElementById('dh-target').value,
    client:       document.getElementById('dh-client').value,
    band:         document.getElementById('dh-band').value,
    bursts:       document.getElementById('dh-bursts').value,
    capture:      document.getElementById('dh-capture').value,
  };
  try { const d = await api('/api/wireless/deauth', { method: 'POST', body: JSON.stringify(body) }); fnlog(d.message, d.live ? 't-ok' : 't-warn'); loadTree(); }
  catch (e) { fnlog('deauth failed: ' + e.message, 't-err'); }
};
window.fnDeauthStop = async function () {
  try { await api('/api/wireless/deauth/stop', { method: 'POST' }); fnlog('deauth stopped', 't-warn'); }
  catch (e) { fnlog('stop failed: ' + e.message, 't-err'); }
};

/* ── PCAP / Hashcat ─────────────────────────────────────────────────────── */
async function loadPcaps() {
  try {
    const d = await api('/api/wireless/pcap');
    const items = d.items || [];
    document.getElementById('pcap-tbody').innerHTML = items.length ? items.map(p => {
      const st = ({
        captured: '<span class="badge badge-info">CAPTURED</span>',
        queued:   '<span class="badge badge-warning">QUEUED</span>',
        running:  '<span class="badge badge-violet">RUNNING</span>',
        cracked:  '<span class="badge badge-green">CRACKED</span>',
        failed:   '<span class="badge badge-danger">FAILED</span>',
      })[p.state] || `<span class="badge badge-muted">${esc(p.state)}</span>`;
      const cracked = p.cracked_value ? ` <span class="text-green" style="font-size:11px">→ ${esc(p.cracked_value)}</span>` : '';
      return `<tr>
        <td class="text-cyan">${esc(p.name)}${cracked}</td>
        <td><span class="badge ${p.type === 'handshake' ? 'badge-warning' : p.type === 'pmkid' ? 'badge-orange' : 'badge-violet'}">${esc(p.type)}</span></td>
        <td class="text-muted">${esc(p.source)}</td>
        <td class="text-muted">${esc(p.size)}</td>
        <td class="text-muted" style="font-size:11px">${esc(p.hashcat_mode)}</td>
        <td>${st}</td>
        <td class="flex gap-1">
          <button class="btn btn-green btn-sm" onclick="hcQueue('${p.id}')">→ QUEUE</button>
          <button class="btn btn-red btn-sm"   onclick="pcapRemove('${p.id}')">✕</button>
        </td></tr>`;
    }).join('')
      : '<tr><td colspan="7" class="text-muted" style="text-align:center;padding:1rem">no captures yet</td></tr>';
    document.getElementById('ss-qhc').textContent = items.filter(x => x.state === 'queued').length;
  } catch (e) {
    document.getElementById('pcap-tbody').innerHTML = '<tr><td colspan="7" class="text-red">load failed: ' + esc(e.message) + '</td></tr>';
  }
}
window.hcQueue = async function (id) {
  try { await api('/api/wireless/pcap/' + id + '/queue', { method: 'POST' }); hclog('queued for hashcat', 't-info'); await loadPcaps(); }
  catch (e) { hclog('queue failed: ' + e.message, 't-err'); }
};
window.pcapRemove = async function (id) {
  if (!confirm('Delete this capture?')) return;
  try { await api('/api/wireless/pcap/' + id, { method: 'DELETE' }); await loadPcaps(); }
  catch (e) { hclog('delete failed: ' + e.message, 't-err'); }
};
window.hcRun = async function () {
  const body = { wordlist: document.getElementById('hc-wl').value, rules: document.getElementById('hc-rule').value };
  try {
    const d = await api('/api/wireless/hashcat/run', { method: 'POST', body: JSON.stringify(body) });
    (d.plan || []).forEach(p => hclog(p.cmd, 't-info'));
    (d.outcomes || []).forEach(o => hclog(o.msg, o.cls || 't-info'));
    await loadPcaps();
  } catch (e) { hclog('run failed: ' + e.message, 't-err'); }
};
window.hcClearLog = function () { document.getElementById('hc-term').innerHTML = '<span class="t-dim">// cleared //</span>'; };

document.addEventListener('DOMContentLoaded', function () {
  loadTree(); loadWirelessConfig(); fnRecon(true); loadPcaps();
});
})();
