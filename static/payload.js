/* ─────────────────────────────────────────────────────────────────────────
   payload.js — Payload flow front-end: Inventory → Arm → Deploy.
   ───────────────────────────────────────────────────────────────────────── */
(function () {
'use strict';

let TREE = [];                  // payload-class product nodes
let PRODUCTS = [];              // [{id,name,transport,default_port}]
let PAYLOADS_ALL = [];          // payload catalog (decorated)
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
const plog = (m, c = 't-ok') => logTo('p-term', c, m);
const dlog = (m, c = 't-ok') => logTo('dep-term', c, m);
const llog = (m, c = 't-ok') => logTo('lib-term', c, m);

async function api(url, opts) {
  const r = await fetch(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || ('HTTP ' + r.status));
  return body;
}
function tierBadge(t) {
  return t === 'full' ? '<span class="badge badge-green">FULL REMOTE</span>'
    : t === 'managed' ? '<span class="badge badge-warning">SSH MANAGED</span>'
    : '<span class="badge badge-muted">AUTHOR ONLY</span>';
}
function dot(o) {
  return o === true ? '<span class="status-dot pulse"></span>'
    : o === false ? '<span class="status-dot red"></span>'
    : '<span class="status-dot orange"></span>';
}
function callbackCell(cs) {
  if (!cs || cs.status === 'n/a') return '<span class="text-muted">none</span>';
  const cb = esc(cs.callback || '');
  if (cs.status === 'landed') {
    return `<span class="badge badge-green">LANDED</span> <span class="text-green" style="font-size:10px">${esc(cs.detail || '')}</span>`;
  }
  if (cs.status === 'waiting') {
    return `<span class="badge badge-warning">${cb}</span> <span class="text-muted" style="font-size:10px">waiting</span>`;
  }
  return `<span class="badge badge-info">${cb}</span> <span class="text-muted" style="font-size:10px">${esc(cs.status)}</span>`;
}
let _cbPoll = null;
function startCallbackPoll() {
  if (_cbPoll) return;
  _cbPoll = setInterval(() => {
    const dash = document.getElementById('view-p-dash');
    if (dash && !dash.classList.contains('hidden')) renderArmed();
  }, 5000);
}

/* ── tabs ───────────────────────────────────────────────────────────────── */
window.pTab = function (t) {
  ['p-dash', 'p-inv', 'p-arm', 'p-deploy', 'p-lib'].forEach(x =>
    document.getElementById('view-' + x).classList.toggle('hidden', x !== t));
  document.querySelectorAll('.subtab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === t));
  if (t === 'p-dash') { loadTree(); renderArmed(); }
  if (t === 'p-arm') { fillArmSelects(); }
  if (t === 'p-deploy') { depAckChanged(); }
  if (t === 'p-lib') { loadSources(); }
};

/* Selection made on the Arm tab; consumed by the Deploy tab's install. */
const SEL = { inst: null, payload: null };

/* ── inventory tree ─────────────────────────────────────────────────────── */
async function loadTree() {
  try {
    const d = await api('/api/implants/tree?class=payload');
    TREE = d.tree || [];
    PRODUCTS = TREE.map(p => ({ id: p.id, name: p.name, transport: p.transport, default_port: null }));
    renderTree();
    const s = d.stats || {};
    document.getElementById('ps-prod').textContent = s.products ?? '—';
    document.getElementById('ps-on').textContent   = s.online   ?? '—';
    document.getElementById('ps-tot').textContent  = s.instances ?? '—';
    document.getElementById('ps-armed').textContent = s.armed   ?? '—';
    fillAddProduct();
  } catch (e) {
    document.getElementById('tree-p').innerHTML =
      '<div class="text-red" style="padding:1.5rem">load failed: ' + esc(e.message) + '</div>';
  }
}
function renderTree() {
  const root = document.getElementById('tree-p');
  root.innerHTML = TREE.map(p => {
    const open = !!expanded[p.id];
    const children = (p.instances || []).map(i => {
      const armed = i.armed_payload
        ? `<span class="badge badge-warning" title="armed">ARMED · ${esc(i.armed_payload)}</span>` : '';
      return `<div class="tree-inst">
        ${dot(i.online)}
        <span class="inst-id" onclick="pEditInst('${i.id}', this)">${esc(i.device_id)}</span>
        <span class="text-muted" style="font-size:11px">${esc(i.host || '(no host)')}${i.port ? ':' + i.port : ''}</span>
        ${armed}
        <span class="ml-auto flex gap-1">
          <button class="btn btn-cyan btn-sm" onclick="pValidate('${i.id}')">VALIDATE</button>
          <button class="btn btn-violet btn-sm" onclick="pGoArmWith('${i.id}')">→ ARM</button>
          <button class="btn btn-red btn-sm" onclick="pRemove('${i.id}')">✕</button>
        </span>
      </div>`;
    }).join('');
    return `<div class="tree-product">
      <div class="tree-prod-row" onclick="pToggle('${p.id}')">
        <span class="tree-toggle">${open ? '－' : '＋'}</span>
        <span class="tree-prod-name">${esc(p.name)}</span>
        <span class="badge ${p.cap_badge}">${esc(p.capability)}</span>
        ${tierBadge(p.tier)}
        <span class="ml-auto tree-prod-meta">${p.online}/${p.total} online · ${p.armed} armed · ${esc(p.transport_label)}</span>
      </div>
      <div class="tree-children ${open ? '' : 'collapsed'}">
        ${children || '<div class="tree-inst text-muted">no instances — use CONNECT &amp; ADD above</div>'}
      </div>
    </div>`;
  }).join('');
}
window.pToggle = function (pid) { expanded[pid] = !expanded[pid]; renderTree(); };
window.pRemove = async function (id) {
  if (!confirm('Remove this instance from inventory?')) return;
  try { await api('/api/implants/instance/' + id, { method: 'DELETE' }); plog('removed instance', 't-warn'); await loadTree(); }
  catch (e) { plog('remove failed: ' + e.message, 't-err'); }
};
window.pEditInst = function (id, el) {
  const cur = el.textContent;
  const inp = document.createElement('input');
  inp.className = 'inst-id-input'; inp.value = cur;
  el.replaceWith(inp); inp.focus(); inp.select();
  let done = false;
  async function commit() {
    if (done) return; done = true;
    const v = inp.value.trim();
    if (v && v !== cur) {
      try { await api('/api/implants/instance/' + id, { method: 'PATCH', body: JSON.stringify({ device_id: v }) }); plog('renamed → ' + v); }
      catch (e) { plog('rename failed: ' + e.message, 't-err'); }
    }
    await loadTree();
  }
  inp.addEventListener('blur', commit);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') { done = true; loadTree(); } });
};
window.pValidate = async function (id) {
  plog('validating callback…', 't-info');
  try {
    const v = await api('/api/implants/instance/' + id + '/validate', { method: 'POST' });
    const r = v.result;
    const cls = r.status === 'ok' ? 't-ok' : r.status === 'manual' ? 't-warn' : 't-err';
    plog(`${r.device_id} → ${r.detail}${r.latency_ms ? ' · ' + r.latency_ms + 'ms' : ''}`, cls);
    await loadTree();
  } catch (e) { plog('validate failed: ' + e.message, 't-err'); }
};
window.pGoArmWith = function (id) { pTab('p-arm'); setTimeout(() => { const s = document.getElementById('arm-inst'); if (s) { s.value = id; armRefresh(); } }, 50); };

/* ── connect-to-add ─────────────────────────────────────────────────────── */
function fillAddProduct() {
  const sel = document.getElementById('add-product');
  if (!sel) return;
  sel.innerHTML = TREE.map(p => `<option value="${p.id}" data-tr="${p.transport}" data-port="${p.default_port || ''}">${esc(p.name)}</option>`).join('');
  addPrefill();
}
window.addPrefill = function () {
  const sel = document.getElementById('add-product');
  const opt = sel.options[sel.selectedIndex]; if (!opt) return;
  const tr = opt.dataset.tr;
  document.getElementById('add-port').value = opt.dataset.port || (tr === 'ssh' ? 22 : tr === 'wifi' ? 80 : '');
  document.getElementById('add-host').placeholder = tr === 'usb' ? '(usb)' : '';
  document.getElementById('add-user').value = tr === 'ssh' ? 'root' : '';
  document.getElementById('add-status').textContent =
    tr === 'usb' ? 'USB device — added without callback validation.' : 'callback validated before add';
};
window.clearAdd = function () {
  ['add-host', 'add-port', 'add-user', 'add-name', 'add-notes'].forEach(id => document.getElementById(id).value = '');
  addPrefill();
};
window.connectAndAdd = async function () {
  const body = {
    product_id: document.getElementById('add-product').value,
    host:       document.getElementById('add-host').value.trim() || undefined,
    port:       parseInt(document.getElementById('add-port').value, 10) || undefined,
    username:   document.getElementById('add-user').value,
    device_id:  document.getElementById('add-name').value.trim() || undefined,
    notes:      document.getElementById('add-notes').value,
  };
  plog(`connecting to ${body.host || '(usb)'}…`, 't-info');
  try {
    const d = await api('/api/implants/connect-add', { method: 'POST', body: JSON.stringify(body) });
    if (d.status === 'added') {
      const v = d.validation || {};
      plog(`added ${d.instance.device_id} — ${v.detail || ''}${v.latency_ms ? ' · ' + v.latency_ms + 'ms' : ''}`, 't-ok');
      clearAdd(); await loadTree();
    } else {
      plog(`add failed: ${d.validation?.detail || 'unreachable'}`, 't-err');
    }
  } catch (e) { plog('add failed: ' + e.message, 't-err'); }
};

/* ── ARM ────────────────────────────────────────────────────────────────── */
async function fillArmSelects() {
  const insts = TREE.flatMap(p => (p.instances || []).map(i => ({ ...i, _product: p })));
  const instSel = document.getElementById('arm-inst');
  instSel.innerHTML =
    insts.length
      ? insts.map(i => `<option value="${i.id}">${esc(i.device_id)}  —  ${esc(i._product.name)}</option>`).join('')
      : '<option value="">(no instances — add one in Inventory)</option>';
  // Preserve a prior selection across tab switches so revisiting ARM (then
  // DEPLOY) doesn't silently re-target the first instance/payload in the list.
  if (SEL.inst && insts.some(i => i.id === SEL.inst)) {
    instSel.value = SEL.inst;
  }
  await armRefresh();
}
window.armRefresh = async function () {
  const id = document.getElementById('arm-inst').value;
  const insts = TREE.flatMap(p => (p.instances || []).map(i => ({ ...i, _product: p })));
  const inst = insts.find(x => x.id === id);
  if (!inst) {
    document.getElementById('arm-payload').innerHTML = '';
    document.getElementById('arm-meta').textContent = '—';
    document.getElementById('arm-pay-meta').textContent = '—';
    SEL.inst = null;
    SEL.payload = null;
    if (typeof depAckChanged === 'function') depAckChanged();
    return;
  }
  try {
    const d = await api('/api/implants/payloads?product=' + encodeURIComponent(inst._product.id));
    const pays = d.payloads || [];
    const paySel = document.getElementById('arm-payload');
    paySel.innerHTML = pays.length
      ? pays.map(p => `<option>${esc(p.name)}</option>`).join('')
      : '<option value="">(no compatible payloads)</option>';
    // Restore a previously-chosen payload if it's still compatible.
    if (SEL.payload && pays.some(p => p.name === SEL.payload)) {
      paySel.value = SEL.payload;
    }
    PAYLOADS_ALL = pays;
    document.getElementById('arm-meta').innerHTML =
      `Product: <span class="text-cyan">${esc(inst._product.name)}</span> · `
      + `Transport: ${esc(inst._product.transport_label)} · ${tierBadge(inst._product.tier)} · `
      + `Host: <span class="text-cyan">${esc(inst.host || '(usb)')}${inst.port ? ':' + inst.port : ''}</span>`
      + (inst.armed_payload ? ` · <span class="badge badge-warning">ARMED · ${esc(inst.armed_payload)}</span>` : '');
    const cur = document.getElementById('arm-payload').value;
    const pm = pays.find(x => x.name === cur);
    document.getElementById('arm-pay-meta').innerHTML = pm
      ? `Lang: <span class="text-cyan">${esc(pm.lang)}</span> · ATT&CK: <span class="text-muted">${esc(pm.attack)}</span> · Countermeasure: <span class="text-green">${esc(pm.cm)}</span>`
      : '<span class="text-muted">no payload selected</span>';
    // Persist selection so the Deploy tab knows what to install.
    SEL.inst = id;
    SEL.payload = cur || null;
  } catch (e) { plog('payload list failed: ' + e.message, 't-err'); }
};
/* Deploy tab: the liability ack gates the One-Click Install. The install
   consumes the selection made on the Arm tab (SEL). On run, the install fires
   (server-side compat check still applies) and the page jumps to the Dashboard
   so the streaming install log + the new armed-instance row are visible. */
window.depAckChanged = function () {
  const ack = document.getElementById('dep-ack') && document.getElementById('dep-ack').checked;
  const ready = !!(SEL.inst && SEL.payload && ack);
  const btn = document.getElementById('btn-install');
  if (btn) btn.disabled = !ready;
  const status = document.getElementById('install-status');
  if (status) {
    status.textContent = !SEL.inst    ? 'select an instance + payload on the Arm tab first'
                       : !SEL.payload ? 'select a compatible payload on the Arm tab'
                       : !ack         ? 'acknowledge the statement above to enable'
                                      : 'ready to install ' + SEL.payload;
  }
};

window.depInstallNow = async function () {
  if (!SEL.inst || !SEL.payload) { dlog('no Arm-tab selection — pick an instance + payload first', 't-err'); return; }
  const ackEl = document.getElementById('dep-ack');
  if (!ackEl || !ackEl.checked) { dlog('liability acknowledgement is required', 't-err'); return; }
  const btn = document.getElementById('btn-install'); if (btn) btn.disabled = true;

  // Jump to the Dashboard so the streaming install log + armed row are visible.
  pTab('p-dash');
  dlog(`[ack] liability acknowledged at ${ts()}`, 't-info');
  try {
    const d = await api('/api/implants/instance/' + SEL.inst + '/arm',
                        { method: 'POST', body: JSON.stringify({ payload: SEL.payload }) });
    (d.steps || []).forEach(s => dlog(s.msg, s.cls || 't-info'));
    await loadTree();
    await renderArmed();
    // Reset the ack for the next operation.
    if (ackEl) ackEl.checked = false;
    depAckChanged();
  } catch (e) {
    dlog('install failed: ' + e.message, 't-err');
    if (btn) btn.disabled = false;
  }
};

/* Dashboard: armed/deployed instances table + loot information. MARK DEPLOYED
   flows through /deploy (which enforces ack=true server-side); the operator
   already acknowledged on Deploy to install, so we pass ack:true here. */
const LOOT_MAP = {
  bunny:          ['NetNTLMv2 hashes',          'Credentials → hashcat'],
  turtle:         ['Responder / nmap loot',     'Credentials / Scan'],
  shark:          ['nmap output',               'Scan → Enumerate'],
  packetsquirrel: ['pcap / DNS-spoof loot',     'Loot / Scan'],
  keycroc:        ['keystroke log / creds',     'Credentials'],
  signalowl:      ['WiFi / BT recon + loot',    'Loot / Scan'],
  'omg-plug':     ['keylog / exfil',            'Credentials'],
  'omg-adapter':  ['keylog / exfil',            'Credentials'],
  'omg-unblocker':['keylog / exfil',            'Credentials'],
  'omg-cable':    ['keylog / exfil',            'Credentials'],
  ducky:          ['reverse shell / output',    'MSF Sessions'],
};
async function renderArmed() {
  const tbody = document.getElementById('deploy-tbody');
  const lootBody = document.getElementById('loot-tbody-p');
  if (!tbody && !lootBody) return;
  try {
    const d = await api('/api/implants/armed');
    const armed = d.armed || [];
    if (tbody) {
      tbody.innerHTML = armed.length ? armed.map(i => `
        <tr>
          <td class="text-cyan">${esc(i.device_id)}</td>
          <td class="text-muted">${esc(i.product_name)}</td>
          <td><span class="badge badge-warning">${esc(i.armed_payload)}</span></td>
          <td>${callbackCell(i.callback_status)}</td>
          <td><input type="text" placeholder="target host / SSID / room…" id="dn-${i.id}" value="${esc(i.deploy_target || '')}"></td>
          <td>${i.deployed
              ? '<span class="badge badge-violet">DEPLOYED · ' + esc(i.deployed_at || '') + '</span>'
              : '<span class="badge badge-warning">ARMED · ready to plug in</span>'}</td>
          <td class="flex gap-1">
            ${i.deployed
              ? `<button class="btn btn-green btn-sm" onclick="pMarkReturned('${i.id}')">MARK RETURNED</button>`
              : `<button class="btn btn-red btn-sm"   onclick="pMarkDeployed('${i.id}')">MARK DEPLOYED</button>`}
            <button class="btn btn-sm" onclick="pDisarm('${i.id}')">DISARM</button>
          </td>
        </tr>`).join('')
        : '<tr><td colspan="7" class="text-muted" style="text-align:center;padding:1rem">no armed instances yet — Arm + Deploy a device</td></tr>';
    }
    if (lootBody) {
      lootBody.innerHTML = armed.length ? armed.map(i => {
        const m = LOOT_MAP[i.product_id] || ['loot', 'Loot'];
        const state = i.deployed
          ? '<span class="badge badge-violet">awaiting pull</span>'
          : '<span class="badge badge-muted">armed (not deployed)</span>';
        return `<tr>
          <td class="text-cyan">${esc(i.device_id)}</td>
          <td class="text-muted">${esc(m[0])}</td>
          <td class="text-green" style="font-size:11px">${esc(m[1])}</td>
          <td>${state}</td>
        </tr>`;
      }).join('')
        : '<tr><td colspan="4" class="text-muted" style="text-align:center;padding:1rem">no loot expected yet — arm + deploy a device. (loot pull lands in a later phase)</td></tr>';
    }
  } catch (e) { dlog('armed list failed: ' + e.message, 't-err'); }
}
window.renderArmed = renderArmed;

window.pDisarm = async function (id) {
  try { await api('/api/implants/instance/' + id + '/disarm', { method: 'POST' }); dlog('disarmed', 't-warn'); await loadTree(); await renderArmed(); }
  catch (e) { dlog('disarm failed: ' + e.message, 't-err'); }
};
window.pMarkDeployed = async function (id) {
  const note = (document.getElementById('dn-' + id) || {}).value || '';
  try {
    const d = await api('/api/implants/instance/' + id + '/deploy', { method: 'POST', body: JSON.stringify({ target: note, ack: true }) });
    if (d.status === 'deployed') dlog(`[deploy] ${d.instance.device_id} (${d.instance.armed_payload}) → ${note || '(no target)'}`, 't-warn');
    else dlog(`[deploy] denied: ${d.reason}`, 't-err');
    await renderArmed();
  } catch (e) { dlog('deploy failed: ' + e.message, 't-err'); }
};
window.pMarkReturned = async function (id) {
  try {
    const d = await api('/api/implants/instance/' + id + '/return', { method: 'POST' });
    if (d.status === 'returned') dlog(`[recall] ${d.instance.device_id} returned — disarmed`, 't-ok');
    await loadTree(); await renderArmed();
  } catch (e) { dlog('return failed: ' + e.message, 't-err'); }
};

/* ── LIBRARY: vetted GitHub sources + synced payload browser ──────────────── */
let SOURCES = [];
let SYNCED  = [];
let SYNCED_BY_CID = new Map();   // cid -> payload record
let libRenderKeys = [];          // current render's ordered group keys
const libGroupOpen = {};         // group key -> bool (default collapsed)
const libRowOpen   = {};         // cid -> bool
const DESC_CACHE   = {};         // cid -> {state:'loading'|'ok'|'err', data?, reason?}

function srcStatusBadge(s) {
  return s === 'ok'          ? '<span class="badge badge-green">OK</span>'
    : s === 'unreachable'    ? '<span class="badge badge-warning">UNREACHABLE</span>'
    : s === 'error'          ? '<span class="badge badge-danger">ERROR</span>'
                             : '<span class="badge badge-muted">NEVER</span>';
}
function fmtTs(iso) {
  if (!iso) return '<span class="text-muted">—</span>';
  try { return '<span class="text-muted" style="font-size:10px">' + esc(String(iso).replace('T', ' ').slice(0, 19)) + '</span>'; }
  catch (e) { return esc(String(iso)); }
}

async function loadSources() {
  try {
    const d = await api('/api/implants/sources');
    SOURCES = d.sources || [];
    renderSourcesTable();
    const s = d.stats || {};
    document.getElementById('ls-src').textContent     = s.sources ?? '—';
    document.getElementById('ls-builtin').textContent = s.builtin_payloads ?? '—';
    document.getElementById('ls-synced').textContent  = s.synced_payloads ?? '—';
    document.getElementById('ls-total').textContent   = s.total_payloads ?? '—';
    await loadSyncedPayloads();
  } catch (e) {
    document.getElementById('src-tbody').innerHTML =
      '<tr><td colspan="7" class="text-red" style="padding:1rem">load failed: ' + esc(e.message) + '</td></tr>';
  }
}
function renderSourcesTable() {
  const tb = document.getElementById('src-tbody');
  if (!tb) return;
  tb.innerHTML = SOURCES.length ? SOURCES.map(s => `
    <tr>
      <td class="text-cyan">${esc(s.label)}</td>
      <td><a href="${esc(s.homepage)}" target="_blank" rel="noopener" class="text-muted" style="font-size:11px">${esc(s.repo)}</a> <span class="pill">${esc(s.branch)}</span></td>
      <td class="text-muted" style="font-size:10px">${(s.products || []).map(esc).join(', ')}</td>
      <td>${fmtTs(s.last_synced)}</td>
      <td class="text-green">${s.count || 0}</td>
      <td>${srcStatusBadge(s.status)}</td>
      <td><button class="btn btn-violet btn-sm" onclick="updateSource('${esc(s.id)}')">⟲ UPDATE</button></td>
    </tr>`).join('')
    : '<tr><td colspan="7" class="text-muted" style="text-align:center;padding:1rem">no vetted sources registered</td></tr>';
}

function _applyUpdateResult(d) {
  (d.steps || []).forEach(s => llog(s.msg, s.cls || 't-info'));
  if (d.sources) { SOURCES = d.sources; renderSourcesTable(); }
  const s = d.stats || {};
  if (s.sources != null)          document.getElementById('ls-src').textContent     = s.sources;
  if (s.builtin_payloads != null) document.getElementById('ls-builtin').textContent = s.builtin_payloads;
  if (s.synced_payloads != null)  document.getElementById('ls-synced').textContent  = s.synced_payloads;
  if (s.total_payloads != null)   document.getElementById('ls-total').textContent   = s.total_payloads;
}

window.updateSource = async function (id) {
  const st = document.getElementById('lib-status');
  if (st) st.textContent = 'pulling ' + id + '…';
  llog('pulling ' + id + ' from GitHub…', 't-info');
  try {
    const d = await api('/api/implants/sources/update', { method: 'POST', body: JSON.stringify({ source_id: id }) });
    _applyUpdateResult(d);
    if (st) st.textContent = 'pulled ' + (d.pulled || 0) + ' payloads from ' + id;
    await loadSyncedPayloads();
  } catch (e) { llog('update failed: ' + e.message, 't-err'); if (st) st.textContent = 'update failed'; }
};
window.updateAllSources = async function () {
  const st = document.getElementById('lib-status');
  if (st) st.textContent = 'pulling all vetted sources…';
  llog('pulling all vetted sources from GitHub…', 't-info');
  try {
    const d = await api('/api/implants/sources/update', { method: 'POST', body: JSON.stringify({}) });
    _applyUpdateResult(d);
    if (st) st.textContent = 'registered ' + (d.registered || 0) + ' synced payloads (' + (d.pulled || 0) + ' pulled)';
    await loadSyncedPayloads();
  } catch (e) { llog('update failed: ' + e.message, 't-err'); if (st) st.textContent = 'update failed'; }
};

async function loadSyncedPayloads() {
  try {
    const d = await api('/api/implants/payloads');
    SYNCED = (d.payloads || []).filter(p => p.vetted);
    SYNCED_BY_CID = new Map();
    SYNCED.forEach((p, i) => { p._cid = String(i); SYNCED_BY_CID.set(p._cid, p); });
    fillLibProduct();
    renderSyncedPayloads();
  } catch (e) { /* browser stays as-is on error */ }
}

function fillLibProduct() {
  const sel = document.getElementById('lib-product');
  if (!sel) return;
  const cur = sel.value;
  const names = new Map();   // product id -> label
  SYNCED.forEach(p => {
    const ids = p.products || [];
    const labels = p.product_names || ids;
    ids.forEach((id, i) => names.set(id, labels[i] || id));
  });
  sel.innerHTML = ['<option value="">All products</option>'].concat(
    [...names.entries()].sort((a, b) => a[1].localeCompare(b[1]))
      .map(([id, label]) => `<option value="${esc(id)}">${esc(label)}</option>`)).join('');
  if (cur) sel.value = cur;
}

function libGroupKey(p, mode) {
  if (mode === 'product') return (p.product_names || p.products || ['(none)']).join(', ');
  if (mode === 'source')  return p.source_label || p.source || '(none)';
  if (mode === 'category') return p.category || '(uncategorized)';
  return '';
}
function libFiltered() {
  const prod = (document.getElementById('lib-product') || {}).value || '';
  const q = ((document.getElementById('lib-q') || {}).value || '').toLowerCase();
  return SYNCED.filter(p => {
    if (prod && !(p.products || []).includes(prod)) return false;
    if (!q) return true;
    return (p.name || '').toLowerCase().includes(q)
      || (p.category || '').toLowerCase().includes(q)
      || (p.source || '').toLowerCase().includes(q)
      || (p.source_label || '').toLowerCase().includes(q);
  });
}

function descHtml(cid) {
  const c = DESC_CACHE[cid];
  const p = SYNCED_BY_CID.get(cid) || {};
  if (!c || c.state === 'loading') return '<span class="text-muted">loading description…</span>';
  if (c.state === 'err') {
    return '<span class="text-red">could not load: ' + esc(c.reason || 'error') + '</span>'
      + (p.url ? ' · <a href="' + esc(p.url) + '" target="_blank" rel="noopener" class="text-violet">view source ↗</a>' : '');
  }
  const d = c.data || {};
  const meta = [];
  if (p.attack) meta.push('ATT&amp;CK <b>' + esc(p.attack) + '</b>');
  if (p.cm) meta.push('CM <b>' + esc(p.cm) + '</b>');
  if (d.author) meta.push('author <b>' + esc(d.author) + '</b>');
  const body = d.description
    ? esc(d.description)
    : '<span class="text-muted">(no description text in the source — open the file)</span>';
  return (meta.length ? '<div class="meta">' + meta.join(' · ') + '</div>' : '')
    + body
    + (d.doc_url ? '<div style="margin-top:.4rem"><a href="' + esc(d.doc_url) + '" target="_blank" rel="noopener" class="text-violet" style="font-size:10px">view source ↗</a></div>' : '');
}
function libRowHtml(p) {
  const cid = p._cid;
  const open = !!libRowOpen[cid];
  return `<div class="lib-row">
    <div class="lib-row-main" onclick="libToggleDesc('${cid}')">
      <span class="lib-row-tw">${open ? '▾' : '▸'}</span>
      <span class="lib-row-name">${esc(p.name)}</span>
      <span class="lib-row-cat">${esc(p.category || '')}</span>
      <span class="ml-auto"><span class="badge badge-muted" style="font-size:9px">${esc(p.source_label || p.source || '')}</span></span>
    </div>
    <div class="lib-row-desc ${open ? '' : 'hidden'}" id="desc-${cid}">${open ? descHtml(cid) : ''}</div>
  </div>`;
}

window.renderSyncedPayloads = function () {
  const root = document.getElementById('syn-groups');
  if (!root) return;
  const mode   = (document.getElementById('lib-group') || {}).value || 'category';
  const sortBy = (document.getElementById('lib-sort') || {}).value || 'name';
  const qActive = !!((document.getElementById('lib-q') || {}).value || '').trim();
  const rows = libFiltered();

  const cnt = document.getElementById('syn-count');
  if (cnt) cnt.textContent = rows.length + ' of ' + SYNCED.length + ' synced payloads';

  if (!rows.length) {
    root.innerHTML = '<div class="lib-empty">' +
      (SYNCED.length ? 'no payloads match the filter' : 'no synced payloads yet — run an update above') + '</div>';
    return;
  }

  const cmp = {
    name:     (a, b) => (a.name || '').localeCompare(b.name || ''),
    category: (a, b) => (a.category || '').localeCompare(b.category || '') || (a.name || '').localeCompare(b.name || ''),
    source:   (a, b) => (a.source_label || '').localeCompare(b.source_label || '') || (a.name || '').localeCompare(b.name || ''),
  }[sortBy] || (() => 0);

  if (mode === 'none') {
    libRenderKeys = [];
    root.innerHTML = '<div class="lib-group"><div class="lib-rows">' +
      rows.slice().sort(cmp).map(libRowHtml).join('') + '</div></div>';
    return;
  }

  const groups = new Map();
  rows.forEach(p => {
    const k = libGroupKey(p, mode);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(p);
  });
  libRenderKeys = [...groups.keys()].sort((a, b) => a.localeCompare(b));
  root.innerHTML = libRenderKeys.map((k, gi) => {
    const items = groups.get(k).slice().sort(cmp);
    const open = qActive ? true : !!libGroupOpen[k];
    return `<div class="lib-group">
      <div class="lib-group-hd" onclick="libToggleGroup(${gi})">
        <span class="lib-row-tw">${open ? '▾' : '▸'}</span>
        <span class="lib-group-name">${esc(k)}</span>
        <span class="lib-group-meta">${items.length} payload${items.length !== 1 ? 's' : ''}</span>
      </div>
      <div class="lib-rows ${open ? '' : 'collapsed'}">${items.map(libRowHtml).join('')}</div>
    </div>`;
  }).join('');
};

window.libToggleGroup = function (gi) {
  const k = libRenderKeys[gi];
  if (k == null) return;
  libGroupOpen[k] = !libGroupOpen[k];
  renderSyncedPayloads();
};
window.libExpandAll = function (open) {
  const mode = (document.getElementById('lib-group') || {}).value || 'category';
  if (mode === 'none') return;
  new Set(libFiltered().map(p => libGroupKey(p, mode))).forEach(k => { libGroupOpen[k] = open; });
  renderSyncedPayloads();
};
window.libToggleDesc = async function (cid) {
  const p = SYNCED_BY_CID.get(cid);
  const desc = document.getElementById('desc-' + cid);
  if (!p || !desc) return;
  libRowOpen[cid] = !libRowOpen[cid];
  const tw = desc.previousElementSibling && desc.previousElementSibling.querySelector('.lib-row-tw');
  if (tw) tw.textContent = libRowOpen[cid] ? '▾' : '▸';
  if (!libRowOpen[cid]) { desc.classList.add('hidden'); return; }
  desc.classList.remove('hidden');
  if (DESC_CACHE[cid] && DESC_CACHE[cid].state !== 'loading') { desc.innerHTML = descHtml(cid); return; }
  DESC_CACHE[cid] = { state: 'loading' };
  desc.innerHTML = descHtml(cid);
  try {
    const d = await api('/api/implants/sources/describe',
      { method: 'POST', body: JSON.stringify({ source_id: p.source, path: p.path }) });
    DESC_CACHE[cid] = (d.status === 'ok') ? { state: 'ok', data: d } : { state: 'err', reason: d.reason || d.status };
  } catch (e) { DESC_CACHE[cid] = { state: 'err', reason: e.message }; }
  if (libRowOpen[cid]) desc.innerHTML = descHtml(cid);
};

document.addEventListener('DOMContentLoaded', function () {
  loadTree();          // populates stats + tree + add-product select
  renderArmed();       // dashboard armed table + loot information (landing tab)
  startCallbackPoll(); // refresh callback status every 5s while on Dashboard
});
})();
