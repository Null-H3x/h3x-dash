/* H3x-Dash :: Cease Buzzer
 * A large, always-present ENDEX / cease-fire control fixed bottom-left.
 * Self-injects on every page (works in the raw-served /console and the
 * Jinja-rendered pages alike). One click -> confirm -> halt ALL operations
 * across the tool via /api/cease/halt, then optionally /api/cease/shutdown.
 *
 * Backend: modules/cease.py  (blueprint mounted at /api/cease)
 */
(function () {
  if (window.__h3xCease) return;            // idempotent
  window.__h3xCease = true;

  var CSS = ''
    + '#h3x-cease-btn{position:fixed;top:calc(var(--topbar-h,54px) + 16px);left:calc((var(--side-w,220px) - 104px)/2);z-index:99998;'
    + 'width:104px;height:104px;border:none;cursor:pointer;border-radius:50%;'
    + 'background:radial-gradient(circle at 50% 38%,#ff5a6e 0%,#ff2d55 42%,#b30028 100%);'
    + 'box-shadow:0 0 0 4px #2a0009,0 0 0 7px #ff2d55,0 0 26px 6px rgba(255,45,85,.55),inset 0 -6px 14px rgba(0,0,0,.45);'
    + 'font-family:"Rajdhani","Share Tech Mono",system-ui,sans-serif;color:#fff;'
    + 'display:flex;flex-direction:column;align-items:center;justify-content:center;'
    + 'letter-spacing:.12em;transition:transform .08s ease, box-shadow .2s ease;'
    + 'animation:h3xCeasePulse 2.4s ease-in-out infinite;}'
    + '#h3x-cease-btn:hover{transform:scale(1.05);'
    + 'box-shadow:0 0 0 4px #2a0009,0 0 0 7px #ff2d55,0 0 34px 10px rgba(255,45,85,.8),inset 0 -6px 14px rgba(0,0,0,.45);}'
    + '#h3x-cease-btn:active{transform:scale(.94);}'
    + '#h3x-cease-btn .cg{font-size:30px;line-height:1;margin-bottom:2px;text-shadow:0 2px 4px rgba(0,0,0,.5);}'
    + '#h3x-cease-btn .ct{font-size:16px;font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,.6);}'
    + '#h3x-cease-btn .cs{font-size:8.5px;font-weight:600;opacity:.85;margin-top:1px;}'
    + '@keyframes h3xCeasePulse{0%,100%{box-shadow:0 0 0 4px #2a0009,0 0 0 7px #ff2d55,0 0 22px 4px rgba(255,45,85,.45),inset 0 -6px 14px rgba(0,0,0,.45);}'
    + '50%{box-shadow:0 0 0 4px #2a0009,0 0 0 7px #ff5a6e,0 0 30px 9px rgba(255,45,85,.7),inset 0 -6px 14px rgba(0,0,0,.45);}}'
    + '#h3x-cease-ov{position:fixed;inset:0;z-index:99999;display:none;align-items:center;'
    + 'justify-content:center;background:rgba(6,6,10,.82);backdrop-filter:blur(3px);'
    + 'font-family:"Rajdhani","Share Tech Mono",system-ui,sans-serif;}'
    + '#h3x-cease-ov.show{display:flex;}'
    + '#h3x-cease-modal{width:min(560px,92vw);background:linear-gradient(180deg,#141019,#0d0a12);'
    + 'border:1px solid #3a1030;border-radius:6px;padding:26px 26px 22px;position:relative;'
    + 'box-shadow:0 0 40px rgba(255,45,85,.25);}'
    + '#h3x-cease-modal::before,#h3x-cease-modal::after{content:"";position:absolute;width:14px;height:14px;}'
    + '#h3x-cease-modal::before{top:0;left:0;border-top:2px solid #ff2d55;border-left:2px solid #ff2d55;}'
    + '#h3x-cease-modal::after{bottom:0;right:0;border-bottom:2px solid #ff2d55;border-right:2px solid #ff2d55;}'
    + '#h3x-cease-modal h2{margin:0 0 6px;color:#ff5a6e;font-size:22px;letter-spacing:.14em;text-transform:uppercase;}'
    + '#h3x-cease-modal .sub{color:#c9b6c6;font-size:13.5px;line-height:1.5;margin-bottom:18px;'
    + 'font-family:"Share Tech Mono",monospace;}'
    + '#h3x-cease-modal .row{display:flex;gap:12px;flex-wrap:wrap;}'
    + '.h3x-cbtn{font-family:"Rajdhani",system-ui,sans-serif;text-transform:uppercase;letter-spacing:.1em;'
    + 'font-weight:700;font-size:14px;padding:12px 20px;border-radius:4px;cursor:pointer;border:1px solid;'
    + 'background:transparent;transition:.12s;flex:1;min-width:120px;}'
    + '.h3x-cbtn.kill{color:#fff;border-color:#ff2d55;background:linear-gradient(180deg,#ff2d55,#b30028);}'
    + '.h3x-cbtn.kill:hover{box-shadow:0 0 16px rgba(255,45,85,.6);}'
    + '.h3x-cbtn.ghost{color:#9fb0c0;border-color:#2a3340;}'
    + '.h3x-cbtn.ghost:hover{border-color:#0ff0fc;color:#0ff0fc;}'
    + '.h3x-cbtn.warn{color:#ffb300;border-color:#ffb300;}'
    + '.h3x-cbtn.warn:hover{background:rgba(255,179,0,.12);}'
    + '#h3x-cease-report{margin:6px 0 18px;font-family:"Share Tech Mono",monospace;font-size:12.5px;'
    + 'max-height:210px;overflow:auto;}'
    + '#h3x-cease-report .cr{display:flex;justify-content:space-between;gap:10px;padding:5px 8px;'
    + 'border-bottom:1px solid rgba(58,16,48,.5);}'
    + '#h3x-cease-report .cr .n{color:#0ff0fc;text-transform:uppercase;letter-spacing:.06em;}'
    + '#h3x-cease-report .cr .d.ok{color:#39ff14;}#h3x-cease-report .cr .d.bad{color:#ff2d55;}';

  function el(html) { var t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstChild; }

  function inject() {
    if (document.getElementById('h3x-cease-btn')) return;
    var style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    var btn = el('<button id="h3x-cease-btn" title="Cease Buzzer — halt all operations">'
      + '<span class="cg">&#9632;</span><span class="ct">CEASE</span><span class="cs">BUZZER</span></button>');
    var ov = el('<div id="h3x-cease-ov"><div id="h3x-cease-modal">'
      + '<h2>&#9888; Cease-Fire / ENDEX</h2>'
      + '<div class="sub" id="h3x-cease-sub">Immediately halt <b>all active operations</b> across H3x-Dash — '
      + 'scans, enumeration, MSF sessions, beacons, emulation, and the MSEL scheduler. '
      + 'This is logged as the ENDEX record.</div>'
      + '<div id="h3x-cease-report"></div>'
      + '<div class="row" id="h3x-cease-actions">'
      + '<button class="h3x-cbtn kill" id="h3x-cease-go">&#9632; CEASE ALL</button>'
      + '<button class="h3x-cbtn ghost" id="h3x-cease-cancel">Cancel</button>'
      + '</div></div></div>');

    document.body.appendChild(btn);
    document.body.appendChild(ov);

    var sub = ov.querySelector('#h3x-cease-sub');
    var report = ov.querySelector('#h3x-cease-report');
    var actions = ov.querySelector('#h3x-cease-actions');

    function open() { ov.classList.add('show'); }
    function close() { ov.classList.remove('show'); }

    function resetModal() {
      report.innerHTML = '';
      sub.style.display = '';
      actions.innerHTML = '<button class="h3x-cbtn kill" id="h3x-cease-go">&#9632; CEASE ALL</button>'
        + '<button class="h3x-cbtn ghost" id="h3x-cease-cancel">Cancel</button>';
      wireActions();
    }

    function renderReport(rep) {
      sub.style.display = 'none';
      var rows = (rep && rep.results || []).map(function (r) {
        return '<div class="cr"><span class="n">' + r.name + '</span>'
          + '<span class="d ' + (r.ok ? 'ok' : 'bad') + '">' + (r.ok ? '\u2713 ' : '\u2717 ') + r.detail + '</span></div>';
      }).join('');
      report.innerHTML = '<div class="cr" style="border-bottom:1px solid #3a1030;margin-bottom:4px">'
        + '<span class="n" style="color:#ff5a6e">CEASE ACKNOWLEDGED</span>'
        + '<span class="d ' + (rep && rep.ok ? 'ok' : 'bad') + '">' + ((rep && rep.results || []).length) + ' subsystem(s)</span></div>'
        + rows;
      actions.innerHTML = '<button class="h3x-cbtn warn" id="h3x-cease-shutdown">Shut Down Server</button>'
        + '<button class="h3x-cbtn ghost" id="h3x-cease-close">Close</button>';
      wireActions();
    }

    async function doHalt() {
      var go = document.getElementById('h3x-cease-go');
      if (go) { go.textContent = 'CEASING\u2026'; go.disabled = true; }
      var rep;
      try {
        var r = await fetch('/api/cease/halt', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'cease buzzer (' + location.pathname + ')' })
        });
        rep = await r.json();
      } catch (e) {
        rep = { ok: false, results: [{ name: 'cease', ok: false, detail: e.message }] };
      }
      renderReport(rep);
    }

    async function doShutdown() {
      var sd = document.getElementById('h3x-cease-shutdown');
      if (sd) { sd.textContent = 'SHUTTING DOWN\u2026'; sd.disabled = true; }
      try {
        await fetch('/api/cease/shutdown', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      } catch (e) { /* connection drops as the server exits — expected */ }
      report.innerHTML = '<div class="cr"><span class="n" style="color:#ffb300">SERVER TERMINATING</span>'
        + '<span class="d">operations halted \u00b7 you may close this tab</span></div>';
      setTimeout(function () { try { window.close(); } catch (e) {} }, 600);
    }

    function wireActions() {
      var go = document.getElementById('h3x-cease-go');
      var cancel = document.getElementById('h3x-cease-cancel');
      var shut = document.getElementById('h3x-cease-shutdown');
      var cl = document.getElementById('h3x-cease-close');
      if (go) go.onclick = doHalt;
      if (cancel) cancel.onclick = close;
      if (shut) shut.onclick = doShutdown;
      if (cl) cl.onclick = function () { close(); resetModal(); };
    }

    btn.onclick = function () { resetModal(); open(); };
    ov.addEventListener('click', function (e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
    wireActions();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
