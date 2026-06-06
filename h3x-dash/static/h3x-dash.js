/**
 * H3x-Dash — client-side utilities
 * SSE stream consumer, terminal helpers, shared UI functions.
 */

'use strict';

/**
 * Open an SSE stream from `url`, pipe output lines into `termEl`.
 * Calls `onComplete()` when the server sends { type: 'complete' }.
 * Returns the EventSource so the caller can close it if needed.
 *
 * @param {string}      url        SSE endpoint URL
 * @param {HTMLElement} termEl     Terminal <div> to append lines to
 * @param {Function}    onComplete Called when type === 'complete'
 * @returns {EventSource}
 */
function h3xStream(url, termEl, onComplete) {
  const es = new EventSource(url);

  es.onmessage = function (evt) {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }

    if (msg.type === 'heartbeat') return;

    if (msg.type === 'output') {
      h3xTermLine(termEl, msg.data);
    }

    if (msg.type === 'complete') {
      h3xTermLine(termEl, `\n[H3x-Dash] Scan complete — ${msg.host_count ?? 0} host(s).`, 'info');
      es.close();
      if (onComplete) onComplete(msg);
    }

    if (msg.type === 'error') {
      h3xTermLine(termEl, `[ERROR] ${msg.data || 'unknown error'}`, 'err');
      es.close();
    }
  };

  es.onerror = function () {
    h3xTermLine(termEl, '[H3x-Dash] Stream connection closed.', 'warn');
    es.close();
  };

  return es;
}


/**
 * Append a line to a terminal element, with optional colour class.
 * @param {HTMLElement} termEl
 * @param {string}      text
 * @param {string}      [cls]  'err' | 'warn' | 'info' | 'dim' — maps to .t-* CSS classes
 */
function h3xTermLine(termEl, text, cls) {
  if (!termEl) return;

  // Colorise common prefixes automatically if no class given
  if (!cls) {
    const lo = text.toLowerCase();
    if (lo.includes('[error]') || lo.includes('[!]'))       cls = 'err';
    else if (lo.includes('[warn') || lo.startsWith('  ⚑'))  cls = 'warn';
    else if (lo.includes('[h3x-dash]') || lo.includes('[*]')) cls = 'info';
    else if (lo.startsWith('  ') || lo.startsWith('──'))    cls = 'dim';
  }

  const span = document.createElement('span');
  if (cls) span.className = `t-${cls}`;
  span.textContent = text + '\n';
  termEl.appendChild(span);
  termEl.scrollTop = termEl.scrollHeight;
}


/**
 * Show a temporary flash message inside `parentEl`.
 * @param {HTMLElement} parentEl
 * @param {string}      message
 * @param {'ok'|'err'}  type
 * @param {number}      [ttl=4000]  Auto-hide after ms
 */
function h3xFlash(parentEl, message, type = 'ok', ttl = 4000) {
  const div = document.createElement('div');
  div.className = `flash flash-${type}`;
  div.textContent = message;
  parentEl.prepend(div);
  if (ttl > 0) setTimeout(() => div.remove(), ttl);
}


/**
 * POST JSON to `url` and return the parsed response.
 * @param {string} url
 * @param {object} body
 * @returns {Promise<object>}
 */
async function h3xPost(url, body) {
  const r = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  return r.json();
}


/**
 * GET JSON from `url`.
 * @param {string} url
 * @returns {Promise<object>}
 */
async function h3xGet(url) {
  const r = await fetch(url);
  return r.json();
}
