/*
 * H3x-Dash :: fixed-scale
 * -----------------------
 * Makes the console render at a consistent apparent size across resolutions.
 * The UI is authored in fixed px against a DESIGN_WIDTH baseline; this scales
 * the whole page uniformly so a 3840x2160 workstation and a 1280x800 VM show
 * the same proportions instead of the fixed-px layout looking tiny on 4K.
 *
 * Implementation note: we use CSS `zoom` on <html>, NOT transform:scale().
 * `zoom` scales the layout (crisp text, correct viewport units) and does not
 * create a containing block, so the position:fixed topbar / shell / status
 * dock / cease buzzer keep working. transform:scale() would reparent those and
 * break the layout. `zoom` is supported in Chromium/Chrome/Edge and Firefox
 * >=126 — i.e. every current Kali browser.
 *
 * Loaded tool-wide from console.html (add the same <script> line to base.html
 * if you want the legacy multi-page views scaled too).
 */
(function () {
  if (window.__h3xScale) return;
  window.__h3xScale = true;

  // Baseline the UI was tuned at. Larger = everything renders smaller.
  // 1440 is a comfortable desktop reference; drop toward 1280 to match the VM
  // exactly, raise toward 1600 for denser panels. This is the one knob.
  var DESIGN_WIDTH = 1440;
  var MIN_SCALE = 0.70;   // never shrink below this (tiny windows stay usable)
  var MAX_SCALE = 2.50;   // never blow up past this on very large panels

  function apply() {
    var el = document.documentElement;
    // Neutralise our own zoom before measuring so innerWidth reports the true
    // CSS width and we don't feed our previous scale back into the calc.
    el.style.zoom = '1';
    var w = window.innerWidth || DESIGN_WIDTH;
    var z = w / DESIGN_WIDTH;
    if (z < MIN_SCALE) z = MIN_SCALE;
    if (z > MAX_SCALE) z = MAX_SCALE;
    el.style.zoom = String(z);
  }

  var raf = 0;
  function onResize() {
    if (raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(apply);
  }

  apply();
  window.addEventListener('resize', onResize);
  window.addEventListener('orientationchange', onResize);
})();
