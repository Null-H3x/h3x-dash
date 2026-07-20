"""
H3x-Dash :: Cease Coordinator
=============================
A single, global ENDEX / cease-fire control. Subsystems register a halt
callback; a `halt()` invokes every one of them and returns a per-subsystem
report. This is what the always-present "Cease Buzzer" drives.

Why a coordinator (not just calling each stop endpoint): on a hot box routing
through a live network, the operator needs ONE action that halts everything at
once, honestly, and leaves an audit record — not a scavenger hunt across panes.

Design:
  * Honest reporting. Each halt callback's result (or exception) is captured
    and returned. If a subsystem has no halt, it simply isn't registered —
    nothing is faked as stopped.
  * Append-only cease log (JSONL) under the app log dir — the ENDEX record for
    the AAR / deconfliction.
  * shutdown() mimics Ctrl+C to the process group so it also stops the dev
    reloader, with a hard os._exit fallback.

Wire-in (h3x-dash.py, after the engine singletons):
    from modules.cease import cease, make_cease_blueprint
    cease.configure(H3xConfig.LOG_DIR)
    cease.register('scan',  lambda: scan_engine.stop_scan())
    cease.register('enum',  lambda: enum_engine.stop_all())
    ...
    app.register_blueprint(make_cease_blueprint())
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarize(out: Any) -> str:
    """Turn a halt callback's return value into a short human status."""
    if out is None:
        return "ok"
    if isinstance(out, bool):
        return "ok" if out else "nothing running"
    if isinstance(out, dict):
        if "count" in out:
            return f"{out['count']} stopped"
        if "killed" in out:
            return f"{len(out['killed']) if isinstance(out['killed'], list) else out['killed']} killed"
        if "pending_cancelled" in out:
            return f"{out['pending_cancelled']} cancelled"
        return "ok"
    return str(out)[:80]


class CeaseCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._halts: Dict[str, Callable[[], Any]] = {}
        self._order: List[str] = []
        self._last_report: Optional[Dict[str, Any]] = None
        self.data_dir = os.environ.get("H3X_CEASE_DATA", os.path.join(os.getcwd(), "logs"))

    def configure(self, data_dir) -> None:
        self.data_dir = str(data_dir)

    def register(self, name: str, halt_fn: Callable[[], Any]) -> None:
        with self._lock:
            if name not in self._halts:
                self._order.append(name)
            self._halts[name] = halt_fn

    def registered(self) -> List[str]:
        with self._lock:
            return list(self._order)

    def _log(self, event: Dict[str, Any]) -> None:
        rec = {"ts": _iso(), **event}
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            with open(os.path.join(self.data_dir, "cease.log.jsonl"), "a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass  # logging must never block an ENDEX

    def halt(self, reason: str = "cease buzzer") -> Dict[str, Any]:
        with self._lock:
            names = list(self._order)
            halts = dict(self._halts)
        self._log({"event": "CEASE", "reason": reason, "subsystems": names})
        results: List[Dict[str, Any]] = []
        for name in names:
            fn = halts.get(name)
            t0 = time.time()
            try:
                out = fn() if fn else None
                results.append({"name": name, "ok": True, "detail": _summarize(out)})
                self._log({"event": "halt", "subsystem": name, "ok": True,
                           "ms": round((time.time() - t0) * 1000)})
            except Exception as exc:  # noqa: BLE001 — surface every failure honestly
                results.append({"name": name, "ok": False,
                                "detail": f"{type(exc).__name__}: {exc}"})
                self._log({"event": "halt", "subsystem": name, "ok": False,
                           "error": str(exc)})
        report = {"ts": _iso(), "reason": reason, "results": results,
                  "ok": all(r["ok"] for r in results), "count": len(results)}
        with self._lock:
            self._last_report = report
        return report

    def last(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._last_report

    def shutdown(self) -> None:
        """Quit the process. Mimics Ctrl+C to the process group so the dev
        reloader stops too; hard-exits as a fallback. Never touches the shell —
        SIGINT goes to our own process group only."""
        self._log({"event": "SHUTDOWN"})

        def _die():
            time.sleep(0.5)  # let the HTTP response flush
            try:
                os.killpg(os.getpgrp(), signal.SIGINT)
            except Exception:
                pass
            time.sleep(1.0)
            os._exit(0)

        threading.Thread(target=_die, daemon=True).start()


# process singleton
cease = CeaseCoordinator()


def make_cease_blueprint(url_prefix: str = "/api/cease"):
    from flask import Blueprint, jsonify, request

    bp = Blueprint("cease", __name__, url_prefix=url_prefix)

    @bp.post("/halt")
    def halt():
        body = request.get_json(silent=True) or {}
        return jsonify(cease.halt(body.get("reason", "cease buzzer")))

    @bp.get("/status")
    def status():
        return jsonify({"registered": cease.registered(), "last": cease.last()})

    @bp.post("/shutdown")
    def shutdown():
        cease.shutdown()
        return jsonify({"shutdown": True})

    return bp
