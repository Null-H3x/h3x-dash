"""
H3x-Dash :: MSEL Inject Scheduler
=================================
Master Scenario Events List engine for driving a field exercise.

An MSEL is an ordered list of *injects*. An inject is a noticeable event that
provokes a defender reaction -- a ping, scan, enum, shell, pivot, beacon, or
any custom action. Each inject TYPE dispatches to a registered handler; the
handler is a thin adapter to a REAL tool already wired in h3x-dash.py (nmap,
enum suite, the beacon emitter). The scheduler owns timing, state, the master
abort, and the append-only ground-truth timeline.

House rules honoured:
  * No synthetic telemetry. If a handler is not registered, the inject fails
    with HANDLER_NOT_REGISTERED -- never faked as success.
  * The timeline (JSONL) is an append-only audit trail: deconfliction record
    + AAR ground truth.
  * Long-running injects fire in worker threads so one never stalls the loop.
  * Abort is cooperative & honest: pending injects cancel immediately;
    in-flight handlers are signalled via an abort_event they poll.

Wire-in (h3x-dash.py):
    from modules.msel import engine as msel_engine, Inject as MselInject, \
                             make_blueprint as make_msel_blueprint
    msel_engine.configure(H3xConfig.LOG_DIR / 'msel')
    msel_engine.register_handler('scan', my_scan_adapter)
    app.register_blueprint(make_msel_blueprint())
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

_TICK_SECONDS = 0.5


def _now() -> float:
    return time.time()


def _iso(ts: Optional[float] = None) -> str:
    ts = _now() if ts is None else ts
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class InjectStatus(str, Enum):
    PENDING = "pending"
    ARMED = "armed"
    FIRING = "firing"
    COMPLETE = "complete"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class Inject:
    name: str
    inject_type: str
    target: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    trigger: Dict[str, Any] = field(default_factory=lambda: {"type": "manual"})
    unit: str = ""
    phase: str = ""
    id: str = field(default_factory=lambda: "inj-" + uuid.uuid4().hex[:8])

    status: str = InjectStatus.PENDING.value
    armed_at: Optional[float] = None
    due_at: Optional[float] = None
    fired_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None

    def reset_runtime(self) -> None:
        self.status = InjectStatus.PENDING.value
        self.armed_at = self.due_at = self.fired_at = self.completed_at = None
        self.result = None
        self.error = None


class HandlerNotRegistered(Exception):
    pass


class MSELEngine:
    def __init__(self, data_dir: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._injects: Dict[str, Inject] = {}
        self._order: List[str] = []
        self._handlers: Dict[str, Callable[..., Any]] = {}
        self._workers: Dict[str, threading.Thread] = {}

        self._t_zero: Optional[float] = None
        self._armed = False
        self._paused = False
        self._abort_event = threading.Event()
        self._stop_loop = threading.Event()
        self._loop_thread: Optional[threading.Thread] = None

        self.data_dir = data_dir or os.environ.get(
            "H3X_MSEL_DATA", os.path.join(os.getcwd(), "logs", "msel"))

    # ----- config / paths -------------------------------------------------- #

    def configure(self, data_dir) -> None:
        self.data_dir = str(data_dir)

    @property
    def msel_path(self) -> str:
        return os.path.join(self.data_dir, "msel.json")

    @property
    def timeline_path(self) -> str:
        return os.path.join(self.data_dir, "msel_timeline.jsonl")

    def _ensure_dir(self) -> None:
        os.makedirs(self.data_dir, exist_ok=True)

    # ----- handler registry ------------------------------------------------ #

    def register_handler(self, inject_type: str, fn: Callable[..., Any]) -> None:
        with self._lock:
            self._handlers[inject_type] = fn

    def registered_types(self) -> List[str]:
        with self._lock:
            return sorted(self._handlers.keys())

    # ----- MSEL authoring -------------------------------------------------- #

    def add_inject(self, inject: Inject) -> Inject:
        with self._lock:
            self._injects[inject.id] = inject
            self._order.append(inject.id)
            return inject

    def update_inject(self, inject_id: str, **fields) -> Inject:
        with self._lock:
            inj = self._require(inject_id)
            if inj.status == InjectStatus.FIRING.value:
                raise ValueError("cannot edit an inject while it is firing")
            for k, v in fields.items():
                if hasattr(inj, k) and k != "id":
                    setattr(inj, k, v)
            return inj

    def remove_inject(self, inject_id: str) -> None:
        with self._lock:
            self._require(inject_id)
            del self._injects[inject_id]
            self._order = [i for i in self._order if i != inject_id]

    def _require(self, inject_id: str) -> Inject:
        inj = self._injects.get(inject_id)
        if inj is None:
            raise KeyError(f"unknown inject {inject_id!r}")
        return inj

    def ordered(self) -> List[Inject]:
        with self._lock:
            return [self._injects[i] for i in self._order if i in self._injects]

    # ----- persistence ----------------------------------------------------- #

    def save(self, path: Optional[str] = None) -> str:
        path = path or self.msel_path
        self._ensure_dir()
        with self._lock:
            payload = {"saved_at": _iso(),
                       "injects": [asdict(i) for i in self.ordered()]}
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
        return path

    def load(self, path: Optional[str] = None) -> int:
        path = path or self.msel_path
        if not os.path.exists(path):
            return 0
        with open(path) as fh:
            payload = json.load(fh)
        with self._lock:
            self._injects.clear()
            self._order.clear()
            for row in payload.get("injects", []):
                known = {k: row[k] for k in row if k in Inject.__dataclass_fields__}
                inj = Inject(**known)
                inj.reset_runtime()
                self._injects[inj.id] = inj
                self._order.append(inj.id)
        return len(self._order)

    def _append_timeline(self, event: Dict[str, Any]) -> None:
        self._ensure_dir()
        event = {"ts": _iso(), **event}
        try:
            with open(self.timeline_path, "a") as fh:
                fh.write(json.dumps(event) + "\n")
        except Exception:
            pass

    def timeline(self, limit: int = 500) -> List[Dict[str, Any]]:
        if not os.path.exists(self.timeline_path):
            return []
        with open(self.timeline_path) as fh:
            lines = fh.readlines()
        return [json.loads(l) for l in lines[-limit:]]

    # ----- exercise control ------------------------------------------------ #

    def arm(self, t_zero: Optional[float] = None) -> Dict[str, Any]:
        with self._lock:
            if self._armed:
                raise RuntimeError("exercise already armed")
            self._t_zero = t_zero if t_zero is not None else _now()
            self._armed = True
            self._paused = False
            self._abort_event.clear()
            self._stop_loop.clear()
            for inj in self.ordered():
                if inj.status == InjectStatus.PENDING.value:
                    inj.status = InjectStatus.ARMED.value
                    inj.armed_at = _now()
                    inj.due_at = self._resolve_due(inj)
            self._append_timeline({"event": "arm", "t_zero": _iso(self._t_zero),
                                   "inject_count": len(self._order)})
        self._loop_thread = threading.Thread(target=self._loop, name="msel-loop", daemon=True)
        self._loop_thread.start()
        return self.status()

    def pause(self) -> None:
        with self._lock:
            self._paused = True
            self._append_timeline({"event": "pause"})

    def resume(self) -> None:
        with self._lock:
            self._paused = False
            self._append_timeline({"event": "resume"})

    def abort(self, reason: str = "operator abort") -> Dict[str, Any]:
        with self._lock:
            self._abort_event.set()
            self._stop_loop.set()
            self._armed = False
            self._paused = False
            cancelled = 0
            for inj in self.ordered():
                if inj.status in (InjectStatus.ARMED.value, InjectStatus.PENDING.value):
                    inj.status = InjectStatus.ABORTED.value
                    cancelled += 1
            self._append_timeline({"event": "ABORT", "reason": reason,
                                   "pending_cancelled": cancelled})
        return {"aborted": True, "reason": reason, "pending_cancelled": cancelled}

    def fire_now(self, inject_id: str) -> Dict[str, Any]:
        with self._lock:
            inj = self._require(inject_id)
            if inj.status == InjectStatus.FIRING.value:
                raise ValueError("inject already firing")
            self._dispatch(inj, manual=True)
        return {"fired": inject_id}

    # ----- trigger resolution --------------------------------------------- #

    def _resolve_due(self, inj: Inject) -> Optional[float]:
        trig = inj.trigger or {"type": "manual"}
        ttype = trig.get("type", "manual")
        if ttype == "offset":
            base = self._t_zero if self._t_zero is not None else _now()
            return base + float(trig.get("seconds", 0))
        if ttype == "absolute":
            at = trig.get("at")
            if not at:
                return None
            try:
                return datetime.fromisoformat(at.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
        return None

    def _dependency_due(self, inj: Inject) -> Optional[float]:
        trig = inj.trigger or {}
        if trig.get("type") != "after":
            return None
        dep = self._injects.get(trig.get("inject_id", ""))
        if dep is None or dep.completed_at is None:
            return None
        if dep.status != InjectStatus.COMPLETE.value:
            return None
        return dep.completed_at + float(trig.get("delay", 0))

    # ----- scheduler loop -------------------------------------------------- #

    def _loop(self) -> None:
        while not self._stop_loop.is_set():
            if not self._paused:
                self._tick()
            time.sleep(_TICK_SECONDS)

    def _tick(self) -> None:
        now = _now()
        with self._lock:
            for inj in self.ordered():
                if inj.status != InjectStatus.ARMED.value:
                    continue
                trig_type = (inj.trigger or {}).get("type", "manual")
                if trig_type == "manual":
                    continue
                if trig_type == "after":
                    due = self._dependency_due(inj)
                    if due is not None:
                        inj.due_at = due
                due = inj.due_at
                if due is not None and now >= due:
                    self._dispatch(inj)

    # ----- dispatch -------------------------------------------------------- #

    def _dispatch(self, inj: Inject, manual: bool = False) -> None:
        inj.status = InjectStatus.FIRING.value
        inj.fired_at = _now()
        self._append_timeline({"event": "fire", "inject_id": inj.id, "name": inj.name,
                               "type": inj.inject_type, "target": inj.target,
                               "unit": inj.unit, "phase": inj.phase, "manual": manual})
        worker = threading.Thread(target=self._run_handler, args=(inj,),
                                  name=f"msel-{inj.id}", daemon=True)
        self._workers[inj.id] = worker
        worker.start()

    def _run_handler(self, inj: Inject) -> None:
        handler = self._handlers.get(inj.inject_type)
        try:
            if handler is None:
                raise HandlerNotRegistered(
                    f"HANDLER_NOT_REGISTERED for inject_type '{inj.inject_type}'")
            result = handler(inj, self._abort_event)
            with self._lock:
                inj.status = InjectStatus.COMPLETE.value
                inj.completed_at = _now()
                inj.result = result
            self._append_timeline({"event": "complete", "inject_id": inj.id,
                                   "name": inj.name,
                                   "duration_s": round((inj.completed_at or 0) - (inj.fired_at or 0), 3)})
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                if self._abort_event.is_set():
                    inj.status = InjectStatus.ABORTED.value
                else:
                    inj.status = InjectStatus.FAILED.value
                inj.completed_at = _now()
                inj.error = f"{type(exc).__name__}: {exc}"
            self._append_timeline({
                "event": "error" if inj.status == InjectStatus.FAILED.value else "aborted",
                "inject_id": inj.id, "name": inj.name, "error": inj.error})
        finally:
            self._workers.pop(inj.id, None)

    # ----- status ---------------------------------------------------------- #

    def clock(self) -> Optional[float]:
        if self._t_zero is None:
            return None
        return _now() - self._t_zero

    def status(self) -> Dict[str, Any]:
        with self._lock:
            injects = [asdict(i) for i in self.ordered()]
            counts: Dict[str, int] = {}
            for i in injects:
                counts[i["status"]] = counts.get(i["status"], 0) + 1
            return {"armed": self._armed, "paused": self._paused,
                    "aborted": self._abort_event.is_set(),
                    "t_zero": _iso(self._t_zero) if self._t_zero else None,
                    "clock_s": round(self.clock(), 1) if self.clock() is not None else None,
                    "registered_types": sorted(self._handlers.keys()),
                    "counts": counts, "injects": injects,
                    "active_workers": list(self._workers.keys())}

    def reset(self) -> None:
        with self._lock:
            self.abort(reason="reset")
            self._t_zero = None
            self._abort_event.clear()
            self._stop_loop.set()
            for inj in self.ordered():
                inj.reset_runtime()


# process singleton
engine = MSELEngine()


def make_blueprint(url_prefix: str = "/api/msel"):
    from flask import Blueprint, jsonify, request

    bp = Blueprint("msel", __name__, url_prefix=url_prefix)

    @bp.get("/status")
    def status():
        return jsonify(engine.status())

    @bp.get("/timeline")
    def timeline():
        return jsonify({"events": engine.timeline(int(request.args.get("limit", 500)))})

    @bp.post("/inject")
    def add_inject():
        body = request.get_json(force=True) or {}
        allowed = {"name", "inject_type", "target", "params", "trigger", "unit", "phase"}
        kwargs = {k: v for k, v in body.items() if k in allowed}
        if not kwargs.get("name") or not kwargs.get("inject_type"):
            return jsonify({"error": "name and inject_type are required"}), 400
        return jsonify(asdict(engine.add_inject(Inject(**kwargs)))), 201

    @bp.patch("/inject/<inject_id>")
    def update_inject(inject_id):
        try:
            return jsonify(asdict(engine.update_inject(inject_id, **(request.get_json(force=True) or {}))))
        except (KeyError, ValueError) as e:
            return jsonify({"error": str(e)}), 400

    @bp.delete("/inject/<inject_id>")
    def delete_inject(inject_id):
        try:
            engine.remove_inject(inject_id)
        except KeyError as e:
            return jsonify({"error": str(e)}), 404
        return jsonify({"deleted": inject_id})

    @bp.post("/inject/<inject_id>/fire")
    def fire_inject(inject_id):
        try:
            return jsonify(engine.fire_now(inject_id))
        except (KeyError, ValueError) as e:
            return jsonify({"error": str(e)}), 400

    @bp.post("/arm")
    def arm():
        body = request.get_json(silent=True) or {}
        t = None
        if body.get("t_zero"):
            try:
                t = datetime.fromisoformat(body["t_zero"].replace("Z", "+00:00")).timestamp()
            except ValueError:
                return jsonify({"error": "bad t_zero"}), 400
        try:
            return jsonify(engine.arm(t))
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 409

    @bp.post("/pause")
    def pause():
        engine.pause()
        return jsonify(engine.status())

    @bp.post("/resume")
    def resume():
        engine.resume()
        return jsonify(engine.status())

    @bp.post("/abort")
    def abort():
        body = request.get_json(silent=True) or {}
        return jsonify(engine.abort(body.get("reason", "operator abort")))

    @bp.post("/reset")
    def reset():
        engine.reset()
        return jsonify(engine.status())

    @bp.post("/save")
    def save():
        return jsonify({"saved": True, "path": engine.save()})

    @bp.post("/load")
    def load():
        return jsonify({"loaded": engine.load()})

    return bp
