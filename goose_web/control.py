"""Local control channel: is anything running, and drain before a restart (FIX deploy-interrupts-running-turns, 1.16.0).

A deploy or an upgrade must not restart the gateway while a turn runs in any worker: Goose cancels a run when its
worker stops, and a turn that waits for a long tool call or a sub-agent uses no CPU, so no outside measurement can
tell it from an idle worker. Only the gateway knows. This module lets a local script ask it.

The channel is a folder, ``<system_dir>/run/`` (next to config.yaml and the database): no network listener and no
credential. Whoever can write the gateway's system folder can ask; that is already everyone who can change its
configuration.

  gateway.json     written at start-up: {"pid", "version", "startedAt", "protocol"}; removed at a clean stop
  req-<id>.json    a request: {"action": "status" | "drain" | "undrain", "seconds": N, "reason": "..."}
  resp-<id>.json   the gateway's answer (within about a second): {"id", "pid", "version", "at", "draining",
                   "busy": [...]} - written atomically; the client deletes it after reading

The gateway looks for requests once a second (one directory listing of a nearly empty folder). ``busy`` lists every
turn the gateway knows is running, in every worker: a prompt that has not finished (including long tool calls and
sub-agents, which run inside the turn), a pending permission request or question, a direct tool call, a prompt that
is still being checked, and a job of Goose's scheduler running inside one of the gateway's workers.

``drain`` refuses new prompts for N seconds (the deploy asks right before its last check and the restart, so no turn
can start in between) and tells every open tab; ``undrain`` ends it early. A drain also ends by itself.

The client side (``goose-web gateway status|drain|undrain``) also handles a gateway older than 1.16 that does not
answer: it then reads the herd marks the gateway keeps in its database (spec 019: "working" / "needs_you" are
written within half a second of a change) and checks that something listens on the gateway's port.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("goose_web.control")

PROTOCOL = 1
POLL_SECONDS = 1.0
RESPONSE_MAX_AGE = 600          # unread answers older than this are removed
DRAIN_DEFAULT = 120
DRAIN_MAX = 900
SCHEDULE_TIMEOUT = 8.0          # asking a worker's scheduler which jobs run
# Exit codes of `goose-web gateway ...` (closeout 2026-11-11 D4): `status` 0 idle / 3 busy or unknown; `drain` and
# `undrain` 0 = done (whatever runs: ask `status` for that) / 5 = not done (no answer, or a gateway older than 1.16
# that cannot drain). 2 = usage error (argparse).
EXIT_IDLE, EXIT_BUSY, EXIT_USAGE, EXIT_NOT_DONE = 0, 3, 2, 5
EXIT_DONE = EXIT_IDLE


def run_dir(settings) -> Path:
    return Path(settings.system_dir) / "run"


def _atomic_write(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    for _ in range(20):   # Windows: a reader holding the target open makes the replace fail for a moment
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.05)
    os.replace(tmp, path)


def _read_json(path: Path) -> dict | None:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def pid_alive(pid: Any) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = ctypes.c_void_p
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ctypes.get_last_error() == 5   # access denied: it exists
        try:
            code = ctypes.c_ulong()
            ok = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
            return bool(ok) and code.value == 259   # STILL_ACTIVE
        finally:
            k32.CloseHandle(ctypes.c_void_p(h))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# ====================================================================== gateway side
class ControlChannel:
    """Answers the requests in <system_dir>/run (one task, started by the app's lifespan)."""

    def __init__(self, hub: Any, settings: Any, version: str):
        self.hub = hub
        self.dir = run_dir(settings)
        self.version = version
        self.started = time.time()
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            for p in self.dir.glob("req-*.json"):   # left over from before this start: nobody waits for them any more
                p.unlink(missing_ok=True)
            _atomic_write(self.dir / "gateway.json", {"pid": os.getpid(), "version": self.version,
                                                      "startedAt": self.started, "protocol": PROTOCOL})
        except OSError:
            log.exception("control channel: cannot write %s", self.dir)
            return
        self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
        info = _read_json(self.dir / "gateway.json")
        if info and info.get("pid") == os.getpid():
            try:
                (self.dir / "gateway.json").unlink()
            except OSError:
                pass

    async def _loop(self) -> None:
        last_clean = 0.0
        while True:
            try:
                await asyncio.sleep(POLL_SECONDS)
                self.hub.expire_drain()
                reqs = await asyncio.to_thread(self._pending)
                for p in reqs:
                    await self.handle_file(p)
                if time.time() - last_clean > 60:
                    last_clean = time.time()
                    await asyncio.to_thread(self._clean)
            except asyncio.CancelledError:
                return
            except Exception:   # pragma: no cover - the channel must never die
                log.exception("control channel")

    def _pending(self) -> list[Path]:
        try:
            return sorted(self.dir.glob("req-*.json"))
        except OSError:
            return []

    def _clean(self) -> None:
        now = time.time()
        for p in self.dir.glob("resp-*.json"):
            try:
                if now - p.stat().st_mtime > RESPONSE_MAX_AGE:
                    p.unlink()
            except OSError:
                pass

    async def handle_file(self, p: Path) -> None:
        rid = p.name[4:-5]
        req = _read_json(p)
        try:
            p.unlink()
        except OSError:
            pass
        if not rid or not all(ch.isalnum() or ch in "-_" for ch in rid) or len(rid) > 64:
            return
        resp = await self.handle(req or {})
        resp["id"] = rid
        try:
            await asyncio.to_thread(_atomic_write, self.dir / f"resp-{rid}.json", resp)
        except OSError:
            log.exception("control channel: cannot answer %s", rid)

    async def handle(self, req: dict) -> dict:
        action = str(req.get("action") or "status")
        reason = str(req.get("reason") or "")[:200]
        if action == "drain":
            try:
                secs = float(req.get("seconds") or DRAIN_DEFAULT)
            except (TypeError, ValueError):
                secs = DRAIN_DEFAULT
            self.hub.set_draining(min(max(secs, 5.0), DRAIN_MAX), reason)
        elif action == "undrain":
            self.hub.end_draining("cancelled")
        elif action != "status":
            return self._answer(error=f"unknown action {action!r}")
        log.info("control: %s%s", action, f" ({reason})" if reason else "")
        busy = await self.hub.busy_report()
        return self._answer(busy=busy)

    def _answer(self, busy: list | None = None, error: str = "") -> dict:
        d = {"pid": os.getpid(), "version": self.version, "startedAt": self.started, "at": time.time(),
             "protocol": PROTOCOL, "draining": self.hub.draining, "busy": busy or []}
        if error:
            d["error"] = error
        return d


# ====================================================================== client side (CLI, deploy scripts)
def _listening(settings, timeout: float = 3.0) -> bool:
    host = str(settings.get("server", "host") or "127.0.0.1").strip("[]")
    try:   # bound to every interface ("any" address): ask on loopback
        any_v4 = ipaddress.ip_address(host).is_unspecified and ipaddress.ip_address(host).version == 4
        any_v6 = ipaddress.ip_address(host).is_unspecified and not any_v4
    except ValueError:
        any_v4, any_v6 = host in ("", "*"), False
    if any_v4:
        host = "127.0.0.1"
    elif any_v6:
        host = "::1"
    try:
        port = int(settings.get("server", "port") or 8710)
    except (TypeError, ValueError):
        return False
    try:
        with socket.create_connection((host.strip("[]"), port), timeout=timeout):
            return True
    except OSError:
        return False


def marks_busy(settings) -> list[dict]:
    """Chats the database says are running (herd marks, spec 019) - the view of a gateway older than 1.16."""
    db = Path(settings.system_dir) / "goose-web.db"
    if not db.exists():
        return []
    con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=5)
    try:
        rows = con.execute("SELECT profile, session_id, data FROM chat_state WHERE kind='mark'").fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()
    out = []
    for profile, sid, data in rows:
        try:
            m = json.loads(data)
        except (TypeError, ValueError):
            continue
        if isinstance(m, dict) and m.get("status") in ("working", "needs_you"):
            out.append({"profile": profile, "username": profile, "sessionId": sid, "title": str(m.get("title") or ""),
                        "status": m["status"], "since": m.get("since"),
                        "kind": "permission" if m["status"] == "needs_you" else "turn"})
    return out


def request(settings, action: str = "status", seconds: float = DRAIN_DEFAULT, reason: str = "",
            timeout: float = 20.0) -> dict:
    """Ask the gateway. Returns {"source", "running", "busy", "draining", "note", ...}; "busy" non-empty or
    "unknown" true means: do not restart now."""
    d = run_dir(settings)
    info = _read_json(d / "gateway.json")
    new_gateway = bool(info) and pid_alive(info.get("pid"))
    if new_gateway:
        rid = f"{int(time.time() * 1000)}-{os.getpid()}-{os.urandom(3).hex()}"
        try:
            _atomic_write(d / f"req-{rid}.json", {"action": action, "seconds": seconds, "reason": reason,
                                                  "at": time.time(), "by": os.getpid()})
        except OSError as e:
            return {"source": "none", "running": True, "unknown": True, "busy": [], "draining": None,
                    "note": f"cannot write a request into {d}: {e}"}
        end = time.monotonic() + timeout
        rp = d / f"resp-{rid}.json"
        while time.monotonic() < end:
            r = _read_json(rp)
            if r is not None:
                try:
                    rp.unlink()
                except OSError:
                    pass
                r.update(source="gateway", running=True)
                if r.get("error"):
                    r["unknown"] = True
                    r["note"] = r["error"]
                return r
            time.sleep(0.2)
        try:
            (d / f"req-{rid}.json").unlink(missing_ok=True)
        except OSError:
            pass
    if not _listening(settings):
        return {"source": "none", "running": False, "busy": [], "draining": None,
                "note": "the gateway is not running (nothing listens on its port)"}
    busy = marks_busy(settings)
    if new_gateway:
        return {"source": "database", "running": True, "unknown": True, "busy": busy, "draining": None,
                "pid": info.get("pid"), "version": info.get("version"),
                "note": f"the gateway (pid {info.get('pid')}) did not answer within {int(timeout)} s; "
                        "treated as busy"}
    note = "the running gateway does not answer the control channel (older than 1.16): running chats read from its " \
           "database (herd marks)"
    if action == "drain":
        note += "; it cannot drain, so a new prompt could still start before the restart"
    return {"source": "database", "running": True, "busy": busy, "draining": None, "note": note}


def is_busy(r: dict) -> bool:
    return bool(r.get("busy")) or bool(r.get("unknown"))


def action_done(r: dict) -> bool:
    """drain / undrain: the gateway answered and applied it, or no gateway runs (nothing to drain)."""
    if r.get("running") is False:
        return True
    return r.get("source") == "gateway" and not r.get("error")


def exit_code(action: str, r: dict) -> int:
    if action == "status":
        return EXIT_BUSY if is_busy(r) else EXIT_IDLE
    return EXIT_DONE if action_done(r) else EXIT_NOT_DONE


def describe(r: dict) -> list[str]:
    """Human-readable lines (the deploy log): the first one says IDLE or BUSY."""
    busy = r.get("busy") or []
    who = sorted({f"{b.get('username') or b.get('profile')}/{b.get('sessionId')}" for b in busy if b.get("sessionId")})
    if is_busy(r):
        head = f"BUSY: {len(busy)} running" + (f" ({', '.join(who)})" if who else "")
        if r.get("unknown"):
            head += " - state unknown"
    else:
        head = "IDLE: nothing running" + ("" if r.get("running") else " (gateway not running)")
    head += f" [source: {r.get('source')}]"
    lines = [head]
    if r.get("draining"):
        dr = r["draining"]
        lines.append(f"  draining until {time.strftime('%H:%M:%S', time.localtime(dr.get('until') or 0))}"
                     + (f" ({dr.get('reason')})" if dr.get("reason") else ""))
    for b in busy:
        since = b.get("since")
        when = time.strftime("%H:%M:%S", time.localtime(since)) if isinstance(since, (int, float)) else "?"
        title = str(b.get("title") or "")[:60]
        lines.append(f"  {b.get('kind', 'turn')}: {b.get('username') or b.get('profile')}/{b.get('sessionId') or '-'} "
                     f"{b.get('status') or ''} since {when}" + (f" \"{title}\"" if title else "")
                     + (f" - {b['detail']}" if b.get("detail") else ""))
    if r.get("note"):
        lines.append(f"  note: {r['note']}")
    return lines
