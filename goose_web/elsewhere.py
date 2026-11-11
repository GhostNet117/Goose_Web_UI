"""Working elsewhere (spec 020): sessions of the NATIVE profile that another program is writing - Goose Desktop, the
goose CLI (also a Windows scheduled task running `goose run`), or a Goose scheduler job - shown read-only to
administrators next to the herd.

Source: the profile's sessions.db (<root>/data/sessions/sessions.db), which Goose Desktop and the CLI write at the same
time. Goose Web only READS it: a read-only connection (`mode=ro`, `PRAGMA query_only`), a short busy timeout, a few
indexed queries, closed at once - never a write, never a long lock. It is opened only when the file changed (stat of
the database and its -wal) and at most once per `elsewhere.poll_seconds`, and only while an administrator has Goose
Web open (a tab that asked for the list).

What counts:
* activity of a session = its newest message (candidates come from messages.timestamp and sessions.updated_at, both
  indexed; updated_at itself is not activity - just opening a chat bumps it); a chat without messages is not listed;
  a sub-agent session's activity counts for its parent
* "running"  = its last message is an assistant tool request (a tool is running; long tool calls write nothing) and
  the last write is at most `stale_minutes` old, or a user message / tool result (the model is answering) written
  within `active_minutes` (a cancelled run also ends with a tool result, so it does not stay "running")
* "finished" = otherwise; it leaves Working elsewhere and becomes a Done marker (below)
* chats Goose Web itself runs, or wrote at most two minutes before their last write (prompt, turn end, edit; a
  restored herd mark counts), are not "elsewhere"; viewing a chat in Goose Web does not make it Goose Web's
Done (1.16.0): every session that FINISHED elsewhere after the list started watching (a run that was
working elsewhere and went idle, and one created and finished between two polls - also while nobody had Goose Web
open: the next read starts at the stored watermark, at most `done_hours` back) becomes a Done entry, grouped like the
working list, persisted in the gateway database (chat_state, session "~elsewhere", kind "done"), until an
administrator interacts with it in Goose Web: opens any of its sessions (_gw/seen; opening a group's session clears
the whole group), clears it, or "mark all read". Opening it in Goose Desktop or the CLI cannot be seen and does not
clear it.
Grouping: one job usually makes many short sessions (a scheduled task running `goose run` every few minutes): sessions
with the same schedule id, or the same name without its trailing date/number in the same working folder, form one
entry with a count and the newest session.
Privacy: tabs get names, ids, counts and times only - no folders, no message content.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import logging
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("goose_web.elsewhere")

DEFAULTS = {"enabled": True, "poll_seconds": 20, "active_minutes": 5, "stale_minutes": 30, "done_hours": 24,
            "max_items": 40}
DONE_ROW = "~elsewhere"     # chat_state session id of the Done markers ("~" = never a Goose session id)
DONE_LIST = 20             # sessions remembered per Done group (the count goes on)
DONE_IDS = 300             # session ids per group used to count each session once
DONE_SEND = 10             # sessions per Done group sent to tabs
ACKED_MAX = 5000
OWN_GRACE = 120.0          # a write this soon after Goose Web's own activity in the chat is Goose Web's
MAX_SESSIONS = 300         # candidate sessions read per poll (newest first)
LIST_SESSIONS = 5          # sessions listed per group
_TRAIL = re.compile(r"(?:[\s\-_:#.,/]*(?:\d[\d\-_:./]*(?:[Tt ]\d[\d:.]*)?[Zz]?|\(\d+\)|#\d+))+$")


def name_prefix(name: str) -> str:
    """'Hourly-Report 2026-11-11 04:00' -> 'Hourly-Report'; 'Report (3)' -> 'Report'; 'Weekly' -> 'Weekly'."""
    n = (name or "").strip()
    return _TRAIL.sub("", n).strip(" -_:#.,/") or n


def _epoch(ts: Any) -> float | None:
    """Goose's TIMESTAMP text ('YYYY-MM-DD HH:MM:SS', UTC) -> epoch seconds."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return float(calendar.timegm(time.strptime(s.split("+")[0], fmt)))
        except ValueError:
            continue
    return None


def _utc(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))


def read_activity(db: Path, horizon: float, skip: set[str] | None = None) -> list[dict]:
    """Sessions with any write since `horizon` (epoch), newest first. Read-only; raises sqlite3.Error when the
    database is locked or unreadable (the caller keeps its previous answer)."""
    con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=0.5, check_same_thread=False)
    try:
        con.execute("PRAGMA query_only=1")
        since = _utc(horizon)
        recent = {r[0]: r[1] for r in con.execute(
            "SELECT session_id, MAX(timestamp) FROM messages WHERE timestamp >= ? GROUP BY session_id", (since,))}
        rows = con.execute(
            "SELECT id, name, session_type, schedule_id, working_dir, created_at, updated_at, parent_session_id "
            "FROM sessions WHERE updated_at >= ? OR created_at >= ? OR id IN (SELECT value FROM json_each(?)) "
            "ORDER BY updated_at DESC LIMIT ?", (since, since, json.dumps(list(recent)), MAX_SESSIONS)).fetchall()
        by_id = {r[0]: r for r in rows}
        parents = {r[7] for r in rows if r[7] and r[7] not in by_id}
        if parents:
            for r in con.execute(
                    "SELECT id, name, session_type, schedule_id, working_dir, created_at, updated_at, parent_session_id "
                    "FROM sessions WHERE id IN (SELECT value FROM json_each(?))", (json.dumps(sorted(parents)),)):
                by_id[r[0]] = r
        out = []
        for sid, r in by_id.items():
            times = [x for x in (_epoch(r[5]), _epoch(r[6]), _epoch(recent.get(sid))) if x is not None]
            last = max(times) if times else None
            out.append({"sessionId": sid, "name": r[1] or "", "type": r[2] or "", "scheduleId": r[3] or "",
                        "cwd": r[4] or "", "created": _epoch(r[5]), "last": last, "parent": r[7] or "",
                        "role": "", "tool": False})
        # The last message of every top-level candidate: who spoke last decides running / finished, and its time is the
        # session's activity. updated_at is not: opening a chat (session/load, also in Goose Web) bumps it.
        for e in out:
            if e["parent"] or (skip and e["sessionId"] in skip):
                continue
            m = con.execute("SELECT role, CASE WHEN role='assistant' THEN instr(content_json, '\"toolRequest\"') "
                            "ELSE 0 END, created_timestamp, timestamp FROM messages WHERE session_id=? "
                            "ORDER BY created_timestamp DESC, id DESC LIMIT 1", (e["sessionId"],)).fetchone()
            if m:
                e["role"], e["tool"] = m[0] or "", bool(m[1])
                times = [x for x in (_epoch(m[2]), _epoch(m[3]), _epoch(recent.get(e["sessionId"]))) if x is not None]
                e["last"] = max(times) if times else e["last"]
            else:
                e["empty"] = True   # no message yet (a new chat nobody typed into): nothing runs
        return out
    finally:
        con.close()


def session_status(r: dict, now: float, active_s: float, stale_s: float) -> str:
    """running / finished from who wrote last and when:
    * assistant tool request -> a tool runs: running for up to stale_s without writes (long tool calls write nothing)
    * user message (a prompt, or a tool result going back to the model) -> running if written within active_s; a
      cancelled run also ends with a tool result, so after active_s it counts as finished
    * a sub-agent of the session wrote within active_s -> running
    * the final assistant message -> finished"""
    age = now - (r.get("last") or 0)
    if r.get("tool"):
        return "running" if age <= stale_s else "finished"
    if r.get("role") == "user" or r.get("sub"):
        return "running" if age <= active_s else "finished"
    return "finished"


def group_key(s: dict) -> str:
    if s.get("scheduleId"):
        return "schedule\0" + s["scheduleId"]
    return "name\0" + name_prefix(s.get("name") or "").lower() + "\0" + (s.get("cwd") or "").lower()


def hkey(k: str) -> str:
    return hashlib.sha256(k.encode("utf-8", "replace")).hexdigest()[:16]


def classify(rows: list[dict], *, now: float, own: Callable[[str, float], bool], stale_s: float,
             active_s: float = 300.0) -> list[dict]:
    """Top-level sessions written by another program, each with its status (running / finished)."""
    by_id = {r["sessionId"]: dict(r) for r in rows}
    for r in rows:   # a sub-agent's writes are its parent's activity
        p = by_id.get(r.get("parent") or "")
        if p is not None and (r.get("last") or 0) > (p.get("last") or 0):
            p["last"] = r["last"]
            p["sub"] = True
    out = []
    for r in by_id.values():
        if r.get("parent") or r.get("type") == "hidden" or r.get("empty") or not r.get("last"):
            continue
        if own(r["sessionId"], r["last"]):
            continue
        out.append({**r, "status": session_status(r, now, active_s, stale_s)})
    return out


def build_items(rows: list[dict], *, now: float, own: Callable[[str, float], bool], stale_s: float,
                max_items: int, scheduler_owner: str = "", active_s: float = 300.0, **_: Any) -> list[dict]:
    """The "Working elsewhere" list: groups of sessions another program is running now (pure)."""
    sessions = [s for s in classify(rows, now=now, own=own, stale_s=stale_s, active_s=active_s)
                if s["status"] == "running"]
    groups: dict[str, list[dict]] = {}
    for s in sessions:
        groups.setdefault(group_key(s), []).append(s)
    items = []
    for k, ss in groups.items():
        ss.sort(key=lambda s: -(s["last"] or 0))
        latest = ss[0]
        running = sum(1 for s in ss if s["status"] == "running")
        title = (f"Scheduled job {latest['scheduleId']}" if latest.get("scheduleId") else
                 name_prefix(latest["name"]) if len(ss) > 1 else latest["name"]) or "Untitled session"
        items.append({
            "key": hkey(k), "title": title[:200],
            "sessionId": latest["sessionId"], "latestTitle": (latest["name"] or "")[:200], "count": len(ss),
            "running": running, "status": "running" if running else "finished", "last": latest["last"],
            "first": min((s.get("created") or s["last"]) for s in ss),
            "source": "schedule" if latest.get("scheduleId") else "other",
            "scheduleId": latest.get("scheduleId") or "", "scheduler": scheduler_owner if latest.get("scheduleId") else "",
            "sessions": [{"sessionId": s["sessionId"], "title": (s["name"] or "")[:200], "last": s["last"],
                          "status": s["status"]} for s in ss[:LIST_SESSIONS]]})
    items.sort(key=lambda i: (i["status"] != "running", -(i["last"] or 0)))
    return items[:max_items]


class ElsewhereWatcher:
    """Working elsewhere + Done for one native profile (one per native Upstream; driven by Hub._elsewhere_loop)."""

    def __init__(self, up: Any, knobs: dict, state: dict | None = None, save: Callable[[dict], None] | None = None):
        self.up = up
        self.knobs = knobs
        self.sig: tuple | None = None
        self.rows: list[dict] | None = None
        self.items: list[dict] = []
        self.ticked = 0.0
        self.reads = 0
        self.error = ""
        self.save = save
        st = state if isinstance(state, dict) else {}
        # watermark: sessions whose last write is older were seen already (first start: no backfill of history)
        self.watermark = float(st.get("watermark") or time.time())
        self.groups: dict[str, dict] = {k: g for k, g in (st.get("groups") or {}).items() if isinstance(g, dict)}
        self.acked: dict[str, float] = {str(k): float(v) for k, v in (st.get("acked") or {}).items()
                                        if isinstance(v, (int, float))}
        if not st and save is not None:
            self._persist()

    # ---------------------------------------------------------------- Done markers
    def state(self) -> dict:
        return {"watermark": self.watermark, "groups": self.groups, "acked": self.acked}

    def _persist(self) -> None:
        if self.save is not None:
            try:
                self.save(self.state())
            except Exception:
                log.exception("running elsewhere: saving the Done markers")

    def done(self) -> list[dict]:
        """What tabs get: newest first, names / ids / times only."""
        out = []
        for g in sorted(self.groups.values(), key=lambda g: -(g.get("last") or 0)):
            ss = g.get("sessions") or []
            out.append({"key": g["key"], "title": g.get("title") or "Untitled session",
                        "sessionId": ss[0]["sessionId"] if ss else "", "latestTitle": ss[0]["title"] if ss else "",
                        "count": int(g.get("count") or len(ss)), "last": g.get("last"), "first": g.get("first"),
                        "source": g.get("source") or "other", "scheduleId": g.get("scheduleId") or "",
                        "sessions": ss[:DONE_SEND]})
        return out

    def done_ids(self) -> set[str]:
        return {s["sessionId"] for g in self.groups.values() for s in g.get("sessions") or []}

    def _add_done(self, s: dict) -> bool:
        k = group_key(s)
        key = hkey(k)
        g = self.groups.get(key)
        if g is None:
            g = self.groups[key] = {"key": key, "title": "", "count": 0, "first": s["last"], "last": 0.0,
                                    "source": "schedule" if s.get("scheduleId") else "other",
                                    "scheduleId": s.get("scheduleId") or "", "sessions": [], "ids": []}
        sid = s["sessionId"]
        cur = next((x for x in g["sessions"] if x["sessionId"] == sid), None)
        if cur is not None and cur["last"] >= s["last"]:
            return False
        if sid not in g["ids"]:
            g["ids"] = (g["ids"] + [sid])[-DONE_IDS:]
            g["count"] = int(g.get("count") or 0) + 1
        g["sessions"] = [x for x in g["sessions"] if x["sessionId"] != sid]
        g["sessions"].insert(0, {"sessionId": sid, "title": (s.get("name") or "")[:200], "last": s["last"]})
        g["sessions"].sort(key=lambda x: -(x["last"] or 0))
        g["sessions"] = g["sessions"][:DONE_LIST]
        g["last"] = max(float(g.get("last") or 0), s["last"])
        g["first"] = min(float(g.get("first") or s["last"]), s["last"])
        many = int(g["count"]) > 1
        g["title"] = ((f"Scheduled job {g['scheduleId']}" if g.get("scheduleId") else
                       name_prefix(s.get("name") or "") if many else s.get("name") or "") or "Untitled session")[:200]
        if len(self.groups) > int(self.knobs.get("max_items") or 40):   # a sane cap: the oldest group goes
            oldest = min(self.groups.values(), key=lambda x: x.get("last") or 0)
            self._ack_group(oldest)
        return True

    def _ack_group(self, g: dict) -> None:
        now = time.time()
        for sid in g.get("ids") or []:   # sessions counted but no longer listed
            self.acked[sid] = max(self.acked.get(sid, 0.0), now)
        for x in g.get("sessions") or []:
            self.acked[x["sessionId"]] = max(self.acked.get(x["sessionId"], 0.0), float(x.get("last") or 0))
        self.groups.pop(g["key"], None)
        if len(self.acked) > ACKED_MAX:
            for sid, _ in sorted(self.acked.items(), key=lambda kv: kv[1])[:len(self.acked) - ACKED_MAX]:
                self.acked.pop(sid, None)

    def ack(self, sid: str) -> bool:
        """An administrator opened `sid` in Goose Web: its Done group goes (all of it - the group is one entry)."""
        hit = [g for g in self.groups.values()
               if sid in (g.get("ids") or []) or any(x["sessionId"] == sid for x in g.get("sessions") or [])]
        for g in hit:
            self._ack_group(g)
        if hit:
            self._persist()
        return bool(hit)

    def clear(self, key: str | None = None) -> bool:
        hit = [g for g in self.groups.values() if key is None or g["key"] == key]
        for g in hit:
            self._ack_group(g)
        if hit:
            self._persist()
        return bool(hit)

    def _update_done(self, sessions: list[dict], fresh: bool, now: float) -> bool:
        changed = False
        running = {s["sessionId"] for s in sessions if s["status"] == "running"}
        for g in list(self.groups.values()):   # working elsewhere again: not done any more (comes back when it ends)
            keep = [x for x in g["sessions"] if x["sessionId"] not in running]
            if len(keep) != len(g["sessions"]):
                changed = True
                g["sessions"] = keep
                if not keep:
                    self.groups.pop(g["key"], None)
        for s in sessions:
            if s["status"] != "finished" or s["last"] <= self.watermark - 5:
                continue
            if s["last"] <= self.acked.get(s["sessionId"], 0.0):
                continue
            changed = self._add_done(s) or changed
        if fresh:
            self.watermark = max(self.watermark, now - 5)
            cutoff = now - float(self.knobs.get("done_hours") or 24) * 3600 - 7200
            for sid in [k for k, v in self.acked.items() if v < cutoff]:
                self.acked.pop(sid, None)
            changed = True   # the watermark moved: persisted (cheap: one row, written in the background)
        if changed:
            self._persist()
        return changed

    # ---------------------------------------------------------------- Working elsewhere
    def running_ids(self) -> set[str]:
        if time.time() - self.ticked > 3 * float(self.knobs["poll_seconds"]):
            return set()   # stale: nobody watches; never refuse a prompt on old information
        return {s["sessionId"] for i in self.items for s in i["sessions"] if s["status"] == "running"} | \
            {i["sessionId"] for i in self.items if i["status"] == "running"}

    def _own(self, sid: str, last: float) -> bool:
        """Goose Web's own chat: running in its worker, or Goose Web wrote it (prompt, turn end, edit) at most
        OWN_GRACE before the last write. Opening a chat (also the read-only view) does not count."""
        s = self.up.sessions.get(sid)
        return s is not None and (s.running() or s.wrote_at >= last - OWN_GRACE)

    async def tick(self) -> bool:
        """Re-read if the database changed; rebuild the lists. True if what tabs see changed."""
        import asyncio
        k = self.knobs
        paths = self.up._db_paths()
        sig = self.up._db_sig(paths)
        now = time.time()
        fresh = False
        if sig is None:
            self.rows = []
        elif sig != self.sig or self.rows is None:
            window = now - max(float(k["stale_minutes"]), float(k["active_minutes"])) * 60
            horizon = max(now - float(k.get("done_hours") or 24) * 3600, min(window, self.watermark - 60))
            skip = {sid for sid, s in self.up.sessions.items() if s.running()}
            try:
                self.rows = await asyncio.to_thread(read_activity, paths[0], horizon, skip)
                self.sig, self.error = sig, ""
                self.reads += 1
                fresh = True
            except (sqlite3.Error, OSError) as e:   # locked by a writer, or being replaced: keep the last answer
                self.error = str(e)
                log.debug("running elsewhere: cannot read %s: %s", paths[0], e)
                if self.rows is None:
                    self.rows = []
        try:
            w = self.up.worker
            owner = "Goose Web" if getattr(w, "scheduler", False) else "Goose Desktop"
        except Exception:
            owner = ""
        stale_s, active_s = float(k["stale_minutes"]) * 60, float(k["active_minutes"]) * 60
        before = self.done()
        self._update_done(classify(self.rows or [], now=now, own=self._own, stale_s=stale_s, active_s=active_s),
                          fresh, now)
        items = build_items(self.rows or [], now=now, own=self._own, stale_s=stale_s, max_items=int(k["max_items"]),
                            scheduler_owner=owner, active_s=active_s)
        self.ticked = now
        changed = items != self.items or self.done() != before
        self.items = items
        return changed
