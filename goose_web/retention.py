"""Chat retention (spec 040): a chat, and the files uploaded to it, are deleted after N days without use.

Last use of a chat = the later of
  * when Goose Web last saw it used (table chat_access: opened, prompted, steered, stopped, forked, mode changed or any
    audited call naming it - from the hub's audit hook, app.make_audit_handler -> note_activity; at most one write a
    minute per chat), and
  * Goose's own times of the session (sessions.db of the profile, read-only: updated_at - Goose bumps it when a chat is
    opened, also in Goose Desktop - and created_at), which covers chats used outside Goose Web.

The sweep (`maybe_sweep` from the maintenance loop, at most hourly; `sweep` for Admin > Settings > Run now) deletes, per
profile, each top-level chat (session types Goose lists over ACP) whose last use is older than the period, through the
profile's Goose worker (ACP session/delete, the hub's internal request), with its sub-agent sessions; then the files
recorded for it (uploads + upload_links, spec 039) - a file only when it is still in a folder named Web_Uploads, the
profile may write there (as written and resolved), it is a regular file and the same file that was uploaded, and no
chat that is kept has it. Files never linked to a chat that exists go when their upload is older than the period.
Never deleted: a chat that is running, being opened, shown in a tab, with queued messages, steers, questions or an
unanswered request, a chat Goose Desktop / a scheduled job is running. At most CHATS_PER_SWEEP chats per sweep.
Every deletion is audited. 0 days = keep forever. The first automatic sweep waits FIRST_RUN_DELAY after retention is
first in force (the administrator can look at the preview first); Run now does not wait.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import stat
import time
import weakref
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.routing import Route

from .context import HTTPError

log = logging.getLogger("goose_web")

DAYS_DEFAULT = 180
DAYS_MAX = 3650
SWEEP_SECONDS = 3600               # at most one automatic sweep an hour
TOUCH_SECONDS = 60                 # chat_access is written at most once a minute per chat
CHATS_PER_SWEEP = 200
CHILDREN_PER_CHAT = 200            # sub-agent sessions deleted with a chat (per sweep)
FIRST_RUN_DELAY = 7 * 86400        # the first automatic sweep after retention is first in force
CHAT_TYPES = ("user", "scheduled", "acp")   # Goose's ACP_VISIBLE_SESSION_TYPES: what Goose lists as chats
ACCESS_ACTIONS = frozenset({"chat.open", "chat.prompt", "chat.cancel", "chat.fork", "chat.mode", "chat.steer"})
SESSION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
UPLOAD_FOLDER = "web_uploads"


def _api():
    from . import api   # api imports this module for its routes
    return api


class _State:
    def __init__(self) -> None:
        self.touched: dict[tuple[str, str], float] = {}
        self.lock = asyncio.Lock()
        self.running = False


_STATE: "weakref.WeakKeyDictionary[Any, _State]" = weakref.WeakKeyDictionary()


def _state(db) -> _State:
    st = _STATE.get(db)
    if st is None:
        st = _STATE[db] = _State()
    return st


# ---------------------------------------------------------------------- the setting
def clamp_days(value: Any) -> int:
    try:
        d = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return DAYS_DEFAULT
    return max(0, min(DAYS_MAX, d))


def config_days(settings) -> int:
    v = settings.get("retention", "chat_days")
    return DAYS_DEFAULT if v in (None, "") else clamp_days(v)


def retention_days(c) -> int:
    """Admin > Settings (stored, 0 included) over retention.chat_days; 0 = keep forever."""
    v = c.db.get_setting("retention_days")
    return clamp_days(v) if v is not None else config_days(c.settings)


def settings_view(c) -> dict:
    armed = c.db.get_setting("retention_armed_at")
    return {"retentionDays": retention_days(c), "retentionDaysMax": DAYS_MAX, "retentionDaysDefault": DAYS_DEFAULT,
            "retentionDaysConfig": config_days(c.settings),
            "retentionDaysStored": c.db.get_setting("retention_days") is not None,
            "retentionFirstAutoRun": float(armed) + FIRST_RUN_DELAY if armed else None,
            "retentionLast": c.db.get_setting("retention_last")}


def clean_settings(b: dict) -> dict:
    """Admin > Settings: `retentionDays` 0..3650 (0 = never); above 3650 is stored as 3650. 400 otherwise."""
    if "retentionDays" not in b:
        return {}
    v = b["retentionDays"]
    try:
        if isinstance(v, bool) or v in (None, "") or float(v) != float(v) or float(v) < 0:
            raise ValueError
    except (TypeError, ValueError):
        raise HTTPError(400, "bad_request", "Days without use must be a number from 0 (never delete) to "
                                            f"{DAYS_MAX}")
    return {"retentionDays": clamp_days(v)}


def store_settings(c, cleaned: dict) -> None:
    if "retentionDays" in cleaned:
        c.db.set_setting("retention_days", cleaned["retentionDays"])


def check_lines(settings) -> list[tuple[str, str]]:
    """`goose-web check`: the retention in force (the database is opened read-only)."""
    from .uploads import read_stored
    stored = read_stored(settings, "retention_days", "retention_last")
    days = clamp_days(stored["retention_days"]) if stored.get("retention_days") is not None else config_days(settings)
    src = "Admin > Settings" if stored.get("retention_days") is not None else "retention.chat_days"
    if days <= 0:
        return [("--", f"retention: off ({src} = 0) - chats and their attachments are kept forever")]
    out = [("--", f"retention: chats and their attachments are deleted after {days} days without use ({src}); "
                  f"hourly, at most {CHATS_PER_SWEEP} chats per sweep")]
    last = stored.get("retention_last")
    if isinstance(last, dict) and last.get("at"):
        out.append(("--", f"retention: last sweep {time.strftime('%Y-%m-%d %H:%M', time.localtime(last['at']))}: "
                          f"{last.get('chats', 0)} chat(s), {last.get('files', 0)} file(s) deleted"))
    raw = settings.get("retention", "chat_days")
    try:
        if raw not in (None, "") and float(raw) > DAYS_MAX:
            out.append(("!!", f"retention.chat_days: {raw} is configured, the limit is {DAYS_MAX} - {DAYS_MAX} is used"))
    except (TypeError, ValueError):
        out.append(("!!", f"retention.chat_days: {raw!r} is not a number of days - {DAYS_DEFAULT} is used"))
    return out


# ---------------------------------------------------------------------- last use
def touch(db, profile: Any, sid: Any, now: float | None = None, force: bool = False) -> bool:
    """Record that a chat was used now (at most once a minute per chat unless `force`). Session ids are taken only
    when they look like ids; the sweep removes rows of chats Goose no longer has."""
    profile = str(profile or "").strip().lower()
    sid = str(sid or "")
    if not profile or not SESSION_RE.match(sid):
        return False
    now = time.time() if now is None else now
    st = _state(db)
    k = (profile, sid)
    last = st.touched.get(k)
    if not force and last is not None and now - last < TOUCH_SECONDS:
        return False
    st.touched[k] = now
    if len(st.touched) > 20000:
        st.touched = {kk: t for kk, t in st.touched.items() if now - t < TOUCH_SECONDS}
    db.execute("INSERT INTO chat_access(profile, session_id, last_access) VALUES(?,?,?) "
               "ON CONFLICT(profile, session_id) DO UPDATE SET last_access=MAX(last_access, excluded.last_access)",
               (profile, sid, now))
    return True


def note_activity(c, action: str, target: Any, detail: Any) -> None:
    """The hub's audit hook (app.make_audit_handler): chat.* activity names the chat in `target`, audited ACP calls
    in detail.sessionId; detail.profile is the profile the chat belongs to."""
    try:
        d = detail if isinstance(detail, dict) else {}
        if action in ACCESS_ACTIONS:
            sid = target
        elif str(action).startswith("acp.") and action != "acp.session/delete" and d.get("sessionId"):
            sid = d.get("sessionId")
        else:
            return
        touch(c.db, d.get("profile"), sid)
    except Exception:
        log.exception("retention: recording the last use of a chat")


# ---------------------------------------------------------------------- Goose's sessions (read-only)
def sessions_db(c, user: dict) -> Path:
    return Path(c.profiles.root_for(user)) / "data" / "sessions" / "sessions.db"


def goose_sessions(dbfile: Path) -> list[dict] | None:
    """Every session of a profile's sessions.db: None when there is no such file; raises sqlite3.Error / OSError when
    it cannot be read (the caller then skips the profile - never "no chats")."""
    from .elsewhere import _epoch
    if not Path(dbfile).is_file():
        return None
    con = sqlite3.connect(f"{Path(dbfile).as_uri()}?mode=ro", uri=True, timeout=2, check_same_thread=False)
    try:
        con.execute("PRAGMA query_only=1")
        cols = {r[1] for r in con.execute("PRAGMA table_info(sessions)")}
        if "id" not in cols:
            raise sqlite3.DatabaseError("sessions.db has no sessions table")
        pick = [("session_type" if "session_type" in cols else "'user'"),
                ("parent_session_id" if "parent_session_id" in cols else "NULL"),
                ("created_at" if "created_at" in cols else "NULL"),
                ("updated_at" if "updated_at" in cols else "NULL")]
        # column names come from the fixed list above, never from the database's content
        rows = con.execute(f"SELECT id, {', '.join(pick)} FROM sessions").fetchall()  # nosec B608
    finally:
        con.close()
    return [{"id": str(r[0]), "type": str(r[1] or "user").lower(), "parent": str(r[2] or ""),
             "created": _epoch(r[3]), "updated": _epoch(r[4])} for r in rows if r[0] is not None]


def sessions_in_use(hub: Any, key: str) -> set[str]:
    """Chats of profile `key` the hub is using now (a read-only look at its state; hub.py is not changed): running,
    being opened, shown in a tab, with queued messages, steers, questions or a request Goose has not answered."""
    out: set[str] = set()
    up = (getattr(hub, "upstreams", None) or {}).get(key) if hub is not None else None
    if up is None:
        return out
    for s in list(up.sessions.values()):
        if s.running() or s.loading_client is not None or s.queue or s.steers or s.prompts:
            out.add(s.sid)
    for cl in list(up.clients):
        out |= {str(x) for x in (getattr(cl, "watch", None) or ())}
    for a in list(up.asks.values()):
        out.add(str(a.get("sessionId") or ""))
    for e in list(up.pending.values()):
        p = e[4] if len(e) > 4 else None
        if isinstance(p, dict) and p.get("sessionId"):
            out.add(str(p["sessionId"]))
    out.discard("")
    return out


def _in_use(c, keys: list[str], sid: str, jobs: set[tuple[str, str]]) -> bool:
    hub = c.hub
    for k in keys:
        if sid in sessions_in_use(hub, k) or (k, sid) in jobs:
            return True
        try:
            if hub is not None and hub.elsewhere_running(k, sid):
                return True
        except Exception:
            return True   # cannot tell: keep it
    return False


# ---------------------------------------------------------------------- files
def _ident(st) -> str:
    from .uploads import file_ident
    return file_ident(st)


def file_problem(c, owner: dict, row: dict) -> tuple[str, int]:
    """('', size) when the recorded file may be deleted, else (why not, 0). 'gone' = no such file any more."""
    from .uploads import is_link
    p = str(row.get("path") or "")
    if not p:
        return "no file", 0
    if Path(p).parent.name.lower() != UPLOAD_FOLDER:
        return "not in a Web_Uploads folder", 0
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return "gone", 0
    except OSError as e:
        return f"cannot be read ({e.__class__.__name__})", 0
    if is_link(st) or not stat.S_ISREG(st.st_mode):
        return "not a regular file", 0
    try:
        if Path(os.path.realpath(p)).parent.name.lower() != UPLOAD_FOLDER:
            return "not in a Web_Uploads folder", 0
    except (OSError, ValueError):
        return "cannot be resolved", 0
    if not c.path_ok(owner, p, write=True):
        return "outside the folders this profile may write", 0
    if row.get("file_id") and _ident(st) != row["file_id"]:
        return "replaced since the upload", 0
    return "", int(st.st_size)


def _delete_file(c, owner: dict, row: dict, now: float) -> tuple[bool, int]:
    """Delete one recorded file (every check of file_problem first): (deleted, its size)."""
    why, size = file_problem(c, owner, row)
    if why == "gone":
        c.db.execute("UPDATE uploads SET state='gone', updated_at=? WHERE id=?", (now, row["id"]))
        return False, 0
    if why:
        c.db.execute("UPDATE uploads SET state='kept', note=?, updated_at=? WHERE id=?", (why, now, row["id"]))
        log.info("retention: %s kept: %s", row.get("path"), why)
        return False, 0
    try:
        os.unlink(row["path"])
    except FileNotFoundError:
        c.db.execute("UPDATE uploads SET state='gone', updated_at=? WHERE id=?", (now, row["id"]))
        return False, 0
    except OSError as e:      # in use, or access denied: tried again at the next sweep
        log.warning("retention: %s not deleted: %s", row.get("path"), e)
        return False, 0
    c.db.execute("UPDATE uploads SET state='deleted', updated_at=? WHERE id=?", (now, row["id"]))
    return True, size


def _links(c, upload_id: str) -> set[str]:
    return {r["session_id"] for r in c.db.query("SELECT session_id FROM upload_links WHERE upload_id=?", (upload_id,))}


def _marks(keys: list[str]) -> str:
    return ",".join("?" for _ in keys)


# ---------------------------------------------------------------------- the sweep
def _profile_groups(c) -> list[tuple[Path, list[dict]]]:
    """Enabled users grouped by their Goose profile folder (several native administrators share one)."""
    groups: dict[str, tuple[Path, list[dict]]] = {}
    for u in c.db.users():
        if u.get("disabled"):
            continue
        try:
            root = Path(c.profiles.root_for(u))
        except Exception:
            continue
        groups.setdefault(os.path.normcase(os.path.abspath(root)), (root, []))[1].append(u)
    return list(groups.values())


def _plan(c, keys: list[str], sessions: list[dict] | None, cutoff: float) -> dict:
    """Expired chats of one profile, oldest first, with their sub-agent sessions."""
    access: dict[str, float] = {}
    if keys:
        for r in c.db.query(f"SELECT session_id, MAX(last_access) AS t FROM chat_access WHERE profile IN "  # nosec B608
                            f"({_marks(keys)}) GROUP BY session_id", keys):
            access[r["session_id"]] = float(r["t"] or 0)
    children: dict[str, list[str]] = {}
    for s in sessions or []:
        if s["parent"]:
            children.setdefault(s["parent"], []).append(s["id"])
    expired = []
    for s in sessions or []:
        if s["parent"] or s["type"] not in CHAT_TYPES:
            continue
        times = [t for t in (s["updated"], s["created"], access.get(s["id"])) if t]
        if not times:
            continue      # no time at all: never deleted
        last = max(times)
        if last < cutoff:
            expired.append({"id": s["id"], "last": last, "children": children.get(s["id"], [])})
    expired.sort(key=lambda e: e["last"])
    return {"expired": expired, "existing": None if sessions is None else {s["id"] for s in sessions}}


async def _delete_session(c, user: dict, sid: str, dbfile: Path) -> str:
    """'' when Goose deleted the session (or it is gone), else why not."""
    try:
        up = c.upstream_for(user)
        await up.request("session/delete", {"sessionId": sid}, timeout=60)
        return ""
    except Exception as e:   # worker refused to start, Goose's error, time-out
        why = f"{e.__class__.__name__}: {str(e)[:200]}"
    try:
        rows = await asyncio.to_thread(goose_sessions, dbfile)
        if rows is not None and sid not in {r["id"] for r in rows}:
            return ""
    except (sqlite3.Error, OSError):
        pass
    return why


def _iso(t: float | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if t else ""


async def sweep(c, *, now: float | None = None, dry_run: bool = False, days: int | None = None,
                by: dict | None = None, cap: int | None = CHATS_PER_SWEEP) -> dict:
    """One retention sweep over every profile (dry_run: count only - the preview). Returns the report."""
    now = time.time() if now is None else now
    days = retention_days(c) if days is None else clamp_days(days)
    report: dict[str, Any] = {"at": now, "days": days, "dryRun": dry_run, "manual": by is not None, "chats": 0,
                              "files": 0, "bytes": 0, "busy": 0, "more": False, "users": [], "errors": [],
                              "perSweep": CHATS_PER_SWEEP}
    if by is not None:
        report["by"] = by.get("username")
    if days <= 0:
        report["off"] = True
        return report
    cutoff = now - days * 86400
    report["cutoff"] = cutoff
    jobs: set[tuple[str, str]] = set()
    if not dry_run and c.hub is not None:
        try:   # scheduler jobs running inside workers (they never pass through the gateway)
            for b in await asyncio.wait_for(c.hub.busy_report(), 30):
                if b.get("sessionId"):
                    jobs.add((str(b.get("profile") or ""), str(b["sessionId"])))
        except Exception as e:
            report["errors"].append(f"the running jobs could not be listed ({e.__class__.__name__}); nothing deleted")
            return report
    left = cap if cap is not None else 10 ** 9
    for root, members in _profile_groups(c):
        keys = [str(m["username"]).lower() for m in members]
        owner = members[0]
        by_key = {str(m["username"]).lower(): m for m in members}
        since = min(float(m.get("created_at") or 0) for m in members)   # rows older than the account are not its own
        entry = {"username": owner["username"], "chats": 0, "files": 0, "bytes": 0, "busy": 0, "error": ""}
        report["users"].append(entry)
        dbfile = root / "data" / "sessions" / "sessions.db"
        try:
            sessions = await asyncio.to_thread(goose_sessions, dbfile)
        except (sqlite3.Error, OSError) as e:
            entry["error"] = f"the chat list could not be read ({e.__class__.__name__}); skipped"
            continue
        plan = await asyncio.to_thread(_plan, c, keys, sessions, cutoff)
        existing: set[str] | None = plan["existing"]
        gone: set[str] = set()                     # deleted in this sweep (or counted as such in the preview)
        handled: set[str] = set()                  # uploads already dealt with as a chat's files

        def live() -> set[str]:
            return (existing or set()) - gone

        def owner_of(row: dict) -> dict:
            return by_key.get(str(row.get("profile") or ""), owner)

        stop = False
        for chat in plan["expired"]:
            if left <= 0:
                report["more"] = True
                break
            sid = chat["id"]
            if _in_use(c, keys, sid, jobs):
                entry["busy"] += 1
                continue
            files = [r for r in c.db.query(
                f"SELECT u.* FROM uploads u JOIN upload_links l ON l.upload_id=u.id WHERE l.session_id=? AND "  # nosec B608
                f"l.profile IN ({_marks(keys)}) AND u.state='done' AND u.created_at>=?", (sid, *keys, since))]
            left -= 1
            gone.add(sid)
            keep_shared = [r for r in files if (_links(c, r["id"]) - {sid}) & live()]
            todo = [r for r in files if r not in keep_shared]
            handled.update(r["id"] for r in todo)
            if dry_run:
                entry["chats"] += 1
                for r in todo:
                    why, size = await asyncio.to_thread(file_problem, c, owner_of(r), r)
                    if not why:
                        entry["files"] += 1
                        entry["bytes"] += size
                continue
            why = await _delete_session(c, owner, sid, dbfile)
            if why:
                gone.discard(sid)
                entry["error"] = f"chat {sid} not deleted: {why}"
                report["errors"].append(f"{owner['username']}: {entry['error']}")
                stop = True     # the worker is not answering: the rest of this profile waits for the next sweep
                break
            for child in chat["children"][:CHILDREN_PER_CHAT]:
                if await _delete_session(c, owner, child, dbfile):
                    log.info("retention: sub-agent session %s of %s not deleted", child, sid)
            n = nbytes = 0
            for r in todo:
                done, size = await asyncio.to_thread(_delete_file, c, owner_of(r), r, now)
                if done:
                    n += 1
                    nbytes += size
            c.db.execute(f"DELETE FROM chat_access WHERE session_id=? AND profile IN ({_marks(keys)})",  # nosec B608
                         (sid, *keys))
            c.db.execute(f"DELETE FROM upload_links WHERE session_id=? AND profile IN ({_marks(keys)})",  # nosec B608
                         (sid, *keys))
            entry["chats"] += 1
            entry["files"] += n
            entry["bytes"] += nbytes
            c.db.audit("retention.chat_deleted", target=sid,
                       detail={"profile": keys[0], "files": n, "bytes": nbytes, "lastUsed": _iso(chat["last"]),
                               "days": days, "subSessions": len(chat["children"][:CHILDREN_PER_CHAT])})
        if stop:
            continue
        # files not linked to any chat that is kept, uploaded longer ago than the period
        un = unb = 0
        for r in c.db.query(f"SELECT * FROM uploads WHERE state='done' AND profile IN ({_marks(keys)}) AND "  # nosec B608
                            "created_at>=? AND COALESCE(completed_at, created_at)<?", (*keys, since, cutoff)):
            if r["id"] in handled:
                continue
            links = _links(c, r["id"])
            if existing is None:
                if links:
                    continue    # no chat list: cannot tell whether those chats exist
            elif links & live():
                continue
            if dry_run:
                why, size = await asyncio.to_thread(file_problem, c, owner_of(r), r)
                if not why:
                    un += 1
                    unb += size
                continue
            done, size = await asyncio.to_thread(_delete_file, c, owner_of(r), r, now)
            if done:
                un += 1
                unb += size
        entry["files"] += un
        entry["bytes"] += unb
        if un and not dry_run:
            c.db.audit("retention.files_deleted", target=keys[0],
                       detail={"profile": keys[0], "files": un, "bytes": unb, "reason": "not linked to a kept chat",
                               "days": days})
        if not dry_run and existing is not None:
            # rows of chats Goose no longer has (deleted elsewhere, or ids nobody created) do not pile up
            c.db.execute(f"DELETE FROM chat_access WHERE profile IN ({_marks(keys)}) AND last_access<? AND "  # nosec B608
                         "session_id NOT IN (SELECT value FROM json_each(?))",
                         (*keys, now - 3600, json.dumps(sorted(existing))))
    for e in report["users"]:
        report["chats"] += e["chats"]
        report["files"] += e["files"]
        report["bytes"] += e["bytes"]
        report["busy"] += e["busy"]
    if not dry_run:
        summary = {k: report[k] for k in ("at", "days", "chats", "files", "bytes", "busy", "more", "manual")}
        summary["errors"] = report["errors"][:5]
        if by is not None:
            summary["by"] = by.get("username")
        c.db.set_setting("retention_last", summary)
        c.db.audit("retention.run", user=by, target=f"{days} days",
                   detail={k: summary[k] for k in ("chats", "files", "bytes", "busy", "more", "manual", "errors")})
        if report["chats"] or report["files"]:
            log.info("retention: %d chat(s), %d file(s), %d bytes deleted (%d days without use)", report["chats"],
                     report["files"], report["bytes"], days)
    return report


async def run(c, *, by: dict | None = None, now: float | None = None) -> dict:
    """One real sweep at a time (the maintenance loop and Run now)."""
    st = _state(c.db)
    if st.lock.locked():
        raise HTTPError(409, "busy", "A retention sweep is running; try again in a minute")
    async with st.lock:
        st.running = True
        try:
            return await sweep(c, by=by, now=now)
        finally:
            st.running = False


async def maybe_sweep(c, now: float | None = None) -> dict | None:
    """From the maintenance loop: at most hourly, and not before FIRST_RUN_DELAY after retention first applied."""
    now = time.time() if now is None else now
    if retention_days(c) <= 0:
        return None
    armed = c.db.get_setting("retention_armed_at")
    if not armed:
        c.db.set_setting("retention_armed_at", now)
        log.info("retention: in force; the first automatic sweep runs after %s",
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(now + FIRST_RUN_DELAY)))
        return None
    if now < float(armed) + FIRST_RUN_DELAY:
        return None
    last = c.db.get_setting("retention_last") or {}
    if now - float((last if isinstance(last, dict) else {}).get("at") or 0) < SWEEP_SECONDS:
        return None
    if _state(c.db).lock.locked():
        return None
    return await run(c, now=now)


# ---------------------------------------------------------------------- admin API
async def admin_retention(request: Request):
    api = _api()
    c = api.ctx(request)
    c.require(request, admin=True)
    return api.ok({**settings_view(c), "running": _state(c.db).running, "perSweep": CHATS_PER_SWEEP,
                   "sweepMinutes": SWEEP_SECONDS // 60})


async def admin_retention_preview(request: Request):
    api = _api()
    c = api.ctx(request)
    c.require(request, admin=True)
    raw = request.query_params.get("days")
    days = None
    if raw not in (None, ""):
        days = api.int_param(raw, "days", lo=0, hi=DAYS_MAX)
    return api.ok(await sweep(c, dry_run=True, days=days, cap=None))


async def admin_retention_run(request: Request):
    api = _api()
    c = api.ctx(request)
    admin = c.require(request, admin=True).user
    return api.ok(await run(c, by=admin))


routes = [
    Route("/api/admin/retention", admin_retention),
    Route("/api/admin/retention/preview", admin_retention_preview),
    Route("/api/admin/retention/run", admin_retention_run, methods=["POST"]),
]
