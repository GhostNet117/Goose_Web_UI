"""Spec 040: a chat and the files uploaded to it are deleted after N days without use (default 180, 0 = never).

Last use = the later of Goose Web's record (chat_access, from the hub's audit hook, at most once a minute per chat)
and Goose's own times in the profile's sessions.db (read-only). The sweep deletes an expired chat through the
profile's worker (ACP session/delete), then its files - only inside Web_Uploads, inside folders the profile may
write, the same file that was uploaded, not shared with a kept chat; unlinked files older than the period too. Never a
chat that is running, being opened, open in a tab, queued, asked about or running elsewhere; at most 200 per sweep."""
import asyncio
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from goose_web import app as gw_app
from goose_web import retention, uploads
from goose_web.hub import SessionState
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)

DAY = 86400
NOW = time.time()
WIN = sys.platform == "win32"


def _ts(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch))


class FakeUp:
    """A profile's Upstream as far as retention looks at it; session/delete removes the row from sessions.db."""

    def __init__(self, dbfile: Path):
        self.dbfile = dbfile
        self.sessions, self.clients, self.asks, self.pending = {}, set(), {}, {}
        self.deleted: list[str] = []
        self.fail = False

    async def request(self, method, params=None, timeout=None):
        assert method == "session/delete"
        if self.fail:
            raise RuntimeError("the worker did not start")
        sid = params["sessionId"]
        self.deleted.append(sid)
        con = sqlite3.connect(self.dbfile)
        con.execute("DELETE FROM sessions WHERE id=?", (sid,))
        con.commit()
        con.close()
        return {}


class FakeHub:
    def __init__(self):
        self.upstreams: dict[str, FakeUp] = {}
        self.elsewhere: set[tuple[str, str]] = set()
        self.jobs: list[dict] = []

    def elsewhere_running(self, key, sid):
        return (key, sid) in self.elsewhere

    async def busy_report(self):
        return list(self.jobs)


class Tab:
    def __init__(self, *sids):
        self.watch = set(sids)


@pytest.fixture
def rt(env, monkeypatch):
    s, db, pr, c = env
    hub = FakeHub()
    c.hub = hub
    monkeypatch.setattr(c, "upstream_for", lambda u: hub.upstreams[u["username"].lower()])
    return s, db, pr, c, hub


def member(rt, name="dee", policy=None):
    s, db, pr, c, hub = rt
    tid = team(db, "T-" + name, {**ANYCHAT, **(policy or {})})
    u = user(db, name)
    db.set_user_team(u["id"], tid)
    db.execute("UPDATE users SET created_at=? WHERE id=?", (NOW - 2000 * DAY, u["id"]))   # an old account
    u = db.user_by_id(u["id"])
    pr.ensure_layout(u)
    dbfile = Path(pr.root_for(u)) / "data" / "sessions" / "sessions.db"
    dbfile.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(dbfile)
    con.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, name TEXT, session_type TEXT, "
                "parent_session_id TEXT, working_dir TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)")
    con.commit()
    con.close()
    hub.upstreams[name] = FakeUp(dbfile)
    return u


def chat(rt, u, sid, days_ago, kind="user", parent=None, created_days_ago=None):
    s, db, pr, c, hub = rt
    con = sqlite3.connect(hub.upstreams[u["username"]].dbfile)
    created = NOW - (created_days_ago if created_days_ago is not None else days_ago) * DAY
    con.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?)",
                (sid, "chat " + sid, kind, parent, "", _ts(created), _ts(NOW - days_ago * DAY)))
    con.commit()
    con.close()


def chats_left(rt, u):
    con = sqlite3.connect(rt[4].upstreams[u["username"]].dbfile)
    try:
        return sorted(r[0] for r in con.execute("SELECT id FROM sessions"))
    finally:
        con.close()


def attach(rt, u, name, data=b"data", session="", days_ago=0, folder=None):
    """A finished upload of `u` recorded like the gateway records one (spec 039)."""
    s, db, pr, c, hub = rt
    base = Path(folder) if folder else pr.workspace(u)
    d = base / "Web_Uploads"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data)
    uid = uploads.record_saved(c, u, p, len(data), "text/plain", d, session=session)
    t = NOW - days_ago * DAY
    db.execute("UPDATE uploads SET created_at=?, completed_at=?, updated_at=? WHERE id=?", (t, t, t, uploads._key(uid)))
    return uid, p


def sweep(c, **kw):
    return asyncio.run(retention.sweep(c, now=NOW, **kw))


# ------------------------------------------------------------------ the setting
def test_retention_setting_range(rt):
    s, db, pr, c, hub = rt
    boss = user(db, "boss", role="admin")
    dee = member(rt)
    assert retention.retention_days(c) == 180 == retention.DAYS_DEFAULT
    s.data.setdefault("retention", {})["chat_days"] = 30
    assert retention.retention_days(c) == 30
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        g = tc.get("/api/admin/settings").json()
        assert (g["retentionDays"], g["retentionDaysMax"], g["retentionDaysConfig"], g["retentionDaysStored"]) == (30, 3650, 30, False)
        for sent, stored in ((5000, 3650), (0, 0), (180.9, 180), ("90", 90)):
            assert tc.put("/api/admin/settings", json={"retentionDays": sent}, headers=h).status_code == 200
            assert db.get_setting("retention_days") == stored and retention.retention_days(c) == stored
        for bad in (-1, "x", None, True):
            assert tc.put("/api/admin/settings", json={"retentionDays": bad}, headers=h).status_code == 400
        assert db.get_setting("retention_days") == 90
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert tc.put("/api/admin/settings", json={"retentionDays": 1}, headers=h).status_code == 403


# ------------------------------------------------------------------ last use
def test_last_access_is_recorded_and_throttled(rt):
    s, db, pr, c, hub = rt
    member(rt)
    row = lambda sid: db.one("SELECT last_access FROM chat_access WHERE profile='dee' AND session_id=?", (sid,))  # noqa: E731
    assert retention.touch(db, "Dee", "20261124_1", now=1000.0)
    assert row("20261124_1")["last_access"] == 1000.0
    assert not retention.touch(db, "dee", "20261124_1", now=1030.0)          # within a minute: not written
    assert row("20261124_1")["last_access"] == 1000.0
    assert retention.touch(db, "dee", "20261124_1", now=1061.0)
    assert row("20261124_1")["last_access"] == 1061.0
    assert retention.touch(db, "dee", "20261124_1", now=900.0, force=True)   # never goes back in time
    assert row("20261124_1")["last_access"] == 1061.0
    for bad in ("", "a b", "x" * 200, "../x", None):
        assert not retention.touch(db, "dee", bad)
    assert not retention.touch(db, "", "20261124_9")
    # what the hub's audit hook passes on: chat activity and audited calls that name a chat
    before = time.time()
    retention.note_activity(c, "chat.open", "s-open", {"profile": "dee"})
    retention.note_activity(c, "chat.prompt", "s-prompt", {"profile": "dee", "chars": 3})
    retention.note_activity(c, "acp.session/extensions/add", "_goose/...", {"profile": "dee", "sessionId": "s-ext"})
    retention.note_activity(c, "acp.session/delete", "session/delete", {"profile": "dee", "sessionId": "s-del"})
    retention.note_activity(c, "chat.new", "", {"profile": "dee", "cwd": "x"})
    retention.note_activity(c, "auth.login", "x", None)
    got = {r["session_id"] for r in db.query("SELECT session_id FROM chat_access WHERE last_access>=?", (before,))}
    assert got == {"s-open", "s-prompt", "s-ext"}
    # the gateway's audit handler (app.make_audit_handler) is where the hub's events arrive
    client = type("C", (), {"user": db.user_by_name("dee"), "ip": "192.0.2.10"})()
    gw_app.make_audit_handler(c)(client, "chat.steer", "s-steer", {"profile": "dee"}, True)
    assert row("s-steer") is not None and db.query("SELECT * FROM audit WHERE action='chat.steer'")


def test_goose_updated_time_is_the_fallback(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "A", 200)                       # never opened in Goose Web, unused in Goose for 200 days: expired
    chat(rt, dee, "B", 200)                       # Goose's time is old, but Goose Web saw it 10 days ago
    retention.touch(db, "dee", "B", now=NOW - 10 * DAY)
    chat(rt, dee, "C", 10)                        # Goose's time is recent; an old Goose Web record does not matter
    retention.touch(db, "dee", "C", now=NOW - 300 * DAY)
    chat(rt, dee, "D", 179)
    p = sweep(c, dry_run=True)
    assert (p["chats"], p["users"][0]["username"]) == (1, "dee") and chats_left(rt, dee) == ["A", "B", "C", "D"]
    r = sweep(c)
    assert r["chats"] == 1 and hub.upstreams["dee"].deleted == ["A"] and chats_left(rt, dee) == ["B", "C", "D"]
    a = db.query("SELECT * FROM audit WHERE action='retention.chat_deleted'")
    assert [x["target"] for x in a] == ["A"] and a[0]["detail"]["profile"] == "dee"


def test_pre_chat_uploads_are_linked_and_forks_share_them(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    boss = user(db, "boss", role="admin")
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = tc.post("/api/fs/uploads", json={"dir": str(ws), "name": "n.txt", "size": 1}, headers=h).json()["id"]
        tc.put(f"/api/fs/uploads/{uid}", params={"offset": 0}, content=b"n", headers=h)
        key = uploads._key(uid)
        assert not db.query("SELECT * FROM upload_links")                # New chat: no chat yet
        r = tc.post("/api/fs/uploads/link", json={"session": "S1", "ids": [uid, "x" * 43, 5]}, headers=h)
        assert r.json() == {"linked": 1}
        assert db.one("SELECT * FROM chat_access WHERE profile='dee' AND session_id='S1'")   # a new chat is a use
        r = tc.post("/api/fs/uploads/link", json={"session": "S2", "from": "S1"}, headers=h)     # a fork
        assert r.json() == {"linked": 1}
        assert {(x["upload_id"], x["session_id"]) for x in db.query("SELECT * FROM upload_links")} == {(key, "S1"), (key, "S2")}
        # uploaded inside a chat: linked when it is complete
        uid2 = tc.post("/api/fs/uploads", json={"dir": str(ws), "name": "m.txt", "size": 1, "session": "S3"}, headers=h).json()["id"]
        assert not db.query("SELECT * FROM upload_links WHERE session_id='S3'")
        tc.put(f"/api/fs/uploads/{uid2}", params={"offset": 0}, content=b"m", headers=h)
        assert db.query("SELECT * FROM upload_links WHERE session_id='S3'")[0]["upload_id"] == uploads._key(uid2)
        assert tc.post("/api/fs/uploads/link", json={"ids": [uid]}, headers=h).status_code == 400   # no chat
        assert tc.post("/api/fs/uploads/link", json={"session": "S4", "ids": [uid], "profile": "boss"}, headers=h).status_code == 403
    with client_for(c) as tc:   # an administrator in dee's profile links dee's chats only through `profile`
        h = sign_in(tc, c, boss)
        r = tc.post("/api/fs/uploads/link", json={"session": "S5", "from": "S1", "profile": "dee"}, headers=h)
        assert r.json() == {"linked": 1}
        assert tc.post("/api/fs/uploads/link", json={"session": "S6", "from": "S1"}, headers=h).json() == {"linked": 0}


# ------------------------------------------------------------------ the sweep
def test_sweep_deletes_an_expired_chat_and_its_files_only(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "OLD", 200)
    chat(rt, dee, "OLD-sub", 200, kind="sub_agent", parent="OLD")
    chat(rt, dee, "NEW", 3)
    f1, p1 = attach(rt, dee, "a.txt", b"aaaa", session="OLD", days_ago=200)
    f2, p2 = attach(rt, dee, "b.txt", b"bb", session="OLD", days_ago=5)      # a recent file of an expired chat goes too
    f3, p3 = attach(rt, dee, "c.txt", b"c", session="NEW", days_ago=200)     # an old file of a used chat stays
    retention.touch(db, "dee", "OLD", now=NOW - 400 * DAY)
    r = sweep(c)
    assert (r["chats"], r["files"], r["bytes"]) == (1, 2, 6)
    assert hub.upstreams["dee"].deleted == ["OLD", "OLD-sub"] and chats_left(rt, dee) == ["NEW"]
    assert not p1.exists() and not p2.exists() and p3.read_bytes() == b"c"
    states = {r["path"]: r["state"] for r in db.query("SELECT path, state FROM uploads")}
    assert states == {str(p1): "deleted", str(p2): "deleted", str(p3): "done"}
    assert not db.query("SELECT * FROM chat_access WHERE session_id='OLD'")
    assert not db.query("SELECT * FROM upload_links WHERE session_id='OLD'")
    a = db.query("SELECT * FROM audit WHERE action='retention.chat_deleted'")
    assert len(a) == 1 and a[0]["target"] == "OLD" and a[0]["user_id"] is None
    assert {k: a[0]["detail"][k] for k in ("profile", "files", "bytes", "days", "subSessions")} == \
        {"profile": "dee", "files": 2, "bytes": 6, "days": 180, "subSessions": 1}
    run = db.query("SELECT * FROM audit WHERE action='retention.run'")[-1]
    assert run["detail"]["chats"] == 1 and run["detail"]["manual"] is False
    assert db.get_setting("retention_last")["chats"] == 1
    # nothing more to do
    r = sweep(c)
    assert (r["chats"], r["files"]) == (0, 0) and hub.upstreams["dee"].deleted == ["OLD", "OLD-sub"]


def test_files_shared_with_a_kept_chat_are_kept(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "A", 200)
    chat(rt, dee, "FORK", 2)
    fid, p = attach(rt, dee, "shared.txt", b"s", session="A", days_ago=200)
    uploads.link_upload(db, uploads._key(fid), "dee", "FORK")
    r = sweep(c)
    assert r["chats"] == 1 and r["files"] == 0 and p.exists()
    assert {x["session_id"] for x in db.query("SELECT * FROM upload_links")} == {"FORK"}
    # the fork expires later: now the file goes with it
    con = sqlite3.connect(hub.upstreams["dee"].dbfile)
    con.execute("UPDATE sessions SET updated_at=?, created_at=? WHERE id='FORK'", (_ts(NOW - 190 * DAY), _ts(NOW - 190 * DAY)))
    con.commit()
    con.close()
    r = sweep(c)
    assert r["chats"] == 1 and r["files"] == 1 and not p.exists()


def test_files_outside_web_uploads_or_writable_folders_are_kept(rt, tmp_path):
    s, db, pr, c, hub = rt
    out = tmp_path / "outside"
    out.mkdir()
    dee = member(rt)
    ws = pr.workspace(dee)
    chat(rt, dee, "X", 300)
    _, inside = attach(rt, dee, "ok.txt", b"1", session="X")
    _, outside = attach(rt, dee, "out.txt", b"2", session="X", folder=out)            # not a folder dee may write
    fid, renamed = attach(rt, dee, "moved.txt", b"3", session="X")
    db.execute("UPDATE uploads SET path=? WHERE id=?", (str(ws / "notes.txt"), uploads._key(fid)))
    (ws / "notes.txt").write_bytes(b"MINE")                                            # not in a Web_Uploads folder
    _, replaced = attach(rt, dee, "again.txt", b"4", session="X")
    replaced.unlink()
    replaced.write_bytes(b"NEWER FILE")                                                # another file of the same name
    links = []
    if WIN:
        (ws / "j").mkdir()
        target = out / "Web_Uploads"
        r = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(ws / "j" / "Web_Uploads"), str(target)], capture_output=True)
        assert r.returncode == 0
        (target / "linked.txt").write_bytes(b"5")
        lid = uploads.record_saved(c, dee, ws / "j" / "Web_Uploads" / "linked.txt", 1, "text/plain", ws / "j" / "Web_Uploads",
                                   session="X")
        links.append(target / "linked.txt")
    r = sweep(c)
    assert r["chats"] == 1 and r["files"] == 1 and not inside.exists()
    assert outside.read_bytes() == b"2" and (ws / "notes.txt").read_bytes() == b"MINE"
    assert replaced.read_bytes() == b"NEWER FILE" and all(p.exists() for p in links)
    notes = {Path(x["path"]).name: x["note"] for x in db.query("SELECT path, note FROM uploads WHERE state='kept'")}
    assert notes["out.txt"] == "outside the folders this profile may write"
    assert notes["notes.txt"] == "not in a Web_Uploads folder"
    assert notes["again.txt"] == "replaced since the upload"
    if WIN:
        assert notes["linked.txt"] in ("not in a Web_Uploads folder", "outside the folders this profile may write")


def test_unlinked_uploads_older_than_the_period_go(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "KEPT", 1)
    _, old_unlinked = attach(rt, dee, "o.txt", b"12345", days_ago=200)
    _, new_unlinked = attach(rt, dee, "n.txt", b"1", days_ago=10)
    _, gone_chat = attach(rt, dee, "g.txt", b"12", session="DELETED-IN-DESKTOP", days_ago=200)
    _, kept_chat = attach(rt, dee, "k.txt", b"1", session="KEPT", days_ago=200)
    p = sweep(c, dry_run=True)
    assert (p["chats"], p["files"], p["bytes"]) == (0, 2, 7) and old_unlinked.exists()
    r = sweep(c)
    assert (r["chats"], r["files"], r["bytes"]) == (0, 2, 7)
    assert not old_unlinked.exists() and not gone_chat.exists() and new_unlinked.exists() and kept_chat.exists()
    a = db.query("SELECT * FROM audit WHERE action='retention.files_deleted'")
    assert len(a) == 1 and a[0]["detail"]["files"] == 2 and a[0]["detail"]["bytes"] == 7 and a[0]["target"] == "dee"
    # files recorded before the account existed (a deleted account of the same name) are not this account's
    _, foreign = attach(rt, dee, "f.txt", b"1", days_ago=2500)
    assert sweep(c)["files"] == 0 and foreign.exists()


def test_running_loading_and_open_chats_are_skipped(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    for sid in ("RUN", "LOAD", "TAB", "QUEUE", "ASK", "REQ", "ELSE", "JOB", "FREE"):
        chat(rt, dee, sid, 400)
    up = hub.upstreams["dee"]
    up.sessions["RUN"] = SessionState(sid="RUN", status="working")
    up.sessions["LOAD"] = SessionState(sid="LOAD", loading=object())
    up.sessions["QUEUE"] = SessionState(sid="QUEUE", queue=[{"id": "q1"}])
    up.clients.add(Tab("TAB"))
    up.asks["r1"] = {"sessionId": "ASK", "msg": {}}
    up.pending[7] = (None, None, None, "session/load", {"sessionId": "REQ"})
    hub.elsewhere.add(("dee", "ELSE"))
    hub.jobs.append({"profile": "dee", "sessionId": "JOB", "kind": "schedule"})
    assert retention.sessions_in_use(hub, "dee") == {"RUN", "LOAD", "QUEUE", "TAB", "ASK", "REQ"}
    r = sweep(c)
    assert r["chats"] == 1 and r["busy"] == 8 and up.deleted == ["FREE"]
    assert chats_left(rt, dee) == ["ASK", "ELSE", "JOB", "LOAD", "QUEUE", "REQ", "RUN", "TAB"]


def test_a_hub_that_cannot_be_asked_keeps_the_chats(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "OLD", 400)
    del hub.upstreams["dee"].asks          # e.g. the hub's state looks different after a refactoring
    r = sweep(c)
    assert r["chats"] == 0 and r["busy"] == 1 and chats_left(rt, dee) == ["OLD"]


def test_at_most_200_chats_per_sweep(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    for i in range(205):
        chat(rt, dee, f"C{i:03d}", 400 - i)
    r = sweep(c)
    assert r["chats"] == 200 and r["more"] is True
    assert hub.upstreams["dee"].deleted[:2] == ["C000", "C001"]                       # oldest first
    r = sweep(c)
    assert r["chats"] == 5 and r["more"] is False and chats_left(rt, dee) == []


def test_zero_days_deletes_nothing(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "ANCIENT", 3000)
    _, p = attach(rt, dee, "u.txt", days_ago=3000)
    db.set_setting("retention_days", 0)
    assert sweep(c)["off"] is True and sweep(c, dry_run=True)["off"] is True
    assert asyncio.run(retention.maybe_sweep(c, now=NOW)) is None
    assert chats_left(rt, dee) == ["ANCIENT"] and p.exists() and not hub.upstreams["dee"].deleted
    assert db.get_setting("retention_armed_at") is None


def test_unreadable_sessions_db_skips_the_profile(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    _, p = attach(rt, dee, "u.txt", days_ago=500)
    hub.upstreams["dee"].dbfile.write_bytes(b"this is not a database" * 100)
    r = sweep(c)
    assert r["files"] == 0 and p.exists() and "could not be read" in r["users"][0]["error"]
    # a profile without sessions.db (never chatted): only files linked to no chat at all may go
    bob = member(rt, "bob")
    hub.upstreams["bob"].dbfile.unlink()
    _, lone = attach(rt, bob, "lone.txt", days_ago=500)
    _, linked = attach(rt, bob, "linked.txt", session="S9", days_ago=500)
    r = sweep(c)
    assert not lone.exists() and linked.exists()


def test_a_worker_that_does_not_answer_stops_its_profile_only(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    bob = member(rt, "bob")
    chat(rt, dee, "D1", 300)
    _, f = attach(rt, dee, "d.txt", session="D1", days_ago=300)
    chat(rt, bob, "B1", 300)
    hub.upstreams["dee"].fail = True
    r = sweep(c)
    assert r["chats"] == 1 and hub.upstreams["bob"].deleted == ["B1"]
    assert f.exists() and chats_left(rt, dee) == ["D1"] and "D1 not deleted" in r["errors"][0]


def test_disabled_accounts_are_skipped(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "OLD", 300)
    db.execute("UPDATE users SET disabled=1 WHERE id=?", (dee["id"],))
    assert sweep(c)["chats"] == 0 and chats_left(rt, dee) == ["OLD"]


def test_maybe_sweep_runs_hourly_after_the_first_run_delay(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "OLD", 300)
    t0 = NOW
    assert asyncio.run(retention.maybe_sweep(c, now=t0)) is None and db.get_setting("retention_armed_at") == t0
    assert asyncio.run(retention.maybe_sweep(c, now=t0 + DAY)) is None and chats_left(rt, dee) == ["OLD"]
    r = asyncio.run(retention.maybe_sweep(c, now=t0 + retention.FIRST_RUN_DELAY + 1))
    assert r["chats"] == 1 and chats_left(rt, dee) == []
    chat(rt, dee, "OLD2", 300)
    assert asyncio.run(retention.maybe_sweep(c, now=t0 + retention.FIRST_RUN_DELAY + 1800)) is None
    r = asyncio.run(retention.maybe_sweep(c, now=t0 + retention.FIRST_RUN_DELAY + 3700))
    assert r["chats"] == 1
    v = retention.settings_view(c)
    assert v["retentionFirstAutoRun"] == t0 + retention.FIRST_RUN_DELAY and v["retentionLast"]["chats"] == 1


def test_last_access_rows_of_vanished_chats_are_removed(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "HERE", 1)
    retention.touch(db, "dee", "HERE", now=NOW - 2 * DAY)
    retention.touch(db, "dee", "GONE", now=NOW - 2 * DAY)
    retention.touch(db, "dee", "JUST-NOW", now=NOW)        # Goose may not have written a brand-new chat yet
    sweep(c)
    assert {r["session_id"] for r in db.query("SELECT session_id FROM chat_access")} == {"HERE", "JUST-NOW"}


# ------------------------------------------------------------------ admin API
def test_preview_matches_the_sweep(rt):
    s, db, pr, c, hub = rt
    boss = user(db, "boss", role="admin")
    dee = member(rt)
    bob = member(rt, "bob")
    chat(rt, dee, "D1", 300)
    chat(rt, dee, "D2", 100)
    chat(rt, bob, "B1", 400)
    attach(rt, dee, "d1.txt", b"123", session="D1", days_ago=300)
    attach(rt, dee, "d2.txt", b"12", session="D2", days_ago=100)
    attach(rt, bob, "b1.txt", b"1", session="B1", days_ago=400)
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        v = tc.get("/api/admin/retention").json()
        assert v["retentionDays"] == 180 and v["running"] is False and v["perSweep"] == 200
        p = tc.get("/api/admin/retention/preview").json()
        per = {u["username"]: (u["chats"], u["files"], u["bytes"]) for u in p["users"] if u["chats"] or u["files"]}
        assert per == {"dee": (1, 1, 3), "bob": (1, 1, 1)} and (p["chats"], p["files"], p["bytes"]) == (2, 2, 4)
        p90 = tc.get("/api/admin/retention/preview", params={"days": 90}).json()      # a value not saved yet
        assert (p90["days"], p90["chats"], p90["files"]) == (90, 3, 3)
        assert chats_left(rt, dee) == ["D1", "D2"]                                     # the preview deletes nothing
        assert tc.post("/api/admin/retention/run", json={}).status_code == 403          # CSRF
        r = tc.post("/api/admin/retention/run", json={}, headers=h).json()
        per_run = {u["username"]: (u["chats"], u["files"], u["bytes"]) for u in r["users"] if u["chats"] or u["files"]}
        assert per_run == per and r["manual"] is True and r["by"] == "boss"
        last = tc.get("/api/admin/retention").json()["retentionLast"]
        assert last["chats"] == 2 and last["by"] == "boss" and last["manual"] is True
    run = db.query("SELECT * FROM audit WHERE action='retention.run'")[-1]
    assert run["username"] == "boss" and run["detail"]["chats"] == 2


def test_admin_api_refuses_members(rt):
    s, db, pr, c, hub = rt
    dee = member(rt)
    chat(rt, dee, "D1", 300)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for r in (tc.get("/api/admin/retention"), tc.get("/api/admin/retention/preview"),
                  tc.post("/api/admin/retention/run", json={}, headers=h)):
            assert r.status_code == 403 and r.json()["error"] == "forbidden"
    with client_for(c) as tc:
        assert tc.get("/api/admin/retention").status_code == 401
    assert chats_left(rt, dee) == ["D1"]


def test_check_reports_retention(tmp_path):
    from goose_web.db import Database
    from tests.test_sec_web import make_settings
    s = make_settings(tmp_path)
    assert retention.check_lines(s) == [("--", "retention: chats and their attachments are deleted after 180 days without "
                                               "use (retention.chat_days); hourly, at most 200 chats per sweep")]
    s.data["retention"]["chat_days"] = 9999
    assert retention.check_lines(s)[-1] == ("!!", "retention.chat_days: 9999 is configured, the limit is 3650 - 3650 is used")
    db = Database(s.system_dir / "goose-web.db")
    db.set_setting("retention_days", 0)
    db.close()
    assert retention.check_lines(s) == [("--", "retention: off (Admin > Settings = 0) - chats and their attachments are "
                                               "kept forever")]
