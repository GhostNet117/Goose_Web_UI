"""Spec 020: sessions of the native profile that another program (Goose Desktop, the goose CLI, a scheduled job) is
writing are listed read-only for administrators - read from a Goose-shaped sessions.db, read-only."""
import hashlib
import json
import os
import sqlite3
import time

import pytest
import websockets

from goose_web import elsewhere as ew
from goose_web.db import Database
from goose_web.hub import ELSEWHERE_REFUSAL, RPC_ELSEWHERE, Hub
from test_hub import FakeWorkers, mk_client
from test_live_state import SteerAgent

SCHEMA = """
CREATE TABLE sessions (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  session_type TEXT NOT NULL DEFAULT 'user', working_dir TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, schedule_id TEXT, parent_session_id TEXT);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, session_id TEXT NOT NULL REFERENCES sessions(id),
  role TEXT NOT NULL, content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, tokens INTEGER, metadata_json TEXT);
CREATE INDEX idx_messages_session ON messages(session_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
CREATE INDEX idx_messages_session_created ON messages(session_id, created_timestamp, id);
CREATE INDEX idx_sessions_updated ON sessions(updated_at DESC);
"""
TEXT = json.dumps([{"type": "text", "text": "secret message content"}])
TOOL = json.dumps([{"type": "text", "text": "running"}, {"type": "toolRequest", "id": "t1", "toolCall": {}}])


def utc(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


class GooseDB:
    def __init__(self, root, wal=True):
        d = root / "data" / "sessions"
        d.mkdir(parents=True)
        self.path = d / "sessions.db"
        self.con = sqlite3.connect(self.path, isolation_level=None)
        if wal:
            self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript(SCHEMA)
        self.n = 0

    def session(self, sid, name, *, ago, cwd=r"C:\jobs\tqqq", schedule="", parent="", stype="user", msgs=("user", "assistant"),
                last_tool=False):
        t = time.time() - ago
        self.con.execute("INSERT INTO sessions(id, name, session_type, working_dir, created_at, updated_at, schedule_id, "
                         "parent_session_id) VALUES(?,?,?,?,?,?,?,?)",
                         (sid, name, stype, cwd, utc(t - 30), utc(t - 30), schedule or None, parent or None))
        for i, role in enumerate(msgs):
            last = i == len(msgs) - 1
            self.add(sid, role, TOOL if last and last_tool else TEXT, t - (len(msgs) - 1 - i))

    def add(self, sid, role, content, t):
        self.n += 1
        self.con.execute("INSERT INTO messages(message_id, session_id, role, content_json, created_timestamp, timestamp) "
                         "VALUES(?,?,?,?,?,?)", (f"m{self.n}", sid, role, content, int(t), utc(t)))


class NativeWorkers(FakeWorkers):
    def __init__(self, port, root):
        super().__init__(port)
        w = self.workers["alice"]
        w.native, w.path_root = True, str(root)


@pytest.fixture
async def nenv(tmp_path):
    agent = SteerAgent()
    server = await websockets.serve(agent.handler, "127.0.0.1", 0)
    db = GooseDB(tmp_path)
    hub = Hub(NativeWorkers(server.sockets[0].getsockname()[1], tmp_path))
    hub.started = time.time() - 3600   # the gateway has been up for an hour
    hub.db = Database(tmp_path / "gw.db")
    hub.start()
    yield agent, hub, db
    db.con.close()
    server.close()
    await server.wait_closed()


async def _subscribe(hub, up, role="admin", user="alice"):
    c, s = mk_client(user=user, role=role)
    hub.attach(up, c)
    await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 77, "method": "_gw/elsewhere", "params": {}})
    r = await s.wait_for(lambda m: m.get("id") == 77)
    return c, s, r["result"]


def test_name_prefix():
    assert ew.name_prefix("TQQQ-Macro 2026-11-11 04:00") == "TQQQ-Macro"
    assert ew.name_prefix("TQQQ-Macro 2026-11-11T04:00:12Z") == "TQQQ-Macro"
    assert ew.name_prefix("Report (3)") == "Report"
    assert ew.name_prefix("Run #12") == "Run"
    assert ew.name_prefix("Weekly review") == "Weekly review"
    assert ew.name_prefix("2026-11-11") == "2026-11-11"   # nothing but a date: kept
    assert ew._epoch("2026-11-11 09:00:00") == pytest.approx(1794387600.0)


async def test_cli_job_desktop_and_schedule_are_listed_grouped_and_private(nenv):
    agent, hub, db = nenv
    for i in range(5):   # a Windows task running `goose run` every few minutes: short finished sessions
        db.session(f"2026111_{i}", f"TQQQ-Macro 2026-11-11 04:{i:02d}", ago=60 * (i + 1))
    db.session("2026111_9", "TQQQ-Macro 2026-11-11 04:59", ago=5, msgs=("user",))           # the current run
    db.session("d1", "Desktop chat", ago=400, cwd=r"C:\work", msgs=("user", "assistant"), last_tool=True)   # long tool
    db.session("old", "Old CLI run", ago=60 * 25, cwd=r"C:\other")                          # finished 25 min ago
    db.session("sch1", "Nightly", ago=30, cwd=r"C:\x", schedule="nightly-report", msgs=("user",))
    db.session("p1", "Desktop parent", ago=60 * 20, cwd=r"C:\p", msgs=("user", "assistant"))  # quiet parent...
    db.session("c1", "subagent", ago=10, cwd=r"C:\p", parent="p1", stype="sub_agent", msgs=("user",))  # ...busy child
    db.session("gw1", "Goose Web chat", ago=3, cwd=r"C:\gw", msgs=("user",))                 # the gateway's own
    up = hub.upstream("alice", "alice")
    up.sess("gw1").prompts = 1   # running in Goose Web's worker
    c, s, res = await _subscribe(hub, up)
    assert res["enabled"] is True
    items = {i["title"]: i for i in res["items"]}   # Working elsewhere = what runs now (finished ones go to Done)
    assert set(items) == {"TQQQ-Macro 2026-11-11 04:59", "Desktop chat", "Scheduled job nightly-report",
                          "Desktop parent"}
    g = items["TQQQ-Macro 2026-11-11 04:59"]
    assert (g["count"], g["running"], g["status"], g["sessionId"]) == (1, 1, "running", "2026111_9")
    assert res["done"] == []   # first start: what finished before is history, not "done" (no backfill)
    assert items["Desktop chat"]["status"] == "running"          # assistant tool request last: a tool is running
    assert items["Desktop parent"]["status"] == "running"        # its sub-agent writes
    sch = items["Scheduled job nightly-report"]
    assert sch["source"] == "schedule" and sch["scheduleId"] == "nightly-report" and sch["scheduler"] == "Goose Desktop"
    raw = json.dumps(res)
    for secret in ("secret message content", "jobs", "tqqq\\", "C:\\\\work", "cwd"):   # no folders, no content
        assert secret not in raw
    # the gateway's own chat is never "elsewhere"; once it ran in Goose Web two minutes before the write it is not either
    assert "gw1" not in raw
    # prompts into a chat running elsewhere are refused; a finished one can be continued
    await up.from_client(c, {"jsonrpc": "2.0", "id": 5, "method": "session/prompt",
                             "params": {"sessionId": "d1", "prompt": [{"type": "text", "text": "x"}]}})
    err = await s.wait_for(lambda m: m.get("id") == 5)
    assert err["error"] == {"code": RPC_ELSEWHERE, "message": ELSEWHERE_REFUSAL}
    assert agent.prompt is None
    await up.from_client(c, {"jsonrpc": "2.0", "id": 6, "method": "_goose/unstable/session/conversation/truncate",
                             "params": {"sessionId": "2026111_9", "truncateFrom": 5}})
    assert (await s.wait_for(lambda m: m.get("id") == 6))["error"]["code"] == RPC_ELSEWHERE
    await up.from_client(c, {"jsonrpc": "2.0", "id": 7, "method": "session/prompt",
                             "params": {"sessionId": "2026111_3", "prompt": [{"type": "text", "text": "go on"}]}})
    await s.wait_for(lambda m: (m.get("params") or {}).get("update", {}).get("_meta", {}).get("goose", {})
                     .get("activeRunId") == "run-1")


async def test_viewing_is_not_writing_and_updated_at_is_not_activity(nenv):
    """Opening a chat in Goose Web (session/load) bumps sessions.updated_at and touches the gateway's session state;
    neither may turn a running-elsewhere chat into Goose Web's own, nor revive an old one. A chat without messages
    is not listed; a chat restored from a herd mark is Goose Web's."""
    agent, hub, db = nenv
    db.session("d1", "Desktop chat", ago=400, cwd=r"C:\work", last_tool=True)
    db.session("old", "Old chat", ago=60 * 40, cwd=r"C:\work2")
    db.con.execute("UPDATE sessions SET updated_at=? WHERE id='old'", (utc(time.time()),))   # just opened somewhere
    db.con.execute("INSERT INTO sessions(id, name, working_dir, created_at, updated_at) VALUES('empty', 'New Chat', "
                   "'C:\\x', ?, ?)", (utc(time.time()), utc(time.time())))
    db.session("marked", "Interrupted chat", ago=50, cwd=r"C:\gw", last_tool=True)
    up = hub.upstream("alice", "alice")
    up.restore_state([{"session_id": "marked", "kind": "mark",
                       "data": {"status": "working", "since": time.time() - 60, "title": "Interrupted chat"}}])
    up.sess("d1")   # the administrator opened it (read-only view): touched, not written
    c, s, res = await _subscribe(hub, up)
    # what a tab sends when it opens a chat (load, extension list, info) is not a write
    for i, m in enumerate(("session/load", "_goose/unstable/session/extensions/list", "_goose/unstable/session/info")):
        await up.from_client(c, {"jsonrpc": "2.0", "id": 100 + i, "method": m, "params": {"sessionId": "d1", "cwd": "/"}})
        await s.wait_for(lambda msg, i=i: msg.get("id") == 100 + i)
    assert up.sessions["d1"].wrote_at == 0.0
    await hub.elsewhere_tick(up)
    res = {"items": hub.elsewhere["alice"].items}
    assert [(i["sessionId"], i["status"]) for i in res["items"]] == [("d1", "running")]
    assert hub.elsewhere_running("alice", "d1")
    # Goose Web itself writes it (a prompt that went through): from then on it is Goose Web's
    up.sessions["d1"].wrote_at = time.time()
    db.add("d1", "user", TEXT, time.time())
    await hub.elsewhere_tick(up)
    assert hub.elsewhere["alice"].items == []


async def test_members_and_non_native_profiles_never_see_it(nenv):
    agent, hub, db = nenv
    db.session("x1", "CLI run", ago=5, msgs=("user",))
    up = hub.upstream("alice", "alice")
    c, s, res = await _subscribe(hub, up, role="user", user="bob")
    assert res == {"enabled": False, "items": [], "done": []} and c.elsewhere is False
    hub.workers.workers["alice"].native = False
    c2, s2, res2 = await _subscribe(hub, up)
    assert res2 == {"enabled": False, "items": [], "done": []}
    assert not hub.elsewhere_running("alice", "x1")


async def test_reads_only_when_the_database_changed_and_pushes_changes(nenv):
    agent, hub, db = nenv
    db.session("x1", "CLI run", ago=5, msgs=("user",))
    up = hub.upstream("alice", "alice")
    c, s, res = await _subscribe(hub, up)
    wt = hub.elsewhere["alice"]
    assert wt.reads == 1 and [i["status"] for i in res["items"]] == ["running"]
    for _ in range(3):
        await hub.elsewhere_tick(up)
    assert wt.reads == 1                       # unchanged database: no query
    db.add("x1", "assistant", TEXT, time.time())   # the CLI run finishes
    await hub.elsewhere_tick(up)
    assert wt.reads == 2
    await s.wait_for(lambda m: m.get("method") == "_gw/elsewhere" and not m["params"]["items"]
                     and [d["sessionId"] for d in m["params"]["done"]] == ["x1"])   # working -> done
    assert not hub.elsewhere_running("alice", "x1")
    assert wt.items == []
    # stale information never refuses a prompt
    db.session("x2", "CLI run 2", ago=1, msgs=("user",))
    await hub.elsewhere_tick(up)
    assert hub.elsewhere_running("alice", "x2")
    wt.ticked -= 10 * 60
    assert not hub.elsewhere_running("alice", "x2")


def test_read_is_read_only_and_never_waits_long(tmp_path):
    db = GooseDB(tmp_path, wal=False)
    db.session("a", "CLI run", ago=5, msgs=("user",))
    before = hashlib.sha256(db.path.read_bytes()).hexdigest()
    rows = ew.read_activity(db.path, time.time() - 600)
    assert [r["sessionId"] for r in rows] == ["a"] and rows[0]["role"] == "user"
    assert hashlib.sha256(db.path.read_bytes()).hexdigest() == before
    assert not os.path.exists(str(db.path) + "-journal")
    # a writer holding the lock: the read gives up after ~0.5 s (the watcher keeps its previous list)
    db.con.execute("BEGIN EXCLUSIVE")
    t = time.monotonic()
    with pytest.raises(sqlite3.OperationalError):
        ew.read_activity(db.path, time.time() - 600)
    assert time.monotonic() - t < 3
    db.con.execute("ROLLBACK")
    db.con.close()


async def test_locked_database_keeps_the_previous_list(nenv, monkeypatch):
    agent, hub, db = nenv
    db.session("x1", "CLI run", ago=5, msgs=("user",))
    up = hub.upstream("alice", "alice")
    c, s, res = await _subscribe(hub, up)
    assert len(res["items"]) == 1

    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(ew, "read_activity", locked)
    db.add("x1", "user", TEXT, time.time())
    await hub.elsewhere_tick(up)
    wt = hub.elsewhere["alice"]
    assert "locked" in wt.error and len(wt.items) == 1


def test_status_rules_and_restart_forgets_own_chats():
    now = 10_000.0
    st = lambda **r: ew.session_status({"last": now - r.pop("age"), **r}, now, 300, 1800)   # noqa: E731
    assert st(age=1500, role="assistant", tool=True) == "running"     # a long tool call writes nothing
    assert st(age=1900, role="assistant", tool=True) == "finished"
    assert st(age=60, role="user") == "running"                       # the model is answering
    assert st(age=400, role="user") == "finished"                     # cancelled: ends with a tool result
    assert st(age=5, role="assistant") == "finished"                  # the final answer
    assert st(age=60, role="assistant", sub=True) == "running"        # its sub-agent writes


def _finish(db, sid, name, cwd=r"C:\jobs\tqqq", **kw):
    db.session(sid, name, ago=1, cwd=cwd, **kw)   # created and finished between two polls


async def test_done_elsewhere_grouped_persisted_until_opened(nenv, tmp_path):
    """Every chat that finished elsewhere stays in Done until the administrator interacts with it in Goose Web;
    a job's many short sessions are ONE entry; the markers survive a refresh, other devices and a restart."""
    agent, hub, db = nenv
    db.session("r1", "TQQQ-Macro 2026-11-11 05:00", ago=5, msgs=("user",))          # working elsewhere now
    db.session("hist", "Old run", ago=600, cwd=r"C:\h")                              # finished before: history
    up = hub.upstream("alice", "alice")
    c, s, res = await _subscribe(hub, up)
    assert [i["sessionId"] for i in res["items"]] == ["r1"] and res["done"] == []
    wt = hub.elsewhere["alice"]
    db.add("r1", "assistant", TEXT, time.time())                                        # r1 ends
    for k in range(60):                                                                 # a flood of short CLI runs
        _finish(db, f"q{k}", f"TQQQ-Macro 2026-11-11 05:{k:02d}")
    _finish(db, "dsk", "Desktop chat", cwd=r"C:\work")
    _finish(db, "nr", "Nightly", cwd=r"C:\x", schedule="nightly-report")
    await hub.elsewhere_tick(up)
    done = {d["title"]: d for d in wt.done()}
    assert set(done) == {"TQQQ-Macro", "Desktop chat", "Scheduled job nightly-report"}
    assert done["TQQQ-Macro"]["count"] == 61 and len(done["TQQQ-Macro"]["sessions"]) == ew.DONE_SEND
    assert wt.items == [] and "hist" not in json.dumps(wt.done())
    push = await s.wait_for(lambda m: m.get("method") == "_gw/elsewhere" and len(m["params"]["done"]) == 3)
    assert "C:\\\\jobs" not in json.dumps(push) and "secret" not in json.dumps(push)
    # unchanged database: nothing is added twice
    await hub.elsewhere_tick(up)
    assert done["TQQQ-Macro"]["count"] == {d["title"]: d for d in wt.done()}["TQQQ-Macro"]["count"]
    # persisted (survives a gateway restart / another device): a new hub on the same database has it
    hub.flush_state_now()
    hub2 = Hub(hub.workers)
    hub2.db = hub.db
    up2 = hub2.upstream("alice", "alice")
    c2, s2, res2 = await _subscribe(hub2, up2)
    assert {d["title"] for d in res2["done"]} == set(done)
    # opening ONE session of the group in Goose Web clears the whole group (the group is one entry)
    await hub2.gw_method(up2, c2, {"jsonrpc": "2.0", "id": 8, "method": "_gw/seen", "params": {"sessionId": "q3"}})
    assert {d["title"] for d in hub2.elsewhere["alice"].done()} == {"Desktop chat", "Scheduled job nightly-report"}
    await s2.wait_for(lambda m: m.get("method") == "_gw/elsewhere" and len(m["params"]["done"]) == 2)
    # ...and it does not come back, while a NEW run of the job is done again (count 1)
    db.add("dsk", "user", TEXT, time.time())          # change the database (Desktop chat working again)
    await hub2.elsewhere_tick(up2)
    w2 = hub2.elsewhere["alice"]
    assert {d["title"] for d in w2.done()} == {"Scheduled job nightly-report"}   # working again: not done
    assert [i["sessionId"] for i in w2.items] == ["dsk"]
    _finish(db, "q99", "TQQQ-Macro 2026-11-11 06:00")
    await hub2.elsewhere_tick(up2)
    d = {x["title"]: x for x in w2.done()}
    assert d["TQQQ-Macro 2026-11-11 06:00"]["count"] == 1
    # members cannot clear; an administrator clears one group, then "mark all read"
    cm, sm = mk_client(user="bob", role="user")
    hub2.attach(up2, cm)
    await hub2.gw_method(up2, cm, {"jsonrpc": "2.0", "id": 9, "method": "_gw/elsewhere_clear", "params": {}})
    assert (await sm.wait_for(lambda m: m.get("id") == 9))["result"] == {"ok": False}
    key = d["Scheduled job nightly-report"]["key"]
    await hub2.gw_method(up2, c2, {"jsonrpc": "2.0", "id": 10, "method": "_gw/elsewhere_clear", "params": {"key": key}})
    assert {x["title"] for x in w2.done()} == {"TQQQ-Macro 2026-11-11 06:00"}
    await hub2.gw_method(up2, c2, {"jsonrpc": "2.0", "id": 11, "method": "_gw/elsewhere_clear", "params": {}})
    assert w2.done() == []
    hub2.flush_state_now()
    row = [r for r in hub.db.chat_state("alice") if r["session_id"] == ew.DONE_ROW]
    assert row and row[0]["data"]["groups"] == {} and "q3" in row[0]["data"]["acked"]
    # the row is not a chat: the session-list prune keeps it
    hub2.prune_chat_state("alice", set())
    assert [r for r in hub.db.chat_state("alice") if r["session_id"] == ew.DONE_ROW]


async def test_finished_while_nobody_watched_is_caught_up(nenv):
    agent, hub, db = nenv
    up = hub.upstream("alice", "alice")
    c, s, res = await _subscribe(hub, up)
    wt = hub.elsewhere["alice"]
    hub.detach(up, c)                       # everybody closes Goose Web; the watcher is not ticked
    wt.watermark = time.time() - 3 * 3600   # ... for three hours
    wt.ticked = 0
    db.session("late", "Overnight job", ago=2 * 3600, cwd=r"C:\n")
    db.session("ancient", "Last week", ago=30 * 3600, cwd=r"C:\n2")   # beyond done_hours
    c, s, res = await _subscribe(hub, up)
    assert [d["sessionId"] for d in res["done"]] == ["late"]


def test_frontend_wiring():
    """Read-only in the UI: the chat hides its message box while another program runs it; the herd card has no Stop;
    a refused prompt (drain or running elsewhere) goes back into the message box."""
    from pathlib import Path
    js = Path(ew.__file__).parent / "static" / "js"
    chat = (js / "views" / "chat.js").read_text(encoding="utf-8")
    assert "composer.el.hidden = ro" in chat and "Working elsewhere - read-only" in chat
    herd = (js / "views" / "herd.js").read_text(encoding="utf-8")
    card = herd[herd.index("const elseCard"):herd.index("const markAllRead")]
    assert "Stop" not in card and "session/cancel" not in card and "Read-only here" in card
    assert "'Working elsewhere'" in herd and "Mark all read" in herd and "clearElsewhereDone(it.key)" in card
    store = (js / "herd.js").read_text(encoding="utf-8")
    assert "c.done += c.doneElsewhere" in store   # Done elsewhere counts in the done counter and the badge
    side = (js / "views" / "sidebar.js").read_text(encoding="utf-8")
    assert "'Working elsewhere'" in side and "bus.on('elsewhere'" in side
    app = (js / "app.js").read_text(encoding="utf-8")
    assert "rpc.call('_gw/elsewhere'" in app and "meNow.isAdmin && !rpc.profileParam" in app
    cs = (js / "chatsession.js").read_text(encoding="utf-8")
    assert "e.code === -32010 || e.code === -32011" in cs and "this.emit('edit', blocks)" in cs


def test_no_database_no_list(tmp_path):
    rows = []
    assert ew.build_items(rows, now=time.time(), own=lambda s, t: False, stale_s=1800, max_items=40) == []
