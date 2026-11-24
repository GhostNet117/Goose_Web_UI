"""FIX chat-open-readonly-fallback: when Goose cannot load a chat, the person can read a read-only copy of it, read
straight from the profile's Goose session database (GET /api/sessions/{sid}/transcript, goose_web/transcript.py).

Access is that of opening the chat and never wider: the caller's own profile; ?profile= for administrators only
(audited as transcript.view); for a member the folder rules session/load gets. The database is only read."""
import calendar
import hashlib
import json
import re
import sqlite3
from pathlib import Path

import pytest

from goose_web import api, security
from goose_web import policy as pol
from goose_web import transcript as T
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)

JS = Path(api.__file__).parent / "static" / "js"
DOCS = Path(api.__file__).parent.parent / "docs"
SID = "20261124_1"
T0 = 1764000000

# The tables Goose writes (schema checked on Goose's sessions.db, 2026-11-24; columns this feature does not read are
# left out). WAL like Goose.
SCHEMA = [
    """CREATE TABLE sessions (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
       user_set_name BOOLEAN DEFAULT FALSE, session_type TEXT NOT NULL DEFAULT 'user', working_dir TEXT NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       extension_data TEXT DEFAULT '{}', schedule_id TEXT, recipe_json TEXT, goose_mode TEXT NOT NULL DEFAULT 'auto',
       archived_at TIMESTAMP, project_id TEXT, parent_session_id TEXT)""",
    """CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
       session_id TEXT NOT NULL REFERENCES sessions(id), role TEXT NOT NULL, content_json TEXT NOT NULL,
       created_timestamp INTEGER NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, tokens INTEGER,
       metadata_json TEXT)""",
    "CREATE INDEX idx_messages_session ON messages(session_id)",
    "CREATE INDEX idx_messages_session_created ON messages(session_id, created_timestamp, id)",
]
SHOWN = {"userVisible": True, "agentVisible": True}
HIDDEN = {"userVisible": False, "agentVisible": True}


def text(t):
    return [{"type": "text", "text": t}]


def goose_db(path: Path, sessions: list[tuple], messages: list[tuple] = ()) -> Path:
    """sessions: (id, working_dir[, name]); messages: (session id, role, content blocks, metadata or raw text)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    for s in SCHEMA:
        con.execute(s)
    for s in sessions:
        con.execute("INSERT INTO sessions(id, name, working_dir, created_at, updated_at) VALUES(?,?,?,?,?)",
                    (s[0], s[2] if len(s) > 2 else "A chat", s[1], "2026-11-24 10:00:00", "2026-11-24 11:30:00"))
    add(con, messages)
    con.commit()
    con.close()
    return path


def add(con, messages) -> None:
    for i, (sid, role, content, meta) in enumerate(messages):
        con.execute("INSERT INTO messages(message_id, session_id, role, content_json, created_timestamp, metadata_json) "
                    "VALUES(?,?,?,?,?,?)", (f"msg_{i}", sid, role, content if isinstance(content, str) else
                                            json.dumps(content), T0 + i,
                                            meta if meta is None or isinstance(meta, str) else json.dumps(meta)))


def conversation(sid: str = SID) -> list[tuple]:
    return [
        (sid, "user", text("Please list the files"), SHOWN),
        (sid, "assistant", [{"type": "thinking", "thinking": "I should call the shell.", "signature": "sig"},
                            {"type": "text", "text": "Listing **now**."},
                            {"type": "toolRequest", "id": "call_1", "_meta": {},
                             "toolCall": {"status": "success", "value": {"name": "developer__shell",
                                                                         "arguments": {"command": "dir"}}}}], SHOWN),
        (sid, "user", [{"type": "toolResponse", "id": "call_1", "toolResult": {"status": "success", "value": {
            "content": [{"type": "text", "text": "a.txt\nb.txt"}], "isError": False, "resultType": "x"}}}], SHOWN),
        (sid, "user", text("SECRET SYSTEM-ONLY CONTEXT"), HIDDEN),
        (sid, "user", [{"type": "text", "text": "And this picture?"},
                       {"type": "image", "data": "aGVsbG8gaW1hZ2UgYnl0ZXM=", "mimeType": "image/png"}], SHOWN),
        (sid, "assistant", text("Done."), {"userVisible": True, "agentVisible": True, "usage": {}}),
    ]


@pytest.fixture(autouse=True)
def _fresh_limiter(monkeypatch):
    # the limiter is per process and keyed by user id, which every test's fresh database hands out again
    monkeypatch.setattr(api, "_TRANSCRIPT_LIMIT", security.RateLimiter(10_000, 60.0))


@pytest.fixture
def world(env, tmp_path):
    """A team member (dee) with a chat in her workspace, another member (eve) and an administrator (boss)."""
    s, db, pr, c = env
    tid = team(db, "A", ANYCHAT)
    people = {}
    for name, role in (("dee", "user"), ("eve", "user"), ("boss", "admin")):
        u = user(db, name, role=role)
        if role != "admin":
            db.set_user_team(u["id"], tid)
        u = db.user_by_id(u["id"])
        pr.ensure_layout(u)
        people[name] = u
    dee_db = goose_db(T.db_path(pr.root_for(people["dee"])), [(SID, str(pr.workspace(people["dee"])), "Files")],
                      conversation())
    goose_db(T.db_path(pr.root_for(people["eve"])), [("20261124_9", str(pr.workspace(people["eve"])))],
             [("20261124_9", "user", text("EVE PRIVATE NOTE"), SHOWN)])
    return s, db, pr, c, people, dee_db


def url(sid=SID, **q):
    return f"/api/sessions/{sid}/transcript", q


def get(tc, sid=SID, **q):
    path, params = url(sid, **q)
    return tc.get(path, params=params)


def audit_rows(db, action):
    return [dict(r) for r in db.query("SELECT username, action, target, detail, ok FROM audit WHERE action=? ORDER BY id",
                                      (action,))]


# ------------------------------------------------------------------ access
def test_own_profile_shows_the_visible_conversation(world):
    s, db, pr, c, people, _ = world
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        r = get(tc)
        assert r.status_code == 200, r.text
        assert r.headers["cache-control"] == "no-store"
        d = r.json()
    ses = d["session"]
    assert ses["id"] == SID and ses["name"] == "Files" and ses["workingDir"] == str(pr.workspace(people["dee"]))
    assert ses["created"] == calendar.timegm((2026, 11, 24, 10, 0, 0)) and ses["updated"] == calendar.timegm((2026, 11, 24, 11, 30, 0))
    assert d["total"] == 5 and d["more"] is False and len(d["messages"]) == 5 and d["after"] == 0
    roles = [m["role"] for m in d["messages"]]
    assert roles == ["user", "assistant", "user", "user", "assistant"]
    assert d["next"] == d["messages"][-1]["id"] and d["messages"][0]["created"] == T0
    think, words, call = d["messages"][1]["blocks"]
    assert think == {"type": "thinking", "text": "I should call the shell."}             # marked as thinking
    assert words == {"type": "text", "text": "Listing **now**."}
    assert call["type"] == "toolRequest" and call["tool"] == "developer__shell" and json.loads(call["text"]) == {"command": "dir"}
    res = d["messages"][2]["blocks"][0]
    assert res["type"] == "toolResponse" and res["tool"] == "developer__shell" and res["text"] == "a.txt\nb.txt"
    assert not res["error"]
    pic = d["messages"][3]["blocks"]
    assert pic[1] == {"type": "image", "mimeType": "image/png"}                         # a placeholder, no bytes
    assert "aGVsbG8" not in r.text and "SECRET SYSTEM-ONLY CONTEXT" not in r.text
    assert audit_rows(db, "transcript.view") == []                                       # own profile: not audited


def test_another_members_chat_is_refused(world):
    s, db, pr, c, people, _ = world
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        r = get(tc, "20261124_9")                     # eve's chat is not in dee's profile
        assert r.status_code == 404 and r.json()["error"] == "not_found"
        r = get(tc, "20261124_9", profile="eve")     # ?profile= is for administrators only
        assert r.status_code == 403 and r.json()["error"] == "forbidden"
        r = get(tc, SID, profile="Dee")              # her own name (any case) is her own profile
        assert r.status_code == 200
    assert "EVE PRIVATE NOTE" not in r.text


def test_member_folder_rules_refuse_like_session_load(world, tmp_path):
    s, db, pr, c, people, dee_db = world
    dee = people["dee"]
    outside = tmp_path / "outside"
    outside.mkdir()
    con = sqlite3.connect(dee_db)
    con.execute("INSERT INTO sessions(id, name, working_dir) VALUES('20261124_2', 'Elsewhere', ?)", (str(outside),))
    add(con, [("20261124_2", "user", text("hello"), SHOWN)])
    con.commit()
    con.close()
    policy = c.policy_for(dee)
    with pytest.raises(pol.Denied) as e:          # what opening the chat answers
        pol.check("session/load", {"sessionId": "20261124_2", "cwd": str(outside)}, is_admin=False, policy=policy,
                  roots=c.roots_for(dee, policy))
    with client_for(c) as tc:
        sign_in(tc, c, dee)
        r = get(tc, "20261124_2")
        assert r.status_code == 403 and r.json()["error"] == "forbidden"
        assert r.json()["message"] == f"forbidden: {e.value}" and "folder not allowed" in r.json()["message"]
        assert "hello" not in r.text
        sign_in(tc, c, people["boss"])            # administrators have no folder rules (as with session/load)
        assert get(tc, "20261124_2", profile="dee").status_code == 200
    denied = audit_rows(db, "acp.denied")
    assert denied and denied[0]["username"] == "dee" and denied[0]["target"] == "session/load" and not denied[0]["ok"]
    assert denied[0]["detail"]["via"] == "transcript" and "folder not allowed" in denied[0]["detail"]["reason"]


def test_admin_profile_param_is_allowed_and_audited(world):
    s, db, pr, c, people, _ = world
    with client_for(c) as tc:
        sign_in(tc, c, people["boss"])
        r = get(tc, profile="dee", after=0, limit=2)
        assert r.status_code == 200 and len(r.json()["messages"]) == 2
        rows = audit_rows(db, "transcript.view")
        assert len(rows) == 1 and rows[0]["username"] == "boss" and rows[0]["target"] == "dee" and rows[0]["ok"]
        assert rows[0]["detail"] == {"sessionId": SID, "after": 0}
        assert get(tc, profile="nobody").status_code == 404
        assert get(tc).status_code == 404                     # the admin's own profile has no such chat
        sign_in(tc, c, people["eve"])
        r = get(tc, profile="boss")
        assert r.status_code == 403 and r.json()["error"] == "forbidden"
    assert len(audit_rows(db, "transcript.view")) == 1


def test_bad_ids_unknown_chats_and_sign_in(world, tmp_path):
    s, db, pr, c, people, _ = world
    with client_for(c) as tc:
        assert get(tc).status_code == 401                     # signed out
        sign_in(tc, c, people["dee"])
        for bad in ("bad$id", "a b", "x" * 129, "%C3%A9t%C3%A9", "a;drop"):
            r = get(tc, bad)
            assert r.status_code == 400 and r.json()["error"] == "bad_request", bad
        assert get(tc, "20991231_7").status_code == 404
        for q in ({"after": "x"}, {"limit": "many"}, {"after": "1e999"}):
            assert get(tc, **q).status_code == 400, q
        sign_in(tc, c, people["boss"])                         # a profile without a session database yet
        assert get(tc).status_code == 404
    assert not T.db_path(pr.root_for(people["boss"])).exists()   # ... which was not created
    assert T.read(tmp_path / "none" / "sessions.db", SID) is None and not (tmp_path / "none").exists()


def test_unreadable_database_answers_503(world):
    s, db, pr, c, people, dee_db = world
    for suffix in ("-wal", "-shm"):
        Path(str(dee_db) + suffix).unlink(missing_ok=True)
    dee_db.write_bytes(b"this is not a database" * 100)
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        r = get(tc)
        assert r.status_code == 503 and r.json()["error"] == "unavailable"


def test_rate_limited(world, monkeypatch):
    s, db, pr, c, people, _ = world
    monkeypatch.setattr(api, "_TRANSCRIPT_LIMIT", security.RateLimiter(2, 60.0))
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        assert [get(tc).status_code for _ in range(3)] == [200, 200, 429]


# ------------------------------------------------------------------ paging and what is shown
def test_paging_by_message_id(world):
    s, db, pr, c, people, dee_db = world
    con = sqlite3.connect(dee_db)
    add(con, [(SID, "user" if i % 2 else "assistant", text(f"m{i}"), HIDDEN if i % 10 == 0 else SHOWN)
              for i in range(450)])
    con.commit()
    want = [r[0] for r in con.execute(f"SELECT id FROM messages WHERE session_id=? AND {T._VISIBLE} ORDER BY id", (SID,))]
    con.close()
    assert len(want) == 5 + 405
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        got, after, pages = [], 0, 0
        while True:
            d = get(tc, after=after).json()
            pages += 1
            assert d["total"] == len(want) and d["limit"] == T.DEFAULT_LIMIT and len(d["messages"]) <= 200
            got += [m["id"] for m in d["messages"]]
            if not d["more"]:
                break
            assert d["next"] == d["messages"][-1]["id"]
            after = d["next"]
        assert got == want and pages == 3
        assert len(get(tc, limit=5000).json()["messages"]) == len(want)     # at most MAX_LIMIT (1000) per page
        assert T.MAX_LIMIT == 1000
        d = get(tc, limit=0).json()                                           # at least one
        assert len(d["messages"]) == 1 and d["more"] is True
        d = get(tc, after=want[-1]).json()
        assert d["messages"] == [] and d["more"] is False and d["next"] == want[-1]


def test_only_user_visible_messages(tmp_path):
    db = goose_db(tmp_path / "sessions.db", [(SID, "C:/w")], [
        (SID, "user", text("shown"), SHOWN),
        (SID, "user", text("hidden"), HIDDEN),
        (SID, "user", text("no metadata"), None),
        (SID, "user", text("empty metadata"), {}),
        (SID, "user", text("bad metadata"), "{not json"),
        (SID, "assistant", text("agent only"), {"userVisible": False, "agentVisible": True}),
        (SID, "assistant", text("summary for the user"), {"userVisible": True, "agentVisible": False}),
        ("20261124_5", "user", text("another chat"), SHOWN),
    ])
    d = T.read(db, SID)
    shown = [m["blocks"][0]["text"] for m in d["messages"]]
    assert shown == ["shown", "no metadata", "empty metadata", "bad metadata", "summary for the user"]
    assert d["total"] == 5


def test_block_summaries_cover_goose_shapes():
    tools = {}
    blocks = [
        {"type": "toolRequest", "id": "c1", "toolCall": {"status": "error", "error": "no such tool"}},
        {"type": "frontendToolRequest", "id": "c2", "toolCall": {"status": "success", "value": {"name": "ui__x", "arguments": None}}},
        {"type": "toolResponse", "id": "c2", "toolResult": {"status": "success", "value": [
            {"type": "text", "text": "old style"}, {"type": "image", "data": "QUJD", "mimeType": "image/png"},
            {"type": "resource", "resource": {"uri": "file:///x", "blob": "QUJD"}}]}},
        {"type": "toolResponse", "id": "c3", "toolResult": {"status": "error", "error": {"code": -1, "message": "boom"}}},
        {"type": "toolResponse", "id": "c4", "toolResult": {"status": "success", "value": {"content": [], "isError": True}}},
        {"type": "redactedThinking", "data": "xyz"},
        {"type": "systemNotification", "notificationType": "inlineMessage", "msg": "Compacting"},
        {"type": "somethingNew", "payload": 1},
        "not a block",
    ]
    m = T.message_view(7, "assistant", T0, 100, json.dumps(blocks), tools)
    b = m["blocks"]
    assert b[0]["type"] == "toolRequest" and b[0]["error"] and b[0]["text"] == "no such tool" and b[0]["tool"] == ""
    assert b[1]["tool"] == "ui__x" and b[1]["text"] == "" and tools == {"c2": "ui__x"}
    assert b[2]["tool"] == "ui__x" and b[2]["text"] == "old style\n[image]\n[resource file:///x]" and "QUJD" not in json.dumps(m)
    assert b[3]["error"] and b[3]["text"] == "boom" and b[4]["error"] and b[4]["text"] == ""
    assert b[5] == {"type": "thinking", "text": "", "redacted": True}
    assert b[6] == {"type": "notice", "kind": "systemNotification", "text": "Compacting"}
    assert b[7] == {"type": "notice", "kind": "somethingNew", "text": ""} and len(b) == 8
    assert T.message_view(8, "user", "x", 5, "{bad")["blocks"][0]["kind"] == "unreadable"
    assert T.message_view(9, "user", T0, 3, "{}")["created"] == T0


# ------------------------------------------------------------------ size caps
def test_message_and_page_size_caps(tmp_path, monkeypatch):
    big = "x" * (T.TEXT_MAX + 50_000)
    db = goose_db(tmp_path / "sessions.db", [(SID, "C:/w")], [
        (SID, "assistant", [{"type": "text", "text": big}, {"type": "text", "text": "after the cap"}], SHOWN),
        (SID, "user", [{"type": "toolResponse", "id": "t", "toolResult": {"status": "success", "value": {
            "content": [{"type": "text", "text": "y" * 10_000}], "isError": False}}}], SHOWN),
        (SID, "user", [{"type": "image", "data": "Z" * 3000, "mimeType": "image/jpeg"}], SHOWN),
    ] + [(SID, "assistant", text("z" * 2000), SHOWN) for _ in range(30)])
    d = T.read(db, SID)
    first = d["messages"][0]
    assert first["truncated"] and len(first["blocks"]) == 1 and len(first["blocks"][0]["text"]) == T.TEXT_MAX
    assert first["blocks"][0]["truncated"]
    tool = d["messages"][1]["blocks"][0]
    assert tool["truncated"] and len(tool["text"]) == T.TOOL_TEXT_MAX
    assert "ZZZZ" not in json.dumps(d)
    # a stored message over RAW_MAX is not read at all
    monkeypatch.setattr(T, "RAW_MAX", 1000)
    d = T.read(db, SID, limit=3)
    assert d["messages"][0]["blocks"][0]["kind"] == "too-large" and d["messages"][0]["truncated"]
    monkeypatch.undo()
    # the page: at most PAGE_BYTES of JSON, at least one message, and the next page goes on from there
    monkeypatch.setattr(T, "PAGE_BYTES", 20_000)
    d = T.read(db, SID)
    assert len(d["messages"]) == 1 and d["more"] is True                # the first message alone is bigger
    d2 = T.read(db, SID, after=d["next"])
    n = sum(len(json.dumps(m, ensure_ascii=False).encode()) for m in d2["messages"])
    assert d2["more"] is True and 1 < len(d2["messages"]) < 30 and n <= 20_000
    assert d2["messages"][0]["id"] == d["next"] + 1
    monkeypatch.setattr(T, "READ_MAX", 1)                                # stored content read per page
    d3 = T.read(db, SID, after=d["next"])
    assert len(d3["messages"]) == 1 and d3["more"] is True


# ------------------------------------------------------------------ read-only
def test_the_database_is_opened_read_only_and_left_unchanged(world):
    s, db, pr, c, people, dee_db = world
    before = hashlib.sha256(dee_db.read_bytes()).hexdigest()
    with client_for(c) as tc:
        sign_in(tc, c, people["dee"])
        for q in ({}, {"after": 2}, {"limit": 1}):
            assert get(tc, **q).status_code == 200
    assert hashlib.sha256(dee_db.read_bytes()).hexdigest() == before
    con = T.connect(dee_db)
    try:
        assert con.execute("PRAGMA query_only").fetchone()[0] == 1
        for sql in ("INSERT INTO messages(session_id, role, content_json, created_timestamp) VALUES('x','user','[]',1)",
                    "UPDATE sessions SET name='changed'", "DELETE FROM messages", "CREATE TABLE gw(x)"):
            with pytest.raises(sqlite3.OperationalError, match="readonly|read-only|query_only"):
                con.execute(sql)
    finally:
        con.close()
    raw = sqlite3.connect(f"{dee_db.as_uri()}?mode=ro", uri=True)      # the URI alone refuses writes, too
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            raw.execute("DELETE FROM messages")
    finally:
        raw.close()
    assert hashlib.sha256(dee_db.read_bytes()).hexdigest() == before
    check = sqlite3.connect(dee_db)
    assert check.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 6
    assert check.execute("SELECT name FROM sessions WHERE id=?", (SID,)).fetchone()[0] == "Files"
    check.close()
    src = (Path(api.__file__).parent / "transcript.py").read_text(encoding="utf-8")
    assert "?mode=ro" in src and "PRAGMA query_only=1" in src and "uri=True" in src


# ------------------------------------------------------------------ the route, the front end and the docs
def test_route_and_front_end_wiring():
    assert any(getattr(r, "path", "") == "/api/sessions/{sid}/transcript" and r.endpoint is api.session_transcript
               for r in api.routes)
    ro = (JS / "readonly.js").read_text(encoding="utf-8")
    for name in ("renderReadOnly", "offerReadOnly", "transcriptPath"):
        assert re.search(rf"export function {name}\(", ro), name
    assert "import { mdElement } from './markdown.js';" in ro            # marked + DOMPurify
    code = "\n".join(line for line in ro.splitlines() if not line.lstrip().startswith("//"))
    assert "innerHTML" not in code and "insertAdjacentHTML" not in code and "outerHTML" not in code
    assert "'Read-only copy'" in ro and "' - Goose could not load this chat: '" in ro
    assert "btn('Load more'" in ro and "btn('Try again'" in ro and "onRetry()" in ro
    assert "btn('Show a read-only copy'" in ro and ".empty-actions" in ro
    assert "'/api/sessions/' + encodeURIComponent(sessionId) + '/transcript'" in ro
    assert "rpc.profileParam" in ro                                       # an admin's view of another profile
    md = (JS / "markdown.js").read_text(encoding="utf-8")
    assert "DOMPurify.sanitize(" in md and "export function mdElement(" in md
    chat = (JS / "views" / "chat.js").read_text(encoding="utf-8")
    assert "import { offerReadOnly } from '../readonly.js';" in chat
    card = chat.split("'Could not open this session'", 1)[1].split("} else errorEl.hidden = true;", 1)[0]
    assert "offerReadOnly(errorEl, chat.id, chat.error, () => chat.reload());" in card
    css = (JS.parent / "css" / "app.css").read_text(encoding="utf-8")
    assert ".readonly {" in css and ".ro-pre {" in css
    assert "/api/sessions/{id}/transcript" in (DOCS / "API.md").read_text(encoding="utf-8")
    assert "readonly.js" in (DOCS / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "read-only copy" in (DOCS / "USER-GUIDE.md").read_text(encoding="utf-8").lower()
