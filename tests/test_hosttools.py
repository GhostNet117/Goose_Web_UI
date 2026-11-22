"""Spec 035 (1.26.0): host tools - servers the gateway runs for sandboxed members, lent tool by tool.

A fake stdio MCP server stands in for the administrator's server. It offers a tool that must never be lent
(`read_file`: a path on the host) next to the lent ones, asks the client for sampling, and records cancellations.
"""
import asyncio
import base64
import json
import os
import sys

import pytest
import yaml

from goose_web import hosttools as ht
from goose_web import policy as pol
from goose_web.config import load_settings
from goose_web.db import Database
from goose_web.egress import EgressProxy
from goose_web.profiles import Profiles

FAKE_SERVER = r'''
import json, os, sys, threading, time
out_lock = threading.Lock()
cancelled, pending, deaf = [], {}, [False]
def send(m):
    with out_lock:
        sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
sys.stdout.write("starting up (not JSON)\n"); sys.stdout.flush()
TOOLS = [
  {"name": "echo", "description": "Echo", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
  {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}}}},
  {"name": "slow", "inputSchema": {"type": "object", "properties": {"seconds": {"type": "number"}, "tag": {"type": "string"}}}},
  {"name": "whoami", "inputSchema": {"type": "object", "properties": {}}},
  {"name": "ask", "inputSchema": {"type": "object", "properties": {}}},
  {"name": "cancelled", "inputSchema": {"type": "object", "properties": {}}},
  {"name": "deaf", "inputSchema": {"type": "object", "properties": {}}},
]
def text(s): return {"content": [{"type": "text", "text": s}]}
def handle(m):
    mid, method, p = m.get("id"), m.get("method"), m.get("params") or {}
    if method == "initialize":
        if os.environ.get("SLOW_INIT"):
            time.sleep(1.5)
        send({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": p.get("protocolVersion"),
              "capabilities": {"tools": {"listChanged": True}, "resources": {}, "prompts": {}},
              "serverInfo": {"name": "fake", "version": "1"}, "instructions": "be nice " + json.dumps(p.get("capabilities"))}})
        send({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hello"}})
    elif method == "tools/list":
        if p.get("cursor") == "p2":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS[3:]}})
        else:
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS[:3], "nextCursor": "p2"}})
    elif method == "tools/call":
        name, a = p.get("name"), p.get("arguments") or {}
        if name == "echo":
            r = text(json.dumps({"text": a.get("text"), "meta": sorted((p.get("_meta") or {}).keys())}))
        elif name == "read_file":
            r = text("SHOULD NEVER RUN")
        elif name == "slow":
            time.sleep(float(a.get("seconds") or 0)); r = text(str(a.get("tag")))
        elif name == "whoami":
            r = text(json.dumps({"cwd": os.getcwd(), "fake": os.environ.get("FAKE_ENV"),
                                 "secret": os.environ.get("HT_TEST_API_KEY"), "goose": os.environ.get("GOOSE_HT_TEST")}))
        elif name == "ask":
            ev = threading.Event(); pending["s1"] = [ev, None]
            send({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": {}})
            ev.wait(10); r = text(json.dumps(pending["s1"][1]))
        elif name == "cancelled":
            r = text(json.dumps(cancelled))
        elif name == "deaf":                       # from now on the server reads nothing more
            deaf[0] = True; r = text("deaf")
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown"}}); return
        send({"jsonrpc": "2.0", "id": mid, "result": r})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "notifications/cancelled":
        cancelled.append(p.get("requestId"))
    elif mid is not None and method is None:
        if mid in pending:
            pending[mid][1] = m; pending[mid][0].set()
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "nope"}})
for line in sys.stdin:
    if deaf[0]:
        time.sleep(60)
    try: m = json.loads(line)
    except ValueError: continue
    threading.Thread(target=handle, args=(m,), daemon=True).start()
'''
LENT = ["echo", "slow", "whoami", "ask", "cancelled", "deaf"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    from tests.test_team_profiles import ANYCHAT, team, user
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    # the test's server runs on this repository's venv, which a developer's C:\ often lets every account change; on
    # GitHub's Windows runner the checkout's drive (D:\) belongs to NT AUTHORITY\NETWORK SERVICE: switch off all four
    # program-folder checks here (as _no_findings does), the checks themselves have tests of their own
    monkeypatch.setattr(ht, "writable_by_others", lambda p: [])
    monkeypatch.setattr(ht, "ancestor_writers", lambda p: [])
    monkeypatch.setattr(ht, "subfolder_creators", lambda p: [])
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "")
    monkeypatch.setenv("HT_TEST_API_KEY", "must-not-reach-the-server")
    monkeypatch.setenv("GOOSE_HT_TEST", "must-not-reach-the-server")
    s = load_settings()
    srv = tmp_path / "fake_mcp.py"
    srv.write_text(FAKE_SERVER, encoding="utf-8")
    s.data["host_tools"]["servers"] = {"fake": {"command": [sys.executable, "-u", str(srv)], "tools": LENT,
                                                "env": {"FAKE_ENV": "{service_dir}"}, "timeout": 20}}
    db = Database(tmp_path / "gw.db")
    pr = Profiles(s, db)
    tid = team(db, "A", ANYCHAT)
    alice = user(db, "alice")
    db.set_user_team(alice["id"], tid)
    tid2 = team(db, "B", ANYCHAT)
    bob = user(db, "bob")
    db.set_user_team(bob["id"], tid2)
    item = db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
                      (tid, "hosttool", "fake", json.dumps({"server": "fake"}), "manual"))
    audit = []
    h = ht.HostTools(s, db, pr, [], audit=lambda m, t, d: audit.append((m, t, d)))
    yield {"s": s, "db": db, "pr": pr, "h": h, "audit": audit, "tid": tid, "item": item, "alice": alice,
           "bob": bob, "tmp": tmp_path}
    for k in list(h.procs):
        h._stop(k, "test end")
    db.close()


async def rpc(h, method, params=None, sid="", rid=1, member="alice"):
    st, res, hdr = await h.message(member, "fake", {"jsonrpc": "2.0", "id": rid, "method": method,
                                                    "params": params or {}}, sid)
    # a tool's answer comes encoded (HT-2: done in the reader thread, not on the event loop)
    return st, json.loads(res) if isinstance(res, bytes) else res, hdr


async def session(h, member="alice"):
    st, res, hdr = await rpc(h, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {"roots": {}},
                                               "clientInfo": {"name": "goose", "version": "1.57.0"}}, member=member)
    assert st == 200 and "result" in res, res
    return hdr["Mcp-Session-Id"], res["result"]


def text_of(res):
    return res["result"]["content"][0]["text"]


# ------------------------------------------------------------------ definitions
def test_definitions_and_their_problems(tmp_path, monkeypatch):
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Users"] if "shared" in p else [])
    monkeypatch.setattr(ht, "ancestor_writers", lambda p: [])
    monkeypatch.setattr(ht, "subfolder_creators", lambda p: [])     # not what this test is about (CI runner's D:\)
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "")
    prog = tmp_path / "prog.exe"
    prog.write_bytes(b"")
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "s.py").write_text("x", encoding="utf-8")

    class S:
        def __init__(self, servers):
            self.d = {"servers": servers}

        def get(self, sec, key, default=None):
            return self.d.get(key, default) if sec == "host_tools" else default
    admin = {"wiki": {"type": "stdio", "cmd": str(prog), "args": ["-I", "x"], "envs": {"A": "1"}, "timeout": 120,
                      "description": "The wiki"},
             "web": {"type": "streamable_http", "uri": "https://x"}}
    good = ht.load_servers(S({"wiki": {"from_extension": "wiki", "tools": ["wiki_search", "wiki_page"],
                                       "env": {"B": "{service_dir}"}}}), admin)["wiki"]
    assert good.problems == [] and good.command == [str(prog), "-I", "x"] and good.env == {"A": "1", "B": "{service_dir}"}
    assert good.timeout == 120 and good.description == "The wiki" and good.source == "from_extension: wiki"
    bad = ht.load_servers(S({
        "Bad_Name": {"command": [str(prog)], "tools": ["a"]},
        "developer": {"command": [str(prog)], "tools": ["a"]},                       # a key profiles.py manages
        "notools": {"command": [str(prog)], "tools": []},
        "both": {"command": [str(prog)], "from_extension": "wiki", "tools": ["a"]},
        "noext": {"from_extension": "missing", "tools": ["a"]},
        "http": {"from_extension": "web", "tools": ["a"]},
        "relative": {"command": ["python.exe", "x.py"], "tools": ["a"]},
        "gone": {"command": [str(tmp_path / "nothere.exe")], "tools": ["a"]},
        "writable": {"command": [str(prog), str(shared / "s.py")], "tools": ["a"]},
        "badenv": {"command": [str(prog)], "tools": ["a"], "env": {"1X": "y"}},
        "nothing": {"tools": ["a"]},
    }), admin)
    for name, d in bad.items():
        assert d.problems, name
    assert "Users" in bad["writable"].problems[0] and "administrators" in bad["writable"].problems[0]
    assert ht.member_entry(good) == {
        "type": "streamable_http", "name": "wiki", "description": "The wiki", "uri": "http://wiki.goose-web.invalid/mcp",
        "timeout": 120, "enabled": True, "bundled": False, "envs": {}, "env_keys": [], "headers": {},
        "available_tools": ["wiki_page", "wiki_search"]}


def test_host_names():
    assert ht.host_name("wiki.goose-web.invalid") == "wiki"
    assert ht.host_name("WIKI.Goose-Web.Invalid.") == "wiki"
    assert ht.host_name("a.b.goose-web.invalid") == ""            # not a valid name: refused, never looked up
    assert ht.host_name("goose-web.invalid") is None and ht.host_name("wiki.example.com") is None
    assert ht.risky_params({"inputSchema": {"properties": {"file_path": {}, "text": {}, "url": {}}}}) == ["file_path", "url"]


# ------------------------------------------------------------------ the protocol a member gets
async def test_member_gets_only_the_lent_tools(env):
    h = env["h"]
    h.start()
    st, res, _ = await rpc(h, "server/discover")
    assert res["error"]["code"] == ht.METHOD_NOT_FOUND                      # Goose then uses initialize
    sid, init = await session(h)
    assert init["capabilities"] == {"tools": {}}                              # no resources, prompts, list_changed
    assert init["serverInfo"]["name"] == "fake" and init["protocolVersion"] == ht.CLIENT_PROTOCOL
    assert '"{}"' not in init["instructions"] and init["instructions"].startswith("be nice {}")  # no client caps
    st, res, _ = await rpc(h, "tools/list", sid=sid, rid=2)
    assert sorted(t["name"] for t in res["result"]["tools"]) == sorted(LENT)  # read_file (page 1) is not lent
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {"text": "hi"},
                                             "_meta": {"progressToken": 7, "agent-session-id": "s"}}, sid=sid, rid=3)
    assert json.loads(text_of(res)) == {"text": "hi", "meta": []}   # nothing of the member's _meta (HT-5)
    st, res, _ = await rpc(h, "tools/call", {"name": "read_file", "arguments": {"file_path": "C:\\secret"}}, sid=sid, rid=4)
    assert res["error"]["code"] == ht.INVALID_PARAMS and "not lent" in res["error"]["message"]
    for m in ("resources/list", "resources/read", "prompts/list", "prompts/get", "completion/complete",
              "logging/setLevel", "tasks/list"):
        st, res, _ = await rpc(h, m, {"uri": "file:///C:/x"}, sid=sid, rid=5)
        assert res["error"]["code"] == ht.METHOD_NOT_FOUND, m
    st, res, _ = await rpc(h, "ping", sid=sid, rid=6)
    assert res["result"] == {}
    # the server asks the member for sampling: it gets an error from the gateway, never reaches the member
    st, res, _ = await rpc(h, "tools/call", {"name": "ask", "arguments": {}}, sid=sid, rid=7)
    assert json.loads(text_of(res))["error"]["code"] == ht.METHOD_NOT_FOUND
    # environment and folder of the server
    st, res, _ = await rpc(h, "tools/call", {"name": "whoami", "arguments": {}}, sid=sid, rid=8)
    who = json.loads(text_of(res))
    sdir = env["s"].system_dir / "host-tools" / "fake" / "alice"
    assert os.path.normcase(who["cwd"]) == os.path.normcase(str(sdir)) and who["fake"] == str(sdir)
    assert who["secret"] is None and who["goose"] is None
    # a session id of nobody, or of another member
    st, res, _ = await rpc(h, "tools/list", sid="nope", rid=9)
    assert st == 404
    assert not any("file_path" in json.dumps(d) or "C:\\secret" in json.dumps(d) for _, _, d in env["audit"])
    assert any(t == "fake:read_file" and d["decision"] == "refused" for _, t, d in env["audit"])
    assert any(t == "fake:echo" and d["decision"] == "allowed" and "ms" in d for _, t, d in env["audit"])
    await h.close()


async def test_ids_are_remapped_and_cancellations_reach_the_server(env):
    h = env["h"]
    h.start()
    a, _ = await session(h)
    b, _ = await session(h)
    # two sessions of one member use the same request id at the same time
    r1, r2 = await asyncio.gather(
        rpc(h, "tools/call", {"name": "slow", "arguments": {"seconds": 0.6, "tag": "A"}}, sid=a, rid=5),
        rpc(h, "tools/call", {"name": "slow", "arguments": {"seconds": 0.1, "tag": "B"}}, sid=b, rid=5))
    assert text_of(r1[1]) == "A" and text_of(r2[1]) == "B" and r1[1]["id"] == r2[1]["id"] == 5
    call = asyncio.ensure_future(rpc(h, "tools/call", {"name": "slow", "arguments": {"seconds": 1.5, "tag": "C"}},
                                     sid=a, rid="c-1"))
    await asyncio.sleep(0.3)
    st, res, _ = await h.message("alice", "fake", {"jsonrpc": "2.0", "method": "notifications/cancelled",
                                                   "params": {"requestId": "c-1"}}, a)
    assert st == 202 and res is None
    await call
    st, res, _ = await rpc(h, "tools/call", {"name": "cancelled", "arguments": {}}, sid=a, rid=9)
    got = json.loads(text_of(res))
    assert got and all(str(x).startswith("gw-") for x in got)     # the server's own id, not the member's
    await h.close()


async def test_who_may_use_it_is_checked_at_every_request(env):
    h, db = env["h"], env["db"]
    h.start()
    st, res, _ = await rpc(h, "initialize", {}, member="bob")                      # another team
    assert res["error"]["code"] == ht.REFUSED and "does not have" in res["error"]["message"]
    admin = db.create_user(username="root", role="admin")
    st, res, _ = await rpc(h, "initialize", {}, member="root")
    assert res["error"]["code"] == ht.REFUSED and db.user_by_id(admin)
    sid, _ = await session(h)
    db.execute("DELETE FROM team_items WHERE id=?", (env["item"],))               # taken from the team
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {"text": "x"}}, sid=sid, rid=2)
    assert res["error"]["code"] == ht.REFUSED and "does not have" in res["error"]["message"]
    await h.sweep()                                                                # its process is stopped
    assert not h.procs
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
               (env["tid"], "hosttool", "fake", "{}", "manual"))
    db.update_user(env["alice"]["id"], disabled=1)
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {"text": "x"}}, sid=sid, rid=3)
    assert res["error"]["code"] == ht.REFUSED and "disabled" in res["error"]["message"]
    # bob may not use alice's session
    db.update_user(env["alice"]["id"], disabled=0)
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES("
               "(SELECT team_id FROM team_members WHERE user_id=?),?,?,?,?,0)", (env["bob"]["id"], "hosttool", "fake",
                                                                                "{}", "manual"))
    st, res, _ = await rpc(h, "tools/list", sid=sid, rid=4, member="bob")
    assert st == 404
    await h.close()


async def test_limits_idle_stop_and_member_stop(env):
    h = env["h"]
    h.servers["fake"].max_calls_per_minute = 2          # a refused call (busy) does not count
    h.servers["fake"].max_concurrent = 1
    h.start()
    sid, _ = await session(h)
    slow = asyncio.ensure_future(rpc(h, "tools/call", {"name": "slow", "arguments": {"seconds": 0.5}}, sid=sid, rid=1))
    await asyncio.sleep(0.15)
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {}}, sid=sid, rid=2)
    assert "already running" in res["error"]["message"]
    await slow
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {}}, sid=sid, rid=3)
    assert "result" in res
    st, res, _ = await rpc(h, "tools/call", {"name": "echo", "arguments": {}}, sid=sid, rid=4)
    assert "too many calls" in res["error"]["message"]
    hp = h.procs[("fake", "alice")]
    proc = hp.proc
    hp.last_used -= 3600
    await h.sweep()
    assert not h.procs and proc.wait(10) is not None                               # unused: stopped
    sid, _ = await session(h)
    assert h.procs
    h.member_stopped("alice")
    await asyncio.sleep(0)
    assert not h.procs and not [s for s in h.sessions.values() if s.member == "alice"]
    await h.close()


async def test_a_server_that_does_not_start(env):
    h = env["h"]
    h.servers["fake"].command = [sys.executable, "-c", "import sys; sys.exit(3)"]
    h.start()
    for _ in range(3):
        st, res, _ = await rpc(h, "initialize", {})
        assert res["error"]["code"] == ht.REFUSED and "did not start" in res["error"]["message"]
    st, res, _ = await rpc(h, "initialize", {})
    assert "three times" in res["error"]["message"]
    await h.close()


# ------------------------------------------------------------------ through a member's egress proxy
async def _http(port, user, token, request_line, body=b"", extra=""):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    w.write((f"{request_line}\r\nHost: fake.goose-web.invalid\r\nProxy-Authorization: Basic {auth}\r\n{extra}"
             f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
    await w.drain()
    data = await asyncio.wait_for(r.read(), 30)
    w.close()
    head, _, payload = data.partition(b"\r\n\r\n")
    return head.decode("latin-1"), payload


async def test_through_the_members_egress_proxy(env):
    h = env["h"]
    h.start()
    p = await EgressProxy("alice", network="none", audit=lambda *a: None).start()
    p.broker = h
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
        head, payload = await _http(p.port, p.user, p.token, "POST http://fake.goose-web.invalid/mcp HTTP/1.1", body)
        assert head.startswith("HTTP/1.1 200") and "Mcp-Session-Id:" in head
        assert json.loads(payload)["result"]["capabilities"] == {"tools": {}}
        sid = [ln.split(":", 1)[1].strip() for ln in head.split("\r\n") if ln.lower().startswith("mcp-session-id")][0]
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "echo", "arguments": {"text": "via proxy"}}}).encode()
        head, payload = await _http(p.port, p.user, p.token, "POST http://fake.goose-web.invalid/mcp HTTP/1.1", body,
                                    f"Mcp-Session-Id: {sid}\r\n")
        assert json.loads(text_of(json.loads(payload)))["text"] == "via proxy"
        head, _ = await _http(p.port, p.user, p.token, "GET http://fake.goose-web.invalid/mcp HTTP/1.1")
        assert head.startswith("HTTP/1.1 405")
        head, _ = await _http(p.port, p.user, p.token, "CONNECT fake.goose-web.invalid:443 HTTP/1.1")
        assert head.startswith("HTTP/1.1 403")
        head, _ = await _http(p.port, p.user, "wrong", "POST http://fake.goose-web.invalid/mcp HTTP/1.1", body)
        assert head.startswith("HTTP/1.1 407")                                    # only the member's own proxy
        p.revoke()
        head, _ = await _http(p.port, p.user, p.token, "POST http://fake.goose-web.invalid/mcp HTTP/1.1", body)
        assert head.startswith("HTTP/1.1 407")
        q = await EgressProxy("alice", network="none", audit=lambda *a: None).start()   # a gateway without host tools
        head, _ = await _http(q.port, q.user, q.token, "POST http://fake.goose-web.invalid/mcp HTTP/1.1", body)
        assert head.startswith("HTTP/1.1 502")                    # never 401/403: Goose would try OAuth
        head, _ = await _http(q.port, q.user, q.token, "POST http://a.b.goose-web.invalid/mcp HTTP/1.1", body)
        assert head.startswith("HTTP/1.1 400")
        await q.close()
    finally:
        await p.close()
        await h.close()


# ------------------------------------------------------------------ delivery into the member's profile
def test_provisioning_delivers_an_http_extension_only_on_mxc(env):
    s, pr, alice = env["s"], env["pr"], env["db"].user_by_id(env["alice"]["id"])
    pr.host_tools = env["h"]
    s.data["sandbox"]["enabled"] = True
    s.data["sandbox"]["backend"] = "mxc"
    pr.provision(alice)
    cfg = yaml.safe_load((pr.config_dir(alice) / "config.yaml").read_text(encoding="utf-8"))
    e = cfg["extensions"]["fake"]
    assert e == ht.member_entry(env["h"].servers["fake"])
    assert "cmd" not in e and not e["envs"] and not e["env_keys"]
    secrets = pr.config_dir(alice) / "secrets.yaml"
    assert not secrets.exists() or "fake" not in secrets.read_text(encoding="utf-8")
    s.data["sandbox"]["backend"] = "appcontainer"                         # no egress proxy: not delivered
    pr.provision(alice)
    assert "fake" not in yaml.safe_load((pr.config_dir(alice) / "config.yaml").read_text(encoding="utf-8"))["extensions"]
    s.data["sandbox"]["backend"] = "mxc"
    pr.provision(alice)
    env["h"].servers["fake"].problems.append("broken")                   # a definition that cannot run
    pr.provision(alice)
    assert "fake" not in yaml.safe_load((pr.config_dir(alice) / "config.yaml").read_text(encoding="utf-8"))["extensions"]


def test_team_page_warnings():
    def texts(**kw):
        return [w["text"] for w in pol.team_warnings(dict(pol.DEFAULT_POLICY), hints=1, members=1, **kw)]
    assert any("host tool 'w': it is not defined" in t for t in texts(host_tool_items={"w": "it is not defined"},
                                                                     host_tools_reach=True))
    assert any("only in the MXC sandbox" in t for t in texts(host_tool_items={"w": ""}, host_tools_reach=False))
    assert not any("host tool" in t for t in texts(host_tool_items={"w": ""}, host_tools_reach=True))


def test_api_gives_only_defined_host_tools(env):
    from tests.test_team_profiles import client_for, sign_in, user
    from goose_web.auth import AuthService
    from goose_web.context import Ctx

    class _Workers:
        def get(self, key):
            return None
    s, db, pr = env["s"], env["db"], env["pr"]
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=pr, workers=_Workers(), hub=None, version="t")
    c.host_tools = env["h"]
    admin = user(db, "boss", role="admin")
    tc = client_for(c)
    hdr = sign_in(tc, c, admin)
    tid = env["tid"]
    r = tc.post(f"/api/admin/teams/{tid}/items", json={"kind": "hosttool", "name": "nothere"}, headers=hdr)
    assert r.status_code == 400 and "no host tool" in r.json()["message"]
    env["h"].servers["fake"].problems.append("its folder can be changed by Users")
    r = tc.post(f"/api/admin/teams/{tid}/items", json={"kind": "hosttool", "name": "fake"}, headers=hdr)
    assert r.status_code == 400 and "Users" in r.json()["message"]
    env["h"].servers["fake"].problems.clear()
    r = tc.post(f"/api/admin/teams/{tid}/items", json={"kind": "hosttool", "name": "fake"}, headers=hdr)
    assert r.status_code == 200
    row = db.one("SELECT * FROM team_items WHERE team_id=? AND kind='hosttool'", (tid,))
    assert row["source"] == "manual" and json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
    r = tc.get("/api/admin/host-tools", headers=hdr)
    d = r.json()["items"][0] if isinstance(r.json(), dict) else r.json()[0]
    assert d["name"] == "fake" and d["tools"] == LENT and d["uri"] == "http://fake.goose-web.invalid/mcp"
    member = user(db, "carol")
    tc2 = client_for(c)
    hdr2 = sign_in(tc2, c, member)
    assert tc2.get("/api/admin/host-tools", headers=hdr2).status_code == 403


# ------------------------------------------------------------------ review 2026-11-20 (before release)
async def test_a_server_that_stops_reading_never_blocks_the_gateway(env, monkeypatch):
    """HT-1: writes to a server's stdin happen in its own thread; a stop kills first and never waits on the pipe;
    a server that takes no message for WRITE_DEADLINE is stopped by the sweep."""
    monkeypatch.setattr(ht, "WRITE_DEADLINE", 0.5)
    h = env["h"]
    h.servers["fake"].max_concurrent = 8
    h.start()
    sid, _ = await session(h)
    st, res, _ = await rpc(h, "tools/call", {"name": "deaf", "arguments": {}}, sid=sid, rid=1)
    assert text_of(res) == "deaf"
    big = "x" * (600 * 1024)
    calls = [asyncio.ensure_future(rpc(h, "tools/call", {"name": "echo", "arguments": {"text": big}}, sid=sid,
                                       rid=10 + i)) for i in range(3)]
    await asyncio.sleep(0.8)                       # the writer thread is stuck on the full pipe by now
    t0 = asyncio.get_running_loop().time()
    await asyncio.sleep(0.01)
    assert asyncio.get_running_loop().time() - t0 < 0.2          # the event loop is free
    hp = h.procs[("fake", "alice")]
    assert hp.writing_since > 0
    proc = hp.proc
    await h.sweep()                                # stuck longer than WRITE_DEADLINE: stopped
    assert ("fake", "alice") not in h.procs
    assert proc.wait(10) is not None
    for c in calls:
        st, res, _ = await asyncio.wait_for(c, 10)
        assert res["error"]["code"] == ht.REFUSED
    # a second server, stopped directly while its writer is stuck: the stop itself returns at once
    sid, _ = await session(h)
    await rpc(h, "tools/call", {"name": "deaf", "arguments": {}}, sid=sid, rid=1)
    calls = [asyncio.ensure_future(rpc(h, "tools/call", {"name": "echo", "arguments": {"text": big}}, sid=sid,
                                       rid=20 + i)) for i in range(3)]
    await asyncio.sleep(0.8)
    import time as _t
    t0 = _t.monotonic()
    h._stop(("fake", "alice"), "test")
    assert _t.monotonic() - t0 < 1.0
    await asyncio.gather(*calls)
    await h.close()


def test_program_folder_checks_reach_ancestors_arguments_and_path_variables(tmp_path, monkeypatch):
    """HT-6: R5 also looks above the program, at `--x=<path>` arguments and at path variables."""
    prog = tmp_path / "bin" / "prog.exe"
    prog.parent.mkdir()
    prog.write_bytes(b"")
    lib = tmp_path / "lib"
    lib.mkdir()
    monkeypatch.setattr(ht, "writable_by_others", lambda p: [])
    monkeypatch.setattr(ht, "ancestor_writers", lambda p: [])
    monkeypatch.setattr(ht, "subfolder_creators", lambda p: [])     # not what this test is about (CI runner's D:\)
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "")
    assert ht.program_problems([str(prog)]) == []
    monkeypatch.setattr(ht, "ancestor_writers", lambda p: ["Users"] if os.path.normcase(p) ==
                        os.path.normcase(str(tmp_path)) else [])
    probs = ht.program_problems([str(prog)])
    assert probs and "rename or re-permission" in probs[0]
    monkeypatch.setattr(ht, "ancestor_writers", lambda p: [])
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Everyone"] if "lib" in p else [])
    assert ht.program_problems([str(prog), f"--root={lib}"])
    assert ht.program_problems([str(prog)], {"PYTHONPATH": str(lib)})
    assert ht.program_problems([str(prog)], {"OUT": "{service_dir}\\x"}) == []
    assert "does not exist" in ht.program_problems([str(tmp_path / "nothere.exe")])[0]


async def test_the_folder_check_is_repeated_at_every_start(env, monkeypatch):
    h = env["h"]
    h.start()
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Users"])
    st, res, _ = await rpc(h, "initialize", {})
    assert res["error"]["code"] == ht.REFUSED and "can be changed by Users" in res["error"]["message"]
    assert not h.procs
    await h.close()


async def test_a_start_under_way_when_the_agent_stops_is_not_kept(env):
    """HT-10"""
    h = env["h"]
    h.servers["fake"].env["SLOW_INIT"] = "1"
    h.start()
    t = asyncio.ensure_future(rpc(h, "initialize", {}))
    await asyncio.sleep(0.4)
    h.member_stopped("alice")
    st, res, _ = await t
    assert res["error"]["code"] == ht.REFUSED and "agent stopped" in res["error"]["message"]
    assert not h.procs
    await h.close()


async def test_requests_are_limited_and_refusals_summarised(env, monkeypatch):
    """HT-3: every request counts toward a per-member limit; refusals are written one by one only up to the
    activity log's per-minute budget, then summarised."""
    import goose_web.egress as eg
    monkeypatch.setattr(eg, "AUDIT_VERBATIM_PER_MINUTE", 3)
    monkeypatch.setattr(ht, "REQUESTS_PER_MINUTE", 12)
    h, audit = env["h"], env["audit"]
    h.start()
    sid, _ = await session(h)                                      # request 1
    for i in range(8):                                             # requests 2-9: refused, not lent
        await rpc(h, "tools/call", {"name": "read_file", "arguments": {}}, sid=sid, rid=i)
    verbatim = [a for a in audit if a[1] == "fake:read_file"]
    assert len(verbatim) <= 3
    for i in range(5):                                             # requests 10-14: over the limit from 13 on
        st, res, _ = await rpc(h, "ping", sid=sid, rid=100 + i)
    assert "too many requests" in res["error"]["message"]
    h._limiter("alice").flush()
    assert any(t == "(summary)" and d["decision"] == "summary" and d["count"] >= 5 for _, t, d in audit)
    await h.close()


async def test_a_cancellation_needs_the_member_and_host_tool_of_the_session(env):
    """HT-8"""
    h = env["h"]
    h.start()
    sid, _ = await session(h)
    call = asyncio.ensure_future(rpc(h, "tools/call", {"name": "slow", "arguments": {"seconds": 0.8}}, sid=sid,
                                     rid="k"))
    await asyncio.sleep(0.2)
    await h.message("alice", "other", {"jsonrpc": "2.0", "method": "notifications/cancelled",
                                       "params": {"requestId": "k"}}, sid)      # another host tool's name
    await call
    st, res, _ = await rpc(h, "tools/call", {"name": "cancelled", "arguments": {}}, sid=sid, rid=9)
    assert json.loads(text_of(res)) == []
    await h.close()


# ------------------------------------------------------------------ second review 2026-11-20 (before release)
def _no_findings(monkeypatch):
    for f in ("writable_by_others", "ancestor_writers", "subfolder_creators"):
        monkeypatch.setattr(ht, f, lambda p: [])
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "")


def test_node_and_python_look_for_code_above_the_program(tmp_path, monkeypatch):
    """R2-1: Node looks for a module it does not find in every node_modules up to the root; Python reads
    pyvenv.cfg in its folder and the one above it."""
    _no_findings(monkeypatch)
    node = tmp_path / "rt" / "node.exe"
    node.parent.mkdir()
    node.write_bytes(b"")
    script = tmp_path / "app" / "dist" / "index.js"
    script.parent.mkdir(parents=True)
    script.write_text("x", encoding="utf-8")
    # a stand-in for the root of the drive, where every account may create a sub-folder by default
    top = str(tmp_path)
    monkeypatch.setattr(ht, "_above", lambda p: [top])
    monkeypatch.setattr(ht, "subfolder_creators", lambda p: ["Authenticated Users"] if p == top else [])
    probs = ht.program_problems([str(node), str(script)])
    assert probs and os.path.join(top, "node_modules") in probs[0] and "create" in probs[0]
    (tmp_path / "node_modules").mkdir()                           # created first, administrators only: fine
    assert ht.program_problems([str(node), str(script)]) == []
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Users"] if p.endswith("node_modules") else [])
    assert "node_modules" in ht.program_problems([str(node), str(script)])[0]
    monkeypatch.setattr(ht, "writable_by_others", lambda p: [])
    (tmp_path / "node_modules").rmdir()
    other = tmp_path / "rt" / "other.exe"
    other.write_bytes(b"")
    assert ht.program_problems([str(other)]) == []                # not a Node program: the root does not matter
    py = tmp_path / "py" / "Scripts" / "python.exe"
    py.parent.mkdir(parents=True)
    py.write_bytes(b"")
    above = str(tmp_path / "py")
    monkeypatch.setattr(ht, "subfolder_creators", lambda p: [])
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Users"] if p == above else [])
    probs = ht.program_problems([str(py)])
    assert probs and above in probs[0]


def test_owners_and_unreadable_permissions_refuse(tmp_path, monkeypatch):
    """R2-3: a folder owned by another account, or permissions that cannot be read, keep a server from starting."""
    _no_findings(monkeypatch)
    prog = tmp_path / "bin" / "prog.exe"
    prog.parent.mkdir()
    prog.write_bytes(b"")
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "OTHER\\someone" if p == str(prog.parent) else "")
    probs = ht.program_problems([str(prog)])
    assert probs and "belongs to OTHER\\someone" in probs[0]

    def unreadable(p):
        raise OSError(5, "access denied")
    monkeypatch.setattr(ht, "foreign_owner", lambda p: "")
    monkeypatch.setattr(ht, "writable_by_others", unreadable)
    probs = ht.program_problems([str(prog)])
    assert probs and "cannot be read" in probs[0]


def test_the_servers_path_and_environment(tmp_path, monkeypatch):
    """R2-2: PATH keeps only folders other accounts cannot change or replace; interpreter-steering variables of the
    gateway are not passed on."""
    _no_findings(monkeypatch)
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.mkdir()
    bad.mkdir()
    monkeypatch.setattr(ht, "writable_by_others", lambda p: ["Users"] if p == str(bad) else [])
    value = os.pathsep.join([str(good), str(bad), "relative\\dir", str(tmp_path / "missing"), str(good)])
    assert ht.safe_path_entries(value) == [str(good)]
    monkeypatch.setenv("PATH", value)
    monkeypatch.setenv("NODE_OPTIONS", "--require C:\\evil.js")
    monkeypatch.setenv("PYTHONPATH", str(bad))
    sd = ht.ServerDef(name="x", command=[str(tmp_path / "p.exe")], env={"KEEP": "1"})
    env = ht.HostProcess(sd, "alice", tmp_path / "svc", tmp_path / "logs", []).env()
    path_key = [k for k in env if k.upper() == "PATH"][0]
    assert env[path_key] == str(good)
    assert "NODE_OPTIONS" not in env and "PYTHONPATH" not in env and env["KEEP"] == "1"
    assert env["NoDefaultCurrentDirectoryInExePath"] == "1" and env["TEMP"].startswith(str(tmp_path / "svc"))


async def test_unknown_names_cost_nothing_and_stops_are_idempotent(env):
    """R2-9, R2-4, R2-7"""
    h = env["h"]
    h.start()
    for i in range(50):
        st, res, _ = await h.message("alice", f"nope{i}", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, "")
        assert res["error"]["code"] == ht.REFUSED
    assert not any(k[0].startswith("nope") for k in h.requests)
    sid, _ = await session(h)
    hp = h.procs[("fake", "alice")]
    hp.stop()
    hp.stop()                                                     # a second stop does nothing
    assert hp.dead
    h.servers["fake"].env["SLOW_INIT"] = "1"
    h._stop(("fake", "alice"), "test")
    t = asyncio.ensure_future(rpc(h, "initialize", {}))
    await asyncio.sleep(0.4)
    t.cancel()                                                    # the request's task is cancelled mid-start
    with pytest.raises(asyncio.CancelledError):
        await t
    await asyncio.sleep(0.2)
    assert ("fake", "alice") not in h.procs
    await h.close()


def test_a_new_member_worker_gets_no_scheduler_unless_told(tmp_path, monkeypatch):
    """R2-15"""
    import goose_web.workers as wk
    s = load_settings()
    wm = wk.WorkerManager(s)
    assert wm.register("bob", "bob", str(tmp_path), False, []).scheduler_allowed is False
    assert wm.register("nat", "nat", None, True, []).scheduler_allowed is True

