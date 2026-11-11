"""Hub tests against a fake ACP agent (no goose needed)."""
import asyncio
import json

import pytest
import websockets

from goose_web import policy as pol
from goose_web.hub import Client, Hub
from goose_web.workers import Worker

MEMBER = {**pol.LEGACY_DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}


class FakeAgent:
    def __init__(self):
        self.answers = asyncio.Queue()
        self.sessions = 0
        self.loads = 0
        self.counts = {}   # sessionId -> messageCount reported by session/info
        self.ext_results = None   # _meta.extensionResults returned by session/load
        self.fail_add = None      # error message for _goose/unstable/session/extensions/add

    async def handler(self, ws):
        async for raw in ws:
            m = json.loads(raw)
            if "method" not in m:
                await self.answers.put(m)
                continue
            meth, mid, p = m["method"], m.get("id"), m.get("params") or {}
            if meth == "initialize":
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1}}))
            elif meth == "session/new":
                self.sessions += 1
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {
                    "sessionId": f"s{self.sessions}", "modes": {"currentModeId": "approve"}, "_meta": {"echo": p["_meta"]}}}))
            elif meth == "session/load":
                self.loads += 1
                await ws.send(json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": p["sessionId"], "update": {"sessionUpdate": "agent_message_chunk",
                                                            "content": {"type": "text", "text": "old"}}}}))
                res = {"_meta": {"extensionResults": self.ext_results}} if self.ext_results is not None else {}
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}))
            elif meth == "_goose/unstable/session/extensions/add" and self.fail_add:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": self.fail_add}}))
            elif meth == "session/prompt":
                asyncio.create_task(self.run(ws, mid, p["sessionId"]))
            elif meth == "_goose/unstable/session/info":
                n = self.counts.get(p["sessionId"], 1)
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"session": {
                    "sessionId": p["sessionId"], "cwd": "/", "updatedAt": f"t{n}", "title": "T",
                    "_meta": {"messageCount": n}}}}))
            elif mid is not None:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {}}))

    async def run(self, ws, mid, sid):
        def upd(u):
            return json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": u}})
        await ws.send(upd({"sessionUpdate": "session_info_update", "_meta": {"goose": {"activeRunId": "r1"}}}))
        await ws.send(upd({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Hello "}}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": "perm-1", "method": "session/request_permission", "params": {
            "sessionId": sid, "toolCall": {"toolCallId": "t1", "title": "shell · rm"},
            "options": [{"optionId": "allow_once", "name": "Allow", "kind": "allow_once"}]}}))
        ans = await self.answers.get()
        assert ans["id"] == "perm-1"
        await ws.send(upd({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "done"}}))
        await ws.send(upd({"sessionUpdate": "session_info_update", "_meta": {"goose": {"activeRunId": None}}}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": "end_turn"}}))


class FakeWorkers:
    def __init__(self, port):
        self.workers = {"alice": Worker(key="alice", username="alice", path_root=None, native=False, port=port,
                                        secret="x", state="ready")}
        self.activity = None
        self.on_restart = None

    async def ensure(self, key):
        return self.workers[key]


class Sink:
    def __init__(self):
        self.msgs = []
        self.event = asyncio.Event()

    async def send(self, raw):
        self.msgs.append(json.loads(raw))
        self.event.set()

    async def wait_for(self, pred, timeout=5):
        end = asyncio.get_running_loop().time() + timeout
        while True:
            for m in self.msgs:
                if pred(m):
                    return m
            self.event.clear()
            left = end - asyncio.get_running_loop().time()
            if left <= 0:
                raise AssertionError(f"timeout; got {self.msgs}")
            try:
                await asyncio.wait_for(self.event.wait(), left)
            except asyncio.TimeoutError:
                pass


@pytest.fixture
async def env():
    agent = FakeAgent()
    server = await websockets.serve(agent.handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    hub = Hub(FakeWorkers(port))
    hub.start()
    yield agent, hub
    server.close()
    await server.wait_closed()


def mk_client(user="alice", role="user"):
    sink = Sink()
    c = Client(sink.send, {"id": 1, "username": user, "role": role}, dict(MEMBER),
               [__import__("os").path.abspath("/ws")])
    c.start()
    return c, sink


async def test_run_survives_disconnect_and_replays(env):
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    hub.attach(up, c1)
    cwd = __import__("os").path.abspath("/ws/p")
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 1, "method": "session/new", "params": {"cwd": cwd}})
    r = await s1.wait_for(lambda m: m.get("id") == 1)
    assert r["result"]["_meta"]["echo"]["client"] == "goose-web"
    sid = r["result"]["sessionId"]
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                              "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "hi"}]}})
    ask = await s1.wait_for(lambda m: m.get("method") == "session/request_permission")
    assert up.sessions[sid].status == "needs_you"
    # the tab closes while the agent waits
    hub.detach(up, c1)
    c2, s2 = mk_client()
    hub.attach(up, c2)
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 9, "method": "_gw/hello", "params": {}})
    hello = await s2.wait_for(lambda m: m.get("id") == 9)
    assert hello["result"]["asks"][0]["id"] == ask["id"]          # pending ask replayed
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 10, "method": "session/load",
                              "params": {"sessionId": sid, "cwd": cwd}})
    await s2.wait_for(lambda m: m.get("id") == 10)
    assert agent.loads == 0                                         # served from the buffer
    texts = [m["params"]["update"].get("content", {}).get("text") for m in s2.msgs if m.get("method") == "session/update"]
    assert "hi" in texts and "Hello " in texts                      # user prompt echo + agent text
    await up.from_client(c2, {"jsonrpc": "2.0", "id": ask["id"],
                              "result": {"outcome": {"outcome": "selected", "optionId": "allow_once"}}})
    await s2.wait_for(lambda m: m.get("method") == "_gw/ask_resolved")
    await s2.wait_for(lambda m: m.get("method") == "session/update" and
                      m["params"]["update"].get("content", {}).get("text") == "done")
    for _ in range(50):
        if up.sessions[sid].status == "done":
            break
        await asyncio.sleep(0.05)
    assert up.sessions[sid].status == "done"
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 11, "method": "_gw/seen", "params": {"sessionId": sid}})
    await s2.wait_for(lambda m: m.get("id") == 11)
    assert up.sessions[sid].status == "idle"


async def test_policy_denial(env):
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c, s = mk_client()
    hub.attach(up, c)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 5, "method": "session/new", "params": {"cwd": "C:\\Windows"}})
    r = await s.wait_for(lambda m: m.get("id") == 5)
    assert r["error"]["code"] == -32003
    await up.from_client(c, {"jsonrpc": "2.0", "id": 6, "method": "_goose/unstable/config/upsert",
                             "params": {"key": "GOOSE_PROVIDER", "value": "x"}})
    r = await s.wait_for(lambda m: m.get("id") == 6)
    assert r["error"]["code"] == -32003


async def test_second_answer_loses(env):
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    c2, s2 = mk_client()
    hub.attach(up, c1)
    hub.attach(up, c2)
    cwd = __import__("os").path.abspath("/ws")
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 1, "method": "session/new", "params": {"cwd": cwd}})
    sid = (await s1.wait_for(lambda m: m.get("id") == 1))["result"]["sessionId"]
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                              "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "x"}]}})
    ask = await s2.wait_for(lambda m: m.get("method") == "session/request_permission")
    ans = {"jsonrpc": "2.0", "id": ask["id"], "result": {"outcome": {"outcome": "selected", "optionId": "allow_once"}}}
    await up.from_client(c1, ans)
    await up.from_client(c2, ans)
    m = await s2.wait_for(lambda m: m.get("method") == "_gw/ask_resolved" and m["params"]["by"] == "already-answered")
    assert m
    await s1.wait_for(lambda m: m.get("id") == 2)
    assert agent.answers.qsize() == 0


async def _load(up, client, sink, sid, mid):
    cwd = __import__("os").path.abspath("/ws")
    await up.from_client(client, {"jsonrpc": "2.0", "id": mid, "method": "session/load",
                                  "params": {"sessionId": sid, "cwd": cwd, "mcpServers": []}})
    return await sink.wait_for(lambda m: m.get("id") == mid)


async def _fp_settled(up, sid):
    for _ in range(100):
        s = up.sessions.get(sid)
        if s and s.fp is not None and not s.fp_pending:
            return s
        await asyncio.sleep(0.02)
    raise AssertionError("fingerprint never settled")


async def test_idle_replay_only_while_unchanged_elsewhere(env):
    """Bug 2026-11-06: a chat continued in Goose Desktop must not be replayed from the stale hub buffer."""
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    hub.attach(up, c1)
    agent.counts["x1"] = 4
    await _load(up, c1, s1, "x1", 1)
    assert agent.loads == 1
    await _fp_settled(up, "x1")
    r = await _load(up, c1, s1, "x1", 2)            # unchanged -> replay from the buffer
    assert agent.loads == 1 and r["result"]["_meta"]["gw"]["replayed"] is True
    agent.counts["x1"] = 6                           # another process added two messages
    r = await _load(up, c1, s1, "x1", 3)
    assert agent.loads == 2 and "gw" not in (r["result"].get("_meta") or {})
    await _fp_settled(up, "x1")
    agent.counts["x1"] = 6                           # a rename elsewhere is not a content change
    await _load(up, c1, s1, "x1", 4)
    assert agent.loads == 2


async def test_watcher_announces_external_change(env, tmp_path, monkeypatch):
    import goose_web.hub as hubmod
    monkeypatch.setattr(hubmod, "WATCH_INTERVAL", 0.05)
    agent, hub = env
    db = tmp_path / "data" / "sessions"
    db.mkdir(parents=True)
    (db / "sessions.db").write_bytes(b"x")
    hub.workers.workers["alice"].path_root = str(tmp_path)
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    hub.attach(up, c1)
    c1.watch.add("x9")
    agent.counts["x9"] = 2
    await _load(up, c1, s1, "x9", 1)
    await _fp_settled(up, "x9")
    await asyncio.sleep(0.15)
    agent.counts["x9"] = 3
    (db / "sessions.db-wal").write_bytes(b"new turn")   # Desktop wrote the shared session store
    m = await s1.wait_for(lambda m: m.get("method") == "_gw/session_changed")
    assert m["params"] == {"sessionId": "x9", "messageCount": 3, "updatedAt": "t3", "title": "T"}
    assert await s1.wait_for(lambda m: m.get("method") == "_gw/sessions_changed")
    assert up.sessions["x9"].loaded is False and not up.sessions["x9"].buffer
    await _load(up, c1, s1, "x9", 2)
    assert agent.loads == 2


async def test_retry_updates_replayed_extension_status(env):
    """Bug 2026-11-08: an extension that failed at start and was started later with Retry must not show as
    failed again when a tab reconnects (the reconnect is answered from the cached load result)."""
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client(role="admin")
    hub.attach(up, c1)
    agent.counts["e1"] = 3
    agent.ext_results = [{"name": "developer", "success": True},
                         {"name": "example_ext", "success": False, "error": "process quit before initialization"}]
    r = await _load(up, c1, s1, "e1", 1)
    assert r["result"]["_meta"]["extensionResults"][1]["success"] is False
    await _fp_settled(up, "e1")
    # Retry in the extension panel: remove the dead entry, then add it again (MCP: name in server.name)
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 2, "method": "_goose/unstable/session/extensions/remove",
                              "params": {"sessionId": "e1", "extensionKey": "example_ext"}})
    await s1.wait_for(lambda m: m.get("id") == 2)
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 3, "method": "_goose/unstable/session/extensions/add",
                              "params": {"sessionId": "e1", "extension": {"type": "mcp", "server": {"name": "example_ext"}}}})
    await s1.wait_for(lambda m: m.get("id") == 3)
    await _fp_settled(up, "e1")
    # a second tab (reload) is served from the cache: example_ext must now be loaded
    c2, s2 = mk_client(role="admin")
    hub.attach(up, c2)
    r = await _load(up, c2, s2, "e1", 4)
    assert agent.loads == 1 and r["result"]["_meta"]["gw"]["replayed"] is True
    assert r["result"]["_meta"]["extensionResults"] == [{"name": "developer", "success": True},
                                                        {"name": "example_ext", "success": True}]
    # a failed add records Goose's error; a remove drops the entry
    agent.fail_add = "spawn failed"
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 5, "method": "_goose/unstable/session/extensions/add",
                              "params": {"sessionId": "e1", "extension": {"type": "builtin", "name": "Developer"}}})
    assert "error" in await s2.wait_for(lambda m: m.get("id") == 5)
    assert up.sessions["e1"].load_result["_meta"]["extensionResults"][0] == {
        "name": "developer", "success": False, "error": "spawn failed"}
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 6, "method": "_goose/unstable/session/extensions/remove",
                              "params": {"sessionId": "e1", "extensionKey": "developer"}})
    await s2.wait_for(lambda m: m.get("id") == 6)
    assert up.sessions["e1"].load_result["_meta"]["extensionResults"] == [{"name": "example_ext", "success": True}]


def test_apply_extension_change_edge_cases():
    from goose_web.hub import EXT_ADD, EXT_REMOVE, apply_extension_change
    assert apply_extension_change(None, EXT_ADD, {"extension": {"name": "x"}}, {}) is False
    assert apply_extension_change({}, EXT_ADD, {"extension": {"name": "x"}}, {}) is False      # no start-up results
    lr = {"_meta": {"extensionResults": [], "other": 1}}
    assert apply_extension_change(lr, EXT_ADD, {"extension": {"name": "Web Search"}}, {"result": {}}) is True
    assert lr["_meta"] == {"extensionResults": [{"name": "Web Search", "success": True}], "other": 1}
    assert apply_extension_change(lr, EXT_REMOVE, {"extensionKey": "web_search"}, {"error": {}}) is False  # failed remove
    assert apply_extension_change(lr, EXT_REMOVE, {"extensionKey": "websearch"}, {"result": {}}) is True
    assert lr["_meta"]["extensionResults"] == []
    assert apply_extension_change(lr, EXT_ADD, {"extension": "bogus"}, {}) is False
