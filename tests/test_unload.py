"""FIX idle-sessions-keep-mcp-servers: the gateway closes idle chats in Goose so their MCP servers stop (unload.py),
against a fake ACP agent that advertises session/close like Goose 1.57."""
import asyncio
import json
import os
import time
from pathlib import Path

import pytest
import websockets

import goose_web
from goose_web import hub as hubmod
from goose_web.config import DEFAULTS, Settings, orphan_reaper, session_unload
from goose_web.hub import Client, Hub, queue_item
from goose_web.unload import LRU_MIN_IDLE_SECONDS, close_supported
from goose_web.workers import Worker

CWD = os.path.abspath("/ws/p")
G = "_goose/unstable/"


class Agent:
    """Goose-like ACP agent: records every request in order; session/close can be held back or refused."""

    def __init__(self, close=True):
        self.close = close
        self.close_error = None
        self.close_gate = None
        self.calls = []   # (method, sessionId)
        self.n = 0
        self.load_result = {}   # what session/load answers (M-1 tests: the chat's current provider)

    def methods(self, sid=None):
        return [m for m, s in self.calls if sid is None or s == sid]

    async def handler(self, ws):
        async for raw in ws:
            m = json.loads(raw)
            if "method" not in m:
                continue
            meth, mid, p = m["method"], m.get("id"), m.get("params") or {}
            sid = p.get("sessionId")
            self.calls.append((meth, sid))
            res = {}
            if meth == "initialize":
                caps = {"loadSession": True, "sessionCapabilities": {"close": {}} if self.close else {"list": {}}}
                res = {"protocolVersion": 1, "agentCapabilities": caps,
                       "agentInfo": {"name": "goose", "version": "1.57.0"}}
            elif meth == "session/new":
                self.n += 1
                res = {"sessionId": f"s{self.n}", "modes": {"currentModeId": "auto"}}
            elif meth == "session/load":
                await ws.send(json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": sid, "update": {"sessionUpdate": "agent_message_chunk",
                                                 "content": {"type": "text", "text": "replayed"}}}}))
                res = dict(self.load_result)
            elif meth == "session/close":
                asyncio.create_task(self._close(ws, mid))
                continue
            elif meth == "session/prompt":
                res = {"stopReason": "end_turn"}
            elif meth == hubmod.SESSION_INFO:
                res = {"session": {"sessionId": sid, "cwd": CWD, "updatedAt": "t1", "title": "T",
                                   "_meta": {"messageCount": 1}}}
            if mid is not None:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}))

    async def _close(self, ws, mid):
        if self.close_gate is not None:
            await self.close_gate.wait()
        if self.close_error:
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "error": self.close_error}))
        else:
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {}}))


class FakeWorkers:
    def __init__(self, port, **goose):
        self.workers = {"alice": Worker(key="alice", username="alice", path_root=None, native=False, port=port,
                                        secret="x", state="ready")}
        self.s = Settings({"goose": {"session_unload_minutes": 30, "max_loaded_sessions": 12, **goose}}, None)
        self.activity = None
        self.on_restart = None

    async def ensure(self, key):
        return self.workers[key]


class Sink:
    def __init__(self):
        self.msgs = []
        self.event = asyncio.Event()

    async def send(self, raw):
        m = json.loads(raw)   # a replay comes in JSON-array batches (FIX chat-open-replay-overflow)
        self.msgs.extend(m if isinstance(m, list) else [m])
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


def client(user="alice"):
    sink = Sink()
    c = Client(sink.send, {"id": 1, "username": user, "role": "admin"}, {}, [])
    c.start()
    return c, sink


@pytest.fixture
async def mk():
    servers = []

    async def make(close=True, **goose):
        agent = Agent(close)
        server = await websockets.serve(agent.handler, "127.0.0.1", 0)
        servers.append(server)
        hub = Hub(FakeWorkers(server.sockets[0].getsockname()[1], **goose))
        hub.start()
        up = hub.upstream("alice", "alice")
        c, sink = client()
        hub.attach(up, c)
        await up.ensure()
        up.unloader.stop()   # the tests tick by hand
        return agent, hub, up, c, sink
    yield make
    for s in servers:
        s.close()
        await s.wait_closed()


async def wait_until(pred, timeout=3.0):
    end = time.monotonic() + timeout
    while not pred():
        if time.monotonic() > end:
            raise AssertionError("condition not met")
        await asyncio.sleep(0.01)


async def settle(up):
    """No request in flight (the fingerprint read after session/new or a load)."""
    await wait_until(lambda: not up.pending and not any(s.fp_pending for s in up.sessions.values()))


async def new_chat(up, c, sink, i=0):
    await up.from_client(c, {"jsonrpc": "2.0", "id": 1000 + i, "method": "session/new",
                             "params": {"cwd": CWD, "mcpServers": []}})
    r = await sink.wait_for(lambda m: m.get("id") == 1000 + i)
    return r["result"]["sessionId"]


def age(up, sid, seconds):
    t = time.time() - seconds
    up.unloader.held[sid] = t
    up.sessions[sid].last_touch = t


def prompt(mid, sid, method="session/prompt"):
    params = {"sessionId": sid}
    params.update({"session/prompt": {"prompt": [{"type": "text", "text": "hi"}]},
                   "session/set_mode": {"modeId": "chat"},
                   G + "session/working-dir/update": {"workingDir": CWD}}[method])
    return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params}


# ------------------------------------------------------------------ unloading
async def test_an_idle_chat_is_closed_once_and_keeps_its_queue_title_and_mark(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    s = up.sessions[sid]
    s.title = "Keep me"
    up._set_status(s, "done")
    assert up.unloader.loaded_count() == 1
    age(up, sid, 31 * 60)
    agent.close_gate = asyncio.Event()
    t = asyncio.create_task(up.unloader.tick())
    await wait_until(lambda: "session/close" in agent.methods(sid))
    # a message queued while Goose closes the chat (a chat with queued messages is never picked)
    s.queue = [queue_item([{"type": "text", "text": "later"}], "alice", held=True)]
    agent.close_gate.set()
    assert await t == [sid]
    assert agent.methods(sid).count("session/close") == 1
    assert await up.unloader.tick() == []
    assert agent.methods(sid).count("session/close") == 1
    # the state stays (unlike the hub's own close branch): queue, title, herd status; the buffer and load result go
    s = up.sessions[sid]
    assert s.queue and s.title == "Keep me" and s.status == "done"
    assert not s.loaded and s.load_result is None and s.buffer_bytes == 0 and not s.buffer
    assert sid not in up.unloader.held and sid in up.unloader.unloaded and up.unloader.loaded_count() == 0
    note = await sink.wait_for(lambda m: m.get("method") == "_gw/session_changed")
    assert note["params"] == {"sessionId": sid, "reason": "unloaded"}
    assert not any(m.get("method") == "_gw/queue_update" for m in sink.msgs)
    assert not any(m.get("method") == "_gw/herd" and (m.get("params") or {}).get("removed") for m in sink.msgs)
    d = up.unloader.describe()
    assert d["loadedSessions"] == 0 and d["unloadedSessions"] == 1 and d["unloading"] and not d["unloadOff"]


BLOCKERS = {
    "running": lambda up, c, s: setattr(s, "status", "working"),
    "waiting for an answer": lambda up, c, s: setattr(s, "status", "needs_you"),
    "prompt in flight": lambda up, c, s: setattr(s, "prompts", 1),
    "active run": lambda up, c, s: setattr(s, "run_id", "r1"),
    "ask": lambda up, c, s: up.asks.__setitem__("k", {"sessionId": s.sid, "msg": {"id": "p1"}}),
    "pending request": lambda up, c, s: up.pending.__setitem__(
        99999, (None, None, None, "session/set_mode", {"sessionId": s.sid})),
    "queued message": lambda up, c, s: setattr(s, "queue", [queue_item([{"type": "text", "text": "x"}], "alice")]),
    "steer": lambda up, c, s: setattr(s, "steers", [{"id": "x", "messageId": "m1", "runId": "", "blocks": [],
                                                     "by": "alice", "at": time.time(), "state": "pending"}]),
    "being loaded": lambda up, c, s: setattr(s, "loading", hubmod.UpstreamLoad(99998)),
    "current chat of a tab": lambda up, c, s: setattr(c, "current", s.sid),
    "prompt being checked": lambda up, c, s: setattr(up, "starting", 1),
}


@pytest.mark.parametrize("why", sorted(BLOCKERS))
async def test_a_busy_chat_is_never_closed(mk, why):
    agent, hub, up, c, sink = await mk(max_loaded_sessions=1)
    sid = await new_chat(up, c, sink, 1)
    await new_chat(up, c, sink, 2)
    await settle(up)
    BLOCKERS[why](up, c, up.sessions[sid])
    age(up, sid, 3 * 3600)
    assert sid not in await up.unloader.tick()
    assert "session/close" not in agent.methods(sid)


async def test_not_before_the_limit_and_never_with_zero_minutes(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 29 * 60)
    assert await up.unloader.tick() == []
    agent2, hub2, up2, c2, sink2 = await mk(session_unload_minutes=0)
    sid2 = await new_chat(up2, c2, sink2)
    await settle(up2)
    age(up2, sid2, 99 * 3600)
    assert await up2.unloader.tick() == []
    assert "session/close" not in agent.methods() + agent2.methods()
    assert not up2.unloader.describe()["unloading"]


async def test_the_next_tab_load_comes_from_goose(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    assert await up.unloader.tick() == [sid]
    loads = agent.methods(sid).count("session/load")
    c2, sink2 = client()
    hub.attach(up, c2)
    await up.from_client(c2, {"jsonrpc": "2.0", "id": 5, "method": "session/load",
                              "params": {"sessionId": sid, "cwd": CWD, "mcpServers": []}})
    r = await sink2.wait_for(lambda m: m.get("id") == 5)
    assert agent.methods(sid).count("session/load") == loads + 1
    assert not ((r["result"].get("_meta") or {}).get("gw") or {}).get("replayed")
    assert any(m.get("method") == "session/update" for m in sink2.msgs)   # Goose's own replay reached the tab
    assert sid in up.unloader.held and sid not in up.unloader.unloaded and up.sessions[sid].loaded


@pytest.mark.parametrize("method", ["session/prompt", "session/set_mode", G + "session/working-dir/update"])
async def test_a_method_for_an_unloaded_chat_loads_it_silently_first(mk, method):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    assert await up.unloader.tick() == [sid]
    up.sessions[sid].cwd = ""   # also when the gateway does not know the chat's folder: it asks Goose
    c2, sink2 = client()
    hub.attach(up, c2)
    c2.watch.add(sid)
    start = len(agent.calls)
    await up.from_client(c, prompt(7, sid, method))
    r = await sink.wait_for(lambda m: m.get("id") == 7)
    assert "error" not in r, r
    seq = [m for m, s in agent.calls[start:] if s == sid and m in ("session/load", "session/close", method)]
    assert seq == ["session/load", method]
    for snk in (sink, sink2):   # the silent load's replay went to no tab
        assert not any(m.get("method") == "session/update" and
                       ((m["params"]["update"].get("content") or {}).get("text") == "replayed") for m in snk.msgs)
    assert sid in up.unloader.held and sid not in up.unloader.unloaded
    assert up.sessions[sid].loading is None and up.sessions[sid].cwd == CWD


# ------------------------------------------------------------------ M-1 (assessment 2026-11-24)
def member(roots=(CWD,)):
    from goose_web import policy as pol
    sink = Sink()
    p = {**pol.DEFAULT_POLICY, "allowed_providers": ["good-provider"], "allowed_models": ["*"], "allowed_modes": ["*"]}
    c = Client(sink.send, {"id": 2, "username": "alice", "role": "user"}, p, list(roots))
    c.start()
    return c, sink


def uses(provider):
    return {"configOptions": [{"id": "provider", "currentValue": provider}]}


async def test_a_members_prompt_to_an_unloaded_chat_is_checked_after_a_reload(mk):
    """The prompt-time check of the chat's provider used to see no load result once the unloader had closed the
    chat, and let one prompt through unchecked. Now the chat is loaded first and the prompt refused."""
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    assert await up.unloader.tick() == [sid]
    assert up.sessions[sid].load_result is None
    agent.load_result = uses("forbidden-provider")
    m, msink = member()
    hub.attach(up, m)
    start = len(agent.calls)
    await up.from_client(m, prompt(9, sid))
    r = await msink.wait_for(lambda x: x.get("id") == 9)
    assert "error" in r and "forbidden-provider" in r["error"]["message"], r
    seq = [meth for meth, s in agent.calls[start:] if s == sid]
    assert "session/load" in seq and "session/prompt" not in seq


async def test_a_members_prompt_to_an_unloaded_allowed_chat_goes_through_after_the_load(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    assert await up.unloader.tick() == [sid]
    agent.load_result = uses("good-provider")
    m, msink = member()
    hub.attach(up, m)
    start = len(agent.calls)
    await up.from_client(m, prompt(10, sid))
    r = await msink.wait_for(lambda x: x.get("id") == 10)
    assert "error" not in r, r
    seq = [meth for meth, s in agent.calls[start:] if s == sid and meth in ("session/load", "session/prompt")]
    assert seq == ["session/load", "session/prompt"]


async def test_a_members_prompt_to_a_chat_never_loaded_here_is_loaded_and_checked_first(mk):
    agent, hub, up, c, sink = await mk()
    agent.load_result = uses("forbidden-provider")
    m, msink = member()
    hub.attach(up, m)
    await up.from_client(m, prompt(11, "old-chat"))   # no state in the gateway at all
    r = await msink.wait_for(lambda x: x.get("id") == 11)
    assert "error" in r and "forbidden-provider" in r["error"]["message"], r
    calls = agent.methods("old-chat")   # its folder is asked first (session/info), then it is loaded
    assert "session/load" in calls and "session/prompt" not in calls   # loaded to learn its settings; no prompt


async def test_a_members_prompt_never_loads_a_chat_in_a_folder_they_may_not_use(mk):
    """The silent load for a member's prompt applies the folder rule of opening the chat in a tab (policy.check of
    session/load) BEFORE Goose is asked to load it."""
    agent, hub, up, c, sink = await mk()
    agent.load_result = uses("good-provider")
    m, msink = member(roots=(os.path.abspath("/elsewhere"),))   # the chat works in CWD, outside these roots
    hub.attach(up, m)
    await up.from_client(m, prompt(12, "old-chat-2"))
    r = await msink.wait_for(lambda x: x.get("id") == 12)
    assert "error" in r and "folder not allowed" in r["error"]["message"], r
    calls = agent.methods("old-chat-2")
    assert "session/load" not in calls and "session/prompt" not in calls


async def test_a_prompt_during_a_close_waits_then_loads_the_chat(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    agent.close_gate = asyncio.Event()
    t = asyncio.create_task(up.unloader.tick())
    await wait_until(lambda: "session/close" in agent.methods(sid))
    p = asyncio.create_task(up.from_client(c, prompt(8, sid)))
    lo = asyncio.create_task(up.from_client(c, {"jsonrpc": "2.0", "id": 9, "method": "session/load",
                                                "params": {"sessionId": sid, "cwd": CWD, "mcpServers": []}}))
    await asyncio.sleep(0.2)
    assert "session/prompt" not in agent.methods(sid) and "session/load" not in agent.methods(sid)
    agent.close_gate.set()
    assert await t == [sid]
    await asyncio.gather(p, lo)
    assert "error" not in await sink.wait_for(lambda m: m.get("id") == 8)
    assert "error" not in await sink.wait_for(lambda m: m.get("id") == 9)
    after = agent.methods(sid)[agent.methods(sid).index("session/close"):]
    assert [m for m in after if m in ("session/close", "session/load", "session/prompt")][:2] == \
        ["session/close", "session/load"]
    assert "session/prompt" in after and after.count("session/close") == 1


async def test_without_close_capability_nothing_is_closed(mk):
    agent, hub, up, c, sink = await mk(close=False)
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    assert await up.unloader.tick() == []
    assert "session/close" not in agent.methods()
    d = up.unloader.describe()
    assert d["loadedSessions"] == 1 and not d["unloading"] and "session/close" in d["unloadOff"]


async def test_method_not_found_turns_unloading_off_for_the_worker(mk):
    agent, hub, up, c, sink = await mk()
    agent.close_error = {"code": -32601, "message": "Method not found"}
    a, b = await new_chat(up, c, sink, 1), await new_chat(up, c, sink, 2)
    await settle(up)
    age(up, a, 3600)
    age(up, b, 3500)
    assert await up.unloader.tick() == []
    assert agent.methods().count("session/close") == 1    # the first refusal ends the round
    assert up.unloader.off and up.sessions[a].loaded and a in up.unloader.held
    assert await up.unloader.tick() == [] and agent.methods().count("session/close") == 1
    assert "method not found" in up.unloader.describe()["unloadOff"]


async def test_max_loaded_sessions_unloads_the_least_recently_used_first(mk):
    agent, hub, up, c, sink = await mk(max_loaded_sessions=2)
    sids = [await new_chat(up, c, sink, i) for i in range(4)]
    await settle(up)
    for sid, secs in zip(sids, (300, 900, 200, 600)):
        age(up, sid, secs)
    assert await up.unloader.tick() == [sids[1], sids[3]]
    assert [s for m, s in agent.calls if m == "session/close"] == [sids[1], sids[3]]
    assert up.unloader.loaded_count() == 2
    # a chat used less than LRU_MIN_IDLE_SECONDS ago stays, even above the limit
    more = [await new_chat(up, c, sink, 10 + i) for i in range(2)]
    await settle(up)
    for sid in sids[0::2] + more:
        age(up, sid, LRU_MIN_IDLE_SECONDS / 2)
    assert await up.unloader.tick() == []


async def test_pruning_a_state_closes_the_chat_first(mk, monkeypatch):
    agent, hub, up, c, sink = await mk()
    sids = [await new_chat(up, c, sink, i) for i in range(3)]
    await settle(up)
    c.watch.clear()
    age(up, sids[0], 50)
    monkeypatch.setattr(hubmod, "SESSION_STATES_MAX", 3)
    up._prune_sessions()
    assert sids[0] not in up.sessions and sids[1] in up.sessions
    await wait_until(lambda: sids[0] in up.unloader.unloaded)
    assert agent.methods(sids[0]).count("session/close") == 1 and sids[0] not in up.unloader.held


async def test_a_tabs_own_close_still_forgets_the_chat(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    up.sessions[sid].queue = [queue_item([{"type": "text", "text": "x"}], "alice")]
    await up.from_client(c, {"jsonrpc": "2.0", "id": 9, "method": "session/close", "params": {"sessionId": sid}})
    assert "error" not in await sink.wait_for(lambda m: m.get("id") == 9)
    assert sid not in up.sessions and sid not in up.unloader.held and sid not in up.unloader.unloaded
    await sink.wait_for(lambda m: m.get("method") == "_gw/queue_update" and m["params"]["items"] == [])


async def test_the_current_chat_comes_from_watch_and_seen(mk):
    agent, hub, up, c, sink = await mk()
    sid = await new_chat(up, c, sink)
    await settle(up)
    age(up, sid, 3600)
    await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 1, "method": "_gw/watch",
                                "params": {"sessionIds": [sid], "current": sid}})
    assert c.current == sid and await up.unloader.tick() == []
    await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 2, "method": "_gw/watch",
                                "params": {"sessionIds": [sid], "current": ""}})
    await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 3, "method": "_gw/seen", "params": {"sessionId": sid}})
    assert c.current == sid and await up.unloader.tick() == []
    await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 4, "method": "_gw/watch", "params": {"sessionIds": [sid]}})
    assert c.current == sid   # an older tab that does not send "current" keeps what _gw/seen said
    hub.detach(up, c)          # the tab closed: its chat is no longer shown
    assert await up.unloader.tick() == [sid]


async def test_a_new_connection_holds_no_chat(mk):
    agent, hub, up, c, sink = await mk()
    await new_chat(up, c, sink)
    await settle(up)
    assert up.unloader.loaded_count() == 1
    await up.reset("test")
    assert up.unloader.loaded_count() == 0 and not up.unloader.held


def test_close_capability_and_knobs():
    assert close_supported({"agentCapabilities": {"sessionCapabilities": {"close": {}}}})
    assert not close_supported({"agentCapabilities": {"sessionCapabilities": {"list": {}}}})
    assert not close_supported(None) and not close_supported({"agentCapabilities": None})
    g = DEFAULTS["goose"]
    assert (g["session_unload_minutes"], g["max_loaded_sessions"], g["orphan_reaper"], g["orphan_grace_seconds"]) == \
        (30, 12, True, 120)
    assert session_unload(Settings({"goose": {}}, None)) == (30, 12, [])
    assert session_unload(Settings({"goose": {"session_unload_minutes": 0, "max_loaded_sessions": 0}}, None)) == \
        (0, 0, [])
    m, n, probs = session_unload(Settings({"goose": {"session_unload_minutes": "soon", "max_loaded_sessions": -1}},
                                          None))
    assert (m, n) == (30, 12) and len(probs) == 2 and "goose.session_unload_minutes" in probs[0]
    assert orphan_reaper(Settings({"goose": {}}, None)) == (True, 120, [])
    on, grace, probs = orphan_reaper(Settings({"goose": {"orphan_reaper": "off", "orphan_grace_seconds": 5}}, None))
    assert on is False and grace == 120 and "goose.orphan_grace_seconds" in probs[0]


def test_admin_system_lists_loaded_chats(tmp_path, monkeypatch):
    from tests.test_team_profiles import client_for, sign_in, user
    from goose_web import mxc
    from goose_web.auth import AuthService
    from goose_web.config import load_settings
    from goose_web.context import Ctx
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    from goose_web.workers import WorkerManager
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    monkeypatch.setattr(mxc, "summary", lambda st, refresh=False: {})
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    wm = WorkerManager(s)
    wm.workers["alice"] = Worker(key="alice", username="alice", path_root=None, native=False, state="ready")
    hub = Hub(wm)
    up = hub.upstream("alice", "alice")
    up.ws = object()
    up.unloader.loaded_count()
    up.unloader.held.update({"s1": 1.0, "s2": 2.0})
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=wm, hub=hub, version="t")
    admin = user(db, "root", role="admin")
    with client_for(c) as tc:
        sign_in(tc, c, admin)
        r = tc.get("/api/admin/system")
    assert r.status_code == 200, r.text
    w = next(x for x in r.json()["workers"] if x["key"] == "alice")
    assert w["loadedSessions"] == 2 and w["unloadMinutes"] == 30 and w["maxLoadedSessions"] == 12
    db.close()


# ------------------------------------------------------------------ the browser side (sources)
JS = Path(goose_web.__file__).parent / "static" / "js"


def test_tabs_reload_an_unloaded_chat_quietly():
    cs = (JS / "chatsession.js").read_text(encoding="utf-8")
    fn = cs[cs.index("export function sessionChangedElsewhere"):]
    fn = fn[:fn.index("\n}\n")]
    branch = fn[fn.index("p.reason === 'unloaded'"):fn.index("const patch")]
    assert "return;" in branch and "c.gwUnloaded = true" in branch and "c.loaded = false" in branch
    assert "refreshFromElsewhere" not in branch and "external" not in branch   # no "updated elsewhere" notice
    assert "sid !== currentId" in branch
    assert "e.code === -32002 && this.gwUnloaded" in cs   # Goose said "not found" for an unloaded chat: load once more
    for m in ("'session/prompt'", "'session/set_mode'", "'session/set_config_option'", "G('session/working-dir/update')"):
        assert f"this.callLoaded({m}" in cs
    assert "rpc.setWatched([...chats.keys()], currentId" in cs
    rpc = (JS / "rpc.js").read_text(encoding="utf-8")
    assert rpc.count("current: this.current") == 2   # every _gw/watch names the chat the tab shows
    admin = (JS / "views" / "admin.js").read_text(encoding="utf-8")
    assert "w.loadedSessions" in admin and "w.unloadOff" in admin
