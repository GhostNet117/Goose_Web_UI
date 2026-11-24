"""FIX chat-open-replay-overflow: opening a chat whose run streamed tens of thousands of chunks must not end the tab's
socket; one upstream session/load per chat; a load watchdog; transport errors answered; the front end backs off.

Every hub test runs against a fake Goose (websocket) and real hub.Client objects whose socket can be blocked (a tab that
reads slowly or not at all)."""
import asyncio
import json
import logging
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import websockets

import goose_web
import goose_web.hub as hubmod
from goose_web.hub import Client, Hub

from test_hub import MEMBER, FakeWorkers, Sink

CWD = os.path.abspath("/ws")
JS = Path(goose_web.__file__).parent / "static" / "js"


def upd(sid, u):
    return json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": u}})


def tool(i, pad=0):
    return {"sessionUpdate": "tool_call_update", "toolCallId": f"t{i}", "status": "in_progress", "title": "x" * pad}


def chunk(kind, text, mid=None):
    u = {"sessionUpdate": kind, "content": {"type": "text", "text": text}}
    if mid is not None:
        u["messageId"] = mid
    return u


class LoadAgent:
    """Fake Goose: session/load sends history[sid], waits for `gate` (when set), sends late[sid], then answers."""

    def __init__(self):
        self.loads = 0
        self.history: dict[str, list] = {}
        self.late: dict[str, list] = {}
        self.gate: asyncio.Event | None = None
        self.tasks: set = set()

    async def handler(self, ws):
        async for raw in ws:
            m = json.loads(raw)
            meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
            if meth is None:
                continue
            if meth == "initialize":
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1}}))
            elif meth == "session/load":
                self.loads += 1
                t = asyncio.create_task(self._load(ws, mid, p, self.gate))
                self.tasks.add(t)
                t.add_done_callback(self.tasks.discard)
            elif meth == "_goose/unstable/session/info":
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"session": {
                    "sessionId": p["sessionId"], "cwd": CWD, "updatedAt": "t1", "title": "T",
                    "_meta": {"messageCount": 1}}}}))
            elif mid is not None:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {}}))

    async def _load(self, ws, mid, p, gate):
        sid = p["sessionId"]
        try:
            for u in self.history.get(sid, []):
                await ws.send(upd(sid, u))
            if gate is not None:
                await gate.wait()
            for u in self.late.get(sid, []):
                await ws.send(upd(sid, u))
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"modes": {"currentModeId": "auto"}}}))
        except Exception:
            pass   # the hub dropped this connection (worker restart test)


class Tab(Sink):
    """A browser socket that can stop reading (open cleared) and counts the frames it was sent."""

    def __init__(self):
        super().__init__()
        self.open = asyncio.Event()
        self.open.set()
        self.frames = 0

    async def send(self, raw):
        await self.open.wait()
        self.frames += 1
        await super().send(raw)

    def updates(self, sid):
        return [m["params"]["update"] for m in self.msgs
                if m.get("method") == "session/update" and m["params"]["sessionId"] == sid]

    def index(self, pred):
        return next(i for i, m in enumerate(self.msgs) if pred(m))


@pytest.fixture
async def lenv():
    agent = LoadAgent()
    server = await websockets.serve(agent.handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    hub = Hub(FakeWorkers(port))
    hub.start()
    yield agent, hub, hub.upstream("alice", "alice")
    if agent.gate is not None:
        agent.gate.set()
    for t in list(agent.tasks):
        t.cancel()
    server.close()
    await server.wait_closed()


def tab(hub, up):
    sink = Tab()
    c = Client(sink.send, {"id": 1, "username": "alice", "role": "user"}, dict(MEMBER), [CWD])
    c.start()
    hub.attach(up, c)
    return c, sink


async def ask_load(up, c, sid, mid):
    await up.from_client(c, {"jsonrpc": "2.0", "id": mid, "method": "session/load",
                             "params": {"sessionId": sid, "cwd": CWD, "mcpServers": []}})


async def load(up, c, sink, sid, mid, timeout=10):
    await ask_load(up, c, sid, mid)
    return await sink.wait_for(lambda m: m.get("id") == mid and "method" not in m, timeout)


def live(up, sid, u):
    raw = upd(sid, u)
    up._dispatch(json.loads(raw), raw)


# ---------------------------------------------------------------- RC1: the replay must never close its own tab
async def test_replay_of_25000_buffered_frames_keeps_the_tab_open(lenv):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await load(up, c, sink, "big", 1)
    s = up.sessions["big"]
    s.prompts = 1                                      # running: a load is answered from the buffer
    s.buffer.clear()                                   # what a long run left before the fix: one frame per chunk
    s.buffer.extend(upd("big", tool(i, pad=300)) for i in range(25000))   # ~9 MB, 25,000 frames
    sink.msgs.clear()
    sink.frames = 0
    sink.open.clear()                                  # the tab reads slowly: the replay must wait for it
    await ask_load(up, c, "big", 2)
    await asyncio.sleep(0.2)
    live(up, "big", tool("live"))                      # the run goes on during the replay
    assert not c.closed
    sink.open.set()
    r = await sink.wait_for(lambda m: m.get("id") == 2, timeout=60)
    await sink.wait_for(lambda m: m.get("method") == "session/update"
                        and m["params"]["update"]["toolCallId"] == "tlive", timeout=10)
    assert not c.closed and r["result"]["_meta"]["gw"] == {"replayed": True, "running": True, "truncated": False}
    ids = [u["toolCallId"] for u in sink.updates("big")]
    assert ids == [f"t{i}" for i in range(25000)] + ["tlive"]       # all of it, in order, nothing twice
    at = {k: sink.index(lambda m, k=k: m.get("method") == "session/update" and m["params"]["update"]["toolCallId"] == k)
          for k in ("t24999", "tlive")}
    assert at["t24999"] < sink.index(lambda m: m.get("id") == 2) < at["tlive"]   # result: after the replay, then live
    assert sink.frames < 200                                        # sent in batches, not 25,000 frames
    assert c.qbytes == 0 and not c.holds and not c.replays


# ---------------------------------------------------------------- the buffer: coalescing and the frame cap
async def test_thought_chunks_of_one_message_coalesce(lenv):
    agent, hub, up = lenv
    c1, s1 = tab(hub, up)
    await load(up, c1, s1, "th", 1)
    s = up.sessions["th"]
    pieces = [f"w{i} " for i in range(30000)] + ['say "hi"\n', "\u00e9\u2028", "\\end"]
    for p in pieces:
        live(up, "th", chunk("agent_thought_chunk", p, "m1"))
    for p in ("Hello", " world"):
        live(up, "th", chunk("agent_message_chunk", p, "m2"))
    for p in ("no ", "id"):
        live(up, "th", chunk("agent_thought_chunk", p))
    assert len(s.buffer) == 3                                       # one frame per message (was 30,007)
    await s1.wait_for(lambda m: m.get("method") == "session/update"
                      and m["params"]["update"].get("content", {}).get("text") == "id")
    assert len(s1.updates("th")) == len(pieces) + 4                 # the live tab still got every chunk
    s.prompts = 1
    c2, s2 = tab(hub, up)
    r = await load(up, c2, s2, "th", 1)
    assert "result" in r
    got = s2.updates("th")
    assert [(u["sessionUpdate"], u.get("messageId")) for u in got] == [
        ("agent_thought_chunk", "m1"), ("agent_message_chunk", "m2"), ("agent_thought_chunk", None)]
    assert [u["content"]["text"] for u in got] == ["".join(pieces), "Hello world", "no id"]
    # the buffer counts what it holds: about the text, not 30,000 frame envelopes
    assert s.buffer_bytes < len("".join(pieces)) + 2000
    # a replay does not end the tail: later chunks of m1's successor still merge
    live(up, "th", chunk("agent_thought_chunk", "!"))
    assert len(s.buffer) == 3 and json.loads(up._frames(s)[-1])["params"]["update"]["content"]["text"] == "no id!"


async def test_buffer_frame_cap_truncates_so_an_idle_open_reloads(lenv):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await load(up, c, sink, "cap", 1)
    s = up.sessions["cap"]
    cap = getattr(hubmod, "SESSION_BUFFER_FRAMES", 5000)
    for i in range(cap + 100):
        live(up, "cap", tool(i))
    assert len(s.buffer) == cap and s.truncated                     # 5,100 small frames: far below the 12 MB cap
    for _ in range(100):                                            # the fingerprint after the first load
        if s.fp is not None and not s.fp_pending:
            break
        await asyncio.sleep(0.02)
    await load(up, c, sink, "cap", 2)
    assert agent.loads == 2                                         # loaded from Goose, not from a cut buffer


# ---------------------------------------------------------------- RC6: one upstream load per chat
async def test_two_tabs_opening_one_chat_share_one_upstream_load(lenv):
    agent, hub, up = lenv
    agent.history["two"] = [tool(i) for i in range(10)]
    agent.late["two"] = [tool(i) for i in range(10, 20)]
    agent.gate = asyncio.Event()
    ca, sa = tab(hub, up)
    cb, sb = tab(hub, up)
    await ask_load(up, ca, "two", 1)
    await sa.wait_for(lambda m: m.get("method") == "session/update" and m["params"]["update"]["toolCallId"] == "t9")
    await ask_load(up, cb, "two", 1)                    # the second tab joins the load in flight
    await asyncio.sleep(0.05)
    agent.gate.set()
    for sink in (sa, sb):
        r = await sink.wait_for(lambda m: m.get("id") == 1)
        assert r["result"]["modes"] == {"currentModeId": "auto"}
        assert [u["toolCallId"] for u in sink.updates("two")] == [f"t{i}" for i in range(20)]   # complete, no duplicates
        last = max(i for i, m in enumerate(sink.msgs) if m.get("method") == "session/update")
        assert sink.index(lambda m: m.get("id") == 1) > last          # the result after the whole history
    assert agent.loads == 1
    s = up.sessions["two"]
    assert s.loaded and s.loading is None and len(s.buffer) == 20 and not ca.replays and not cb.replays


async def test_worker_restart_during_a_load_answers_every_tab_and_a_retry_works(lenv):
    agent, hub, up = lenv
    agent.history["rs"] = [tool(0)]
    agent.gate = asyncio.Event()
    ca, sa = tab(hub, up)
    cb, sb = tab(hub, up)
    await ask_load(up, ca, "rs", 1)
    await ask_load(up, cb, "rs", 7)
    await asyncio.sleep(0.1)
    assert agent.loads == 1
    await up.reset("the Goose worker restarted")         # what Hub._on_restart does
    for sink, mid in ((sa, 1), (sb, 7)):
        e = await sink.wait_for(lambda m: m.get("id") == mid)
        assert e["error"] == {"code": -32000, "message": "the Goose worker restarted"}
    assert up.sessions["rs"].loading is None and not up.pending and not ca.replays and not cb.replays
    agent.gate = None
    r = await load(up, ca, sa, "rs", 2)                  # the tab's retry
    assert "result" in r and agent.loads == 2 and not ca.closed


# ---------------------------------------------------------------- RC5: a dead stdio worker
class DeadChannel:
    """A stdio worker channel whose stdin is closed (StdioChannel.send raises ConnectionError)."""

    def __init__(self, exited=None):
        self.proc = SimpleNamespace(poll=lambda: exited)

    async def send(self, text):
        raise ConnectionError("worker stdin closed: [Errno 22] Invalid argument")

    async def close(self):
        pass


async def test_closed_stdio_channel_answers_and_leaks_no_pending_entry(lenv):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await up.ensure()
    up.ws = DeadChannel()                                # the process still runs, but its stdin is gone
    await up.from_client(c, {"jsonrpc": "2.0", "id": 5, "method": "session/list", "params": {}})
    r = await sink.wait_for(lambda m: m.get("id") == 5)
    assert r["error"] == {"code": -32000, "message": "the Goose worker is restarting"}
    await ask_load(up, c, "dead", 6)
    r = await sink.wait_for(lambda m: m.get("id") == 6)
    assert r["error"]["code"] == -32000
    assert up.pending == {} and up.sessions["dead"].loading is None and not c.replays and not c.closed


async def test_ensure_reconnects_when_the_stdio_process_has_exited(lenv):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await up.ensure()
    dead = up.ws = DeadChannel(exited=1)                 # state still says "ready"
    await up.ensure()
    assert up.ws is not dead and up.state == "ready"
    await sink.wait_for(lambda m: m.get("method") == "_gw/upstream" and m["params"]["state"] == "down")
    r = await load(up, c, sink, "back", 1)
    assert "result" in r


# ---------------------------------------------------------------- RC4: the load watchdog
async def test_load_watchdog_answers_and_drops_the_late_frames(lenv, caplog):
    agent, hub, up = lenv
    hub.workers.s = SimpleNamespace(get=lambda sec, key, default=None:
                                    0.3 if (sec, key) == ("goose", "session_load_timeout_seconds") else default)
    agent.history["wd"] = [tool(0)]
    agent.late["wd"] = [tool(1), tool(2)]
    agent.gate = asyncio.Event()
    c, sink = tab(hub, up)
    with caplog.at_level(logging.WARNING, logger="goose_web.hub"):
        await ask_load(up, c, "wd", 1)
        r = await sink.wait_for(lambda m: m.get("id") == 1)
    assert r["error"] == {"code": -32000, "message": "Goose did not answer within 0.3 s"}
    assert "did not answer session/load of wd within 0.3 s" in caplog.text
    s = up.sessions["wd"]
    assert s.loading is None and s.abandoned is not None and not s.buffer and not s.loaded
    r = await load(up, c, sink, "wd", 2, timeout=2)      # refused at once while Goose still owes the answer
    assert r["error"]["code"] == -32000 and "earlier load" in r["error"]["message"] and agent.loads == 1
    seen = len(sink.updates("wd"))
    agent.gate.set()                                     # Goose answers late, with more history
    for _ in range(100):
        if s.abandoned is None:
            break
        await asyncio.sleep(0.02)
    assert s.abandoned is None and len(sink.updates("wd")) == seen and not s.buffer and not s.loaded
    agent.gate = None
    r = await load(up, c, sink, "wd", 3)
    assert "result" in r and agent.loads == 2 and len(s.buffer) == 3


# ---------------------------------------------------------------- the tab's queue: bounded by bytes
async def test_queue_overflow_sends_resync_and_never_closes(lenv, monkeypatch, caplog):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await load(up, c, sink, "q", 1)
    sink.open.clear()                                    # a tab that stopped reading (phone in a pocket)
    for i in range(25000):                               # more frames than the old 20,000-item queue held
        live(up, "q", tool(i))
    assert not c.closed and not c.stale
    c.send({"jsonrpc": "2.0", "id": 77, "result": {"kept": True}})   # a response must never be dropped
    monkeypatch.setattr(hubmod, "CLIENT_QUEUE_BYTES", 1024 * 1024)
    with caplog.at_level(logging.WARNING, logger="goose_web.hub"):
        live(up, "q", tool("over"))
    assert re.search(r"tab queue overflow \(profile alice, user alice, session q\): dropped \d+ frame\(s\), \d+ bytes",
                     caplog.text)
    assert not c.closed and "q" in c.stale and c.dropped["q"] == 1
    live(up, "q", tool("after"))                         # stale until the tab loads the chat again
    sink.open.set()
    m = await sink.wait_for(lambda m: m.get("method") == "_gw/resync")
    assert m["params"] == {"sessionId": "q"}
    assert (await sink.wait_for(lambda m: m.get("id") == 77))["result"] == {"kept": True}
    assert len(sink.updates("q")) <= 1                   # at most the frame the socket was writing
    r = await load(up, c, sink, "q", 2)                  # the tab reloads: frames flow again
    assert "result" in r and "q" not in c.stale
    live(up, "q", tool("again"))
    await sink.wait_for(lambda m: m.get("method") == "session/update"
                        and m["params"]["update"]["toolCallId"] == "tagain")
    assert not c.closed


async def test_unread_responses_past_the_hard_cap_close_with_queue_full(lenv, monkeypatch, caplog):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    sink.open.clear()
    monkeypatch.setattr(hubmod, "CLIENT_QUEUE_BYTES", 256 * 1024)
    monkeypatch.setattr(hubmod, "CLIENT_QUEUE_HARD_BYTES", 512 * 1024)
    with caplog.at_level(logging.WARNING, logger="goose_web.hub"):
        for i in range(10):
            c.send({"jsonrpc": "2.0", "id": i, "result": {"pad": "x" * 100_000}})
    assert c.closed and c.reason == "queue-full" and "tab queue full (profile alice" in caplog.text


async def test_overflow_during_a_replay_answers_resync(lenv, monkeypatch):
    agent, hub, up = lenv
    c, sink = tab(hub, up)
    await load(up, c, sink, "ov", 1)
    s = up.sessions["ov"]
    s.prompts = 1
    s.buffer.clear()
    s.buffer.extend(upd("ov", tool(i, pad=1000)) for i in range(2000))   # ~2 MB
    monkeypatch.setattr(hubmod, "CLIENT_QUEUE_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(hubmod, "REPLAY_QUEUE_BYTES", 256 * 1024)
    sink.open.clear()
    await ask_load(up, c, "ov", 2)
    await asyncio.sleep(0.1)                             # the replay waits for the tab
    for i in range(3000):                                # the run streams on: held frames overflow the tab
        live(up, "ov", tool(f"l{i}", pad=1000))
    assert c.dropped.get("ov") == 1 and not c.closed
    sink.open.set()
    r = await sink.wait_for(lambda m: m.get("id") == 2, timeout=20)
    assert r["error"]["code"] == -32000 and r["error"]["data"] == {"resync": True}
    assert (await sink.wait_for(lambda m: m.get("method") == "_gw/resync"))["params"] == {"sessionId": "ov"}
    assert not c.closed and not c.replays and not c.holds


# ---------------------------------------------------------------- app.py: why a socket ended
def test_ws_disconnect_records_the_reason(stack, monkeypatch):
    from starlette.testclient import TestClient

    from goose_web import app as gw_app
    from test_release_fixes import WS, make_app, mk_user
    _, db, auth, c, _ = stack()
    _, token = auth.create_api_token(mk_user(db, "alice"), "script", None)
    got = []
    monkeypatch.setattr(gw_app.activity, "record", lambda action, **kw: got.append((action, kw)))

    class Up:
        async def from_client(self, client, msg):
            if msg["method"] == "x/full":
                client.disconnect("unread", kind="queue-full")   # what Client._overflow does past the hard cap
            elif msg["method"] == "x/kick":
                client.disconnect("signed out")                  # SC-3
            else:
                client.send({"jsonrpc": "2.0", "id": msg.get("id"), "result": {}})
    c.upstream_for = lambda user: Up()
    hdr = {"Authorization": f"Bearer {token}"}
    with TestClient(make_app(c), base_url="http://localhost") as client:
        with client.websocket_connect(WS, headers=hdr) as ws:
            ws.send_json({"jsonrpc": "2.0", "id": 1, "method": "session/list"})
            ws.receive_json()
        for meth in ("x/full", "x/kick"):
            with client.websocket_connect(WS, headers=hdr) as ws:
                ws.send_json({"jsonrpc": "2.0", "id": 2, "method": meth})
                with pytest.raises(Exception):
                    ws.receive_json()
    reasons = [kw["detail"]["reason"] for action, kw in got if action == "ws.disconnect"]
    assert reasons == ["client", "queue-full", "kick"]


from test_release_fixes import stack  # noqa: E402,F401  (the fixture above)


# ---------------------------------------------------------------- front-end wiring (read from the sources)
def _js(rel):
    return (JS / rel).read_text(encoding="utf-8")


def test_rpc_backoff_resets_only_after_a_stable_socket_and_load_has_a_timeout():
    rpc = _js("rpc.js")
    assert "export const STABLE_MS = 10000;" in rpc
    assert "if (wasReady && Date.now() - (this.readyAt || 0) >= STABLE_MS) this.attempt = 0;" in rpc
    on_open = rpc.split("async onOpen(ws)")[1].split("onClose(ws, ev)")[0]
    assert "this.attempt = 0" not in on_open and "this.readyAt = Date.now()" in on_open
    assert "export const LOAD_TIMEOUT_MS = 180000;" in rpc
    assert "const METHOD_TIMEOUTS = { 'session/load': LOAD_TIMEOUT_MS };" in rpc
    long_methods = re.search(r"const LONG_METHODS = new Set\(\[([^\]]*)\]\)", rpc).group(1)
    assert "'session/load'" not in long_methods
    assert "method in METHOD_TIMEOUTS ? METHOD_TIMEOUTS[method]" in rpc
    assert "if (Array.isArray(msg)) { msg.forEach((m) => this.dispatch(m)); return; }" in rpc   # replay batches


def test_chat_load_retries_only_transient_errors_and_shares_a_load_in_flight():
    cs = _js("chatsession.js")
    assert "export const LOAD_RETRY_DELAYS = [500, 1000, 2000, 4000];" in cs
    assert "const LOAD_NO_RETRY = new Set([-32002, -32602, -32003]);" in cs
    fn = cs.split("export function retryableLoadError(e) {")[1].split("\n}")[0]
    assert "LOAD_NO_RETRY.has(e.code)" in fn
    for code in ("e.disconnected", "'disconnected'", "'timeout'", "-32000"):
        assert code in fn
    load = cs.split("  async load() {")[1].split("  async loadOnce() {")[0]
    assert "retry >= LOAD_RETRY_DELAYS.length || !retryableLoadError(e)" in load
    assert "setTimeout(r, LOAD_RETRY_DELAYS[retry])" in load
    assert "e.attempt = retry; e.attempts = LOAD_RETRY_DELAYS.length;" in load
    assert "rpc.call('session/load'" in cs.split("  async loadOnce() {")[1].split("\n  }\n")[0]
    reload = cs.split("  reload() {")[1].split("\n  }\n")[0]
    assert "if (this.loading && this.loadPromise) return this.loadPromise;" in reload
    resync = cs.split("  resync() {")[1].split("\n  }\n")[0]
    assert "if (this.loading) { this.resyncPending = true; return this.loadPromise; }" in resync
    assert "return this.reload();" in resync
    assert "if (this.loaded && this.resyncPending) { this.resyncPending = false; this.reload()" in load
    rs = cs.split("export function resyncChat(p) {")[1].split("\n}")[0]
    assert "if (c.id === currentId) c.resync()" in rs and "c.loaded = false" in rs


def test_app_handles_resync_and_keeps_the_hello_reload():
    app = _js("app.js")
    assert "rpc.on('_gw/resync', (p) => resyncChat(p || {}));" in app
    assert re.search(r"import \{[^}]*\bresyncChat\b[^}]*\} from './chatsession\.js'", app)
    hello = app.split("rpc.on('hello', (hello) => {")[1].split("\n});")[0]
    assert "if (c === cur) c.reload().catch(() => {});" in hello


def test_open_error_texts():
    ui = _js("ui.js")
    fn = ui.split("export function openErrMsg(e, { cwd = '' } = {}) {")[1].split("\n}")[0]
    assert "if (code === -32002) text = 'This chat no longer exists';" in fn
    assert "code === -32602 && /director/i.test(raw)) text = \"This chat's folder no longer exists: \" + (cwd" in fn
    assert "code === -32003) text = raw.replace(/^forbidden:\\s*/i, '')" in fn
    assert "'The connection dropped while opening (attempt ' + (e.attempt || 1) + '/' + (e.attempts || 4) + ')'" in fn
    assert "bits.push('code ' + code)" in fn and "JSON.stringify(e.data)" in fn
    chat = _js("views/chat.js")
    assert "'Could not open this session', openErrMsg(chat.error, { cwd: chat.cwd })" in chat
