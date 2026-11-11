"""FIX deploy-interrupts-running-turns (1.16.0): the deploy's idle check asks the gateway what runs (every worker, long
tool calls and sub-agents included, permission requests, scheduler jobs), and the gateway drains before a restart."""
import asyncio
import json
import os
import socket
import time

import pytest
import websockets

from goose_web import control
from goose_web.__main__ import main as cli_main
from goose_web.config import Settings
from goose_web.db import Database
from goose_web.hub import DRAIN_REFUSAL, RPC_DRAINING, Hub
from test_hub import FakeAgent, FakeWorkers, mk_client
from test_live_state import SteerAgent


class SchedWorkers(FakeWorkers):
    def __init__(self, port, scheduler=True):
        super().__init__(port)
        self.workers["alice"].scheduler = scheduler

    def get(self, key):
        return self.workers.get(key)


class JobAgent(SteerAgent):
    """SteerAgent whose scheduler runs one job (Goose's schedules/list shape)."""

    def __init__(self, jobs=None, error=None):
        super().__init__()
        self.jobs = jobs if jobs is not None else [
            {"id": "tqqq-macro", "cron": "0 * * * *", "currentlyRunning": True, "currentSessionId": "20261111_7",
             "jobStartTime": "2026-11-11T09:00:00Z"},
            {"id": "idle-job", "cron": "0 0 * * *", "currentlyRunning": False}]
        self.error = error
        self.lists = 0

    async def handler(self, ws):
        self.ws = ws
        async for raw in ws:
            m = json.loads(raw)
            if m.get("method") == "_goose/unstable/schedules/list":
                self.lists += 1
                if self.error:
                    await ws.send(json.dumps({"jsonrpc": "2.0", "id": m["id"], "error": self.error}))
                else:
                    await ws.send(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"jobs": self.jobs}}))
                continue
            await self._one(ws, m)

    async def _one(self, ws, m):   # SteerAgent's handling of one frame
        meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
        if meth == "initialize":
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1}}))
        elif meth == "session/new":
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"sessionId": "s1"}}))
        elif meth == "session/prompt":
            self.prompt = (mid, p["sessionId"])
            await ws.send(self.upd(p["sessionId"], {"sessionUpdate": "session_info_update",
                                                    "_meta": {"goose": {"activeRunId": "run-1"}}}))
        elif mid is not None:
            await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {}}))


async def _hub(agent, workers_cls=FakeWorkers, **kw):
    server = await websockets.serve(agent.handler, "127.0.0.1", 0)
    hub = Hub(workers_cls(server.sockets[0].getsockname()[1], **kw))
    hub.start()
    return hub, server


async def _prompt(hub, text="wait for a 30-minute tool call"):
    up = hub.upstream("alice", "alice")
    c, s = mk_client()
    hub.attach(up, c)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": "session/new",
                             "params": {"cwd": os.path.abspath("/ws/p")}})
    await s.wait_for(lambda m: m.get("id") == 1)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                             "params": {"sessionId": "s1", "prompt": [{"type": "text", "text": text}]}})
    await s.wait_for(lambda m: (m.get("params") or {}).get("update", {}).get("_meta", {}).get("goose", {})
                     .get("activeRunId") == "run-1")
    return up, c, s


async def test_a_turn_waiting_on_a_long_tool_call_is_busy():
    """The incident: a turn inside a long tool call (no CPU, no traffic) must count as running."""
    agent = SteerAgent()
    hub, server = await _hub(agent)
    try:
        assert await hub.busy_report() == []
        up, c, s = await _prompt(hub)
        busy = await hub.busy_report()
        assert [(b["profile"], b["sessionId"], b["kind"], b["status"]) for b in busy] == [("alice", "s1", "turn", "working")]
        assert "prompt(s) waiting for Goose" in busy[0]["detail"]
        # the tab goes away: the turn still runs, still busy
        hub.detach(up, c)
        assert [b["sessionId"] for b in await hub.busy_report()] == ["s1"]
        await agent.end("end_turn")
        for _ in range(50):
            if not await hub.busy_report():
                break
            await asyncio.sleep(0.02)
        assert await hub.busy_report() == []
    finally:
        server.close()
        await server.wait_closed()


async def test_a_pending_permission_request_is_busy():
    agent = FakeAgent()
    hub, server = await _hub(agent)
    try:
        up = hub.upstream("alice", "alice")
        c, s = mk_client()
        hub.attach(up, c)
        await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": "session/new",
                                 "params": {"cwd": os.path.abspath("/ws/p")}})
        sid = (await s.wait_for(lambda m: m.get("id") == 1))["result"]["sessionId"]
        await up.from_client(c, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                                 "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "hi"}]}})
        await s.wait_for(lambda m: m.get("method") == "session/request_permission")
        busy = await hub.busy_report()
        assert [(b["sessionId"], b["kind"]) for b in busy] == [(sid, "permission")]
    finally:
        server.close()
        await server.wait_closed()


async def test_scheduler_jobs_in_a_gateway_worker_are_busy():
    agent = JobAgent()
    hub, server = await _hub(agent, SchedWorkers)
    try:
        hub.upstream("alice", "alice")
        busy = await hub.busy_report()
        assert [(b["kind"], b["sessionId"], b["title"]) for b in busy] == [
            ("schedule", "20261111_7", "scheduled job tqqq-macro")]
        assert busy[0]["since"] == pytest.approx(1794387600.0)
        agent.jobs = [{"id": "idle-job", "currentlyRunning": False}]
        assert await hub.busy_report() == []
        # a worker without the scheduler is not asked
        hub.workers.workers["alice"].scheduler = False
        n = agent.lists
        assert await hub.busy_report() == []
        assert agent.lists == n
    finally:
        server.close()
        await server.wait_closed()


async def test_scheduler_list_errors():
    agent = JobAgent(error={"code": -32601, "message": "Method not found"})
    hub, server = await _hub(agent, SchedWorkers)
    try:
        hub.upstream("alice", "alice")
        assert await hub.busy_report() == []          # an old Goose without the schedules API: nothing to ask
        agent.error = {"code": -32603, "message": "scheduler not ready"}
        busy = await hub.busy_report()                # anything else: unknown = do not restart
        assert busy[0]["kind"] == "schedule" and busy[0]["status"] == "unknown"
        assert "scheduler not ready" in busy[0]["detail"]
    finally:
        server.close()
        await server.wait_closed()


async def test_drain_refuses_new_prompts_tells_every_tab_and_ends():
    agent = SteerAgent()
    hub, server = await _hub(agent)
    try:
        up = hub.upstream("alice", "alice")
        c, s = mk_client()
        hub.attach(up, c)
        await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": "session/new",
                                 "params": {"cwd": os.path.abspath("/ws/p")}})
        await s.wait_for(lambda m: m.get("id") == 1)
        hub.set_draining(60, "deploy test")
        note = await s.wait_for(lambda m: m.get("method") == "_gw/notice")
        assert note["params"]["kind"] == "restart" and "restarts for an update" in note["params"]["message"]
        await up.from_client(c, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                                 "params": {"sessionId": "s1", "prompt": [{"type": "text", "text": "x"}]}})
        err = await s.wait_for(lambda m: m.get("id") == 2)
        assert err["error"] == {"code": RPC_DRAINING, "message": DRAIN_REFUSAL}
        assert agent.prompt is None                   # never reached Goose
        assert up.starting == 0 and await hub.busy_report() == []
        # a second hello during the drain says so
        await hub.gw_method(up, c, {"jsonrpc": "2.0", "id": 3, "method": "_gw/hello", "params": {}})
        assert (await s.wait_for(lambda m: m.get("id") == 3))["result"]["draining"] is True
        # it ends by itself
        hub.draining["until"] = time.time() - 1
        hub.expire_drain()
        assert hub.draining is None
        await s.wait_for(lambda m: m.get("method") == "_gw/notice" and "postponed" in m["params"]["message"])
        await up.from_client(c, {"jsonrpc": "2.0", "id": 4, "method": "session/prompt",
                                 "params": {"sessionId": "s1", "prompt": [{"type": "text", "text": "y"}]}})
        await s.wait_for(lambda m: (m.get("params") or {}).get("update", {}).get("_meta", {}).get("goose", {})
                         .get("activeRunId") == "run-1")
        assert [b["sessionId"] for b in await hub.busy_report()] == ["s1"]
    finally:
        server.close()
        await server.wait_closed()


async def test_a_prompt_still_being_checked_counts_as_busy():
    """Between the drain check and Goose (prompt guard, worker start-up) a prompt is `starting`: busy."""
    agent = SteerAgent()
    hub, server = await _hub(agent)
    try:
        up = hub.upstream("alice", "alice")
        c, s = mk_client()
        hub.attach(up, c)
        gate = asyncio.Event()
        orig = up._from_client

        async def slow(client, msg):
            await gate.wait()
            await orig(client, msg)
        up._from_client = slow
        t = asyncio.create_task(up.from_client(c, {"jsonrpc": "2.0", "id": 9, "method": "session/prompt",
                                                   "params": {"sessionId": "s1", "prompt": []}}))
        await asyncio.sleep(0.05)
        busy = await hub.busy_report()
        assert [b["kind"] for b in busy] == ["starting"]
        assert up.activity()[1] == 1
        gate.set()
        await t
        assert up.starting == 0
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------- the control channel (files) and the CLI
def _settings(tmp_path, port=1):
    return Settings({"paths": {"profiles_root": str(tmp_path), "system_dir": str(tmp_path / "_system")},
                     "server": {"host": "127.0.0.1", "port": port}}, None)


async def test_control_channel_answers_status_drain_undrain(tmp_path):
    agent = SteerAgent()
    hub, server = await _hub(agent)
    st = _settings(tmp_path)
    ch = control.ControlChannel(hub, st, "9.9.9")
    ch.start()
    try:
        info = json.loads((tmp_path / "_system" / "run" / "gateway.json").read_text())
        assert info["pid"] == os.getpid() and info["protocol"] == control.PROTOCOL
        r = await asyncio.to_thread(control.request, st, "status", timeout=10)
        assert r["source"] == "gateway" and r["busy"] == [] and not control.is_busy(r)
        assert control.describe(r)[0].startswith("IDLE")
        await _prompt(hub)
        r = await asyncio.to_thread(control.request, st, "drain", seconds=30, reason="deploy abc", timeout=10)
        assert control.is_busy(r) and r["draining"]["reason"] == "deploy abc"
        assert hub.draining is not None
        lines = control.describe(r)
        assert lines[0].startswith("BUSY: 1 running (alice/s1)") and "[source: gateway]" in lines[0]
        assert any("turn: alice/s1 working since" in x for x in lines)
        r = await asyncio.to_thread(control.request, st, "undrain", timeout=10)
        assert hub.draining is None and r["draining"] is None
        assert not list((tmp_path / "_system" / "run").glob("re*-*.json"))   # requests and answers cleaned up
        r = await asyncio.to_thread(control.request, st, "bogus", timeout=10)
        assert r.get("unknown") and "unknown action" in r["note"]
    finally:
        ch.stop()
        server.close()
        await server.wait_closed()
    assert not (tmp_path / "_system" / "run" / "gateway.json").exists()


def _mark_db(tmp_path, status="working"):
    (tmp_path / "_system").mkdir(parents=True, exist_ok=True)
    db = Database(tmp_path / "_system" / "goose-web.db")
    db.set_chat_state("dcb", "20261104_9", "mark", {"status": status, "since": time.time(), "title": "Long job"})
    db.set_chat_state("dcb", "20261104_8", "mark", {"status": "done", "since": time.time(), "title": "Finished"})
    db.close()


def test_old_gateway_falls_back_to_database_marks(tmp_path):
    """1.15.x does not answer the channel: its herd marks (spec 019) say what runs."""
    lsn = socket.socket()
    lsn.bind(("127.0.0.1", 0))
    lsn.listen(64)
    try:
        st = _settings(tmp_path, lsn.getsockname()[1])
        _mark_db(tmp_path)
        r = control.request(st, "drain", timeout=1)
        assert r["source"] == "database" and control.is_busy(r)
        assert [(b["sessionId"], b["kind"]) for b in r["busy"]] == [("20261104_9", "turn")]
        assert "cannot drain" in r["note"]
        _mark_db(tmp_path, "needs_you")
        assert control.request(st)["busy"][0]["kind"] == "permission"
        _mark_db(tmp_path, "done")
        assert not control.is_busy(control.request(st))
    finally:
        lsn.close()


def test_not_running_is_idle_and_a_silent_new_gateway_is_unknown(tmp_path):
    st = _settings(tmp_path, 1)   # nothing listens on port 1
    _mark_db(tmp_path)            # a stale "working" mark of a gateway that is gone
    r = control.request(st, timeout=1)
    assert r["running"] is False and not control.is_busy(r)
    # a 1.16 gateway (live pid) that does not answer while its port is open: unknown = busy
    run = tmp_path / "_system" / "run"
    run.mkdir(parents=True)
    (run / "gateway.json").write_text(json.dumps({"pid": os.getpid(), "version": "1.16.0", "protocol": 1}))
    lsn = socket.socket()
    lsn.bind(("127.0.0.1", 0))
    lsn.listen(64)
    try:
        st = _settings(tmp_path, lsn.getsockname()[1])
        r = control.request(st, timeout=0.5)
        assert r.get("unknown") and control.is_busy(r) and "did not answer" in r["note"]
        assert not list(run.glob("req-*.json"))
    finally:
        lsn.close()
    # a dead pid in gateway.json (hard kill) with nothing listening: not running
    (run / "gateway.json").write_text(json.dumps({"pid": 999999999, "protocol": 1}))
    assert control.pid_alive(999999999) is False
    assert control.request(_settings(tmp_path, 1), timeout=0.5)["running"] is False


def test_cli_exit_codes(tmp_path, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"paths:\n  profiles_root: '{tmp_path.as_posix()}'\nserver:\n  host: 127.0.0.1\n  port: 1\n",
                   encoding="utf-8")
    assert cli_main(["--config", str(cfg), "gateway", "status"]) == control.EXIT_IDLE
    assert "IDLE" in capsys.readouterr().out
    lsn = socket.socket()
    lsn.bind(("127.0.0.1", 0))
    lsn.listen(64)
    try:
        cfg.write_text(cfg.read_text().replace("port: 1", f"port: {lsn.getsockname()[1]}"), encoding="utf-8")
        _mark_db(tmp_path)
        assert cli_main(["--config", str(cfg), "gateway", "status", "--json"]) == control.EXIT_BUSY
        out = json.loads(capsys.readouterr().out)
        assert out["busy"][0]["sessionId"] == "20261104_9"
    finally:
        lsn.close()
