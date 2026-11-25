"""FIX scheduled-runs-in-members-history: a member's scheduled runs land in the member's own chat list, in a folder
the member may open, and nobody writes into a chat while the worker's scheduler is still writing it.

Goose 1.57 gives a scheduled run the worker process's own folder as working folder (scheduler/full.rs:
`create_session(std::env::current_dir()?, ..., SessionType::Scheduled)`). The sandboxed backends start a member's
worker in `<profile>\\workspace`; a worker without the sandbox started in the profile root, so the member's runs
worked next to the profile's config and secrets and the member could not open them ("folder not allowed")."""
import asyncio
import json
import logging
import os
import types

import pytest
import websockets

from goose_web import hub as hubmod
from goose_web import policy as pol
from goose_web.config import Settings
from goose_web.hub import Client, Hub
from goose_web.workers import Worker, start_dir, worker_start_dir

CWD = os.path.abspath("/ws/p")


# ------------------------------------------------------------------ where a worker starts
def mkw(path_root, native=False):
    return Worker(key="k", username="k", path_root=path_root, native=native, port=0, secret="x")


def test_an_isolated_worker_starts_in_the_members_workspace(tmp_path):
    root = tmp_path / "profiles" / "alice"
    (root / "workspace").mkdir(parents=True)
    assert worker_start_dir(mkw(str(root))) == str(root / "workspace")


def test_without_a_workspace_the_profile_root_is_used(tmp_path):
    root = tmp_path / "profiles" / "bob"
    root.mkdir(parents=True)
    assert worker_start_dir(mkw(str(root))) == str(root)


def test_the_native_profile_keeps_its_root_or_the_home_folder(tmp_path):
    root = tmp_path / "native"
    (root / "workspace").mkdir(parents=True)   # a folder of that name in a native root changes nothing
    assert worker_start_dir(mkw(str(root), native=True)) == str(root)
    assert worker_start_dir(mkw(None, native=True)) == os.path.expanduser("~")
    assert worker_start_dir(mkw(str(tmp_path / "gone"))) == os.path.expanduser("~")


def test_the_start_without_sandbox_really_starts_goose_in_the_workspace(tmp_path, monkeypatch):
    """S-6: WorkerManager._start itself, with a fake Popen (not a reading of the source)."""
    import goose_web.workers as wk
    from tests.test_sec_web import make_settings
    wm = wk.WorkerManager(make_settings(tmp_path))
    root = tmp_path / "profiles" / "alice"
    (root / "workspace").mkdir(parents=True)
    w = wm.register("alice", "alice", str(root), False, [], scheduler_allowed=True, plugins_allowed=False)
    seen = {}

    class Proc:
        pid, returncode = 4242, 1

        def poll(self):
            return 1   # exits at once: _start stops waiting

    def popen(args, **kw):
        seen["cwd"], seen["args"] = kw.get("cwd"), args
        return Proc()
    monkeypatch.setattr(wk.subprocess, "Popen", popen)
    monkeypatch.setattr(wk, "_Job", lambda: types.SimpleNamespace(add=lambda p: None, close=lambda: None))
    monkeypatch.setattr(wm, "job", types.SimpleNamespace(add=lambda p: None))
    with pytest.raises(RuntimeError, match="exited"):
        asyncio.run(wm._start(w))
    assert seen["cwd"] == str(root / "workspace") and "--enable-scheduler" in seen["args"]


def test_both_sandboxed_backends_use_the_same_rule():
    """The AppContainer and MXC starts (heavy to run here) call the same start_dir, with the profile root as fallback."""
    src = open(os.path.join(os.path.dirname(hubmod.__file__), "workers.py"), encoding="utf-8").read()
    assert src.count('cwd = start_dir(spec["profile_root"], False, w.plugins_allowed, w.key, '
                     'fallback=spec["profile_root"])') == 2
    assert "cwd = worker_start_dir(w)" in src


# ------------------------------------------------------------------ S-1: the plugin rule for the start folder
def plugin(ws, name="hooks"):
    (ws / ".agents" / "plugins" / name).mkdir(parents=True)


def test_a_workspace_with_plugins_is_not_the_start_folder_without_allow_shell(tmp_path, caplog):
    root = tmp_path / "profiles" / "carol"
    plugin(root / "workspace")
    with caplog.at_level(logging.WARNING):
        assert start_dir(str(root), False, plugins_allowed=False, key="carol") == str(root)
    assert "may not use plugins" in caplog.text and "hooks" in caplog.text
    assert start_dir(str(root), False, plugins_allowed=True) == str(root / "workspace")   # allow_shell: as session/new
    assert start_dir(str(tmp_path / "gone"), False, False, fallback="X") == "X"


def test_the_plugin_permission_follows_the_member_and_restarts_a_worker_when_it_changes(tmp_path):
    from goose_web.workers import WorkerManager
    from tests.test_sec_web import make_settings
    wm = WorkerManager(make_settings(tmp_path))
    w = wm.register("dave", "dave", str(tmp_path / "p"), False, [])
    assert w.plugins_allowed is False                      # a new isolated worker: fail safe
    assert wm.register("admin", "admin", None, True, []).plugins_allowed is True   # the native profile
    w.state = "ready"
    wm.register("dave", "dave", str(tmp_path / "p"), False, [])                    # not said: kept, no restart
    assert w.plugins_allowed is False and w.restart_pending is False
    wm.register("dave", "dave", str(tmp_path / "p"), False, [], plugins_allowed=True)
    assert w.plugins_allowed is True and w.restart_pending is True


def test_ctx_plugins_allowed_is_allow_shell_for_members():
    from goose_web.context import Ctx

    class _C:
        pass
    c = _C()
    c.profiles = types.SimpleNamespace(is_native=lambda u: u.get("username") == "native")
    c.policy_for = lambda u: {"allow_shell": u.get("username") == "shelly"}
    assert Ctx.plugins_allowed(c, {"username": "shelly", "role": "user"}) is True
    assert Ctx.plugins_allowed(c, {"username": "nora", "role": "user"}) is False
    assert Ctx.plugins_allowed(c, {"username": "nora", "role": "admin"}) is True
    assert Ctx.plugins_allowed(c, {"username": "native", "role": "user"}) is True


# ------------------------------------------------------------------ no second writer while a scheduled job runs
class Agent:
    def __init__(self):
        self.calls = []
        self.jobs = []
        self.list_error = None
        self.n = 0

    def methods(self, sid=None):
        return [m for m, s in self.calls if sid is None or s == sid]

    async def handler(self, ws):
        async for raw in ws:
            m = json.loads(raw)
            if "method" not in m:
                continue
            meth, mid, p = m["method"], m.get("id"), m.get("params") or {}
            self.calls.append((meth, p.get("sessionId")))
            res = {}
            if meth == "initialize":
                res = {"protocolVersion": 1, "agentCapabilities": {"loadSession": True},
                       "agentInfo": {"name": "goose", "version": "1.57.0"}}
            elif meth == "session/new":
                self.n += 1
                res = {"sessionId": f"s{self.n}"}
            elif meth == "session/prompt":
                res = {"stopReason": "end_turn"}
            elif meth == hubmod.P_SCHEDULES_LIST:
                if self.list_error:
                    await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "error": self.list_error}))
                    continue
                res = {"jobs": self.jobs}
            elif meth == hubmod.SESSION_INFO:
                res = {"session": {"sessionId": p.get("sessionId"), "cwd": CWD}}
            if mid is not None:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}))


class FakeWorkers:
    def __init__(self, port, scheduler):
        self.workers = {"alice": Worker(key="alice", username="alice", path_root=None, native=False, port=port,
                                        secret="x", state="ready", scheduler=scheduler)}
        self.s = Settings({"goose": {"session_unload_minutes": 0}}, None)
        self.activity = None
        self.on_restart = None

    async def ensure(self, key):
        return self.workers[key]


class Sink:
    def __init__(self):
        self.msgs = []
        self.event = asyncio.Event()

    async def send(self, raw):
        m = json.loads(raw)
        self.msgs.extend(m if isinstance(m, list) else [m])
        self.event.set()

    async def wait_for(self, mid, timeout=5):
        end = asyncio.get_running_loop().time() + timeout
        while True:
            for m in self.msgs:
                if m.get("id") == mid:
                    return m
            self.event.clear()
            left = end - asyncio.get_running_loop().time()
            if left <= 0:
                raise AssertionError(f"no answer to {mid}; got {self.msgs}")
            try:
                await asyncio.wait_for(self.event.wait(), left)
            except asyncio.TimeoutError:
                pass


def tab(role="admin", policy=None, roots=()):
    sink = Sink()
    c = Client(sink.send, {"id": 1 if role == "admin" else 2, "username": "alice", "role": role},
               policy or {}, list(roots))
    c.start()
    return c, sink


@pytest.fixture
async def mk(monkeypatch):
    servers = []

    async def make(scheduler=True, cache=0.0):
        monkeypatch.setattr(hubmod, "SCHEDULED_CACHE_SECONDS", cache, raising=False)   # 0 = every check asks
        agent = Agent()
        server = await websockets.serve(agent.handler, "127.0.0.1", 0)
        servers.append(server)
        hub = Hub(FakeWorkers(server.sockets[0].getsockname()[1], scheduler))
        hub.start()
        up = hub.upstream("alice", "alice")
        c, sink = tab()
        hub.attach(up, c)
        await up.ensure()
        up.unloader.stop()
        return agent, hub, up, c, sink
    yield make
    for s in servers:
        s.close()
        await s.wait_closed()


def prompt(mid, sid):
    return {"jsonrpc": "2.0", "id": mid, "method": "session/prompt",
            "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "and now?"}]}}


def running(sid):
    return [{"id": "daily-report", "currentlyRunning": True, "currentSessionId": sid,
             "jobStartTime": "2026-11-25T05:00:00Z"}]


async def test_a_prompt_to_a_chat_the_scheduler_is_writing_is_refused(mk):
    agent, hub, up, c, sink = await mk()
    agent.jobs = running("run-1")
    await up.from_client(c, prompt(1, "run-1"))
    r = await sink.wait_for(1)
    assert r["error"]["code"] == hubmod.RPC_ELSEWHERE and "scheduled job" in r["error"]["message"]
    assert "session/prompt" not in agent.methods("run-1")
    await up.from_client(c, prompt(2, "other-chat"))   # another chat of the same profile is not affected
    assert "error" not in await sink.wait_for(2)


async def test_once_the_run_has_finished_the_chat_can_be_continued(mk):
    agent, hub, up, c, sink = await mk()
    agent.jobs = running("run-1")
    await up.from_client(c, prompt(1, "run-1"))
    assert "error" in await sink.wait_for(1)
    agent.jobs = [{"id": "daily-report", "currentlyRunning": False}]
    await up.from_client(c, prompt(2, "run-1"))
    assert "error" not in await sink.wait_for(2)
    assert agent.methods("run-1").count("session/prompt") == 1


async def test_an_edit_of_a_chat_the_scheduler_is_writing_is_refused(mk):
    agent, hub, up, c, sink = await mk()
    agent.jobs = running("run-1")
    await up.from_client(c, {"jsonrpc": "2.0", "id": 3, "method": hubmod.TRUNCATE,
                             "params": {"sessionId": "run-1", "truncateFrom": 1795000000}})
    r = await sink.wait_for(3)
    assert r["error"]["code"] == hubmod.RPC_ELSEWHERE
    assert hubmod.TRUNCATE not in agent.methods("run-1")


async def test_a_worker_without_a_scheduler_is_never_asked(mk):
    agent, hub, up, c, sink = await mk(scheduler=False)
    agent.jobs = running("run-1")   # (it would not have any)
    await up.from_client(c, prompt(1, "run-1"))
    assert "error" not in await sink.wait_for(1)
    assert hubmod.P_SCHEDULES_LIST not in agent.methods()


async def test_a_scheduler_that_cannot_answer_refuses_nothing(mk):
    agent, hub, up, c, sink = await mk()
    agent.list_error = {"code": -32603, "message": "scheduler busy"}
    await up.from_client(c, prompt(1, "run-1"))
    assert "error" not in await sink.wait_for(1)


async def test_a_member_is_refused_before_anything_is_loaded(mk):
    agent, hub, up, c, sink = await mk()
    agent.jobs = running("run-9")
    p = {**pol.DEFAULT_POLICY, "allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}
    m, msink = tab(role="user", policy=p, roots=(CWD,))
    hub.attach(up, m)
    await up.from_client(m, prompt(4, "run-9"))
    r = await msink.wait_for(4)
    assert r["error"]["code"] == hubmod.RPC_ELSEWHERE
    assert agent.methods("run-9") == []   # neither loaded (M-1) nor prompted


async def test_two_tabs_sending_at_once_share_one_question_and_both_are_refused(mk):
    """S-2: at the real 2 s cache, two prompts at once: one schedules/list, both judged on its answer."""
    agent, hub, up, c, sink = await mk(cache=2.0)
    agent.jobs = running("run-1")
    c2, sink2 = tab()
    hub.attach(up, c2)
    await asyncio.gather(up.from_client(c, prompt(1, "run-1")), up.from_client(c2, prompt(2, "run-1")))
    r1, r2 = await sink.wait_for(1), await sink2.wait_for(2)
    assert r1["error"]["code"] == r2["error"]["code"] == hubmod.RPC_ELSEWHERE
    assert agent.methods().count(hubmod.P_SCHEDULES_LIST) == 1
    await up.from_client(c, prompt(3, "run-1"))            # within the 2 s: the same answer, no new question
    assert "error" in await sink.wait_for(3) and agent.methods().count(hubmod.P_SCHEDULES_LIST) == 1


async def test_a_worker_that_is_not_running_is_neither_asked_nor_started_by_the_check(mk):
    """S-3: a stopped worker has no running job."""
    agent, hub, up, c, sink = await mk()
    agent.jobs = running("run-1")
    hub.workers.workers["alice"].state = "stopped"
    assert await up._written_by_scheduler("run-1") is False
    assert hubmod.P_SCHEDULES_LIST not in agent.methods()


async def test_a_scheduler_that_does_not_answer_is_not_asked_again_for_a_while(mk, caplog):
    """S-5: fail open, one warning, and the next prompts do not wait for it again."""
    agent, hub, up, c, sink = await mk()
    agent.list_error = {"code": -32603, "message": "scheduler busy"}
    with caplog.at_level(logging.WARNING):
        for i in (1, 2, 3):
            await up.from_client(c, prompt(i, "run-1"))
            assert "error" not in await sink.wait_for(i)
    assert agent.methods().count(hubmod.P_SCHEDULES_LIST) == 1
    assert caplog.text.count("did not say which chats its jobs write") == 1
