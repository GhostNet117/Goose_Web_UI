"""FIX idle-sessions-keep-mcp-servers against a real `goose serve` (opt-in: GOOSE_WEB_TEST_GOOSE=1; the binary from
GOOSE_WEB_TEST_GOOSE_BINARY or `goose` on PATH). Every chat starts its own copy of a small stdio MCP server, started
through this virtual environment's python.exe (a launcher that runs the real interpreter as its child - the
launcher + child shape of uvx and venvs). Windows only (process listing through reaper.WinProcs). A throw-away
profile root and a provider that is never reached (a closed local port) are used."""
import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time

import httpx
import pytest

from goose_web.config import Settings
from goose_web.hub import Client, Hub
from goose_web.reaper import OrphanReaper, WinProcs
from goose_web.workers import Worker, _Job

pytestmark = pytest.mark.skipif(os.environ.get("GOOSE_WEB_TEST_GOOSE") != "1" or os.name != "nt",
                                reason="opt-in: GOOSE_WEB_TEST_GOOSE=1 (Windows, real goose)")

SERVER = r'''import json, sys, time
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("id") is None:
        continue
    if m.get("method") == "initialize":
        out = {"result": {"protocolVersion": (m.get("params") or {}).get("protocolVersion", "2025-03-26"),
                          "capabilities": {"tools": {}}, "serverInfo": {"name": "gw-probe", "version": "1"}}}
    elif m.get("method") == "tools/list":
        out = {"result": {"tools": []}}
    else:
        out = {"error": {"code": -32601, "message": "method not found"}}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], **out}) + "\n")
    sys.stdout.flush()
if "--ignore-eof" in sys.argv:
    time.sleep(600)       # a server that does not end when Goose closes its input
'''

LAUNCHER = "import subprocess, sys\nsys.exit(subprocess.call([sys.executable] + sys.argv[1:]))\n"


class Workers:
    def __init__(self, port, secret):
        self.workers = {"t": Worker(key="t", username="t", path_root=None, native=False, port=port, secret=secret,
                                    state="ready")}
        self.s = Settings({"goose": {"session_unload_minutes": 30, "max_loaded_sessions": 12}}, None)
        self.activity = None
        self.on_restart = None

    async def ensure(self, key):
        return self.workers[key]


def servers(script):
    """(direct children of a goose.exe, all processes) running the probe server."""
    w = WinProcs()
    rows = w.snapshot()
    exe = {pid: name.lower() for pid, _, name in rows}
    mine = [(pid, ppid) for pid, ppid, _ in rows if script.lower() in (w.cmdline(pid) or "").lower()]
    return [p for p, pp in mine if exe.get(pp) == "goose.exe"], [p for p, _ in mine]


async def wait_for(pred, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = await asyncio.to_thread(pred)
        if v:
            return v
        await asyncio.sleep(0.5)
    return await asyncio.to_thread(pred)


@contextlib.asynccontextmanager
async def real_goose(tmp_path, *server_args, launcher=False):
    goose = os.environ.get("GOOSE_WEB_TEST_GOOSE_BINARY") or shutil.which("goose")
    if not goose:
        pytest.skip("no goose binary")
    script = tmp_path / "gw_probe_server.py"
    script.write_text(SERVER, encoding="utf-8")
    cmd, args = sys.executable, [str(script), *server_args]   # the venv's python.exe: a launcher + interpreter pair
    if launcher:
        # a launcher that does not tie its child to itself (as uv's does not; Python's venv launcher does, with a
        # kill-on-close job of its own), on the base interpreter
        (tmp_path / "gw_launcher.py").write_text(LAUNCHER, encoding="utf-8")
        cmd, args = sys._base_executable, [str(tmp_path / "gw_launcher.py"), *args]
    cfg = tmp_path / "root" / "config" / "config.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"extensions": {"probe": {
        "enabled": True, "type": "stdio", "name": "probe", "cmd": cmd, "args": args, "timeout": 60,
        "envs": {}}}}), encoding="utf-8")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    secret = "t-" + os.urandom(8).hex()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GOOSE_")}
    env.update(GOOSE_PATH_ROOT=str(tmp_path / "root"), GOOSE_DISABLE_KEYRING="1", GOOSE_TELEMETRY_ENABLED="false",
               GOOSE_SERVER__SECRET_KEY=secret, GOOSE_PROVIDER="ollama", GOOSE_MODEL="none",
               OLLAMA_HOST="http://127.0.0.1:9")
    job = _Job()
    log = open(tmp_path / "goose.log", "wb")
    proc = subprocess.Popen([goose, "serve", "--host", "127.0.0.1", "--port", str(port), "--platform", "desktop"],
                            env=env, cwd=str(tmp_path), stdout=log, stderr=subprocess.STDOUT, creationflags=0x08000000)
    job.add(proc)
    try:
        async with httpx.AsyncClient() as h:
            for _ in range(120):
                try:
                    if (await h.get(f"http://127.0.0.1:{port}/status")).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
        hub = Hub(Workers(port, secret))
        up = hub.upstream("t", "t")
        msgs = []

        async def send(raw):
            msgs.append(json.loads(raw))
        c = Client(send, {"id": 1, "username": "t", "role": "admin"}, {}, [])
        c.start()
        hub.attach(up, c)
        await up.ensure()
        up.unloader.stop()

        async def call(mid, method, params, timeout=90):
            await up.from_client(c, {"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                for m in msgs:
                    if m.get("id") == mid:
                        return m
                await asyncio.sleep(0.1)
            raise AssertionError(f"no answer to {method}")
        yield {"up": up, "call": call, "script": script.name, "job": job, "config": cfg}
        await up.reset("test over")
    finally:
        job.terminate()
        job.close()
        log.close()


async def new_chats(g, n, cwd):
    sids = []
    for i in range(n):
        r = await g["call"](10 + i, "session/new", {"cwd": str(cwd), "mcpServers": []})
        assert "result" in r, r
        sids.append(r["result"]["sessionId"])
    direct = await wait_for(lambda: len(servers(g["script"])[0]) >= n and servers(g["script"]), 60)
    assert len(direct[0]) == n, direct           # one server per chat
    return sids


async def unload_all(g, sids):
    up = g["up"]
    for sid in sids:
        up.unloader.held[sid] = up.sessions[sid].last_touch = time.time() - 3600
    assert sorted(await up.unloader.tick()) == sorted(sids)


async def test_unloading_ends_the_servers_of_idle_chats_in_real_goose(tmp_path):
    async with real_goose(tmp_path) as g:
        up = g["up"]
        assert up.unloader.supported()
        sids = await new_chats(g, 3, tmp_path)
        assert up.unloader.loaded_count() == 3
        await unload_all(g, sids)
        left = await wait_for(lambda: not servers(g["script"])[1], 30)
        assert left is True, servers(g["script"])    # none left: not the launcher, not its child
        # a method that needs the agent of an unloaded chat (Goose answers -32002 "Session not found" for a closed
        # chat): the gateway loads the chat again first, and its server starts again (a prompt would do the same, but
        # would then wait for the unreachable model)
        r = await g["call"](20, "session/set_mode", {"sessionId": sids[0], "modeId": "approve"})
        assert "error" not in r, r
        assert await wait_for(lambda: len(servers(g["script"])[0]) == 1, 60), servers(g["script"])
        assert sids[0] in up.unloader.held and sids[0] not in up.unloader.unloaded


async def test_the_reaper_ends_what_goose_leaves_behind_in_real_goose(tmp_path):
    """The server ignores the end of its input: Goose ends the launcher (its direct child) 3 s after the close, and
    the launcher's child, the server, keeps running in the worker's job - the bug's shape on Windows (uvx)."""
    async with real_goose(tmp_path, "--ignore-eof", launcher=True) as g:
        sids = await new_chats(g, 2, tmp_path)
        reaper = OrphanReaper(Settings({"goose": {}}, None), workers=None, procs=WinProcs())
        target = {"key": "t", "username": "t", "handle": g["job"].handle, "config": g["config"]}
        assert await asyncio.to_thread(reaper.sweep, [target], 0.0, 120) == []
        trees = reaper.trees["t"]
        # 2 launchers (roots), their interpreters, and the console host each launcher has (conhost.exe)
        assert len({e["root"] for e in trees.values()}) == 2 and len(trees) >= 4
        await unload_all(g, sids)
        assert await wait_for(lambda: not servers(g["script"])[0], 30)        # Goose ended the launchers ...
        orphans = servers(g["script"])[1]
        assert len(orphans) == 2                                                # ... not their children
        assert await asyncio.to_thread(reaper.sweep, [target], 10.0, 120) == []   # cut off: the grace starts
        assert await asyncio.to_thread(reaper.sweep, [target], 100.0, 120) == []  # within the grace
        ended = await asyncio.to_thread(reaper.sweep, [target], 140.0, 120)
        assert set(orphans) <= {e["pid"] for e in ended}
        assert all(e["extension"] == "probe" for e in ended)
        assert sum("gw_probe_server.py" in e["commandLine"] for e in ended) == 2
        assert await wait_for(lambda: not servers(g["script"])[1], 10)
        goose_alive = [p for p, _, exe in WinProcs().snapshot() if exe.lower() == "goose.exe"
                       and p in WinProcs().job_pids(g["job"].handle)]
        assert goose_alive                                                      # the worker itself untouched
