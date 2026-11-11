"""Spec 014: Goose 1.50 compatibility (version caps) and brokered relays for sandboxed workers."""
import asyncio
import json
import os
import socket
import subprocess
import sys
import threading

import pytest

from goose_web import relay as rl
from goose_web import sandbox as sb
from goose_web.hub import Hub, goose_caps, parse_version
from tests.test_hub import mk_client

# A stdio ACP agent that reports Goose 1.50.1 and logs every request it gets (one JSON line each).
OLD_GOOSE = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m or "method" not in m:
        continue
    log.write(json.dumps(m) + "\n"); log.flush()
    meth = m["method"]
    if meth == "initialize":
        res = {"protocolVersion": 1, "agentInfo": {"name": "goose", "version": "1.50.1"}}
    elif meth == "_goose/unstable/tools/list":
        res = {"tools": [{"name": "shell"}, {"name": "text_editor"}]} if m["params"].get("extensionName") == "developer" else {"tools": []}
    else:
        res = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": res}) + "\n")
    sys.stdout.flush()
"""


def test_parse_version():
    assert parse_version("1.57.0") == (1, 57, 0) and parse_version("v1.50.1") == (1, 50, 1)
    assert parse_version("goose 1.50.1") == (1, 50, 1) and parse_version("") == ()


# Measured against every release binary 1.50.0 - 1.57.0 (`goose acp` probes, 2026-11-08):
# (toolCallScoped, toolshim, liveVoice, importWithoutSource, persistentSystemPrompt, compactTokenLimit)
MEASURED = {
    "1.50.0": (0, 0, 0, 0, 0, 0), "1.50.1": (0, 0, 0, 0, 0, 0), "1.51.0": (1, 1, 0, 0, 0, 0),
    "1.52.0": (1, 1, 1, 0, 0, 0), "1.53.0": (1, 1, 1, 0, 0, 0), "1.54.0": (1, 1, 1, 1, 0, 0),
    "1.55.0": (1, 1, 1, 1, 1, 1), "1.56.0": (1, 1, 1, 1, 1, 1), "1.57.0": (1, 1, 1, 1, 1, 1),
}


@pytest.mark.parametrize("ver", sorted(MEASURED))
def test_caps_match_measured_goose_behaviour(ver):
    c = goose_caps({"agentInfo": {"name": "goose", "version": ver}})
    keys = ("toolCallScoped", "toolshim", "liveVoice", "importWithoutSource", "persistentSystemPrompt", "compactTokenLimit")
    assert tuple(int(c[k]) for k in keys) == MEASURED[ver]
    assert c["supported"] and c["importNeedsSource"] == (not c["importWithoutSource"]) and c["version"] == ver


def test_caps_unknown_and_too_old():
    assert all(v for k, v in goose_caps(None).items() if k not in ("version", "importNeedsSource"))  # assume current
    assert not goose_caps({"agentInfo": {"version": "1.49.2"}})["supported"]


class _OldGooseWorkers:
    def __init__(self, log):
        from goose_web.workers import Worker
        self.log = log
        self.w = Worker(key="alice", username="alice", path_root=None, native=False, sandbox={"name": "t"})
        self.workers = {"alice": self.w}
        self.activity = self.on_restart = None

    async def ensure(self, key):
        if self.w.channel is None:
            self.w.proc = subprocess.Popen([sys.executable, "-c", OLD_GOOSE, self.log], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE)
            self.w.channel = sb.StdioChannel(self.w.proc, asyncio.get_running_loop())
            self.w.state = "ready"
        return self.w

    async def stop(self, key, reason=""):
        if self.w.proc:
            self.w.proc.kill()
            self.w.proc.wait()
        self.w.proc, self.w.channel, self.w.state = None, None, "stopped"


async def test_hub_adapts_to_goose_150(tmp_path):
    log = str(tmp_path / "requests.jsonl")
    workers = _OldGooseWorkers(log)
    hub = Hub(workers)
    hub.start()
    up = hub.upstream("alice", "alice")
    c, s = mk_client(role="admin")
    hub.attach(up, c)

    def sent(method):
        with open(log, encoding="utf-8") as f:
            return [m for m in map(json.loads, f) if m["method"] == method]

    async def call(i, method, params):
        await up.from_client(c, {"jsonrpc": "2.0", "id": i, "method": method, "params": params})
        return await s.wait_for(lambda m: m.get("id") == i)
    try:
        # tools/call: the tool must belong to the named extension (1.50 ignores extensionName)
        r = await call(1, "_goose/unstable/tools/call", {"sessionId": "s1", "extensionName": "developer", "name": "shell", "arguments": {}})
        assert "result" in r and up.caps()["version"] == "1.50.1"
        r = await call(2, "_goose/unstable/tools/call", {"sessionId": "s1", "extensionName": "developer", "name": "computercontroller__web_scrape", "arguments": {}})
        assert "error" in r and "does not belong" in r["error"]["message"]
        assert len(sent("_goose/unstable/tools/call")) == 1                         # the second never reached Goose
        # live voice does not exist before 1.57
        r = await call(3, "_goose/unstable/session/live-voice/availability", {"sessionId": "s1"})
        assert r["error"]["code"] == -32601 and "1.52" in r["error"]["message"]
        # session/import needs `source` on 1.50
        await call(4, "_goose/unstable/session/import", {"json": "{}"})
        assert sent("_goose/unstable/session/import")[-1]["params"]["source"] == "json"
        # per-chat system prompts are re-applied after a load (1.50-1.54 keep them in memory only); one per mode/key
        sp = "_goose/unstable/session/system-prompt/set"
        await call(5, sp, {"sessionId": "s1", "mode": "append", "key": "goose-web", "text": "Be brief."})
        await call(51, sp, {"sessionId": "s1", "mode": "set", "text": "Base."})
        await call(52, sp, {"sessionId": "s1", "mode": "set", "text": ""})                  # cleared again
        await call(6, "session/load", {"sessionId": "s1", "cwd": os.path.abspath("/ws"), "mcpServers": []})
        for _ in range(100):
            if len(sent(sp)) == 4:
                break
            await asyncio.sleep(0.02)
        again = sent(sp)
        assert len(again) == 4 and again[3]["params"] == {"sessionId": "s1", "mode": "append", "key": "goose-web", "text": "Be brief."}
    finally:
        await workers.stop("alice")


# ------------------------------------------------------------------ relays
def test_forward_ips_are_unique_loopback_addresses():
    ips = [rl.forward_ip(i) for i in range(1, 5000)]
    assert len(set(ips)) == len(ips)
    for ip in ips:
        a, b, c, d = map(int, ip.split("."))
        assert a == 127 and b == 64 and 0 <= c <= 255 and 1 <= d <= 254


def test_relay_specs_and_pipe_names():
    specs = rl.relay_specs("GooseWeb.ab12cd34.bob", 7, ["127.0.0.1:4000", "localhost:9000"])
    assert specs[0]["listen"] == rl.forward_ip(7) + ":4000" and specs[0]["target"] == "127.0.0.1:4000"
    assert specs == rl.relay_specs("GooseWeb.ab12cd34.bob", 7, ["127.0.0.1:4000", "localhost:9000"])  # stable spec
    # C-1: the pipe name is chosen per worker start, random and unguessable (not derived from user or target)
    names = {rl.new_pipe_name() for _ in range(50)}
    assert len(names) == 50 and all(n.startswith("\\\\.\\pipe\\goose-web-relay.") for n in names)
    assert all(len(n.rsplit(".", 1)[1]) == 32 for n in names)
    with pytest.raises(ValueError):
        rl.parse_target("4000")


def test_profile_urls_are_rewritten_and_restored(tmp_path):
    cfg = tmp_path / "config"
    (cfg / "custom_providers").mkdir(parents=True)
    (cfg / "config.yaml").write_text("OPENAI_HOST: http://127.0.0.1:4000\nOTHER: http://127.0.0.1:9999\n", encoding="utf-8")
    (cfg / "custom_providers" / "p.json").write_text('{"api_url": "http://localhost:4000/v1"}', encoding="utf-8")
    m = {"127.0.0.1:4000": "127.64.0.8:4000"}
    assert len(rl.rewrite_profile_urls(str(tmp_path), m)) == 2
    assert "//127.64.0.8:4000" in (cfg / "config.yaml").read_text(encoding="utf-8")
    assert "//127.0.0.1:9999" in (cfg / "config.yaml").read_text(encoding="utf-8")      # not listed: untouched
    assert "//127.64.0.8:4000/v1" in (cfg / "custom_providers" / "p.json").read_text(encoding="utf-8")
    assert rl.rewrite_profile_urls(str(tmp_path), m) == []                               # idempotent
    rl.restore_profile_urls(str(tmp_path), m)
    assert (cfg / "config.yaml").read_text(encoding="utf-8").startswith("OPENAI_HOST: http://127.0.0.1:4000")
    assert "//127.0.0.1:4000/v1" in (cfg / "custom_providers" / "p.json").read_text(encoding="utf-8")
    # undo_relays: restores from the record the worker wrote and forgets it
    rl.rewrite_profile_urls(str(tmp_path), m)
    state = tmp_path / "state"
    state.mkdir()
    (state / "GooseWeb.x.bob.relays.json").write_text(json.dumps(m), encoding="utf-8")
    assert len(rl.undo_relays(str(state), "GooseWeb.x.bob", str(tmp_path))) == 2
    assert not (state / "GooseWeb.x.bob.relays.json").exists()
    assert "//127.0.0.1:4000" in (cfg / "config.yaml").read_text(encoding="utf-8")
    assert rl.undo_relays(str(state), "GooseWeb.x.bob", str(tmp_path)) == []          # nothing recorded: no-op


@pytest.mark.skipif(sys.platform != "win32", reason="named-pipe relay is Windows-only")
def test_relay_carries_bytes_both_ways(tmp_path):
    """forwarder (TCP) -> named pipe -> PipeRelayServer -> TCP echo service, outside a container."""
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(4)
    target = f"127.0.0.1:{echo.getsockname()[1]}"

    def serve():
        while True:
            try:
                c, _ = echo.accept()
            except OSError:
                return
            with c:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    c.sendall(b"ECHO:" + d)
    threading.Thread(target=serve, daemon=True).start()
    with socket.socket() as probe:                                     # a free port for the forwarder
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    spec = rl.relay_specs(f"GooseWebTest.{os.getpid()}", 4242, [target])[0]
    listen = spec["listen"].rsplit(":", 1)[0] + f":{port}"
    pipe = rl.new_pipe_name()
    srv = rl.PipeRelayServer(pipe, "S-1-5-18", target).start()
    fwd = rl.write_forwarder(str(tmp_path))
    # the forwarder's last argument: the pid of the process that serves the pipe (here this test process)
    p = subprocess.Popen([sys.executable, "-I", fwd, listen, pipe, str(os.getpid())], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        assert p.stdout.readline().strip() == b"listening"
        host, prt = listen.rsplit(":", 1)
        with socket.create_connection((host, int(prt)), timeout=10) as s:
            s.sendall(b"HELLO")
            got = b""
            while len(got) < len(b"ECHO:HELLO"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                got += chunk
        assert got == b"ECHO:HELLO"
    finally:
        p.kill()
        p.wait()
        srv.stop()
        echo.close()
