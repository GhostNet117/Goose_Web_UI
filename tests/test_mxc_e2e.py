"""Spec 025 R8: end-to-end with the real MXC executor (Windows, wxc-exec 1.0.1 installed and supported).

Uses the executor in GOOSE_WEB_TEST_MXC_DIR (a sandbox.mxc_dir that `goose-web sandbox install-mxc` filled), else
the default <install>/vendor/mxc. Skipped cleanly when it is missing, does not match the pin, or this Windows cannot
run MXC process containers (CI runners). Nothing here needs administrator rights."""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from goose_web import mxc
from goose_web.config import DEFAULTS, Settings, _deep_merge


def _settings(tmp_path) -> Settings:
    d = {"paths": {"profiles_root": str(tmp_path / "profiles")}, "sandbox": {}}
    if os.environ.get("GOOSE_WEB_TEST_MXC_DIR"):
        d["sandbox"]["mxc_dir"] = os.environ["GOOSE_WEB_TEST_MXC_DIR"]
    return Settings(_deep_merge(DEFAULTS, d), None)


def _ready(tmp_path) -> Settings:
    if sys.platform != "win32":
        pytest.skip("MXC process containers are Windows-only")
    s = _settings(tmp_path)
    st = mxc.Availability().check(s, refresh=True)
    if not st["available"]:
        pytest.skip(f"MXC not usable here: {st['reason']}")
    return s


PROBE = r'''
import json, os, socket, subprocess, sys, urllib.request
G, DENIED, RELAY, BLOCKED, PROXY = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
out = {}
def t(name, f):
    try:
        out[name] = f()
    except Exception as e:
        out[name] = "ERR " + type(e).__name__
t("read_allowed", lambda: open(os.path.join(G, "in.txt")).read())
t("write_allowed", lambda: open(os.path.join(G, "w.txt"), "w").write("x") and "ok")
t("read_denied", lambda: open(DENIED).read())
t("child_read_denied", lambda: subprocess.run([sys.executable, "-I", "-c", "open(%r).read()" % DENIED],
                                              capture_output=True).returncode)
t("pid", lambda: os.getpid())
t("proxy_env", lambda: bool(os.environ.get("HTTP_PROXY")) and bool(os.environ.get("HTTPS_PROXY")))
t("child_proxy_env", lambda: subprocess.run([sys.executable, "-I", "-c",
                                             "import os; print(bool(os.environ.get('HTTPS_PROXY')))"],
                                            capture_output=True, text=True).stdout.strip())
t("direct_loopback", lambda: socket.create_connection(("127.0.0.1", BLOCKED), 3).close() or "CONNECTED")
t("direct_proxy_port", lambda: socket.create_connection(("127.0.0.1", PROXY), 3).close() or "CONNECTED")
t("relay_via_proxy", lambda: urllib.request.urlopen("http://%s/hello" % RELAY, timeout=15).status)
t("other_loopback_via_proxy", lambda: urllib.request.urlopen("http://127.0.0.1:%d/" % BLOCKED, timeout=15).status)
print(json.dumps(out), flush=True)
'''


async def _http(tag: bytes):
    async def h(r, w):
        try:
            await r.readuntil(b"\r\n\r\n")
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(tag), tag))
            await w.drain()
        finally:
            w.close()
    s = await asyncio.start_server(h, "127.0.0.1", 0)
    return s, s.sockets[0].getsockname()[1]


async def test_mxc_contains_files_children_network_and_reaches_relays_via_proxy(tmp_path):
    s = _ready(tmp_path)
    from goose_web.egress import EgressProxy
    from goose_web.workers import _Job
    g = tmp_path / "granted"
    g.mkdir()
    (g / "in.txt").write_text("IN", encoding="utf-8")
    (g / "probe.py").write_text(PROBE, encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("SECRET", encoding="utf-8")
    relay_srv, relay_port = await _http(b"RELAY-OK")
    other_srv, other_port = await _http(b"MUST-NOT-BE-REACHED")
    audit = []
    proxy = await EgressProxy("e2e", network="internet", relays=[f"127.0.0.1:{relay_port}"],
                              audit=lambda u, t, d: audit.append((t, d["decision"]))).start()
    gj, wj = _Job(), _Job()
    try:
        py = sys.base_prefix
        policy = mxc.build_policy(
            command=[os.path.join(py, "python.exe"), "-I", str(g / "probe.py"), str(g), str(outside / "secret.txt"),
                     f"127.0.0.1:{relay_port}", str(other_port), str(proxy.port)],
            cwd=str(g), env={"SystemRoot": os.environ["SystemRoot"], "PATH": py,
                             "LOCALAPPDATA": os.environ["LOCALAPPDATA"]},
            grants={str(g): "modify", py: "read"}, proxy_url=proxy.url(),
            system_drive=os.environ.get("SystemDrive", "C:"))
        pf = tmp_path / "policy.json"
        mxc.write_policy(pf, policy)
        errf = open(tmp_path / "err.log", "wb")
        t0 = time.monotonic()
        p = mxc.launch(mxc.exe_path(s), pf, errf, [gj, wj])
        out, _ = await asyncio.to_thread(p.communicate, None, 120)
        errf.close()
        assert p.returncode == 0, (tmp_path / "err.log").read_text(errors="replace")
        r = json.loads(out.decode().strip().splitlines()[-1])
        assert r["read_allowed"] == "IN" and r["write_allowed"] == "ok" and (g / "w.txt").read_text() == "x"
        assert r["read_denied"] == "ERR PermissionError" and r["child_read_denied"] != 0
        assert r["proxy_env"] is True and r["child_proxy_env"] == "True"           # MCP servers inherit it
        assert str(r["direct_loopback"]).startswith("ERR") and r["direct_proxy_port"] == "CONNECTED"
        assert r["relay_via_proxy"] == 200 and r["other_loopback_via_proxy"] == "ERR HTTPError"
        assert (f"127.0.0.1:{relay_port}", "allowed") in audit and (f"127.0.0.1:{other_port}", "refused") in audit
        assert time.monotonic() - t0 < 60
    finally:
        await proxy.close()
        relay_srv.close()
        other_srv.close()
        wj.close()
        gj.close()


def _alive(pid: int) -> bool:
    r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"], capture_output=True, text=True)
    return f'"{pid}"' in r.stdout


async def test_mxc_dies_with_the_gateway_job(tmp_path):
    s = _ready(tmp_path)
    from goose_web.workers import _Job
    g = tmp_path / "g"
    g.mkdir()
    (g / "sleep.py").write_text("import os, sys, time\nopen(sys.argv[1], 'w').write(str(os.getpid()))\n"
                                "time.sleep(120)\n", encoding="utf-8")
    py = sys.base_prefix
    pf = tmp_path / "p.json"
    mxc.write_policy(pf, mxc.build_policy(
        command=[os.path.join(py, "python.exe"), "-I", str(g / "sleep.py"), str(g / "pid.txt")], cwd=str(g),
        env={"SystemRoot": os.environ["SystemRoot"], "LOCALAPPDATA": os.environ["LOCALAPPDATA"]},
        grants={str(g): "modify", py: "read"}))
    gj, wj = _Job(), _Job()
    p = mxc.launch(mxc.exe_path(s), pf, subprocess.DEVNULL, [gj, wj])
    for _ in range(200):
        if (g / "pid.txt").exists() and (g / "pid.txt").read_text():
            break
        await asyncio.sleep(0.05)
    inner = int((g / "pid.txt").read_text())
    assert _alive(inner) and p.poll() is None
    gj.close()                                                                    # the gateway "crashes"
    for _ in range(100):
        if not _alive(inner) and p.poll() is not None:
            break
        await asyncio.sleep(0.1)
    assert not _alive(inner) and p.poll() is not None
    wj.close()


async def test_goose_acp_initializes_in_an_mxc_worker(tmp_path, monkeypatch):
    s = _ready(tmp_path)
    goose = os.environ.get("GOOSE_WEB_TEST_GOOSE") or s.goose_binary
    if not goose or not os.path.isfile(goose):
        pytest.skip("goose binary not found (set GOOSE_WEB_TEST_GOOSE)")
    from goose_web.workers import WorkerManager
    s.data["goose"]["binary"] = goose
    wm = WorkerManager(s)
    names = ["alice", "bob", "carol"]          # several members start at once (shared probe, own proxies/policies)
    specs = {}
    for n in names:
        prof = tmp_path / "profiles" / n
        (prof / "workspace").mkdir(parents=True)
        specs[n] = {"name": f"GooseWeb.e2e.{n}", "profile_root": str(prof), "relays": [], "grants": {}, "caps": [],
                    "backend": "mxc", "config_problems": [], "network": "internet",
                    "relay_targets": ["127.0.0.1:8317"], "mxc_grants": {str(prof): "modify",
                                                                         os.path.dirname(goose): "read"},
                    "profiles_root": str(tmp_path / "profiles"), "system_dir": str(s.system_dir),
                    "protected_write": mxc.protected_write_paths(s), "protected_any": []}
        wm.register(n, n, str(prof), False, [], sandbox=specs[n])

    async def start_and_init(n):
        t0 = time.monotonic()
        w = await wm.ensure(n)
        assert w.backend == "mxc" and w.proxy_port and w.state == "ready"
        await w.channel.send(json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": 1, "clientCapabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}}}))
        it = w.channel.__aiter__()
        while True:
            msg = json.loads(await asyncio.wait_for(it.__anext__(), 60))
            if msg.get("id") == 0:
                break
        assert msg["result"]["agentInfo"]["name"] == "goose", msg
        return time.monotonic() - t0
    try:
        took = await asyncio.gather(*(start_and_init(n) for n in names))
        ports = {wm.get(n).proxy_port for n in names}
        assert len(ports) == 3                                                    # one proxy per member
        print("goose acp initialize in MXC after " + ", ".join(f"{t:.2f}s" for t in took))
    finally:
        await wm.shutdown()
    for n in names:
        assert not Path(s.system_dir, "sandbox", "mxc", specs[n]["name"] + ".json").exists()
