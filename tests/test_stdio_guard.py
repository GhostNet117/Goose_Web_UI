"""FIX member-stdio-start-hang (1.26.1): the stdio start-up guard and how a team's stdio extensions reach it.

Goose 1.57 sends `server/discover`, waits 10 s, then sends `initialize` on the same connection; a slow server that
speaks the 2026-07-28 protocol answers the late discover and rejects initialize (-32022), and the extension never
starts. FAKE_SERVER behaves like that (measured with duckduckgo-mcp-server 0.7.0, MCP SDK 2.2/2.3).
"""
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from goose_web import mxc
from goose_web.config import extension_start_seconds, load_settings
from goose_web.db import Database
from goose_web.profiles import GUARD_FILE, Profiles, guard_entry, unguard_entry
from goose_web.stdio_guard import parse_args

GUARD = str(Path(__file__).resolve().parents[1] / "goose_web" / "stdio_guard.py")

FAKE_SERVER = r'''
import json, os, sys, time
delay, mode, pidfile = float(sys.argv[1]), sys.argv[2], sys.argv[3]
with open(pidfile, "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(delay)                      # a slow start: Goose's messages wait in the pipe
seen, modern = [], False
for line in sys.stdin:
    m = json.loads(line)
    seen.append(m.get("method"))
    if "id" not in m:
        continue
    if m.get("method") == "server/discover":
        modern = True
        out = {"result": {"supportedVersions": ["2026-07-28"]}}
    elif m.get("method") == "initialize":
        if mode == "never":
            continue
        out = ({"error": {"code": -32022, "message": "connection is serving the 2026-07-28 protocol; the "
                          "initialize handshake is not accepted"}} if modern else
               {"result": {"protocolVersion": "2025-11-25", "seen": list(seen)}})
    else:
        out = {"result": {"tools": [{"name": "search"}], "seen": list(seen)}}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], **out}) + "\n")
    sys.stdout.flush()
'''

DISCOVER = {"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {}}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "goose"}}}


class Proc:
    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.q = queue.Queue()
        threading.Thread(target=self._rd, daemon=True).start()

    def _rd(self):
        for line in iter(self.p.stdout.readline, b""):
            self.q.put(json.loads(line))
        self.q.put(None)

    def send(self, m):
        self.p.stdin.write((json.dumps(m) + "\n").encode())
        self.p.stdin.flush()

    def get(self, timeout):
        return self.q.get(timeout=timeout)

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass


def _alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(0x1000 | 0x00100000, False, pid)        # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    if not h:
        return False
    try:
        return k32.WaitForSingleObject(ctypes.c_void_p(h), 0) == 0x102          # WAIT_TIMEOUT: still running
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def _gone(pidfile: Path, secs=15) -> bool:
    pid = int(pidfile.read_text())
    end = time.time() + secs
    while time.time() < end:
        if not _alive(pid):
            return True
        time.sleep(0.2)
    return False


def _server(tmp_path, delay, mode):
    srv = tmp_path / "fake_server.py"
    srv.write_text(FAKE_SERVER, encoding="utf-8")
    pidfile = tmp_path / "server.pid"
    return [sys.executable, "-u", str(srv), str(delay), mode, str(pidfile)], pidfile


def _wait_file(p: Path, secs=15):
    end = time.time() + secs
    while time.time() < end and not (p.exists() and p.read_text()):
        time.sleep(0.05)


def test_parse_args():
    assert parse_args(["--", "x", "--", "y"]) == (120.0, "extension", ["x", "--", "y"])
    assert parse_args(["--limit", "30", "--name", "ws", "--odd", "--", "uvx", "a@1"]) == (30.0, "ws", ["uvx", "a@1"])
    assert parse_args(["--limit", "-5", "--", "x"])[0] == 0.0
    assert parse_args(["--limit", "nope", "--", "x"])[0] == 120.0


def test_without_the_guard_a_slow_server_rejects_goose_s_initialize(tmp_path):
    """The bug at unit level: discover answered late, initialize rejected - Goose never completes the start."""
    cmd, _ = _server(tmp_path, 1.0, "ok")
    pr = Proc(cmd)
    try:
        pr.send(DISCOVER)
        pr.send(INITIALIZE)          # what Goose sends after its 10 s
        r0, r1 = pr.get(20), pr.get(20)
        assert "result" in r0 and r0["id"] == 0
        assert r1["id"] == 1 and r1["error"]["code"] == -32022
    finally:
        pr.close()
        pr.p.wait(10)


def test_guard_answers_discover_and_the_server_only_sees_initialize(tmp_path):
    cmd, pidfile = _server(tmp_path, 1.5, "ok")
    pr = Proc([sys.executable, "-I", GUARD, "--limit", "60", "--name", "fake", "--", *cmd])
    try:
        t0 = time.time()
        pr.send(DISCOVER)
        r0 = pr.get(10)
        assert r0["id"] == 0 and r0["error"]["code"] == -32601        # "method not found", from the guard
        assert time.time() - t0 < 1.4                                 # at once, while the server still sleeps
        pr.send(INITIALIZE)
        r1 = pr.get(20)
        assert r1["id"] == 1 and r1["result"]["protocolVersion"] == "2025-11-25"
        assert r1["result"]["seen"] == ["initialize"]                 # discover never reached the server
        pr.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        pr.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        r2 = pr.get(20)                                               # everything else passes through
        assert r2["id"] == 2 and r2["result"]["tools"] == [{"name": "search"}]
        assert r2["result"]["seen"] == ["initialize", "notifications/initialized", "tools/list"]
        pr.send({"jsonrpc": "2.0", "id": 3, "method": "server/discover", "params": {}})
        assert pr.get(20)["id"] == 3                                  # after the handshake: passed on, untouched
    finally:
        pr.close()
    assert pr.p.wait(20) == 0                                         # Goose closed its input: the guard ends
    assert _gone(pidfile)


def test_a_server_that_does_not_start_in_time_is_ended(tmp_path):
    cmd, pidfile = _server(tmp_path, 0, "never")
    pr = Proc([sys.executable, "-I", GUARD, "--limit", "2", "--name", "websearch", "--", *cmd])
    try:
        pr.send(DISCOVER)
        assert pr.get(10)["error"]["code"] == -32601
        t0 = time.time()
        pr.send(INITIALIZE)
        r = pr.get(20)
        assert r["id"] == 1 and r["error"]["code"] == -32000
        assert "websearch" in r["error"]["message"] and "within 2 s" in r["error"]["message"]
        assert 1.5 < time.time() - t0 < 10
        assert pr.p.wait(20) == 1                                     # Goose sees the process end: extension failed
        assert b"start-up guard" in pr.p.stderr.read()
    finally:
        pr.close()
    _wait_file(pidfile)
    assert _gone(pidfile)                                             # the server's tree went with it


def test_without_a_limit_the_guard_still_waits(tmp_path):
    cmd, pidfile = _server(tmp_path, 2.5, "ok")
    pr = Proc([sys.executable, "-I", GUARD, "--limit", "0", "--", *cmd])
    try:
        pr.send(DISCOVER)
        pr.get(10)
        pr.send(INITIALIZE)
        assert "result" in pr.get(30)
    finally:
        pr.close()
        pr.p.wait(20)
    assert _gone(pidfile)


def test_a_server_that_cannot_start_ends_the_guard(tmp_path):
    pr = Proc([sys.executable, "-I", GUARD, "--", str(tmp_path / "missing.exe")])
    pr.close()
    assert pr.p.wait(20) == 1
    assert b"cannot start" in pr.p.stderr.read()


def test_entries_round_trip():
    e = {"type": "stdio", "name": "ws", "cmd": "C:\\g\\uvx.exe", "args": ["pkg@1", "--", "x"], "timeout": 300,
         "envs": {"A": "1"}, "env_keys": ["K"], "enabled": True, "available_tools": ["search"]}
    g = guard_entry(e, "C:\\py\\python.exe", "C:\\p\\alice\\.goose-web\\stdio_guard.py", 120, "ws")
    assert g["cmd"] == "C:\\py\\python.exe"
    assert g["args"] == ["-I", "C:\\p\\alice\\.goose-web\\stdio_guard.py", "--limit", "120", "--name", "ws", "--",
                         "C:\\g\\uvx.exe", "pkg@1", "--", "x"]
    assert {k: v for k, v in g.items() if k not in ("cmd", "args")} == \
        {k: v for k, v in e.items() if k not in ("cmd", "args")}
    assert unguard_entry(g) == e
    assert unguard_entry(e) == e
    other = {"type": "stdio", "cmd": "python", "args": ["-I", "C:\\x\\elsewhere.py", "--", "y"]}
    assert unguard_entry(other) == other                              # not the guard: left alone
    assert unguard_entry({"type": "streamable_http", "uri": "http://x/mcp"}) == \
        {"type": "streamable_http", "uri": "http://x/mcp"}


def test_extension_start_seconds():
    class S:
        def __init__(self, v):
            self.v = v

        def get(self, sec, key):
            return self.v
    assert extension_start_seconds(S(None)) == (120, "")
    assert extension_start_seconds(S(45)) == (45, "")
    assert extension_start_seconds(S("0")) == (0, "")
    for bad in (-1, 3601, 2.5, "x", True, [1]):
        n, why = extension_start_seconds(S(bad))
        assert n == 120 and "extension_start_seconds" in why


# ------------------------------------------------------------------------------------------------ provisioning
@pytest.fixture
def env(tmp_path, monkeypatch):
    from tests.test_team_profiles import ANYCHAT, team, user
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    monkeypatch.setattr(mxc, "_broad_writers", lambda p: [])   # a developer's C:\ often lets every account write
    pyd = tmp_path / "members_python"
    pyd.mkdir()
    (pyd / ("python.exe" if os.name == "nt" else "python3")).write_bytes(b"")
    s = load_settings()
    s.data["sandbox"]["read_dirs"] = [str(pyd)]
    db = Database(tmp_path / "gw.db")
    pr = Profiles(s, db)
    tid = team(db, "A", {**ANYCHAT, "allow_shell": True})
    alice = user(db, "alice")
    db.set_user_team(alice["id"], tid)
    entry = {"type": "stdio", "name": "websearch", "cmd": "C:\\Goose\\bin\\uvx.exe",
             "args": ["duckduckgo-mcp-server@0.7.0"], "enabled": True, "timeout": 300, "env_keys": [], "envs": {}}
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
               (tid, "extension", "websearch", json.dumps({"key": "websearch", "entry": entry}), "manual"))
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
               (tid, "extension", "web", json.dumps({"key": "web", "entry": {
                   "type": "streamable_http", "name": "web", "uri": "https://example.invalid/mcp",
                   "enabled": True}}), "manual"))
    yield {"s": s, "db": db, "pr": pr, "alice": db.user_by_id(alice["id"]), "entry": entry,
           "python": str(pyd / ("python.exe" if os.name == "nt" else "python3"))}
    db.close()


def _exts(pr, u):
    return yaml.safe_load((pr.config_dir(u) / "config.yaml").read_text(encoding="utf-8"))["extensions"]


def test_a_team_stdio_extension_starts_through_the_guard(env):
    pr, alice, entry = env["pr"], env["alice"], env["entry"]
    pr.provision(alice)
    e = _exts(pr, alice)["websearch"]
    guard = pr.root_for(alice) / ".goose-web" / GUARD_FILE
    assert e["cmd"] == env["python"]
    assert e["args"] == ["-I", str(guard), "--limit", "120", "--name", "websearch", "--", entry["cmd"], *entry["args"]]
    assert guard.read_text(encoding="utf-8") == (Path(GUARD).read_text(encoding="utf-8"))
    assert _exts(pr, alice)["web"]["uri"] == "https://example.invalid/mcp"     # not a stdio entry: untouched
    assert "cmd" not in _exts(pr, alice)["web"]
    guard.write_text("changed by the member", encoding="utf-8")
    pr.provision(alice)                                                        # rewritten when it differs
    assert guard.read_text(encoding="utf-8") == Path(GUARD).read_text(encoding="utf-8")
    assert pr.provision(alice) == []                                           # idempotent
    # a team library never receives the guard: export_item gives the server's own command
    name, payload = pr.export_item(alice, "extension", "websearch")
    assert payload["entry"]["cmd"] == entry["cmd"] and payload["entry"]["args"] == entry["args"]


def test_no_guard_when_it_is_off_or_there_is_no_python(env):
    s, pr, alice, entry = env["s"], env["pr"], env["alice"], env["entry"]
    s.data["sandbox"]["extension_start_seconds"] = 0
    pr.provision(alice)
    e = _exts(pr, alice)["websearch"]
    assert e["cmd"] == entry["cmd"] and e["args"] == entry["args"]
    s.data["sandbox"]["extension_start_seconds"] = 90
    s.data["sandbox"]["read_dirs"] = []
    pr.provision(alice)
    assert _exts(pr, alice)["websearch"]["cmd"] == entry["cmd"]
    s.data["sandbox"]["read_dirs"] = [str(Path(env["python"]).parent)]
    pr.provision(alice)
    assert _exts(pr, alice)["websearch"]["args"][2:4] == ["--limit", "90"]


def test_no_guard_without_shell(env):
    """Without allow_shell a stdio item is not delivered at all (unchanged); the guard does not change that."""
    db, pr, alice = env["db"], env["pr"], env["alice"]
    from tests.test_team_profiles import ANYCHAT
    tid = db.user_team(alice["id"])["id"]
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps(ANYCHAT), tid))
    pr.provision(db.user_by_id(alice["id"]))
    assert "websearch" not in _exts(pr, alice)



# ------------------------------------------------------------------------- FIX stdio-guard-orphans (1.26.2)
STDERR_SERVER = r"""
import json, sys
sys.stderr.write("hello from the server's stderr\n")
sys.stderr.flush()
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "x"}}) + "\n")
        sys.stdout.flush()
"""

# A launcher like uvx: starts its own child at once and never answers; both ids go to a file.
LAUNCHER = r"""
import subprocess, sys, time
kid = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
with open(sys.argv[1], "w") as fh:
    fh.write(f"{kid.pid} {__import__('os').getpid()}")
time.sleep(120)
"""


def _pids(p: Path, secs=15):
    _wait_file(p, secs)
    return [int(x) for x in p.read_text().split()]


def _gone_pid(pid, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if not _alive(pid):
            return True
        time.sleep(0.2)
    return False


def test_the_server_s_stderr_reaches_goose_through_the_guard(tmp_path):
    srv = tmp_path / "srv.py"
    srv.write_text(STDERR_SERVER, encoding="utf-8")
    pr = Proc([sys.executable, "-I", GUARD, "--limit", "30", "--", sys.executable, "-u", str(srv)])
    try:
        pr.send(DISCOVER)
        pr.get(10)
        pr.send(INITIALIZE)
        assert pr.get(20)["result"]["protocolVersion"] == "x"
    finally:
        pr.close()
    assert pr.p.wait(20) == 0
    assert b"hello from the server's stderr" in pr.p.stderr.read()      # forwarded by the guard, line by line


@pytest.mark.skipif(os.name != "nt", reason="Windows job objects and process snapshots")
def test_a_launcher_s_whole_tree_ends_at_the_time_out(tmp_path):
    """1.26.1 put the server into its job only after it had started, so a launcher's child created in that moment
    (uvx starting uv) stayed outside and survived the time-out, holding Goose's stderr; Goose kept waiting."""
    launcher = tmp_path / "launcher.py"
    launcher.write_text(LAUNCHER, encoding="utf-8")
    ids = tmp_path / "ids.txt"
    pr = Proc([sys.executable, "-I", GUARD, "--limit", "3", "--name", "slow", "--",
               sys.executable, "-u", str(launcher), str(ids)])
    try:
        pr.send(DISCOVER)
        pr.get(10)
        pr.send(INITIALIZE)
        kid, launcher_pid = _pids(ids)
        r = pr.get(30)
        assert r["error"]["code"] == -32000
        box = []
        t = threading.Thread(target=lambda: box.append(pr.p.stderr.read()), daemon=True)
        t.start()
        t.join(15)                                   # EOF: nothing of the server holds the guard's stderr any more
        assert box, "the guard's stderr stayed open"
        assert box[0].rstrip().endswith(b"stopped its server")           # the guard's message comes last
        assert pr.p.wait(20) == 1
    finally:
        pr.close()
    assert _gone_pid(kid) and _gone_pid(launcher_pid)


@pytest.mark.skipif(os.name != "nt", reason="Windows process snapshots")
def test_descendants_are_found_after_their_parent_ended(tmp_path):
    from goose_web.stdio_guard import _created, _terminate, descendants
    ids = tmp_path / "ids.txt"
    # the base interpreter, also inside (a venv's python.exe is a launcher with a child of its own)
    py = getattr(sys, "_base_executable", sys.executable)
    env = {k: v for k, v in os.environ.items() if k.upper() != "__PYVENV_LAUNCHER__"}
    parent = subprocess.Popen([py, "-c",
                               "import subprocess, sys; k = subprocess.Popen([sys.argv[2], '-c', "
                               "'import time; time.sleep(120)']); open(sys.argv[1], 'w').write(str(k.pid))",
                               str(ids), py], env=env)
    born = _created(parent._handle)
    kid = _pids(ids)[0]
    parent.wait(20)                                  # the parent is gone; its child is an orphan now
    found = {}
    try:
        found = descendants({parent.pid: born})
        assert kid in found
        assert kid not in descendants({parent.pid: found[kid] + 1})   # a "child" older than its parent: never
        assert not _terminate(kid, found[kid] + 1)                     # not the process created then: not ended
        assert _terminate(kid, found[kid])
        assert _gone_pid(kid)
    finally:
        for pid in {kid, *found}:
            if _alive(pid):
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows process snapshots")
def test_a_reused_process_id_is_not_taken_for_a_parent():
    from goose_web.stdio_guard import _created_pid, descendants
    kid = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-c", "import time; time.sleep(60)"])
    try:
        me = os.getpid()
        born = _created_pid(me)
        assert kid.pid in descendants({me: born})
        assert kid.pid not in descendants({me: born + 1})            # "me" is now a different process: not followed
        assert kid.pid not in descendants({me: None})                 # cannot be compared: not followed either
    finally:
        kid.kill()
        kid.wait(10)


@pytest.mark.skipif(os.name != "nt", reason="Windows job objects")
def test_the_server_starts_suspended_and_joins_the_job_before_it_runs(monkeypatch):
    """The 1.26.1 race (a launcher's child created before the job assignment) cannot happen: Popen creates the
    server suspended, it joins the job, and only then is it resumed."""
    import io
    from goose_web import stdio_guard as sg
    order = []

    class FakeProc:
        pid, _handle = 4242, 0

        def __init__(self):
            self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(b""), io.BytesIO(b"")

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(sg.subprocess, "Popen", lambda cmd, **kw: order.append(("popen", kw.get("creationflags")))
                        or FakeProc())
    monkeypatch.setattr(sg.Job, "add", lambda self, p: order.append("join") or True)
    monkeypatch.setattr(sg, "_resume", lambda p: order.append("resume") or True)
    monkeypatch.setattr(sg, "_created", lambda h: 1)
    g = sg.Guard(["server"], 0, "x", io.BytesIO(b""), io.BytesIO(), io.BytesIO())
    assert g.run() == 0
    assert order == [("popen", sg.CREATE_SUSPENDED), "join", "resume"]


def test_exit_codes_that_os_exit_takes():
    from goose_web.stdio_guard import _exit_code
    assert [_exit_code(x) for x in (0, 1, 0xC0000005, -5, 2 ** 32, True, None)] == \
        [0, 1, 0xC0000005 - 2 ** 32, -5, 1, 1, 1]


SLEEPER_PYPROJECT = """[project]
name = "gw-sleeper"
version = "0.1.0"
requires-python = ">=3.11"

[project.scripts]
gw-sleeper = "gw_sleeper:main"

[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[tool.setuptools]
py-modules = ["gw_sleeper"]
"""


@pytest.mark.skipif(os.name != "nt" or not os.environ.get("GOOSE_WEB_TEST_UVX"),
                    reason="the real uvx chain: set GOOSE_WEB_TEST_UVX=1 (needs uvx on PATH and PyPI)")
def test_a_uvx_started_server_leaves_nothing_behind(tmp_path):
    """The live case of 2026-11-22: uvx -> uv -> uv's launcher -> python -> python."""
    import shutil
    uvx = shutil.which("uvx")
    assert uvx, "uvx not on PATH"
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(SLEEPER_PYPROJECT, encoding="utf-8")
    (pkg / "gw_sleeper.py").write_text("import time\n\ndef main():\n    time.sleep(300)\n", encoding="utf-8")
    env = {**os.environ, "UV_CACHE_DIR": str(tmp_path / "uvcache")}
    subprocess.run([uvx, "--from", str(pkg), "python", "-c", "print(1)"], env=env, capture_output=True, timeout=300)
    p = subprocess.Popen([sys.executable, "-I", GUARD, "--limit", "6", "--", uvx, "--from", str(pkg), "gw-sleeper"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    p.stdin.write((json.dumps(INITIALIZE) + "\n").encode())
    p.stdin.flush()                                  # Goose's input stays open, as in a chat that waits
    box = []
    t = threading.Thread(target=lambda: box.append(p.stderr.read()), daemon=True)
    t.start()
    threading.Thread(target=p.stdout.read, daemon=True).start()
    rc = p.wait(60)
    t.join(15)
    p.stdin.close()
    assert rc == 1 and box and b"did not start within 6 s" in box[0]
    time.sleep(1)
    left = subprocess.run(["powershell", "-NoProfile", "-Command",
                           "Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine "
                           "-like '*" + str(tmp_path / "uvcache").replace("'", "''") + "*' } | "
                           "ForEach-Object { $_.ProcessId }"],
                          capture_output=True, text=True).stdout.split()
    for pid in left:
        subprocess.run(["taskkill", "/T", "/F", "/PID", pid], capture_output=True)
    assert left == []
