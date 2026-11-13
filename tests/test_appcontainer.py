"""The AppContainer backend, measured with real containers and checked line by line (SECURITY-ASSESSMENT 16).

The backend of spec 012 is what a member's agent runs in on a Windows that cannot run MXC process containers
(`sandbox.backend: appcontainer`, or `sandbox.fallback: appcontainer`). The Windows tests here build a member's
container with the product's own code - sandbox.prepare, sandbox.spawn, relay.PipeRelayServer and the relay
forwarder - and ask a Python inside it what it can reach. Nothing needs administrator rights."""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from goose_web import mxc
from goose_web import relay as rl
from goose_web import sandbox as sb
from goose_web import winsec, workers
from goose_web.config import DEFAULTS, Settings, _deep_merge, sandbox_config_problems

windows = pytest.mark.skipif(sys.platform != "win32", reason="AppContainer is Windows-only")

PRELUDE = r'''
import json, os, socket, subprocess, sys
out = {}
def t(name, fn):
    try:
        out[name] = "OK " + str(fn())
    except BaseException as e:
        out[name] = "ERR " + type(e).__name__
def mklink(kind, link, target):
    r = subprocess.run([os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), "/d", "/c", "mklink", kind,
                        link, target], capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    if r.returncode:
        raise PermissionError("mklink")
    return "made"
'''


def env_for(root: Path) -> dict:
    """What workers._sandbox_env keeps for a sandboxed process, in small."""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    env = {k: os.environ[k] for k in ("SystemRoot", "windir", "SystemDrive", "ComSpec", "LOCALAPPDATA")
           if os.environ.get(k)}
    env["PATH"] = os.pathsep.join([os.path.join(sysroot, "System32"), sysroot])
    for k in ("TEMP", "TMP", "USERPROFILE", "HOME", "APPDATA"):
        env[k] = str(root)
    return env


def member_grants(prof: Path, pybase: str, extra: dict | None = None) -> dict:
    """A member's grants as workers._start_appcontainer applies them: sandbox.desired_grants, then the rules and
    the link resolution of mxc.filter_grants. The resolution matters: icacls on a directory link changes the link,
    not the folder behind it, and uv keeps its Pythons behind such a link."""
    kept, refused = mxc.filter_grants({**sb.desired_grants(str(prof), [], [pybase], ""), **(extra or {})},
                                      profile_root=str(prof), profiles_root=str(prof.parent),
                                      system_dir=str(prof.parent / "_system"), protected_write=[], protected_any=[])
    assert not refused, refused
    return kept


@pytest.fixture
def box(tmp_path):
    """A member's container as the gateway prepares it: the own profile (modify) and the base Python (read)."""
    py, pybase = rl.python_for_container()
    prof = tmp_path / "profiles" / "alice"
    (prof / "workspace").mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / "dir").mkdir(parents=True)
    (outside / "secret.txt").write_text("OUTSIDE", encoding="utf-8")
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    state_dir = str(tmp_path / "state")
    b = SimpleNamespace(py=py, pybase=pybase, prof=prof, work=prof / "workspace", outside=outside, name=name,
                        sid="", state_dir=state_dir, tmp=tmp_path, procs=[], servers=[])
    try:
        b.sid = sb.prepare(name, state_dir, member_grants(prof, pybase))["sid"]
        yield b
    finally:
        for p in b.procs:
            p.kill()
        for s in b.servers:
            s.stop()
        if not sb.remove(state_dir, name):      # prepare failed before it recorded anything
            sb.delete_container(name)


def inside(b, code: str, caps=()) -> dict:
    """Run `code` in a Python inside the container; it fills `out` through t(name, fn)."""
    script = b.work / f"t{uuid.uuid4().hex[:8]}.py"
    script.write_text(PRELUDE + code + "\nprint(json.dumps(out), flush=True)\n", encoding="utf-8")
    with open(b.tmp / "err.log", "ab") as logf:
        p = sb.spawn([b.py, "-I", str(script)], env_for(b.prof), str(b.work), b.sid, list(caps), logf)
    p.stdin.close()
    guard = threading.Timer(180, p.kill)      # a process that never ends must not hold the test
    guard.start()
    try:
        raw = p.stdout.read().decode("utf-8", "replace")
        p.wait(120)
    finally:
        guard.cancel()
    assert raw.strip(), (b.tmp / "err.log").read_text(errors="replace")
    return json.loads(raw.strip().splitlines()[-1])


class _Service(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"LOOPBACK-SERVICE"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def service():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Service)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ------------------------------------------------------------------ what a member's container reaches
@windows
def test_a_member_reads_and_lists_only_its_own_folders(box):
    other = box.tmp / "profiles" / "bob"
    other.mkdir()
    (other / "secret.txt").write_text("BOB", encoding="utf-8")
    home = winsec.profile_folder() or ""
    r = inside(box, f'''
t("own write", lambda: open(os.path.join({str(box.work)!r}, "w.txt"), "w").write("x"))
t("own read", lambda: open(os.path.join({str(box.work)!r}, "w.txt")).read())
t("other member read", lambda: open({str(other / "secret.txt")!r}).read())
t("other member list", lambda: os.listdir({str(other)!r}))
t("profiles root list", lambda: os.listdir({str(box.tmp / "profiles")!r}))
t("outside read", lambda: open({str(box.outside / "secret.txt")!r}).read())
t("outside list", lambda: os.listdir({str(box.outside)!r}))
t("outside write", lambda: open({str(box.outside / "dir" / "x.txt")!r}, "w").write("x"))
t("account home list", lambda: os.listdir({home!r}))
t("child cannot either", lambda: subprocess.run([sys.executable, "-I", "-c", "open(%r).read()" % {str(other / "secret.txt")!r}],
                                               capture_output=True, stdin=subprocess.DEVNULL).returncode)
''')
    assert r["own write"].startswith("OK") and r["own read"] == "OK x"
    for k in ("other member read", "other member list", "profiles root list", "outside read", "outside list",
              "outside write"):
        assert r[k] == "ERR PermissionError", (k, r[k])
    if home:        # Goose's home-folder skills, recipes and agents live here (spec 028): not even the names
        assert r["account home list"] == "ERR PermissionError"
    assert r["child cannot either"] not in ("OK 0",)
    assert not list((box.outside / "dir").iterdir())


@windows
def test_no_link_leads_out_of_the_container(box):
    """The gateway reads and writes files in a member's folders with its own rights, so what a link there could
    point at matters. An AppContainer cannot make one to anything it may not write."""
    r = inside(box, f'''
own = {str(box.work)!r}
open(os.path.join(own, "mine.txt"), "w").write("mine")
os.mkdir(os.path.join(own, "sub"))
t("hard link out", lambda: os.link({str(box.outside / "secret.txt")!r}, os.path.join(own, "hl.txt")))
t("hard link to a read-only grant", lambda: os.link({box.py!r}, os.path.join(own, "py.exe")))
t("junction out", lambda: mklink("/J", os.path.join(own, "j"), {str(box.outside / "dir")!r}))
t("symlink out", lambda: os.symlink({str(box.outside / "secret.txt")!r}, os.path.join(own, "sl.txt")))
t("hard link inside", lambda: os.link(os.path.join(own, "mine.txt"), os.path.join(own, "mine2.txt")))
''')
    for k in ("hard link out", "hard link to a read-only grant", "junction out", "symlink out"):
        assert r[k].startswith("ERR"), (k, r[k])
    assert r["hard link inside"].startswith("OK")
    assert not any((box.work / n).exists() for n in ("hl.txt", "py.exe", "j", "sl.txt"))


@windows
def test_loopback_is_closed_and_the_relay_is_the_only_way_in(box, service):
    spec = rl.relay_specs(box.name, 7, [service])[0]
    pipe = rl.new_pipe_name()
    box.servers.append(rl.PipeRelayServer(pipe, box.sid, spec["target"], 8).start())
    fwd = rl.write_forwarder(str(box.prof))
    with open(box.tmp / "err.log", "ab") as logf:
        f = sb.spawn([box.py, "-I", fwd, spec["listen"], pipe, str(os.getpid())], env_for(box.prof), str(box.prof),
                     box.sid, [], logf)
    box.procs.append(f)
    assert workers._first_line(f, 60) == "listening", (box.tmp / "err.log").read_text(errors="replace")
    host, port = service.split(":")
    r = inside(box, f'''
import urllib.request
t("loopback direct", lambda: socket.create_connection(({host!r}, {int(port)}), 3).close())
t("through the relay", lambda: urllib.request.build_opener(urllib.request.ProxyHandler({{}})).open(
    "http://{spec["listen"]}/", timeout=20).read().decode())
t("gateway process", lambda: __import__("ctypes").WinDLL("kernel32").OpenProcess(0x1000, False, {os.getpid()}) or 1 / 0)
import _winapi
t("an instance of its own relay pipe", lambda: _winapi.CreateNamedPipe({pipe!r}, 3, 0, 255, 4096, 4096, 0, 0))
def second_address():
    s = socket.socket(); s.bind(({rl.forward_ip(7, 1)!r}, 0)); s.listen(1); s.close()
t("a second forward address", second_address)
''', caps=[sb.CAP_INTERNET])
    assert r["loopback direct"].startswith("ERR")              # also with the internet capability
    assert r["through the relay"] == "OK LOOPBACK-SERVICE"
    assert r["gateway process"].startswith("ERR")
    assert r["an instance of its own relay pipe"] == "ERR PermissionError"      # V-9: it cannot sit in front of the gateway
    assert r["a second forward address"].startswith("OK")                       # V-12: 127.65.x.y is usable too
    # another member's container is refused by the pipe itself
    bob = box.tmp / "profiles" / "bob"
    (bob / "workspace").mkdir(parents=True)
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    st = sb.prepare(name, box.state_dir, member_grants(bob, box.pybase))
    try:
        b2 = SimpleNamespace(py=box.py, prof=bob, work=bob / "workspace", sid=st["sid"], tmp=box.tmp)
        r2 = inside(b2, f'''
import _winapi
t("someone else's relay", lambda: _winapi.CreateFile({pipe!r}, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, 0,
                                                     _winapi.OPEN_EXISTING, 0, 0))
''')
        assert r2["someone else's relay"] == "ERR PermissionError"
    finally:
        sb.remove(box.state_dir, name)
    # the normal end of an answer is not an error in the worker's log (AC-8)
    assert "relay pipe to socket" not in (box.tmp / "err.log").read_text(errors="replace")


@windows
def test_a_folder_behind_a_link_is_granted_where_it_really_is(box):
    """Found by the Python 3.11 run: a program folder reached through a directory link (uv keeps its Pythons so)
    was granted on the link, and a program started through it could not load its DLLs (exit 0xC0000135) - with the
    relay forwarder that meant no relays. The start resolves links before it grants."""
    real, link = box.tmp / "tools-1.2.3", box.tmp / "tools"
    real.mkdir()
    (real / "a.txt").write_text("TOOL", encoding="utf-8")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], check=True, capture_output=True)
    code = f'''
t("through the link", lambda: open({str(link / "a.txt")!r}).read())
'''
    sb.prepare(box.name, box.state_dir, {**member_grants(box.prof, box.pybase), str(link): "read"})      # as before 1.21.1
    assert inside(box, code)["through the link"] == "ERR PermissionError"
    grants = member_grants(box.prof, box.pybase, {str(link): "read"})                                   # as the start does it
    assert os.path.normcase(os.path.realpath(str(real))) in {os.path.normcase(k) for k in grants}
    assert not any(os.path.normcase(k) == os.path.normcase(str(link)) for k in grants)
    sb.prepare(box.name, box.state_dir, grants)
    assert inside(box, code)["through the link"] == "OK TOOL"


# ------------------------------------------------------------------ AC-3: the relay serves a bounded number
@windows
def test_a_relay_serves_no_more_connections_than_its_limit(tmp_path):
    import _winapi
    held, lock = [], threading.Lock()
    lst = socket.socket()
    lst.bind(("127.0.0.1", 0))
    lst.listen(16)

    def accept():
        while True:
            try:
                c, _ = lst.accept()
            except OSError:
                return
            with lock:
                held.append(c)
    threading.Thread(target=accept, daemon=True).start()
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    sid = sb.ensure_container(name)
    pipe = rl.new_pipe_name()
    server = rl.PipeRelayServer(pipe, sid, f"127.0.0.1:{lst.getsockname()[1]}", max_connections=2).start()
    clients = []

    def connect():
        for _ in range(200):
            try:
                return _winapi.CreateFile(pipe, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, 0,
                                          _winapi.OPEN_EXISTING, 0, 0)
            except OSError as e:
                if e.winerror not in (231, 2):      # busy / the next instance is not there yet
                    raise
                time.sleep(0.02)
        raise AssertionError("no pipe instance")

    def wait_for(cond, seconds=15):
        end = time.monotonic() + seconds
        while not cond() and time.monotonic() < end:
            time.sleep(0.05)
        return cond()
    try:
        for _ in range(5):
            clients.append(connect())
        assert wait_for(lambda: server.refused == 3), server.refused
        assert wait_for(lambda: len(held) == 2) and len(held) == 2          # the target saw two, not five
        _winapi.CloseHandle(clients.pop(0))                                  # one ends: its place is free again
        with lock:
            for c in held:
                c.close()
        # the relay's threads give the places back a moment later: connect until one is served
        end = time.monotonic() + 20
        while len(held) < 3 and time.monotonic() < end:
            h = connect()
            clients.append(h)
            if not wait_for(lambda: len(held) >= 3, 0.5):
                _winapi.CloseHandle(clients.pop())
        assert len(held) >= 3
    finally:
        for h in clients:
            try:
                _winapi.CloseHandle(h)
            except OSError:
                pass
        server.stop()
        lst.close()
        sb.delete_container(name)


# ------------------------------------------------------------------ AC-4: never outside the kill-on-close job
@windows
def test_a_process_that_cannot_join_its_job_never_runs(tmp_path):
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    st = sb.prepare(name, str(tmp_path / "state"), {str(tmp_path): "modify"})
    marker = tmp_path / "ran.txt"
    cmd_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    line = f'"{cmd_exe}" /d /c echo ran> "{marker}"'
    good = workers._Job()
    closed = workers._Job()
    stale = closed.handle
    closed.close()
    try:
        for job in ([good, SimpleNamespace(handle=None)], [SimpleNamespace(handle=stale)]):
            with open(tmp_path / "err.log", "ab") as logf, pytest.raises(sb.SandboxError, match="kill-on-close job"):
                sb.spawn(line, env_for(tmp_path), str(tmp_path), st["sid"], [], logf, job=job)
        time.sleep(0.5)
        assert not marker.exists()                       # ended while still suspended
        with open(tmp_path / "err.log", "ab") as logf:    # and with its jobs it runs
            p = sb.spawn(line, env_for(tmp_path), str(tmp_path), st["sid"], [], logf, job=[good])
        p.stdin.close()
        p.wait(30)
        assert marker.exists()
    finally:
        good.close()
        sb.remove(str(tmp_path / "state"), name)


# ------------------------------------------------------------------ AC-2: the grant rules of MXC hold here too
@windows
async def test_the_appcontainer_start_leaves_protected_folders_out(tmp_path, monkeypatch):
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "profiles")}}), None)
    prof, code, team = tmp_path / "profiles" / "alice", tmp_path / "code", tmp_path / "team"
    native, tools = tmp_path / "native", tmp_path / "tools"
    for d in (prof, code / "goose_web", team, native, tools, tmp_path / "profiles" / "bob", Path(s.system_dir)):
        d.mkdir(parents=True, exist_ok=True)
    grants = {str(prof): "modify", str(team): "modify", str(tools): "read",
              str(code): "modify",                                   # a folder above the code
              str(code / "goose_web").upper(): "modify",             # the code itself, in another spelling
              str(tmp_path / "profiles" / "bob"): "modify",          # another member
              str(s.system_dir): "read", str(native): "read",        # the gateway's data, the native Goose profile
              str(tmp_path / "profiles"): "read"}
    spec = {"name": "GooseWeb.test.filter", "profile_root": str(prof), "relays": [], "grants": grants, "caps": [],
            "backend": "appcontainer", "config_problems": [], "profiles_root": str(tmp_path / "profiles"),
            "system_dir": str(s.system_dir), "protected_write": [str(code / "goose_web")],
            "protected_any": [str(native)]}
    seen = {}

    def prepare(name, state_dir, g):
        seen.update(g)
        raise sb.SandboxError("stop here")
    monkeypatch.setattr(sb, "prepare", prepare)
    wm = workers.WorkerManager(s)
    wm.register("alice", "alice", str(prof), False, [], sandbox=spec)
    try:
        with pytest.raises(RuntimeError, match="stop here"):
            await wm.ensure("alice")
    finally:
        await wm.shutdown()
    kept = {os.path.normcase(os.path.realpath(k)): v for k, v in seen.items()}
    assert kept == {os.path.normcase(os.path.realpath(str(prof))): "modify",
                    os.path.normcase(os.path.realpath(str(team))): "modify",
                    os.path.normcase(os.path.realpath(str(tools))): "read"}


# ------------------------------------------------------------------ AC-5: the URL rewrite
def test_a_relay_target_rewrites_only_its_own_port():
    m = {"10.0.0.5:80": "127.64.0.8:80", "127.0.0.1:4000": "127.64.0.8:4000", "not a target": "x"}
    text = "a: http://10.0.0.5:8080/v1\nb: http://10.0.0.5:80/v1\nc: http://localhost:4000\nd: http://127.0.0.1:40001/"
    assert rl.rewrite_text(text, m) == ("a: http://10.0.0.5:8080/v1\nb: http://127.64.0.8:80/v1\n"
                                        "c: http://127.64.0.8:4000\nd: http://127.0.0.1:40001/")
    back = {v: k for k, v in m.items() if k != "not a target"}
    # undone, "localhost" comes back as 127.0.0.1 (the same service); nothing else differs
    assert rl.rewrite_text(rl.rewrite_text(text, m), back) == text.replace("localhost:4000", "127.0.0.1:4000")


def _profile(tmp_path) -> Path:
    root = tmp_path / "profile"
    (root / "config" / "custom_providers").mkdir(parents=True)
    (root / "config" / "config.yaml").write_bytes(b"OPENAI_HOST: http://127.0.0.1:4000\nother: 1\n")
    (root / "config" / "custom_providers" / "p.json").write_bytes(b'{"base_url": "http://localhost:4000/v1"}')
    return root


def test_the_rewrite_keeps_bytes_and_leaves_no_temporary_file(tmp_path):
    root = _profile(tmp_path)
    m = {"127.0.0.1:4000": "127.64.0.8:4000"}
    changed = rl.rewrite_profile_urls(str(root), m)
    assert len(changed) == 2
    assert (root / "config" / "config.yaml").read_bytes() == b"OPENAI_HOST: http://127.64.0.8:4000\nother: 1\n"
    assert (root / "config" / "custom_providers" / "p.json").read_bytes() == b'{"base_url": "http://127.64.0.8:4000/v1"}'
    assert rl.rewrite_profile_urls(str(root), m) == []                      # idempotent
    assert rl.restore_profile_urls(str(root), m) and \
        (root / "config" / "config.yaml").read_bytes() == b"OPENAI_HOST: http://127.0.0.1:4000\nother: 1\n"
    assert not [p.name for p in root.rglob("*") if ".tmp" in p.name]


def test_the_rewrite_never_writes_through_a_link(tmp_path):
    """The member can write in config/: a provider file with a second name outside the profile, or a providers
    folder that is a link, must not lead the gateway to rewrite a file somewhere else."""
    root = _profile(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.json"
    victim.write_bytes(b'{"u": "http://127.0.0.1:4000/"}')
    try:
        os.link(victim, root / "config" / "custom_providers" / "linked.json")
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    big = root / "config" / "custom_providers" / "big.json"
    big.write_bytes(b'{"u": "http://127.0.0.1:4000/"}' + b" " * rl.MAX_REWRITE_BYTES)
    changed = rl.rewrite_profile_urls(str(root), {"127.0.0.1:4000": "127.64.0.8:4000"})
    assert victim.read_bytes() == b'{"u": "http://127.0.0.1:4000/"}'
    assert not any(n.endswith(("linked.json", "big.json")) for n in changed) and len(changed) == 2
    if sys.platform == "win32":
        root2 = tmp_path / "p2"
        (root2 / "config").mkdir(parents=True)
        (outside / "prov").mkdir()
        (outside / "prov" / "x.json").write_bytes(b'{"u": "http://127.0.0.1:4000/"}')
        subprocess.run(["cmd", "/c", "mklink", "/J", str(root2 / "config" / "custom_providers"), str(outside / "prov")],
                       check=True, capture_output=True)
        assert rl.rewrite_profile_urls(str(root2), {"127.0.0.1:4000": "127.64.0.8:4000"}) == []
        assert b"127.0.0.1:4000" in (outside / "prov" / "x.json").read_bytes()
        root3 = tmp_path / "p3"
        root3.mkdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(root3 / ".goose-web"), str(outside / "prov")], check=True,
                       capture_output=True)
        with pytest.raises(OSError, match="is a link"):
            rl.write_forwarder(str(root3))
        assert not (outside / "prov" / "relay_forwarder.py").exists()


def test_the_forwarder_file_replaces_a_linked_name(tmp_path):
    root = tmp_path / "profile"
    (root / ".goose-web").mkdir(parents=True)
    victim = tmp_path / "victim.py"
    victim.write_text("print('mine')", encoding="utf-8")
    try:
        os.link(victim, root / ".goose-web" / "relay_forwarder.py")
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    p = Path(rl.write_forwarder(str(root)))
    assert p.read_bytes().decode("utf-8") == rl.FORWARDER_SRC and victim.read_text(encoding="utf-8") == "print('mine')"
    before = p.stat().st_mtime_ns
    assert rl.write_forwarder(str(root)) == str(p) and p.stat().st_mtime_ns == before      # unchanged: not rewritten


def test_write_atomic_is_whole_or_nothing(tmp_path, monkeypatch):
    f = tmp_path / "state.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("victim", encoding="utf-8")
    try:
        os.link(victim, f)                                    # the target name is a second name of another file
    except (OSError, NotImplementedError):
        f.write_text("old", encoding="utf-8")
    sb.write_atomic(f, "new\n")
    assert f.read_bytes() == b"new\n" and victim.read_text(encoding="utf-8") == "victim"      # replaced, not written through
    opened = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda p, flags, *a, **k: opened.append(flags) or real_open(p, flags, *a, **k))
    sb.write_atomic(f, "newer")
    assert opened and all(fl & os.O_EXCL for fl in opened)     # the temporary file is always a new file
    # a reader holds the target for a moment (V-5): the move is tried again
    real_replace, calls = os.replace, []

    def busy_twice(a, b):
        calls.append(a)
        if len(calls) < 3:
            raise PermissionError(13, "in use")
        return real_replace(a, b)
    monkeypatch.setattr(os, "replace", busy_twice)
    sb.write_atomic(f, "third")
    assert f.read_bytes() == b"third" and len(calls) == 3
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(OSError("no")))
    with pytest.raises(OSError):
        sb.write_atomic(f, "fourth")
    assert f.read_bytes() == b"third" and sorted(p.name for p in tmp_path.iterdir()) == ["state.json", "victim.txt"]


def test_the_relay_record_is_written_before_the_rewrite(tmp_path, monkeypatch):
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "profiles")}}), None)
    prof = tmp_path / "profiles" / "alice"
    prof.mkdir(parents=True)
    wm = workers.WorkerManager(s)
    spec = {"name": "GooseWeb.test.rec", "profile_root": str(prof),
            "relays": [{"target": "127.0.0.1:4000", "listen": "127.64.0.8:4000"}]}
    w = wm.register("alice", "alice", str(prof), False, [], sandbox=spec)
    limits = []

    class Server:
        def __init__(self, pipe, sid, target, limit):
            limits.append(limit)

        def start(self):
            return self

        def stop(self):
            pass
    monkeypatch.setattr(rl, "PipeRelayServer", Server)
    monkeypatch.setattr(rl, "write_forwarder", lambda root: "fwd.py")
    monkeypatch.setattr(sb, "spawn", lambda *a, **k: SimpleNamespace(kill=lambda: None))
    monkeypatch.setattr(workers, "_first_line", lambda p, seconds: "listening")
    monkeypatch.setattr(rl, "rewrite_profile_urls", lambda root, m: (_ for _ in ()).throw(OSError("disk full")))
    record = Path(s.system_dir) / "sandbox" / "GooseWeb.test.rec.relays.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text("[1, 2]", encoding="utf-8")                 # a damaged record does not stop the relays
    with pytest.raises(OSError, match="disk full"):
        wm._start_relays(w, "S-1-15-2-1")
    assert json.loads(record.read_text(encoding="utf-8")) == {"127.0.0.1:4000": "127.64.0.8:4000"}
    assert limits == [DEFAULTS["sandbox"]["proxy_max_connections"]]
    wm._stop_relays(w)


def test_a_forwarder_that_says_nothing_does_not_hold_the_start():
    release = threading.Event()
    silent = SimpleNamespace(stdout=SimpleNamespace(readline=lambda: release.wait(30) and b""))
    t0 = time.monotonic()
    assert workers._first_line(silent, 0.2) == "" and time.monotonic() - t0 < 5
    release.set()
    assert workers._first_line(SimpleNamespace(stdout=SimpleNamespace(readline=lambda: b"listening\r\n")), 5) == "listening"


# ------------------------------------------------------------------ AC-6: sandbox.relays
def test_relay_targets_are_checked():
    from goose_web import mxc
    from goose_web.config import sandbox_relay_problems
    for ok in ("127.0.0.1:4000", "localhost:8080", "model-proxy.internal:443", "my_host:1"):
        assert rl.target_problem(ok) == ""
    for bad in ("nonsense", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000", "[::1]:8080", "a b:80", "h/x:80", 4000,
                ":80", "127.0.0.1:http", "a..b:80", "-:80", "x" * 64 + ":80", ".a:80"):
        assert rl.target_problem(bad), bad
    s = Settings(_deep_merge(DEFAULTS, {"sandbox": {"relays": ["127.0.0.1:4000", "oops", ""]}}), None)
    assert sandbox_relay_problems(s) == [
        "sandbox.relays entry 'oops' is left out: not host:port; use host:port, for example 127.0.0.1:4000"]
    # a relay that is not there means less access, never more: members' agents still start (V-6)
    assert not sandbox_config_problems(s) and mxc.summary(s)["relayProblems"] == sandbox_relay_problems(s)
    for odd in ("127.0.0.1:4000", 4000, True, {"a": 1}):                     # not a list: nothing relayed, said so (V-7)
        s = Settings(_deep_merge(DEFAULTS, {"sandbox": {"relays": odd}}), None)
        sm = mxc.summary(s)
        assert sm["relays"] == [] and "use a list" in sm["relayProblems"][0] and not sandbox_config_problems(s)
    assert sandbox_relay_problems(Settings(_deep_merge(DEFAULTS, {}), None)) == []


def test_two_services_on_one_port_get_an_address_each():
    """V-12: they shared one forward address, the second forwarder could not bind, and that stopped every relay."""
    specs = rl.relay_specs("n", 7, ["127.0.0.1:4000", "10.0.0.5:4000", "127.0.0.1:4000", "LOCALHOST:8080"])
    assert [s["target"] for s in specs] == ["127.0.0.1:4000", "10.0.0.5:4000", "LOCALHOST:8080"]
    assert [s["listen"] for s in specs] == ["127.64.0.8:4000", "127.65.0.8:4000", "127.64.0.8:8080"]
    assert rl.relay_specs("n", 7, ["127.0.0.1:4000"]) == [{"target": "127.0.0.1:4000", "listen": "127.64.0.8:4000"}]
    assert len(rl.relay_specs("n", 7, [f"h{i}:9" for i in range(rl.FORWARD_BLOCKS + 3)])) == rl.FORWARD_BLOCKS
    assert len({s["listen"] for s in rl.relay_specs("n", 7, [f"h{i}:9" for i in range(rl.FORWARD_BLOCKS)])}) == rl.FORWARD_BLOCKS


def test_a_bad_relay_entry_is_left_out_and_reported_not_a_failed_connection(tmp_path, monkeypatch, caplog):
    from goose_web.auth import AuthService
    from goose_web.context import Ctx
    from goose_web.config import load_settings
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    from tests.test_team_profiles import ANYCHAT, team, user
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=None, hub=None, version="t")
    bob = user(db, "bob")
    db.set_user_team(bob["id"], team(db, "A", ANYCHAT))
    s.data.setdefault("sandbox", {}).update({"enabled": True, "relays": ["127.0.0.1:4000", "oops-1", "[::1]:9"]})
    with caplog.at_level("ERROR"):
        spec = c.sandbox_spec(db.user_by_id(bob["id"]))
        c.sandbox_spec(db.user_by_id(bob["id"]))
    assert spec["relay_targets"] == ["127.0.0.1:4000"] and spec["config_problems"] == []
    assert sum("'oops-1' is left out" in r.getMessage() for r in caplog.records) == 1       # logged once
    s.data["sandbox"]["relays"] = "127.0.0.1:4000"                                           # not a list: no relay
    assert c.sandbox_spec(db.user_by_id(bob["id"]))["relays"] == []
    db.close()


# ------------------------------------------------------------------ V-4: a restore that could not finish is owed
def test_a_restore_that_cannot_finish_is_tried_again(tmp_path, monkeypatch):
    root = _profile(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    m = {"127.0.0.1:4000": "127.64.0.8:4000"}
    assert len(rl.rewrite_profile_urls(str(root), m)) == 2
    (state / "N.relays.json").write_text(json.dumps(m), encoding="utf-8")
    cfg = root / "config" / "config.yaml"
    real = sb.write_atomic
    monkeypatch.setattr(sb, "write_atomic", lambda p, text: (_ for _ in ()).throw(PermissionError(13, "in use"))
                        if Path(p) == cfg else real(p, text))
    changed = rl.undo_relays(str(state), "N", str(root))                    # the worker moves to MXC
    assert [Path(x).name for x in changed] == ["p.json"] and b"127.64.0.8" in cfg.read_bytes()
    assert not (state / "N.relays.json").exists()                           # no relay runs: state_mapping says so
    assert rl.state_mapping(state, "N") == {}
    assert json.loads((state / "N.relays.undo.json").read_text(encoding="utf-8")) == m       # but the restore is owed
    monkeypatch.setattr(sb, "write_atomic", real)
    assert [Path(x).name for x in rl.undo_relays(str(state), "N", str(root))] == ["config.yaml"]
    assert b"http://127.0.0.1:4000" in cfg.read_bytes() and not (state / "N.relays.undo.json").exists()
    # a file with a second name is not touched, and stays owed until the name is gone
    rl.rewrite_profile_urls(str(root), m)
    try:
        os.link(cfg, root / "config" / "copy.yaml")
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    rl.restore_pending(str(state), "N", str(root), m)
    assert b"127.64.0.8" in cfg.read_bytes() and (state / "N.relays.undo.json").exists()
    assert rl.restore_pending(str(state), "N", str(root), None, active=m) == []             # the relay is back: nothing owed
    assert not (state / "N.relays.undo.json").exists()
    (state / "N.relays.undo.json").write_text(json.dumps(m), encoding="utf-8")
    (root / "config" / "copy.yaml").unlink()
    assert len(rl.restore_pending(str(state), "N", str(root))) == 1 and b"http://127.0.0.1:4000" in cfg.read_bytes()
    assert not (state / "N.relays.undo.json").exists()
    (state / "N.relays.undo.json").write_text("[1]", encoding="utf-8")       # damaged, or the user is gone
    assert rl.restore_pending(str(state), "N", None) == [] and not (state / "N.relays.undo.json").exists()


def test_the_forwarder_file_is_never_read_beyond_its_size(tmp_path, monkeypatch):
    """V-3: the member can leave any file under that name; the gateway compares the size first."""
    import builtins
    root = tmp_path / "profile"
    (root / ".goose-web").mkdir(parents=True)
    p = root / ".goose-web" / "relay_forwarder.py"
    p.write_bytes(b"x" * (len(rl.FORWARDER_SRC.encode()) + 1))
    reads = []
    real_open = builtins.open

    def spy(file, mode="r", *a, **k):
        if "r" in mode and Path(file) == p:
            reads.append(mode)
        return real_open(file, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", spy)
    real_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda self: reads.append("read_bytes") or real_read(self)
                        if self == p and not reads_allowed else real_read(self))
    reads_allowed = False
    rl.write_forwarder(str(root))
    reads_allowed = True
    assert reads == [] and p.read_bytes() == rl.FORWARDER_SRC.encode()        # replaced without being read
    p.write_bytes(b"y" * len(rl.FORWARDER_SRC.encode()))                      # same size, other content
    rl.write_forwarder(str(root))
    assert p.read_bytes() == rl.FORWARDER_SRC.encode()


def test_a_revoke_that_fails_stays_on_record(tmp_path, monkeypatch):
    """V-10: the entry is still on the folder; forgetting it would leave it there for good."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    monkeypatch.setattr(sb, "ensure_container", lambda name: "S-1-15-2-9")
    monkeypatch.setattr(sb, "grant", lambda p, sid, right: None)
    monkeypatch.setattr(sb, "revoke", lambda p, sid: None)
    state = str(tmp_path / "state")
    sb.prepare("N", state, {str(a): "modify", str(b): "modify"})
    monkeypatch.setattr(sb, "revoke", lambda p, sid: (_ for _ in ()).throw(sb.SandboxError("icacls failed")))
    st = sb.prepare("N", state, {str(a): "modify"})                           # b is no longer granted
    assert st["grants"] == {str(a): "modify"} and st["pending"] == {str(b): "modify"}
    tried = []
    monkeypatch.setattr(sb, "revoke", lambda p, sid: tried.append(p))
    st = sb.prepare("N", state, {str(a): "modify"})                           # the next start tries again
    assert tried == [str(b)] and st["pending"] == {}


@windows
def test_a_target_that_cannot_be_connected_closes_the_pipe(tmp_path):
    """V-8: a name that cannot be encoded raises something that is not an OSError; the pipe instance was left open."""
    import _winapi
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    sid = sb.ensure_container(name)
    pipe = rl.new_pipe_name()
    server = rl.PipeRelayServer(pipe, sid, "a..b:80").start()
    try:
        h = _winapi.CreateFile(pipe, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, 0, _winapi.OPEN_EXISTING, 0, 0)
        closed, end = False, time.monotonic() + 40
        while not closed and time.monotonic() < end:
            try:
                _winapi.PeekNamedPipe(h, 0)
                time.sleep(0.1)
            except OSError:
                closed = True
        _winapi.CloseHandle(h)
        assert closed
    finally:
        server.stop()
        sb.delete_container(name)


# ------------------------------------------------------------------ AC-1: what `check` says about the registry
def test_names_that_look_like_secrets():
    for n in ("CUSTOM_X_API_KEY", "GH_TOKEN", "db.password", "Secret", "AWS_SECRET_ACCESS_KEY", "npm_config_pwd",
              "OPENAI_API_KEY2", "GITHUB_PAT", "apiToken", "TOKENS", "KEYS", "PASSWORDS", "AUTH", "CONNECTION_STRING",
              "dbPassword", "SqlConnectionString"):
        assert winsec.secret_looking(n), n
    for n in ("GOOSE_DISABLE_KEYRING", "MONKEY", "Path", "PATH", "PATHEXT", "TEMP", "TOKENIZERS_PARALLELISM",
              "OneDrive", "", "PROCESSOR_LEVEL", "ComSpec", "NUMBER_OF_PROCESSORS", "DriverData", "123"):
        assert not winsec.secret_looking(n), n


def test_check_names_the_variables_a_sandboxed_agent_can_read(monkeypatch):
    from goose_web.__main__ import _registry_line
    on = Settings(_deep_merge(DEFAULTS, {"sandbox": {"enabled": True}}), None)
    off = Settings(_deep_merge(DEFAULTS, {"sandbox": {"enabled": False}}), None)
    names = ["Path", "TEMP", "B_API_KEY", "A_TOKEN", "C_KEY", "D_KEY", "E_KEY", "F_SECRET", "GOOSE_DISABLE_KEYRING"]
    monkeypatch.setattr(winsec, "user_environment_names", lambda: names)
    monkeypatch.setattr(winsec, "machine_environment_names", lambda: ["Path", "OS"])
    line = _registry_line(on)
    assert line.startswith("[!!] registry: 6 environment variable(s) stored in the registry are named like secrets")
    assert "(user variables of this account: A_TOKEN, B_API_KEY, C_KEY, D_KEY, E_KEY and 1 more)" in line
    assert "MXC and AppContainer alike" in line and "an account used for nothing else" in line
    assert "the sandbox is off" in _registry_line(off)
    # machine variables are readable too, and another account does not help with those (V-2)
    monkeypatch.setattr(winsec, "machine_environment_names", lambda: ["Path", "SERVICE_PASSWORD"])
    line = _registry_line(on)
    assert "7 environment variable(s)" in line and "machine variables: SERVICE_PASSWORD" in line
    assert "machine variables are readable under any account" in line
    monkeypatch.setattr(winsec, "user_environment_names", lambda: ["Path", "TEMP"])
    line = _registry_line(on)
    assert line.startswith("[!!] registry: 1 environment") and "Keep secrets out of machine variables" in line
    assert "an account used for nothing else" not in line
    monkeypatch.setattr(winsec, "machine_environment_names", lambda: ["Path"])
    ok = _registry_line(on)
    assert ok.startswith("[OK] registry: none of the 2 user and 1 machine environment variable(s)")
    assert "NAMED like a secret (values are not looked at)" in ok           # V-13: it says what it judges
    monkeypatch.setattr(winsec, "user_environment_names", lambda: None)
    monkeypatch.setattr(winsec, "machine_environment_names", lambda: None)
    assert _registry_line(on).startswith("[--] registry")


@windows
def test_the_user_environment_is_listed_by_name():
    for names in (winsec.user_environment_names(), winsec.machine_environment_names()):
        assert isinstance(names, list) and all(isinstance(n, str) for n in names)
    assert any(n.lower() == "path" for n in winsec.machine_environment_names())


def test_the_sandbox_environment_keeps_what_an_appcontainer_start_needs():
    # CreateProcess fails with error 203 for an AppContainer whose environment has no LOCALAPPDATA: Windows replaces
    # it, TEMP and TMP with the container's own folder (AC-9), and needs the variable to be there
    assert "LOCALAPPDATA" in workers.SANDBOX_ENV_ALLOW
