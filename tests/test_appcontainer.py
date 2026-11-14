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


# ------------------------------------------------------------------ folders whose permissions cannot be changed
def lock(folder: Path, *extra: str) -> None:
    """Take away this account's right to change the folder's permissions while it stays the owner ("OWNER RIGHTS:
    Modify"): what a folder that an administrator installed looks like to the gateway's account. Every earlier test
    used folders the test had made itself, where changing permissions always works - and so none saw that a grant
    which was never made was recorded as made (found in use, 2026-11-13)."""
    icacls = os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe")
    me = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]
    subprocess.run([icacls, str(folder), "/inheritance:r", "/grant:r", "*S-1-3-4:(OI)(CI)M", f"{me}:(OI)(CI)M",
                    *extra, "/Q"], check=True, capture_output=True)
    still = subprocess.run([icacls, str(folder), "/grant", "*S-1-15-2-2:(RX)", "/Q"], capture_output=True)
    if sb.can_change_permissions(str(folder)) or still.returncode == 0:
        pytest.skip("this account can change the permissions of a folder it was denied that on")


def _key(grants: dict, folder: Path) -> str:
    return next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(folder))))


def _touch(folder: Path) -> str:
    return f'''
t("read", lambda: open({str(folder / "f.txt")!r}).read())
t("write", lambda: open({str(folder / "w.txt")!r}, "w").write("x"))
'''


@windows
def test_a_grant_that_was_not_made_is_not_recorded_as_made(box):
    team = box.tmp / "team"
    team.mkdir()
    (team / "f.txt").write_text("TEAM", encoding="utf-8")
    lock(team)
    grants = member_grants(box.prof, box.pybase, {str(team): "modify"})
    st = sb.prepare(box.name, box.state_dir, grants, required=[str(box.prof)])
    key = next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(team))))
    assert key not in st["grants"] and key in st["failed"]                 # 1.21.1 said "granted"
    assert f'icacls "{key}" /grant' in st["failed"][key] and "(OI)(CI)F" in st["failed"][key]
    assert sb.load_state(box.state_dir, box.name)["failed"] == st["failed"]
    r = inside(box, _touch(team))
    assert r["read"] == "ERR PermissionError" and r["write"] == "ERR PermissionError"      # and the record agrees
    assert inside(box, "t('own', lambda: open('own.txt', 'w').write('x'))")["own"].startswith("OK")   # the agent runs
    # the administrator puts the folder right (here: a new folder under that name): the next start grants it
    import shutil
    shutil.rmtree(team)
    team.mkdir()
    (team / "f.txt").write_text("TEAM", encoding="utf-8")
    st = sb.prepare(box.name, box.state_dir, grants, required=[str(box.prof)])
    assert key in st["grants"] and not st["failed"]
    r = inside(box, _touch(team))
    assert r["read"] == "OK TEAM" and r["write"].startswith("OK")


@windows
def test_a_folder_the_agent_cannot_run_without_fails_the_start_and_says_what_to_do(box):
    programs = box.tmp / "programs"
    programs.mkdir()
    lock(programs)
    grants = member_grants(box.prof, box.pybase, {str(programs): "read"})
    key = next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(programs))))
    with pytest.raises(sb.SandboxError) as e:
        sb.prepare(box.name, box.state_dir, grants, required=[str(box.prof), key])
    assert f'icacls "{key}" /grant "*S-1-15-2-1:(OI)(CI)RX"' in str(e.value) and "may not change its permissions" in str(e.value)


@windows
def test_a_folder_every_container_may_read_is_left_alone(box):
    """C:\\Program Files gives "ALL APPLICATION PACKAGES" read access and belongs to the system: the gateway's
    account cannot change it and does not have to. The start used to try, fail unnoticed, and record a grant."""
    programs = box.tmp / "programs"
    programs.mkdir()
    (programs / "f.txt").write_text("TOOL", encoding="utf-8")
    lock(programs, "*S-1-15-2-1:(OI)(CI)RX")
    grants = member_grants(box.prof, box.pybase, {str(programs): "read"})
    key = next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(programs))))
    st = sb.prepare(box.name, box.state_dir, grants, required=[str(box.prof), key])
    assert st["external"] == {key: "read"} and key not in st["grants"] and not st["failed"]
    assert inside(box, _touch(programs))["read"] == "OK TOOL"
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase))       # no longer wanted
    assert not st.get("external") and not st["pending"] and not st["failed"]             # nothing of ours to take off


@windows
def test_a_grant_on_record_that_is_not_on_the_folder_is_made_again(box):
    """An installation that ran 1.21.1 or earlier has such records; they must not stay wrong for good."""
    shared = box.tmp / "shared"
    shared.mkdir()
    (shared / "f.txt").write_text("SHARED", encoding="utf-8")
    grants = member_grants(box.prof, box.pybase, {str(shared): "modify"})
    key = next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(shared))))
    st = sb.load_state(box.state_dir, box.name)
    sb._save_state(box.state_dir, box.name, {**st, "grants": {**st["grants"], key: "modify"}})     # the old record
    assert inside(box, _touch(shared))["read"] == "ERR PermissionError"
    st = sb.prepare(box.name, box.state_dir, grants)
    assert key in st["grants"] and inside(box, _touch(shared))["read"] == "OK SHARED"


@windows
def test_an_entry_that_could_not_be_taken_off_stays_on_record(box):
    shared = box.tmp / "shared"
    shared.mkdir()
    (shared / "f.txt").write_text("SHARED", encoding="utf-8")
    grants = member_grants(box.prof, box.pybase, {str(shared): "modify"})
    key = next(k for k in grants if os.path.normcase(k) == os.path.normcase(os.path.realpath(str(shared))))
    assert key in sb.prepare(box.name, box.state_dir, grants)["grants"]
    lock(shared)                                        # from now on its permissions cannot be changed
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase))       # the folder is taken away
    assert key not in st["grants"] and st["pending"] == {key: "modify"}                 # 1.21.1: "revoked"
    assert inside(box, _touch(shared))["read"] == "OK SHARED"                           # true: it is still there
    left = sb.remove(box.state_dir, box.name)
    assert left and sb.load_state(box.state_dir, box.name).get("pending") == {key: "modify"}


@windows
def test_folders_this_account_cannot_prepare_are_named(tmp_path):
    plain, ac, ours, root = tmp_path / "plain", tmp_path / "ac", tmp_path / "ours", tmp_path / "profiles"
    for d in (plain, ac, ours, root):
        d.mkdir()
    assert sb.can_change_permissions(str(ours)) and not sb.allowed(str(ours), [sb.ALL_APP_PACKAGES], "read")
    lock(plain)
    lock(ac, "*S-1-15-2-1:(OI)(CI)RX")
    assert sb.allowed(str(ac), [sb.ALL_APP_PACKAGES], "read") and not sb.allowed(str(ac), [sb.ALL_APP_PACKAGES], "modify")
    probs = sb.folder_problems([str(plain), str(ac), str(ours), str(tmp_path / "missing")], str(root))
    assert [p["path"] for p in probs] == [str(plain)] and "*S-1-15-2-1:(OI)(CI)RX" in probs[0]["why"]
    lock(root)
    probs = sb.folder_problems([str(ours)], str(root))
    assert [p["path"] for p in probs] == [str(root)] and ":(OI)(CI)F" in probs[0]["why"]


def test_check_and_status_report_the_folders_only_where_the_appcontainer_backend_may_be_used(tmp_path, monkeypatch, capsys):
    from goose_web import mxc
    root = str(tmp_path / "profiles")
    seen = []
    monkeypatch.setattr(sb, "folder_problems", lambda folders, r: seen.append(list(folders)) or [
        {"path": r, "why": "ROOT: do this"}, {"path": "X:\\tools", "why": "TOOLS: do that"}])
    base = {"paths": {"profiles_root": root}}
    for sandbox, expected, fatal in (({"enabled": True, "backend": "appcontainer"}, True, [True, False]),
                                     ({"enabled": True, "backend": "mxc", "fallback": "appcontainer"}, True, [False, False]),
                                     ({"enabled": True, "backend": "mxc", "fallback": "none"}, False, None),
                                     ({"enabled": False, "backend": "appcontainer"}, False, None)):
        sm = mxc.summary(Settings(_deep_merge(DEFAULTS, {**base, "sandbox": sandbox}), None))
        assert ("folderProblems" in sm) is expected, sandbox
        if expected:        # only what no agent can run without stops `check`, and only for the configured backend (X-3)
            assert [p["fatal"] for p in sm["folderProblems"]] == fatal
    # the gateway's Python is looked at only when something is relayed (X-3)
    seen.clear()
    quiet = {"enabled": True, "backend": "appcontainer", "relays": []}
    mxc.summary(Settings(_deep_merge(DEFAULTS, {**base, "sandbox": quiet, "guard": {"classifier_port": 0}}), None))
    mxc.summary(Settings(_deep_merge(DEFAULTS, {**base, "sandbox": {**quiet, "relays": ["127.0.0.1:4000"]},
                                                "guard": {"classifier_port": 0}}), None))
    py = os.path.normcase(mxc.resolved(sys.base_prefix))
    assert py not in {os.path.normcase(f) for f in seen[0]} and py in {os.path.normcase(f) for f in seen[1]}


@windows
def test_a_folder_taken_from_a_team_loses_its_entry_at_once(tmp_path, monkeypatch):
    """Nothing is mocked: the entry is put on a real folder by a real start's prepare, the administrator removes the
    folder from the team, and the entry is gone from the folder - without the member's agent starting again.
    Before, it stayed until that agent next started, for good when it never did."""
    import asyncio
    from goose_web import api
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
    extra = tmp_path / "approved"
    extra.mkdir()
    tid = team(db, "A", {**ANYCHAT, "allowed_roots": [str(extra)]})
    bob, carol = user(db, "bob"), user(db, "carol")
    db.set_user_team(bob["id"], tid)
    db.set_user_team(carol["id"], tid)
    s.data.setdefault("sandbox", {})["enabled"] = True
    spec = c.sandbox_spec(db.user_by_id(bob["id"]))
    Path(spec["profile_root"]).mkdir(parents=True, exist_ok=True)
    grants, _, required = workers.appcontainer_grants(spec, s)
    state_dir = str(s.system_dir / "sandbox")
    st = sb.prepare(spec["name"], state_dir, grants, required=required)       # what the start of bob's agent does
    try:
        key, prof = _key(grants, extra), _key(grants, Path(spec["profile_root"]))
        assert sb.allowed(key, [st["sid"]], "modify") and key in st["grants"]
        assert asyncio.run(api._sync_grants(c, db.user_by_id(bob["id"]))) == []           # nothing was taken away yet
        db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps(ANYCHAT), tid))    # the administrator removes it
        gone = asyncio.run(api._sync_grants(c, db.user_by_id(bob["id"])))
        assert [os.path.normcase(g) for g in gone] == [os.path.normcase(key)]
        assert sb.own_mask(key, st["sid"]) == 0 and not sb.allowed(key, [st["sid"]], "read")      # off the folder
        now = sb.load_state(state_dir, spec["name"])
        assert key not in now["grants"] and prof in now["grants"] and sb.allowed(prof, [st["sid"]], "modify")
        # nothing is granted and no container is made by an administrator's change: that is the next start's business
        db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**ANYCHAT, "allowed_roots": [str(extra)]}), tid))
        assert asyncio.run(api._sync_grants(c, db.user_by_id(bob["id"]))) == [] and sb.own_mask(key, st["sid"]) == 0
        cname = sb.container_name(str(s.profiles_root), "carol")
        assert asyncio.run(api._sync_grants(c, db.user_by_id(carol["id"]))) == [] and not sb.load_state(state_dir, cname)
    finally:
        sb.remove(state_dir, spec["name"])
        db.close()


@windows
def test_what_a_failed_start_put_on_folders_is_on_record_and_comes_off_later(box):
    """Review X-1: a start that gave two folders and then failed on a third saved nothing; at the next start those
    entries were taken for someone else's and never taken off again - a member kept a folder that was taken away."""
    team, programs = box.tmp / "team", box.tmp / "programs"
    team.mkdir()
    programs.mkdir()
    (team / "f.txt").write_text("TEAM", encoding="utf-8")
    lock(programs)
    grants = member_grants(box.prof, box.pybase, {str(team): "modify", str(programs): "read"})
    tkey, pkey = _key(grants, team), _key(grants, programs)
    with pytest.raises(sb.SandboxError, match="may not change its permissions"):
        sb.prepare(box.name, box.state_dir, grants, required=[str(box.prof), pkey])
    st = sb.load_state(box.state_dir, box.name)
    assert tkey in st["grants"] and pkey in st["failed"] and sb.allowed(tkey, [box.sid], "modify")    # saved first
    # worse: the record is lost altogether. What is on the folders is found and goes on record as Goose Web's.
    (Path(box.state_dir) / f"{box.name}.json").unlink()
    with_team = member_grants(box.prof, box.pybase, {str(team): "modify"})
    st = sb.prepare(box.name, box.state_dir, with_team, required=[str(box.prof)])
    assert tkey in st["grants"] and not st["external"] and not st["failed"]
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase), required=[str(box.prof)])
    assert sb.own_mask(tkey, box.sid) == 0 and tkey not in st["grants"] and not st["pending"]         # taken away: gone
    assert inside(box, _touch(team))["read"] == "ERR PermissionError"


@windows
def test_a_folder_taken_down_to_read_that_cannot_be_changed_is_not_recorded_as_read(box):
    """Review X-2: revoke and grant both failed, "read" was satisfied by the modify entry still there, and the
    record said read."""
    shared = box.tmp / "shared"
    shared.mkdir()
    (shared / "f.txt").write_text("SHARED", encoding="utf-8")
    grants = member_grants(box.prof, box.pybase, {str(shared): "modify"})
    key = _key(grants, shared)
    assert key in sb.prepare(box.name, box.state_dir, grants)["grants"]
    lock(shared)
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(shared): "read"}))
    assert key not in st["grants"] and key in st["failed"] and st["pending"] == {key: "modify"}
    assert sb.exceeds(key, box.sid, "read") and inside(box, _touch(shared))["write"].startswith("OK")   # and that is true
    # a record that says less than the folder carries (as 1.21.1 could leave it) is put right, not repeated (Z-2)
    sb._save_state(box.state_dir, box.name, {**st, "grants": {**st["grants"], key: "read"}, "pending": {}, "failed": {}})
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(shared): "read"}))
    assert st["pending"] == {key: "modify"} and "could not be narrowed" in st["failed"][key] and key not in st["grants"]
    # the same where every container may read the folder: nothing of the container's own is needed, what is there stays on record
    both = box.tmp / "both"
    both.mkdir()
    grants = member_grants(box.prof, box.pybase, {str(both): "modify"})
    bkey = _key(grants, both)
    sb.prepare(box.name, box.state_dir, grants)
    lock(both, "*S-1-15-2-1:(OI)(CI)RX")
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(both): "read"}))
    assert st["external"] == {bkey: "read"} and st["pending"].get(bkey) == "modify" and bkey not in st["grants"]


@windows
def test_taking_a_folder_away_takes_the_entry_off_what_is_below_it_too(box):
    """Review Z-1 (true of every earlier version): a subfolder whose inheritance was switched off keeps a copy of
    the container's entry as its own. The revoke looked at the folder only and reported success."""
    icacls = os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe")
    shared, stuck = box.tmp / "shared", box.tmp / "stuck"
    for top in (shared, stuck):
        (top / "sub").mkdir(parents=True)
        (top / "sub" / "f.txt").write_text("SUB", encoding="utf-8")
    grants = member_grants(box.prof, box.pybase, {str(shared): "modify", str(stuck): "modify"})
    skey, tkey = _key(grants, shared), _key(grants, stuck)
    sb.prepare(box.name, box.state_dir, grants)
    for top in (shared, stuck):       # "disable inheritance, convert to explicit" in Explorer
        subprocess.run([icacls, str(top / "sub"), "/inheritance:d", "/Q"], check=True, capture_output=True)
        assert sb.own_mask(str(top / "sub"), box.sid)
    lock(stuck / "sub")                # and this one cannot be changed any more
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase))       # both folders are taken away
    assert sb.own_mask(str(shared / "sub"), box.sid) == 0 and skey not in st["pending"]   # cleaned below as well
    assert inside(box, _touch(shared / "sub"))["read"] == "ERR PermissionError"
    assert st["pending"].get(tkey) == "modify" and sb.own_mask(str(stuck / "sub"), box.sid)   # true: still there, on record
    assert inside(box, _touch(stuck / "sub"))["read"] == "OK SUB"
    # a folder that is still wanted inside one that is taken away keeps its entry
    outer, inner = box.tmp / "outer", box.tmp / "outer" / "inner"
    inner.mkdir(parents=True)
    both = member_grants(box.prof, box.pybase, {str(outer): "modify", str(inner): "modify"})
    sb.prepare(box.name, box.state_dir, both)
    st = sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(inner): "modify"}))
    ikey = _key(both, inner)
    assert ikey in st["grants"] and sb.allowed(ikey, [box.sid], "modify") and sb.own_mask(_key(both, outer), box.sid) == 0


def test_a_damaged_record_stops_the_change_instead_of_being_forgotten(tmp_path, monkeypatch):
    """Review Z-5: it was read as "no record" and overwritten; the entries it listed stayed on their folders."""
    monkeypatch.setattr(sb, "ensure_container", lambda name: "S-1-15-2-9")
    state = tmp_path / "state"
    state.mkdir()
    a = tmp_path / "a"
    a.mkdir()
    for bad in ("{not json", json.dumps({"sid": "S-1-15-2-9", "grants": ["a"]}), json.dumps([1, 2])):
        f = state / "N.json"
        f.write_text(bad, encoding="utf-8")
        for call in (lambda: sb.prepare("N", str(state), {str(a): "modify"}), lambda: sb.shrink("N", str(state), {}),
                     lambda: sb.remove(str(state), "N")):
            with pytest.raises(sb.SandboxError, match="nothing was changed"):
                call()
        assert f.read_text(encoding="utf-8") == bad
    (state / "N.json").unlink()
    assert sb.shrink("N", str(state), {}) == {} and sb.remove(str(state), "N") == {}       # no record: nothing to do


@windows
def test_what_the_access_list_says(tmp_path):
    icacls = os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe")
    d = tmp_path / "d"
    d.mkdir()
    ac, sid = sb.ALL_APP_PACKAGES, "S-1-15-2-99-1-2-3-4-5-6"

    def set_(*entries):
        subprocess.run([icacls, str(d), "/remove:g", f"*{ac}", f"*{sid}", "/Q"], capture_output=True)
        subprocess.run([icacls, str(d), "/grant", *entries, "/Q"], check=True, capture_output=True)
    set_(f"*{ac}:(OI)(CI)RX")
    assert sb.allowed(str(d), [ac], "read") and not sb.allowed(str(d), [ac], "modify") and sb.own_mask(str(d), sid) == 0
    set_(f"*{ac}:(RX)", f"*{ac}:(OI)(CI)(IO)(GR,GE)")                   # how C:\Program Files is written
    assert sb.allowed(str(d), [ac], "read")
    set_(f"*{ac}:(RX)")                                                  # the folder only: its files are not covered
    assert not sb.allowed(str(d), [ac], "read")
    set_(f"*{ac}:(OI)(CI)(NP)RX")                                        # one level only (review X-8)
    assert not sb.allowed(str(d), [ac], "read")
    set_(f"*{sid}:(OI)(CI)M")
    assert sb.allowed(str(d), [sid], "modify") and sb.exceeds(str(d), sid, "read") and not sb.exceeds(str(d), sid, "modify")
    subprocess.run([icacls, str(d), "/deny", f"*{sid}:(OI)(CI)R", "/Q"], check=True, capture_output=True)
    assert not sb.allowed(str(d), [sid], "read")                         # a deny entry: nothing is assumed
    assert sb.access_of(str(tmp_path / "missing"), [ac]) is None and not sb.allowed(str(tmp_path / "missing"), [ac], "read")
    who, ident = sb._account()
    assert ident.startswith("*S-1-") and f'/grant "{ident}:(OI)(CI)F"' in sb.grant_help(str(d), "modify")     # X-7


# ------------------------------------------------------------------ AC-3: the relay serves a bounded number
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

    def prepare(name, state_dir, g, required=()):
        seen.update(g)
        seen_required.extend(required)
        raise sb.SandboxError("stop here")
    seen_required = []
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
    # the folders without which the agent cannot run at all: a grant that fails there fails the start
    assert os.path.normcase(os.path.realpath(str(prof))) in {os.path.normcase(p) for p in seen_required}


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
    assert rl.restore_pending(str(state), "N", str(root), None, active=m) == []             # the relay is back: not undone
    assert b"127.64.0.8" in cfg.read_bytes() and (state / "N.relays.undo.json").exists()    # owed until it is on record (W-2)
    rl.forget_owed(str(state), "N", m)
    assert not (state / "N.relays.undo.json").exists()
    (state / "N.relays.undo.json").write_text(json.dumps(m), encoding="utf-8")
    (root / "config" / "copy.yaml").unlink()
    assert len(rl.restore_pending(str(state), "N", str(root))) == 1 and b"http://127.0.0.1:4000" in cfg.read_bytes()
    assert not (state / "N.relays.undo.json").exists()
    (state / "N.relays.undo.json").write_text("[1]", encoding="utf-8")       # damaged, or the user is gone
    assert rl.restore_pending(str(state), "N", None) == [] and not (state / "N.relays.undo.json").exists()


def _start(state, root, old, new):
    """What workers._start_relays does with the URLs at one start, in its order."""
    gone = {k: v for k, v in old.items() if new.get(k) != v}
    rl.restore_pending(str(state), "N", str(root), gone, active=new)
    (state / "N.relays.json").write_text(json.dumps(new), encoding="utf-8")
    rl.forget_owed(str(state), "N", new)
    rl.rewrite_profile_urls(str(root), new)
    return new


def test_an_owed_restore_never_undoes_a_running_relay(tmp_path):
    """W-1: an owed entry whose forward address now belongs to another target was replayed at every start."""
    root = tmp_path / "profile"
    (root / "config" / "custom_providers").mkdir(parents=True)
    cfg = root / "config" / "config.yaml"
    cfg.write_bytes(b"a: http://10.0.0.5:8080/v1\nb: http://10.0.0.6:8080/v1\n")
    other = root / "config" / "custom_providers" / "x.json"
    other.write_bytes(b"{}")
    try:
        os.link(other, root / "config" / "custom_providers" / "y.json")     # a restore here never "finishes"
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    state = tmp_path / "state"
    state.mkdir()
    first = {s["target"]: s["listen"] for s in rl.relay_specs("N", 7, ["10.0.0.5:8080", "10.0.0.6:8080"])}
    second = {s["target"]: s["listen"] for s in rl.relay_specs("N", 7, ["10.0.0.6:8080", "10.0.0.5:8080"])}
    assert first["10.0.0.5:8080"] == second["10.0.0.6:8080"] == "127.64.0.8:8080"      # the addresses changed hands
    live = _start(state, root, {}, first)
    assert cfg.read_bytes() == b"a: http://127.64.0.8:8080/v1\nb: http://127.65.0.8:8080/v1\n"
    live = _start(state, root, live, second)                                           # the administrator reorders
    want = b"a: http://127.65.0.8:8080/v1\nb: http://127.64.0.8:8080/v1\n"
    assert cfg.read_bytes() == want
    for _ in range(3):                                                                 # and it stays so
        live = _start(state, root, live, second)
        assert cfg.read_bytes() == want
    assert not (state / "N.relays.undo.json").exists()
    # a target replaced on the same port: the old one is undone once, at the changeover, and never again
    cfg.write_bytes(b"a: http://127.0.0.1:4000/v1\n")
    live = _start(state, root, {}, {"127.0.0.1:4000": "127.64.0.8:4000"})
    new = {"10.0.0.5:4000": "127.64.0.8:4000"}
    live = _start(state, root, live, new)
    assert cfg.read_bytes() == b"a: http://127.0.0.1:4000/v1\n"       # that URL was the old service's: restored
    cfg.write_bytes(b"a: http://10.0.0.5:4000/v1\n")                  # the member now uses the new one
    for _ in range(3):
        live = _start(state, root, live, new)
        assert cfg.read_bytes() == b"a: http://127.64.0.8:4000/v1\n"


def test_a_debt_for_a_relay_that_runs_again_is_kept_until_its_record_exists(tmp_path):
    """W-2: dropped before the relays were started, it was lost when a forwarder then failed to start."""
    root = _profile(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    m = {"127.0.0.1:4000": "127.64.0.8:4000", "10.0.0.9:9": "127.64.0.8:9"}
    (state / "N.relays.undo.json").write_text(json.dumps(m), encoding="utf-8")
    live = {"127.0.0.1:4000": "127.64.0.8:4000"}
    rl.restore_pending(str(state), "N", str(root), {}, active=live)
    assert json.loads((state / "N.relays.undo.json").read_text(encoding="utf-8")) == live     # the other one is settled
    rl.forget_owed(str(state), "N", live)                              # its record is written: covered
    assert not (state / "N.relays.undo.json").exists()
    rl.forget_owed(str(state), "N", live)                              # nothing there: nothing happens


@windows
def test_a_grant_replaces_the_containers_entry(monkeypatch):
    """W-5: icacls /grant adds to an entry that is still there; a folder taken down to read kept modify."""
    seen = []
    monkeypatch.setattr(sb, "_icacls", seen.append)
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: True)
    monkeypatch.setattr(sb, "exceeds", lambda path, sid, right: False)
    sb.grant(r"C:\x", "S-1-15-2-9", "read")
    assert seen == [[r"C:\x", "/grant:r", "*S-1-15-2-9:(OI)(CI)RX", "/Q", "/C"]]
    # icacls /C exits 0 also when it changed nothing: without the entry on the folder the grant has failed
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: False)
    with pytest.raises(sb.SandboxError, match="could not be changed"):
        sb.grant(r"C:\x", "S-1-15-2-9", "read")
    # ... and an older, wider entry that was not replaced is not "read" either (review X-2)
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: True)
    monkeypatch.setattr(sb, "exceeds", lambda path, sid, right: True)
    with pytest.raises(sb.SandboxError, match="wider than read"):
        sb.grant(r"C:\x", "S-1-15-2-9", "read")


@windows
def test_a_folder_taken_down_to_read_is_read_only_in_the_container(box):
    shared = box.tmp / "shared"
    shared.mkdir()
    code = f'''
t("write", lambda: open({str(shared / "w.txt")!r}, "w").write("x"))
t("list", lambda: len(os.listdir({str(shared)!r})))
'''
    sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(shared): "modify"}))
    assert inside(box, code)["write"].startswith("OK")
    real_revoke = sb.revoke
    try:
        sb.revoke = lambda p, sid: (_ for _ in ()).throw(sb.SandboxError("icacls failed"))     # the revoke fails
        sb.prepare(box.name, box.state_dir, member_grants(box.prof, box.pybase, {str(shared): "read"}))
    finally:
        sb.revoke = real_revoke
    r = inside(box, code)
    assert r["write"] == "ERR PermissionError" and r["list"].startswith("OK")


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


@windows
def test_install_makes_sure_the_gateway_account_has_full_control_of_the_profiles_root(tmp_path):
    """Members' profiles and team folders are made there, and the AppContainer backend changes their permissions:
    when install.ps1 cannot set the folder's permissions it must not go on with a warning."""
    import re
    text = (Path(__file__).resolve().parents[1] / "scripts" / "install.ps1").read_text(encoding="utf-8")
    fn = re.search(r"function Test-FullControl.*?\n}\n", text, re.S)
    assert fn, "install.ps1 has no Test-FullControl"
    after = text[text.index("& icacls $ProfilesRoot /inheritance:r /grant:r @grants"):][:1500]
    assert "Test-FullControl $ProfilesRoot $gwAccount" in after and "throw " in after
    full, modify = tmp_path / "full", tmp_path / "modify"
    full.mkdir()
    modify.mkdir()
    icacls = os.path.join(os.environ["SystemRoot"], "System32", "icacls.exe")
    me = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]
    subprocess.run([icacls, str(full), "/inheritance:r", "/grant:r", f"{me}:(OI)(CI)F", "/Q"], check=True, capture_output=True)
    subprocess.run([icacls, str(modify), "/inheritance:r", "/grant:r", f"{me}:(OI)(CI)M", "/Q"], check=True, capture_output=True)
    script = tmp_path / "t.ps1"
    script.write_text(fn.group(0) + f"\n\"$(Test-FullControl '{full}' '{me}') $(Test-FullControl '{modify}' '{me}') "
                      f"$(Test-FullControl '{tmp_path / 'missing'}' '{me}') $(Test-FullControl '{full}' 'NO-SUCH\\nobody')\"\n",
                      encoding="utf-8")
    ps = os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    # Also where Windows PowerShell cannot load its own modules: started from PowerShell 7 (as on the project's CI),
    # PSModulePath names the newer ones and Get-Acl does not load. The first version used Get-Acl and answered
    # "False" four times there. Tried with the variable as it is, without it, and pointing nowhere.
    for label, env in (("as it is", dict(os.environ)),
                       ("without PSModulePath", {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}),
                       ("PSModulePath pointing nowhere", {**os.environ, "PSModulePath": str(tmp_path / "no-modules")})):
        r = subprocess.run([ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)], capture_output=True,
                           text=True, timeout=120, env=env)
        assert r.stdout.strip() == "True False False False", (label, r.stdout + r.stderr)
    code = "\n".join(ln for ln in fn.group(0).splitlines() if not ln.lstrip().startswith("#"))
    assert "Get-Acl" not in code and "New-Object" not in code            # no cmdlet: nothing to load
    # the program folders are opened to sandboxes by the installer itself, so that a fresh installation whose gateway
    # does not own them (a service account) is not one where no member's agent starts
    grant = text[text.index("if ($Sandbox -ne 'off') {"):][:1800]
    assert "'*S-1-15-2-1:(OI)(CI)RX'" in grant and "'*S-1-15-2-2:(OI)(CI)RX'" in grant and "Split-Path $gooseExe" in grant


@windows
def test_what_icacls_could_not_change_below_a_granted_folder_is_said(monkeypatch, caplog):
    """icacls /C exits 0 whatever happened; its own sentence is the only trace of files it skipped."""
    class Done:
        returncode = 0
        stderr = ""

        def __init__(self, out):
            self.stdout = out
    outs = iter(["Successfully processed 3 files; Failed processing 2 files\n", "Successfully processed 5 files; Failed processing 0 files\n",
                 "Erfolgreich verarbeitet: 5 Dateien\n"])
    monkeypatch.setattr(sb.subprocess, "run", lambda *a, **k: Done(next(outs)))
    assert [sb._icacls(["x", "/grant"]) for _ in range(3)] == [2, 0, 0]
    monkeypatch.setattr(sb, "_icacls", lambda args: 4)
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: True)
    monkeypatch.setattr(sb, "exceeds", lambda path, sid, right: False)
    with caplog.at_level("WARNING"):
        sb.grant(r"C:\x", "S-1-15-2-9", "read")
    assert any("could not change 4 file(s)" in r.getMessage() for r in caplog.records)
    assert "WRITE_DAC" in sb.grant_help(r"C:\x", "read") and "WRITE_DAC" in sb.grant_help(r"C:\x", "modify")


# ------------------------------------------------------------------ does a container process start where the gateway runs?
# A program that loads user32 connects to a desktop while it loads, and its container must be let in there. Where
# somebody is signed in Windows sees to that; a gateway started at boot under an account nobody signs in with sits on
# a desktop that does not (FIX appcontainer-session0, reported from Windows Server 2022, reproduced on build 26100 by
# putting the process on such a desktop).
def _user32():
    import ctypes
    from ctypes import wintypes
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    u32.CreateDesktopW.restype = wintypes.HANDLE
    u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p]
    u32.CloseDesktop.argtypes = [wintypes.HANDLE]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                                         ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                                         ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    return ctypes, wintypes, u32, adv


def _access_list(h) -> str:
    ctypes, wintypes, _u32, adv = _user32()
    psd, text = ctypes.c_void_p(), wintypes.LPWSTR()
    assert adv.GetSecurityInfo(h, 7, 4, None, None, None, None, ctypes.byref(psd)) == 0
    assert adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, 1, 4, ctypes.byref(text), None)
    return text.value


@pytest.fixture
def desk():
    """A desktop on the window station of this test run, made as `desk(access list)`; the default names this account
    and SYSTEM and no application container. Nothing is shown on it and it ends with the test."""
    ctypes, wintypes, u32, adv = _user32()
    made = []

    class SA(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]

    def make(sddl: str = ""):
        psd = ctypes.c_void_p()
        sddl = sddl or f"D:P(A;;GA;;;{winsec.current_user_sid()})(A;;GA;;;SY)"
        assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(psd), None)
        name = f"gwtest{uuid.uuid4().hex[:10]}"
        h = u32.CreateDesktopW(name, None, None, 0, 0x10000000, ctypes.byref(SA(ctypes.sizeof(SA), psd.value, False)))
        if not h:
            pytest.skip(f"this account may not make a desktop here ({ctypes.get_last_error()})")
        made.append(h)
        return SimpleNamespace(name=name, handle=h)
    yield make
    for h in made:
        u32.CloseDesktop(h)


@pytest.fixture
def throwaway():
    """A container that has nothing but the right to read the gateway's Python."""
    py = rl.python_for_container()[0]
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    sid, granted = sb.ensure_container(name), ""
    folder = os.path.realpath(os.path.dirname(py))      # the folder, not a link to it (uv's Pythons; AC-11)
    try:
        if not sb.allowed(folder, [sb.ALL_APP_PACKAGES], "read"):
            sb.grant(folder, sid, "read")
            granted = folder
        yield SimpleNamespace(sid=sid, py=py)
    finally:
        if granted:
            sb.revoke(granted, sid)
        sb.delete_container(name)


# What a process sees of the account that runs the gateway: where it is, whether it can copy the screen, and how
# many formats are on the clipboard it reaches (FIX members-read-screen, WS-1).
WHERE_AM_I = r'''
import ctypes, json
from ctypes import wintypes as w
u = ctypes.WinDLL("user32", use_last_error=True); k = ctypes.WinDLL("kernel32"); g = ctypes.WinDLL("gdi32", use_last_error=True)
u.GetProcessWindowStation.restype = w.HANDLE; u.GetThreadDesktop.restype = w.HANDLE
def n(h):
    b = ctypes.create_unicode_buffer(256); u.GetUserObjectInformationW(w.HANDLE(h), 2, b, 512, ctypes.byref(w.DWORD())); return b.value
out = {"where": n(u.GetProcessWindowStation()) + "\\" + n(u.GetThreadDesktop(k.GetCurrentThreadId()))}
u.GetDC.restype = w.HDC; u.GetDC.argtypes = [w.HWND]
g.CreateCompatibleDC.restype = w.HDC; g.CreateCompatibleDC.argtypes = [w.HDC]
g.CreateCompatibleBitmap.restype = w.HANDLE; g.CreateCompatibleBitmap.argtypes = [w.HDC, ctypes.c_int, ctypes.c_int]
g.SelectObject.restype = w.HANDLE; g.SelectObject.argtypes = [w.HDC, w.HANDLE]
g.BitBlt.argtypes = [w.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HDC, ctypes.c_int, ctypes.c_int, w.DWORD]
g.GetBitmapBits.argtypes = [w.HANDLE, ctypes.c_long, ctypes.c_void_p]
hdc = u.GetDC(None); mem = g.CreateCompatibleDC(hdc); bmp = g.CreateCompatibleBitmap(hdc, 64, 64); g.SelectObject(mem, bmp)
out["copied"] = bool(g.BitBlt(mem, 0, 0, 64, 64, hdc, 100, 100, 0x00CC0020))
buf = ctypes.create_string_buffer(64 * 64 * 4); got = g.GetBitmapBits(bmp, len(buf), buf)
out["distinct"] = len(set(buf.raw[:got]))
ok = u.OpenClipboard(None); out["formats"] = u.CountClipboardFormats() if ok else -1
if ok: u.CloseClipboard()
print(json.dumps(out))
'''


@windows
def test_a_members_process_is_not_started_on_the_desktop_of_the_signed_in_account(throwaway, monkeypatch):
    """Measured on build 26100: on the window station of a signed-in user every application container may read the
    screen, and one of this backend the clipboard too. A member's agent is such a container - so it is started on
    a desktop of the gateway's own, on a window station without a screen and with a clipboard of its own."""
    if not sb.session_info()["interactive"]:
        pytest.skip("nobody is signed in here: there is no screen and no clipboard of a person to keep away from")
    c = throwaway

    def see() -> dict:
        with open(os.devnull, "wb") as errf:
            p = sb.spawn([c.py, "-I", "-c", WHERE_AM_I], {k: os.environ[k] for k in ("SystemRoot", "LOCALAPPDATA")},
                         os.environ["SystemRoot"], c.sid, [], errf)
            p.stdin.close()
            raw = p.stdout.read().decode("utf-8", "replace").strip()
            assert p.wait(60) == 0 and raw, raw
        return json.loads(raw.splitlines()[-1])
    monkeypatch.setitem(sb.PRIVATE_DESKTOP, "on", True)
    place = sb.members_desktop()
    assert "\\" in place and not place.lower().startswith("winsta0\\") and sb.members_desktop() == place
    there = see()
    assert there["where"] == place, there
    assert not there["copied"] or there["distinct"] <= 1, there         # no screen to copy
    assert sb.admit(c.sid, place, dry=True) == []                       # let in there as it is
    with pytest.raises(sb.SandboxError):
        sb.admit(c.sid, "WinSta0\\Default")                             # only this gateway's own is ever touched
    with pytest.raises(sb.SandboxError), open(os.devnull, "wb") as errf:   # and nothing is started anywhere else
        sb.spawn([c.py, "-I", "-c", "pass"], {}, os.environ["SystemRoot"], c.sid, [], errf, desktop="WinSta0\\Default")
    assert sb.dismiss(c.sid) == []                                      # looks at both places, finds nothing of its
    # a gateway that once could not be put back on its window station starts nothing any more (T-6)
    monkeypatch.setitem(sb._PLACE, "broken", "this gateway could not be put back on its own window station")
    with pytest.raises(sb.SandboxError, match="could not be put back"):
        sb.members_desktop()
    monkeypatch.delitem(sb._PLACE, "broken")
    # sandbox.desktop: shared - the desktop of the account, as every version before 1.23.0
    monkeypatch.setitem(sb.PRIVATE_DESKTOP, "on", False)
    assert sb.members_desktop() == "" and see()["where"].lower() == "winsta0\\default"


@windows
def test_the_self_test_starts_container_processes_in_this_session():
    res = sb.selftest(rl.python_for_container()[0])
    ok, text = sb.selftest_text(res)
    assert ok and res["ok"] and [s["ok"] for s in res["steps"]] == [True, True], res
    assert isinstance(res["session"], int) and res["windowStation"] and res["build"] and "starts here" in text
    assert all(not s["detail"] for s in res["steps"]), res        # a step that passed says nothing more
    if res["interactive"]:          # somebody is signed in: the steps ran on the gateway's own desktop for members
        assert not res["missing"] and not res["admitted"] and "stepsBefore" not in res and not res["remedy"], res
        assert res["membersDesktop"] == sb.members_desktop() and "not on the desktop of the signed-in account" in text


@windows
def test_a_container_that_its_desktop_does_not_let_in_cannot_load_user32_and_admit_lets_it_in(desk, throwaway, caplog):
    """The failure reported from a gateway started at boot under a service account, and its cure, on a real
    desktop: `import ctypes` (COM, user32) ends with "DLL initialization routine failed" - a program that links
    user32, like goose, ends with 0xC0000142 - while a console program that does not load user32 runs."""
    d, c = desk(), throwaway
    before = _access_list(d.handle)
    steps = sb._selftest_run(c.sid, c.py, d.name)
    if all(s["ok"] for s in steps):
        pytest.skip("this Windows lets a container use a desktop that does not name it")
    assert [s["ok"] for s in steps] == [True, False] and "initialization routine failed" in steps[1]["detail"], steps
    assert sb.admit(c.sid, d.name, dry=True) == [f"desktop {d.name}"] and _access_list(d.handle) == before
    assert sb.admit(c.sid, d.name) == [f"desktop {d.name}"]
    assert f"(A;;CCDCLCDTLORC;;;{c.sid})" in _access_list(d.handle)      # 0x000200C7: no hooks, no switch, no change
    assert sb.admit(c.sid, d.name) == [] and sb.admit(c.sid, d.name, dry=True) == []
    assert [s["ok"] for s in sb._selftest_run(c.sid, c.py, d.name)] == [True, True]
    # taken off again when the container goes: the desktop is as it was and the process fails as before
    assert sb.dismiss(c.sid, d.name) == [f"desktop {d.name}"] and _access_list(d.handle) == before
    assert [s["ok"] for s in sb._selftest_run(c.sid, c.py, d.name)] == [True, False]
    # what a member's start does: spawn lets the container in first, and says so
    with caplog.at_level("INFO"), open(os.devnull, "wb") as errf:
        p = sb.spawn([c.py, "-I", "-c", "import ctypes; print('in')"],
                     {k: os.environ[k] for k in ("SystemRoot", "LOCALAPPDATA")},     # without LOCALAPPDATA: error 203
                     os.environ["SystemRoot"], c.sid, [], errf, desktop=d.name)
        p.stdin.close()
        assert p.stdout.read().strip() == b"in" and p.wait(60) == 0
    assert any(f"is now named on the desktop {d.name}" in r.getMessage() for r in caplog.records)
    sb.dismiss(c.sid, d.name)


@windows
def test_a_desktop_that_gives_application_packages_too_little_counts_as_closed(desk, throwaway):
    """What a desktop on the window station of a logon nobody is signed in to gives ALL APPLICATION PACKAGES by
    default (read, list, switch: 0x00020141) is not what user32 needs. Being named is not being let in."""
    d = desk(f"D:P(A;;GA;;;{winsec.current_user_sid()})(A;;GA;;;SY)(A;;CCDTCRRC;;;AC)")
    c = throwaway
    assert sb.admit(c.sid, d.name, dry=True) == [f"desktop {d.name}"]
    steps = sb._selftest_run(c.sid, c.py, d.name)
    if all(s["ok"] for s in steps):
        pytest.skip("this Windows lets a container load user32 with less")
    assert sb.admit(c.sid, d.name) == [f"desktop {d.name}"]
    assert [s["ok"] for s in sb._selftest_run(c.sid, c.py, d.name)] == [True, True]
    sb.dismiss(c.sid, d.name)
    # and a desktop that gives application packages what the desktop of a signed-in user gives them is left alone
    open_ = desk(f"D:P(A;;GA;;;{winsec.current_user_sid()})(A;;GA;;;SY)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;AC)")
    assert sb.admit(c.sid, open_.name) == [] and [s["ok"] for s in sb._selftest_run(c.sid, c.py, open_.name)] == [True, True]


@windows
def test_nothing_is_taken_off_a_desktop_that_this_process_did_not_put_there(desk, throwaway):
    """What happened on 2026-11-14: a record on disk said the container's SID was S-1-15-2-1 (a stand-in in a test),
    and removing "that container" took ALL APPLICATION PACKAGES off the window station and desktop of the signed-in
    session. Only a container's own SID is ever handled, and only the entry this process added."""
    me, c = winsec.current_user_sid(), throwaway
    d = desk(f"D:P(A;;GA;;;{me})(A;;GA;;;SY)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-15-2-2)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;AC)")
    before = _access_list(d.handle)
    for sid in (sb.ALL_APP_PACKAGES, sb.ALL_RESTRICTED_APP_PACKAGES, "S-1-1-0", me, "", "S-1-15-2-9",
                "S-1-15-2-99-1-2-3-4-5-6\n"):
        assert sb.dismiss(sid, d.name) == [] and _access_list(d.handle) == before, sid
        with pytest.raises(sb.SandboxError):
            sb.admit(sid, d.name)
    # an entry of a real container that somebody else made stays as well
    closed = desk()
    sb._set_entry(closed.handle, c.sid, 0x000200C7, 1, "desktop")
    made = _access_list(closed.handle)
    assert c.sid in made and sb.admit(c.sid, closed.name) == []
    assert sb.dismiss(c.sid, closed.name) == [] and _access_list(closed.handle) == made
    # ALL RESTRICTED APPLICATION PACKAGES alone lets an ordinary container in: nothing is added there
    only = desk(f"D:P(A;;GA;;;{me})(A;;GA;;;SY)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-15-2-2)")
    assert sb.admit(c.sid, only.name) == [] and [s["ok"] for s in sb._selftest_run(c.sid, c.py, only.name)] == [True, True]


@windows
def test_an_object_without_an_access_list_is_left_without_one(desk):
    """Everybody is let in there; a list with one entry would shut everybody else out - the gateway included."""
    d = desk("D:NO_ACCESS_CONTROL")
    assert sb.admit("S-1-15-2-99-1-2-3-4-5-6", d.name) == [] and sb.dismiss("S-1-15-2-99-1-2-3-4-5-6", d.name) == []
    assert _access_list(d.handle) == "D:NO_ACCESS_CONTROL"


@windows
def test_the_self_test_on_a_closed_desktop_says_what_it_took_and_leaves_it_as_it_was(desk):
    d = desk()
    before = _access_list(d.handle)
    res = sb.selftest(rl.python_for_container()[0], desktop=d.name)
    if "stepsBefore" in res and all(s["ok"] for s in res["stepsBefore"]):
        pytest.skip("this Windows lets a container use a desktop that does not name it")
    ok, text = sb.selftest_text(res)
    assert ok and res["missing"] == res["admitted"] == [f"desktop {d.name}"], res
    assert [s["ok"] for s in res["stepsBefore"]] == [True, False] and [s["ok"] for s in res["steps"]] == [True, True]
    assert "only once its container is named on the desktop" in text and "names every member's container" in text
    assert _access_list(d.handle) == before


@windows
def test_a_gateway_nobody_is_signed_in_to_starts_container_processes(tmp_path):
    """As close as a test gets without a boot task: a process of its own moves onto the window station of this
    logon that nobody is signed in to ("Service-0x0-...$") and a desktop made there with default security, and
    runs the self-test from there - the gateway's start. The processes it starts must go THERE (they would go to
    the desktop this test run was started on, where everything works) and must start."""
    child = tmp_path / "child.py"
    child.write_text(f"""
import ctypes, json, sys
from ctypes import wintypes
sys.path.insert(0, {str(Path(sb.__file__).resolve().parents[1])!r})
from goose_web import relay, sandbox as sb
u32 = ctypes.WinDLL("user32", use_last_error=True)
u32.CreateWindowStationW.restype = u32.CreateDesktopW.restype = wintypes.HANDLE
u32.CreateWindowStationW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
u32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
u32.SetProcessWindowStation.argtypes = u32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
ws = u32.CreateWindowStationW(None, 0, 0x000F037F, None)
assert ws and u32.SetProcessWindowStation(ws), ctypes.get_last_error()
dt = u32.CreateDesktopW({('gwsvc' + uuid.uuid4().hex[:8])!r}, None, None, 0, 0x10000000, None)
assert dt and u32.SetThreadDesktop(dt), ctypes.get_last_error()
adv = ctypes.WinDLL("advapi32")
adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
def lists():
    out = []
    for h in (ws, dt):
        psd, text = ctypes.c_void_p(), wintypes.LPWSTR()
        assert adv.GetSecurityInfo(h, 7, 4, None, None, None, None, ctypes.byref(psd)) == 0
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, 1, 4, ctypes.byref(text), None)
        out.append(text.value)
    return out
before = lists()
res = sb.selftest(relay.python_for_container()[0])
res["text"] = sb.selftest_text(res)[1]
res["unchanged"] = lists() == before
print(json.dumps(res))
""", encoding="utf-8")
    r = subprocess.run([sys.executable, str(child)], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0 and r.stdout.strip(), r.stdout + r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    assert res["ok"] and not res["interactive"] and res["windowStation"].lower() != "winsta0", res
    assert res["desktop"].startswith("gwsvc") and "nobody signed in" in res["text"]
    assert res["missing"] == res["admitted"] and res["unchanged"], res      # its entries were taken off again
    if res["missing"]:      # measured on build 26100: such a desktop does not let containers in
        assert not res["desktopLetsContainersIn"] and f"desktop {res['desktop']}" in res["missing"]
        assert [s["ok"] for s in res["stepsBefore"]] == [True, False] and "only once its container is named" in res["text"]


def test_the_self_test_believes_what_it_sees(monkeypatch):
    """The three ways it can end where the container is not let in: cured by naming it, not allowed to name it,
    named and still failing. No Windows needed."""
    monkeypatch.setattr(sb, "IS_WINDOWS", True)
    monkeypatch.setattr(sb, "ensure_container", lambda name: "S-1-15-2-9")
    monkeypatch.setattr(sb, "delete_container", lambda name: True)
    monkeypatch.setattr(sb, "dismiss", lambda sid, desktop="": [])
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: True)
    py = r"C:\py\python.exe"
    monkeypatch.setattr(sb, "session_info", lambda: {"session": 0, "windowStation": "Service-0x0-1a2b3$", "desktop": "Default",
                                                     "interactive": False, "build": 20348,
                                                     "windowStationLetsContainersIn": False, "desktopLetsContainersIn": False})
    where = ["window station Service-0x0-1a2b3$", "desktop Default"]
    bad = [{"what": "a program", "ok": False, "exit": "0xC0000142", "detail": ""}]
    good = [{"what": "a program", "ok": True, "exit": "0x00000000", "detail": ""}]
    runs = iter([bad, good])
    monkeypatch.setattr(sb, "_selftest_run", lambda sid, python, desktop="": next(runs))
    monkeypatch.setattr(sb, "admit", lambda sid, desktop="", dry=False: list(where))
    res = sb.selftest(py)
    ok, text = sb.selftest_text(res)
    assert ok and res["stepsBefore"] == bad and res["steps"] == good and res["admitted"] == where
    assert "only once its container is named on the window station Service-0x0-1a2b3$ and desktop Default" in text
    assert "ended with 0xC0000142" in text and "session 0" in text and "nobody signed in" in text

    def refused(sid, desktop="", dry=False):
        if dry:
            return list(where)
        raise sb.SandboxError("the desktop 'Default' this gateway runs on does not let the container in, and this "
                              "account may not change its access list (5)")
    monkeypatch.setattr(sb, "admit", refused)
    monkeypatch.setattr(sb, "_selftest_run", lambda sid, python, desktop="": bad)
    res = sb.selftest(py)
    ok, text = sb.selftest_text(res)
    assert not ok and not res["admitted"] and "may not change its access list (5)" in text
    assert "0xC0000142" in text and "session 0" in text and "nobody is signed in there" in text and "ADMINISTRATION 11.6" in text
    monkeypatch.setattr(sb, "admit", lambda sid, desktop="", dry=False: list(where))
    res = sb.selftest(py)
    assert not res["ok"] and "did not help" in sb.selftest_text(res)[1]
    # A console program that starts proves nothing - cmd.exe runs exactly where goose ends with 0xC0000142. When the
    # program that uses its desktop could not be tried, the answer is not "ok" (review S-1).
    console = [{"what": "a console program (cmd.exe)", "ok": True, "exit": "0x00000000", "detail": ""}]
    undone = []
    monkeypatch.setattr(sb, "_selftest_run", lambda sid, python, desktop="": console)
    monkeypatch.setattr(sb, "allowed", lambda path, sids, right: False)
    monkeypatch.setattr(sb, "grant", lambda path, sid, right: (_ for _ in ()).throw(sb.SandboxError("no WRITE_DAC")))
    monkeypatch.setattr(sb, "own_mask", lambda path, sid: 0x1200A9)
    monkeypatch.setattr(sb, "revoke", lambda path, sid: undone.append(path))
    monkeypatch.setattr(sb, "admit", refused)
    res = sb.selftest(py)
    ok, text = sb.selftest_text(res)
    assert not ok and "were not tried" in text and "says nothing about a member's agent" in text
    assert undone == [os.path.realpath(r"C:\py")]       # a grant that failed half-way is taken off as well (S-7)
    for none in ("", None):
        res = sb.selftest(none or "")
        assert not res["ok"] and "no Python was given" in sb.selftest_text(res)[1]


def test_removing_a_container_takes_its_entries_off_the_gateways_desktop(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(sb, "delete_container", lambda name: True)
    monkeypatch.setattr(sb, "dismiss", lambda sid, desktop="": seen.append(sid) or [])
    sb._save_state(str(tmp_path), "gooseweb.t.alice", {"name": "gooseweb.t.alice", "sid": "S-1-15-2-9", "grants": {},
                                                      "updatedAt": 0})
    assert sb.remove(str(tmp_path), "gooseweb.t.alice")["sid"] == "S-1-15-2-9" and seen == ["S-1-15-2-9"]


def test_check_shows_what_the_gateway_measured_in_its_own_session(tmp_path):
    from goose_web.__main__ import _selftest_line
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "profiles")}}), None)
    assert _selftest_line(s).startswith("[--] sandbox self-test: no result yet")
    d = Path(s.system_dir) / "sandbox"
    d.mkdir(parents=True)
    (d / "selftest.json").write_text(json.dumps({"ok": False, "session": 0, "windowStation": "Service-0x0-1a2b3$",
                                                 "interactive": False, "at": 1700000000, "remedy": "",
                                                 "reason": "a process in an application container does not start in this session: x ended with 0xC0000142."}),
                                     encoding="utf-8")
    line = _selftest_line(s)
    assert line.startswith("[!!] sandbox self-test (by the gateway, ") and "0xC0000142" in line and "ADMINISTRATION 11.6" in line
    (d / "selftest.json").write_text(json.dumps({"ok": True, "session": 1, "windowStation": "WinSta0", "interactive": True, "at": 1700000000}),
                                     encoding="utf-8")
    assert _selftest_line(s).startswith("[OK] sandbox self-test (by the gateway, ") and "session 1" in _selftest_line(s)
