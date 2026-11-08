"""Spec 012: per-user AppContainer sandbox and the stdio worker transport."""
import asyncio
import os
import subprocess
import sys
import uuid

import pytest

from goose_web import sandbox as sb
from goose_web.hub import Hub
from tests.test_hub import mk_client

# A minimal ACP agent on stdio (what `goose acp` is to the gateway): answers initialize and session/new.
FAKE_STDIO_AGENT = r"""
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m or "method" not in m:
        continue
    res = {"protocolVersion": 1} if m["method"] == "initialize" else \
          {"sessionId": "stdio-s1", "modes": {"currentModeId": "auto"}} if m["method"] == "session/new" else {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": res}) + "\n")
    sys.stdout.flush()
"""


def test_container_name_is_deterministic_and_valid():
    root = os.path.abspath("Goose_Web_Profiles")
    a = sb.container_name(root, "Alice.Smith")
    assert a == sb.container_name(root, "alice.smith")                            # same root/user -> same SID
    if sys.platform == "win32":                                                   # Windows paths are case-insensitive
        assert a == sb.container_name(root.lower(), "alice.smith")
    assert a != sb.container_name(os.path.abspath("Other"), "alice.smith")         # two gateways stay apart
    assert len(a) <= 64 and a.startswith("GooseWeb.") and all(ch.isalnum() or ch in "._-" for ch in a)


def test_desired_and_diff_grants(tmp_path):
    goose = str(tmp_path / "goose" / "goose.exe")
    g = sb.desired_grants(str(tmp_path / "p"), [str(tmp_path / "p" / "workspace"), str(tmp_path / "team")],
                          [str(tmp_path / "py")], goose)
    assert g[os.path.normpath(str(tmp_path / "goose"))] == "read" and g[os.path.normpath(str(tmp_path / "py"))] == "read"
    assert g[os.path.normpath(str(tmp_path / "team"))] == "modify"
    both = sb.desired_grants(str(tmp_path / "x"), [], [str(tmp_path / "x")], "")
    assert both == {os.path.normpath(str(tmp_path / "x")): "modify"}               # modify wins over read
    apply, revoke = sb.diff_grants({"A": "read", "B": "modify", "C": "modify"}, {"A": "modify", "B": "modify", "D": "read"})
    assert apply == {"A": "modify", "D": "read"} and sorted(revoke) == ["A", "C"]


def test_sandbox_spec_only_for_isolated_non_admins(tmp_path, monkeypatch):
    from tests.test_team_profiles import ANYCHAT, team, user
    from goose_web.auth import AuthService
    from goose_web.config import load_settings
    from goose_web.context import Ctx
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=None, hub=None, version="t")
    extra = tmp_path / "approved"
    tid = team(db, "A", {**ANYCHAT, "allowed_roots": [str(extra)]})
    bob = user(db, "bob")
    db.set_user_team(bob["id"], tid)
    root = user(db, "root", role="admin")
    nat = user(db, "nat", role="admin", profile_mode="native", profile_path=str(tmp_path / "native"))
    assert c.sandbox_spec(bob) is None                                                 # off by default
    s.data.setdefault("sandbox", {})["enabled"] = True
    spec = c.sandbox_spec(db.user_by_id(bob["id"]))
    assert c.sandbox_spec(root) is None and c.sandbox_spec(nat) is None                 # admins never sandboxed
    prof = os.path.normpath(str(tmp_path / "profiles" / "bob"))
    assert spec["profile_root"] == str(tmp_path / "profiles" / "bob")
    assert spec["grants"][prof] == "modify" and spec["grants"][os.path.normpath(str(extra))] == "modify"
    assert any(k.endswith(os.path.join("_teams", str(tid))) for k in spec["grants"])  # team folder
    assert spec["caps"] == [sb.CAP_INTERNET]
    assert not any(k.startswith(os.path.normpath(str(tmp_path / "native"))) for k in spec["grants"])
    s.data["sandbox"]["network"] = "internet+lan"
    assert c.sandbox_spec(db.user_by_id(bob["id"]))["caps"] == [sb.CAP_INTERNET, sb.CAP_PRIVATE_NETWORK]
    db.close()


class _StdioWorkers:
    """Stand-in WorkerManager: one 'sandboxed' worker whose goose is the fake stdio agent."""

    def __init__(self):
        from goose_web.workers import Worker
        self.w = Worker(key="alice", username="alice", path_root=None, native=False, sandbox={"name": "t"})
        self.workers = {"alice": self.w}
        self.activity = self.on_restart = None
        self.starts = 0

    async def ensure(self, key):
        if self.w.channel is None:
            self.starts += 1
            self.w.proc = subprocess.Popen([sys.executable, "-c", FAKE_STDIO_AGENT], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE)
            self.w.channel = sb.StdioChannel(self.w.proc, asyncio.get_running_loop())
            self.w.state = "ready"
        return self.w

    async def stop(self, key, reason=""):
        if self.w.proc:
            self.w.proc.kill()
            self.w.proc.wait()
        self.w.proc, self.w.channel, self.w.state = None, None, "stopped"


async def test_hub_talks_to_a_stdio_worker():
    workers = _StdioWorkers()
    hub = Hub(workers)
    hub.start()
    up = hub.upstream("alice", "alice")
    c, s = mk_client()
    hub.attach(up, c)
    try:
        await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": "session/new",
                                 "params": {"cwd": os.path.abspath("/ws")}})
        r = await s.wait_for(lambda m: m.get("id") == 1)
        assert r["result"]["sessionId"] == "stdio-s1" and up.init_result == {"protocolVersion": 1}
        assert workers.w.channel.claimed and workers.starts == 1
        # the connection drops (worker died): the next request starts a fresh worker and connection
        await workers.stop("alice")
        for _ in range(100):
            if up.ws is None:
                break
            await asyncio.sleep(0.02)
        await up.from_client(c, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                                 "params": {"cwd": os.path.abspath("/ws")}})
        r = await s.wait_for(lambda m: m.get("id") == 2)
        assert r["result"]["sessionId"] == "stdio-s1" and workers.starts == 2
    finally:
        await workers.stop("alice")


@pytest.mark.skipif(sys.platform != "win32", reason="AppContainer is Windows-only")
def test_appcontainer_confines_a_process(tmp_path):
    """Real kernel enforcement: a cmd.exe in the container reads the granted folder and nothing else."""
    allowed, denied = tmp_path / "allowed", tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    (allowed / "a.txt").write_text("ALLOWED", encoding="utf-8")
    (denied / "d.txt").write_text("DENIED", encoding="utf-8")
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    state_dir = str(tmp_path / "state")
    st = sb.prepare(name, state_dir, {str(allowed): "modify"})
    try:
        assert st["sid"].startswith("S-1-15-2-")
        assert sb.load_state(state_dir, name)["grants"] == {str(allowed): "modify"}
        log = open(tmp_path / "err.log", "wb")
        cmd = (f'type "{allowed / "a.txt"}" & echo. & type "{denied / "d.txt"}" & echo. & '
               f'echo W> "{allowed / "w.txt"}" & echo. & echo X> "{denied / "x.txt"}"')
        cmd_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        p = sb.spawn(f'"{cmd_exe}" /d /c {cmd}',
                     dict(os.environ), str(allowed), st["sid"], [], log)
        p.stdin.close()
        out = p.stdout.read().decode("utf-8", "replace")
        p.wait(30)
        log.close()
        err = (tmp_path / "err.log").read_text(encoding="utf-8", errors="replace")
        assert "ALLOWED" in out and "DENIED" not in out
        assert (allowed / "w.txt").exists() and not (denied / "x.txt").exists()
        assert "denied" in err.lower()
    finally:
        sb.remove(state_dir, name)
    assert sb.load_state(state_dir, name) == {}
