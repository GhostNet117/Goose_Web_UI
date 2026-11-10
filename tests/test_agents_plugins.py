"""NEW-36 (1.13.1): Goose 1.50-1.57 loads every folder under <cwd>/.agents/plugins of a new chat as an enabled plugin
and starts its MCP servers (commands) during session/new; no Goose setting turns that off. A member without
allow_shell must neither create a `.agents` folder through the file API nor start a chat in a folder that has
plugins."""
import json
import os
import sys

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from goose_web import api, security
from goose_web import policy as pol
from goose_web.auth import AuthService
from goose_web.config import load_settings
from goose_web.context import Ctx, HTTPError
from goose_web.db import Database
from goose_web.profiles import Profiles

PW = "Blue-Kettle-42"
ANYCHAT = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}
MEMBER = {**pol.DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}


def plant(folder, name="evil"):
    d = os.path.join(str(folder), ".agents", "plugins", name)
    os.makedirs(d)
    with open(os.path.join(d, ".mcp.json"), "w", encoding="utf-8") as fh:
        json.dump({"mcpServers": {"m": {"command": "cmd.exe", "args": ["/c", "whoami"]}}}, fh)
    return d


# ------------------------------------------------------------------ policy helpers

@pytest.mark.parametrize("name", [".agents", ".AGENTS", ".Agents.", ".agents. . ", " .agents",
                                  ".agents::$INDEX_ALLOCATION", ".agents:x"])
def test_is_agents_name_variants(name):
    assert pol.is_agents_name(name)


@pytest.mark.parametrize("name", ["agents", ".agents2", "my.agents", ".agent", "", None, ".goose"])
def test_is_agents_name_others(name):
    assert not pol.is_agents_name(name)


def test_has_agents_component(tmp_path):
    assert pol.has_agents_component(str(tmp_path / ".agents"))
    assert pol.has_agents_component(str(tmp_path / ".Agents" / "plugins" / "x"))
    assert pol.has_agents_component(str(tmp_path) + "/.agents./plugins")
    assert not pol.has_agents_component(str(tmp_path / "agents" / "plugins"))
    assert not pol.has_agents_component(str(tmp_path / "work.agents"))


@pytest.mark.skipif(sys.platform != "win32", reason="8.3 short names are a Windows file system feature")
def test_has_agents_component_resolves_short_names(tmp_path):
    import ctypes
    real = tmp_path / ".agents"
    real.mkdir()
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(real), buf, 1024)
    short = buf.value if n else ""
    if not short or os.path.basename(short).lower() == ".agents":
        pytest.skip("8.3 names are disabled on this volume")
    assert not pol.is_agents_name(os.path.basename(short))   # e.g. AGENTS~1
    assert pol.has_agents_component(os.path.join(short, "plugins", "x"))


def test_project_plugins(tmp_path):
    assert pol.project_plugins(str(tmp_path)) == []
    assert pol.project_plugins(None) == [] and pol.project_plugins("") == []
    (tmp_path / ".agents" / "plugins").mkdir(parents=True)
    assert pol.project_plugins(str(tmp_path)) == []                 # an empty plugins folder loads nothing
    (tmp_path / ".agents" / "plugins" / "readme.txt").write_text("x", encoding="utf-8")
    assert pol.project_plugins(str(tmp_path)) == []                 # Goose ignores files there
    plant(tmp_path, "b")
    plant(tmp_path, "a")
    assert pol.project_plugins(str(tmp_path)) == ["a", "b"]
    f = tmp_path / "file-not-folder"
    f.write_text("x", encoding="utf-8")
    assert pol.project_plugins(str(f)) == []


# ------------------------------------------------------------------ firewall: session/new

def chk(method, params, policy=None, admin=False, roots=None):
    pol.check(method, params, is_admin=admin, policy=policy or dict(MEMBER), roots=roots or [])


def test_session_new_refused_in_folder_with_plugins(tmp_path):
    ws = str(tmp_path)
    chk("session/new", {"cwd": ws, "mcpServers": []}, roots=[ws])           # nothing planted: allowed
    plant(tmp_path)
    with pytest.raises(pol.Denied, match=r"\.agents/plugins \(evil\).*allow_shell"):
        chk("session/new", {"cwd": ws, "mcpServers": []}, roots=[ws])
    chk("session/new", {"cwd": ws, "mcpServers": []}, policy={**MEMBER, "allow_shell": True}, roots=[ws])
    chk("session/new", {"cwd": ws, "mcpServers": []}, admin=True)       # admins are trusted (and untouched)
    # Goose rediscovers plugins only on session/new: other entry points are not affected
    chk("session/load", {"sessionId": "s1", "cwd": ws, "mcpServers": []}, roots=[ws])
    # a subfolder without its own .agents/plugins is fine (Goose looks at the cwd only, not at parents)
    sub = tmp_path / "project"
    sub.mkdir()
    chk("session/new", {"cwd": str(sub), "mcpServers": []}, roots=[ws])


def test_session_new_refusal_lists_names_briefly(tmp_path):
    ws = str(tmp_path)
    for n in ("p1", "p2", "p3", "p4"):
        plant(tmp_path, n)
    with pytest.raises(pol.Denied) as ei:
        chk("session/new", {"cwd": ws}, roots=[ws])
    assert "p1, p2, p3, ..." in str(ei.value) and "p4" not in str(ei.value)


# ------------------------------------------------------------------ file API

class _Workers:
    def get(self, key):
        return None


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")   # GOOSE_WEB_CONFIG must exist (A-10)
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    pr = Profiles(s, db)
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=pr, workers=_Workers(), hub=None, version="t")
    yield s, db, pr, c
    db.close()


def _user(db, name, role="user"):
    return db.user_by_id(db.create_user(username=name, role=role, password_hash=security.hash_password(PW)))


def _client(c):
    async def on_http_error(request, exc):
        return exc.response()
    app = Starlette(routes=api.routes, exception_handlers={HTTPError: on_http_error})
    app.state.ctx = c
    return TestClient(app, base_url="http://localhost")


def _sign_in(tc, c, u):
    r = tc.post("/api/auth/login", json={"username": u["username"], "password": PW})
    assert r.status_code == 200, r.text
    return {"x-csrf-token": r.json()["csrf"]}


def test_member_cannot_create_agents_folder(env):
    s, db, pr, c = env
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES(?,?,0)", ("T", json.dumps(ANYCHAT)))
    dee = _user(db, "dee")
    db.set_user_team(dee["id"], tid)
    with _client(c) as tc:
        h = _sign_in(tc, c, dee)
        pr.ensure_layout(dee)
        ws = str(pr.workspace(dee))
        team = [r["path"] for r in tc.get("/api/fs/roots").json()["roots"] if r["label"].startswith("Team")][0]
        for base in (ws, team):
            for rel in (".agents", os.path.join(".agents", "plugins", "evil"), os.path.join("proj", ".AGENTS."),
                        os.path.join("proj", ".agents", "skills")):
                r = tc.post("/api/fs/mkdir", json={"path": os.path.join(base, rel)}, headers=h)
                assert r.status_code == 403 and r.json()["error"] == "agents_folder_refused", (base, rel)
            if sys.platform == "win32":   # NTFS: creating ".agents::$INDEX_ALLOCATION" creates ".agents"
                r = tc.post("/api/fs/mkdir", json={"path": os.path.join(base, ".agents::$INDEX_ALLOCATION")},
                            headers=h)
                assert r.status_code == 403
            d = os.path.join(base, ".agents", "plugins", "evil")
            r = tc.post("/api/fs/upload", params={"dir": d}, headers=h,
                        files=[("f", (".mcp.json", b'{"mcpServers": {}}'))])
            assert r.status_code == 403 and r.json()["error"] == "agents_folder_refused"
            r = tc.post("/api/fs/upload", params={"dir": base}, headers=h, files=[("f", (".agents", b"x"))])
            assert r.status_code == 403 and r.json()["error"] == "agents_folder_refused"
            assert not os.path.exists(os.path.join(base, ".agents")), base
            assert not os.path.exists(os.path.join(base, "proj", ".agents"))
            # ordinary folders and files still work
            assert tc.post("/api/fs/mkdir", json={"path": os.path.join(base, "agents")}, headers=h).status_code == 200
            r = tc.post("/api/fs/upload", params={"dir": os.path.join(base, "agents")}, headers=h,
                        files=[("f", ("notes.md", b"x"))])
            assert r.status_code == 200


def test_admin_may_create_agents_folder(env, tmp_path):
    s, db, pr, c = env
    root = _user(db, "root", role="admin")
    target = tmp_path / "adminwork" / ".agents" / "skills"
    with _client(c) as tc:
        h = _sign_in(tc, c, root)
        assert tc.post("/api/fs/mkdir", json={"path": str(target)}, headers=h).status_code == 200
        r = tc.post("/api/fs/upload", params={"dir": str(target)}, headers=h, files=[("f", ("SKILL.md", b"x"))])
        assert r.status_code == 200
    assert (target / "SKILL.md").is_file()
