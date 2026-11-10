"""Spec 009: team profiles with least privilege (one team per user, deny by default, team hints are final,
the hints-file lock, team folders, team default model, migration)."""
import json
import os
import sqlite3

import pytest
import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient

from goose_web import api, security
from goose_web import policy as pol
from goose_web.auth import AuthService
from goose_web.config import load_settings
from goose_web.context import Ctx, HTTPError
from goose_web.db import Database
from goose_web.profiles import GW_HINTS_FILENAME, HINTS_HEADER, Profiles
from goose_web.workers import Worker, WorkerManager

PW = "Blue-Kettle-42"
P = "_goose/unstable/"
ANYCHAT = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}


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


def team(db, name, policy=None):
    return db.execute("INSERT INTO teams(name, policy, created_at) VALUES(?,?,0)", (name, json.dumps(policy or {})))


def user(db, name, role="user", **kw):
    return db.user_by_id(db.create_user(username=name, role=role, password_hash=security.hash_password(PW), **kw))


def client_for(c):
    async def on_http_error(request, exc):
        return exc.response()
    app = Starlette(routes=api.routes, exception_handlers={HTTPError: on_http_error})
    app.state.ctx = c
    return TestClient(app, base_url="http://localhost")


def sign_in(tc, c, u) -> dict:
    token, csrf = c.auth.create_session(u, "127.0.0.1", "pytest", "password")
    tc.cookies.set(c.cookie_name, token)
    return {"x-csrf-token": csrf}


# ------------------------------------------------------------------ policy: deny by default, Any, chat gate
def test_new_team_allows_nothing_and_cannot_chat():
    e = pol.effective_policy({"role": "user"}, [{"id": 1, "name": "t", "policy": {}}])
    assert not any(e[k] for k in pol.BOOL_KEYS)
    assert e["allowed_models"] == [] and e["chat_blocked"]
    with pytest.raises(pol.Denied, match="no providers"):
        pol.check("session/new", {}, is_admin=False, policy=e, roots=["/x"])


def test_no_team_can_read_but_not_chat():
    e = pol.effective_policy({"role": "user"}, [])
    assert e["no_team"] and e["chat_blocked"] == pol.NO_TEAM_REASON
    for m in ("session/new", "session/prompt", "session/fork"):
        with pytest.raises(pol.Denied, match="not in a team"):
            pol.check(m, {"sessionId": "s"}, is_admin=False, policy=e, roots=["/x"])
    pol.check("session/list", {}, is_admin=False, policy=e, roots=["/x"])     # old chats stay readable


def test_any_and_explicit_lists():
    e = pol.effective_policy({"role": "user"}, [{"id": 1, "name": "t", "policy": {
        "allowed_providers": ["*"], "allowed_models": ["m1"], "allowed_modes": ["approve", "chat"]}}])
    assert e["chat_blocked"] == ""
    chk = lambda m, p: pol.check(m, p, is_admin=False, policy=e, roots=["/x"])  # noqa: E731
    chk("session/set_config_option", {"configId": "provider", "value": "anything"})
    chk("session/set_config_option", {"configId": "model", "value": "m1"})
    for m, p in (("session/set_config_option", {"configId": "model", "value": "m2"}),
                 ("session/set_mode", {"modeId": "auto"}),
                 ("session/set_config_option", {"configId": "mode", "value": "auto"})):
        with pytest.raises(pol.Denied):
            chk(m, p)


def test_config_writes_checked_and_hints_key_locked():
    e = {**pol.effective_policy({"role": "user"}, [{"id": 1, "name": "t", "policy": {
        **ANYCHAT, "allowed_models": ["m1"], "config_edit": True, "providers_edit": True}}])}
    chk = lambda m, p: pol.check(m, p, is_admin=False, policy=e, roots=["/x"])  # noqa: E731
    with pytest.raises(pol.Denied, match="managed by Goose Web"):
        chk(P + "config/upsert", {"key": "CONTEXT_FILE_NAMES", "value": ["AGENTS.md"]})
    with pytest.raises(pol.Denied, match="managed by Goose Web"):
        chk(P + "config/remove", {"key": "context_file_names"})
    with pytest.raises(pol.Denied):
        chk(P + "config/upsert", {"key": "GOOSE_MODEL", "value": "m2"})
    chk(P + "config/upsert", {"key": "GOOSE_MODEL", "value": "m1"})
    with pytest.raises(pol.Denied):
        chk(P + "defaults/save", {"providerId": "p", "modelId": "m2"})
    chk(P + "defaults/save", {"providerId": "p", "modelId": "m1"})
    pol.check(P + "config/upsert", {"key": "CONTEXT_FILE_NAMES", "value": []}, is_admin=True, policy=e, roots=[])


def test_prompt_refused_when_current_model_not_allowed():
    e = pol.effective_policy({"role": "user"}, [{"id": 1, "name": "t", "policy": {**ANYCHAT, "allowed_models": ["m1"]}}])
    ok = {"configOptions": [{"id": "provider", "currentValue": "p"}, {"id": "model", "currentValue": "m1"}],
          "modes": {"currentModeId": "approve"}}
    pol.check_session_choice(e, ok)
    pol.check_session_choice(e, None)
    with pytest.raises(pol.Denied, match="model 'm9'"):
        pol.check_session_choice(e, {"configOptions": [{"id": "model", "currentValue": "m9"}]})


def test_team_warnings():
    texts = [w["text"] for w in pol.team_warnings({}, hints=0, members=0)]
    assert "No models allowed: members can't chat." in texts
    assert any("No team hints" in t for t in texts)
    w = pol.team_warnings({**ANYCHAT, "allowed_models": ["a"], "default_provider": "p", "default_model": "b",
                           "allow_shell": True}, hints=1, members=2)
    levels = {x["text"].split(":")[0]: x["level"] for x in w}
    assert any("default model 'b' is not in the allowed models" in x["text"] for x in w)
    assert levels.get("Shell is on") == "warn"
    assert not any(x["level"] == "err" for x in w)


def test_roots_are_workspace_team_folder_and_extras():
    roots = pol.user_roots({"team_folder": "T", "allowed_roots": ["X", "*"]}, "W")
    assert roots == ["W", "T", "X"]


# ------------------------------------------------------------------ migration
def test_migration_keeps_old_behaviour_and_one_team(tmp_path):
    path = tmp_path / "old.db"
    db = Database(path)                       # create the schema, then make it look like a 1.4 database
    db.close()
    con = sqlite3.connect(path)
    con.execute("DELETE FROM meta WHERE key='policy_model'")
    con.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
    con.execute("DROP INDEX ux_team_members_user")
    con.execute("INSERT INTO teams(id, name, policy, created_at) VALUES(1, 'Everyone', '{}', 0)")
    con.execute("INSERT INTO teams(id, name, policy, created_at) VALUES(2, 'Ops', ?, 0)",
                (json.dumps({"allow_shell": True, "allowed_models": ["m1"]}),))
    con.execute("INSERT INTO users(id, username, created_at, policy_overrides) VALUES(5, 'ann', 0, ?)",
                (json.dumps({"allowed_providers": []}),))
    con.execute("INSERT INTO team_members VALUES(1, 5)")
    con.execute("INSERT INTO team_members VALUES(2, 5)")
    con.commit()
    con.close()
    for _ in range(2):                         # idempotent
        db = Database(path)
        everyone = db.one("SELECT policy FROM teams WHERE id=1")["policy"]
        ops = db.one("SELECT policy FROM teams WHERE id=2")["policy"]
        assert everyone["allowed_models"] == ["*"] and everyone["recipes_edit"] is True
        assert everyone["hints_edit"] is True and everyone["allow_shell"] is False
        assert ops["allowed_models"] == ["m1"] and ops["allowed_providers"] == ["*"] and ops["allow_shell"] is True
        assert db.user_by_id(5)["policy_overrides"]["allowed_providers"] == ["*"]
        assert [t["id"] for t in db.user_teams(5)] == [1]
        assert db.one("SELECT value FROM meta WHERE key='schema_version'")["value"] in (5, "5")
        assert db.one("SELECT COUNT(*) AS n FROM audit WHERE action='team.migrate.membership'")["n"] == 1
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO team_members VALUES(2, 5)")
        e = pol.effective_policy(db.user_by_id(5), db.user_teams(5))
        assert e["chat_blocked"] == "" and e["recipes_edit"] is True
        db.close()


# ------------------------------------------------------------------ hints
def test_hints_order_team_last_and_personal_drop(env):
    s, db, pr, c = env
    tid = team(db, "InfoSec", {**ANYCHAT, "hints_edit": True})
    u = user(db, "ann", personal_hints="Personal: be chatty.")
    db.set_user_team(u["id"], tid)
    h1 = db.execute("INSERT INTO hints_docs(name, content, updated_at) VALUES('zz-team', 'TEAM RULE', 0)")
    h2 = db.execute("INSERT INTO hints_docs(name, content, updated_at) VALUES('aa-mine', 'ASSIGNED', 0)")
    db.execute("INSERT INTO team_hints VALUES(?,?)", (tid, h1))
    db.execute("INSERT INTO user_hints VALUES(?,?)", (u["id"], h2))
    text = pr.compose_hints(u)
    assert text.startswith(HINTS_HEADER) and "take precedence" in text
    assert text.index("Personal: be chatty.") < text.index("ASSIGNED") < text.index("TEAM RULE")
    assert "Team: InfoSec (final" in text
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps(ANYCHAT), tid))   # hints_edit off
    text = pr.compose_hints(u)
    assert "be chatty" not in text and "TEAM RULE" in text
    assert pr.hint_sections(u)["personalDropped"] is True


def test_hints_file_and_context_file_names_env(env, tmp_path):
    s, db, pr, c = env
    u = user(db, "bob")
    root = tmp_path / "profiles" / "bob" / "config"
    root.mkdir(parents=True)
    (root / ".goosehints").write_text(HINTS_HEADER + "old", encoding="utf-8")
    pr.provision(u)
    assert (root / GW_HINTS_FILENAME).is_file() and not (root / ".goosehints").exists()
    wm = WorkerManager(s)
    iso = wm._env(Worker(key="bob", username="bob", path_root=str(tmp_path / "profiles" / "bob"), native=False))
    assert json.loads(iso["CONTEXT_FILE_NAMES"]) == [GW_HINTS_FILENAME]
    nat = wm._env(Worker(key="adm", username="adm", path_root=None, native=True))
    assert nat.get("CONTEXT_FILE_NAMES") == os.environ.get("CONTEXT_FILE_NAMES")   # native: untouched


# ------------------------------------------------------------------ team folder, default model
def test_team_folder_and_default_model(env, tmp_path):
    s, db, pr, c = env
    tid = team(db, "Risk", {**ANYCHAT, "allowed_providers": ["p1"], "default_provider": "p1",
                            "default_model": "m1"})
    u = user(db, "cat")
    db.set_user_team(u["id"], tid)
    pr.provision(u)
    cfgp = tmp_path / "profiles" / "cat" / "config" / "config.yaml"
    cfg = yaml.safe_load(cfgp.read_text())
    assert (cfg["GOOSE_PROVIDER"], cfg["GOOSE_MODEL"]) == ("p1", "m1")
    assert (tmp_path / "profiles" / "_teams" / str(tid)).is_dir()
    p = c.policy_for(u)
    assert c.roots_for(u, p)[1] == str(tmp_path / "profiles" / "_teams" / str(tid))
    assert pol.path_allowed(str(tmp_path / "profiles" / "_teams" / str(tid) / "doc.txt"), c.roots_for(u, p))
    # the team default changes and the member still had the old default: follow it
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**ANYCHAT, "allowed_providers": ["p1"],
                                                                      "default_provider": "p1",
                                                                      "default_model": "m2"}), tid))
    pr.provision(u)
    assert yaml.safe_load(cfgp.read_text())["GOOSE_MODEL"] == "m2"
    # a profile default outside the lists is reset
    cfg = yaml.safe_load(cfgp.read_text())
    cfg["GOOSE_PROVIDER"], cfg["GOOSE_MODEL"] = "other", "x"
    cfgp.write_text(yaml.safe_dump(cfg))
    changes = pr.provision(u)
    cfg = yaml.safe_load(cfgp.read_text())
    assert (cfg["GOOSE_PROVIDER"], cfg["GOOSE_MODEL"]) == ("p1", "m2")
    assert "provider reset to an allowed one" in changes


# ------------------------------------------------------------------ API
def test_api_one_team_move_hints_view_and_upload_refusal(env, tmp_path):
    s, db, pr, c = env
    admin = user(db, "root", role="admin")
    t1, t2 = team(db, "A", ANYCHAT), team(db, "B", ANYCHAT)
    dee = user(db, "dee")
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"teams": [t1, t2]}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "one_team"
        assert tc.patch(f"/api/admin/users/{dee['id']}", json={"team": t1}, headers=h).status_code == 200
        r = tc.patch(f"/api/admin/teams/{t2}", json={"members": [dee["id"]]}, headers=h)
        assert r.status_code == 200 and r.json()["moved"] == ["dee (from A)"]
        assert [t["id"] for t in db.user_teams(dee["id"])] == [t2]
        r = tc.get(f"/api/admin/teams/{t2}")
        assert r.json()["warnings"] and r.json()["teamFolder"].endswith(os.path.join("_teams", str(t2)))
        r = tc.post("/api/admin/teams", json={"name": "C"}, headers=h)
        new = r.json()["team"]["policy"]
        assert not any(new[k] for k in pol.BOOL_KEYS) and new["allowed_models"] == []
        r = tc.get(f"/api/admin/users/{dee['id']}/hints")
        assert r.status_code == 200 and r.json()["effective"].startswith(HINTS_HEADER)
        assert tc.patch(f"/api/admin/teams/{t2}", json={"policy": {"share_folder": "relative"}},
                        headers=h).status_code == 400
    dee = db.user_by_id(dee["id"])
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        ws = str(pr.workspace(dee))
        pr.ensure_layout(dee)
        for name in ("AGENTS.md", "agents.MD", ".goosehints", GW_HINTS_FILENAME):
            r = tc.post("/api/fs/upload", params={"dir": ws}, headers=h, files=[("f", (name, b"x"))])
            assert r.status_code == 403 and r.json()["error"] == "hint_file_refused", name
        r = tc.post("/api/fs/upload", params={"dir": ws}, headers=h, files=[("f", ("notes.md", b"x"))])
        assert r.status_code == 200
        r = tc.post("/api/fs/mkdir", json={"path": os.path.join(ws, "AGENTS.md")}, headers=h)
        assert r.status_code == 403
        roots = tc.get("/api/fs/roots").json()["roots"]
        assert [x["label"] for x in roots] == ["Workspace", "Team: B"]
        c.upstream_for = lambda u: None          # no Goose worker in this test
        me = tc.get("/api/me").json()
        assert me["team"] == {"id": t2, "name": "B"} and me["policy"]["chat_blocked"] == ""


def test_api_managed_native_hints(env, tmp_path):
    """Spec 011: /api/me/hints and the admin hints view for a native admin with managed native hints."""
    from goose_web.profiles import NATIVE_HINTS_HEADER, NATIVE_HINTS_SETTING
    s, db, pr, c = env
    native = tmp_path / "appdata"
    (native / "config").mkdir(parents=True)
    (native / "config" / ".goosehints").write_text("raw file\n", encoding="utf-8")
    admin = user(db, "root", role="admin", profile_mode="native", profile_path=str(native))
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        r = tc.get("/api/me/hints").json()
        assert r["native"] is True and r["managed"] is False and r["personal"] == "raw file\n"
        # unmanaged: a save writes the raw file (unchanged 1.5 behaviour)
        assert tc.put("/api/me/hints", json={"personal": "raw v2\n"}, headers=h).status_code == 200
        assert (native / "config" / ".goosehints").read_text(encoding="utf-8") == "raw v2\n"
        # managed: an Admins team with a document; personal hints are stored in the DB and composed
        tid = team(db, "Admins")
        db.set_user_team(admin["id"], tid)
        hid = db.execute("INSERT INTO hints_docs(name, content, updated_at) VALUES('Admin rules', '- rule A', 0)")
        db.execute("INSERT INTO team_hints(team_id, hints_id) VALUES(?,?)", (tid, hid))
        db.set_setting(NATIVE_HINTS_SETTING, admin["id"])
        assert tc.put("/api/me/hints", json={"personal": "- mine"}, headers=h).status_code == 200
        text = (native / "config" / ".goosehints").read_text(encoding="utf-8")
        assert text.startswith(NATIVE_HINTS_HEADER) and text.index("- mine") < text.index("- rule A")
        r = tc.get("/api/me/hints").json()
        assert r["managed"] is True and r["personal"] == "- mine" and r["team"]["name"] == "Admins"
        r = tc.get(f"/api/admin/users/{admin['id']}/hints").json()
        assert r["managed"] is True and r["effective"] == text and r["team"] == "Admins"
        # a library edit rewrites the native file for its users
        assert tc.put(f"/api/admin/hints/{hid}", json={"content": "- rule B"}, headers=h).json()["updatedUsers"] == ["root"]
        assert "- rule B" in (native / "config" / ".goosehints").read_text(encoding="utf-8")
