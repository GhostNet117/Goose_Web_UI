import os

import pytest

from goose_web import policy as pol

P = "_goose/unstable/"
ROOT = os.path.abspath(os.sep + "profiles" + os.sep + "alice" + os.sep + "workspace")


def chk(method, params=None, policy=None, admin=False):
    pol.check(method, params if params is not None else {}, is_admin=admin,
              policy=policy or dict(pol.DEFAULT_POLICY), roots=[ROOT])


def test_admin_unrestricted():
    chk(P + "config/upsert", {"key": "X", "value": 1}, admin=True)
    chk("session/new", {"cwd": "/anywhere"}, admin=True)


def test_session_new_forces_client_meta():
    params = {"cwd": ROOT, "_meta": {"hidden": True}}
    chk("session/new", params)
    assert params["_meta"]["client"] == "goose-web" and "hidden" not in params["_meta"]


def test_cwd_outside_roots_denied():
    with pytest.raises(pol.Denied):
        chk("session/new", {"cwd": os.path.abspath(os.sep + "Windows")})
    with pytest.raises(pol.Denied):
        chk("session/new", {"cwd": ROOT + "-evil"})
    with pytest.raises(pol.Denied):
        chk("session/new", {"cwd": os.path.join(ROOT, "..", "..", "bob")})
    chk("session/new", {"cwd": os.path.join(ROOT, "proj")})


def test_unknown_method_denied():
    with pytest.raises(pol.Denied):
        chk(P + "brand-new/method")


def test_extension_permissions():
    with pytest.raises(pol.Denied):
        chk(P + "config/extensions/add", {"extension": {"type": "platform", "name": "todo"}})
    p = {**pol.DEFAULT_POLICY, "extensions_edit": True}
    chk(P + "config/extensions/add", {"extension": {"type": "platform", "name": "todo"}}, policy=p)
    with pytest.raises(pol.Denied):  # stdio = arbitrary command
        chk(P + "config/extensions/add", {"extension": {"type": "mcp", "server": {"name": "x", "command": "cmd"}}},
            policy=p)
    with pytest.raises(pol.Denied):
        chk(P + "config/extensions/set-enabled", {"configKey": "developer", "enabled": True}, policy=p)


def test_model_and_mode_allow_lists():
    p = {**pol.DEFAULT_POLICY, "allowed_models": ["m1"], "allowed_modes": ["approve"]}
    chk("session/set_config_option", {"configId": "model", "value": "m1"}, policy=p)
    with pytest.raises(pol.Denied):
        chk("session/set_config_option", {"configId": "model", "value": "m2"}, policy=p)
    with pytest.raises(pol.Denied):
        chk("session/set_mode", {"modeId": "auto"}, policy=p)


def test_sources_by_type():
    chk(P + "sources/create", {"type": "skill", "target": {"scope": "global"}})
    p = {**pol.DEFAULT_POLICY, "skills_edit": False}
    with pytest.raises(pol.Denied):
        chk(P + "sources/create", {"type": "skill", "target": {"scope": "global"}}, policy=p)


def test_config_read_allow_list():
    chk(P + "config/read", {"key": "GOOSE_MODEL"})
    with pytest.raises(pol.Denied):
        chk(P + "config/read", {"key": "SOME_API_KEY", "isSecret": True})


def test_effective_policy_merge():
    user = {"role": "user", "policy_overrides": {"max_concurrent_runs": 9}}
    teams = [{"policy": {"allow_shell": True, "allowed_models": ["a"]}},
             {"policy": {"allowed_models": ["b"], "allowed_roots": ["D:\\x"]}}]
    e = pol.effective_policy(user, teams)
    assert e["allow_shell"] is True
    assert e["allowed_models"] == ["a", "b"]
    assert e["allowed_roots"] == ["D:\\x"]
    assert e["max_concurrent_runs"] == 9
    teams.append({"policy": {}})  # a team with no model list = unrestricted
    assert pol.effective_policy(user, teams)["allowed_models"] == []
    assert pol.effective_policy({"role": "admin"}, [])["config_edit"] is True


def test_tools_call_shell_by_name_prefix():
    with pytest.raises(pol.Denied):
        chk(P + "tools/call", {"sessionId": "s", "name": "developer__shell", "arguments": {}})
    chk(P + "tools/call", {"sessionId": "s", "name": "todo__write", "arguments": {}})


def test_reserved_usernames(tmp_path):
    from goose_web.db import Database
    db = Database(tmp_path / "t.db")
    with pytest.raises(ValueError):
        db.create_user(username="AppData", role="user")
