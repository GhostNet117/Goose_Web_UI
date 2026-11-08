import os

import pytest

from goose_web import policy as pol

P = "_goose/unstable/"
# a typical team member: the 1.4 defaults with Any provider / model / mode (spec 009 representation)
MEMBER = {**pol.LEGACY_DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}
ROOT = os.path.abspath(os.sep + "profiles" + os.sep + "alice" + os.sep + "workspace")


def chk(method, params=None, policy=None, admin=False):
    pol.check(method, params if params is not None else {}, is_admin=admin,
              policy=policy or dict(MEMBER), roots=[ROOT])


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
    p = {**MEMBER, "extensions_edit": True}
    chk(P + "config/extensions/add", {"extension": {"type": "platform", "name": "todo"}}, policy=p)
    with pytest.raises(pol.Denied):  # stdio = arbitrary command
        chk(P + "config/extensions/add", {"extension": {"type": "mcp", "server": {"name": "x", "command": "cmd"}}},
            policy=p)
    with pytest.raises(pol.Denied):
        chk(P + "config/extensions/set-enabled", {"configKey": "developer", "enabled": True}, policy=p)


def test_model_and_mode_allow_lists():
    p = {**MEMBER, "allowed_models": ["m1"], "allowed_modes": ["approve"]}
    chk("session/set_config_option", {"configId": "model", "value": "m1"}, policy=p)
    with pytest.raises(pol.Denied):
        chk("session/set_config_option", {"configId": "model", "value": "m2"}, policy=p)
    with pytest.raises(pol.Denied):
        chk("session/set_mode", {"modeId": "auto"}, policy=p)


def test_sources_by_type():
    chk(P + "sources/create", {"type": "skill", "target": {"scope": "global"}})
    p = {**MEMBER, "skills_edit": False}
    with pytest.raises(pol.Denied):
        chk(P + "sources/create", {"type": "skill", "target": {"scope": "global"}}, policy=p)


def test_config_read_allow_list():
    chk(P + "config/read", {"key": "GOOSE_MODEL"})
    with pytest.raises(pol.Denied):
        chk(P + "config/read", {"key": "SOME_API_KEY", "isSecret": True})


def test_effective_policy_one_team_and_overrides():
    user = {"role": "user", "policy_overrides": {"max_concurrent_runs": 9}}
    teams = [{"id": 1, "name": "a", "policy": {"allow_shell": True, "allowed_models": ["a"],
                                                "allowed_roots": ["D:\\x"]}},
             {"id": 2, "name": "b", "policy": {"allowed_models": ["b"], "config_edit": True}}]
    e = pol.effective_policy(user, teams)
    assert e["allow_shell"] is True
    assert e["allowed_models"] == ["a"]            # one team: no union with a second team
    assert e["config_edit"] is False
    assert e["allowed_roots"] == ["D:\\x"]
    assert e["max_concurrent_runs"] == 9
    assert e["team"] == {"id": 1, "name": "a"}
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


def test_per_session_mcp_servers_need_allow_shell_on_every_entry_point():
    """1.7.0 security fix (NEW-30): Goose persists mcpServers given on session/new, load, fork and resume, and a
    stdio server is an arbitrary command. Before 1.7.0 only session/new was checked (GW-32)."""
    stdio = [{"name": "x", "command": "cmd.exe", "args": ["/c", "whoami"], "env": []}]
    base = {**MEMBER, "allow_shell": False}
    for method in ("session/new", "session/load", "session/fork", "session/resume"):
        with pytest.raises(pol.Denied, match="allow_shell"):
            chk(method, {"sessionId": "s1", "cwd": ROOT, "mcpServers": stdio}, policy=dict(base))
        chk(method, {"sessionId": "s1", "cwd": ROOT, "mcpServers": []}, policy=dict(base))   # the normal case
        chk(method, {"sessionId": "s1", "cwd": ROOT, "mcpServers": stdio}, policy={**base, "allow_shell": True})
        chk(method, {"sessionId": "s1", "cwd": "/anywhere", "mcpServers": stdio}, admin=True)


def test_fork_meta_reduced_to_cut_point_for_members():
    params = {"sessionId": "s1", "cwd": ROOT, "_meta": {"conversationBefore": 1762598040, "enabledExtensions": ["x"],
                                                         "anything": 1}}
    chk("session/fork", params)
    assert params["_meta"] == {"conversationBefore": 1762598040}
    admin_params = {"sessionId": "s1", "cwd": ROOT, "_meta": {"conversationBefore": 1, "other": 2}}
    chk("session/fork", admin_params, admin=True)
    assert admin_params["_meta"] == {"conversationBefore": 1, "other": 2}
