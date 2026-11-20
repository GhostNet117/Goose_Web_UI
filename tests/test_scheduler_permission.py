"""FIX scheduler-needs-schedules (1.26.0): a team's Schedules switch also governs its members' agents.

Before: `scheduler` needed only Shell, so a team with Shell on and Schedules off gave every member's agent Goose's
`scheduler` tool (seen 2026-11-20), and every isolated worker ran Goose's scheduler (`--enable-scheduler`), which also
runs a job an agent with Shell wrote into its own data/schedule.json.
"""
import json

import pytest
import yaml

from goose_web import policy as pol

P = "_goose/unstable/"
MEMBER = {**pol.LEGACY_DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}


def test_scheduler_needs_shell_and_schedules():
    assert pol.extension_needs("scheduler") == ["allow_shell", "schedules"]
    assert pol.extension_needs("Scheduler") == ["allow_shell", "schedules"]
    for n in ("developer", "summon", "computercontroller", "code_execution", "orchestrator"):
        assert pol.extension_needs(n) == ["allow_shell"], n
    assert pol.extension_needs("extensionmanager") == ["extensions_edit", "allow_shell"]
    assert pol.extension_needs("todo") == []


def test_direct_scheduler_call_needs_schedules():
    call = {"sessionId": "s", "extensionName": "scheduler", "name": "scheduler__manage_schedule"}
    shell_only = {**MEMBER, "allow_shell": True, "schedules": False}
    with pytest.raises(pol.Denied, match="schedules"):
        pol.check(P + "tools/call", dict(call), is_admin=False, policy=shell_only, roots=[])
    pol.check(P + "tools/call", dict(call), is_admin=False, policy={**shell_only, "schedules": True}, roots=[])
    # session extensions and recipes ask the same question
    with pytest.raises(pol.Denied, match="schedules"):
        pol.check_enabled_extensions(["scheduler"], {**shell_only, "extensions_edit": True})
    probs = pol.recipe_problems({"title": "t", "instructions": "x",
                                 "extensions": [{"type": "platform", "name": "scheduler"}]},
                                {**shell_only, "extensions_edit": True}, {})
    assert probs and "schedules" in probs[0]


def _profiles(tmp_path, monkeypatch, team_policy):
    from goose_web.config import load_settings
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "db.sqlite")
    native = tmp_path / "native"
    (native / "config").mkdir(parents=True)
    exts = {"todo": {"enabled": True, "type": "platform", "name": "todo"},
            "developer": {"enabled": True, "type": "platform", "name": "developer"},
            "scheduler": {"enabled": True, "type": "platform", "name": "scheduler", "bundled": True}}
    (native / "config" / "config.yaml").write_text(yaml.safe_dump({"extensions": exts}), encoding="utf-8")
    db.create_user(username="admin", role="admin", profile_mode="native", profile_path=str(native))
    uid = db.create_user(username="alice", role="user")
    base = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES('t', ?, 0)",
                     (json.dumps({**base, **team_policy}),))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, uid))
    return s, db, Profiles(s, db), db.user_by_id(uid), tid


def _exts(pr, user):
    return (yaml.safe_load((pr.config_dir(user) / "config.yaml").read_text(encoding="utf-8")) or {})["extensions"]


def test_shell_without_schedules_pins_the_scheduler(tmp_path, monkeypatch):
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch, {"allow_shell": True, "schedules": False})
    changes = pr.provision(alice)
    ex = _exts(pr, alice)
    assert ex["developer"]["enabled"] is True              # Shell still gives the shell
    assert ex["scheduler"]["enabled"] is False
    assert any("scheduler" in c and "schedules" in c for c in changes)
    base = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}
    db.execute("UPDATE teams SET policy=? WHERE id=?",
               (json.dumps({**base, "allow_shell": True, "schedules": True}), tid))
    pr.provision(alice)
    assert _exts(pr, alice)["scheduler"]["enabled"] is True   # restored as in the administrator's config


def test_team_page_says_what_schedules_means():
    def texts(**kw):
        return [w["text"] for w in pol.team_warnings({**pol.DEFAULT_POLICY, **kw}, hints=1, members=1)]
    assert any("no scheduler, and no scheduled job" in t for t in texts(allow_shell=True, schedules=False))
    assert any("no scheduler tool" in t for t in texts(allow_shell=False, schedules=True))
    assert not any("scheduler" in t for t in texts(allow_shell=True, schedules=True))


def test_member_worker_runs_the_scheduler_only_with_schedules(tmp_path, monkeypatch):
    import goose_web.workers as wk
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch, {"allow_shell": True})
    wm = wk.WorkerManager(s)
    w = wm.register("alice", "alice", str(tmp_path / "p"), False, [], scheduler_allowed=False)
    on, why = wm.wants_scheduler(w)
    assert on is False and "does not allow schedules" in why
    wm.register("alice", "alice", str(tmp_path / "p"), False, [])      # SC-1: a caller that does not say keeps it
    assert w.scheduler_allowed is False
    w.state, w.scheduler = "ready", False
    wm.register("alice", "alice", str(tmp_path / "p"), False, [], scheduler_allowed=True)
    assert wm.wants_scheduler(w) == (True, "this profile's own scheduler")
    # the monitor applies the change (scheduler != wants_scheduler -> restart when quiet); nothing else is pending
    assert w.restart_pending is False and w.scheduler != wm.wants_scheduler(w)[0]
    # native profiles are not affected by the member rule
    nat = wk.Worker(key="admin", username="admin", path_root=None, native=True, scheduler_allowed=False)
    monkeypatch.setattr(wk, "desktop_running", lambda binary="": False)
    monkeypatch.setitem(s.data["goose"], "native_scheduler", "on")
    assert wm.wants_scheduler(nat)[0] is True


def test_ctx_scheduler_allowed_follows_the_team(tmp_path, monkeypatch):
    from goose_web.context import Ctx
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch, {"allow_shell": True})

    class _C:   # only what Ctx.scheduler_allowed / policy_for use
        pass
    c = _C()
    c.profiles, c.db = pr, db
    c.policy_for = lambda u: Ctx.policy_for(c, u)
    assert Ctx.scheduler_allowed(c, alice) is False
    assert Ctx.scheduler_allowed(c, {**alice, "role": "admin"}) is True
    base = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"]}
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**base, "schedules": True}), tid))
    assert Ctx.scheduler_allowed(c, alice) is True
