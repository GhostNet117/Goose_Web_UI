import json

import yaml

from goose_web.config import load_settings
from goose_web.db import Database
from goose_web.profiles import Profiles


def make(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")   # GOOSE_WEB_CONFIG must exist (A-10)
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "db.sqlite")
    native = tmp_path / "native"
    (native / "config" / "custom_providers").mkdir(parents=True)
    (native / "config" / "skills" / "hello").mkdir(parents=True)
    (native / "config" / "skills" / "hello" / "SKILL.md").write_text("---\nname: hello\ndescription: Says hi\n---\nHi",
                                                                     encoding="utf-8")
    (native / "config" / "config.yaml").write_text(yaml.safe_dump({
        "GOOSE_PROVIDER": "p1", "GOOSE_MODEL": "m1",
        "extensions": {"todo": {"enabled": True, "type": "platform", "name": "todo"},
                       "developer": {"enabled": True, "type": "platform", "name": "developer"},
                       "fetch": {"enabled": True, "type": "stdio", "name": "fetch", "cmd": "uvx", "args": ["x"],
                                 "env_keys": ["FETCH_KEY"]}}}), encoding="utf-8")
    (native / "config" / "secrets.yaml").write_text(yaml.safe_dump({"P1_KEY": "s1", "FETCH_KEY": "s2", "OTHER": "no"}),
                                                    encoding="utf-8")
    (native / "config" / "custom_providers" / "p1.json").write_text(json.dumps(
        {"name": "p1", "engine": "openai", "api_key_env": "P1_KEY", "base_url": "http://x"}), encoding="utf-8")
    admin = db.create_user(username="admin", role="admin", profile_mode="native", profile_path=str(native))
    alice = db.create_user(username="alice", role="user")
    return s, db, Profiles(s, db), db.user_by_id(admin), db.user_by_id(alice), native


def test_isolated_layout_and_base(tmp_path, monkeypatch):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    assert pr.path_root_env(alice) == str(tmp_path / "profiles" / "alice")
    assert pr.path_root_env(admin) == str(native)
    pr.provision(alice)
    cfg = yaml.safe_load((tmp_path / "profiles" / "alice" / "config" / "config.yaml").read_text())
    assert cfg["extensions"]["todo"]["enabled"] is True
    assert cfg["extensions"]["developer"]["enabled"] is False  # no shell by default
    assert (tmp_path / "profiles" / "alice" / "workspace").is_dir()
    # native profile is never touched
    assert pr.provision(admin) == []


def test_team_items_and_secrets(tmp_path, monkeypatch):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES('t', ?, 0)",
                     (json.dumps({"default_provider": "p1", "default_model": "m1", "allowed_providers": ["*"],
                                 "allowed_models": ["*"], "allowed_modes": ["*"]}),))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, alice["id"]))
    for kind, ref in (("provider", "p1"), ("skill", "hello"), ("extension", "fetch")):
        name, payload = pr.export_item(admin, kind, ref)
        db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
                   (tid, kind, name, json.dumps(payload)))
    hid = db.execute("INSERT INTO hints_docs(name, content, updated_at) VALUES('style', 'Be brief.', 0)")
    db.execute("INSERT INTO team_hints(team_id, hints_id) VALUES(?,?)", (tid, hid))
    changes = pr.provision(alice)
    root = tmp_path / "profiles" / "alice" / "config"
    cfg = yaml.safe_load((root / "config.yaml").read_text())
    sec = yaml.safe_load((root / "secrets.yaml").read_text())
    assert cfg["GOOSE_PROVIDER"] == "p1"
    assert sec == {"P1_KEY": "s1"}                                # only referenced secrets; the stdio item's are not copied
    assert "fetch" not in cfg["extensions"]                         # stdio team items need allow_shell (B-2, 1.12)
    assert (root / "skills" / "hello" / "SKILL.md").exists()
    assert "Be brief." in (root / ".goose-web-hints.md").read_text()
    assert not (root / ".goosehints").exists()
    assert changes
    # removal cleans up only managed items
    (root / "skills" / "mine").mkdir()
    db.execute("DELETE FROM team_members")
    pr.provision(db.user_by_id(alice["id"]))
    cfg = yaml.safe_load((root / "config.yaml").read_text())
    assert "fetch" not in cfg["extensions"]
    assert not (root / "skills" / "hello").exists() and (root / "skills" / "mine").exists()
    assert not (root / "custom_providers" / "p1.json").exists()
    assert yaml.safe_load((root / "secrets.yaml").read_text()) in ({}, None)
    # the admin's native files are unchanged
    assert yaml.safe_load((native / "config" / "secrets.yaml").read_text())["OTHER"] == "no"


def test_reprovision_keeps_relayed_urls_of_a_sandboxed_member(tmp_path, monkeypatch):
    """FIX closeout-2026-11-11 F1: the worker of a sandboxed member rewrote its provider URL to the relay forwarder
    (spec 014). A later team or user save re-provisioned the real URL over it (the member's chats timed out until
    the worker restarted) and reported the provider as changed on every save. Re-provisioning must be a no-op."""
    from goose_web import relay as rl
    from goose_web import sandbox as sb
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    (native / "config" / "custom_providers" / "p1.json").write_text(json.dumps(
        {"name": "p1", "engine": "openai", "api_key_env": "P1_KEY", "base_url": "http://127.0.0.1:8801/v1"}),
        encoding="utf-8")
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES('t', ?, 0)",
                     (json.dumps({"default_provider": "p1", "default_model": "m1", "allowed_providers": ["*"],
                                 "allowed_models": ["*"], "allowed_modes": ["*"]}),))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, alice["id"]))
    name, payload = pr.export_item(admin, "provider", "p1")
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
               (tid, "provider", name, json.dumps(payload)))
    pr.provision(alice)
    root = tmp_path / "profiles" / "alice"
    pfile = root / "config" / "custom_providers" / "p1.json"
    assert "//127.0.0.1:8801/v1" in pfile.read_text(encoding="utf-8")
    # the worker starts in the sandbox: relays on, URLs rewritten, the record kept (workers._start_relays)
    mapping = {"127.0.0.1:8801": rl.forward_ip(alice["id"]) + ":8801"}
    rl.rewrite_profile_urls(str(root), mapping)
    state = s.system_dir / "sandbox"
    state.mkdir(parents=True, exist_ok=True)
    (state / f"{sb.container_name(str(s.profiles_root), 'alice')}.relays.json").write_text(json.dumps(mapping))
    relayed = pfile.read_text(encoding="utf-8")
    assert "//127.64." in relayed and "//127.0.0.1:8801" not in relayed
    assert pr.relay_mapping(alice) == mapping
    # a team / user save: nothing changes, the forwarder URL stays
    assert [c for c in pr.provision(db.user_by_id(alice["id"])) if c.startswith("provider")] == []
    assert pfile.read_text(encoding="utf-8") == relayed
    # a real change of the team item is still written - relayed
    payload["json"]["base_url"] = "http://127.0.0.1:8801/v2"
    db.execute("UPDATE team_items SET payload=? WHERE team_id=?", (json.dumps(payload), tid))
    assert "provider p1" in pr.provision(db.user_by_id(alice["id"]))
    assert f"//{mapping['127.0.0.1:8801']}/v2" in pfile.read_text(encoding="utf-8")
    # no relay record (not sandboxed): the real URL as before
    (state / f"{sb.container_name(str(s.profiles_root), 'alice')}.relays.json").unlink()
    assert pr.relay_mapping(alice) == {}
    pr.provision(db.user_by_id(alice["id"]))
    assert "//127.0.0.1:8801/v2" in pfile.read_text(encoding="utf-8")


def test_library_listing(tmp_path, monkeypatch):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    assert [i["ref"] for i in pr.library(admin, "provider")] == ["p1"]
    assert [i["ref"] for i in pr.library(admin, "skill")] == ["hello"]
    assert {i["ref"] for i in pr.library(admin, "extension")} == {"todo", "developer", "fetch"}


def test_native_scheduler_yields_to_desktop(tmp_path, monkeypatch):
    """Regression 2026-11-06: WorkerManager.desktop_running used a missing attribute, the error was swallowed,
    and the native worker ran Goose's scheduler next to Goose Desktop's."""
    import goose_web.workers as wk
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    wm = wk.WorkerManager(s)
    w = wk.Worker(key="admin", username="admin", path_root=None, native=True)
    monkeypatch.setattr(wk, "desktop_running", lambda binary="": True)
    assert wm.desktop_running(max_age=0) is True
    assert wm.wants_scheduler(w)[0] is False
    monkeypatch.setattr(wk, "desktop_running", lambda binary="": False)
    assert wm.wants_scheduler(wk.Worker(key="a2", username="a2", path_root=None, native=True))[0] is False  # cached
    assert wm.desktop_running(max_age=0) is False

    def boom(binary=""):
        raise OSError("toolhelp failed")
    monkeypatch.setattr(wk, "desktop_running", boom)
    assert wm.desktop_running(max_age=0) is True   # fail safe: never double the Desktop scheduler
