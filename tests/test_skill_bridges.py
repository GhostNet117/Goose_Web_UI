"""FIX team-skills-not-loadable-via-load: every skill of an isolated profile also gets a Summon agent bridge
(config/agents/<name>.md) so load(source=<skill>) works in members' chats, without ever writing through links."""
import json
import os
import sys

import pytest
import yaml

from goose_web import security
from goose_web.config import load_settings
from goose_web.db import Database
from goose_web.profiles import SKILL_BRIDGE_MARK, Profiles

SKILL = "---\nname: project-map\ndescription: 'Query the graph: \"where is X\"'\n---\n\n# project-map\nUse query_graph first.\n"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    yield s, db, Profiles(s, db)
    db.close()


def member(db, name="cat", **kw):
    u = db.user_by_id(db.create_user(username=name, role="user", password_hash=security.hash_password("Blue-Kettle-42"),
                                     **kw))
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES(?,?,0)", ("Risk", json.dumps({})))
    db.set_user_team(u["id"], tid)
    return u, tid


def add_skill(db, tid, name, text):
    return db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
                      (tid, "skill", name, json.dumps({"files": {"SKILL.md": text}})))


def front(p):
    t = p.read_text(encoding="utf-8")
    _, head, body = t.split("---\n", 2)
    return yaml.safe_load(head), body


def test_team_skill_gets_a_bridge_and_provision_stays_idempotent(env):
    s, db, pr = env
    u, tid = member(db)
    add_skill(db, tid, "project-map", SKILL)
    changes = pr.provision(u)
    assert not any("bridge" in c for c in changes)          # bridges never restart a worker
    b = pr.config_dir(u) / "agents" / "project-map.md"
    meta, body = front(b)
    assert meta == {"name": "project-map", "description": 'Query the graph: "where is X"'}
    assert body.startswith(SKILL_BRIDGE_MARK) and "Use query_graph first." in body
    before = b.read_bytes()
    assert pr.sync_skill_bridges(u) == []                     # idempotent
    assert b.read_bytes() == before


def test_member_made_skill_is_bridged_and_owned_agent_files_are_left_alone(env):
    s, db, pr = env
    u, _ = member(db)
    pr.provision(u)
    cfg = pr.config_dir(u)
    (cfg / "skills" / "mine").mkdir(parents=True)
    (cfg / "skills" / "mine" / "SKILL.md").write_text("---\nname: mine\ndescription: d\n---\nbody\n", encoding="utf-8")
    (cfg / "skills" / "taken").mkdir()
    (cfg / "skills" / "taken" / "SKILL.md").write_text("---\nname: taken\n---\nx\n", encoding="utf-8")
    (cfg / "agents").mkdir(exist_ok=True)
    (cfg / "agents" / "taken.md").write_text("my own agent\n", encoding="utf-8")
    (cfg / "skills" / "nofront").mkdir()
    (cfg / "skills" / "nofront" / "SKILL.md").write_text("no frontmatter\n", encoding="utf-8")
    (cfg / "skills" / "badyaml").mkdir()
    (cfg / "skills" / "badyaml" / "SKILL.md").write_text("---\nname: badyaml\ndescription: a: b\n---\nx\n",
                                                          encoding="utf-8")   # Goose rejects it too
    assert pr.sync_skill_bridges(u) == ["bridge mine"]
    assert (cfg / "agents" / "taken.md").read_text(encoding="utf-8") == "my own agent\n"
    assert not (cfg / "agents" / "nofront.md").exists()


def test_removed_skill_removes_only_managed_bridges(env):
    s, db, pr = env
    u, tid = member(db)
    item = add_skill(db, tid, "project-map", SKILL)
    pr.provision(u)
    agents = pr.config_dir(u) / "agents"
    (agents / "keep.md").write_text("---\nname: keep\n---\nmine\n", encoding="utf-8")
    db.execute("DELETE FROM team_items WHERE id=?", (item,))
    pr.provision(u)
    assert not (agents / "project-map.md").exists()
    assert (agents / "keep.md").exists()


def test_bad_names_are_skipped(env):
    s, db, pr = env
    u, _ = member(db)
    pr.provision(u)
    sk = pr.config_dir(u) / "skills" / "evil"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: ..\\..\\x\n---\nb\n", encoding="utf-8")
    assert pr.sync_skill_bridges(u) == []
    assert list((pr.config_dir(u) / "agents").glob("*")) == [] if (pr.config_dir(u) / "agents").exists() else True


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junction")
def test_never_writes_through_a_junctioned_agents_folder(env, tmp_path):
    import _winapi
    s, db, pr = env
    u, tid = member(db)
    add_skill(db, tid, "project-map", SKILL)
    pr.provision(u)
    agents = pr.config_dir(u) / "agents"
    for f in agents.glob("*"):
        f.unlink()
    agents.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _winapi.CreateJunction(str(outside), str(agents))
    assert pr.sync_skill_bridges(u) == []
    assert list(outside.iterdir()) == []


def test_hard_linked_skill_file_is_not_read(env, tmp_path):
    s, db, pr = env
    u, _ = member(db)
    pr.provision(u)
    secret = tmp_path / "secret.md"
    secret.write_text("---\nname: leak\n---\nTOP SECRET\n", encoding="utf-8")
    d = pr.config_dir(u) / "skills" / "leak"
    d.mkdir(parents=True)
    try:
        os.link(secret, d / "SKILL.md")
    except OSError:
        pytest.skip("hard links not supported here")
    assert pr.sync_skill_bridges(u) == []


def test_bridge_failure_never_fails_provisioning(env, monkeypatch):
    s, db, pr = env
    u, _ = member(db)

    def boom(user):
        raise RuntimeError("disk full")
    monkeypatch.setattr(pr, "sync_skill_bridges", boom)
    assert isinstance(pr.provision(u), list)


def test_native_profile_is_never_touched(env, tmp_path):
    s, db, pr = env
    u, _ = member(db, "nat", profile_mode="native", profile_path=str(tmp_path / "nativecfg"))
    assert pr.sync_skill_bridges(u) == []
    assert not (tmp_path / "nativecfg").exists()
