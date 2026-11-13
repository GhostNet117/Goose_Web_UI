"""Spec 028: the administrator offers skills and recipes from Goose's home-folder locations to a team; nothing is
shared by default; and the library export never reads through a link.

Goose finds its global skill, recipe and agent folders through the operating system's home folder, which
GOOSE_PATH_ROOT does not move. That home is the gateway's account. `profiles.account_home` is that folder; conftest
points it at an empty folder for every test, and the `home` fixture here at one the test fills.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from goose_web import profiles
from goose_web.__main__ import main as cli

import test_team_profiles as _tp
from test_profiles import make
from test_team_profiles import ANYCHAT, client_for, sign_in, team, user

env = _tp.env   # the shared fixture: (settings, db, profiles, ctx)
SECRET = "TOP-SECRET-do-not-copy"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "account-home"
    h.mkdir()
    monkeypatch.setattr(profiles, "account_home", lambda: h)
    return h


def skill(folder: Path, name: str, body: str = "Body", extra: dict | None = None) -> Path:
    d = folder / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {body} of {name}\n---\n{body}\n", encoding="utf-8")
    for rel, text in (extra or {}).items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(text, encoding="utf-8")
    return d


def junction(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if r.returncode != 0 or not link.exists():
        pytest.skip("cannot create a junction here")


def outside(tmp_path) -> Path:
    d = tmp_path / "outside"
    d.mkdir(exist_ok=True)
    (d / "secret.txt").write_text(SECRET, encoding="utf-8")
    (d / "SKILL.md").write_text(f"---\nname: stolen\ndescription: x\n---\n{SECRET}\n", encoding="utf-8")
    (d / "plan.yaml").write_text(yaml.safe_dump({"title": "Plan", "description": SECRET, "prompt": SECRET}), encoding="utf-8")
    return d


def refs(pr, u, kind="skill"):
    return [i["ref"] for i in pr.library(u, kind)]


# ------------------------------------------------------------------ SC6: the tests never read the real home
def test_the_test_session_never_reads_the_developers_home_folder():
    h = profiles.account_home()
    assert h != Path(os.path.expanduser("~")) and h.is_dir() and list(h.iterdir()) == []
    assert "GOOSE_RECIPE_PATH" not in os.environ
    assert profiles.home_library_summary() == {"home": str(h), "skills": [], "recipes": [], "agents": [], "linked": []}


# ------------------------------------------------------------------ SC1: what the picker offers
def test_native_library_lists_gooses_home_folder_skills_in_gooses_order(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)             # config/skills/hello exists
    skill(home / ".agents" / "skills", "review", "A")
    skill(home / ".agents" / "skills", "same-name", "from .agents")
    skill(native / "config" / "skills", "same-name", "from config")
    skill(home / ".claude" / "skills", "claude-one", "C")
    skill(home / ".claude" / "skills", "same-name", "from .claude")
    skill(home / ".config" / "agents" / "skills", "portable", "P")
    (home / ".agents" / "skills" / "not-a-skill").mkdir()                      # no SKILL.md: not offered
    items = pr.library(admin, "skill")
    assert [i["ref"] for i in items] == ["review", "same-name", "hello", "claude-one", "portable"]
    by = {i["ref"]: i for i in items}
    assert by["same-name"]["source"] == str(home / ".agents" / "skills")       # the first folder wins, as in Goose
    assert by["same-name"]["description"] == "from .agents of same-name"
    assert by["hello"]["source"] == str(native / "config" / "skills") and by["portable"]["description"] == "P of portable"
    name, payload = pr.export_item(admin, "skill", "same-name")
    assert name == "same-name" and "from .agents" in payload["files"]["SKILL.md"]


def test_a_members_library_never_lists_the_home_folder(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    skill(home / ".agents" / "skills", "review")
    (home / ".agents" / "recipes").mkdir(parents=True)
    (home / ".agents" / "recipes" / "weekly.yaml").write_text(yaml.safe_dump({"title": "Weekly"}), encoding="utf-8")
    pr.provision(alice)
    assert refs(pr, alice) == [] and refs(pr, alice, "recipe") == []
    skill(pr.config_dir(alice) / "skills", "mine")
    assert refs(pr, alice) == ["mine"]
    with pytest.raises(ValueError, match="not found"):
        pr.export_item(alice, "skill", "review")


def test_native_recipe_library_reads_both_home_folder_recipe_folders(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    for rel, name in ((".agents", "weekly"), (".goose", "legacy")):
        (home / rel / "recipes").mkdir(parents=True)
        (home / rel / "recipes" / f"{name}.yaml").write_text(yaml.safe_dump({"title": name, "prompt": "p"}), encoding="utf-8")
    own = tmp_path / "own-recipes"
    own.mkdir()
    (own / "house.yaml").write_text(yaml.safe_dump({"title": "house", "prompt": "p"}), encoding="utf-8")
    monkeypatch.setenv("GOOSE_RECIPE_PATH", os.pathsep.join([str(own), str(own)]))   # listed once
    assert sorted(i["name"] for i in pr.library(admin, "recipe")) == ["house", "legacy", "weekly"]
    name, payload = pr.export_item(admin, "recipe", str(home / ".goose" / "recipes" / "legacy.yaml"))
    assert name == "legacy" and yaml.safe_load(payload["yaml"])["title"] == "legacy"


# ------------------------------------------------------------------ SC2: nothing by default, one team only
def _offer(db, pr, src, tid, kind, ref):
    name, payload = pr.export_item(src, kind, ref)
    iid = db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
                     (tid, kind, name, json.dumps(payload)))
    pr.store_team_item_files(tid, kind, name, payload)
    return iid


def test_a_home_folder_skill_reaches_only_the_team_it_was_offered_to(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    bob = db.user_by_id(db.create_user(username="bob", role="user"))
    ta, tb = team(db, "A", ANYCHAT), team(db, "B", ANYCHAT)
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (ta, alice["id"]))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tb, bob["id"]))
    skill(home / ".agents" / "skills", "review", "Review carefully", {"templates/checklist.md": "- [ ] tests"})
    pr.provision(alice)
    pr.provision(bob)
    a_dir, b_dir = pr.config_dir(alice) / "skills" / "review", pr.config_dir(bob) / "skills" / "review"
    assert not a_dir.exists() and not b_dir.exists()                           # by default: nothing
    iid = _offer(db, pr, admin, ta, "skill", "review")
    pr.provision(alice)
    pr.provision(bob)
    assert "Review carefully" in (a_dir / "SKILL.md").read_text(encoding="utf-8")
    assert (a_dir / "templates" / "checklist.md").read_text(encoding="utf-8") == "- [ ] tests"
    assert (a_dir / profiles.MANAGED_MARK).is_file() and not b_dir.exists()   # team B: still nothing
    db.execute("DELETE FROM team_items WHERE id=?", (iid,))
    pr.provision(alice)
    assert not a_dir.exists()                                                  # taken back with the item


def test_api_the_picker_is_for_administrators_and_delivers_to_the_team(env, tmp_path, home):
    s, db, pr, c = env
    native = tmp_path / "native"
    (native / "config").mkdir(parents=True)
    (native / "config" / "config.yaml").write_text(yaml.safe_dump({"GOOSE_MODE": "auto"}), encoding="utf-8")
    root = user(db, "root", role="admin", profile_mode="native", profile_path=str(native))
    alice, bob = user(db, "alice"), user(db, "bob")
    ta, tb = team(db, "A", ANYCHAT), team(db, "B", ANYCHAT)
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (ta, alice["id"]))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tb, bob["id"]))
    skill(home / ".agents" / "skills", "review", "Review carefully")
    with client_for(c) as tc:
        assert tc.get("/api/admin/library?profile=root&kind=skill").status_code == 401
        h = sign_in(tc, c, alice)                                              # a member: neither listing nor adding
        assert tc.get("/api/admin/library?profile=root&kind=skill").status_code == 403
        assert tc.post(f"/api/admin/teams/{ta}/items", headers=h,
                       json={"kind": "skill", "fromProfile": "root", "ref": "review"}).status_code == 403
        tc.cookies.clear()
        h = sign_in(tc, c, root)
        items = tc.get("/api/admin/library?profile=root&kind=skill").json()
        assert [(i["ref"], i["source"]) for i in items] == [("review", str(home / ".agents" / "skills"))]
        assert tc.get("/api/admin/library?profile=alice&kind=skill").json() == []
        r = tc.post(f"/api/admin/teams/{ta}/items", headers=h, json={"kind": "skill", "fromProfile": "root", "ref": "review"})
        assert r.status_code == 200 and r.json()["name"] == "review"
        r = tc.post(f"/api/admin/teams/{ta}/items", headers=h, json={"kind": "skill", "fromProfile": "root", "ref": "nope"})
        assert r.status_code == 400 and r.json()["error"] == "bad_ref"
    assert (pr.config_dir(alice) / "skills" / "review" / "SKILL.md").is_file()
    assert not (pr.config_dir(bob) / "skills" / "review").exists()
    row = db.query("SELECT detail FROM audit WHERE action='team.item.add'")[0]
    assert row["detail"]["source"] == "root:review"


# ------------------------------------------------------------------ SC3: the export never reads through a link
def test_export_skips_a_junction_a_symbolic_link_and_a_hard_link_inside_a_skill(tmp_path, monkeypatch, home):
    """A skill folder in a member's profile is the member's to fill. Before 1.21.0 the export read every file in it
    with the gateway's rights - also through a link to a file the member cannot read - and copied it to a team."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    pr.provision(alice)
    d = skill(pr.config_dir(alice) / "skills", "evil", "Looks harmless", {"notes.md": "fine"})
    junction(d / "folder-link", out)
    os.link(out / "secret.txt", d / "hard-link.txt")
    try:
        os.symlink(out / "secret.txt", d / "sym-link.txt")
    except OSError:
        pass                                                                   # needs a privilege on Windows
    assert refs(pr, alice) == ["evil"]
    name, payload = pr.export_item(alice, "skill", "evil")
    assert sorted(payload["files"]) == ["SKILL.md", "notes.md"] and SECRET not in json.dumps(payload)


@pytest.mark.parametrize("who", ["member", "native home"])
def test_a_skill_that_is_itself_a_link_is_not_offered(tmp_path, monkeypatch, home, who):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    pr.provision(alice)
    u, base = (alice, pr.config_dir(alice) / "skills") if who == "member" else (admin, home / ".agents" / "skills")
    base.mkdir(parents=True, exist_ok=True)
    junction(base / "whole-folder", out)                                       # the folder is a junction
    hl = base / "linked-skill-md"
    hl.mkdir()
    os.link(out / "SKILL.md", hl / "SKILL.md")                                 # SKILL.md is a hard link
    skill(base, "real")
    assert [r for r in refs(pr, u) if r != "hello"] == ["real"]
    for ref in ("whole-folder", "linked-skill-md"):
        with pytest.raises(ValueError):
            pr.export_item(u, "skill", ref)
    with pytest.raises(ValueError, match="link"):
        pr._read_skill_files(base / "whole-folder")
    with pytest.raises(ValueError, match="SKILL.md"):
        pr._read_skill_files(hl)


def test_a_linked_skills_or_recipes_folder_in_a_members_profile_is_not_read(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    skill(out, "stolen-skill", SECRET)
    pr.provision(alice)
    cfg = pr.config_dir(alice)
    for name in ("skills", "recipes"):
        if (cfg / name).exists():
            (cfg / name).rmdir()
        junction(cfg / name, out)
    assert refs(pr, alice) == [] and refs(pr, alice, "recipe") == []
    with pytest.raises(ValueError):
        pr.export_item(alice, "recipe", str(cfg / "recipes" / "plan.yaml"))


def test_a_recipe_file_that_is_a_link_is_neither_listed_nor_exported(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    pr.provision(alice)
    rdir = pr.config_dir(alice) / "recipes"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "mine.yaml").write_text(yaml.safe_dump({"title": "Mine", "prompt": "p"}), encoding="utf-8")
    os.link(out / "plan.yaml", rdir / "plan.yaml")                             # a hard link to someone else's file
    assert [i["name"] for i in pr.library(alice, "recipe")] == ["mine"]
    assert SECRET not in json.dumps(pr.library(alice, "recipe"))
    with pytest.raises(ValueError):
        pr.export_item(alice, "recipe", str(rdir / "plan.yaml"))
    name, payload = pr.export_item(alice, "recipe", str(rdir / "mine.yaml"))
    assert name == "mine" and SECRET not in payload["yaml"]


def test_a_skill_that_is_too_large_or_has_too_many_files_is_refused(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    big = skill(home / ".agents" / "skills", "big")
    (big / "data.txt").write_text("x" * (profiles.MAX_SKILL_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="too large"):
        pr.export_item(admin, "skill", "big")
    many = skill(home / ".agents" / "skills", "many")
    for i in range(profiles.MAX_SKILL_FILES + 1):
        (many / f"f{i}.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="too many files"):
        pr.export_item(admin, "skill", "many")
    ok = skill(home / ".agents" / "skills", "binary", extra={"t.txt": "text"})
    (ok / "image.bin").write_bytes(b"\xff\xfe\x00\x81")                         # binary: left out, as before
    assert sorted(pr.export_item(admin, "skill", "binary")[1]["files"]) == ["SKILL.md", "t.txt"]


# ------------------------------------------------------------------ SC5: goose-web check says where things stand
def test_check_reports_the_home_folder_items_and_warns_without_the_sandbox(env, capsys, monkeypatch, home):
    s, db, pr, c = env
    assert cli(["check"]) in (0, 1)
    assert "[--] home-folder Goose items: none in" in capsys.readouterr().out
    skill(home / ".agents" / "skills", "review")
    (home / ".agents" / "agents").mkdir(parents=True)
    (home / ".agents" / "agents" / "helper.md").write_text("---\nname: helper\n---\n", encoding="utf-8")
    (home / ".goose" / "recipes").mkdir(parents=True)
    (home / ".goose" / "recipes" / "weekly.yaml").write_text("title: w\n", encoding="utf-8")
    assert profiles.home_library_summary() == {"home": str(home), "skills": ["review"], "recipes": ["weekly"],
                                               "agents": ["helper"], "linked": []}
    monkeypatch.setenv("GOOSE_WEB__SANDBOX__ENABLED", "true")
    assert cli(["check"]) in (0, 1)
    out = capsys.readouterr().out
    assert "[OK] home-folder Goose items: 1 skill(s), 1 recipe(s), 1 agent(s)" in out and "cannot read them (sandbox on)" in out
    monkeypatch.setenv("GOOSE_WEB__SANDBOX__ENABLED", "false")
    rc = cli(["check"])
    out = capsys.readouterr().out
    assert "[!!] home-folder Goose items: 1 skill(s), 1 recipe(s), 1 agent(s)" in out
    assert "EVERY member's agent loads them while the sandbox is off" in out and rc in (0, 1)
