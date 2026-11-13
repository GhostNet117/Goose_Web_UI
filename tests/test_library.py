"""Spec 028: the administrator offers skills and recipes from Goose's home-folder locations to a team; nothing is
shared by default; and the library never reads through a link in a member's profile.

Goose finds its global skill, recipe and agent folders through the operating system's home folder, which
GOOSE_PATH_ROOT does not move. That home is the gateway's account. `profiles.account_home` is that folder; conftest
points it at an empty folder for every test, and the `home` fixture here at one the test fills.

L-n in a docstring = a finding of the independent review of the first version of this change.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from goose_web import __main__ as cli_mod
from goose_web import profiles, winsec
from goose_web.config import DEFAULTS, Settings

import test_team_profiles as _tp
from test_profiles import make
from test_team_profiles import ANYCHAT, client_for, sign_in, team, user

env = _tp.env   # the shared fixture: (settings, db, profiles, ctx)
SECRET = "TOP-SECRET-do-not-copy"
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows links and profile folder")


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "account-home"
    h.mkdir()
    monkeypatch.setattr(profiles, "account_home", lambda: h)
    return h


def skill(folder: Path, name: str, body: str = "Body", extra: dict | None = None, md: str = "SKILL.md") -> Path:
    d = folder / name
    d.mkdir(parents=True, exist_ok=True)
    (d / md).write_text(f"---\nname: {name}\ndescription: {body} of {name}\n---\n{body}\n", encoding="utf-8")
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
    """A folder outside every profile, with things nobody may be handed."""
    d = tmp_path / "outside"
    d.mkdir(exist_ok=True)
    (d / "secret.txt").write_text(SECRET, encoding="utf-8")
    (d / "SKILL.md").write_text(f"---\nname: stolen\ndescription: x\n---\n{SECRET}\n", encoding="utf-8")
    (d / "plan.yaml").write_text(yaml.safe_dump({"title": "Plan", "description": SECRET, "prompt": SECRET}), encoding="utf-8")
    (d / "config.yaml").write_text(yaml.safe_dump({"extensions": {"vx": {"enabled": True, "type": "stdio", "name": "vx",
                                                                         "cmd": "x", "env_keys": ["VICTIM_KEY"]}}}), encoding="utf-8")
    (d / "secrets.yaml").write_text(yaml.safe_dump({"VICTIM_KEY": SECRET}), encoding="utf-8")
    (d / "custom_providers").mkdir(exist_ok=True)
    (d / "custom_providers" / "vp.json").write_text(json.dumps(
        {"name": "vp", "engine": "openai", "api_key_env": "VICTIM_KEY", "base_url": "http://victim.example"}), encoding="utf-8")
    return d


def refs(pr, u, kind="skill"):
    return [i["ref"] for i in pr.library(u, kind)]


def offer(db, pr, src, tid, kind, ref):
    name, payload = pr.export_item(src, kind, ref)
    iid = db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
                     (tid, kind, name, json.dumps(payload)))
    pr.store_team_item_files(tid, kind, name, payload)
    return iid


def with_team(db, *members, name="A"):
    tid = team(db, name, ANYCHAT)
    for m in members:
        db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, m["id"]))
    return tid


# ------------------------------------------------------------------ the tests never read the real home
def test_the_library_tests_never_read_the_developers_home_folder():
    h = profiles.account_home()
    assert h != Path(os.path.expanduser("~")) and h.is_dir() and list(h.iterdir()) == []
    assert "GOOSE_RECIPE_PATH" not in os.environ
    assert profiles.home_library_summary() == {"home": str(h), "skills": [], "recipes": [], "agents": [], "linked": []}


@windows_only
def test_the_home_folder_is_asked_from_windows_not_taken_from_the_environment(monkeypatch, tmp_path):
    """L-12: Goose asks Windows for the home folder (measured: USERPROFILE does not move it); Python's expanduser
    goes by USERPROFILE. The picker and `check` must look where Goose looks."""
    real = winsec.profile_folder()
    assert real and Path(real).is_dir()
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(winsec, "_PROFILE_FOLDER", None)                       # ask again
    assert os.path.expanduser("~") == str(tmp_path) and winsec.profile_folder() == real


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


def test_the_first_folder_takes_the_name_whatever_the_case_and_also_when_it_is_a_link(tmp_path, monkeypatch, home):
    """L-8: `Review` and `review` are one folder for a member on Windows; and a linked skill in the first folder is
    the one Goose loads, so the same name in a later folder must not be offered in its place."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    skill(home / ".agents" / "skills", "Review", "upper")
    skill(native / "config" / "skills", "review", "lower")
    junction(home / ".agents" / "skills" / "linked-one", skill(tmp_path / "elsewhere", "linked-one", "behind a link"))
    skill(native / "config" / "skills", "linked-one", "the real folder in config")
    assert refs(pr, admin) == ["Review", "hello"]


def test_a_skill_file_named_in_another_case_is_shared_as_skill_md(tmp_path, monkeypatch, home):
    """L-5: Windows finds `skill.md` as SKILL.md, so it is listed; the first version then refused to export it."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    skill(home / ".agents" / "skills", "pdf", "Lower case file", {"notes.md": "n"}, md="skill.md")
    assert "pdf" in refs(pr, admin)
    name, payload = pr.export_item(admin, "skill", "pdf")
    assert sorted(payload["files"]) == ["SKILL.md", "notes.md"] and "Lower case file" in payload["files"]["SKILL.md"]


def test_a_members_library_is_their_own_profile_only(tmp_path, monkeypatch, home):
    """Pins what was already so: a member profile's library never reaches into the gateway account's home."""
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
def test_a_home_folder_skill_reaches_only_the_team_it_was_offered_to(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    bob = db.user_by_id(db.create_user(username="bob", role="user"))
    ta, tb = with_team(db, alice), with_team(db, bob, name="B")
    skill(home / ".agents" / "skills", "review", "Review carefully", {"templates/checklist.md": "- [ ] tests"})
    pr.provision(alice)
    pr.provision(bob)
    a_dir, b_dir = pr.config_dir(alice) / "skills" / "review", pr.config_dir(bob) / "skills" / "review"
    assert not a_dir.exists() and not b_dir.exists()                           # by default: nothing
    iid = offer(db, pr, admin, ta, "skill", "review")
    pr.provision(alice)
    pr.provision(bob)
    assert "Review carefully" in (a_dir / "SKILL.md").read_text(encoding="utf-8")
    assert (a_dir / "templates" / "checklist.md").read_text(encoding="utf-8") == "- [ ] tests"
    assert (a_dir / profiles.MANAGED_MARK).is_file() and not b_dir.exists()   # team B: still nothing
    assert pr.provision(alice) == []                                           # settled: nothing to write again
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
    ta, tb = with_team(db, alice), with_team(db, bob, name="B")
    skill(home / ".agents" / "skills", "review", "Review carefully")
    with client_for(c) as tc:
        h = sign_in(tc, c, root)
        items = tc.get("/api/admin/library?profile=root&kind=skill").json()
        assert [(i["ref"], i["source"]) for i in items] == [("review", str(home / ".agents" / "skills"))]
        assert tc.get("/api/admin/library?profile=alice&kind=skill").json() == []
        r = tc.post(f"/api/admin/teams/{ta}/items", headers=h, json={"kind": "skill", "fromProfile": "root", "ref": "review"})
        assert r.status_code == 200 and r.json()["name"] == "review"
        r = tc.post(f"/api/admin/teams/{ta}/items", headers=h, json={"kind": "skill", "fromProfile": "root", "ref": "nope"})
        assert r.status_code == 400 and r.json()["error"] == "bad_ref"
        tc.cookies.clear()
        h = sign_in(tc, c, alice)                                              # a member: neither listing nor adding
        assert tc.get("/api/admin/library?profile=root&kind=skill").status_code == 403
        assert tc.post(f"/api/admin/teams/{tb}/items", headers=h,
                       json={"kind": "skill", "fromProfile": "root", "ref": "review"}).status_code == 403
    assert (pr.config_dir(alice) / "skills" / "review" / "SKILL.md").is_file()
    assert not (pr.config_dir(bob) / "skills" / "review").exists()
    row = db.query("SELECT detail FROM audit WHERE action='team.item.add'")[0]
    assert row["detail"]["source"] == "root:review"


def test_one_skill_file_that_cannot_be_written_does_not_stop_the_members_start(tmp_path, monkeypatch, home):
    """L-3: any OSError while writing one file of a team skill (a path too long under this member's profile) made
    provisioning raise, and every start of that member's agent failed until someone removed the item."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    ta = with_team(db, alice)
    skill(home / ".agents" / "skills", "review", "R", {"a.md": "A", "sub/b.md": "B"})
    offer(db, pr, admin, ta, "skill", "review")
    real = profiles._atomic_write

    def flaky(p, text):
        if p.name == "b.md":
            raise FileNotFoundError("the path is too long here")
        return real(p, text)
    monkeypatch.setattr(profiles, "_atomic_write", flaky)
    changes = pr.provision(alice)                                              # raised before
    d = pr.config_dir(alice) / "skills" / "review"
    assert (d / "SKILL.md").is_file() and (d / "a.md").read_text(encoding="utf-8") == "A" and not (d / "sub" / "b.md").exists()
    assert any("sub/b.md NOT written (FileNotFoundError)" in ch for ch in changes)
    monkeypatch.setattr(profiles, "_atomic_write", real)
    pr.provision(alice)                                                        # and it heals at the next start
    assert (d / "sub" / "b.md").read_text(encoding="utf-8") == "B"


# ------------------------------------------------------------------ SC3: nothing is read through a link
def _member_with_evil_skill(tmp_path, monkeypatch):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    pr.provision(alice)
    d = skill(pr.config_dir(alice) / "skills", "evil", "Looks harmless", {"notes.md": "fine"})
    return pr, alice, out, d


def test_export_skips_a_hard_link_inside_a_skill(tmp_path, monkeypatch, home):
    """A skill folder in a member's profile is the member's to fill. Before 1.21.0 the export read every file in it
    with the gateway's rights - also through a link to a file outside the profile - and copied it to a team."""
    pr, alice, out, d = _member_with_evil_skill(tmp_path, monkeypatch)
    os.link(out / "secret.txt", d / "hard-link.txt")
    name, payload = pr.export_item(alice, "skill", "evil")
    assert sorted(payload["files"]) == ["SKILL.md", "notes.md"] and SECRET not in json.dumps(payload)


@windows_only
def test_export_skips_a_junction_inside_a_skill(tmp_path, monkeypatch, home):
    pr, alice, out, d = _member_with_evil_skill(tmp_path, monkeypatch)
    junction(d / "folder-link", out)
    name, payload = pr.export_item(alice, "skill", "evil")
    assert sorted(payload["files"]) == ["SKILL.md", "notes.md"] and SECRET not in json.dumps(payload)


def test_export_skips_a_symbolic_link_inside_a_skill(tmp_path, monkeypatch, home):
    pr, alice, out, d = _member_with_evil_skill(tmp_path, monkeypatch)
    try:
        os.symlink(out / "secret.txt", d / "sym-file.txt")
        os.symlink(out, d / "sym-folder", target_is_directory=True)
    except OSError:
        pytest.skip("creating a symbolic link needs a privilege this account does not have")
    name, payload = pr.export_item(alice, "skill", "evil")
    assert sorted(payload["files"]) == ["SKILL.md", "notes.md"] and SECRET not in json.dumps(payload)


@windows_only
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
    assert SECRET not in json.dumps(pr.library(u, "skill"))
    for ref in ("whole-folder", "linked-skill-md"):
        with pytest.raises(ValueError):
            pr.export_item(u, "skill", ref)
    with pytest.raises(ValueError, match="link"):
        pr._read_skill_files(base / "whole-folder")
    with pytest.raises(ValueError, match="SKILL.md"):
        pr._read_skill_files(hl)


@windows_only
@pytest.mark.parametrize("where", ["the folder itself", "a folder above it"])
def test_nothing_is_listed_from_a_members_profile_through_a_linked_folder(tmp_path, monkeypatch, home, where):
    """A junction at skills / recipes / custom_providers, or higher up at `config` (L-11: the first version had no
    test for a link BETWEEN the profile root and the folder)."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    out = outside(tmp_path)
    skill(out / "skills", "stolen-skill", SECRET)
    (out / "recipes").mkdir()
    shutil.copy(out / "plan.yaml", out / "recipes" / "plan.yaml")
    pr.provision(alice)
    cfg = pr.config_dir(alice)
    if where == "the folder itself":
        for name in ("skills", "recipes", "custom_providers"):
            shutil.rmtree(cfg / name, ignore_errors=True)
            junction(cfg / name, out / name)
        kinds = ("skill", "recipe", "provider")
    else:
        shutil.rmtree(cfg)
        junction(cfg, out)                                                     # config itself is the link
        kinds = ("skill", "recipe", "provider", "extension")
    for kind in kinds:
        assert pr.library(alice, kind) == [], kind
    for kind, ref in (("recipe", str(cfg / "recipes" / "plan.yaml")), ("provider", "vp"), ("skill", "stolen-skill")):
        with pytest.raises(ValueError):
            pr.export_item(alice, kind, ref)


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


def test_extensions_providers_and_their_secrets_are_not_read_through_a_link(tmp_path, monkeypatch, home):
    """L-1: the first version hardened skills and recipes and said "the export follows no link". A provider file, a
    config.yaml or a secrets.yaml in a member's profile that is a hard link to someone else's was still read, and
    the secret it named was copied into every team member's secrets.yaml."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    bob = db.user_by_id(db.create_user(username="bob", role="user"))
    out = outside(tmp_path)
    pr.provision(alice)
    cfg = pr.config_dir(alice)
    (cfg / "custom_providers").mkdir(exist_ok=True)
    os.link(out / "custom_providers" / "vp.json", cfg / "custom_providers" / "vp.json")
    assert refs(pr, alice, "provider") == []                                   # a linked provider file: not offered
    with pytest.raises(ValueError):
        pr.export_item(alice, "provider", "vp")
    # her own provider file, naming a key - and a secrets.yaml that is a hard link to someone else's
    (cfg / "custom_providers" / "own.json").write_text(json.dumps(
        {"name": "own", "engine": "openai", "api_key_env": "VICTIM_KEY", "base_url": "http://own.example"}), encoding="utf-8")
    (cfg / "secrets.yaml").unlink(missing_ok=True)
    os.link(out / "secrets.yaml", cfg / "secrets.yaml")
    tid = with_team(db, bob)
    offer(db, pr, alice, tid, "provider", "own")
    pr.provision(bob)
    bcfg = pr.config_dir(bob)
    assert (bcfg / "custom_providers" / "own.json").is_file()                  # the provider itself is delivered
    assert SECRET not in (bcfg / "secrets.yaml").read_text(encoding="utf-8") if (bcfg / "secrets.yaml").exists() else True
    # a config.yaml that is a link: no extension is offered from it
    (cfg / "config.yaml").unlink()
    os.link(out / "config.yaml", cfg / "config.yaml")
    assert refs(pr, alice, "extension") == []
    with pytest.raises(ValueError):
        pr.export_item(alice, "extension", "vx")
    # the administrator's own profile is read as before (regression check for the unchanged kinds)
    assert refs(pr, admin, "provider") == ["p1"] and set(refs(pr, admin, "extension")) == {"todo", "developer", "fetch"}
    assert pr.export_item(admin, "provider", "p1")[1]["secretKeys"] == ["P1_KEY"]


def test_a_managed_mark_that_is_a_link_is_never_written_through(tmp_path, monkeypatch, home):
    """L-9: the mark of a team skill was written in place; as a link it pointed the write at another file."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    ta = with_team(db, alice)
    skill(home / ".agents" / "skills", "review", "R")
    offer(db, pr, admin, ta, "skill", "review")
    pr.provision(alice)
    d = pr.config_dir(alice) / "skills" / "review"
    victim = outside(tmp_path) / "victim.txt"
    victim.write_text("VICTIM", encoding="utf-8")
    (d / profiles.MANAGED_MARK).unlink()
    os.link(victim, d / profiles.MANAGED_MARK)                                 # the member swaps the mark for a link
    (d / "SKILL.md").write_text("changed by the member", encoding="utf-8")
    pr.provision(alice)
    assert victim.read_text(encoding="utf-8") == "VICTIM"                      # not written through
    assert (d / "SKILL.md").read_text(encoding="utf-8") == "changed by the member"   # theirs now: not overwritten
    db.execute("DELETE FROM team_items")
    pr.provision(alice)
    assert d.is_dir() and victim.read_text(encoding="utf-8") == "VICTIM"       # and not deleted as "managed"


# ------------------------------------------------------------------ bounds: whoever fills a folder decides its size
def test_a_skill_that_is_too_large_or_has_too_many_files_is_refused(tmp_path, monkeypatch, home):
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    big = skill(home / ".agents" / "skills", "big")
    (big / "data.txt").write_text("x" * (profiles.MAX_SKILL_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="too large"):
        pr.export_item(admin, "skill", "big")
    many = skill(home / ".agents" / "skills", "many")
    for i in range(profiles.MAX_SKILL_FILES + 1):
        (many / f"f{i}.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="too many files to share"):
        pr.export_item(admin, "skill", "many")
    ok = skill(home / ".agents" / "skills", "binary", extra={"t.txt": "text"})
    (ok / "image.bin").write_bytes(b"\xff\xfe\x00\x81")                         # binary: left out, as before
    assert sorted(pr.export_item(admin, "skill", "binary")[1]["files"]) == ["SKILL.md", "t.txt"]


def test_the_walk_through_a_skill_is_bounded(tmp_path, monkeypatch, home):
    """L-4 / L-13: empty folders and skipped files were never counted, depth was unlimited (a RecursionError on
    Python 3.11), and a path that fits in the source can be too long under a member's profile (L-3)."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    wide = skill(home / ".agents" / "skills", "wide")
    for i in range(30):
        (wide / f"empty-{i}").mkdir()
    monkeypatch.setattr(profiles, "MAX_SKILL_ENTRIES", 20)
    with pytest.raises(ValueError, match="too many files and folders"):
        pr.export_item(admin, "skill", "wide")
    monkeypatch.setattr(profiles, "MAX_SKILL_ENTRIES", 5000)
    deep = skill(home / ".agents" / "skills", "deep", extra={"a/b/c/d/e/f.md": "deep"})
    assert "a/b/c/d/e/f.md" in pr.export_item(admin, "skill", "deep")[1]["files"]
    monkeypatch.setattr(profiles, "MAX_SKILL_DEPTH", 3)
    with pytest.raises(ValueError, match="nested too deeply"):
        pr.export_item(admin, "skill", "deep")
    monkeypatch.setattr(profiles, "MAX_SKILL_DEPTH", 12)
    monkeypatch.setattr(profiles, "MAX_SKILL_REL_PATH", 10)
    with pytest.raises(ValueError, match="too long to share"):
        pr.export_item(admin, "skill", "deep")
    assert deep.is_dir()


def test_what_the_picker_shows_is_bounded_and_is_text(tmp_path, monkeypatch, home):
    """L-2 / L-4: a recipe's description went untyped into the picker's answer. A YAML date made the picker fail for
    that profile; nested YAML aliases expand to gigabytes when written as JSON; and a file of any size was read."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    pr.provision(alice)
    rdir = pr.config_dir(alice) / "recipes"
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "dated.yaml").write_text("title: 2026-11-13\ndescription: 2026-11-13\n", encoding="utf-8")
    bomb = "a: &a [x,x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{n}: &{n} [{','.join('*' + p for _ in range(10))}]\n" for p, n in zip("abcdefg", "bcdefgh"))
    (rdir / "bomb.yaml").write_text(bomb + "title: bomb\ndescription: *h\n", encoding="utf-8")
    (rdir / "long.yaml").write_text(yaml.safe_dump({"title": "t", "description": "d" * 5000}), encoding="utf-8")
    (rdir / "huge.yaml").write_text("title: huge\nprompt: " + "x" * (profiles.MAX_RECIPE_BYTES + 10) + "\n", encoding="utf-8")
    items = pr.library(alice, "recipe")
    # a description that is not text is dropped (the title stands in when IT is text), a long one is cut
    assert {i["name"]: i["description"] for i in items} == {"dated": "", "bomb": "bomb", "long": "d" * 500}
    assert len(json.dumps(items)) < 4000                                       # serialisable, and small
    with pytest.raises(ValueError):
        pr.export_item(alice, "recipe", str(rdir / "huge.yaml"))
    # a SKILL.md of any size: only its head is read for the description
    d = skill(pr.config_dir(alice) / "skills", "heavy", "Short description")
    with open(d / "SKILL.md", "ab") as fh:
        fh.write(b"\n" + b"y" * (3 * 1024 * 1024))
    read = []
    real = profiles._read_head
    monkeypatch.setattr(profiles, "_read_head", lambda p, size=16384: read.append(size) or real(p, size))
    assert [i["description"] for i in pr.library(alice, "skill")] == ["Short description of heavy"] and read == [16384]
    # an extension entry whose description is not text
    cfg = yaml.safe_load((pr.config_dir(alice) / "config.yaml").read_text(encoding="utf-8"))
    cfg.setdefault("extensions", {})["odd"] = {"enabled": True, "type": "stdio", "name": "odd", "description": ["a", "b"],
                                               "display_name": {"x": 1}}
    (pr.config_dir(alice) / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    odd = [i for i in pr.library(alice, "extension") if i["ref"] == "odd"][0]
    assert odd["name"] == "odd" and odd["description"] == "stdio"


# ------------------------------------------------------------------ SC5: goose-web check says where things stand
def _settings(**sandbox) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    data["sandbox"].update(sandbox)
    return Settings(data, None)


def test_the_check_line_reports_the_home_folder_items_and_warns_without_the_sandbox(home):
    assert cli_mod._home_library_line(_settings(enabled=True)) == f"[--] home-folder Goose items: none in {home}"
    skill(home / ".agents" / "skills", "review")
    (home / ".agents" / "agents").mkdir(parents=True)
    (home / ".agents" / "agents" / "helper.md").write_text("---\nname: helper\n---\n", encoding="utf-8")
    (home / ".goose" / "recipes").mkdir(parents=True)
    (home / ".goose" / "recipes" / "weekly.yaml").write_text("title: w\n", encoding="utf-8")
    assert profiles.home_library_summary() == {"home": str(home), "skills": ["review"], "recipes": ["weekly"],
                                               "agents": ["helper"], "linked": []}
    counts = f"1 skill(s), 1 recipe(s), 1 agent(s) in {home}"
    on = cli_mod._home_library_line(_settings(enabled=True, backend="mxc"))
    assert on.startswith(f"[OK] home-folder Goose items: {counts}. Members' agents are sandboxed")
    assert "measured for the MXC backend" in on and "Library items" in on and "review" not in on   # counts, no names
    assert "not measured for the AppContainer backend" in cli_mod._home_library_line(_settings(enabled=True, backend="appcontainer"))
    off = cli_mod._home_library_line(_settings(enabled=False))
    assert off.startswith(f"[!!] home-folder Goose items: {counts}. EVERY member's agent loads them")


@windows_only
def test_a_linked_home_folder_is_counted_but_not_offered(tmp_path, monkeypatch, home):
    """L-6 / L-7: `~/.agents` as a junction (a common dotfiles layout). Goose follows it, so `check` must count what
    is behind it - the first version said "none" - and the picker, which reads through no link, must not offer it."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    dot = tmp_path / "dotfiles" / ".agents"
    skill(dot / "skills", "from-dotfiles")
    (dot / "agents").mkdir()
    (dot / "agents" / "helper.md").write_text("x", encoding="utf-8")
    junction(home / ".agents", dot)
    assert refs(pr, admin) == ["hello"]                                        # only the one in config/skills
    summ = profiles.home_library_summary()
    assert summ["skills"] == ["from-dotfiles"] and summ["agents"] == ["helper"]
    assert summ["linked"] == [str(home / ".agents" / "skills"), str(home / ".agents" / "agents")]
    assert "Reached through a link, so not offered by the picker" in cli_mod._home_library_line(_settings(enabled=True))
    assert cli_mod._home_library_line(_settings(enabled=False)).startswith("[!!] home-folder Goose items: 1 skill(s)")
