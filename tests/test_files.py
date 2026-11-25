"""Spec 041: the Files page, server side - the two team switches (and the one-time switch-on of existing teams), the
locations of a person, browsing, details and type, SHA-256, preview, download, uploads into the folder itself with
their SHA-256, new folder / rename / move / delete into the recycle folder / restore / purge, the folder's activity,
and the same protections as uploads (read-only folders, other people's folders, links leading out, hints files and
.agents, never replacing, CSRF)."""
import asyncio
import errno
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from goose_web import app as gw_app
from goose_web import files, uploads
from goose_web import policy as pol
from goose_web.db import Database
from tests.test_retention import DAY, NOW, attach, rt, sweep  # noqa: F401  (rt: fixture)
from tests.test_retention import member as rt_member
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)
from tests.test_uploads import _junction, put

WIN = sys.platform == "win32"
FILES_ON = {"files": True, "files_manage": True}
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + bytes(20)


def crew(env, policy=None, names=("dee", "ann")):
    """Members of one team (both Files switches on unless `policy` says otherwise), and the team's folder."""
    s, db, pr, c = env
    tid = team(db, "IR", {**ANYCHAT, **FILES_ON, **(policy or {})})
    out = []
    for name in names:
        u = user(db, name)
        db.set_user_team(u["id"], tid)
        u = db.user_by_id(u["id"])
        pr.ensure_layout(u)
        out.append(u)
    return (*out, tid, Path(c.policy_for(out[0])["team_folder"]))


def set_policy(db, tid, **kw):
    t = db.one("SELECT policy FROM teams WHERE id=?", (tid,))
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**t["policy"], **kw}), tid))


def upload(tc, h, folder, name, data, pieces=1, between=None):
    """A chunked upload with target "folder"; `between(i)` runs after piece i."""
    r = tc.post("/api/fs/uploads", json={"dir": str(folder), "name": name, "size": len(data), "target": "folder"},
                headers=h)
    assert r.status_code == 200, r.text
    j = r.json()
    if j["done"]:
        return j
    step = max(1, -(-len(data) // pieces))
    off, i, last = 0, 0, None
    while off < len(data):
        last = put(tc, h, j["id"], off, data[off:off + step])
        assert last.status_code == 200, last.text
        off += step
        i += 1
        if between and off < len(data):
            between(i)
    return {**last.json(), "id": j["id"]}


def audits(db, action):
    return db.query("SELECT * FROM audit WHERE action=? ORDER BY id", (action,))


def names(listing):
    return [e["name"] for e in listing["entries"]]


# ------------------------------------------------------------------ data and policy
def test_an_old_database_gains_the_new_columns_and_tables(tmp_path):
    f = tmp_path / "old.db"
    Database(f).close()
    con = sqlite3.connect(f)     # the schema of 1.27: no Files tables, uploads without target / sha256
    con.execute("DROP TABLE file_hashes")
    con.execute("DROP TABLE file_recycle")
    con.execute("ALTER TABLE uploads DROP COLUMN target")
    con.execute("ALTER TABLE uploads DROP COLUMN sha256")
    con.execute("INSERT INTO uploads(id, dir, name, size, state, created_at, updated_at) "
                "VALUES('k', 'D', 'a.txt', 1, 'done', 0, 0)")
    con.commit()
    assert not {"target", "sha256"} & {r[1] for r in con.execute("PRAGMA table_info(uploads)")}
    con.close()
    db = Database(f)
    try:
        assert {"target", "sha256"} <= {r["name"] for r in db.query("PRAGMA table_info(uploads)")}
        assert db.one("SELECT target, sha256 FROM uploads WHERE id='k'") == {"target": "chat", "sha256": ""}
        assert {"file_hashes", "file_recycle"} <= {r["name"] for r in db.query(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()
    Database(f).close()    # and again: nothing is added twice


def test_existing_teams_get_both_switches_once_and_new_teams_have_them(env):
    s, db, pr, c = env
    a = team(db, "Old A", {**ANYCHAT, "schedules": True})
    b = team(db, "Old B", {})
    assert pol.apply_files_switches(db, now=123.0) == 2
    assert db.one("SELECT policy FROM teams WHERE id=?", (a,))["policy"] == {**ANYCHAT, "schedules": True, **FILES_ON}
    assert db.get_setting(pol.FILES_SWITCHES_SETTING) == 123.0
    rows = audits(db, "team.update")
    assert [r["target"] for r in rows] == ["Old A", "Old B"]
    assert all(r["user_id"] is None and r["username"] == "" and r["detail"]["policy"] == FILES_ON for r in rows)
    # an administrator turns Files off for B: the next start leaves it off (it ran once)
    set_policy(db, b, files=False)
    assert pol.apply_files_switches(db) == 0 and len(audits(db, "team.update")) == 2
    assert db.one("SELECT policy FROM teams WHERE id=?", (b,))["policy"]["files"] is False
    # the gateway does it at start-up; new teams get both; a person without a team has neither
    assert "apply_files_switches(db)" in inspect.getsource(gw_app.create_app)
    assert pol.NEW_TEAM_POLICY["files"] is True and pol.NEW_TEAM_POLICY["files_manage"] is True
    eff = pol.effective_policy(user(db, "nobody"), [])
    assert eff["files"] is False and eff["files_manage"] is False
    assert pol.files_allowed({"role": "admin"}, {}) and pol.files_manage_allowed({"role": "admin"}, {})
    assert not pol.files_manage_allowed({"role": "user"}, {"files": False, "files_manage": True})
    assert pol.ADMIN_POLICY["files"] and pol.ADMIN_POLICY["files_manage"]


def test_switches_are_per_person_overrides_too(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    admin = user(db, "root", role="admin")
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"files_manage": False}}, headers=h)
        assert r.status_code == 200, r.text
        assert db.user_by_id(dee["id"])["policy_overrides"] == {"files_manage": False}
    with client_for(c) as td, client_for(c) as ta:
        hd, ha = sign_in(td, c, dee), sign_in(ta, c, ann)
        (tf / "x.txt").write_text("x")
        r = td.post("/api/files/rename", json={"path": str(tf / "x.txt"), "name": "y.txt"}, headers=hd)
        assert r.status_code == 403 and r.json()["error"] == "files_off" and "rename" in r.json()["message"]
        assert td.get("/api/files/locations").json()["manage"] is False
        assert ta.post("/api/files/rename", json={"path": str(tf / "x.txt"), "name": "y.txt"},
                       headers=ha).status_code == 200
        db.update_user(dee["id"], policy_overrides={"files": False})
        assert td.get("/api/files/locations").json()["error"] == "files_off"
        assert ta.get("/api/files/locations").status_code == 200


def _bodies(f: Path, tf: Path) -> dict:
    return {"/api/files/hash": {"path": str(f)}, "/api/files/mkdir": {"path": str(tf), "name": "new"},
            "/api/files/rename": {"path": str(f), "name": "b.txt"},
            "/api/files/move": {"paths": [str(f)], "to": str(tf / "sub")},
            "/api/files/delete": {"paths": [str(f)]}, "/api/files/restore": {"id": "0" * 20}}


GETS = ["/api/files/locations", "/api/files/list", "/api/files/info", "/api/files/download", "/api/files/preview",
        "/api/files/recycle", "/api/files/activity"]
MANAGE = ["/api/files/rename", "/api/files/move", "/api/files/delete", "/api/files/restore"]


def test_the_files_switch_decides_every_route_and_the_old_file_reads(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, policy={"files": False, "files_manage": False}, names=("dee",))
    f = tf / "a.txt"
    f.write_text("A")
    (tf / "sub").mkdir()
    ws = pr.workspace(dee)
    qp = {"path": str(f), "location": str(tf)}
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for route in GETS:
            r = tc.get(route, params={**qp, "path": str(tf)} if route in ("/api/files/list", "/api/files/activity")
                       else qp)
            assert r.status_code == 403 and r.json()["error"] == "files_off", route
        for route, body in _bodies(f, tf).items():
            r = tc.post(route, json=body, headers=h)
            assert r.status_code == 403 and r.json()["error"] == "files_off", route
        r = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "u.bin", "size": 1, "target": "folder"}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "files_off"
        # the older file routes: reading and downloading need the switch; the folder picker does not
        for route in ("/api/fs/read", "/api/fs/download"):
            r = tc.get(route, params={"path": str(f)})
            assert r.status_code == 403 and r.json()["error"] == "files_off", route
        assert tc.get("/api/fs/roots").status_code == 200
        assert tc.get("/api/fs/list", params={"path": str(tf)}).status_code == 200
        assert tc.post("/api/fs/mkdir", json={"path": str(ws / "picked")}, headers=h).status_code == 200
        # a chat attachment is not a Files upload: it still works
        r = tc.post("/api/fs/uploads", json={"dir": str(ws), "name": "att.txt", "size": 1}, headers=h)
        assert r.status_code == 200 and r.json()["id"]
        assert not f.with_name("b.txt").exists() and f.exists() and not (tf / "new").exists()
        # Files on, rename/move/delete off: everything but the four changes
        set_policy(db, tid, files=True)
        for route in GETS:
            r = tc.get(route, params={**qp, "path": str(tf)} if route in ("/api/files/list", "/api/files/activity")
                       else qp)
            assert r.status_code == 200, (route, r.text)
        for route, body in _bodies(f, tf).items():
            r = tc.post(route, json=body, headers=h)
            if route in MANAGE:
                assert r.status_code == 403 and r.json()["error"] == "files_off", route
            else:
                assert r.status_code == 200, (route, r.text)
        assert tc.get("/api/fs/read", params={"path": str(f)}).json()["content"] == "A"
        assert tc.get("/api/fs/download", params={"path": str(f)}).content == b"A"
        a = audits(db, "files.read")[-1]
        assert a["target"] == str(f) and a["detail"]["route"] == "/api/fs/read" and a["detail"]["size"] == 1
        a = audits(db, "files.download")[-1]
        assert a["detail"]["route"] == "/api/fs/download" and a["username"] == "dee"
        set_policy(db, tid, files_manage=True)
        r = tc.post("/api/files/rename", json={"path": str(f), "name": "b.txt"}, headers=h)
        assert r.status_code == 200 and (tf / "b.txt").read_text() == "A"


def test_csrf_is_needed_for_every_change(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    f = tf / "a.txt"
    f.write_text("A")
    with client_for(c) as tc:
        sign_in(tc, c, dee)
        for route, body in _bodies(f, tf).items():
            r = tc.post(route, json=body)
            assert r.status_code == 403 and r.json()["error"] == "csrf", route
        r = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "u.bin", "size": 1, "target": "folder"})
        assert r.status_code == 403 and r.json()["error"] == "csrf"
    assert f.read_text() == "A" and not (tf / "new").exists() and not (tf / files.RECYCLE_DIR).exists()


def test_locations_are_the_folders_the_person_already_has(env, tmp_path):
    s, db, pr, c = env
    rw, kb = tmp_path / "rw", tmp_path / "kb"
    rw.mkdir()
    kb.mkdir()
    dee, tid, tf = crew(env, policy={"allowed_roots": [str(rw)], "read_roots": [str(kb)]}, names=("dee",))
    admin = user(db, "root", role="admin")
    with client_for(c) as tc:
        sign_in(tc, c, dee)
        j = tc.get("/api/files/locations").json()
    assert j["manage"] is True and j["recycleDays"] == 30
    locs = j["locations"]
    assert [(x["kind"], x["access"]) for x in locs] == [("workspace", "write"), ("team", "write"), ("extra", "write"),
                                                       ("extra", "read")]
    assert [x["path"] for x in locs] == [str(pr.workspace(dee)), str(tf), str(rw), str(kb)]
    assert [x["label"] for x in locs] == ["My workspace", "IR team folder", "rw", "kb"]
    with client_for(c) as tc:
        sign_in(tc, c, admin)
        j = tc.get("/api/files/locations").json()
    assert j["manage"] is True and j["locations"][0]["kind"] == "workspace"
    assert {x["kind"] for x in j["locations"][1:]} == {"drive"} and len(j["locations"]) >= 2


def test_a_read_only_folder_is_read_but_never_changed(env, tmp_path):
    s, db, pr, c = env
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "facts.md").write_text("FACTS")
    (kb / "old").mkdir()
    dee, tid, tf = crew(env, policy={"read_roots": [str(kb)]}, names=("dee",))
    ws = pr.workspace(dee)
    (ws / "mine.txt").write_text("m")
    f = kb / "facts.md"
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.get("/api/files/list", params={"path": str(kb)}).json()
        assert j["access"] == "read" and names(j) == ["old", "facts.md"] and j["parent"] is None
        assert tc.get("/api/files/info", params={"path": str(f)}).json()["access"] == "read"
        assert tc.get("/api/files/download", params={"path": str(f)}).content == b"FACTS"
        assert tc.get("/api/files/preview", params={"path": str(f)}).json()["content"] == "FACTS"
        assert tc.post("/api/files/hash", json={"path": str(f)}, headers=h).status_code == 200

        def refused(r):
            return r.status_code == 403 and r.json()["error"] == "read_only_folder"
        assert refused(tc.post("/api/fs/uploads", json={"dir": str(kb), "name": "x", "size": 1, "target": "folder"},
                               headers=h))
        assert refused(tc.post("/api/files/mkdir", json={"path": str(kb), "name": "n"}, headers=h))
        assert refused(tc.post("/api/files/rename", json={"path": str(f), "name": "g.md"}, headers=h))
        assert refused(tc.post("/api/files/move", json={"paths": [str(ws / "mine.txt")], "to": str(kb)}, headers=h))
        j = tc.post("/api/files/move", json={"paths": [str(f)], "to": str(ws)}, headers=h).json()
        assert j["moved"] == [] and j["failed"][0]["error"] == "read_only_folder"
        j = tc.post("/api/files/delete", json={"paths": [str(f), str(kb / "old")]}, headers=h).json()
        assert j["deleted"] == [] and {x["error"] for x in j["failed"]} == {"read_only_folder"}
        assert tc.get("/api/files/recycle", params={"location": str(kb)}).json() == {"items": []}
    assert sorted(os.listdir(kb)) == ["facts.md", "old"] and (ws / "mine.txt").exists()


def test_other_peoples_folders_and_links_leading_out_are_refused(env, tmp_path):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    out = tmp_path / "outside"
    out.mkdir()
    (out / "secret.txt").write_text("S")
    wd, wa = pr.workspace(dee), pr.workspace(ann)
    (wa / "anns.txt").write_text("A")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for route in ("/api/files/list", "/api/files/info", "/api/files/activity"):
            r = tc.get(route, params={"path": str(wa)})
            assert r.status_code == 403 and r.json()["error"] == "denied", route
        for route in ("/api/files/download", "/api/files/preview", "/api/files/info"):
            assert tc.get(route, params={"path": str(wa / "anns.txt")}).json()["error"] == "denied", route
        assert tc.post("/api/files/hash", json={"path": str(wa / "anns.txt")}, headers=h).json()["error"] == "denied"
        assert tc.post("/api/files/delete", json={"paths": [str(wa / "anns.txt")]},
                       headers=h).json()["failed"][0]["error"] == "denied"
        assert tc.post("/api/files/move", json={"paths": [str(wd)], "to": str(wa)}, headers=h).json()["error"] == "denied"
        r = tc.post("/api/fs/uploads", json={"dir": str(wa), "name": "x", "size": 1, "target": "folder"}, headers=h)
        assert r.status_code == 403
        if WIN and _junction(wd / "door", out):
            assert tc.get("/api/files/list", params={"path": str(wd / "door")}).json()["error"] == "denied"
            r = tc.get("/api/files/download", params={"path": str(wd / "door" / "secret.txt")})
            assert r.status_code == 403
            r = tc.post("/api/fs/uploads", json={"dir": str(wd / "door"), "name": "x", "size": 1, "target": "folder"},
                        headers=h)
            assert r.status_code == 403 and not (out / "x").exists()
            r = tc.post("/api/files/mkdir", json={"path": str(wd / "door"), "name": "n"}, headers=h)
            assert r.status_code == 403 and not (out / "n").exists()
    with client_for(c) as tc:      # ann's item in her recycle folder is not dee's to restore
        ha = sign_in(tc, c, ann)
        rid = tc.post("/api/files/delete", json={"paths": [str(wa / "anns.txt")]}, headers=ha).json()["deleted"][0]["id"]
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert tc.post("/api/files/restore", json={"id": rid}, headers=h).status_code == 404
        assert tc.get("/api/files/recycle", params={"location": str(wa)}).status_code == 403


def test_hints_files_agents_folders_and_bad_names(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    (tf / "AGENTS.md").write_text("team rules")       # put there by an administrator
    (tf / ".agents").mkdir()
    (tf / "x.txt").write_text("x")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)

        def mk(name):
            return tc.post("/api/files/mkdir", json={"path": str(tf), "name": name}, headers=h)
        assert mk("AGENTS.md").json()["error"] == "hint_file_refused"
        assert mk(".goosehints").json()["error"] == "hint_file_refused"
        assert mk(".agents").json()["error"] == "agents_folder_refused"
        for bad in ("", "  ", "a/b", "a\\b", "..", ".", files.RECYCLE_DIR, files.RECYCLE_DIR.upper() + ". ", None, 7):
            r = mk(bad)
            assert r.status_code == 400 and r.json()["error"] == "bad_name", bad
        r = mk("CON")
        assert r.status_code == 200 and r.json()["path"] == str(tf / "_CON")
        r = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": ".goosehints", "size": 1, "target": "folder"},
                    headers=h)
        assert r.json()["error"] == "hint_file_refused"
        r = tc.post("/api/fs/uploads", json={"dir": str(tf / ".agents"), "name": "p.json", "size": 1,
                                             "target": "folder"}, headers=h)
        assert r.json()["error"] == "agents_folder_refused"
        r = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": files.RECYCLE_DIR, "size": 1, "target": "folder"},
                    headers=h)
        assert r.json()["error"] == "bad_name"
        r = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "y", "size": 1, "target": "elsewhere"}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "bad_request"
        assert tc.post("/api/files/rename", json={"path": str(tf / "x.txt"), "name": "AGENTS.md"},
                       headers=h).json()["error"] == "hint_file_refused"
        assert tc.post("/api/files/rename", json={"path": str(tf / "AGENTS.md"), "name": "old.md"},
                       headers=h).json()["error"] == "hint_file_refused"
        assert tc.post("/api/files/rename", json={"path": str(tf / ".agents"), "name": "plugins-off"},
                       headers=h).json()["error"] == "agents_folder_refused"
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "AGENTS.md"), str(tf / ".agents")]}, headers=h).json()
        assert [x["error"] for x in j["failed"]] == ["hint_file_refused", "agents_folder_refused"]
        (tf / "sub").mkdir()
        j = tc.post("/api/files/move", json={"paths": [str(tf / "AGENTS.md")], "to": str(tf / "sub")}, headers=h).json()
        assert j["failed"][0]["error"] == "hint_file_refused"
        assert tc.post("/api/files/move", json={"paths": [str(tf / "x.txt")], "to": str(tf / ".agents")},
                       headers=h).json()["error"] == "agents_folder_refused"
    assert (tf / "AGENTS.md").read_text() == "team rules" and (tf / ".agents").is_dir() and (tf / "x.txt").exists()


# ------------------------------------------------------------------ browsing
def test_list_pages_sorts_filters_and_hides(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    (tf / "B").mkdir()
    (tf / "a").mkdir()
    for name, size, age in (("c.txt", 3, 30), ("D.log", 10, 10), ("e.bin", 1, 20), (".dot", 1, 5)):
        (tf / name).write_bytes(b"x" * size)
        os.utime(tf / name, (NOW - age, NOW - age))
    (tf / "hid.txt").write_text("h")
    uploads._set_hidden(tf / "hid.txt", True)
    visible = ["a", "B", "c.txt", "D.log", "e.bin"] + ([] if WIN else ["hid.txt"])
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)

        def ls(**kw):
            r = tc.get("/api/files/list", params={"path": str(tf), **kw})
            assert r.status_code == 200, r.text
            return r.json()
        j = ls()
        assert names(j) == visible and j["total"] == len(visible) and j["offset"] == 0
        assert j["path"] == str(tf) and j["location"] == str(tf) and j["parent"] is None and j["access"] == "write"
        assert "truncated" not in j
        e = {x["name"]: x for x in j["entries"]}
        assert e["a"]["dir"] and e["D.log"]["size"] == 10 and not e["D.log"]["dir"] and e["D.log"]["path"] == str(tf / "D.log")
        assert e["c.txt"]["mtime"] == pytest.approx(NOW - 30) and e["c.txt"]["hidden"] is False
        assert [x for x in names(ls(sort="size", order="desc")) if x not in ("a", "B", "hid.txt")] == ["D.log", "c.txt", "e.bin"]
        assert names(ls(sort="name", order="desc"))[:2] == ["B", "a"]          # folders stay first
        assert [x for x in names(ls(sort="mtime")) if x in ("c.txt", "D.log", "e.bin")] == ["c.txt", "e.bin", "D.log"]
        assert names(ls(limit=2)) == ["a", "B"] and names(ls(limit=2, offset=2)) == ["c.txt", "D.log"]
        assert ls(limit=2, offset=4)["total"] == len(visible)
        assert names(ls(q=".LOG")) == ["D.log"]
        allh = ls(hidden=1)
        assert {".dot", "hid.txt"} <= set(names(allh))
        assert {x["name"]: x["hidden"] for x in allh["entries"]}[".dot"] is True
        if WIN:
            assert {x["name"]: x["hidden"] for x in allh["entries"]}["hid.txt"] is True
        for bad in ({"sort": "type"}, {"order": "up"}, {"limit": "many"}):
            assert tc.get("/api/files/list", params={"path": str(tf), **bad}).status_code == 400
        assert len(ls(limit=100000)["entries"]) == len(visible)                 # at most 500 a page
        assert tc.get("/api/files/list", params={"path": str(tf / "c.txt")}).status_code == 404
        assert tc.get("/api/files/list", params={"path": "relative\\path"}).status_code == 400
        assert tc.get("/api/files/list").status_code == 400
        sub = tc.get("/api/files/list", params={"path": str(tf / "a")}).json()
        assert sub["parent"] == str(tf) and sub["location"] == str(tf)
        monkeypatch.setattr(files, "SCAN_MAX", 3)
        assert ls()["truncated"] is True
        monkeypatch.undo()
        # the recycle folder: made by a delete, hidden, never listed (here or in the folder picker), never reached
        tc.post("/api/files/delete", json={"paths": [str(tf / "e.bin")]}, headers=h)
        rec = tf / files.RECYCLE_DIR
        assert rec.is_dir() and files.RECYCLE_DIR not in names(ls(hidden=1))
        if WIN:
            assert os.stat(rec).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN
        assert files.RECYCLE_DIR not in [x["name"] for x in tc.get("/api/fs/list", params={"path": str(tf)}).json()["entries"]]
        item = next(rec.rglob("e.bin"))
        for route, p in (("/api/files/list", rec), ("/api/files/info", item), ("/api/files/download", item),
                         ("/api/files/preview", item), ("/api/files/activity", rec), ("/api/fs/list", rec),
                         ("/api/fs/read", item), ("/api/fs/download", item), ("/api/files/list", tf / ".GOOSE-WEB-RECYCLE.")):
            r = tc.get(route, params={"path": str(p)})
            assert r.status_code == 404 and r.json()["error"] == "not_found", (route, p)
        for route, body in (("/api/files/mkdir", {"path": str(rec), "name": "n"}),
                            ("/api/files/hash", {"path": str(item)}),
                            ("/api/files/rename", {"path": str(item), "name": "z"}),
                            ("/api/fs/mkdir", {"path": str(rec / "n")}),
                            ("/api/fs/uploads", {"dir": str(item.parent), "name": "z", "size": 1, "target": "folder"}),
                            ("/api/fs/uploads", {"dir": str(rec), "name": "z", "size": 1})):
            r = tc.post(route, json=body, headers=h)
            assert r.status_code == 404, (route, r.text)
        j = tc.post("/api/files/move", json={"paths": [str(tf / "c.txt")], "to": str(rec)}, headers=h)
        assert j.status_code == 404
        j = tc.post("/api/files/delete", json={"paths": [str(rec), str(item)]}, headers=h).json()
        assert [x["error"] for x in j["failed"]] == ["not_found", "not_found"]
    assert item.exists() and sorted(os.listdir(rec)) == [item.parent.name] and (tf / "c.txt").exists()


def test_the_type_is_recognised_from_the_first_bytes():
    tar = bytes(257) + b"ustar\x0000" + bytes(250)
    cases = {PNG: "PNG image", b"\xff\xd8\xff\xe0\x00\x10JFIF": "JPEG image", b"GIF89a\x01\x00": "GIF image",
             b"RIFF\x10\x00\x00\x00WEBPVP8 ": "WebP image", b"%PDF-1.7\n%": "PDF document",
             b"PK\x03\x04\x14\x00": "ZIP archive", b"MZ\x90\x00\x03\x00": "Windows executable",
             b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00": "pcap capture", b"\x0a\x0d\x0d\x0a\x1c\x00": "pcapng capture",
             b"\x1f\x8b\x08\x00": "gzip archive", b"7z\xbc\xaf\x27\x1c\x00": "7-Zip archive", tar: "tar archive",
             b"ElfFile\x00\x00": "Windows event log (EVTX)", b"regf\x01\x00": "Windows registry hive",
             b"\x7fELF\x02\x01": "ELF executable", b"SQLite format 3\x00": "SQLite database",
             b"hello\r\nworld\t!\n": "text", "h\u00e9llo w\u00f6rld\n".encode(): "text",
             b"\xef\xbb\xbfbom text": "text", b"\xff\xfeh\x00i\x00": "text (UTF-16)",
             b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>': "text",
             bytes(range(256)): "data", b"\x01\x02\x03\x04\x05\x06\x07\x0e" * 8: "data"}
    for head, kind in cases.items():
        assert files.detect_type(head, len(head)) == kind, (head[:12], kind)
    assert files.detect_type(b"", 0) == "empty" and files.detect_type(b"", 5) == "data"


def test_info_gives_dates_type_and_who_uploaded(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    (tf / "shot.png").write_bytes(PNG)
    (tf / "notes").mkdir()
    with client_for(c) as td, client_for(c) as ta:
        hd = sign_in(td, c, dee)
        sign_in(ta, c, ann)
        up = upload(td, hd, tf, "cap.pcap", b"\xd4\xc3\xb2\xa1" + os.urandom(100))
        j = ta.get("/api/files/info", params={"path": str(tf / "shot.png")}).json()
        assert j["type"] == "PNG image" and j["name"] == "shot.png" and j["size"] == len(PNG) and not j["dir"]
        assert j["access"] == "write" and j["ctime"] > 0 and j["mtime"] > 0 and "sha256" not in j and "uploadedBy" not in j
        j = ta.get("/api/files/info", params={"path": up["file"]["path"]}).json()
        assert j["type"] == "pcap capture" and j["uploadedBy"] == "dee" and j["uploadedAt"] > 0
        assert j["sha256"] == up["file"]["sha256"]
        j = ta.get("/api/files/info", params={"path": str(tf / "notes")}).json()
        assert j["dir"] and j["type"] == "folder"
        assert ta.get("/api/files/info", params={"path": str(tf / "nope")}).status_code == 404
        # the same name, another file: no longer "uploaded by"
        Path(up["file"]["path"]).unlink()
        Path(up["file"]["path"]).write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(100))
        j = ta.get("/api/files/info", params={"path": up["file"]["path"]}).json()
        assert "uploadedBy" not in j and "sha256" not in j


def computed(j: dict) -> dict:
    """A hash answer without its labels, after checking them: computed now (assessment F-5)."""
    assert j.pop("sha256Source") == "computed" and abs(j.pop("recordedAt") - __import__("time").time()) < 60
    return j


def test_sha256_is_computed_on_request_and_cached(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    f = tf / "big.bin"
    data = os.urandom(3 * 1024 * 1024 + 7)
    f.write_bytes(data)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/files/hash", json={"path": str(f)}, headers=h)
        assert r.status_code == 200 and computed(r.json()) == {"sha256": hashlib.sha256(data).hexdigest(), "cached": False}
        row = db.one("SELECT * FROM file_hashes")
        assert row["path"] == os.path.normcase(str(f)) and row["size"] == len(data)
        assert tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()["cached"] is True
        # changed in place with the same size and modification time: only `force` reads it again
        st = os.stat(f)
        with open(f, "r+b") as fh:
            fh.write(b"\x00" * 8)
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        assert tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()["sha256"] == hashlib.sha256(data).hexdigest()
        data = b"\x00" * 8 + data[8:]
        j = tc.post("/api/files/hash", json={"path": str(f), "force": True}, headers=h).json()
        assert computed(j) == {"sha256": hashlib.sha256(data).hexdigest(), "cached": False}
        listing = tc.get("/api/files/list", params={"path": str(tf)}).json()
        assert listing["entries"][0]["sha256"] == hashlib.sha256(data).hexdigest()
        assert tc.get("/api/files/info", params={"path": str(f)}).json()["sha256"] == hashlib.sha256(data).hexdigest()
        f.write_bytes(b"changed")
        os.utime(f, (NOW + 100, NOW + 100))
        assert "sha256" not in tc.get("/api/files/info", params={"path": str(f)}).json()
        j = tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()
        assert computed(j) == {"sha256": hashlib.sha256(b"changed").hexdigest(), "cached": False}
        assert db.one("SELECT COUNT(*) AS n FROM file_hashes")["n"] == 1
        assert tc.post("/api/files/hash", json={"path": str(tf)}, headers=h).status_code == 400
        assert tc.post("/api/files/hash", json={"path": str(tf / "nope")}, headers=h).status_code == 404
        files._live(db).hashing[dee["id"]] = files.HASH_PARALLEL      # two are running
        (tf / "other.bin").write_bytes(b"o")
        r = tc.post("/api/files/hash", json={"path": str(tf / "other.bin")}, headers=h)
        assert r.status_code == 429 and r.json()["error"] == "busy"
        files._live(db).hashing.clear()
        assert tc.post("/api/files/hash", json={"path": str(tf / "other.bin")}, headers=h).status_code == 200
    assert "asyncio.to_thread(_hash_file" in inspect.getsource(files.hash_route)     # off the event loop


def test_preview_shows_text_and_true_images_only(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    (tf / "log.txt").write_bytes(b"line 1\nline 2 <b>not html</b>\n")
    (tf / "big.log").write_bytes(b"a" * (files.PREVIEW_TEXT_BYTES + 10))
    (tf / "shot.png").write_bytes(PNG)
    (tf / "photo.png").write_bytes(b"\xff\xd8\xff\xe0" + bytes(40))        # a JPEG named .png
    (tf / "evil.png").write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
    (tf / "evil.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>')
    (tf / "a.zip").write_bytes(b"PK\x03\x04" + bytes(40))
    (tf / "u16.txt").write_bytes("hi there".encode("utf-16"))
    with client_for(c) as tc:
        sign_in(tc, c, dee)

        def pv(name):
            return tc.get("/api/files/preview", params={"path": str(tf / name)})
        r = pv("log.txt")
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
        assert r.json() == {"kind": "text", "type": "text", "content": "line 1\nline 2 <b>not html</b>\n",
                            "truncated": False}
        j = pv("big.log").json()
        assert j["truncated"] is True and len(j["content"]) == files.PREVIEW_TEXT_BYTES
        assert pv("u16.txt").json()["content"] == "hi there"
        r = pv("shot.png")
        assert r.status_code == 200 and r.content == PNG and r.headers["content-type"] == "image/png"
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["content-disposition"] == "inline"
        assert r.headers["content-security-policy"] == "sandbox; default-src 'none'"
        assert pv("photo.png").headers["content-type"] == "image/jpeg"           # from the bytes, not the name
        for name in ("evil.png", "evil.svg"):          # SVG is never an image here: text, shown as text
            r = pv(name)
            assert r.headers["content-type"].startswith("application/json") and r.json()["kind"] == "text"
        r = pv("a.zip")
        assert r.status_code == 415 and r.json()["error"] == "no_preview" and "ZIP archive" in r.json()["message"]
        assert pv("nope.txt").status_code == 404
        assert tc.get("/api/files/preview", params={"path": str(tf)}).status_code == 404
        monkeypatch.setattr(files, "PREVIEW_IMAGE_MAX", 10)
        assert pv("shot.png").status_code == 415
    a = audits(db, "files.preview")
    assert a and a[0]["target"] == str(tf / "log.txt") and a[0]["detail"]["kind"] == "text"
    assert any(x["detail"]["kind"] == "image" and x["detail"]["size"] == len(PNG) for x in a)


def test_download_resumes_with_range_and_is_audited(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    data = bytes(range(256)) * 40
    with client_for(c) as td, client_for(c) as ta:
        hd = sign_in(td, c, dee)
        sign_in(ta, c, ann)
        up = upload(td, hd, tf, "report.bin", data)
        p = up["file"]["path"]
        r = ta.get("/api/files/download", params={"path": p})
        assert r.status_code == 200 and r.content == data
        assert r.headers["content-type"] == "application/octet-stream"
        assert r.headers["content-disposition"].startswith("attachment") and "report.bin" in r.headers["content-disposition"]
        assert r.headers["content-security-policy"].startswith("sandbox") and r.headers["cache-control"] == "no-store"
        r = ta.get("/api/files/download", params={"path": p}, headers={"Range": "bytes=100-199"})
        assert r.status_code == 206 and r.content == data[100:200]
        assert ta.get("/api/files/download", params={"path": str(tf)}).status_code == 404
        assert ta.get("/api/files/download", params={"path": str(tf / "nope")}).status_code == 404
    a = audits(db, "files.download")
    assert [x["username"] for x in a] == ["ann", "ann"] and a[0]["target"] == p
    assert a[0]["detail"] == {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assert a[1]["detail"]["range"] == "bytes=100-199"


# ------------------------------------------------------------------ uploads into the folder itself
def test_a_folder_upload_lands_in_the_folder_with_its_sha256(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    data = os.urandom(10_000)
    with client_for(c) as td, client_for(c) as ta:
        hd = sign_in(td, c, dee)
        sign_in(ta, c, ann)
        (tf / "cap.pcap").write_bytes(b"already here")
        # three pieces; the SHA-256 state kept in memory is lost twice (a restart): read again from the partial file
        j = upload(td, hd, tf, "cap.pcap", data, pieces=3, between=lambda i: uploads._live(db).hashes.clear())
        assert j["done"] and j["file"]["name"] == "cap (1).pcap" and j["file"]["path"] == str(tf / "cap (1).pcap")
        assert j["file"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert (tf / "cap (1).pcap").read_bytes() == data and (tf / "cap.pcap").read_bytes() == b"already here"
        assert not (tf / "Web_Uploads").exists() and not list(tf.glob(".goose-web-upload-*"))
        row = db.one("SELECT * FROM uploads WHERE path=?", (str(tf / "cap (1).pcap"),))
        assert row["target"] == "folder" and row["sha256"] == hashlib.sha256(data).hexdigest()
        assert row["session_id"] == "" and row["dir"] == str(tf)
        a = audits(db, "files.upload")[-1]
        assert a["username"] == "dee" and a["target"] == str(tf / "cap (1).pcap")
        assert a["detail"] == {"name": "cap (1).pcap", "folder": str(tf), "size": len(data),
                               "sha256": hashlib.sha256(data).hexdigest(), "chunked": True}
        assert not audits(db, "fs.upload")
        # the teammate sees it, with who uploaded it, when, and its SHA-256
        e = {x["name"]: x for x in ta.get("/api/files/list", params={"path": str(tf)}).json()["entries"]}
        assert e["cap (1).pcap"]["uploadedBy"] == "dee" and e["cap (1).pcap"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert "uploadedBy" not in e["cap.pcap"]
        # a file of 0 bytes is complete at the start (its SHA-256 read from the empty file)
        j = upload(td, hd, tf, "empty.txt", b"")
        assert j["file"]["sha256"] == hashlib.sha256(b"").hexdigest() and (tf / "empty.txt").read_bytes() == b""
        # in no chat: /api/fs/uploads/link does not take it
        r = td.post("/api/fs/uploads/link", json={"session": "S1", "ids": [j["id"]]}, headers=hd)
        assert r.json() == {"linked": 0} and not db.query("SELECT * FROM upload_links")
        # a sub-folder that does not exist is not made on the way
        r = td.post("/api/fs/uploads", json={"dir": str(tf / "nope"), "name": "x", "size": 1, "target": "folder"},
                    headers=hd)
        assert r.status_code == 404 and not (tf / "nope").exists()
        # cancelling a folder upload
        k = td.post("/api/fs/uploads", json={"dir": str(tf), "name": "c.bin", "size": 5, "target": "folder"},
                    headers=hd).json()
        put(td, hd, k["id"], 0, b"ab")
        assert td.delete(f"/api/fs/uploads/{k['id']}", headers=hd).json() == {"state": "aborted"}
        assert not list(tf.glob(".goose-web-upload-*")) and k["id"] not in uploads._live(db).hashes
        # a chat attachment is as before: Web_Uploads, target chat, no SHA-256, fs.upload
        ws = pr.workspace(dee)
        r = td.post("/api/fs/uploads", json={"dir": str(ws), "name": "att.txt", "size": 2}, headers=hd).json()
        put(td, hd, r["id"], 0, b"hi")
        row = db.one("SELECT * FROM uploads WHERE path=?", (str(ws / "Web_Uploads" / "att.txt"),))
        assert row["target"] == "chat" and row["sha256"] == ""
        assert audits(db, "fs.upload")[-1]["detail"] == {"files": ["att.txt"], "size": 2, "chunked": True}


def test_a_folder_upload_whose_partial_file_was_swapped_is_ended(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        k = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "c.bin", "size": 6, "target": "folder"},
                    headers=h).json()
        assert put(tc, h, k["id"], 0, b"abc").status_code == 200
        uploads._live(db).hashes.clear()      # a restart: the hash is read from the partial file, which is not ours

        def swapped(row, upto):
            raise uploads._Swapped()
        monkeypatch.setattr(uploads, "_hash_partial", swapped)
        r = put(tc, h, k["id"], 3, b"def")
        assert r.status_code == 409 and r.json()["error"] == "upload_lost"
        assert db.one("SELECT state FROM uploads WHERE id=?", (uploads._key(k["id"]),))["state"] == "aborted"
        assert not (tf / "c.bin").exists()


def test_retention_never_deletes_files_uploaded_on_the_files_page(rt):
    s, db, pr, c, hub = rt
    dee = rt_member(rt, policy=FILES_ON)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = upload(tc, h, ws, "evidence.pcap", b"\xd4\xc3\xb2\xa1 capture")
    kept = Path(j["file"]["path"])
    old = NOW - 200 * DAY
    db.execute("UPDATE uploads SET created_at=?, completed_at=?, updated_at=? WHERE path=?", (old, old, old, str(kept)))
    _, chat_file = attach(rt, dee, "o.txt", b"12345", days_ago=200)     # an old attachment in no chat: it goes
    assert sweep(c, dry_run=True)["files"] == 1
    r = sweep(c)
    assert r["files"] == 1 and not chat_file.exists() and kept.exists()
    assert db.one("SELECT state FROM uploads WHERE path=?", (str(kept),))["state"] == "done"


# ------------------------------------------------------------------ new folder, rename, move, delete, restore, purge
def test_mkdir_and_rename_never_replace_and_spare_location_tops(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    ws = pr.workspace(dee)
    (tf / "a.txt").write_text("A")
    (tf / "b.txt").write_text("B")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/files/mkdir", json={"path": str(tf), "name": " Case 42 "}, headers=h)
        assert r.status_code == 200 and r.json() == {"path": str(tf / "Case 42")} and (tf / "Case 42").is_dir()
        r = tc.post("/api/files/mkdir", json={"path": str(tf), "name": "Case 42"}, headers=h)
        assert r.status_code == 409 and r.json()["error"] == "exists"
        r = tc.post("/api/files/mkdir", json={"path": str(tf / "missing"), "name": "x"}, headers=h)
        assert r.status_code == 404
        assert audits(db, "files.mkdir")[0]["target"] == str(tf / "Case 42")
        r = tc.post("/api/files/rename", json={"path": str(tf / "a.txt"), "name": "b.txt"}, headers=h)
        assert r.status_code == 409 and r.json()["error"] == "exists"
        assert (tf / "a.txt").read_text() == "A" and (tf / "b.txt").read_text() == "B"
        r = tc.post("/api/files/rename", json={"path": str(tf / "a.txt"), "name": "c:d?.txt"}, headers=h)
        assert r.status_code == 200 and r.json()["path"] == str(tf / "cd.txt") and (tf / "cd.txt").read_text() == "A"
        a = audits(db, "files.rename")[-1]
        assert a["target"] == str(tf / "cd.txt") and a["detail"] == {"from": str(tf / "a.txt"), "to": str(tf / "cd.txt")}
        if WIN:     # a change of case only
            r = tc.post("/api/files/rename", json={"path": str(tf / "cd.txt"), "name": "CD.txt"}, headers=h)
            assert r.status_code == 200 and "CD.txt" in os.listdir(tf)
        assert tc.post("/api/files/rename", json={"path": str(tf / "gone.txt"), "name": "x"}, headers=h).status_code == 404
        for top in (tf, ws):
            r = tc.post("/api/files/rename", json={"path": str(top), "name": "renamed"}, headers=h)
            assert r.status_code == 403 and r.json()["error"] == "denied", top
            j = tc.post("/api/files/delete", json={"paths": [str(top)]}, headers=h).json()
            assert j["failed"][0]["error"] == "denied" and top.is_dir()
        j = tc.post("/api/files/move", json={"paths": [str(tf)], "to": str(ws)}, headers=h).json()
        assert j["failed"][0]["error"] == "denied" and tf.is_dir()


def test_move_never_replaces_and_not_into_itself(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    ws = pr.workspace(dee)
    (tf / "case").mkdir()
    (tf / "case" / "inner").mkdir()
    (tf / "case" / "log.txt").write_text("L")
    (tf / "r.txt").write_text("R")
    (ws / "r.txt").write_text("mine")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/move", json={"paths": [str(tf / "r.txt"), str(tf / "case"), str(tf / "nope")],
                                             "to": str(ws)}, headers=h).json()
        assert j["moved"] == [{"from": str(tf / "case"), "to": str(ws / "case")}]
        assert [(x["path"], x["error"]) for x in j["failed"]] == [(str(tf / "r.txt"), "exists"),
                                                                  (str(tf / "nope"), "not_found")]
        assert (ws / "r.txt").read_text() == "mine" and (tf / "r.txt").read_text() == "R"
        assert (ws / "case" / "log.txt").read_text() == "L" and not (tf / "case").exists()
        a = audits(db, "files.move")
        assert len(a) == 1 and a[0]["target"] == str(ws / "case") and a[0]["detail"]["from"] == str(tf / "case")
        j = tc.post("/api/files/move", json={"paths": [str(ws / "case")], "to": str(ws / "case" / "inner")},
                    headers=h).json()
        assert j["failed"][0]["error"] == "bad_request" and (ws / "case" / "inner").is_dir()
        j = tc.post("/api/files/move", json={"paths": [str(ws / "case")], "to": str(ws / "case")}, headers=h).json()
        assert j["failed"][0]["error"] == "bad_request"
        assert tc.post("/api/files/move", json={"paths": [], "to": str(ws)}, headers=h).status_code == 400
        assert tc.post("/api/files/move", json={"paths": ["x"] * 201, "to": str(ws)}, headers=h).status_code == 400
        assert tc.post("/api/files/move", json={"paths": [str(tf / "r.txt")], "to": str(ws / "nope")},
                       headers=h).status_code == 404
        # another volume: copied next to the target under a hidden name, then renamed, then the original deleted
        os.chmod(ws / "case" / "log.txt", stat.S_IREAD)       # a read-only file is copied and deleted too
        mt = os.stat(ws / "case" / "log.txt").st_mtime_ns
        other_volume(monkeypatch)
        j = tc.post("/api/files/move", json={"paths": [str(ws / "case")], "to": str(tf)}, headers=h).json()
        assert j == {"moved": [{"from": str(ws / "case"), "to": str(tf / "case")}], "failed": []}
        assert (tf / "case" / "log.txt").read_text() == "L" and (tf / "case" / "inner").is_dir()
        assert os.stat(tf / "case" / "log.txt").st_mtime_ns == mt and not os.access(tf / "case" / "log.txt", os.W_OK)
        assert not (ws / "case").exists() and not list(tf.glob(files.MOVE_PREFIX + "*"))
        # a single file too
        (ws / "one.txt").write_text("1")
        j = tc.post("/api/files/move", json={"paths": [str(ws / "one.txt")], "to": str(tf)}, headers=h).json()
        assert j["moved"] and (tf / "one.txt").read_text() == "1" and not (ws / "one.txt").exists()


def test_delete_goes_to_the_recycle_folder_and_restore_brings_it_back(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    (tf / "case").mkdir()
    (tf / "case" / "notes.txt").write_text("N")
    data = b"evidence"
    with client_for(c) as td, client_for(c) as ta:
        hd, ha = sign_in(td, c, dee), sign_in(ta, c, ann)
        up = upload(td, hd, tf / "case", "e.bin", data)
        p = Path(up["file"]["path"])
        j = td.post("/api/files/delete", json={"paths": [str(p), str(tf / "case")]}, headers=hd).json()
        assert [x["path"] for x in j["deleted"]] == [str(p), str(tf / "case")] and j["failed"] == []
        assert not (tf / "case").exists()
        ids = [x["id"] for x in j["deleted"]]
        rec = tf / files.RECYCLE_DIR
        assert (rec / ids[0] / "e.bin").read_bytes() == data and (rec / ids[1] / "case" / "notes.txt").exists()
        a = audits(db, "files.delete")
        assert [x["target"] for x in a] == [str(p), str(tf / "case")]
        assert a[0]["detail"] == {"id": ids[0], "size": len(data), "dir": False, "sha256": hashlib.sha256(data).hexdigest(),
                                  "sha256Source": "upload"}
        assert a[1]["detail"]["dir"] is True and a[1]["detail"]["size"] == 1
        # the teammate sees both in the recycle bin of the location and restores them
        items = ta.get("/api/files/recycle", params={"location": str(tf)}).json()["items"]
        assert sorted(x["id"] for x in items) == sorted(ids) and items[0]["deletedAt"] >= items[1]["deletedAt"]
        it = {x["id"]: x for x in items}
        assert it[ids[0]]["name"] == "e.bin" and it[ids[0]]["originalPath"] == str(p) and not it[ids[0]]["dir"]
        assert it[ids[0]]["deletedBy"] == "dee" and it[ids[0]]["size"] == len(data)
        assert it[ids[0]]["expiresAt"] == pytest.approx(it[ids[0]]["deletedAt"] + 30 * DAY)
        r = ta.post("/api/files/restore", json={"id": ids[1]}, headers=ha)
        assert r.status_code == 200 and r.json() == {"path": str(tf / "case")} and (tf / "case" / "notes.txt").exists()
        (tf / "case" / "e.bin").write_bytes(b"a new file with the name")
        r = ta.post("/api/files/restore", json={"id": ids[0]}, headers=ha)
        assert r.status_code == 200 and r.json() == {"path": str(tf / "case" / "e (restored).bin")}
        assert (tf / "case" / "e (restored).bin").read_bytes() == data
        assert (tf / "case" / "e.bin").read_bytes() == b"a new file with the name"
        assert not db.query("SELECT * FROM file_recycle") and sorted(os.listdir(rec)) == []
        a = audits(db, "files.restore")
        assert [x["username"] for x in a] == ["ann", "ann"] and a[1]["detail"]["originalPath"] == str(p)
        # the upload's record followed the file: still "uploaded by dee", with its SHA-256
        e = {x["name"]: x for x in ta.get("/api/files/list", params={"path": str(tf / "case")}).json()["entries"]}
        assert e["e (restored).bin"]["uploadedBy"] == "dee" and e["e (restored).bin"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert ta.post("/api/files/restore", json={"id": ids[0]}, headers=ha).status_code == 404
        assert ta.post("/api/files/restore", json={"id": "../../x"}, headers=ha).status_code == 404


def test_restore_refuses_a_recycle_folder_changed_by_something_else(env, tmp_path):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    (tf / "x.txt").write_text("X")
    out = tmp_path / "outside"
    out.mkdir()
    (out / "x.txt").write_text("OUT")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        rid = tc.post("/api/files/delete", json={"paths": [str(tf / "x.txt")]}, headers=h).json()["deleted"][0]["id"]
        slot = tf / files.RECYCLE_DIR / rid
        (slot / "x.txt").unlink()
        slot.rmdir()
        if WIN and _junction(slot, out):      # the agent swaps the item's folder for a link to elsewhere
            r = tc.post("/api/files/restore", json={"id": rid}, headers=h)
            assert r.status_code == 409 and r.json()["error"] == "denied"
            assert (out / "x.txt").read_text() == "OUT" and not (tf / "x.txt").exists()
            os.rmdir(slot)
        r = tc.post("/api/files/restore", json={"id": rid}, headers=h)
        assert r.status_code == 404


def test_purge_removes_old_recycled_items_for_good(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    for n in ("old.txt", "young.txt"):
        (tf / n).write_text(n)
    (tf / "olddir").mkdir()
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        upload(tc, h, tf / "olddir", "f.txt", b"f")
        tc.post("/api/files/hash", json={"path": str(tf / "old.txt")}, headers=h)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "old.txt"), str(tf / "young.txt"),
                                                         str(tf / "olddir")]}, headers=h).json()
    ids = {Path(x["path"]).name: x["id"] for x in j["deleted"]}
    assert db.one("SELECT state FROM uploads WHERE target='folder'")["state"] == "done"
    assert db.one("SELECT COUNT(*) AS n FROM file_hashes")["n"] == 1
    db.execute("UPDATE file_recycle SET deleted_at=? WHERE id IN (?,?)", (NOW - 31 * DAY, ids["old.txt"], ids["olddir"]))
    rec = tf / files.RECYCLE_DIR
    assert asyncio.run(files.purge_recycle(c)) == 2
    assert sorted(os.listdir(rec)) == [ids["young.txt"]]
    # the upload that was in the purged folder and the cached hash of the purged file end with them
    assert db.one("SELECT state FROM uploads WHERE target='folder'")["state"] == "deleted"
    assert db.one("SELECT COUNT(*) AS n FROM file_hashes")["n"] == 0
    assert [r["id"] for r in db.query("SELECT id FROM file_recycle")] == [ids["young.txt"]]
    a = audits(db, "files.purge")
    assert {x["target"] for x in a} == {str(tf / "old.txt"), str(tf / "olddir")}
    assert all(x["user_id"] is None and x["username"] == "" and x["detail"]["days"] == 30 for x in a)
    # a row whose item is already gone is dropped (noted); a longer files.recycle_days keeps items longer
    db.execute("UPDATE file_recycle SET deleted_at=? WHERE id=?", (NOW - 40 * DAY, ids["young.txt"]))
    s.data.setdefault("files", {})["recycle_days"] = 60
    assert asyncio.run(files.purge_recycle(c)) == 0 and (rec / ids["young.txt"]).exists()
    s.data["files"]["recycle_days"] = 30
    import shutil
    shutil.rmtree(rec / ids["young.txt"])
    assert asyncio.run(files.purge_recycle(c)) == 1 and audits(db, "files.purge")[-1]["detail"]["missing"] is True
    assert "files.purge_recycle(c)" in inspect.getsource(gw_app._maintenance_loop)


def test_an_administrators_delete_in_a_team_folder_lands_in_the_teams_recycle_folder(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    admin = user(db, "root", role="admin")
    (tf / "a.txt").write_text("A")
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "a.txt")]}, headers=h).json()
        rid = j["deleted"][0]["id"]
        assert (tf / files.RECYCLE_DIR / rid / "a.txt").exists()
        assert tc.post("/api/files/rename", json={"path": str(tf), "name": "x"}, headers=h).json()["error"] == "denied"
        # a person's workspace, the profile folder holding it and the profiles root stay; what is deleted in a
        # workspace goes to that workspace's recycle folder
        ws = pr.workspace(dee)
        (ws / "w.txt").write_text("W")
        j = tc.post("/api/files/delete", json={"paths": [str(ws), str(ws.parent), str(s.profiles_root),
                                                         str(ws / "w.txt")]}, headers=h).json()
        assert [x["error"] for x in j["failed"]] == ["denied"] * 3 and ws.is_dir()
        assert (ws / files.RECYCLE_DIR / j["deleted"][0]["id"] / "w.txt").exists()
        # nor a folder holding the system folder (the database, keys, logs)
        elsewhere = Path(s.profiles_root).parent / "elsewhere"
        elsewhere.mkdir()
        (Path(s.system_dir) / "x").mkdir(parents=True, exist_ok=True)
        j = tc.post("/api/files/move", json={"paths": [str(Path(s.system_dir).parent)], "to": str(elsewhere)},
                    headers=h).json()
        assert j["failed"][0]["error"] == "denied" and Path(s.system_dir).is_dir()
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert [x["id"] for x in tc.get("/api/files/recycle", params={"location": str(tf)}).json()["items"]] == [rid]
        assert tc.post("/api/files/restore", json={"id": rid}, headers=h).json() == {"path": str(tf / "a.txt")}


# ------------------------------------------------------------------ activity
def test_the_activity_of_a_folder_is_its_own(env, tmp_path):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    (tf / "A").mkdir()
    (tf / "AB").mkdir()          # a name that starts like A: not inside A
    (tf / "B").mkdir()
    with client_for(c) as td, client_for(c) as ta:
        hd, ha = sign_in(td, c, dee), sign_in(ta, c, ann)
        up = upload(td, hd, tf / "A", "x.log", b"x")
        ta.get("/api/files/download", params={"path": up["file"]["path"]})
        (tf / "AB" / "y.txt").write_text("y")
        ta.get("/api/files/download", params={"path": str(tf / "AB" / "y.txt")})
        td.post("/api/files/move", json={"paths": [up["file"]["path"]], "to": str(tf / "B")}, headers=hd)
        td.post("/api/files/mkdir", json={"path": str(tf / "B"), "name": "sub"}, headers=hd)

        def act(p, **kw):
            r = ta.get("/api/files/activity", params={"path": str(p), **kw})
            assert r.status_code == 200, r.text
            return [(x["username"], x["action"], Path(x["target"]).name) for x in r.json()["items"]]
        assert act(tf / "A") == [("dee", "files.move", "x.log"), ("ann", "files.download", "x.log"),
                                 ("dee", "files.upload", "x.log")]
        assert act(tf / "B") == [("dee", "files.mkdir", "sub"), ("dee", "files.move", "x.log")]
        assert act(tf / "AB") == [("ann", "files.download", "y.txt")]
        assert len(act(tf)) == 5 and len(act(tf, limit=2)) == 2
        items = ta.get("/api/files/activity", params={"path": str(tf / "A")}).json()["items"]
        assert items[0]["detail"] == {"from": str(tf / "A" / "x.log"), "to": str(tf / "B" / "x.log")}
        assert items[2]["detail"]["sha256"] == hashlib.sha256(b"x").hexdigest() and items[0]["ts"] > 0
        assert ta.get("/api/files/activity", params={"path": str(tf), "limit": "x"}).status_code == 400
        assert ta.get("/api/files/activity", params={"path": str(tmp_path)}).json()["error"] == "denied"


# ------------------------------------------------------------------ configuration and check
def test_recycle_days_setting_and_check_line(tmp_path):
    from goose_web.config import DEFAULTS
    assert DEFAULTS["files"]["recycle_days"] == 30

    class S:
        def __init__(self, v):
            self.v = v

        def get(self, section, key, default=None):
            assert (section, key) == ("files", "recycle_days")
            return self.v
    for v, want in ((None, 30), ("", 30), (30, 30), (0, 1), (-5, 1), (7.9, 7), ("90", 90), (366, 365),
                    (10 ** 9, 365), ("soon", 30), (float("nan"), 30), (float("inf"), 365)):
        assert files.recycle_days(S(v)) == want, v
    lines = files.check_lines(S(14))
    assert lines == [("--", lines[0][1])] and "14 days" in lines[0][1] and "files.recycle_days" in lines[0][1]
    assert files.check_lines(S(900))[1][0] == "!!" and "365 is used" in files.check_lines(S(900))[1][1]
    assert files.check_lines(S("x"))[1][0] == "!!"
    from goose_web import __main__ as cli
    assert "files.check_lines(settings)" in inspect.getsource(cli)


@pytest.mark.skipif(not WIN, reason="NTFS junctions")
def test_nothing_moves_when_the_target_folder_changed_meanwhile(env, monkeypatch, tmp_path):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    vic, wv = outsider(env)
    (tf / "a.txt").write_text("A")
    (tf / "b.txt").write_text("B")
    (tf / "to").mkdir()
    if not _junction(tmp_path / "probe", wv):
        pytest.skip("junctions cannot be made here")
    real_move, real_slot = files._move_item, files._recycle_slot

    def swapped(src, dst, *a, **k):     # between the check and the move the target folder becomes a junction
        if Path(dst).parent == tf / "to" and not (tf / "to-real").exists():
            os.rename(tf / "to", tf / "to-real")
            assert _junction(tf / "to", wv)
        return real_move(src, dst, *a, **k)

    def slot(loc, rid):                 # ... and the recycle slot, right after it was made
        out = real_slot(loc, rid)
        os.rename(out[0], str(out[0]) + "-real")
        assert _junction(out[0], wv)
        return out
    monkeypatch.setattr(files, "_move_item", swapped)
    monkeypatch.setattr(files, "_recycle_slot", slot)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/move", json={"paths": [str(tf / "a.txt")], "to": str(tf / "to")}, headers=h).json()
        assert j["moved"] == [] and j["failed"][0]["error"] == "denied"
        assert (tf / "a.txt").read_text() == "A" and not (wv / "a.txt").exists()
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "b.txt")]}, headers=h).json()
        assert j["deleted"] == [] and j["failed"][0]["error"] == "denied" and (tf / "b.txt").exists()
        assert not (wv / "b.txt").exists() and not db.query("SELECT * FROM file_recycle")
        # had it landed elsewhere all the same, it would be put back where it was taken from and refused
        monkeypatch.setattr(files, "_landed", lambda fd, dest: False)
        r = tc.post("/api/files/rename", json={"path": str(tf / "b.txt"), "name": "c.txt"}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "denied"
        assert (tf / "b.txt").read_text() == "B" and not (tf / "c.txt").exists()
    assert not audits(db, "files.move") and not audits(db, "files.rename") and not audits(db, "files.delete")


# ------------------------------------------------------------------ independent assessment 2026-11-25 (spec 041)
def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def outsider(env, name="vic"):
    """A member of another team, with a file in her workspace."""
    s, db, pr, c = env
    vt = team(db, "Other-" + name, {**ANYCHAT, **FILES_ON})
    v = user(db, name)
    db.set_user_team(v["id"], vt)
    v = db.user_by_id(v["id"])
    pr.ensure_layout(v)
    wv = pr.workspace(v)
    (wv / "secret.txt").write_text("VICTIM SECRET")
    (wv / "deep").mkdir()
    (wv / "deep" / "more.txt").write_text("M")
    return v, wv


def other_volume(monkeypatch):
    """Every first rename of an item fails as between two volumes; the copy's own rename into place works."""
    real = files._rename_noreplace

    def old(src, dst):
        if Path(src).name.startswith(files.MOVE_PREFIX):
            return real(src, dst)
        raise OSError(errno.EXDEV, "Invalid cross-device link")
    monkeypatch.setattr(files, "_rename_noreplace", old)

    def new(fd, dst):
        raise OSError(errno.EXDEV, "Invalid cross-device link")
    monkeypatch.setattr(files, "_rename_item", new, raising=False)


@pytest.mark.skipif(not WIN, reason="NTFS junctions")
def test_f1_a_move_to_another_volume_never_copies_through_a_link_inside(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    vic, wv = outsider(env)
    ws = pr.workspace(dee)
    (tf / "pack").mkdir()
    (tf / "pack" / "mine.txt").write_text("mine")
    (tf / "pack" / "sub").mkdir()
    if not _junction(tf / "pack" / "sub" / "j", wv):
        pytest.skip("junctions cannot be made here")
    other_volume(monkeypatch)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert tc.get("/api/files/list", params={"path": str(tf / "pack" / "sub" / "j")}).status_code == 403
        j = tc.post("/api/files/move", json={"paths": [str(tf / "pack")], "to": str(ws)}, headers=h).json()
        assert j["moved"] == [] and j["failed"][0]["error"] == "has_link", j
        assert "link" in j["failed"][0]["message"]
    # nothing copied, nothing deleted, the other person's files untouched
    assert not (ws / "pack").exists() and not list(ws.glob(files.MOVE_PREFIX + "*"))
    assert (tf / "pack" / "mine.txt").read_text() == "mine" and os.path.isdir(tf / "pack" / "sub" / "j")
    assert (wv / "secret.txt").read_text() == "VICTIM SECRET" and (wv / "deep" / "more.txt").exists()
    assert not audits(db, "files.move")


@pytest.mark.skipif(not WIN, reason="NTFS junctions")
def test_f2_a_source_folder_swapped_for_a_link_moves_nobody_elses_files(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    vic, wv = outsider(env)
    (tf / "a").mkdir()
    (tf / "a" / "secret.txt").write_text("decoy")
    (tf / "loot").mkdir()
    if not _junction(tf / "probe", wv):
        pytest.skip("junctions cannot be made here")
    os.rmdir(tf / "probe")
    real_move = files._move_item

    def swapped(*a, **k):      # between the check and the move: tf\a becomes a junction to vic's workspace
        if not (tf / "a-real").exists():
            os.rename(tf / "a", tf / "a-real")
            assert _junction(tf / "a", wv)
        return real_move(*a, **k)

    def reset():
        if (tf / "a-real").exists():
            os.rmdir(tf / "a")
            os.rename(tf / "a-real", tf / "a")
    monkeypatch.setattr(files, "_move_item", swapped)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "a" / "secret.txt")]}, headers=h).json()
        assert j["deleted"] == [] and j["failed"][0]["error"] == "denied", j
        assert (wv / "secret.txt").read_text() == "VICTIM SECRET"
        reset()
        j = tc.post("/api/files/move", json={"paths": [str(tf / "a" / "secret.txt")], "to": str(tf / "loot")},
                    headers=h).json()
        assert j["moved"] == [] and j["failed"][0]["error"] == "denied", j
        assert (wv / "secret.txt").read_text() == "VICTIM SECRET" and not (tf / "loot" / "secret.txt").exists()
        reset()
        r = tc.post("/api/files/rename", json={"path": str(tf / "a" / "secret.txt"), "name": "mine.txt"}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "denied"
        assert (wv / "secret.txt").read_text() == "VICTIM SECRET" and not (wv / "mine.txt").exists()
        reset()
    assert (tf / "a" / "secret.txt").read_text() == "decoy"
    assert not db.query("SELECT * FROM file_recycle")
    assert not audits(db, "files.delete") and not audits(db, "files.move") and not audits(db, "files.rename")


def test_f3_a_member_cannot_remove_another_teams_location_inside_their_own(env, tmp_path):
    s, db, pr, c = env
    cases = tmp_path / "Cases"
    nested = cases / "sub" / "2026-1124"
    nested.mkdir(parents=True)
    (nested / "n.txt").write_text("N")
    soc = team(db, "SOC", {**ANYCHAT, **FILES_ON, "allowed_roots": [str(cases)]})
    team(db, "IR-Ext", {**ANYCHAT, **FILES_ON, "allowed_roots": [str(nested)]})
    sam = user(db, "sam")
    db.set_user_team(sam["id"], soc)
    sam = db.user_by_id(sam["id"])
    pr.ensure_layout(sam)
    ws = pr.workspace(sam)
    with client_for(c) as tc:
        h = sign_in(tc, c, sam)
        r = tc.post("/api/files/rename", json={"path": str(nested), "name": "renamed"}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "denied", r.text
        for p in (nested, cases / "sub"):        # the other team's top, and a folder holding it
            j = tc.post("/api/files/delete", json={"paths": [str(p)]}, headers=h).json()
            assert j["failed"] and j["failed"][0]["error"] == "denied", (p, j)
            j = tc.post("/api/files/move", json={"paths": [str(p)], "to": str(ws)}, headers=h).json()
            assert j["failed"] and j["failed"][0]["error"] == "denied", (p, j)
        r = tc.post("/api/files/rename", json={"path": str(cases / "sub"), "name": "other"}, headers=h)
        assert r.status_code == 403
        # what lies inside it is handled as before by whoever may write there
        j = tc.post("/api/files/delete", json={"paths": [str(nested / "n.txt")]}, headers=h).json()
        assert j["deleted"] and not (nested / "n.txt").exists()
    assert nested.is_dir() and (cases / "sub").is_dir() and not audits(db, "files.rename")


def test_f4_goose_and_claude_project_folders_and_gooseignore_are_refused_for_members(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    admin = user(db, "root", role="admin")
    (tf / ".goose").mkdir()
    (tf / ".goose" / "memory").mkdir()       # e.g. Goose's own, or an administrator's
    (tf / "x.txt").write_text("x")
    (tf / "sub").mkdir()
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for name in (".goose", ".claude", ".Claude. ", ".GOOSE"):
            r = tc.post("/api/files/mkdir", json={"path": str(tf), "name": name}, headers=h)
            assert r.json().get("error") == "agents_folder_refused", (name, r.text)
        r = tc.post("/api/files/mkdir", json={"path": str(tf / ".goose"), "name": "skills"}, headers=h)
        assert r.json()["error"] == "agents_folder_refused"
        r = tc.post("/api/fs/mkdir", json={"path": str(tf / ".claude" / "skills")}, headers=h)
        assert r.json()["error"] == "agents_folder_refused"
        for d, name in ((tf / ".goose", "helper.yaml"), (tf / ".goose" / "memory", "SKILL.md"), (tf, ".gooseignore"),
                        (tf, ".GooseIgnore.")):
            r = tc.post("/api/fs/uploads", json={"dir": str(d), "name": name, "size": 1, "target": "folder"},
                        headers=h)
            assert r.status_code == 403 and r.json()["error"] in ("agents_folder_refused", "hint_file_refused"), \
                (d, name, r.text)
        # chat attachments (Web_Uploads of a chat folder) and the multipart upload get the same rule
        r = tc.post("/api/fs/uploads", json={"dir": str(tf / ".goose"), "name": "a.txt", "size": 1}, headers=h)
        assert r.json()["error"] == "agents_folder_refused"
        r = tc.post("/api/fs/upload", params={"dir": str(tf / ".claude")}, files={"f": ("a.txt", b"x")}, headers=h)
        assert r.json()["error"] == "agents_folder_refused"
        r = tc.post("/api/fs/upload", params={"dir": str(tf)}, files={"f": (".gooseignore", b"x")}, headers=h)
        assert r.json()["error"] == "hint_file_refused"
        assert tc.post("/api/files/rename", json={"path": str(tf / "x.txt"), "name": ".gooseignore"},
                       headers=h).json()["error"] == "hint_file_refused"
        assert tc.post("/api/files/rename", json={"path": str(tf / "sub"), "name": ".claude"},
                       headers=h).json()["error"] == "agents_folder_refused"
        assert tc.post("/api/files/move", json={"paths": [str(tf / "x.txt")], "to": str(tf / ".goose")},
                       headers=h).json()["error"] == "agents_folder_refused"
        assert tc.post("/api/files/rename", json={"path": str(tf / ".goose"), "name": "g"},
                       headers=h).json()["error"] == "agents_folder_refused"
        j = tc.post("/api/files/delete", json={"paths": [str(tf / ".goose")]}, headers=h).json()
        assert j["failed"][0]["error"] == "agents_folder_refused"
    assert sorted(os.listdir(tf)) == [".goose", "sub", "x.txt"] and os.listdir(tf / ".goose") == ["memory"]
    with client_for(c) as tc:      # an administrator may
        h = sign_in(tc, c, admin)
        assert tc.post("/api/files/mkdir", json={"path": str(tf), "name": ".claude"}, headers=h).status_code == 200


def test_f5a_a_folder_upload_changed_on_the_server_while_it_arrived_is_not_kept(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    data = os.urandom(30_000)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        k = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "ev.bin", "size": len(data), "target": "folder"},
                    headers=h).json()
        assert put(tc, h, k["id"], 0, data[:10_000]).status_code == 200
        part = next(tf.glob(uploads.PARTIAL_PREFIX + "*"))
        with open(part, "r+b") as f:        # a teammate's agent writes into the hidden partial file
            f.write(b"EVILAA")
        assert put(tc, h, k["id"], 10_000, data[10_000:20_000]).status_code == 200
        r = put(tc, h, k["id"], 20_000, data[20_000:])
    assert r.status_code == 409 and r.json()["error"] == "upload_changed", r.text
    assert not (tf / "ev.bin").exists() and not list(tf.glob(uploads.PARTIAL_PREFIX + "*"))
    row = db.one("SELECT state, sha256 FROM uploads WHERE id=?", (uploads._key(k["id"]),))
    assert row["state"] == "aborted" and row["sha256"] == ""
    a = audits(db, "files.upload")
    assert len(a) == 1 and a[0]["ok"] == 0
    assert a[0]["detail"]["sha256Received"] == sha(data) and a[0]["detail"]["sha256OnDisk"] == sha(b"EVILAA" + data[6:])


def test_f5b_a_stored_sha256_is_shown_only_for_the_unchanged_file_and_says_where_it_comes_from(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    data = b"evidence " * 1000
    with client_for(c) as td, client_for(c) as ta:
        hd = sign_in(td, c, dee)
        ha = sign_in(ta, c, ann)
        p = Path(upload(td, hd, tf, "e.bin", data)["file"]["path"])
        i = ta.get("/api/files/info", params={"path": str(p)}).json()
        assert i["sha256"] == sha(data) and i["sha256Source"] == "upload" and i["recordedAt"] == i["uploadedAt"]
        e = {x["name"]: x for x in ta.get("/api/files/list", params={"path": str(tf)}).json()["entries"]}["e.bin"]
        assert e["sha256"] == sha(data) and e["sha256Source"] == "upload" and "mtime_ns" not in e
        j = ta.post("/api/files/hash", json={"path": str(p)}, headers=ha).json()
        assert j["sha256"] == sha(data) and j["cached"] is True and j["sha256Source"] == "upload"
        # changed in place, same size, its modification time set back near the upload's: not shown any more
        st = os.stat(p)
        with open(p, "r+b") as f:
            f.write(b"EVIDENCE")
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 500_000_000))
        i = ta.get("/api/files/info", params={"path": str(p)}).json()
        assert "sha256" not in i and "sha256Source" not in i and i["uploadedBy"] == "dee"
        j = ta.post("/api/files/hash", json={"path": str(p)}, headers=ha).json()
        assert j["sha256"] == sha(b"EVIDENCE" + data[8:]) and j["cached"] is False and j["sha256Source"] == "computed"
        assert abs(j["recordedAt"] - __import__("time").time()) < 60
        i = ta.get("/api/files/info", params={"path": str(p)}).json()
        assert i["sha256"] == j["sha256"] and i["sha256Source"] == "computed" and i["recordedAt"] == j["recordedAt"]


def test_f5c_a_download_is_audited_with_the_sha256_of_the_bytes_sent(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    f = tf / "x.bin"
    f.write_bytes(b"A" * 5000)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()["sha256"] == sha(b"A" * 5000)
        st = os.stat(f)
        with open(f, "r+b") as fh:       # changed in place; size and modification time as they were
            fh.write(b"B" * 10)
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        r = tc.get("/api/files/download", params={"path": str(f)})
        assert r.status_code == 200 and r.content == b"B" * 10 + b"A" * 4990
        assert tc.head("/api/files/download", params={"path": str(f)}).status_code == 200
        r2 = tc.get("/api/files/download", params={"path": str(f)}, headers={"Range": "bytes=0-9"})
        assert r2.status_code == 206 and r2.content == b"B" * 10
    rows = audits(db, "files.download")
    assert len(rows) == 2, [x["detail"] for x in rows]          # HEAD sends nothing and records nothing
    assert rows[0]["detail"] == {"size": 5000, "sha256": sha(r.content)}
    assert "sha256" not in rows[1]["detail"] and rows[1]["detail"]["range"] == "bytes=0-9"
    assert rows[1]["detail"]["sha256Omitted"]


def test_f6_a_switch_override_must_be_a_real_boolean(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    set_policy(db, tid, files=False, files_manage=False)
    admin = user(db, "root", role="admin")
    with client_for(c) as tc:
        h = sign_in(tc, c, admin)
        for bad in ("false", "off", "0", 0, 1, None):
            r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"files": bad}}, headers=h)
            assert r.status_code == 400 and r.json()["error"] == "bad_request", (bad, r.text)
        assert db.user_by_id(dee["id"])["policy_overrides"] in (None, {})
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"files": False}}, headers=h)
        assert r.status_code == 200
    db.update_user(dee["id"], policy_overrides={"files": "false", "files_manage": "on", "schedules": 1})
    eff = c.policy_for(db.user_by_id(dee["id"]))
    assert eff["files"] is False and eff["files_manage"] is False and eff["schedules"] is False
    with client_for(c) as td:
        sign_in(td, c, dee)
        assert td.get("/api/files/locations").status_code == 403
    db.update_user(dee["id"], policy_overrides={"files": True, "files_manage": True})
    eff = c.policy_for(db.user_by_id(dee["id"]))
    assert eff["files"] is True and eff["files_manage"] is True


def test_f9_switching_files_off_stops_a_folder_upload_between_pieces_and_at_the_finish(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        k = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "c.bin", "size": 6, "target": "folder"},
                    headers=h).json()
        assert put(tc, h, k["id"], 0, b"abc").status_code == 200
        set_policy(db, tid, files=False)
        r = put(tc, h, k["id"], 3, b"def")
        assert r.status_code == 403 and r.json()["error"] == "files_off" and not (tf / "c.bin").exists()
        set_policy(db, tid, files=True)          # switched on again: the upload goes on where it was
        r = put(tc, h, k["id"], 3, b"def")
        assert r.status_code == 200 and r.json()["done"] and (tf / "c.bin").read_bytes() == b"abcdef"
        # switched off while the last piece arrives: the file is not placed
        real = uploads._receive

        async def then_off(*a, **kw):
            n = await real(*a, **kw)
            set_policy(db, tid, files=False)
            return n
        monkeypatch.setattr(uploads, "_receive", then_off)
        set_policy(db, tid, files=True)
        k = tc.post("/api/fs/uploads", json={"dir": str(tf), "name": "d.bin", "size": 2, "target": "folder"},
                    headers=h).json()
        r = put(tc, h, k["id"], 0, b"xy")
        assert r.status_code == 403 and r.json()["error"] == "files_off" and not (tf / "d.bin").exists()


@pytest.mark.skipif(not WIN, reason="a file kept open without sharing delete")
def test_f10_a_move_to_another_volume_that_cannot_delete_all_of_the_original_says_so(env, monkeypatch):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    ws = pr.workspace(dee)
    (ws / "logs").mkdir()
    for n in "abc":
        (ws / "logs" / f"{n}.log").write_text(n)
    other_volume(monkeypatch)
    with client_for(c) as tc, open(ws / "logs" / "a.log", "rb"):    # in use: opened without sharing delete
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/move", json={"paths": [str(ws / "logs")], "to": str(tf)}, headers=h).json()
    assert j["failed"] == [] and j["moved"][0]["to"] == str(tf / "logs"), j
    assert "could not be deleted" in j["moved"][0]["warning"]
    assert sorted(os.listdir(tf / "logs")) == ["a.log", "b.log", "c.log"] and os.listdir(ws / "logs") == ["a.log"]
    a = audits(db, "files.move")
    assert len(a) == 1 and [p.lower()[-5:] for p in a[0]["detail"]["sourceLeft"]] == ["a.log"]


def test_f11_something_squatting_the_recycle_name_does_not_block_deletes(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    (tf / files.RECYCLE_DIR).write_text("squat")       # any teammate's agent can make this
    (tf / "x.txt").write_text("x")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "x.txt")]}, headers=h).json()
    assert j["failed"] == [] and len(j["deleted"]) == 1, j
    assert (tf / files.RECYCLE_DIR / j["deleted"][0]["id"] / "x.txt").read_text() == "x"
    aside = list(tf.glob(files.RECYCLE_DIR + ".conflict-*"))
    assert len(aside) == 1 and aside[0].read_text() == "squat"
    a = audits(db, "files.recycle_conflict")
    assert len(a) == 1 and a[0]["username"] == "dee" and a[0]["detail"] == {"movedTo": str(aside[0])}


def test_f15_format_characters_are_dropped_from_new_names(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    from goose_web import api
    assert api.safe_upload_name("invoice\u202efdp.exe") == "invoicefdp.exe"
    assert api.safe_upload_name("a\u200bb\u200d\ufeff.txt") == "ab.txt"
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/files/mkdir", json={"path": str(tf), "name": "case\u202e\u200b 1"}, headers=h)
        assert r.status_code == 200 and r.json()["path"] == str(tf / "case 1")
        j = upload(tc, h, tf, "invoice\u202efdp.exe", b"MZ")
        assert j["file"]["name"] == "invoicefdp.exe"
        r = tc.post("/api/files/rename", json={"path": str(tf / "invoicefdp.exe"), "name": "\u202e\u200b"}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "bad_name"


def test_f16_refused_attempts_are_audited_once_a_minute_per_path(env):
    s, db, pr, c = env
    dee, ann, tid, tf = crew(env)
    wa = pr.workspace(ann)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for _ in range(3):
            assert tc.get("/api/files/list", params={"path": str(wa)}).status_code == 403
        assert tc.get("/api/files/download", params={"path": str(wa / "x")}).status_code == 403
        j = tc.post("/api/files/delete", json={"paths": [str(wa / "y")]}, headers=h).json()
        assert j["failed"][0]["error"] == "denied"
        assert tc.post("/api/files/rename", json={"path": str(wa / "z"), "name": "q"}, headers=h).status_code == 403
        set_policy(db, tid, files=False)
        assert tc.get("/api/files/locations").status_code == 403
        assert tc.get("/api/files/list", params={"path": str(tf)}).status_code == 403
        set_policy(db, tid, files=True)
        assert tc.get("/api/files/list", params={"path": str(tf)}).status_code == 200      # nothing for an answer
        assert tc.get("/api/files/list", params={"path": str(tf / "nope")}).status_code == 404   # ... nor a 404
    rows = db.query("SELECT * FROM audit WHERE action='files.refused' ORDER BY id")
    assert [(r["target"], r["detail"]["route"], r["detail"]["error"], r["ok"], r["username"]) for r in rows] == [
        (str(wa), "/api/files/list", "denied", 0, "dee"),
        (str(wa / "x"), "/api/files/download", "denied", 0, "dee"),
        (str(wa / "y"), "/api/files/delete", "denied", 0, "dee"),
        (str(wa / "z"), "/api/files/rename", "denied", 0, "dee"),
        ("", "/api/files/locations", "files_off", 0, "dee"),
        (str(tf), "/api/files/list", "files_off", 0, "dee")]
    with client_for(c) as tc:        # the folder's activity is what happened, not what was refused
        sign_in(tc, c, ann)
        assert tc.get("/api/files/activity", params={"path": str(wa)}).json()["items"] == []


def _short(p: Path) -> str:
    import ctypes
    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(p), buf, 1024)
    leaf = os.path.basename(buf.value) if n else ""
    return str(p.parent / leaf) if leaf and leaf.lower() != p.name.lower() else ""    # the 8.3 leaf only


def test_f7_hints_files_by_short_name_and_folders_holding_them_are_the_administrators(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    admin = user(db, "root", role="admin")
    (tf / ".goosehints").write_text("ADMIN HINTS")
    (tf / "pack").mkdir()
    (tf / "pack" / "deep").mkdir()
    (tf / "pack" / "deep" / "AGENTS.md").write_text("rules")
    (tf / "plug").mkdir()
    (tf / "plug" / ".agents").mkdir()
    (tf / "plain").mkdir()
    (tf / "plain" / "notes.txt").write_text("n")
    (tf / "to").mkdir()
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        short = _short(tf / ".goosehints") if WIN else ""
        if short:       # 8.3 names are on for this volume: the alias is refused like the name
            r = tc.post("/api/files/rename", json={"path": short, "name": "gone.txt"}, headers=h)
            assert r.status_code == 403 and r.json()["error"] == "hint_file_refused", r.text
            j = tc.post("/api/files/delete", json={"paths": [short]}, headers=h).json()
            assert j["failed"][0]["error"] == "hint_file_refused"
            j = tc.post("/api/files/move", json={"paths": [short], "to": str(tf / "to")}, headers=h).json()
            assert j["failed"][0]["error"] == "hint_file_refused"
        r = tc.post("/api/files/rename", json={"path": str(tf / "pack"), "name": "other"}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "hint_file_refused"
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "pack"), str(tf / "plug"), str(tf / "plain")]},
                    headers=h).json()
        assert [x["error"] for x in j["failed"]] == ["hint_file_refused", "agents_folder_refused"]
        assert [x["path"] for x in j["deleted"]] == [str(tf / "plain")]
        j = tc.post("/api/files/move", json={"paths": [str(tf / "pack")], "to": str(tf / "to")}, headers=h).json()
        assert j["failed"][0]["error"] == "hint_file_refused"
    assert (tf / ".goosehints").read_text() == "ADMIN HINTS" and (tf / "pack" / "deep" / "AGENTS.md").exists()
    assert (tf / "plug" / ".agents").is_dir()
    with client_for(c) as tc:      # the administrator may
        h = sign_in(tc, c, admin)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "pack")]}, headers=h).json()
        assert j["deleted"] and not (tf / "pack").exists()
