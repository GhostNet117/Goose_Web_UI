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
import time
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


def test_sha256_is_computed_on_request_and_cached(env):
    s, db, pr, c = env
    dee, tid, tf = crew(env, names=("dee",))
    f = tf / "big.bin"
    data = os.urandom(3 * 1024 * 1024 + 7)
    f.write_bytes(data)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/files/hash", json={"path": str(f)}, headers=h)
        assert r.status_code == 200 and r.json() == {"sha256": hashlib.sha256(data).hexdigest(), "cached": False}
        row = db.one("SELECT * FROM file_hashes")
        assert row["path"] == os.path.normcase(str(f)) and row["size"] == len(data)
        assert tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()["cached"] is True
        listing = tc.get("/api/files/list", params={"path": str(tf)}).json()
        assert listing["entries"][0]["sha256"] == hashlib.sha256(data).hexdigest()
        assert tc.get("/api/files/info", params={"path": str(f)}).json()["sha256"] == hashlib.sha256(data).hexdigest()
        f.write_bytes(b"changed")
        os.utime(f, (NOW + 100, NOW + 100))
        assert "sha256" not in tc.get("/api/files/info", params={"path": str(f)}).json()
        j = tc.post("/api/files/hash", json={"path": str(f)}, headers=h).json()
        assert j == {"sha256": hashlib.sha256(b"changed").hexdigest(), "cached": False}
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
        real = files._rename_noreplace

        def other_volume(src, dst):
            if Path(src).name.startswith(files.MOVE_PREFIX):
                return real(src, dst)
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        monkeypatch.setattr(files, "_rename_noreplace", other_volume)
        j = tc.post("/api/files/move", json={"paths": [str(ws / "case")], "to": str(tf)}, headers=h).json()
        assert j == {"moved": [{"from": str(ws / "case"), "to": str(tf / "case")}], "failed": []}
        assert (tf / "case" / "log.txt").read_text() == "L" and (tf / "case" / "inner").is_dir()
        assert not (ws / "case").exists() and not list(tf.glob(files.MOVE_PREFIX + "*"))


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
        assert a[0]["detail"] == {"id": ids[0], "size": len(data), "dir": False, "sha256": hashlib.sha256(data).hexdigest()}
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
    (tf / "olddir" / "f.txt").write_text("f")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        j = tc.post("/api/files/delete", json={"paths": [str(tf / "old.txt"), str(tf / "young.txt"),
                                                         str(tf / "olddir")]}, headers=h).json()
    ids = {Path(x["path"]).name: x["id"] for x in j["deleted"]}
    db.execute("UPDATE file_recycle SET deleted_at=? WHERE id IN (?,?)", (NOW - 31 * DAY, ids["old.txt"], ids["olddir"]))
    rec = tf / files.RECYCLE_DIR
    assert asyncio.run(files.purge_recycle(c)) == 2
    assert sorted(os.listdir(rec)) == [ids["young.txt"]]
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
