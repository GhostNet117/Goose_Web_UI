"""Spec 031 (1.25.0): folders a team may only read (policy `read_roots`), and uploads into <chat folder>\\Web_Uploads.

A member - the person in the file browser, an upload, and the member's agent in its sandbox - can list, open and
download what is in a read-only folder and chat there; nothing is created or changed in it. Files attached in
the browser are written to `Web_Uploads` inside the chat folder; the server names that folder and refuses when
the person may not write there."""
import asyncio
import json
import os
import subprocess
import sys
import uuid

import pytest

from goose_web import api
from goose_web import policy as pol
from goose_web import sandbox as sb
from goose_web.context import HTTPError
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)


def _junction(link, target) -> bool:
    r = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    return r.returncode == 0


# ------------------------------------------------------------------ the rules
def test_roots_writable_first_then_read_only():
    p = {"team_folder": "T", "allowed_roots": ["X", "*"], "read_roots": ["K", "*", "K"]}
    assert pol.user_write_roots(p, "W") == ["W", "T", "X"]
    assert pol.user_read_roots(p, "W") == ["K"]                 # "*" is never a folder; once
    assert pol.user_roots(p, "W") == ["W", "T", "X", "K"]       # the workspace stays first (plugin and skill rules)
    assert pol.user_roots({}, "W") == ["W"]
    assert pol.user_write_roots({"allowed_roots": ["X"]}, "W") == ["W", "X"] and pol.user_read_roots({"allowed_roots": ["X"]}, "W") == []


def test_read_only_wins_where_the_lists_meet(tmp_path):
    """Review 20261119_5, R-3: the two lists can come from different places (a person's overrides and their team),
    which no check at saving time sees. A folder that is, or contains, a read-only folder is then only read."""
    rw, ws = tmp_path / "rw", tmp_path / "ws"
    (rw / "kb").mkdir(parents=True)
    ws.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    W = str(ws)
    # the same folder in both lists (override read-only, team writable): read-only
    p = {"allowed_roots": [str(rw), str(other)], "read_roots": [str(rw).upper() + "\\"]}
    assert pol.user_write_roots(p, W) == [W, str(other)]
    assert [x.lower().rstrip("\\") for x in pol.user_read_roots(p, W)] == [str(rw).lower()]
    # a read-only folder inside a writable one: the outer folder is only read, too
    p = {"allowed_roots": [str(rw), str(other)], "read_roots": [str(rw / "kb")]}
    assert pol.user_write_roots(p, W) == [W, str(other)]
    assert pol.user_read_roots(p, W) == [str(rw), str(rw / "kb")]
    # ... also the team folder; the member's own workspace is always writable
    p = {"team_folder": str(rw), "read_roots": [str(rw / "kb")]}
    assert pol.user_write_roots(p, W) == [W] and pol.user_read_roots(p, W) == [str(rw), str(rw / "kb")]
    # a writable folder inside a read-only one keeps its write access (grants only add)
    p = {"allowed_roots": [str(rw / "kb")], "read_roots": [str(rw)]}
    assert pol.user_write_roots(p, W) == [W, str(rw / "kb")] and pol.user_read_roots(p, W) == [str(rw)]
    # through effective_policy: an override of one person against the team's list
    team = [{"id": 1, "name": "t", "policy": {**ANYCHAT, "allowed_roots": [str(rw)]}}]
    e = pol.effective_policy({"role": "user", "policy_overrides": {"read_roots": [str(rw / "kb")]}}, team)
    assert pol.user_write_roots(e, W) == [W] and str(rw) in pol.user_read_roots(e, W)
    assert not pol.path_allowed(str(rw / "kb" / "x.txt"), pol.user_write_roots(e, W))
    assert pol.path_allowed(str(rw / "kb" / "x.txt"), pol.user_roots(e, W))
    assert "read_roots" in pol.LIST_KEYS and pol.DEFAULT_POLICY["read_roots"] == [] and pol.ADMIN_POLICY["read_roots"] == []
    e = pol.effective_policy({"role": "user"}, [{"id": 1, "name": "t", "policy": {"read_roots": ["D:\\kb"]}}])
    assert e["read_roots"] == ["D:\\kb"] and e["allowed_roots"] == []


def test_cleaning_a_team_policy(tmp_path):
    c = api._clean_policy_fields
    kb, rw = str(tmp_path / "kb"), str(tmp_path / "rw")
    assert c({"read_roots": f"{kb}\n{kb}"})["read_roots"] == [kb]
    for bad in (["relative\\kb"], ["*"]):
        with pytest.raises(HTTPError) as e:
            c({"read_roots": bad})
        assert e.value.status == 400 and e.value.code == "bad_folder"
    # the same folder in both lists is read-only, however it is written
    out = c({"allowed_roots": [rw, kb.upper() + "\\"], "read_roots": [kb]})
    assert out["read_roots"] == [kb] and out["allowed_roots"] == [rw]


def test_a_read_only_folder_cannot_lie_inside_a_writable_one(tmp_path):
    where = dict(profiles_root=str(tmp_path / "profiles"), system_dir=str(tmp_path / "profiles" / "_system"),
                 native_roots=[], users_root=str(tmp_path / "Users"), own_home=str(tmp_path / "Users" / "me"))
    rw, kb = tmp_path / "shared", tmp_path / "kb"
    (rw / "kb").mkdir(parents=True)
    kb.mkdir()
    pol.check_team_folders({"allowed_roots": [str(rw)], "read_roots": [str(kb)]}, **where)              # side by side
    pol.check_team_folders({"allowed_roots": [str(kb / "notes")], "read_roots": [str(kb)]}, **where)    # writable inside read-only
    for policy, extra in (({"allowed_roots": [str(rw)], "read_roots": [str(rw / "kb")]}, {}),
                          ({"allowed_roots": [str(rw)], "read_roots": [str(rw).upper()]}, {}),
                          ({"share_folder": str(rw), "read_roots": [str(rw / "kb")]}, {}),
                          ({"read_roots": [str(rw / "kb")]}, {"own_team_folder": str(rw)})):
        with pytest.raises(ValueError, match="read-only folder cannot be, or lie inside"):
            pol.check_team_folders(policy, **where, **extra)
    # a read-only folder is held to the dangerous-folder rules too (C-11)
    with pytest.raises(ValueError, match="profiles root"):
        pol.check_team_folders({"read_roots": [str(tmp_path / "profiles")]}, **where)
    if sys.platform == "win32" and _junction(tmp_path / "alias", rw / "kb"):
        with pytest.raises(ValueError, match="read-only folder cannot be, or lie inside"):     # through a link
            pol.check_team_folders({"allowed_roots": [str(rw)], "read_roots": [str(tmp_path / "alias")]}, **where)


def test_the_team_page_warns_without_a_sandbox():
    base = {**ANYCHAT, "default_provider": "p", "default_model": "m"}
    kw = dict(hints=1, members=1)
    text = "Read-only folders are set, but the sandbox is off"
    assert any(text in w["text"] for w in pol.team_warnings({**base, "read_roots": ["D:\\kb"]}, sandbox=False, **kw))
    for policy, sandbox in (({**base, "read_roots": ["D:\\kb"]}, True), ({**base, "read_roots": ["D:\\kb"]}, None),
                            (base, False)):
        assert not any(text in w["text"] for w in pol.team_warnings(policy, sandbox=sandbox, **kw))


# ------------------------------------------------------------------ the file API and uploads
def test_file_api_reads_but_does_not_write_and_uploads_go_to_web_uploads(env, tmp_path):
    s, db, pr, c = env
    rw, kb, out = tmp_path / "rw", tmp_path / "kb", tmp_path / "outside"
    for d in (rw, kb, out):
        d.mkdir()
    (kb / "facts.md").write_text("FACTS", encoding="utf-8")
    tid = team(db, "A", {**ANYCHAT, "allowed_roots": [str(rw)], "read_roots": [str(kb)]})
    dee = user(db, "dee")
    db.set_user_team(dee["id"], tid)
    dee = db.user_by_id(dee["id"])
    pr.ensure_layout(dee)
    ws = pr.workspace(dee)
    fp_before = c.rights_fingerprint(dee)
    assert c.write_roots_for(dee)[0] == str(ws) and str(rw) in c.write_roots_for(dee) and str(kb) not in c.write_roots_for(dee)
    assert c.read_roots_for(dee) == [str(kb)] and c.roots_for(dee)[-1] == str(kb)
    assert c.path_ok(dee, str(kb / "facts.md")) and not c.path_ok(dee, str(kb / "facts.md"), write=True)
    assert c.path_ok(dee, str(rw / "x"), write=True) and not c.path_ok(dee, str(out))
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        roots = {r["path"]: r["access"] for r in tc.get("/api/fs/roots").json()["roots"]}
        assert roots[str(ws)] == "write" and roots[str(rw)] == "write" and roots[str(kb)] == "read"
        # read: allowed
        r = tc.get("/api/fs/list", params={"path": str(kb)})
        assert r.status_code == 200 and r.json()["access"] == "read" and [e["name"] for e in r.json()["entries"]] == ["facts.md"]
        assert tc.get("/api/fs/list", params={"path": str(ws)}).json()["access"] == "write"
        assert tc.get("/api/fs/read", params={"path": str(kb / "facts.md")}).status_code == 200
        assert tc.get("/api/fs/download", params={"path": str(kb / "facts.md")}).content == b"FACTS"
        # write: refused, nothing made
        r = tc.post("/api/fs/mkdir", json={"path": str(kb / "new")}, headers=h)
        assert r.status_code == 403 and r.json()["error"] == "read_only_folder" and not (kb / "new").exists()
        r = tc.post("/api/fs/upload", params={"dir": str(kb)}, headers=h, files=[("f", ("a.txt", b"a"))])
        assert r.status_code == 403 and r.json()["error"] == "read_only_folder"
        assert r.json()["message"] == api.READ_ONLY_MESSAGE == \
            "You do not have write access to this folder, so files cannot be uploaded here."
        assert sorted(p.name for p in kb.iterdir()) == ["facts.md"]
        # uploads: the server puts them in <dir>\Web_Uploads
        r = tc.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("notes.md", b"N"))])
        assert r.status_code == 200, r.text
        got = r.json()["files"][0]
        assert got["path"] == str(ws / "Web_Uploads" / "notes.md") and (ws / "Web_Uploads" / "notes.md").read_bytes() == b"N"
        assert not (ws / "notes.md").exists()
        r = tc.post("/api/fs/upload", params={"dir": str(rw / "proj")}, headers=h, files=[("f", ("b.txt", b"B"))])
        assert r.status_code == 200 and (rw / "proj" / "Web_Uploads" / "b.txt").read_bytes() == b"B"
        # a second file of the same name does not overwrite
        r = tc.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("notes.md", b"N2"))])
        assert r.json()["files"][0]["path"] == str(ws / "Web_Uploads" / "notes (1).md")
        # outside every folder
        r = tc.post("/api/fs/upload", params={"dir": str(out)}, headers=h, files=[("f", ("c.txt", b"c"))])
        assert r.status_code == 403 and r.json()["error"] == "path_forbidden" and not any(out.iterdir())
        # Web_Uploads that is a file
        (rw / "odd").mkdir()
        (rw / "odd" / "Web_Uploads").write_text("not a folder", encoding="utf-8")
        r = tc.post("/api/fs/upload", params={"dir": str(rw / "odd")}, headers=h, files=[("f", ("d.txt", b"d"))])
        assert r.status_code == 409 and (rw / "odd" / "Web_Uploads").read_text(encoding="utf-8") == "not a folder"
        # a link called Web_Uploads must not lead out of the writable folders (the gateway is not sandboxed)
        if sys.platform == "win32":
            for name, target, code in (("to_kb", kb, "read_only_folder"), ("to_out", out, "path_forbidden")):
                (ws / name).mkdir()
                if not _junction(ws / name / "Web_Uploads", target):
                    continue
                r = tc.post("/api/fs/upload", params={"dir": str(ws / name)}, headers=h, files=[("f", ("e.txt", b"e"))])
                assert r.status_code == 403 and r.json()["error"] == code, (name, r.text)
                assert not (target / "e.txt").exists()
    # a chat may work in a read-only folder; outside stays refused
    policy = c.policy_for(dee)
    pol.check("session/new", {"cwd": str(kb)}, is_admin=False, policy=policy, roots=c.roots_for(dee, policy))
    with pytest.raises(pol.Denied):
        pol.check("session/new", {"cwd": str(out)}, is_admin=False, policy=policy, roots=c.roots_for(dee, policy))
    # a socket's rights change when the read-only list does (it is then closed and reconnects)
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**ANYCHAT, "allowed_roots": [str(rw)]}), tid))
    assert c.rights_fingerprint(db.user_by_id(dee["id"])) != fp_before
    assert not c.path_ok(db.user_by_id(dee["id"]), str(kb / "facts.md"))


def test_admin_api_refuses_a_nested_read_only_folder_and_checks_overrides(env, tmp_path):
    s, db, pr, c = env
    rw = tmp_path / "rw"
    (rw / "kb").mkdir(parents=True)
    kb = tmp_path / "kb"
    kb.mkdir()
    boss = user(db, "boss", role="admin")
    dee = user(db, "dee")
    tid = team(db, "A", ANYCHAT)
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        ok = {**ANYCHAT, "allowed_roots": [str(rw)], "read_roots": [str(kb)]}
        r = tc.patch(f"/api/admin/teams/{tid}", json={"policy": ok}, headers=h)
        assert r.status_code == 200 and r.json()["team"]["policy"]["read_roots"] == [str(kb)]
        for bad in ({**ANYCHAT, "allowed_roots": [str(rw)], "read_roots": [str(rw / "kb")]},
                    {**ANYCHAT, "read_roots": [str(pr.team_folder({"id": tid, "policy": {}}) / "kb")]},     # own team folder
                    {**ANYCHAT, "read_roots": ["kb"]}):
            r = tc.patch(f"/api/admin/teams/{tid}", json={"policy": bad}, headers=h)
            assert r.status_code == 400 and r.json()["error"] == "bad_folder", r.text
        assert db.one("SELECT policy FROM teams WHERE id=?", (tid,))["policy"]["read_roots"] == [str(kb)]   # unchanged
        # one person's overrides are held to the same folder rules
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"read_roots": [str(pr.root)]}}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "bad_folder"
        # R-4: a NEW team's own folder is known only once it has an id - a read-only folder inside it is refused
        n = db.one("SELECT COUNT(*) AS n FROM teams")["n"]
        nxt = db.one("SELECT MAX(id) AS m FROM teams")["m"] + 1
        r = tc.post("/api/admin/teams", json={"name": "New", "policy": {**ANYCHAT, "read_roots": [str(pr.root / "_teams" / str(nxt) / "kb")]}}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "bad_folder", r.text
        assert db.one("SELECT COUNT(*) AS n FROM teams")["n"] == n
        # R-3: an override saved while the person had no team, then the team: read-only wins at use
        solo = user(db, "solo")
        r = tc.patch(f"/api/admin/users/{solo['id']}", json={"policyOverrides": {"read_roots": [str(rw / "kb")]}}, headers=h)
        assert r.status_code == 200
        assert tc.patch(f"/api/admin/users/{solo['id']}", json={"team": tid}, headers=h).status_code == 200
        solo = db.user_by_id(solo["id"])
        assert not c.path_ok(solo, str(rw / "kb" / "x"), write=True) and not c.path_ok(solo, str(rw / "x"), write=True)
        assert c.path_ok(solo, str(rw / "x")) and c.path_ok(solo, str(pr.workspace(solo) / "x"), write=True)
        s.data.setdefault("sandbox", {})["enabled"] = True
        g = c.sandbox_spec(solo)["grants"]
        assert g[os.path.normpath(str(rw))] == "read" and g[os.path.normpath(str(rw / "kb"))] == "read"
        s.data["sandbox"]["enabled"] = False
        # ... also against what the person's TEAM lets them write (the team has `rw` as a writable folder)
        assert tc.patch(f"/api/admin/users/{dee['id']}", json={"team": tid}, headers=h).status_code == 200
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"read_roots": [str(rw / "kb")]}}, headers=h)
        assert r.status_code == 400 and "this person can write" in r.json()["message"]
        r = tc.patch(f"/api/admin/users/{dee['id']}", json={"policyOverrides": {"read_roots": [str(kb)], "allow_shell": False}}, headers=h)
        assert r.status_code == 200 and db.user_by_id(dee["id"])["policy_overrides"] == {"read_roots": [str(kb)], "allow_shell": False}


def test_admin_uploads_land_in_web_uploads_too(env, tmp_path):
    s, db, pr, c = env
    boss = user(db, "boss", role="admin")
    proj = tmp_path / "proj"
    proj.mkdir()
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        r = tc.post("/api/fs/upload", params={"dir": str(proj)}, headers=h, files=[("f", ("a.txt", b"a"))])
        assert r.status_code == 200 and (proj / "Web_Uploads" / "a.txt").read_bytes() == b"a"
        assert tc.get("/api/fs/list", params={"path": str(proj)}).json()["access"] == "write"


# ------------------------------------------------------------------ the sandbox
def test_sandbox_grants_modify_for_writable_and_read_for_read_only(env, tmp_path):
    s, db, pr, c = env
    rw, kb = tmp_path / "rw", tmp_path / "kb"
    tid = team(db, "A", {**ANYCHAT, "allowed_roots": [str(rw)], "read_roots": [str(kb)]})
    ben = user(db, "ben")
    db.set_user_team(ben["id"], tid)
    s.data.setdefault("sandbox", {})["enabled"] = True
    spec = c.sandbox_spec(db.user_by_id(ben["id"]))
    n = os.path.normpath
    for key in ("grants", "mxc_grants"):                    # both backends take their lists from these
        g = spec[key]
        assert g[n(str(rw))] == "modify" and g[n(str(kb))] == "read", key
        assert g[n(str(pr.root_for(ben)))] == "modify"
        assert any(k.endswith(os.path.join("_teams", str(tid))) and v == "modify" for k, v in g.items())
    assert sb.desired_grants("P", ["W"], ["R"], "", read_roots=["K", "W"]) == {"R": "read", "K": "read", "W": "modify", "P": "modify"}
    from goose_web import mxc
    p = mxc.build_policy(command=["x"], cwd=str(rw), env={}, grants={str(rw): "modify", str(kb): "read"})
    assert p["filesystem"] == {"readwritePaths": [str(rw)], "readonlyPaths": [str(kb)]}
    # folders members can write (plugin / library rules) do not include a read-only folder
    assert not any(os.path.normcase(str(kb)) == w for w in pr._member_writable_folders())


@pytest.mark.skipif(sys.platform != "win32", reason="AppContainer is Windows-only")
def test_appcontainer_reads_a_read_only_folder_and_cannot_write_it(tmp_path):
    """Real kernel enforcement (the AppContainer backend): a program in the member's container reads the read-only
    folder, cannot create, change or delete anything in it, and writes in the writable one."""
    rw, kb = tmp_path / "rw", tmp_path / "kb"
    rw.mkdir()
    (kb / "sub").mkdir(parents=True)
    (kb / "facts.txt").write_text("FACTS", encoding="utf-8")
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    state_dir = str(tmp_path / "state")
    st = sb.prepare(name, state_dir, sb.desired_grants(str(rw), [], [], "", read_roots=[str(kb)]))
    try:
        assert sb.load_state(state_dir, name)["grants"] == {os.path.normpath(str(kb)): "read", os.path.normpath(str(rw)): "modify"}
        log = open(tmp_path / "err.log", "wb")
        cmd = (f'type "{kb / "facts.txt"}" & echo. & echo X> "{kb / "new.txt"}" & echo Y>> "{kb / "facts.txt"}" & '
               f'del "{kb / "facts.txt"}" & mkdir "{kb / "made"}" & echo Z> "{kb / "sub" / "deep.txt"}" & '
               f'echo W> "{rw / "w.txt"}"')
        cmd_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        p = sb.spawn(f'"{cmd_exe}" /d /c {cmd}', dict(os.environ), str(rw), st["sid"], [], log)
        p.stdin.close()
        out = p.stdout.read().decode("utf-8", "replace")
        p.wait(30)
        log.close()
        assert "FACTS" in out
        assert (kb / "facts.txt").read_text(encoding="utf-8") == "FACTS"                  # not changed, not deleted
        assert sorted(x.name for x in kb.iterdir()) == ["facts.txt", "sub"] and not any((kb / "sub").iterdir())
        assert (rw / "w.txt").exists()
        assert "denied" in (tmp_path / "err.log").read_text(encoding="utf-8", errors="replace").lower()
    finally:
        sb.remove(state_dir, name)


@pytest.mark.skipif(sys.platform != "win32", reason="AppContainer is Windows-only")
def test_appcontainer_a_folder_switched_from_writable_to_read_only_loses_the_write_access(tmp_path):
    """The administrator flips the switch on a folder the team could write: the container's Modify entry must be
    gone, not left beside the new read entry - also on what was created in the folder while it was writable."""
    kb, rw = tmp_path / "kb", tmp_path / "rw"
    kb.mkdir()
    rw.mkdir()
    name = f"GooseWeb.test.{uuid.uuid4().hex[:12]}"
    state_dir = str(tmp_path / "state")
    cmd_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")

    def run(st, cmd, tag):
        log = open(tmp_path / f"{tag}.log", "wb")
        p = sb.spawn(f'"{cmd_exe}" /d /c {cmd}', dict(os.environ), str(rw), st["sid"], [], log)
        p.stdin.close()
        out = p.stdout.read().decode("utf-8", "replace")
        p.wait(30)
        log.close()
        return out

    st = sb.prepare(name, state_dir, sb.desired_grants(str(rw), [str(kb)], [], ""))             # writable
    try:
        run(st, f'echo ONE> "{kb / "made-while-writable.txt"}" & mkdir "{kb / "sub"}"', "a")
        assert (kb / "made-while-writable.txt").exists() and (kb / "sub").is_dir()
        # now read only. What the gateway does at the moment of the switch, while the member's agent may be
        # running (api._sync_grants -> sandbox.shrink): the entry is narrowed at once (review 20261119_5, R-2)
        res = sb.shrink(name, state_dir, sb.desired_grants(str(rw), [], [], "", read_roots=[str(kb)]))
        assert res["narrowed"] == [os.path.normpath(str(kb))] and res["revoked"] == []
        assert sb.load_state(state_dir, name)["grants"][os.path.normpath(str(kb))] == "read"
        assert sb.load_state(state_dir, name)["grants"][os.path.normpath(str(rw))] == "modify"       # untouched
        out = run(st, f'type "{kb / "made-while-writable.txt"}" & echo TWO> "{kb / "new.txt"}" & '
                      f'echo THREE>> "{kb / "made-while-writable.txt"}" & echo FOUR> "{kb / "sub" / "deep.txt"}" & '
                      f'del "{kb / "made-while-writable.txt"}"', "b")
        assert "ONE" in out
        assert (kb / "made-while-writable.txt").read_text(encoding="utf-8").strip() == "ONE"
        assert sorted(x.name for x in kb.iterdir()) == ["made-while-writable.txt", "sub"] and not any((kb / "sub").iterdir())
        # a right that grows is not handed out by shrink (that is the next start's business) ...
        assert sb.shrink(name, state_dir, sb.desired_grants(str(rw), [str(kb)], [], ""))["narrowed"] == []
        run(st, f'echo SIX> "{kb / "not-yet.txt"}"', "b2")
        assert not (kb / "not-yet.txt").exists()
        # ... the next start gives it: writable again
        st = sb.prepare(name, state_dir, sb.desired_grants(str(rw), [str(kb)], [], ""))
        run(st, f'echo FIVE> "{kb / "again.txt"}"', "c")
        assert (kb / "again.txt").exists()
    finally:
        sb.remove(state_dir, name)


RO_PROBE = r'''
import json, os, subprocess, sys
RW, KB = sys.argv[1], sys.argv[2]
out = {}
def t(name, f):
    try:
        out[name] = f()
    except Exception as e:
        out[name] = "ERR " + type(e).__name__
t("read", lambda: open(os.path.join(KB, "facts.txt")).read())
t("list", lambda: sorted(os.listdir(KB)))
t("create", lambda: open(os.path.join(KB, "new.txt"), "w").write("x") and "ok")
t("append", lambda: open(os.path.join(KB, "facts.txt"), "a").write("x") and "ok")
t("delete", lambda: os.remove(os.path.join(KB, "facts.txt")) or "ok")
t("rename", lambda: os.rename(os.path.join(KB, "facts.txt"), os.path.join(KB, "moved.txt")) or "ok")
t("mkdir", lambda: os.mkdir(os.path.join(KB, "made")) or "ok")
t("deep", lambda: open(os.path.join(KB, "sub", "deep.txt"), "w").write("x") and "ok")
t("child", lambda: subprocess.run([sys.executable, "-I", "-c", "open(%r, 'w').write('x')" % os.path.join(KB, "child.txt")],
                                  capture_output=True).returncode)
t("write_rw", lambda: open(os.path.join(RW, "w.txt"), "w").write("x") and "ok")
print(json.dumps(out), flush=True)
'''


async def test_mxc_reads_a_read_only_folder_and_cannot_write_it(tmp_path):
    """The same, with the MXC backend (readonlyPaths): skipped where MXC is not usable."""
    from goose_web import mxc
    from goose_web.workers import _Job
    from tests.test_mxc_e2e import _ready
    s = _ready(tmp_path)
    rw, kb = tmp_path / "rw", tmp_path / "kb"
    rw.mkdir()
    (kb / "sub").mkdir(parents=True)
    (kb / "facts.txt").write_text("FACTS", encoding="utf-8")
    (rw / "probe.py").write_text(RO_PROBE, encoding="utf-8")
    py = sys.base_prefix
    grants = sb.desired_grants(str(rw), [], [py], "", read_roots=[str(kb)])
    policy = mxc.build_policy(command=[os.path.join(py, "python.exe"), "-I", str(rw / "probe.py"), str(rw), str(kb)],
                              cwd=str(rw), env={"SystemRoot": os.environ["SystemRoot"], "PATH": py,
                                                "LOCALAPPDATA": os.environ["LOCALAPPDATA"]},
                              grants=grants, proxy_url="", system_drive=os.environ.get("SystemDrive", "C:"))
    assert os.path.normpath(str(kb)) in policy["filesystem"]["readonlyPaths"]
    pf = tmp_path / "policy.json"
    mxc.write_policy(pf, policy)
    gj, wj = _Job(), _Job()
    errf = open(tmp_path / "err.log", "wb")
    try:
        p = mxc.launch(mxc.exe_path(s), pf, errf, [gj, wj])
        out, _ = await asyncio.to_thread(p.communicate, None, 120)
        errf.close()
        assert p.returncode == 0, (tmp_path / "err.log").read_text(errors="replace")
        r = json.loads(out.decode().strip().splitlines()[-1])
        assert r["read"] == "FACTS" and r["list"] == ["facts.txt", "sub"] and r["write_rw"] == "ok"
        for k in ("create", "append", "delete", "rename", "mkdir", "deep"):
            assert str(r[k]).startswith("ERR"), (k, r)
        assert r["child"] != 0
        assert (kb / "facts.txt").read_text(encoding="utf-8") == "FACTS"
        assert sorted(x.name for x in kb.iterdir()) == ["facts.txt", "sub"] and not any((kb / "sub").iterdir())
    finally:
        wj.close()
        gj.close()
