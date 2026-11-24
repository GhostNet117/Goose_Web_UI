"""Spec 039: chunked, resumable uploads into <chat folder>\\Web_Uploads, and the adjustable upload limit (1..5120 MB).

Every check of the single-request upload holds for each piece (sign-in, CSRF/Origin, write access to the folder as it
resolves - at the start, before every piece and before the final name -, cleaned names, no hints files or .agents for
members); an upload belongs to whoever started it; the declared size is the most the server takes; pieces are all or
nothing and must continue exactly where the last ended; bytes go straight to disk; the final name never replaces a
file; idle partial files go after 24 hours; free disk space is checked first."""
import asyncio
import inspect
import itertools
import json
import os
import stat
import subprocess
import sys
import time
import tracemalloc
import types
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from goose_web import api, uploads
from goose_web import app as gw_app
from goose_web.context import HTTPError
from goose_web.db import Database
from tests.test_sec_web import asgi
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)

MB = 1024 * 1024
WIN = sys.platform == "win32"


def _junction(link, target) -> bool:
    r = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    return r.returncode == 0


def member(env, name="dee", policy=None):
    s, db, pr, c = env
    tid = team(db, "T-" + name, {**ANYCHAT, **(policy or {})})
    u = user(db, name)
    db.set_user_team(u["id"], tid)
    u = db.user_by_id(u["id"])
    pr.ensure_layout(u)
    return u, tid


def start(tc, h, d, name, size, **kw):
    return tc.post("/api/fs/uploads", json={"dir": str(d), "name": name, "size": size, **kw}, headers=h)


def put(tc, h, uid, offset, data):
    return tc.put(f"/api/fs/uploads/{uid}", params={"offset": offset}, content=data,
                  headers={**h, "content-type": "application/octet-stream"})


def row_of(db, uid):
    return db.one("SELECT * FROM uploads WHERE id=?", (uploads._key(uid),))


# ------------------------------------------------------------------ the protocol
def test_tables_exist_after_open(tmp_path):
    db = Database(tmp_path / "x.db")
    names = {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"uploads", "upload_links", "chat_access"} <= names
    db.close()


def test_chunk_protocol_start_put_resume_complete(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    data = os.urandom(3000)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        lim = tc.get("/api/fs/uploads").json()
        assert lim["maxMb"] == 25 and lim["chunkBytes"] == uploads.CHUNK_BYTES and lim["parallel"] == 2 and lim["maxFiles"] == 20
        r = start(tc, h, ws, "big.bin", len(data), mime="application/x-test")
        assert r.status_code == 200, r.text
        j = r.json()
        uid = j["id"]
        assert j["received"] == 0 and j["chunkBytes"] == uploads.CHUNK_BYTES and len(uid) >= 40 and not j["done"]
        row = row_of(db, uid)
        partial = Path(row["partial"])
        assert partial.parent == ws / "Web_Uploads" and partial.name.startswith(".goose-web-upload-") and partial.is_file()
        assert uid not in json.dumps(row)                       # only its hash is stored
        if WIN:
            assert os.stat(partial).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN
        r = put(tc, h, uid, 0, data[:1000])
        assert r.json() == {"received": 1000, "size": 3000, "done": False}
        assert tc.get(f"/api/fs/uploads/{uid}").json() == {"received": 1000, "size": 3000, "state": "open", "done": False}
        assert put(tc, h, uid, 1000, data[1000:2000]).json()["received"] == 2000
        j = put(tc, h, uid, 2000, data[2000:]).json()
        final = ws / "Web_Uploads" / "big.bin"
        assert j["done"] and j["file"] == {"name": "big.bin", "path": str(final), "size": 3000, "mime": "application/x-test"}
        assert final.read_bytes() == data and not partial.exists()
        if WIN:
            assert not os.stat(final).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN
        st = tc.get(f"/api/fs/uploads/{uid}").json()
        assert st["done"] and st["state"] == "done" and st["file"]["path"] == str(final)
        a = db.query("SELECT * FROM audit WHERE action='fs.upload'")[-1]
        assert a["target"] == str(ws / "Web_Uploads") and a["detail"] == {"files": ["big.bin"], "size": 3000, "chunked": True}
        assert a["username"] == "dee"
        r = put(tc, h, uid, 3000, b"x")
        assert r.status_code == 409 and r.json()["error"] == "upload_ended"
        # a file of 0 bytes is complete at the start
        j = start(tc, h, ws, "empty.txt", 0).json()
        assert j["done"] and (ws / "Web_Uploads" / "empty.txt").read_bytes() == b""


def test_wrong_offset_and_over_size_are_refused(env, monkeypatch):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "ten.bin", 10).json()["id"]
        partial = Path(row_of(db, uid)["partial"])
        r = put(tc, h, uid, 5, b"abc")
        assert r.status_code == 409 and r.json()["error"] == "offset_mismatch" and r.json()["received"] == 0
        r = put(tc, h, uid, 0, b"x" * 11)                     # more than declared
        assert r.status_code == 413 and partial.stat().st_size == 0 and row_of(db, uid)["received"] == 0
        assert put(tc, h, uid, 0, b"x" * 6).json()["received"] == 6
        r = put(tc, h, uid, 6, b"y" * 5)
        assert r.status_code == 413 and partial.stat().st_size == 6 and row_of(db, uid)["received"] == 6
        assert tc.put(f"/api/fs/uploads/{uid}", params={"offset": "x"}, content=b"y", headers=h).status_code == 400
        monkeypatch.setattr(uploads, "MAX_CHUNK_BYTES", 3)    # one piece may carry at most this much
        r = put(tc, h, uid, 6, b"yyyy")
        assert r.status_code == 413 and "One piece" in r.json()["message"]
        monkeypatch.undo()
        assert put(tc, h, uid, 6, b"yyyy").json()["done"]
        assert (ws / "Web_Uploads" / "ten.bin").read_bytes() == b"xxxxxxyyyy"
        # a declared size above the limit is refused before anything is made
        r = start(tc, h, ws, "huge.iso", 25 * MB + 1)
        assert r.status_code == 413 and r.json()["message"] == "Uploads are limited to 25 MB"
        for bad in (-1, "12", 1.5, True, None):
            assert start(tc, h, ws, "a", bad).status_code == 400
        for raw in (b'{"dir": "%s", "name": "a", "size": Infinity}', b'{"dir": "%s", "name": "a", "size": NaN}'):
            body = raw.replace(b"%s", json.dumps(str(ws))[1:-1].encode())
            r = tc.post("/api/fs/uploads", content=body, headers={**h, "content-type": "application/json"})
            assert r.status_code == 400, r.text
        assert tc.post("/api/fs/uploads", json={"name": "a", "size": 1}, headers=h).status_code == 400   # no dir


def test_never_overwrites(env, monkeypatch):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    (ws / "Web_Uploads").mkdir(parents=True)
    (ws / "Web_Uploads" / "a.txt").write_bytes(b"OLD")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "a.txt", 3).json()["id"]
        assert put(tc, h, uid, 0, b"NEW").json()["file"]["name"] == "a (1).txt"
        # a file that appears between the look and the rename is not replaced either: the next name is taken
        orig = uploads._rename_noreplace
        calls = []

        def racing(src, dst):
            calls.append(dst.name)
            if len(calls) == 1:
                Path(dst).write_bytes(b"RACE")
            return orig(src, dst)
        monkeypatch.setattr(uploads, "_rename_noreplace", racing)
        uid = start(tc, h, ws, "a.txt", 3).json()["id"]
        assert put(tc, h, uid, 0, b"N2!").json()["file"]["name"] == "a (3).txt"
        assert calls == ["a (2).txt", "a (3).txt"]
    up = ws / "Web_Uploads"
    assert (up / "a.txt").read_bytes() == b"OLD" and (up / "a (1).txt").read_bytes() == b"NEW"
    assert (up / "a (2).txt").read_bytes() == b"RACE" and (up / "a (3).txt").read_bytes() == b"N2!"
    assert not [p for p in up.iterdir() if p.name.endswith(".partial")]


def test_abort_deletes_the_partial_file(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "x.bin", 10).json()["id"]
        partial = Path(row_of(db, uid)["partial"])
        put(tc, h, uid, 0, b"1234")
        r = tc.delete(f"/api/fs/uploads/{uid}", headers=h)
        assert r.status_code == 200 and r.json() == {"state": "aborted"} and not partial.exists()
        assert tc.get(f"/api/fs/uploads/{uid}").json()["state"] == "aborted"
        assert put(tc, h, uid, 4, b"5").json()["error"] == "upload_ended"
        assert tc.delete(f"/api/fs/uploads/{uid}", headers=h).json() == {"state": "aborted"}
        assert not (ws / "Web_Uploads" / "x.bin").exists()
        # cancelled while a piece is being received: that piece stops and the file goes
        uid = start(tc, h, ws, "y.bin", 10).json()["id"]
        key = uploads._key(uid)
        uploads._live(db).busy.add(key)
        assert tc.delete(f"/api/fs/uploads/{uid}", headers=h).json() == {"state": "aborted"}
        assert key in uploads._live(db).cancel and Path(row_of(db, uid)["partial"]).exists()
        uploads._live(db).busy.discard(key)
        uploads._live(db).cancel.discard(key)
        # a finished upload is not deleted by the API
        uid = start(tc, h, ws, "z.bin", 1).json()["id"]
        put(tc, h, uid, 0, b"z")
        r = tc.delete(f"/api/fs/uploads/{uid}", headers=h)
        assert r.status_code == 409 and (ws / "Web_Uploads" / "z.bin").exists()


# ------------------------------------------------------------------ security checks
def test_read_only_folder_and_link_are_refused(env, tmp_path):
    s, db, pr, c = env
    rw, kb, out = tmp_path / "rw", tmp_path / "kb", tmp_path / "outside"
    for d in (rw, kb, out):
        d.mkdir()
    dee, tid = member(env, policy={"allowed_roots": [str(rw)], "read_roots": [str(kb)]})
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = start(tc, h, kb, "a.txt", 1)
        assert r.status_code == 403 and r.json()["error"] == "read_only_folder" and r.json()["message"] == api.READ_ONLY_MESSAGE
        r = start(tc, h, out, "a.txt", 1)
        assert r.status_code == 403 and r.json()["error"] == "path_forbidden"
        assert not any(kb.iterdir()) and not any(out.iterdir())
        if WIN:
            for name, target, code in (("to_kb", kb, "read_only_folder"), ("to_out", out, "path_forbidden")):
                (ws / name).mkdir()
                assert _junction(ws / name / "Web_Uploads", target)
                r = start(tc, h, ws / name, "e.txt", 1)
                assert r.status_code == 403 and r.json()["error"] == code, (name, r.text)
            assert not any(kb.iterdir()) and not any(out.iterdir())
        # the folder is looked at again before every piece (and before the final name)
        uid = start(tc, h, rw / "proj", "b.txt", 4).json()["id"]
        assert put(tc, h, uid, 0, b"ab").json()["received"] == 2
        db.execute("UPDATE teams SET policy=? WHERE id=?",
                   (json.dumps({**ANYCHAT, "read_roots": [str(kb), str(rw)]}), tid))
        r = put(tc, h, uid, 2, b"cd")
        assert r.status_code == 403 and r.json()["error"] == "read_only_folder"
        assert not (rw / "proj" / "Web_Uploads" / "b.txt").exists()
        if WIN:
            # Web_Uploads swapped for a junction to somewhere else in the middle of an upload
            db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**ANYCHAT, "allowed_roots": [str(rw)]}), tid))
            uid = start(tc, h, ws / "p2", "c.txt", 4).json()["id"]
            put(tc, h, uid, 0, b"ab")
            os.rename(ws / "p2" / "Web_Uploads", ws / "p2" / "moved")
            assert _junction(ws / "p2" / "Web_Uploads", out)
            r = put(tc, h, uid, 2, b"cd")
            assert r.status_code == 403 and r.json()["error"] == "path_forbidden" and not any(out.iterdir())


def test_a_partial_file_swapped_for_another_file_is_refused(env, tmp_path):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "s.bin", 8).json()["id"]
        partial = Path(row_of(db, uid)["partial"])
        put(tc, h, uid, 0, b"1234")
        partial.unlink()                                  # the agent puts another file in its place
        partial.write_bytes(b"AGENT")
        r = put(tc, h, uid, 4, b"5678")
        assert r.status_code == 409 and r.json()["error"] == "upload_lost"
        assert partial.read_bytes() == b"AGENT" and row_of(db, uid)["state"] == "aborted"
        assert not (ws / "Web_Uploads" / "s.bin").exists()
        if WIN:
            # the whole folder swapped for a junction to a folder holding a file of the same name
            uid = start(tc, h, ws / "q", "t.bin", 8).json()["id"]
            partial = Path(row_of(db, uid)["partial"])
            put(tc, h, uid, 0, b"1234")
            decoy = ws / "decoy"
            decoy.mkdir()
            (decoy / partial.name).write_bytes(b"1234")
            os.rename(ws / "q" / "Web_Uploads", ws / "q" / "old")
            assert _junction(ws / "q" / "Web_Uploads", decoy)
            r = put(tc, h, uid, 4, b"5678")
            assert r.status_code == 409 and r.json()["error"] == "upload_lost"
            assert (decoy / partial.name).read_bytes() == b"1234" and not (decoy / "t.bin").exists()
        # a partial file that lost bytes is not continued
        uid = start(tc, h, ws, "u.bin", 8).json()["id"]
        put(tc, h, uid, 0, b"1234")
        with open(row_of(db, uid)["partial"], "r+b") as f:
            f.truncate(2)
        r = put(tc, h, uid, 4, b"5678")
        assert r.status_code == 410 and r.json()["error"] == "upload_lost"


def test_other_users_upload_id_is_not_found(env):
    s, db, pr, c = env
    dee, _ = member(env)
    bob, _ = member(env, "bob")
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, pr.workspace(dee), "mine.bin", 4).json()["id"]
        put(tc, h, uid, 0, b"12")
    with client_for(c) as tc:
        h = sign_in(tc, c, bob)
        for r in (tc.get(f"/api/fs/uploads/{uid}"), put(tc, h, uid, 2, b"34"), tc.delete(f"/api/fs/uploads/{uid}", headers=h),
                  tc.get("/api/fs/uploads/" + "A" * 43), tc.get("/api/fs/uploads/short")):
            assert r.status_code == 404 and r.json()["error"] == "not_found", r.text
        r = tc.post("/api/fs/uploads/link", json={"session": "20261124_1", "ids": [uid]}, headers=h)
        assert r.json() == {"linked": 0}
    assert row_of(db, uid)["received"] == 2 and row_of(db, uid)["state"] == "open"
    assert not db.query("SELECT * FROM upload_links")


def test_csrf_and_origin_are_checked(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/fs/uploads", json={"dir": str(ws), "name": "a", "size": 1})
        assert r.status_code == 403 and r.json()["error"] == "csrf"
        r = tc.post("/api/fs/uploads", json={"dir": str(ws), "name": "a", "size": 1},
                    headers={**h, "origin": "https://evil.example.org"})
        assert r.status_code == 403 and r.json()["error"] == "bad_origin"
        uid = start(tc, h, ws, "a", 2).json()["id"]
        assert tc.put(f"/api/fs/uploads/{uid}", params={"offset": 0}, content=b"a").json()["error"] == "csrf"
        assert tc.delete(f"/api/fs/uploads/{uid}").json()["error"] == "csrf"
        assert tc.post("/api/fs/uploads/link", json={"session": "s1", "ids": [uid]}).json()["error"] == "csrf"
        assert tc.get(f"/api/fs/uploads/{uid}").status_code == 200        # reading needs no token
        assert row_of(db, uid)["received"] == 0
    with client_for(c) as tc:   # not signed in
        assert tc.get("/api/fs/uploads").status_code == 401
        assert tc.post("/api/fs/uploads", json={}).status_code == 401


def test_per_user_limits(env, monkeypatch):
    s, db, pr, c = env
    dee, _ = member(env)
    bob, _ = member(env, "bob")
    monkeypatch.setattr(uploads, "MAX_OPEN_PER_USER", 3)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        ids = [start(tc, h, pr.workspace(dee), f"f{i}", 5).json()["id"] for i in range(3)]
        r = start(tc, h, pr.workspace(dee), "f4", 5)
        assert r.status_code == 429 and r.json()["error"] == "too_many_uploads"
        # an idle one (beyond 24 hours) no longer counts
        db.execute("UPDATE uploads SET updated_at=? WHERE id=?", (time.time() - 25 * 3600, uploads._key(ids[0])))
        assert start(tc, h, pr.workspace(dee), "f5", 5).status_code == 200
        live = uploads._live(db)
        live.puts[dee["id"]] = uploads.MAX_PUTS_PER_USER
        r = put(tc, h, ids[1], 0, b"1")
        assert r.status_code == 429
        live.puts.pop(dee["id"])
        live.busy.add(uploads._key(ids[1]))
        r = put(tc, h, ids[1], 0, b"1")
        assert r.status_code == 409 and r.json()["error"] == "upload_busy"
        live.busy.discard(uploads._key(ids[1]))
        assert put(tc, h, ids[1], 0, b"1").status_code == 200
        assert not live.puts and not live.busy                   # nothing left counted after a piece
    with client_for(c) as tc:
        h = sign_in(tc, c, bob)
        assert start(tc, h, pr.workspace(bob), "g", 5).status_code == 200   # per person


def test_names_hint_files_and_agents_folders(env):
    s, db, pr, c = env
    dee, _ = member(env)
    boss = user(db, "boss", role="admin")
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        for name in ("AGENTS.md", ".goosehints", ".goose-web-hints.md", "Agents.MD", "AGENTS.md. ", "dir\\AGENTS.md"):
            r = start(tc, h, ws, name, 1)
            assert r.status_code == 403 and r.json()["error"] == "hint_file_refused", name
        r = start(tc, h, ws / ".agents" / "plugins", "x.txt", 1)
        assert r.status_code == 403 and r.json()["error"] == "agents_folder_refused"
        for raw, want in (("..\\..\\evil.txt", "evil.txt"), ("CON.txt", "_CON.txt"), ("b<?>|.txt", "b.txt"), ("", "upload.bin")):
            uid = start(tc, h, ws, raw, 1).json()["id"]
            assert put(tc, h, uid, 0, b"x").json()["file"]["path"] == str(ws / "Web_Uploads" / want)
        # an upload into another person's profile is for administrators only
        r = start(tc, h, ws, "p.txt", 1, profile="boss")
        assert r.status_code == 403
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        uid = start(tc, h, ws, "AGENTS.md", 1, profile="dee", session="20261124_7").json()["id"]
        assert row_of(db, uid)["profile"] == "dee" and row_of(db, uid)["session_id"] == "20261124_7"
        assert start(tc, h, ws, "q.txt", 1, profile="nobody").status_code == 403
        assert start(tc, h, ws, "q.txt", 1, session="bad id!").status_code == 400


def test_disk_space_is_checked_before_anything_is_written(env, monkeypatch):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    free = uploads.DISK_MARGIN + 100
    monkeypatch.setattr(uploads.shutil, "disk_usage", lambda p: types.SimpleNamespace(total=10 * free, used=0, free=free))
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = start(tc, h, ws, "big.bin", 200)
        assert r.status_code == 507 and r.json()["error"] == "disk_full"
        assert r.json()["message"].startswith("Not enough free disk space for this file: it needs 200 bytes plus 1.0 GB")
        assert not (ws / "Web_Uploads").exists()
        assert start(tc, h, ws, "ok.bin", 60).status_code == 200
        r = start(tc, h, ws, "more.bin", 60)                    # 60 + 60 still to come + 1 GB > free
        assert r.status_code == 507 and "other uploads in progress" in r.json()["message"]


# ------------------------------------------------------------------ streaming, bounded memory, the body cap
def test_a_piece_is_written_while_it_arrives(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    app = Starlette(routes=api.routes, exception_handlers={HTTPError: lambda r, e: e.response()})
    app.add_middleware(gw_app.BodyLimit, settings=s)
    app.state.ctx = c
    size = 24 * MB
    piece = 64 * 1024
    with TestClient(app, base_url="http://localhost") as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "stream.bin", size).json()["id"]
    partial = Path(row_of(db, uid)["partial"])
    token, csrf = c.auth.create_session(dee, "127.0.0.1", "pytest", "password")
    headers = {"cookie": f"{c.cookie_name}={token}", "x-csrf-token": csrf, "host": "localhost"}
    seen = []

    def body():
        for k in range(size // piece):
            seen.append((k, partial.stat().st_size))
            yield os.urandom(16) * (piece // 16)            # a new piece each time, dropped after it is written
    tracemalloc.start()
    try:
        status, out, consumed = asgi(app, "PUT", f"/api/fs/uploads/{uid}?offset=0", headers, body())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert status == 200, out
    assert json.loads(out)["done"] and consumed == size
    assert (ws / "Web_Uploads" / "stream.bin").stat().st_size == size
    # the file grew while the body was still arriving: never more than one write buffer behind
    assert all(have >= (k * piece // uploads.WRITE_BYTES - 1) * uploads.WRITE_BYTES for k, have in seen)
    assert seen[-1][1] >= size - 2 * uploads.WRITE_BYTES
    assert peak < 8 * MB, peak                            # 24 MB went through; memory stayed small


def test_a_stalled_piece_ends_and_frees_its_slot(env, monkeypatch):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    monkeypatch.setattr(uploads, "PIECE_IDLE_SECONDS", 0.3)
    app = Starlette(routes=api.routes, exception_handlers={HTTPError: lambda r, e: e.response()})
    app.state.ctx = c
    with TestClient(app, base_url="http://localhost") as tc:
        h = sign_in(tc, c, dee)
        uid = start(tc, h, ws, "slow.bin", 100).json()["id"]
    token, csrf = c.auth.create_session(dee, "127.0.0.1", "pytest", "password")
    steps = iter([b"x" * 10, None])        # 10 bytes, then nothing
    sent = []

    async def receive():
        b = next(steps)
        if b is None:
            await asyncio.sleep(10)
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": b, "more_body": True}

    async def send(m):
        sent.append(m)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "PUT", "scheme": "http",
             "path": f"/api/fs/uploads/{uid}", "raw_path": f"/api/fs/uploads/{uid}".encode(), "query_string": b"offset=0",
             "root_path": "", "client": ("127.0.0.1", 5000), "server": ("localhost", 80),
             "headers": [(b"cookie", f"{c.cookie_name}={token}".encode()), (b"x-csrf-token", csrf.encode()),
                         (b"host", b"localhost")]}
    t0 = time.time()
    asyncio.run(app(scope, receive, send))
    assert time.time() - t0 < 5
    assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 408
    row = row_of(db, uid)
    assert row["received"] == 0 and Path(row["partial"]).stat().st_size == 0     # the half piece was cut back
    live = uploads._live(db)
    assert row["id"] not in live.busy and dee["id"] not in live.puts             # the slot is free again


def test_body_limit_caps_the_piece_route(tmp_path):
    from tests.test_sec_web import make_settings

    async def echo(request: Request):
        n = 0
        async for chunk in request.stream():
            n += len(chunk)
        return PlainTextResponse(str(n))
    inner = Starlette(routes=[Route("/api/fs/uploads/{uid}", echo, methods=["PUT"]),
                              Route("/api/fs/uploads/link", echo, methods=["POST"])],
                      exception_handlers={HTTPError: lambda r, e: e.response()})
    app = gw_app.BodyLimit(inner, make_settings(tmp_path))
    chunk = b"x" * 65536
    path = "/api/fs/uploads/" + "a" * 43
    status, body, consumed = asgi(app, "PUT", path, {}, itertools.repeat(chunk, 600))        # 37.5 MB, no length
    assert status == 413 and consumed <= uploads.MAX_CHUNK_BYTES + len(chunk)
    status, _, consumed = asgi(app, "PUT", path, {"content-length": str(uploads.MAX_CHUNK_BYTES + 1)}, [])
    assert status == 413 and consumed == 0
    status, body, _ = asgi(app, "PUT", path, {}, itertools.repeat(chunk, 256))               # 16 MB: fine
    assert status == 200 and body == str(16 * MB).encode()
    status, _, _ = asgi(app, "POST", "/api/fs/uploads/link", {}, itertools.repeat(chunk, 64))  # 4 MB: default cap
    assert status == 413


def test_idle_partial_files_are_removed_after_24_hours(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        a = start(tc, h, ws, "a.bin", 10).json()["id"]
        put(tc, h, a, 0, b"12345")
        b = start(tc, h, ws, "b.bin", 10).json()["id"]
    pa, pb = Path(row_of(db, a)["partial"]), Path(row_of(db, b)["partial"])
    db.execute("UPDATE uploads SET updated_at=? WHERE id=?", (time.time() - 25 * 3600, uploads._key(a)))
    assert uploads.cleanup(c) == 1
    assert not pa.exists() and pb.exists()
    assert row_of(db, a)["state"] == "abandoned" and row_of(db, b)["state"] == "open"
    assert uploads.cleanup(c) == 0
    db.execute("UPDATE uploads SET updated_at=? WHERE id=?", (time.time() - 31 * 86400, uploads._key(a)))
    uploads.cleanup(c)
    assert row_of(db, a) is None and row_of(db, b) is not None    # ended rows are dropped after 30 days
    # the gateway's maintenance loop runs it (and the retention sweep)
    src = inspect.getsource(gw_app._maintenance_loop)
    assert "uploads.cleanup" in src and "retention.maybe_sweep" in src


# ------------------------------------------------------------------ the limit
def test_limit_setting_range_and_clamp(env):
    s, db, pr, c = env
    dee, _ = member(env)
    boss = user(db, "boss", role="admin")
    with client_for(c) as tc:
        h = sign_in(tc, c, boss)
        g = tc.get("/api/admin/settings").json()
        assert (g["maxUploadMb"], g["maxUploadMbMax"], g["maxUploadMbConfig"], g["maxUploadMbStored"]) == (25, 5120, 25, False)
        for sent, stored in ((9000, 5120), (0, 1), (300.7, 300), ("2048", 2048), (5120, 5120)):
            assert tc.put("/api/admin/settings", json={"maxUploadMb": sent}, headers=h).status_code == 200
            assert db.get_setting("max_upload_mb") == stored and tc.get("/api/admin/settings").json()["maxUploadMb"] == stored
            assert uploads.limit_mb(s) == stored                      # app.BodyLimit's copy follows at once
            assert gw_app.upload_limit_mb(s) == min(stored, 25)       # the single-request route keeps its ceiling
        for bad in ("abc", True, [1]):
            r = tc.put("/api/admin/settings", json={"maxUploadMb": bad, "brand": {"name": "X"}}, headers=h)
            assert r.status_code == 400 and db.get_setting("max_upload_mb") == 5120
        assert (db.get_setting("brand") or {}).get("name") != "X"    # nothing written when a value is refused
        assert tc.put("/api/admin/settings", json={"maxUploadMb": None}, headers=h).status_code == 200
        assert tc.get("/api/admin/settings").json()["maxUploadMb"] == 25 and uploads.limit_mb(s) == 25
        assert tc.put("/api/admin/settings", json={"maxUploadMb": 1}, headers=h).status_code == 200
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        assert tc.get("/api/fs/uploads").json()["maxMb"] == 1
        r = start(tc, h, pr.workspace(dee), "two.bin", 2 * MB)
        assert r.status_code == 413 and r.json()["message"] == "Uploads are limited to 1 MB"
        assert tc.put("/api/admin/settings", json={"maxUploadMb": 100}, headers=h).status_code == 403
    assert uploads.limit_text(5120) == "5120 MB (5 GB)" and uploads.clamp_mb(float("inf")) == 5120


def test_old_endpoint_uses_the_admin_limit_and_records_files(env):
    s, db, pr, c = env
    dee, _ = member(env)
    ws = pr.workspace(dee)
    db.set_setting("max_upload_mb", 1)
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("a.bin", b"x" * (MB + MB // 2)))])
        assert r.status_code == 413
        db.set_setting("max_upload_mb", 2)
        r = tc.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("a.bin", b"x" * (MB + MB // 2)))])
        assert r.status_code == 200, r.text
        f = r.json()["files"][0]
        assert f["path"] == str(ws / "Web_Uploads" / "a.bin") and len(f["id"]) >= 40
    row = row_of(db, f["id"])
    assert row["state"] == "done" and row["path"] == f["path"] and row["size"] == MB + MB // 2 and row["profile"] == "dee"
    assert row["file_id"]
    # a higher limit is for the chunked upload: the single request (multipart, spooled to the temp folder) keeps the
    # configuration's ceiling
    s.data["server"]["max_upload_mb"] = 1
    db.set_setting("max_upload_mb", 100)
    uploads.load_admin_limit(s, db)
    assert gw_app.upload_limit_mb(s) == 1 and uploads.limit_mb(s) == 100
    with client_for(c) as tc:
        h = sign_in(tc, c, dee)
        r = tc.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("b.bin", b"x" * (MB + MB // 2)))])
        assert r.status_code == 413 and r.json()["message"] == "Uploads are limited to 1 MB"
        assert start(tc, h, ws, "b.bin", MB + MB // 2).status_code == 200


def test_check_reports_the_upload_limit(tmp_path):
    from tests.test_sec_web import make_settings
    s = make_settings(tmp_path, max_upload_mb=9000)
    lines = uploads.check_lines(s)
    assert lines[0] == ("--", "uploads: largest file 5120 MB (5 GB) (server.max_upload_mb), sent in resumable pieces of 16 MB")
    assert lines[1][0] == "!!" and "9000 MB is configured, the limit is 5120 MB" in lines[1][1]
    db = Database(s.system_dir / "goose-web.db")
    db.set_setting("max_upload_mb", 300)
    db.close()
    assert uploads.check_lines(s)[0][1].startswith("uploads: largest file 300 MB (Admin > Settings)")
    s2 = make_settings(tmp_path / "b", max_upload_mb="lots")
    assert uploads.check_lines(s2)[1] == ("!!", "server.max_upload_mb: 'lots' is not a number of megabytes - 25 is used")
