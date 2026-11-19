"""Spec 032 (1.25.0): a sign-in lasts eight hours at most and there is no "keep me signed in".

A copied sign-in cookie works for as long as the sign-in lives, and this product starts programs for whoever is
signed in. So: one fixed lifetime (auth.session_hours, 1 to 8, never extended), a session cookie (the browser is
not asked to keep it), sign-ins of earlier versions cut at start-up, and an optional idle limit (off by default)."""
import time

import pytest
from starlette.testclient import TestClient

from goose_web import auth as auth_mod
from goose_web.config import DEFAULTS, REMOVED_SETTINGS, unknown_settings
from test_sec_web import PW, build, mk_user, sign_in


@pytest.fixture
def gw(tmp_path):
    app, c = build(tmp_path)
    with TestClient(app) as client:
        yield client, c
    c.db.close()


def test_the_lifetime_is_eight_hours_at_most():
    c = auth_mod.clamp_session_hours
    assert auth_mod.SESSION_HOURS_MAX == 8
    assert [c(x) for x in (8, 12, 720, 3, "2.5", None, "", 0, -1, "x", float("nan"), float("inf"))] == \
        [8, 8, 8, 3, 2.5, 8, 8, 8, 8, 8, 8, 8]
    i = auth_mod.clamp_idle_minutes
    assert [i(x) for x in (0, None, "", "x", -5, 1, 5, 30, 480, 9999)] == [0, 0, 0, 0, 0, 5, 5, 30, 480, 480]
    assert DEFAULTS["auth"]["session_hours"] == 8 and DEFAULTS["auth"]["idle_minutes"] == 0
    assert "remember_days" not in DEFAULTS["auth"]


def test_a_removed_setting_is_named_with_the_reason():
    assert ("auth", "remember_days") in REMOVED_SETTINGS
    got = unknown_settings({"auth": {"remember_days": 30, "session_hours": 8, "sesion_hours": 4}})
    assert got[0].startswith("auth.remember_days (removed in 1.25.0") and "8 hours at most" in got[0]
    assert got[1] == "auth.sesion_hours"


def test_sign_in_ignores_remember_and_sets_a_session_cookie(gw):
    client, c = gw
    mk_user(c.db, "ann")
    t0 = time.time()
    r = client.post("/api/auth/login", json={"username": "ann", "password": PW, "remember": True},
                    headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    cookie = r.headers["set-cookie"]
    low = cookie.lower()
    assert "max-age" not in low and "expires" not in low                 # the browser is not asked to keep it
    assert "httponly" in low and "samesite=strict" in low and "path=/" in low
    row = c.db.one("SELECT * FROM auth_sessions")
    assert 8 * 3600 - 5 <= row["expires_at"] - t0 <= 8 * 3600 + 5        # not 30 days
    # a configured or stored value above the limit counts as the limit
    c.db.set_setting("session_hours", 720)
    assert c.auth.session_hours() == 8 and c.auth.session_seconds() == 8 * 3600
    c.db.set_setting("session_hours", 2)
    assert c.auth.session_seconds() == 2 * 3600


def test_admin_settings_hold_the_limit(gw):
    client, c = gw
    admin = mk_user(c.db, "boss", role="admin")
    h = sign_in(client, c, admin)
    s = client.get("/api/admin/settings").json()
    assert s["sessionHours"] == 8 and s["sessionHoursMax"] == 8 and s["idleMinutes"] == 0
    assert client.put("/api/admin/settings", headers=h, json={"sessionHours": 720, "idleMinutes": 2}).status_code == 200
    assert c.db.get_setting("session_hours") == 8 and c.db.get_setting("idle_minutes") == 5
    assert client.put("/api/admin/settings", headers=h, json={"sessionHours": 0.2, "idleMinutes": 0}).status_code == 200
    assert c.db.get_setting("session_hours") == 1 and c.db.get_setting("idle_minutes") == 0
    assert client.put("/api/admin/settings", headers=h, json={"sessionHours": "soon"}).status_code == 200
    assert c.db.get_setting("session_hours") == 8


def test_old_sign_ins_are_cut_at_start_up(gw):
    client, c = gw
    ann = mk_user(c.db, "ann")
    now = time.time()

    def stored(created, expires):
        token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password")
        h = auth_mod.security.token_hash(token)
        c.db.execute("UPDATE auth_sessions SET created_at=?, expires_at=? WHERE token_hash=?", (created, expires, h))
        return token, h

    old, old_h = stored(now - 3 * 86400, now + 27 * 86400)          # "keep me signed in", three days ago
    new, new_h = stored(now - 3600, now + 29 * 86400)               # the same, one hour ago
    fine, fine_h = stored(now - 600, now - 600 + 2 * 3600)          # a short one of today
    assert c.auth.resolve_cookie(old) is not None                   # an earlier version would accept it
    assert c.auth.clamp_sessions() == 2
    assert c.auth.resolve_cookie(old) is None
    assert c.db.one("SELECT 1 AS x FROM auth_sessions WHERE token_hash=?", (old_h,)) is None
    row = c.db.one("SELECT * FROM auth_sessions WHERE token_hash=?", (new_h,))
    assert abs(row["expires_at"] - (row["created_at"] + 8 * 3600)) < 1 and c.auth.resolve_cookie(new) is not None
    assert abs(c.db.one("SELECT * FROM auth_sessions WHERE token_hash=?", (fine_h,))["expires_at"] - (now - 600 + 7200)) < 1
    assert c.auth.clamp_sessions() == 0                             # nothing left over the limit
    # a shorter lifetime set by the administrator holds for the sign-ins that exist
    admin = mk_user(c.db, "boss", role="admin")
    h = sign_in(client, c, admin)
    assert client.put("/api/admin/settings", headers=h, json={"sessionHours": 1}).status_code == 200
    row = c.db.one("SELECT * FROM auth_sessions WHERE token_hash=?", (new_h,))
    assert row is None or row["expires_at"] <= row["created_at"] + 3600 + 1


def test_an_unused_sign_in_ends_when_an_idle_limit_is_set(gw):
    client, c = gw
    ann = mk_user(c.db, "ann")
    token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password")
    h = auth_mod.security.token_hash(token)
    now = time.time()
    c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now - 31 * 60, h))
    assert c.auth.idle_seconds() == 0 and c.auth.resolve_cookie(token) is not None      # off by default
    c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now - 31 * 60, h))
    c.db.set_setting("idle_minutes", 30)
    assert c.auth.idle_seconds() == 1800
    assert c.auth.resolve_cookie(token) is None                                           # refused ...
    assert c.db.one("SELECT 1 AS x FROM auth_sessions WHERE token_hash=?", (h,)) is None  # ... and ended on the server
    # used in time: it stays, and the use is written down early enough for the limit to see it
    token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password")
    h = auth_mod.security.token_hash(token)
    c.db.set_setting("idle_minutes", 5)
    c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now - 100, h))    # > 300/4 s ago
    assert c.auth.resolve_cookie(token) is not None
    assert c.db.one("SELECT last_seen FROM auth_sessions WHERE token_hash=?", (h,))["last_seen"] >= now - 1


def test_an_open_tab_counts_as_use(gw):
    """Review 20261119_5, R-1: chatting goes over the WebSocket, not over requests. The 30-second re-check of an
    open tab's connection therefore marks the sign-in as used - or somebody who had chatted for longer than the
    idle limit was signed out by their next upload."""
    from pathlib import Path
    import goose_web
    client, c = gw
    ann = mk_user(c.db, "ann")
    token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password")
    h = auth_mod.security.token_hash(token)
    c.db.set_setting("idle_minutes", 5)
    now = time.time()
    for _ in range(3):      # three re-checks, each 4 minutes after the last use: never idle
        c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now - 240, h))
        row = c.auth.session_alive(h)
        assert row is not None and row["token_hash"] == h
        assert c.db.one("SELECT last_seen FROM auth_sessions WHERE token_hash=?", (h,))["last_seen"] >= now - 1
    assert c.auth.resolve_cookie(token) is not None                 # the next request (an upload) finds it alive
    c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now - 301, h))
    assert c.auth.session_alive(h) is None and c.auth.session_alive(h) is None and c.auth.session_alive("nope") is None
    app_src = (Path(goose_web.__file__).parent / "app.py").read_text(encoding="utf-8")
    still = app_src.split("    def still_valid() -> bool:", 1)[1].split("    try:\n        rights =", 1)[0]
    assert "row = c.auth.session_alive(session_hash)" in still and "FROM auth_sessions" not in still


def test_check_says_how_long_a_sign_in_lasts(tmp_path):
    from pathlib import Path
    from goose_web import __main__ as cli
    from goose_web.config import Settings, _deep_merge
    from goose_web.db import Database
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path)}, "auth": {"session_hours": 12}}), None)
    lines = cli._signin_lines(s)
    assert lines[0][0] == "--" and "lasts 8 h" in lines[0][1] and "no idle limit" in lines[0][1]
    assert lines[1][0] == "!!" and "12 hours is configured, the limit is 8" in lines[1][1]
    Path(s.system_dir).mkdir(parents=True, exist_ok=True)
    db = Database(Path(s.system_dir) / "goose-web.db")
    try:
        db.set_setting("session_hours", 4)
        db.set_setting("idle_minutes", 45)
    finally:
        db.close()
    lines = cli._signin_lines(s)
    assert len(lines) == 1 and "lasts 4 h" in lines[0][1] and "ends after 45 min" in lines[0][1]


def test_the_sign_in_page_has_no_keep_me_signed_in():
    from pathlib import Path
    import goose_web
    js = Path(goose_web.__file__).parent / "static" / "js" / "views"
    login = (js / "login.js").read_text(encoding="utf-8")
    assert "Keep me signed in" not in login.replace('no "Keep me signed in"', "") and "remember" not in login
    assert "{ username: user.value.trim(), password: pass.value }" in login
    admin = (js / "admin.js").read_text(encoding="utf-8")
    assert "max: '720'" not in admin and "idleMinutes: Number(idle.value) || 0" in admin
    api_src = (Path(goose_web.__file__).parent / "api.py").read_text(encoding="utf-8")
    assert "max_age" not in api_src.split("def _set_cookie", 1)[1].split("\n\n\n", 1)[0]
