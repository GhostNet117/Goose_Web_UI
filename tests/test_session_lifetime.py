"""Spec 032 (1.25.0): a sign-in lasts eight hours at most and there is no "keep me signed in".
Spec 037: "Keep me signed in" is back, for 24 hours at most.

A copied sign-in cookie works for as long as the sign-in lives, and this product starts programs for whoever is
signed in. So: one fixed lifetime (auth.session_hours, 1 to 8, never extended), a session cookie (the browser is
not asked to keep it), sign-ins of earlier versions cut at start-up, and an optional idle limit (off by default).
Spec 037: a sign-in with "Keep me signed in" ticked has a cookie the browser keeps, for auth.remember_hours (default
24, 0 = no checkbox, never more than 24), also fixed at sign-in and never extended; each stored sign-in knows its kind,
so the start-up cut holds each kind to its own limit."""
import base64
import json
import sqlite3
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import goose_web
from goose_web import auth as auth_mod
from goose_web import security
from goose_web.config import DEFAULTS, REMOVED_SETTINGS, unknown_settings
from goose_web.db import Database
from test_sec_web import PW, build, mk_user, sign_in

ORIGIN = {"Origin": "http://testserver"}
JS = Path(goose_web.__file__).parent / "static" / "js" / "views"


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
    got = unknown_settings({"auth": {"remember_days": 30, "session_hours": 8, "sesion_hours": 4, "remember_hours": 12}})
    # spec 037: still unknown, and the sentence now points to the setting that replaced it
    assert got[0].startswith("auth.remember_days (removed in 1.25.0") and "auth.remember_hours" in got[0]
    assert "24 hours at most" in got[0]
    assert got[1:] == ["auth.sesion_hours"]                           # remember_hours is a setting again


def test_a_normal_sign_in_sets_a_session_cookie(gw):
    """Spec 032 asserted that `remember` changes nothing; since spec 037 only `remember: true` does. Without it (or
    with anything that is not true) the cookie is a session cookie and the sign-in lasts the normal lifetime."""
    client, c = gw
    mk_user(c.db, "ann")
    for extra in ({}, {"remember": False}, {"remember": "yes"}, {"remember": 1}):
        c.db.execute("DELETE FROM auth_sessions")
        t0 = time.time()
        r = client.post("/api/auth/login", json={"username": "ann", "password": PW, **extra}, headers=ORIGIN)
        assert r.status_code == 200, r.text
        cookie = r.headers["set-cookie"]
        low = cookie.lower()
        assert "max-age" not in low and "expires" not in low             # the browser is not asked to keep it
        assert "httponly" in low and "samesite=strict" in low and "path=/" in low
        row = c.db.one("SELECT * FROM auth_sessions")
        assert 8 * 3600 - 5 <= row["expires_at"] - t0 <= 8 * 3600 + 5    # not 24 hours, not 30 days
        assert row["remember"] == 0
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


def test_a_remember_hours_that_is_not_a_number_is_refused_and_nothing_is_written(gw):
    """M-4 (assessment 2026-11-24): "soon" used to be stored as the 24-hour maximum. Now 400, and the other values of
    the same request are not written either."""
    client, c = gw
    admin = mk_user(c.db, "boss", role="admin")
    h = sign_in(client, c, admin)
    assert client.put("/api/admin/settings", headers=h, json={"rememberHours": 6}).status_code == 200
    for bad in ("soon", None, "", True, float("nan")):
        body = {"rememberHours": bad, "idleMinutes": 30, "retentionDays": 9}
        r = client.put("/api/admin/settings", headers={**h, "content-type": "application/json"},
                       content=json.dumps(body, allow_nan=True))   # NaN is not valid JSON for json=: send it raw
        assert r.status_code == 400 and r.json()["error"] == "bad_request", (bad, r.text)
        assert c.db.get_setting("remember_hours") == 6 and c.db.get_setting("idle_minutes") in (None, 0)
        assert c.db.get_setting("retention_days") is None
    assert client.put("/api/admin/settings", headers=h, json={"rememberHours": 99}).status_code == 200
    assert c.db.get_setting("remember_hours") == 24   # above the limit: stored as the limit (unchanged rule)


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


def test_the_sign_in_page_offers_keep_me_signed_in_off_by_default():
    """Spec 032 asserted that the page had no checkbox; spec 037 brings it back: unchecked, labelled with the
    administrator's lifetime, not there at all when the administrator switched it off (rememberHours 0), and
    `remember: true` is sent only when it is ticked (again with the two-factor code, the body is built each time)."""
    login = (JS / "login.js").read_text(encoding="utf-8")
    assert "const keepHours = Number(cfg.rememberHours) || 0;" in login
    assert "h('input', { type: 'checkbox', checked: false, 'data-remember': '1' })" in login
    assert "const keepField = keepHours > 0 ? h('label'" in login and "'Keep me signed in ('" in login
    assert "credFields, totpField, keepField, err, submit" in login
    form = login.split("form.addEventListener('submit'", 1)[1].split("const res = await POST", 1)[0]
    assert "const body = { username: user.value.trim(), password: pass.value };" in form
    assert "if (keepField && remember.checked) body.remember = true;" in form
    assert form.index("body.remember = true") < form.index("body.totp =")
    admin = (JS / "admin.js").read_text(encoding="utf-8")
    assert "max: '720'" not in admin and "idleMinutes: Number(idle.value) || 0" in admin
    assert "const remMax = Number(s.rememberHoursMax) || 24;" in admin
    assert "field('Keep me signed in lasts (hours)', rem," in admin
    assert "rememberHours: rem.value.trim() === '' ? remMax : Math.max(0, Math.min(remMax, Number(rem.value) || 0))" in admin
    settings = (JS / "settings.js").read_text(encoding="utf-8")
    assert "l.remembered ? [' ', h('span', { class: 'badge'" in settings     # Active sign-ins mark the kept ones
    api_src = (Path(goose_web.__file__).parent / "api.py").read_text(encoding="utf-8")
    cookie = api_src.split("def _set_cookie", 1)[1].split("\n\n\n", 1)[0]
    assert "if max_age > 0:" in cookie and cookie.count("samesite=\"strict\"") == 2 and cookie.count("httponly=True") == 2


# ====================================================================== spec 037: "Keep me signed in", 24 h at most
def test_keep_me_signed_in_lasts_24_hours_at_most():
    c = auth_mod.clamp_remember_hours
    assert auth_mod.REMEMBER_HOURS_MAX == 24
    assert [c(x) for x in (24, 25, 720, 12, "2.5", 0, "0", -3, None, "", "x", float("nan"), float("inf"))] == \
        [24, 24, 24, 12, 2.5, 0, 0, 0, 24, 24, 24, 24, 24]
    assert DEFAULTS["auth"]["remember_hours"] == 24


def _kept(client, c, user="ann", **extra):
    r = client.post("/api/auth/login", json={"username": user, "password": PW, "remember": True, **extra},
                    headers=ORIGIN)
    return r, r.headers.get("set-cookie", "")


def test_a_remembered_sign_in_has_a_cookie_the_browser_keeps(gw):
    client, c = gw
    mk_user(c.db, "ann")
    t0 = time.time()
    r, cookie = _kept(client, c)
    assert r.status_code == 200, r.text
    low = cookie.lower()
    assert f"max-age={24 * 3600}" in low and "expires=" in low            # survives closing the browser
    assert "httponly" in low and "samesite=strict" in low and "path=/" in low and "secure" not in low   # plain http
    row = c.db.one("SELECT * FROM auth_sessions")
    assert row["remember"] == 1 and 24 * 3600 - 5 <= row["expires_at"] - t0 <= 24 * 3600 + 5
    assert row["token_hash"] != cookie.split("=", 1)[1].split(";", 1)[0]  # stored as a hash only
    assert c.db.one("SELECT * FROM audit WHERE action='auth.login' ORDER BY id DESC")["detail"] == {"remember": True}
    me = client.get("/api/me/logins").json()
    assert me[0]["remembered"] is True and abs(me[0]["expiresAt"] - row["expires_at"]) < 1
    # the administrator's lifetime counts, not 24 by itself; fixed at sign-in, never extended by use
    c.db.set_setting("remember_hours", 3)
    c.db.execute("DELETE FROM auth_sessions")
    r, cookie = _kept(client, c)
    assert f"max-age={3 * 3600}" in cookie.lower()
    row = c.db.one("SELECT * FROM auth_sessions")
    c.db.execute("UPDATE auth_sessions SET last_seen=?", (time.time() - 3600,))
    assert client.get("/api/me/logins").status_code == 200                 # used: last_seen moves, expiry does not
    after = c.db.one("SELECT * FROM auth_sessions")
    assert after["expires_at"] == row["expires_at"] and after["last_seen"] > row["last_seen"] - 1
    # over HTTPS the kept cookie is Secure like the session cookie
    https, hc = build(Path(c.settings.system_dir).parent / "https", public_url="https://goose.example.org")
    with TestClient(https, base_url="https://goose.example.org") as tc:
        mk_user(hc.db, "ann")
        r = tc.post("/api/auth/login", json={"username": "ann", "password": PW, "remember": True},
                    headers={"Origin": "https://goose.example.org"})
        assert r.status_code == 200 and "secure" in r.headers["set-cookie"].lower()
        assert r.headers["set-cookie"].startswith("__Host-gw=") and "max-age=86400" in r.headers["set-cookie"].lower()
    hc.db.close()


def test_two_factor_still_applies_to_a_remembered_sign_in(gw):
    client, c = gw
    ann = mk_user(c.db, "ann")
    secret = base64.b32encode(b"12345678901234567890").decode()
    c.db.update_user(ann["id"], totp_secret=secret, totp_enabled=1)
    r, cookie = _kept(client, c)
    assert r.status_code == 401 and r.json()["error"] == "totp_required" and not cookie
    assert c.db.one("SELECT COUNT(*) AS n FROM auth_sessions")["n"] == 0
    r, cookie = _kept(client, c, totp=security.totp(secret))
    assert r.status_code == 200 and f"max-age={24 * 3600}" in cookie.lower()
    assert c.db.one("SELECT remember FROM auth_sessions")["remember"] == 1


def test_keep_me_signed_in_switched_off_is_a_normal_sign_in(gw):
    client, c = gw
    mk_user(c.db, "ann")
    assert client.get("/api/auth/config").json()["rememberHours"] == 24
    c.db.set_setting("remember_hours", 0)
    assert client.get("/api/auth/config").json()["rememberHours"] == 0      # the page shows no checkbox
    t0 = time.time()
    r, cookie = _kept(client, c)                                              # an old page still sends it
    assert r.status_code == 200 and "max-age" not in cookie.lower() and "expires" not in cookie.lower()
    row = c.db.one("SELECT * FROM auth_sessions")
    assert row["remember"] == 0 and row["expires_at"] - t0 <= 8 * 3600 + 5
    assert c.db.one("SELECT * FROM audit WHERE action='auth.login' ORDER BY id DESC")["detail"] == {}


def test_check_reports_both_lifetimes(tmp_path):
    from goose_web import __main__ as cli
    from goose_web.config import Settings, _deep_merge
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path)}, "auth": {"remember_hours": 48}}), None)
    lines = cli._signin_lines(s)
    assert "lasts 8 h" in lines[0][1] and "\"keep me signed in\" lasts 24 h (auth.remember_hours)" in lines[0][1]
    assert ("!!", "keep me signed in: 48 hours is configured, the limit is 24 - 24 is used") in lines
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path)}, "auth": {"remember_hours": "soon"}}), None)
    assert ("!!", "keep me signed in: 'soon' is not a number of hours - 24 is used") in cli._signin_lines(s)
    Path(s.system_dir).mkdir(parents=True, exist_ok=True)
    db = Database(Path(s.system_dir) / "goose-web.db")
    try:
        db.set_setting("remember_hours", 0)          # Admin > Settings wins over the file
    finally:
        db.close()
    lines = cli._signin_lines(s)
    assert len(lines) == 1 and "no \"keep me signed in\" (auth.remember_hours is 0)" in lines[0][1]


def test_start_up_cuts_each_kind_to_its_own_limit(gw):
    client, c = gw
    ann = mk_user(c.db, "ann")
    now = time.time()

    def stored(created, expires, remember):
        token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password", remember=remember)
        h = auth_mod.security.token_hash(token)
        c.db.execute("UPDATE auth_sessions SET created_at=?, expires_at=? WHERE token_hash=?", (created, expires, h))
        return token, h

    _, kept_old = stored(now - 30 * 3600, now + 10 * 3600, True)      # kept 30 h ago, over 24: ends
    _, kept_new = stored(now - 3600, now + 47 * 3600, True)           # kept an hour ago with 48 h: cut to 24
    _, normal = stored(now - 3600, now + 23 * 3600, False)            # a normal one with 24 h: cut to 8
    _, kept_ok = stored(now - 600, now - 600 + 24 * 3600, True)       # a kept one within the limit: untouched
    assert c.auth.clamp_sessions() == 3
    row = lambda h: c.db.one("SELECT * FROM auth_sessions WHERE token_hash=?", (h,))   # noqa: E731
    assert row(kept_old) is None
    assert abs(row(kept_new)["expires_at"] - (row(kept_new)["created_at"] + 24 * 3600)) < 1
    assert abs(row(normal)["expires_at"] - (row(normal)["created_at"] + 8 * 3600)) < 1
    assert abs(row(kept_ok)["expires_at"] - (now - 600 + 24 * 3600)) < 1
    assert c.auth.clamp_sessions() == 0
    # lowering the remembered lifetime shortens the kept ones only - in Admin > Settings at once, and at every start
    admin = mk_user(c.db, "boss", role="admin")
    h = sign_in(client, c, admin)
    assert client.put("/api/admin/settings", headers=h, json={"rememberHours": 2}).status_code == 200
    assert row(kept_new) is not None and row(kept_new)["expires_at"] <= row(kept_new)["created_at"] + 2 * 3600 + 1
    assert row(kept_ok)["expires_at"] <= now - 600 + 2 * 3600 + 1
    assert abs(row(normal)["expires_at"] - (row(normal)["created_at"] + 8 * 3600)) < 1
    # switching "keep me signed in" off ends the kept ones; the normal ones stay
    c.db.set_setting("remember_hours", 0)
    assert c.auth.clamp_sessions() == 2
    assert row(kept_new) is None and row(kept_ok) is None and row(normal) is not None
    assert client.get("/api/admin/settings").status_code == 200           # the administrator's own normal sign-in


def test_the_idle_limit_applies_to_remembered_sign_ins(gw):
    client, c = gw
    ann = mk_user(c.db, "ann")
    token, _ = c.auth.create_session(ann, "127.0.0.1", "pytest", "password", remember=True)
    h = auth_mod.security.token_hash(token)
    assert c.db.one("SELECT remember FROM auth_sessions WHERE token_hash=?", (h,))["remember"] == 1
    c.db.set_setting("idle_minutes", 30)
    c.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (time.time() - 31 * 60, h))
    assert c.auth.resolve_cookie(token) is None
    assert c.db.one("SELECT 1 AS x FROM auth_sessions WHERE token_hash=?", (h,)) is None


def test_admin_settings_hold_the_remembered_limit(gw):
    client, c = gw
    admin = mk_user(c.db, "boss", role="admin")
    h = sign_in(client, c, admin)
    s = client.get("/api/admin/settings").json()
    assert s["rememberHours"] == 24 and s["rememberHoursMax"] == 24
    for sent, kept in ((99, 24), (12, 12), (0.2, 1), (-3, 0), (0, 0), (24, 24)):
        assert client.put("/api/admin/settings", headers=h, json={"rememberHours": sent}).status_code == 200
        assert c.db.get_setting("remember_hours") == kept, sent
        assert client.get("/api/admin/settings").json()["rememberHours"] == kept
    for sent in ("soon", None):   # M-4: not a number = 400 (it used to be stored as 24); the stored value stays
        assert client.put("/api/admin/settings", headers=h, json={"rememberHours": sent}).status_code == 400
        assert c.db.get_setting("remember_hours") == 24
    # a member cannot change it
    bob = mk_user(c.db, "bob")
    hb = sign_in(client, c, bob)
    assert client.put("/api/admin/settings", headers=hb, json={"rememberHours": 0}).status_code == 403


def test_an_older_database_gets_the_remember_column(tmp_path):
    """Spec 037, additive: a database of 1.26 has auth_sessions without `remember`; opening it adds the column and the
    sign-ins already there count as normal ones (so the start-up cut holds them to the normal lifetime)."""
    f = tmp_path / "old.db"
    con = sqlite3.connect(f)
    con.executescript(
        "CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL,"
        " created_at REAL NOT NULL, expires_at REAL NOT NULL, last_seen REAL NOT NULL, ip TEXT NOT NULL DEFAULT '',"
        " user_agent TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT 'password');"
        "INSERT INTO auth_sessions VALUES('h', 1, 'c', 0, 1e12, 0, '', '', 'password');")
    con.close()
    db = Database(f)
    try:
        assert db.one("SELECT remember FROM auth_sessions WHERE token_hash='h'")["remember"] == 0
        db.execute("INSERT INTO auth_sessions(token_hash, user_id, csrf, created_at, expires_at, last_seen)"
                   " VALUES('n', 1, 'c', 0, 1e12, 0)")
        assert db.one("SELECT remember FROM auth_sessions WHERE token_hash='n'")["remember"] == 0   # the default
    finally:
        db.close()
