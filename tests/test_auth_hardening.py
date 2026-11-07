"""Auth hardening: TOTP replay/lockout, self-enrolment setting, OIDC (iss, sub) binding, LDAP transport,
API-token revocation, string-built SQL allow-lists, audit retention and the additive DB migration."""
import base64
import copy
import json
import sqlite3
import time
import types
import urllib.parse
from pathlib import Path

import httpx
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from goose_web import api, security
from goose_web import auth as auth_mod
from goose_web.auth import AuthError, AuthService, LDAP_INSECURE_MESSAGE
from goose_web.config import DEFAULTS, Settings
from goose_web.context import Ctx, HTTPError
from goose_web.db import AUDIT_RETENTION_DAYS, Database

PW = "Blue-Kettle-42"


# ---------------------------------------------------------------- fixtures / helpers
@pytest.fixture
def env(tmp_path):
    data = copy.deepcopy(DEFAULTS)
    data["auth"]["lockout_threshold"] = 3
    settings = Settings(data, None)
    db = Database(tmp_path / "gw.db")
    yield settings, db, AuthService(db, settings)
    db.close()


def mk_user(db, name, role="user", source="local", password=PW, **extra) -> dict:
    uid = db.create_user(username=name, display_name=name, role=role, auth_source=source,
                         password_hash=security.hash_password(password) if password else None, **extra)
    return db.user_by_id(uid)


def with_totp(db, user) -> tuple[dict, str]:
    secret = security.new_totp_secret()
    db.update_user(user["id"], totp_secret=secret, totp_enabled=1)
    return db.user_by_id(user["id"]), secret


class FakeProfiles:
    def __init__(self, root: Path):
        self.root = root

    def is_native(self, user):
        return True

    def root_for(self, user):
        return self.root / user["username"]


@pytest.fixture
def web(env, tmp_path):
    settings, db, auth = env

    async def on_http_error(request, exc):
        return exc.response()

    app = Starlette(routes=api.routes, exception_handlers={HTTPError: on_http_error})
    app.state.ctx = Ctx(settings=settings, db=db, auth=auth, profiles=FakeProfiles(tmp_path), workers=None,
                        hub=None, version="test")
    with TestClient(app) as client:
        yield client, settings, db, auth


def sign_in(client, auth, user) -> dict:
    """Create a cookie session directly; returns headers carrying its CSRF token."""
    token, csrf = auth.create_session(user, "127.0.0.1", "pytest", "password")
    client.cookies.set("gw", token)
    return {"x-csrf-token": csrf}


def token_count(db, uid) -> int:
    return db.one("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id=?", (uid,))["n"]


# ---------------------------------------------------------------- 1. TOTP replay (GW-14)
def test_totp_match_rejects_used_or_older_counters():
    secret = base64.b32encode(b"12345678901234567890").decode()
    code = security.totp(secret, at=59)                      # counter 1
    assert security.totp_match(secret, code, at=59) == 1
    assert security.totp_match(secret, code, at=59, last_counter=0) == 1
    assert security.totp_match(secret, code, at=59, last_counter=1) is None   # replay
    assert security.totp_match(secret, code, at=59, last_counter=5) is None   # older than last use
    assert not security.verify_totp(secret, code, at=59, last_counter=1)
    assert security.totp_match("not base32 !!", "123456") is None


def test_login_totp_code_cannot_be_replayed(env):
    _, db, auth = env
    user, secret = with_totp(db, mk_user(db, "alice"))
    code = security.totp(secret)
    assert auth.login("alice", PW, code, "1.1.1.1")["id"] == user["id"]
    assert db.user_by_id(user["id"])["totp_last_counter"] >= int(time.time() // 30) - 1
    with pytest.raises(AuthError) as e:
        auth.login("alice", PW, code, "1.1.1.1")
    assert e.value.code == "totp_invalid"
    # the next time step's code (inside the +1 window) is still accepted, once
    nxt = security.totp(secret, time.time() + 30)
    assert auth.login("alice", PW, nxt, "1.1.1.1")["id"] == user["id"]


def test_totp_enrolment_code_cannot_be_replayed_at_login(web):
    client, _, db, auth = web
    user = mk_user(db, "bob")
    h = sign_in(client, auth, user)
    secret = client.post("/api/me/totp/setup", headers=h).json()["secret"]
    code = security.totp(secret)
    assert client.post("/api/me/totp/enable", headers=h, json={"code": code}).status_code == 200
    with pytest.raises(AuthError) as e:
        auth.login("bob", PW, code, "1.1.1.1")
    assert e.value.code == "totp_invalid"


# ---------------------------------------------------------------- 2. TOTP failures count toward lockout
def test_failed_totp_codes_lock_the_account(env):
    _, db, auth = env  # lockout_threshold = 3
    user, secret = with_totp(db, mk_user(db, "carol"))
    bad = "000000" if security.totp(secret) != "000000" else "111111"
    for _ in range(2):
        with pytest.raises(AuthError):
            auth.login("carol", PW, bad, "1.1.1.1")
    assert db.user_by_id(user["id"])["failed_logins"] == 2
    with pytest.raises(AuthError):
        auth.login("carol", PW, bad, "1.1.1.1")
    assert db.user_by_id(user["id"])["locked_until"] > time.time()
    with pytest.raises(AuthError) as e:
        auth.login("carol", PW, security.totp(secret), "1.1.1.1")
    assert e.value.code == "locked"


def test_password_and_totp_failures_share_one_counter(env):
    _, db, auth = env
    user, secret = with_totp(db, mk_user(db, "dave"))
    for _ in range(2):
        with pytest.raises(AuthError):
            auth.login("dave", "Wrong-Password-1", None, "1.1.1.1")
    with pytest.raises(AuthError):
        auth.login("dave", PW, "000000" if security.totp(secret) != "000000" else "111111", "1.1.1.1")
    assert db.user_by_id(user["id"])["locked_until"] > time.time()


def test_missing_totp_step_is_not_a_failure(env):
    _, db, auth = env
    user, _ = with_totp(db, mk_user(db, "erin"))
    with pytest.raises(AuthError) as e:
        auth.login("erin", PW, None, "1.1.1.1")
    assert e.value.code == "totp_required"
    assert db.user_by_id(user["id"])["failed_logins"] == 0


# ---------------------------------------------------------------- 3. allow_self_totp
def test_totp_setup_honours_allow_self_totp(web):
    client, _, db, auth = web
    db.set_setting("allow_self_totp", False)
    user = mk_user(db, "frank")
    h = sign_in(client, auth, user)
    r = client.post("/api/me/totp/setup", headers=h)
    assert r.status_code == 403 and r.json()["error"] == "totp_self_disabled"
    assert client.post("/api/me/totp/enable", headers=h, json={"code": "123456"}).status_code == 403
    admin = mk_user(db, "root", role="admin")
    h = sign_in(client, auth, admin)
    assert client.post("/api/me/totp/setup", headers=h).status_code == 200   # admins always can
    db.set_setting("allow_self_totp", True)
    h = sign_in(client, auth, user)
    assert client.post("/api/me/totp/setup", headers=h).status_code == 200


# ---------------------------------------------------------------- 4. requireTotpForAdmins (safe parts)
def test_require_totp_for_admins_needs_own_totp_first(web):
    client, _, db, auth = web
    admin = mk_user(db, "root", role="admin")
    h = sign_in(client, auth, admin)
    r = client.put("/api/admin/settings", headers=h,
                   json={"requireTotpForAdmins": True, "brand": {"name": "Changed"}})
    assert r.status_code == 409 and r.json()["error"] == "totp_needed_first"
    assert not db.get_setting("require_totp_admins") and db.get_setting("brand") is None  # nothing written
    db.update_user(admin["id"], totp_enabled=1, totp_secret=security.new_totp_secret())
    assert client.put("/api/admin/settings", headers=h, json={"requireTotpForAdmins": True}).status_code == 200
    assert db.get_setting("require_totp_admins") is True


def test_totp_enrolment_required_flag(web):
    client, _, db, auth = web
    admin = mk_user(db, "root", role="admin")
    user = mk_user(db, "gina")
    assert not auth.totp_enrolment_required(admin)
    db.set_setting("require_totp_admins", True)
    assert auth.totp_enrolment_required(admin)
    assert not auth.totp_enrolment_required(user)
    r = client.post("/api/auth/login", json={"username": "root", "password": PW})
    assert r.status_code == 200 and r.json()["totpEnrolmentRequired"] is True   # sign-in still allowed
    admin, _ = with_totp(db, admin)
    assert not auth.totp_enrolment_required(admin)


# ---------------------------------------------------------------- 5. OIDC binding by (iss, sub) (GW-12)
ISSUER = "https://idp.example.org"


def _jwt(claims: dict) -> str:
    return "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"


@pytest.fixture
def oidc(env, monkeypatch):
    _, db, auth = env
    auth.save_auth_config({"oidc": [{"id": "corp", "issuer": ISSUER, "clientId": "gw", "clientSecret": "s"}]})
    meta = {"authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token"}

    async def discovery(o):
        return meta

    monkeypatch.setattr(auth, "_oidc_discovery", discovery)
    current: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id_token": _jwt(current)})

    def client_factory(**kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(auth_mod, "httpx", types.SimpleNamespace(AsyncClient=client_factory,
                                                                 HTTPError=httpx.HTTPError))

    async def sign_in_as(sub: str, username: str, iss: str = ISSUER):
        url = await auth.oidc_start("corp", "http://gw/cb")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        current.clear()
        current.update({"iss": iss, "aud": "gw", "exp": time.time() + 300, "nonce": q["nonce"][0],
                        "sub": sub, "preferred_username": username})
        return await auth.oidc_callback("corp", "code", q["state"][0], "http://gw/cb", "1.1.1.1")

    return db, sign_in_as


async def test_oidc_new_user_is_bound_and_found_by_subject(oidc):
    db, sign_in_as = oidc
    u = await sign_in_as("sub-1", "hank@example.org")
    assert u["username"] == "hank" and (u["oidc_issuer"], u["oidc_subject"]) == (ISSUER, "sub-1")
    # renamed at the IdP: still the same account, because (iss, sub) wins over the username
    u2 = await sign_in_as("sub-1", "henry@example.org")
    assert u2["id"] == u["id"] and db.user_by_name("henry") is None


async def test_oidc_existing_unbound_user_is_bound_on_first_sign_in(oidc):
    db, sign_in_as = oidc
    legacy = mk_user(db, "ivy", source="oidc", password=None)
    assert legacy["oidc_subject"] is None
    u = await sign_in_as("sub-ivy", "ivy")
    assert u["id"] == legacy["id"] and u["oidc_subject"] == "sub-ivy"
    assert db.one("SELECT 1 AS x FROM audit WHERE action='user.oidc.bind'")


async def test_oidc_same_username_different_subject_is_refused(oidc):
    db, sign_in_as = oidc
    first = await sign_in_as("sub-a", "jack")
    with pytest.raises(AuthError) as e:
        await sign_in_as("sub-b", "jack")      # another person claiming the same preferred_username
    assert e.value.code == "oidc_conflict"
    assert db.user_by_id(first["id"])["oidc_subject"] == "sub-a"


async def test_oidc_cannot_take_over_local_or_ldap_users(oidc):
    db, sign_in_as = oidc
    mk_user(db, "kate")
    mk_user(db, "liam", source="ldap", password=None)
    for name in ("kate", "liam"):
        with pytest.raises(AuthError) as e:
            await sign_in_as(f"sub-{name}", name)
        assert e.value.code == "oidc_conflict"


async def test_oidc_bound_user_switched_to_local_is_protected(oidc):
    db, sign_in_as = oidc
    u = await sign_in_as("sub-m", "mia")
    db.update_user(u["id"], auth_source="local")
    with pytest.raises(AuthError) as e:
        await sign_in_as("sub-m", "mia")
    assert e.value.code == "oidc_conflict"


# ---------------------------------------------------------------- 6. LDAP cleartext (GW-13)
LDAP_BASE = {"enabled": True, "url": "ldap://dc.example.org", "bindDn": "cn=svc", "bindPassword": "secret",
             "userBase": "dc=example,dc=org"}


def test_ldap_plain_url_is_refused_at_save_with_fix_hint(env):
    _, db, auth = env
    with pytest.raises(ValueError) as e:
        auth.save_auth_config({"ldap": dict(LDAP_BASE)})
    assert "ldaps://" in str(e.value) and "StartTLS" in str(e.value) and "allowInsecure" in str(e.value)
    for ok in ({"url": "ldaps://dc.example.org"}, {"startTls": True}, {"allowInsecure": True}):
        auth.save_auth_config({"ldap": {**LDAP_BASE, "startTls": False, "allowInsecure": False, **ok}})
    masked = auth.masked_auth_config()["ldap"]
    assert masked["allowInsecure"] is True and masked["bindPassword"] == auth_mod.MASK
    # a masked round-trip (what the admin UI sends back) keeps the flag and the secret
    auth.save_auth_config({"ldap": masked})
    assert auth.auth_config()["ldap"]["allowInsecure"] is True
    assert auth.auth_config()["ldap"]["bindPassword"] == "secret"
    assert auth_mod.DEFAULT_AUTH["ldap"]["allowInsecure"] is False      # secure by default


def test_ldap_plain_url_refused_at_login_without_binding(env, monkeypatch):
    _, db, auth = env
    import ldap3
    calls = []

    def fake_server(*a, **k):
        calls.append(a)
        raise OSError("no network in tests")

    monkeypatch.setattr(ldap3, "Server", fake_server)
    db.set_setting("auth", {"ldap": dict(LDAP_BASE)})          # config saved before this check existed
    with pytest.raises(AuthError) as e:
        auth.login("nina", "Some-Password-1", None, "1.1.1.1")
    assert e.value.code == "ldap_insecure" and e.value.status == 503 and calls == []
    assert db.one("SELECT detail FROM audit WHERE action='auth.ldap'")["detail"]["fix"] == LDAP_INSECURE_MESSAGE
    db.set_setting("auth", {"ldap": {**LDAP_BASE, "allowInsecure": True}})   # explicit opt-in: bind is tried
    with pytest.raises(AuthError) as e:
        auth.login("nina", "Some-Password-1", None, "1.1.1.1")
    assert e.value.code == "invalid_credentials" and len(calls) == 1


def test_admin_auth_endpoint_reports_ldap_fix(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "root", role="admin"))
    r = client.put("/api/admin/auth", headers=h, json={"ldap": dict(LDAP_BASE)})
    assert r.status_code == 400 and r.json()["error"] == "bad_config" and "allowInsecure" in r.json()["message"]


# ---------------------------------------------------------------- 7. API tokens revoked (GW-21)
def test_admin_reset_and_disable_revoke_api_tokens(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "root", role="admin"))
    u = mk_user(db, "olga")
    auth.create_api_token(u, "t1", None)
    assert client.post(f"/api/admin/users/{u['id']}/reset-password", headers=h).status_code == 200
    assert token_count(db, u["id"]) == 0
    auth.create_api_token(u, "t2", None)
    assert client.patch(f"/api/admin/users/{u['id']}", headers=h, json={"password": "Another-Pass-77"}).status_code == 200
    assert token_count(db, u["id"]) == 0
    auth.create_api_token(u, "t3", None)
    assert client.patch(f"/api/admin/users/{u['id']}", headers=h, json={"disabled": True}).status_code == 200
    assert token_count(db, u["id"]) == 0


def session_count(db, uid) -> int:
    return db.one("SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?", (uid,))["n"]


# ---------------------------------------------------------------- 8. admin "Reset two-factor" (lost authenticator)
def test_admin_reset_totp_clears_two_factor_and_signs_out(web):
    client, _, db, auth = web
    admin = mk_user(db, "root", role="admin")
    user, secret = with_totp(db, mk_user(db, "quinn"))
    db.update_user(user["id"], totp_last_counter=123, failed_logins=5, locked_until=time.time() + 900)
    auth.create_session(user, "1.1.1.1", "phone", "password")
    auth.create_api_token(user, "t", None)
    h = sign_in(client, auth, admin)
    r = client.post(f"/api/admin/users/{user['id']}/reset-totp", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tokensRevoked"] == 1 and body["sessionsEnded"] is True
    assert body["user"]["totpEnabled"] is False
    u = db.user_by_id(user["id"])
    assert (u["totp_enabled"], u["totp_secret"], u["totp_last_counter"]) == (0, None, None)
    assert u["failed_logins"] == 0 and not u["locked_until"]
    assert session_count(db, user["id"]) == 0 and token_count(db, user["id"]) == 0
    row = db.one("SELECT * FROM audit WHERE action='user.totp.reset'")
    assert row["username"] == "root" and row["target"] == "quinn"
    assert auth.login("quinn", PW, None, "1.1.1.1")["id"] == user["id"]   # password alone is enough now
    # nothing left to reset
    r = client.post(f"/api/admin/users/{user['id']}/reset-totp", headers=h)
    assert r.status_code == 409 and r.json()["error"] == "totp_not_enabled"


def test_admin_reset_totp_refuses_self_and_non_admins(web):
    client, _, db, auth = web
    admin, _ = with_totp(db, mk_user(db, "root", role="admin"))
    h = sign_in(client, auth, admin)
    r = client.post(f"/api/admin/users/{admin['id']}/reset-totp", headers=h)
    assert r.status_code == 400 and r.json()["error"] == "self"
    assert db.user_by_id(admin["id"])["totp_enabled"] == 1
    other, _ = with_totp(db, mk_user(db, "rita"))
    h = sign_in(client, auth, mk_user(db, "sam"))
    assert client.post(f"/api/admin/users/{other['id']}/reset-totp", headers=h).status_code == 403
    assert client.post(f"/api/admin/users/{other['id']}/reset-totp").status_code in (401, 403)   # no session
    assert db.user_by_id(other["id"])["totp_enabled"] == 1


def test_admin_reset_totp_of_admin_under_require_totp_admins(web):
    client, _, db, auth = web
    root, _ = with_totp(db, mk_user(db, "root", role="admin"))
    other, _ = with_totp(db, mk_user(db, "tess", role="admin"))
    db.set_setting("require_totp_admins", True)
    h = sign_in(client, auth, root)
    assert client.post(f"/api/admin/users/{other['id']}/reset-totp", headers=h).status_code == 200
    r = client.post("/api/auth/login", json={"username": "tess", "password": PW})
    assert r.status_code == 200 and r.json()["totpEnrolmentRequired"] is True   # must enrol again


def test_cli_user_reset_totp(tmp_path, capsys):
    from goose_web import __main__ as cli
    data = copy.deepcopy(DEFAULTS)
    data["paths"]["system_dir"] = str(tmp_path / "sys")      # cmd_user opens <system_dir>/goose-web.db
    settings = Settings(data, None)
    (tmp_path / "sys").mkdir()
    db = Database(tmp_path / "sys" / "goose-web.db")
    auth = AuthService(db, settings)
    user, _ = with_totp(db, mk_user(db, "uma"))
    auth.create_session(user, "1.1.1.1", "phone", "password")
    auth.create_api_token(user, "t", None)
    db.close()
    args = types.SimpleNamespace(action="reset-totp", name="uma", password=None, admin=False)
    assert cli.cmd_user(args, settings) == 0
    assert "Two-factor removed for uma" in capsys.readouterr().out
    db2 = Database(tmp_path / "sys" / "goose-web.db")
    try:
        u = db2.user_by_id(user["id"])
        assert (u["totp_enabled"], u["totp_secret"]) == (0, None)
        assert session_count(db2, user["id"]) == 0 and token_count(db2, user["id"]) == 0
        row = db2.one("SELECT * FROM audit WHERE action='user.totp.reset'")
        assert row["target"] == "uma" and row["detail"] == {"via": "cli", "tokensRevoked": 1}
        assert cli.cmd_user(args, settings) == 0                       # already off: harmless no-op
        assert "does not use two-factor" in capsys.readouterr().out
    finally:
        db2.close()


def test_self_password_change_revokes_api_tokens_keeps_session(web):
    client, _, db, auth = web
    u = mk_user(db, "pete")
    auth.create_api_token(u, "t", None)
    h = sign_in(client, auth, u)
    r = client.post("/api/me/password", headers=h, json={"current": PW, "new": "Fresh-Kettle-99"})
    assert r.status_code == 200 and token_count(db, u["id"]) == 0
    assert db.one("SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?", (u["id"],))["n"] == 1


# ---------------------------------------------------------------- 9. string-built SQL allow-lists
def test_user_field_names_are_allow_listed(env):
    _, db, _ = env
    u = mk_user(db, "quinn")
    for bad in ({"role=1 --": "x"}, {"id": 5}, {"nope": 1}):
        with pytest.raises(ValueError):
            db.update_user(u["id"], **bad)
    with pytest.raises(ValueError):
        db.create_user(username="rex", **{"x) VALUES(1); --": 1})


def test_set_links_allow_list():
    with pytest.raises(ValueError):
        api._set_links(None, "users", "id", "id", 1, [])


# ---------------------------------------------------------------- 10. audit retention (GW-23)
def test_purge_audit_and_purge_on_open(tmp_path):
    db = Database(tmp_path / "a.db")
    old = time.time() - 86400 * (AUDIT_RETENTION_DAYS + 1)
    db.execute("INSERT INTO audit(ts, action) VALUES(?, 'old')", (old,))
    db.execute("INSERT INTO audit(ts, action) VALUES(?, 'new')", (time.time(),))
    assert db.purge_audit(days=10_000) == 0
    db.close()
    db = Database(tmp_path / "a.db")                     # default retention applied on open
    assert [r["action"] for r in db.query("SELECT action FROM audit")] == ["new"]
    assert db.purge_audit(0) == 0
    db.close()


# ---------------------------------------------------------------- migration
def test_additive_migration_on_legacy_database(tmp_path):
    path = tmp_path / "legacy.db"
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO meta VALUES('schema_version', '1');
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user',
          auth_source TEXT NOT NULL DEFAULT 'local', password_hash TEXT, must_change_pw INTEGER NOT NULL DEFAULT 0,
          totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
          profile_mode TEXT NOT NULL DEFAULT 'isolated', profile_path TEXT NOT NULL DEFAULT '',
          personal_hints TEXT NOT NULL DEFAULT '', prefs TEXT NOT NULL DEFAULT '{}',
          policy_overrides TEXT NOT NULL DEFAULT '{}', has_schedules INTEGER NOT NULL DEFAULT 0,
          failed_logins INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
          created_at REAL NOT NULL, last_login_at REAL);
        INSERT INTO users(username, created_at) VALUES('old', 1);
    """)
    con.commit()
    con.close()
    for _ in range(2):                                   # idempotent: second open is a no-op
        db = Database(path)
        u = db.user_by_name("old")
        assert u["totp_last_counter"] is None and u["oidc_issuer"] is None and u["oidc_subject"] is None
        assert str(db.one("SELECT value FROM meta WHERE key='schema_version'")["value"]) == "3"
        assert db.one("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_blocks'")
        assert db.one("SELECT name FROM sqlite_master WHERE name='ux_users_oidc'")
        db.close()
