"""Spec 007: block an address after repeated failed sign-ins, forced change of admin-set passwords,
strong-password policy."""
import copy
import json
import time
import types
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient, WebSocketDenialResponse

from goose_web import api, security
from goose_web import app as gw_app
from goose_web.__main__ import generate_admin_password
from goose_web.auth import AuthError, AuthService
from goose_web.config import DEFAULTS, Settings
from goose_web.context import Ctx, HTTPError
from goose_web.db import Database
from goose_web.ipblock import address_key

PW = "Blue-Kettle-42"
ATTACKER = "203.0.113.7"


def make(tmp_path, **auth_cfg):
    data = copy.deepcopy(DEFAULTS)
    data["auth"].update(auth_cfg)
    settings = Settings(data, None)
    db = Database(tmp_path / "gw.db")
    return settings, db, AuthService(db, settings)


@pytest.fixture
def env(tmp_path):
    settings, db, auth = make(tmp_path)
    yield settings, db, auth
    db.close()


def mk_user(db, name, role="user", password=PW, **extra) -> dict:
    uid = db.create_user(username=name, display_name=name, role=role, auth_source="local",
                         password_hash=security.hash_password(password), **extra)
    return db.user_by_id(uid)


def fail(auth, ip, user="nobody", password="Wrong-Pass-123", n=1) -> list[str]:
    codes = []
    for _ in range(n):
        with pytest.raises(AuthError) as e:
            auth.login(user, password, None, ip)
        codes.append(e.value.code)
    return codes


# ---------------------------------------------------------------- strong-password policy
@pytest.mark.parametrize("pw", ["Blue-Kettle-42", "Another-Pass-77", "Fresh-Kettle-99", "Correct horse 9 battery",
                                "Parity-Admin-2026!x", "zK8#mQ2!vL9@"])
def test_strong_passwords_accepted(pw):
    assert security.password_problems(pw, 12, "alice") == []


@pytest.mark.parametrize("pw,problem", [
    ("Short-1a", "must be at least 12 characters"),
    ("all-lower-case-1", "needs an uppercase letter"),
    ("ALL-UPPER-CASE-1", "needs a lowercase letter"),
    ("No-Digits-Here", "needs a number"),
    ("NoSymbols12345", "needs a symbol"),
    ("Alice-Rocks-2026", "must not contain the username"),
    ("P@ssw0rd123!", "is too common"),
    ("Password1234!", "is too common"),
    ("Summer2026!!", "is too common"),
    ("!Qwerty202620", "is too common"),
    ("Welcome-2026#", "is too common"),
    ("Goose-Web-2026", "is too common"),
    ("Aaaa-Kettle-42", "must not repeat a character 4 or more times in a row"),
])
def test_weak_passwords_rejected(pw, problem):
    probs = security.password_problems(pw, 12, "alice")
    assert any(p.startswith(problem) for p in probs), probs


def test_minimum_length_floor_and_raise():
    assert security.PASSWORD_MIN_LENGTH == 12
    assert security.password_problems("Kettle-42-aB", 8) == []                     # 12 characters
    assert security.password_problems("Kettle-42-B", 8) == ["must be at least 12 characters"]  # 8 is raised to 12
    assert security.password_problems("Blue-Kettle-42", 20) == ["must be at least 20 characters"]
    assert security.password_problems("ab", 12, "ab") == [   # 2-character user names are not checked
        "must be at least 12 characters", "needs an uppercase letter", "needs a number", "needs a symbol"]
    assert DEFAULTS["auth"]["min_password_length"] == 12


def test_generated_passwords_meet_policy():
    for _ in range(300):
        pw = api.temp_password()
        assert security.password_problems(pw) == [], pw
    for _ in range(50):
        assert security.password_problems(generate_admin_password(), 16) == []


# ---------------------------------------------------------------- address keys
def test_address_key():
    assert address_key("203.0.113.7") == "203.0.113.7"
    assert address_key(" 203.0.113.7 ") == "203.0.113.7"
    assert address_key("::ffff:203.0.113.7") == "203.0.113.7"
    assert address_key("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
    assert address_key("2001:db8:1:2:bbbb::9") == "2001:db8:1:2::/64"
    assert address_key("testclient") == "" and address_key("") == ""


# ---------------------------------------------------------------- the IP block
def test_ten_consecutive_failures_block_the_address(env):
    _, db, auth = env
    mk_user(db, "alice")
    codes = fail(auth, ATTACKER, "alice", n=9) + fail(auth, ATTACKER, "ghost", n=1)
    assert codes[:8] == ["invalid_credentials"] * 8        # account lockout (8) then counts as "locked"
    assert codes[8] == "locked" and codes[9] == "ip_blocked"
    assert auth.ipblock.is_blocked(ATTACKER)
    # even the right password is refused now, and the refusal is not a new failure
    with pytest.raises(AuthError) as e:
        auth.login("alice", PW, None, ATTACKER)
    assert e.value.code == "ip_blocked" and e.value.status == 403
    # other addresses are unaffected
    db.update_user(db.user_by_name("alice")["id"], locked_until=0)
    assert auth.login("alice", PW, None, "198.51.100.1")["username"] == "alice"
    row = db.one("SELECT * FROM audit WHERE action='auth.ip.blocked'")
    assert row["ip"] == ATTACKER and row["target"] == "ghost" and row["detail"]["failures"] == 10
    assert row["detail"]["until"] == pytest.approx(time.time() + 30 * 86400, abs=60)


def test_success_resets_the_run(env):
    _, db, auth = env
    mk_user(db, "bob")
    fail(auth, ATTACKER, "bob", n=7)
    assert auth.login("bob", PW, None, ATTACKER)["username"] == "bob"
    fail(auth, ATTACKER, "nobody", n=9)
    assert not auth.ipblock.is_blocked(ATTACKER)
    assert fail(auth, ATTACKER, "nobody") == ["ip_blocked"]


def test_totp_failures_and_unknown_users_count(env):
    _, db, auth = env
    uid = mk_user(db, "carol")["id"]
    db.update_user(uid, totp_secret=security.new_totp_secret(), totp_enabled=1)
    with pytest.raises(AuthError) as e:                       # the code prompt is not a failure
        auth.login("carol", PW, None, ATTACKER)
    assert e.value.code == "totp_required"
    assert auth.ipblock.list() == []
    for _ in range(3):
        with pytest.raises(AuthError):
            auth.login("carol", PW, "000000", ATTACKER)
    fail(auth, ATTACKER, "unknown-user", n=2)
    (item,) = auth.ipblock.list()
    assert item["ip"] == ATTACKER and item["failures"] == 5 and not item["blocked"]


def test_empty_submissions_and_rate_limits_do_not_count(env):
    _, _, auth = env
    for _ in range(12):
        with pytest.raises(AuthError):
            auth.login("", "", None, ATTACKER)
    assert auth.ipblock.list() == []


def test_only_failures_inside_the_window_count(env):
    _, db, auth = env
    old = time.time() - 31 * 86400
    db.execute("INSERT INTO ip_blocks(ip, failures, updated_at) VALUES(?,?,?)",
               (ATTACKER, json.dumps([old + i for i in range(9)]), old))
    fail(auth, ATTACKER)
    assert not auth.ipblock.is_blocked(ATTACKER)
    assert auth.ipblock.list()[0]["failures"] == 1
    # nine recent ones plus one more do block
    recent = time.time() - 29 * 86400
    db.execute("UPDATE ip_blocks SET failures=? WHERE ip=?", (json.dumps([recent + i for i in range(9)]), ATTACKER))
    assert fail(auth, ATTACKER) == ["ip_blocked"]


def test_block_expires(env):
    _, db, auth = env
    fail(auth, ATTACKER, n=10)
    assert auth.ipblock.is_blocked(ATTACKER)
    db.execute("UPDATE ip_blocks SET blocked_until=? WHERE ip=?", (time.time() - 1, ATTACKER))
    auth.ipblock._loaded_at = float("-inf")                 # next refresh (every 15 s) sees the expiry...
    assert not auth.ipblock.is_blocked(ATTACKER)
    assert db.one("SELECT * FROM ip_blocks WHERE ip=?", (ATTACKER,)) is None
    assert fail(auth, ATTACKER, "u2") == ["invalid_credentials"]  # starts again from zero
    # an expired block that is still in the table (refresh not yet run) also restarts the count
    assert fail(auth, ATTACKER, "u3", n=9)[-1] == "ip_blocked"
    db.execute("UPDATE ip_blocks SET blocked_at=?, blocked_until=? WHERE ip=?", (time.time() - 9, time.time() - 1,
                                                                                 ATTACKER))
    assert auth.ipblock.record_failure(ATTACKER, "u4") is False
    assert auth.ipblock.list()[0]["failures"] == 1


def test_permanent_block_and_threshold_off(tmp_path):
    _, db, auth = make(tmp_path, ip_block_days=0, ip_block_threshold=3)
    fail(auth, ATTACKER, n=3)
    row = db.one("SELECT * FROM ip_blocks WHERE ip=?", (ATTACKER,))
    assert row["blocked_at"] > 0 and row["blocked_until"] == 0
    assert auth.ipblock.list()[0]["blockedUntil"] is None
    db.close()
    _, db2, auth2 = make(tmp_path / "off", ip_block_threshold=0)
    assert fail(auth2, ATTACKER, n=15).count("ip_blocked") == 0
    assert db2.query("SELECT * FROM ip_blocks") == []
    db2.close()


def test_trusted_proxies_and_exempt_networks_are_never_blocked(tmp_path):
    _, db, auth = make(tmp_path, ip_block_exempt=["192.0.2.0/24"])
    for ip in ("127.0.0.1", "::1", "192.0.2.55"):
        assert "ip_blocked" not in fail(auth, ip, n=12)
        assert not auth.ipblock.is_blocked(ip)
    assert db.query("SELECT * FROM ip_blocks") == []
    db.close()


def test_ipv6_is_grouped_by_64(env):
    _, _, auth = env
    for i in range(10):
        codes = fail(auth, f"2001:db8:1:2::{i + 1:x}")
    assert codes == ["ip_blocked"]
    assert auth.ipblock.is_blocked("2001:db8:1:2:ffff::1")
    assert not auth.ipblock.is_blocked("2001:db8:1:3::1")


def test_unblock_and_unblock_all(env):
    _, _, auth = env
    fail(auth, ATTACKER, n=10)
    fail(auth, "198.51.100.9", n=2)
    assert [x["blocked"] for x in auth.ipblock.list()] == [True, False]
    assert auth.ipblock.unblock(ATTACKER) and not auth.ipblock.is_blocked(ATTACKER)
    assert not auth.ipblock.unblock(ATTACKER)
    assert auth.ipblock.unblock_all() == 1 and auth.ipblock.list() == []


def test_block_survives_restart(tmp_path):
    settings, db, auth = make(tmp_path)
    fail(auth, ATTACKER, n=10)
    assert AuthService(db, settings).ipblock.is_blocked(ATTACKER)
    db.close()


# ---------------------------------------------------------------- middleware
def _guarded_app(c: Ctx) -> Starlette:
    async def ping(request):
        return PlainTextResponse("pong")

    async def ws(websocket):
        await websocket.accept()
        await websocket.send_text("hi")
        await websocket.close()

    app = Starlette(routes=[Route("/healthz", ping), Route("/api/ping", ping), Route("/", ping),
                            WebSocketRoute("/ws", ws)])
    app.add_middleware(gw_app.IPBlockGuard)
    app.state.ctx = c
    return app


def _ctx(settings, db, auth, tmp_path) -> Ctx:
    return Ctx(settings=settings, db=db, auth=auth, profiles=None, workers=None, hub=None, version="test")


def test_middleware_refuses_blocked_addresses(env, tmp_path):
    settings, db, auth = env
    fail(auth, ATTACKER, n=10)
    app = _guarded_app(_ctx(settings, db, auth, tmp_path))
    with TestClient(app, client=(ATTACKER, 5000)) as blocked:
        r = blocked.get("/api/ping")
        assert r.status_code == 403 and r.json()["error"] == "ip_blocked"
        r = blocked.get("/")
        assert r.status_code == 403 and "blocked" in r.text
        assert blocked.get("/healthz").text == "pong"
        with pytest.raises(WebSocketDenialResponse) as e:
            with blocked.websocket_connect("/ws"):
                pass
        assert e.value.status_code == 403
    with TestClient(app, client=("198.51.100.1", 5000)) as other:
        assert other.get("/api/ping").text == "pong"
        with other.websocket_connect("/ws") as s:
            assert s.receive_text() == "hi"


def test_middleware_uses_forwarded_address_only_from_trusted_proxy(env, tmp_path):
    settings, db, auth = env
    fail(auth, ATTACKER, n=10)
    app = _guarded_app(_ctx(settings, db, auth, tmp_path))
    with TestClient(app, client=("127.0.0.1", 5000)) as proxy:      # trusted proxy forwards the attacker
        assert proxy.get("/api/ping", headers={"X-Forwarded-For": ATTACKER}).status_code == 403
        assert proxy.get("/api/ping", headers={"X-Forwarded-For": "198.51.100.1"}).status_code == 200
        assert proxy.get("/api/ping").status_code == 200           # the proxy itself is never blocked
    with TestClient(app, client=("198.51.100.1", 5000)) as direct:  # spoofed header from a non-proxy is ignored
        assert direct.get("/api/ping", headers={"X-Forwarded-For": ATTACKER}).status_code == 200


def test_create_app_installs_ip_block_guard():
    app = gw_app.create_app(Settings(copy.deepcopy(DEFAULTS), None))
    classes = [m.cls for m in app.user_middleware]
    assert gw_app.IPBlockGuard in classes and classes.index(gw_app.IPBlockGuard) > classes.index(gw_app.HostGuard)


# ---------------------------------------------------------------- API
class FakeProfiles:
    def __init__(self, root: Path):
        self.root = root

    def is_native(self, user):
        return True

    def root_for(self, user):
        return self.root / user["username"]

    def provision(self, user):
        return []


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
    token, csrf = auth.create_session(user, "127.0.0.1", "pytest", "password")
    client.cookies.set("gw", token)
    return {"x-csrf-token": csrf}


def test_admin_lists_and_unblocks_addresses(web):
    client, _, db, auth = web
    fail(auth, ATTACKER, "root", n=10)
    fail(auth, "198.51.100.9", "bob", n=3)
    h = sign_in(client, auth, mk_user(db, "boss", role="admin"))
    r = client.get("/api/admin/ip-blocks").json()
    assert (r["threshold"], r["windowDays"], r["blockDays"]) == (10, 30, 30)
    assert [(x["ip"], x["blocked"], x["failures"], x["lastUsername"]) for x in r["items"]] == [
        (ATTACKER, True, 10, "root"), ("198.51.100.9", False, 3, "bob")]
    assert client.post("/api/admin/ip-blocks/unblock", headers=h, json={"ip": ATTACKER}).json() == {"removed": 1}
    assert not auth.ipblock.is_blocked(ATTACKER)
    assert client.post("/api/admin/ip-blocks/unblock", headers=h, json={"ip": ATTACKER}).status_code == 404
    assert client.post("/api/admin/ip-blocks/unblock", headers=h, json={}).status_code == 400
    assert client.post("/api/admin/ip-blocks/unblock", headers=h, json={"all": True}).json() == {"removed": 1}
    acts = [r["action"] for r in db.query("SELECT action FROM audit WHERE action='auth.ip.unblocked'")]
    assert acts == ["auth.ip.unblocked"] * 2


def test_ip_block_api_is_admin_only(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "pleb"))
    assert client.get("/api/admin/ip-blocks").status_code == 403
    assert client.post("/api/admin/ip-blocks/unblock", headers=h, json={"all": True}).status_code == 403


def test_login_endpoint_reports_ip_blocked(web):
    client, _, _, auth = web
    body = {"username": "x", "password": "Wrong-Pass-123"}
    # the default TestClient peer is "testclient" (not an address): nothing can be counted for it
    assert client.post("/api/auth/login", json=body).status_code == 401
    assert auth.ipblock.list() == []
    # behind the trusted proxy the forwarded client address is counted
    with TestClient(client.app, client=("127.0.0.1", 5000)) as proxy:
        fwd = {"X-Forwarded-For": ATTACKER}
        for _ in range(9):
            assert proxy.post("/api/auth/login", json=body, headers=fwd).status_code == 401
        r = proxy.post("/api/auth/login", json=body, headers=fwd)
        assert r.status_code == 403 and r.json()["error"] == "ip_blocked"
        assert proxy.post("/api/auth/login", json=body).status_code == 401   # the proxy itself is not blocked


# ---------------------------------------------------------------- forced change of admin-set passwords
def test_admin_set_password_always_forces_change(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "boss", role="admin"))
    r = client.post("/api/admin/users", headers=h, json={"username": "newbie", "password": "Fresh-Kettle-99",
                                                           "mustChangePassword": False})
    assert r.status_code == 200 and r.json()["tempPassword"] is None
    assert db.user_by_name("newbie")["must_change_pw"] == 1
    r = client.post("/api/admin/users", headers=h, json={"username": "temp1"})
    assert r.json()["tempPassword"] and db.user_by_name("temp1")["must_change_pw"] == 1
    uid = db.user_by_name("newbie")["id"]
    db.update_user(uid, must_change_pw=0)
    r = client.patch(f"/api/admin/users/{uid}", headers=h, json={"password": "Another-Pass-77",
                                                                  "mustChangePassword": False})
    assert r.status_code == 200 and db.user_by_id(uid)["must_change_pw"] == 1
    # a sign-in with the admin-set password is told to change it
    assert auth.login("newbie", "Another-Pass-77", None, "198.51.100.1")["must_change_pw"] == 1


def test_admin_set_password_must_be_strong(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "boss", role="admin"))
    r = client.post("/api/admin/users", headers=h, json={"username": "weakling", "password": "weakling-pass"})
    assert r.status_code == 400 and r.json()["error"] == "weak_password"
    assert r.json()["message"] == "The password does not meet the rules"
    assert "needs an uppercase letter" in r.json()["problems"]
    assert db.user_by_name("weakling") is None
    uid = mk_user(db, "dora")["id"]
    r = client.patch(f"/api/admin/users/{uid}", headers=h, json={"password": "Summer2026!!"})
    assert r.status_code == 400 and r.json()["error"] == "weak_password"


def test_ldap_user_created_by_admin_is_not_stuck_on_password_change(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "boss", role="admin"))
    assert client.post("/api/admin/users", headers=h, json={"username": "adam", "authSource": "ldap"}).status_code == 200
    assert db.user_by_name("adam")["must_change_pw"] == 0


def test_own_password_change_enforces_policy(web):
    client, _, db, auth = web
    h = sign_in(client, auth, mk_user(db, "erin"))
    r = client.post("/api/me/password", headers=h, json={"current": PW, "new": "erin-is-great-1"})
    assert r.status_code == 400 and "must not contain the username" in r.json()["problems"]
    assert client.post("/api/me/password", headers=h, json={"current": PW, "new": "Quiet-Lake-2049"}).status_code == 200


# ---------------------------------------------------------------- weak existing passwords
def test_weak_password_at_sign_in_forces_a_change(env):
    _, db, auth = env
    mk_user(db, "old", password="oldpassword1")           # set before the policy existed
    u = auth.login("old", "oldpassword1", None, "198.51.100.1")
    assert u["must_change_pw"] == 1
    row = db.one("SELECT * FROM audit WHERE action='auth.password.weak'")
    assert row["target"] == "old" and row["detail"] == {"forcedChange": True}
    mk_user(db, "fine")
    assert auth.login("fine", PW, None, "198.51.100.1")["must_change_pw"] == 0


# ---------------------------------------------------------------- CLI
def test_cli_ip_list_and_unblock(tmp_path, capsys):
    from goose_web import __main__ as cli
    data = copy.deepcopy(DEFAULTS)
    data["paths"]["system_dir"] = str(tmp_path / "sys")
    settings = Settings(data, None)
    (tmp_path / "sys").mkdir()
    db = Database(tmp_path / "sys" / "goose-web.db")
    auth = AuthService(db, settings)
    fail(auth, ATTACKER, "root", n=10)
    fail(auth, "2001:db8:5:6::1", n=1)
    db.close()
    args = types.SimpleNamespace(action="list", address=None, all=False)
    assert cli.cmd_ip(args, settings) == 0
    out = capsys.readouterr().out
    assert "Block after 10 consecutive failed sign-ins within 30 days" in out
    assert ATTACKER in out and "BLOCKED until" in out and "2001:db8:5:6::/64" in out and "counting" in out
    assert cli.cmd_ip(types.SimpleNamespace(action="unblock", address=ATTACKER, all=False), settings) == 0
    assert f"Unblocked {ATTACKER}" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.cmd_ip(types.SimpleNamespace(action="unblock", address=ATTACKER, all=False), settings)
    assert cli.cmd_ip(types.SimpleNamespace(action="unblock", address="2001:db8:5:6::99", all=False), settings) == 0
    assert cli.cmd_ip(types.SimpleNamespace(action="unblock", address=None, all=True), settings) == 0
    db2 = Database(tmp_path / "sys" / "goose-web.db")
    try:
        assert db2.query("SELECT * FROM ip_blocks") == []
        rows = db2.query("SELECT target, detail FROM audit WHERE action='auth.ip.unblocked' ORDER BY id")
        assert [r["target"] for r in rows] == [ATTACKER, "2001:db8:5:6::99", "*"]
        assert all(r["detail"]["via"] == "cli" for r in rows)
    finally:
        db2.close()
