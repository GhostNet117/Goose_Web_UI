"""Security assessment 2026-11-09, web / auth slice (A-1 ... A-14, D-9): regression tests."""
import asyncio
import base64
import copy
import datetime
import itertools
import json
import os
import sys
import time
import types
import urllib.parse
from pathlib import Path

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import HTTPConnection, Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from goose_web import api, security
from goose_web import app as gw_app
from goose_web import auth as auth_mod
from goose_web.auth import MASK, AuthError, AuthService
from goose_web.config import DEFAULTS, ConfigError, Settings, load_settings
from goose_web.context import Ctx, HTTPError
from goose_web.db import Database

PW = "Blue-Kettle-42"
ISSUER = "https://idp.example.org"
MB = 1024 * 1024


# ====================================================================== harness
class FakeProfiles:
    def __init__(self, root: Path):
        self.root = root

    def is_native(self, user):
        return user["role"] == "admin"

    def root_for(self, user):
        return self.root / "profiles" / user["username"]

    def workspace(self, user):
        ws = self.root / "ws" / user["username"]
        ws.mkdir(parents=True, exist_ok=True)
        return ws

    def provision(self, user):
        (self.root_for(user) / ".goose-web").mkdir(parents=True, exist_ok=True)
        return []

    def ensure_team_folder(self, team):
        return None

    def team_folder(self, team):
        return None


class FakeWorkers:
    def get(self, key):
        return object()

    def wants_scheduler(self, w):
        return False, "test"


def make_settings(tmp_path, public_url="", **server) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    data["paths"]["profiles_root"] = str(tmp_path / "profiles")
    data["server"].update({"public_url": public_url, "max_upload_mb": 1, **server})
    data["auth"]["lockout_threshold"] = 3
    s = Settings(data, None)
    s.system_dir.mkdir(parents=True, exist_ok=True)
    return s


def build(tmp_path, public_url="", **server):
    settings = make_settings(tmp_path, public_url, **server)
    db = Database(settings.system_dir / "goose-web.db")
    auth = AuthService(db, settings)

    async def on_http_error(request, exc):
        return exc.response()

    app = Starlette(routes=[*api.routes, WebSocketRoute("/ws", gw_app.ws_endpoint)],
                    exception_handlers={HTTPError: on_http_error, ValueError: gw_app._bad_request})
    app.add_middleware(gw_app.BodyLimit, settings=settings)
    app.add_middleware(gw_app.SecurityHeaders, hsts=False)
    c = Ctx(settings=settings, db=db, auth=auth, profiles=FakeProfiles(tmp_path), workers=FakeWorkers(), hub=None,
            version="test")
    app.state.ctx = c
    return app, c


@pytest.fixture
def gw(tmp_path):
    app, c = build(tmp_path)
    with TestClient(app) as client:
        yield client, c
    c.db.close()


def mk_user(db, name, role="user", source="local", password=PW, **extra) -> dict:
    uid = db.create_user(username=name, display_name=name, role=role, auth_source=source,
                         password_hash=security.hash_password(password) if password else None, **extra)
    return db.user_by_id(uid)


def sign_in(client, c: Ctx, user) -> dict:
    token, csrf = c.auth.create_session(user, "127.0.0.1", "pytest", "password")
    client.cookies.set("gw", token)
    return {"x-csrf-token": csrf}


def session_headers(c: Ctx, user) -> dict:
    token, csrf = c.auth.create_session(user, "127.0.0.1", "pytest", "password")
    return {"cookie": f"gw={token}", "x-csrf-token": csrf}


def asgi(app, method: str, target: str, headers: dict, chunks) -> tuple[int, bytes, int]:
    """Drive an ASGI app directly. `chunks` is the request body as an iterable of byte strings; the body is
    sent without Content-Length unless the headers carry one. Returns (status, body, body bytes consumed)."""
    path, _, qs = target.partition("?")
    it = iter(chunks)
    sent: list = []
    consumed = [0]

    async def receive():
        try:
            body = next(it)
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}
        consumed[0] += len(body)
        return {"type": "http.request", "body": body, "more_body": True}

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": qs.encode(), "root_path": "",
             "headers": [(k.lower().encode(), str(v).encode()) for k, v in headers.items()],
             "client": ("127.0.0.1", 5000), "server": ("testserver", 80)}
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"), consumed[0]


# ====================================================================== A-1 / A-2 request bodies
def _unbounded_app():
    async def echo(request: Request):
        return PlainTextResponse(str(len(await request.body())))   # reads everything it is given
    return Starlette(routes=[Route("/api/x", echo, methods=["POST"]), Route("/api/fs/upload", echo, methods=["POST"]),
                             Route("/api/admin/teams/{tid:int}/items", echo, methods=["POST"])],
                     exception_handlers={HTTPError: lambda r, e: e.response()})


def test_body_limit_refuses_large_content_length_before_reading(tmp_path):
    app = gw_app.BodyLimit(_unbounded_app(), make_settings(tmp_path))
    status, body, consumed = asgi(app, "POST", "/api/x", {"content-length": str(400 * MB)}, itertools.repeat(b"x" * 65536))
    assert status == 413 and json.loads(body)["error"] == "too_large" and consumed == 0
    status, body, consumed = asgi(app, "POST", "/api/x", {"content-length": "abc"}, [])
    assert status == 400


def test_body_limit_counts_chunked_bodies(tmp_path):
    app = gw_app.BodyLimit(_unbounded_app(), make_settings(tmp_path))
    chunk = b"x" * 65536
    status, body, consumed = asgi(app, "POST", "/api/x", {}, itertools.repeat(chunk, 400))   # 25 MB, no length
    assert status == 413 and consumed <= gw_app.DEFAULT_BODY_LIMIT + len(chunk)
    # under the cap: delivered untouched
    status, body, _ = asgi(app, "POST", "/api/x", {}, itertools.repeat(chunk, 16))
    assert status == 200 and body == str(16 * 65536).encode()
    # upload route: server.max_upload_mb (1 MB here) plus multipart overhead; large admin route: 8 MB
    status, body, consumed = asgi(app, "POST", "/api/fs/upload", {}, itertools.repeat(chunk, 400))
    assert status == 413 and b"limited to 1 MB" in body and consumed <= MB + 64 * 1024 + len(chunk)
    status, _, _ = asgi(app, "POST", "/api/admin/teams/3/items", {}, itertools.repeat(chunk, 64))   # 4 MB
    assert status == 200


def test_login_body_is_capped_while_streaming(tmp_path):
    app, c = build(tmp_path)
    status, body, consumed = asgi(app, "POST", "/api/auth/login", {"content-type": "application/json"},
                                  itertools.repeat(b" " * 4096, 5000))                      # 20 MB, chunked
    assert status == 413 and consumed <= 16 * 1024 + 4096            # body_json's own 16 KB login limit
    status, _, consumed = asgi(app, "POST", "/api/auth/login", {"content-length": str(50 * MB)}, [])
    assert status == 413 and consumed == 0


def test_create_app_installs_body_limit():
    app = gw_app.create_app(Settings(copy.deepcopy(DEFAULTS), None))
    assert gw_app.BodyLimit in [m.cls for m in app.user_middleware]


def test_chunked_upload_is_refused_before_it_is_spooled(tmp_path):
    app, c = build(tmp_path)
    bob = mk_user(c.db, "bob")
    ws = c.profiles.workspace(bob)
    head = (b"--BB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"big.bin\"\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n")
    chunks = itertools.chain([head], itertools.repeat(b"z" * 65536, 300))                    # ~19 MB, chunked
    headers = {**session_headers(c, bob), "content-type": "multipart/form-data; boundary=BB"}
    status, body, consumed = asgi(app, "POST", "/api/fs/upload?dir=" + urllib.parse.quote(str(ws)), headers, chunks)
    assert status == 413 and b"limited to 1 MB" in body
    assert consumed <= MB + 64 * 1024 + 65536 + len(head)
    assert list(ws.iterdir()) == []


def test_upload_checks_every_name_before_writing(tmp_path):
    app, c = build(tmp_path)
    bob = mk_user(c.db, "bob")
    ws = c.profiles.workspace(bob)
    with TestClient(app) as client:
        h = sign_in(client, c, bob)
        r = client.post("/api/fs/upload", params={"dir": str(ws)}, headers=h,
                        files=[("f", ("a.txt", b"a")), ("f", ("b.txt", b"b")), ("f", ("AGENTS.md", b"x"))])
        assert r.status_code == 403 and r.json()["error"] == "hint_file_refused"
        assert list(ws.iterdir()) == []                               # nothing saved before the refusal
        r = client.post("/api/fs/upload", params={"dir": str(ws)}, headers=h, files=[("f", ("a.txt", b"a"))])
        assert r.status_code == 200 and (ws / "a.txt").read_bytes() == b"a"


# ====================================================================== A-3 lockout
def _ip_failures(c: Ctx, ip: str) -> int:
    row = c.db.one("SELECT failures FROM ip_blocks WHERE ip=?", (ip,))
    return len(row["failures"]) if row else 0


def test_locked_account_answers_like_a_wrong_password(tmp_path):
    _, c = build(tmp_path)
    mk_user(c.db, "carol")
    attacker, owner = "203.0.113.9", "198.51.100.7"
    for _ in range(3):                                            # lockout_threshold = 3 in this harness
        with pytest.raises(AuthError):
            c.auth.login("carol", "Wrong-Pass-123", None, attacker)
    carol = c.db.user_by_name("carol")
    assert carol["locked_until"] > time.time()
    locked_until = carol["locked_until"]
    answers = {}
    for name in ("carol", "nosuchuser"):
        with pytest.raises(AuthError) as e:
            c.auth.login(name, "Wrong-Pass-123", None, attacker)
        answers[name] = (e.value.code, e.value.status, e.value.message)
    assert answers["carol"] == answers["nosuchuser"] == ("invalid_credentials", 401, "Invalid username or password")
    assert _ip_failures(c, attacker) == 5                          # the wrong-password refusal counted
    assert c.db.user_by_name("carol")["locked_until"] == locked_until   # and did not extend the lock
    # the owner with the right password learns the lock, and is not counted toward an IP block
    for _ in range(9):                                            # (the 10th would hit the per-user rate limit)
        with pytest.raises(AuthError) as e:
            c.auth.login("carol", PW, None, owner)
        assert (e.value.code, e.value.status) == ("locked", 423)
    assert _ip_failures(c, owner) == 0 and not c.auth.ipblock.is_blocked(owner)


def test_locked_external_account_never_reveals_the_lock(tmp_path):
    _, c = build(tmp_path)
    u = mk_user(c.db, "olga", source="oidc", password=None)
    c.db.update_user(u["id"], locked_until=time.time() + 600)
    with pytest.raises(AuthError) as e:
        c.auth.login("olga", "anything-at-all", None, "203.0.113.10")
    assert e.value.code == "invalid_credentials"


# ====================================================================== A-9 enumeration
def test_local_disabled_and_oidc_accounts_look_like_unknown_names(tmp_path, monkeypatch):
    _, c = build(tmp_path)
    mk_user(c.db, "bob")
    mk_user(c.db, "dave", source="oidc", password=None)
    c.db.set_setting("auth", {"localEnabled": False})
    calls = []
    real = security.verify_password
    monkeypatch.setattr(security, "verify_password", lambda p, s: calls.append(s) or real(p, s))
    seen = {}
    for name in ("bob", "dave", "ghost"):
        calls.clear()
        with pytest.raises(AuthError) as e:
            c.auth.login(name, "Some-Pass-123", None, f"203.0.113.{len(seen) + 20}")
        seen[name] = (e.value.code, e.value.status, e.value.message)
        assert calls, f"no scrypt work for {name}"                # same cost on every path
    assert len(set(seen.values())) == 1 and seen["bob"][2] == "Invalid username or password"


# ====================================================================== A-4 / A-5 OIDC
def _jwt(claims: dict) -> str:
    return "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"


@pytest.fixture
def oidc(tmp_path, monkeypatch):
    app, c = build(tmp_path, public_url="http://testserver")
    c.auth.save_auth_config({"oidc": [{"id": "corp", "issuer": ISSUER, "clientId": "gw", "clientSecret": "s"}]})
    meta = {"authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token"}

    async def discovery(o):
        return meta

    monkeypatch.setattr(c.auth, "_oidc_discovery", discovery)
    claims: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id_token": _jwt(claims)})

    def client_factory(**kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(auth_mod, "httpx", types.SimpleNamespace(AsyncClient=client_factory, HTTPError=httpx.HTTPError))

    def start(client) -> str:
        """/start in `client`; the IdP 'signs in' and returns the callback URL (what an attacker would hand over)."""
        r = client.get("/api/auth/oidc/corp/start", follow_redirects=False)
        assert r.status_code == 302
        q = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)
        claims["nonce"] = q["nonce"][0]
        return "/api/auth/oidc/corp/callback?code=c&state=" + q["state"][0]

    def identity(sub, **more):
        claims.clear()
        claims.update({"iss": ISSUER, "aud": "gw", "exp": time.time() + 300, "sub": sub, **more})

    yield app, c, start, identity
    c.db.close()


def test_oidc_state_is_bound_to_the_starting_browser(oidc):
    app, c, start, identity = oidc
    with TestClient(app) as attacker, TestClient(app) as victim:
        identity("mallory-sub", preferred_username="mallory")
        url = start(attacker)
        set_cookie = attacker.cookies.get("gw_oidc")
        assert set_cookie
        r = victim.get(url, follow_redirects=False)                 # login CSRF: victim has no binding cookie
        assert r.status_code == 302 and "error=oidc_browser" in r.headers["location"] and "gw" not in victim.cookies
        # a cookie of another sign-in does not match either
        url2 = start(attacker)
        victim.cookies.set("gw_oidc", set_cookie)
        r = victim.get(url2, follow_redirects=False)
        assert "error=oidc_browser" in r.headers["location"]
        # the browser that started it finishes it; the binding cookie is cleared
        url3 = start(attacker)
        r = attacker.get(url3, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/"
        cookies = r.headers.get_list("set-cookie")
        assert any(h.startswith("gw=") for h in cookies)
        assert any(h.startswith("gw_oidc=") and ("Max-Age=0" in h or "max-age=0" in h.lower()) for h in cookies)
    start_cookie = [h for h in TestClient(app).get("/api/auth/oidc/corp/start", follow_redirects=False)
                    .headers.get_list("set-cookie") if h.startswith("gw_oidc=")][0].lower()
    assert "httponly" in start_cookie and "samesite=lax" in start_cookie and "max-age=600" in start_cookie


def test_oidc_never_binds_an_existing_account_by_name(oidc):
    app, c, start, identity = oidc
    # pre-provisioned by an administrator (authSource oidc), not bound to an identity yet
    dave = mk_user(c.db, "dave", source="oidc", password=None, email="dave@corp.example")
    with TestClient(app) as outsider:
        for claims in ({"email": "dave@other-tenant.example", "email_verified": True},   # report PoC
                       {"email": "dave@corp.example"},                                    # not verified
                       {"email": "dave@corp.example", "email_verified": False},
                       {"email": "dave@corp.example", "email_verified": "false"},
                       {}):
            identity("outsider-999", preferred_username="dave", **claims)
            r = outsider.get(start(outsider), follow_redirects=False)
            assert "error=oidc_unlinked" in r.headers["location"], claims
    assert c.db.user_by_id(dave["id"])["oidc_subject"] is None
    with TestClient(app) as real:                                   # verified, equal e-mail: bound once
        identity("dave-sub", preferred_username="dave", email="Dave@Corp.example", email_verified=True)
        r = real.get(start(real), follow_redirects=False)
        assert r.headers["location"] == "/"
    assert c.db.user_by_id(dave["id"])["oidc_subject"] == "dave-sub"


def test_oidc_strip_domain_defaults_off_for_new_providers(tmp_path):
    _, c = build(tmp_path)
    c.auth.save_auth_config({"oidc": [{"id": "old", "issuer": ISSUER, "clientId": "a"}]})
    assert c.auth.auth_config()["oidc"][0]["stripDomain"] is False
    # a provider stored before the change (no key) keeps the old behaviour when it is saved again
    c.db.set_setting("auth", {"oidc": [{"id": "legacy", "issuer": ISSUER, "clientId": "a"}]})
    c.auth.save_auth_config({"oidc": [{"id": "legacy", "issuer": ISSUER, "clientId": "a"},
                                      {"id": "new", "issuer": ISSUER, "clientId": "b"}]})
    got = {o["id"]: o["stripDomain"] for o in c.auth.auth_config()["oidc"]}
    assert got == {"legacy": True, "new": False}


def test_oidc_states_are_capped(tmp_path, monkeypatch):
    _, c = build(tmp_path)
    c.auth.save_auth_config({"oidc": [{"id": "corp", "issuer": ISSUER, "clientId": "gw"}]})

    async def discovery(o):
        return {"authorization_endpoint": ISSUER + "/a"}
    monkeypatch.setattr(c.auth, "_oidc_discovery", discovery)
    monkeypatch.setattr(auth_mod, "OIDC_STATE_CAP", 50)

    async def many():
        for _ in range(120):
            await c.auth.oidc_start("corp", "http://x/cb", "b")
    asyncio.run(many())
    assert c.db.one("SELECT COUNT(*) AS n FROM oidc_states")["n"] == 50


# ====================================================================== A-8 two-factor
def test_admin_must_enrol_before_anything_else(gw):
    client, c = gw
    boss = mk_user(c.db, "boss", role="admin")
    c.db.set_setting("require_totp_admins", True)
    eve = mk_user(c.db, "eve", role="admin")
    old_token = c.auth.create_api_token(eve, "pre-existing", None)[1]
    h = sign_in(client, c, eve)
    assert client.get("/api/me").status_code == 200
    assert client.get("/api/me/prefs").status_code == 200
    for method, path in (("GET", "/api/admin/users"), ("POST", "/api/me/tokens"), ("GET", "/api/me/tokens"),
                         ("POST", f"/api/admin/users/{boss['id']}/reset-totp"), ("PUT", "/api/me/prefs")):
        r = client.request(method, path, headers=h, json={})
        assert (r.status_code, r.json()["error"]) == (403, "totp_enrolment_required"), path
    # the httpx flavour the TestClient itself uses (starlette prefers httpx2 when it is installed)
    from starlette import testclient as _stc
    r = _stc.httpx.Client(transport=client._transport, base_url="http://testserver").get(
        "/api/admin/users", headers={"authorization": f"Bearer {old_token}"})
    assert r.status_code == 403
    assert c.must_enrol_or_change(eve)
    # enrolment itself is open; afterwards everything is
    secret = client.post("/api/me/totp/setup", headers=h).json()["secret"]
    assert client.post("/api/me/totp/enable", headers=h, json={"code": security.totp(secret)}).status_code == 200
    assert client.get("/api/admin/users").status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200


def test_websocket_refused_until_enrolled(tmp_path, monkeypatch):
    app, c = build(tmp_path)
    c.db.set_setting("require_totp_admins", True)
    eve = mk_user(c.db, "eve", role="admin")

    class Reached(Exception):
        pass

    def upstream_for(user):
        raise Reached
    monkeypatch.setattr(c, "policy_for", lambda u: {})
    monkeypatch.setattr(c, "roots_for", lambda *a, **k: [])
    monkeypatch.setattr(c, "upstream_for", upstream_for)
    with TestClient(app) as client:
        sign_in(client, c, eve)
        with pytest.raises(WebSocketDisconnect) as e:
            with client.websocket_connect("/ws", headers={"origin": "http://testserver"}):
                pass
        assert e.value.code == 4401
        c.db.update_user(eve["id"], totp_enabled=1, totp_secret=security.new_totp_secret())
        with pytest.raises(Reached):                                # past the gate once enrolled
            with client.websocket_connect("/ws", headers={"origin": "http://testserver"}):
                pass


def test_disabling_totp_reauthenticates_every_account_type(gw, monkeypatch):
    client, c = gw
    for name, source in (("lena", "ldap"), ("otto", "oidc"), ("lou", "local")):
        u = mk_user(c.db, name, source=source, password=PW if source == "local" else None)
        secret = security.new_totp_secret()
        c.db.update_user(u["id"], totp_secret=secret, totp_enabled=1)
        h = sign_in(client, c, u)
        r = client.post("/api/me/totp/disable", headers=h, json={})
        assert r.status_code == 400, name
        assert c.db.user_by_id(u["id"])["totp_enabled"] == 1
        if source == "oidc":
            r = client.post("/api/me/totp/disable", headers=h, json={"code": security.totp(secret)})
            assert r.status_code == 200
        elif source == "local":
            assert client.post("/api/me/totp/disable", headers=h, json={"password": "nope"}).status_code == 400
            assert client.post("/api/me/totp/disable", headers=h, json={"password": PW}).status_code == 200
        else:   # LDAP: needs a directory bind with the password; directory off here, so never accepted
            assert client.post("/api/me/totp/disable", headers=h, json={"password": PW}).status_code == 400
        client.cookies.clear()


def test_oidc_sign_in_requires_the_enrolled_totp(oidc):
    app, c, start, identity = oidc
    identity("tina-sub", preferred_username="tina")
    with TestClient(app) as b:
        assert b.get(start(b), follow_redirects=False).headers["location"] == "/"    # creates + binds tina
    tina = c.db.user_by_name("tina")
    secret = security.new_totp_secret()
    c.db.update_user(tina["id"], totp_secret=secret, totp_enabled=1)
    with TestClient(app) as b:
        r = b.get(start(b), follow_redirects=False)
        assert r.headers["location"] == "/api/auth/mfa" and "gw" not in b.cookies and b.cookies.get("gw_mfa")
        page = b.get("/api/auth/mfa")
        assert page.status_code == 200 and 'name="code"' in page.text and "<script" not in page.text
        r = b.post("/api/auth/mfa", data={"code": "000000"}, follow_redirects=False)
        assert r.status_code == 200 and "not valid" in r.text and "gw" not in b.cookies
        assert c.db.user_by_id(tina["id"])["failed_logins"] == 1
        r = b.post("/api/auth/mfa", data={"code": security.totp(secret)}, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/" and b.cookies.get("gw")
        assert b.get("/api/me").json()["user"]["username"] == "tina"
        # the pending sign-in is single use
        assert "expired" in b.post("/api/auth/mfa", data={"code": security.totp(secret)}).text


def test_mfa_post_refuses_a_foreign_origin(oidc):
    app, c, start, identity = oidc
    with TestClient(app) as b:
        r = b.post("/api/auth/mfa", data={"code": "1"}, headers={"origin": "https://evil.example"})
        assert r.status_code == 403


# ====================================================================== A-6 file API and system_dir
def test_file_api_refuses_system_dir_for_admins(gw, tmp_path):
    client, c = gw
    root = mk_user(c.db, "root", role="admin")
    sysd = c.settings.system_dir
    (sysd / "tls").mkdir(exist_ok=True)
    (sysd / "tls" / "ca.key").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "ok.txt").write_text("fine", encoding="utf-8")
    h = sign_in(client, c, root)
    variants = [str(sysd / "goose-web.db"), str(sysd / "tls" / "ca.key"), str(sysd),
                str(elsewhere / ".." / "profiles" / "_system" / "goose-web.db"),
                str(sysd / "goose-web.db") + "::$DATA"]
    if os.name == "nt":
        variants += [str(sysd).upper() + "\\GOOSE-WEB.DB", str(sysd) + ".\\goose-web.db"]
    for p in variants:
        for route in ("/api/fs/read", "/api/fs/download"):
            r = client.get(route, params={"path": p})
            assert r.status_code == 403, (route, p, r.status_code)
    assert client.get("/api/fs/list", params={"path": str(sysd)}).status_code == 403
    assert client.post("/api/fs/mkdir", headers=h, json={"path": str(sysd / "new")}).status_code == 403
    r = client.post("/api/fs/upload", params={"dir": str(sysd / "backups")}, headers=h, files=[("f", ("x.txt", b"x"))])
    assert r.status_code == 403 and not (sysd / "backups").exists()
    for unc in (r"\\127.0.0.1\C$\Windows\win.ini", "//127.0.0.1/c$/x", r"\\?\C:\Windows\win.ini"):
        # Windows: UNC/device paths are refused (403). POSIX has no UNC paths: these are just missing files (404).
        assert client.get("/api/fs/read", params={"path": unc}).status_code in ((403,) if os.name == "nt" else (403, 404))
    # the rest of the machine is still open to administrators
    r = client.get("/api/fs/read", params={"path": str(elsewhere / "ok.txt")})
    assert r.status_code == 200 and r.json()["content"] == "fine"
    listing = client.get("/api/fs/list", params={"path": str(sysd.parent)}).json()
    assert any(e["name"] == "_system" for e in listing["entries"])


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
def test_file_api_refuses_junction_into_system_dir(gw, tmp_path):
    import _winapi
    client, c = gw
    root = mk_user(c.db, "root", role="admin")
    sign_in(client, c, root)
    link = tmp_path / "innocent"
    _winapi.CreateJunction(str(c.settings.system_dir), str(link))
    assert client.get("/api/fs/read", params={"path": str(link / "goose-web.db")}).status_code == 403
    assert client.get("/api/fs/list", params={"path": str(link)}).status_code == 403


# ====================================================================== A-7 client address
def _conn(peer: str, xff: str | None) -> HTTPConnection:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return HTTPConnection({"type": "http", "headers": headers, "client": (peer, 1234), "path": "/", "query_string": b""})


@pytest.mark.parametrize("peer,xff,want", [
    ("127.0.0.1", "198.51.100.7", "198.51.100.7"),
    ("127.0.0.1", "<img src=x onerror=alert(1)>", "127.0.0.1"),            # not an address: the peer
    ("127.0.0.1", "", "127.0.0.1"),
    ("127.0.0.1", "unknown", "127.0.0.1"),
    ("127.0.0.1", "203.0.113.1, 198.51.100.7", "198.51.100.7"),            # right-most untrusted
    ("127.0.0.1", "198.51.100.7, 10.1.2.3", "198.51.100.7"),               # 10/8 is a trusted proxy here
    ("127.0.0.1", "198.51.100.7, garbage", "127.0.0.1"),
    ("127.0.0.1", "garbage, 198.51.100.7", "198.51.100.7"),
    ("127.0.0.1", "198.51.100.7:4711", "198.51.100.7"),
    ("127.0.0.1", "[2001:db8::1]:443", "2001:db8::1"),
    ("127.0.0.1", "2001:DB8::1", "2001:db8::1"),
    ("127.0.0.1", "10.9.9.9", "10.9.9.9"),                                 # only trusted hops: the left-most one
    ("192.0.2.50", "198.51.100.7", "192.0.2.50"),                           # untrusted peer: header ignored
])
def test_client_ip_uses_only_valid_forwarded_addresses(tmp_path, peer, xff, want):
    _, c = build(tmp_path, trusted_proxies=["127.0.0.1", "::1", "10.0.0.0/8"])
    assert c.client_ip(_conn(peer, xff)) == want


# ====================================================================== A-10 configuration file
def test_missing_explicit_config_is_fatal(tmp_path, monkeypatch):
    monkeypatch.delenv("GOOSE_WEB_CONFIG", raising=False)
    with pytest.raises(ConfigError) as e:
        load_settings(str(tmp_path / "typo-config.yaml"))
    assert "typo-config.yaml" in str(e.value) and isinstance(e.value, SystemExit)
    real = tmp_path / "real.yaml"
    real.write_text("server:\n  port: 8799\n", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(real))                       # an explicit path never falls back to it
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path / "typo-config.yaml"))
    assert load_settings().get("server", "port") == 8799
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "missing-env.yaml"))
    with pytest.raises(ConfigError) as e:
        load_settings()
    assert "GOOSE_WEB_CONFIG" in str(e.value)


def test_cli_stops_on_a_missing_config(tmp_path, monkeypatch, capsys):
    from goose_web import __main__ as cli
    monkeypatch.delenv("GOOSE_WEB_CONFIG", raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main(["--config", str(tmp_path / "nope.yaml"), "ip", "list"])
    assert e.value.code not in (0, None)


# ====================================================================== A-11 stored secrets
def test_secrets_dropped_when_the_endpoint_changes(tmp_path):
    _, c = build(tmp_path)
    c.auth.save_auth_config({"ldap": {"url": "ldaps://dc1.corp", "bindPassword": "bind-secret"},
                             "oidc": [{"id": "corp", "issuer": ISSUER, "clientId": "gw", "clientSecret": "oidc-secret"}]})
    c.auth.save_auth_config({"ldap": {"url": "ldaps://DC1.corp/", "bindPassword": MASK},
                             "oidc": [{"id": "corp", "issuer": ISSUER + "/", "clientId": "gw", "clientSecret": MASK}]})
    cfg = c.auth.auth_config()
    assert cfg["ldap"]["bindPassword"] == "bind-secret" and cfg["oidc"][0]["clientSecret"] == "oidc-secret"
    c.auth.save_auth_config({"ldap": {"url": "ldaps://evil.example", "bindPassword": MASK},
                             "oidc": [{"id": "corp", "issuer": "https://evil.example", "clientId": "gw",
                                       "clientSecret": MASK}]})
    cfg = c.auth.auth_config()
    assert cfg["ldap"]["bindPassword"] == "" and cfg["oidc"][0]["clientSecret"] == ""
    c.auth.save_auth_config({"ldap": {"url": "ldaps://new.corp", "bindPassword": "new-secret"}})
    assert c.auth.auth_config()["ldap"]["bindPassword"] == "new-secret"


# ====================================================================== A-12 TLS files
def _pem_pair(folder: Path, name: str) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    cp, kp = folder / f"{name}.crt", folder / f"{name}.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return cp, kp


def test_tls_files_mode_checks_the_key(gw, tmp_path):
    client, c = gw
    root = mk_user(c.db, "root", role="admin")
    c.db.update_user(root["id"], totp_enabled=0)
    h = sign_in(client, c, root)
    cert, key = _pem_pair(tmp_path, "a")
    _, other_key = _pem_pair(tmp_path, "b")
    db_file = c.settings.system_dir / "goose-web.db"
    for kf, code in ((db_file, "bad_key"), (other_key, "bad_key"), (r"\\127.0.0.1\share\a.key", "bad_file")):
        r = client.put("/api/admin/tls", headers=h, json={"mode": "files", "certFile": str(cert), "keyFile": str(kf)})
        assert (r.status_code, r.json()["error"]) == (400, code), kf
    r = client.put("/api/admin/tls", headers=h, json={"mode": "files", "certFile": "//host/share/a.crt",
                                                      "keyFile": str(key)})
    assert r.status_code == 400
    assert api._tls_pair_problem(str(cert), str(key)) == ""


# ====================================================================== A-13 errors
def test_audit_before_and_numbers_are_validated(gw):
    client, c = gw
    root = mk_user(c.db, "root", role="admin")
    sign_in(client, c, root)
    for bad in ("1e309", "nan", "abc", "-inf"):
        r = client.get("/api/admin/audit", params={"before": bad})
        assert (r.status_code, r.json()["error"]) == (400, "bad_request"), bad
    assert client.get("/api/admin/audit", params={"before": "12"}).status_code == 200
    assert client.get("/api/admin/audit", params={"limit": "lots"}).status_code == 400
    r = client.get("/api/admin/logs", params={"lines": "abc"})
    assert r.status_code == 400 and "invalid literal" not in r.text


def test_value_errors_are_not_echoed(tmp_path):
    async def boom(request):
        raise ValueError("C:\\secret\\path invalid literal for int()")
    app = Starlette(routes=[Route("/x", boom)], exception_handlers={ValueError: gw_app._bad_request})
    r = TestClient(app).get("/x")
    assert r.status_code == 400 and "secret" not in r.text and "invalid literal" not in r.text


# ====================================================================== A-14 smaller items
def test_prefs_cannot_write_server_keys(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    c.db.update_user(bob["id"], prefs={"_notify": {"webhook": "https://ok.example/h", "events": ["done"]}})
    h = sign_in(client, c, bob)
    r = client.put("/api/me/prefs", headers=h, json={"theme": "dark", "_notify": {"webhook": "http://127.0.0.1/x"},
                                                    "_other": 1})
    assert r.status_code == 200
    prefs = c.db.user_by_id(bob["id"])["prefs"]
    assert prefs == {"theme": "dark", "_notify": {"webhook": "https://ok.example/h", "events": ["done"]}}


def test_logout_requires_csrf(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    assert client.post("/api/auth/logout").status_code == 403
    assert client.get("/api/me").status_code == 200                       # still signed in
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/me").status_code == 401
    assert client.post("/api/auth/logout").status_code == 200              # no session: nothing to protect


def test_static_aliases_are_not_served(tmp_path):
    (tmp_path / "index.html").write_text("hi", encoding="utf-8")
    app = Starlette(routes=[Mount("/static", gw_app.Static(directory=str(tmp_path)))])
    client = TestClient(app)
    assert client.get("/static/index.html").status_code == 200
    for alias in ("index.html::$DATA", "index~1.htm", "index.html.", "index.html%20"):
        assert client.get("/static/" + alias).status_code == 404, alias


# ====================================================================== D-9 headers
def test_route_headers_are_not_duplicated():
    async def frame(request):
        return Response("x", headers={"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})

    async def plain(request):
        return Response("x")
    app = Starlette(routes=[Route("/frame", frame), Route("/plain", plain)])
    client = TestClient(gw_app.SecurityHeaders(app, hsts=True))
    r = client.get("/frame")
    assert r.headers.get_list("referrer-policy") == ["no-referrer"]
    assert r.headers.get_list("x-content-type-options") == ["nosniff"]
    r = client.get("/plain")
    assert r.headers.get_list("referrer-policy") == ["same-origin"]
    assert r.headers.get_list("strict-transport-security") == ["max-age=31536000"]
