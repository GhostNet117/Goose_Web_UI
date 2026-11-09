"""Pre-release fixes: NEW-01 tool-call prefix, NEW-03 WebSocket token header, NEW-04 Host allow-list,
NEW-05 upload names, NEW-07 apps frame policy/CSP, NEW-08 downloads, webhook save-time check, CLI reset."""
import copy
import os
from pathlib import Path

import httpx
import pytest
import yaml
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient, WebSocketDenialResponse
from starlette.websockets import WebSocketDisconnect

from goose_web import __main__ as cli
from goose_web import api, security
from goose_web import app as gw_app
from goose_web import policy as pol
from goose_web.auth import AuthError, AuthService
from goose_web.config import DEFAULTS, Settings
from goose_web.context import Ctx, HTTPError, url_origin
from goose_web.db import Database

MEMBER = {**pol.LEGACY_DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}
REPO = Path(__file__).resolve().parent.parent
PW = "Blue-Kettle-42"
P = "_goose/unstable/"
WS = "ws://localhost/ws"  # websocket_connect ignores base_url


# ---------------------------------------------------------------- fixtures / helpers
def make_settings(**server) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    data["server"].update(server)
    return Settings(data, None)


class FakeProfiles:
    def __init__(self, root: Path):
        self.root = root

    def is_native(self, user):
        return True

    def root_for(self, user):
        return self.root / user["username"]

    def workspace(self, user):
        return self.root / user["username"] / "workspace"


class FakeUpstream:
    def __init__(self):
        self.calls = []

    async def from_client(self, client, msg):
        client.send({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"user": client.user["username"]}})

    async def request(self, method, params, timeout=None):
        self.calls.append((method, params))
        return {"html": "<p>app</p>"}


class FakeHub:
    def attach(self, up, client):
        pass

    def detach(self, up, client):
        client.close()


def mk_user(db, name, role="user") -> dict:
    uid = db.create_user(username=name, display_name=name, role=role, auth_source="local",
                         password_hash=security.hash_password(PW))
    return db.user_by_id(uid)


def sign_in(client, auth, user, cookie="gw") -> dict:
    token, csrf = auth.create_session(user, "127.0.0.1", "pytest", "password")
    client.cookies.set(cookie, token)
    return {"x-csrf-token": csrf}


@pytest.fixture
def stack(tmp_path):
    """(settings, db, auth, ctx, upstream) with fakes for profiles/workers/hub."""
    def build(**server):
        settings = make_settings(**server)
        db = Database(tmp_path / f"gw{len(dbs)}.db")
        dbs.append(db)
        auth = AuthService(db, settings)
        c = Ctx(settings=settings, db=db, auth=auth, profiles=FakeProfiles(tmp_path), workers=None,
                hub=FakeHub(), version="test")
        up = FakeUpstream()
        c.upstream_for = lambda user: up
        return settings, db, auth, c, up
    dbs = []
    yield build
    for db in dbs:
        db.close()


def make_app(c: Ctx, routes=None) -> Starlette:
    async def on_http_error(request, exc):
        return exc.response()

    app = Starlette(routes=routes if routes is not None else [*api.routes, WebSocketRoute("/ws", gw_app.ws_endpoint)],
                    exception_handlers={HTTPError: on_http_error})
    app.add_middleware(gw_app.HostGuard, settings=c.settings)
    app.state.ctx = c
    return app


# ---------------------------------------------------------------- NEW-03: WebSocket API token in a header
def test_ws_token_in_authorization_header(stack):
    _, db, auth, c, _ = stack()
    u = mk_user(db, "alice")
    _, token = auth.create_api_token(u, "script", None)
    with TestClient(make_app(c), base_url="http://localhost") as client:
        with client.websocket_connect(WS, headers={"Authorization": f"Bearer {token}"}) as ws:
            ws.send_json({"jsonrpc": "2.0", "id": 1, "method": "session/list"})
            assert ws.receive_json()["result"]["user"] == "alice"


def test_ws_token_in_query_string_is_refused(stack):
    _, db, auth, c, _ = stack()
    _, token = auth.create_api_token(mk_user(db, "bob"), "script", None)
    with TestClient(make_app(c), base_url="http://localhost") as client:
        with pytest.raises(WebSocketDisconnect) as e:
            with client.websocket_connect(f"{WS}?token={token}"):
                pass
        assert e.value.code == 4401


def test_ws_token_with_origin_is_refused(stack):
    _, db, auth, c, _ = stack()
    _, token = auth.create_api_token(mk_user(db, "carol"), "script", None)
    with TestClient(make_app(c), base_url="http://localhost") as client:
        with pytest.raises(WebSocketDisconnect) as e:
            with client.websocket_connect(WS, headers={"Authorization": f"Bearer {token}",
                                                          "Origin": "http://localhost"}):
                pass
        assert e.value.code == 4401


def test_ws_cookie_from_allowed_origin_still_works(stack):
    _, db, auth, c, _ = stack()
    u = mk_user(db, "dora")
    with TestClient(make_app(c), base_url="http://localhost") as client:
        sign_in(client, auth, u)
        with client.websocket_connect(WS, headers={"Origin": "http://localhost"}) as ws:
            ws.send_json({"jsonrpc": "2.0", "id": 1, "method": "session/list"})
            assert ws.receive_json()["result"]["user"] == "dora"
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(WS, headers={"Origin": "http://evil.example"}):
                pass


def test_no_token_query_param_left_in_server_code():
    for f in (REPO / "goose_web").glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert 'query_params.get("token")' not in text, f.name


# ---------------------------------------------------------------- NEW-04: Host allow-list
@pytest.mark.parametrize("raw,host", [
    ("localhost:8710", "localhost"), ("LOCALHOST", "localhost"), ("127.0.0.1:8710", "127.0.0.1"),
    ("[::1]:8710", "::1"), ("[::1]", "::1"), ("goose.example.org.", "goose.example.org"),
    ("Goose.Example.org:443", "goose.example.org"), ("::1", "::1"),
    ("", ""), (None, ""), ("[::1", ""), ("[::1]x", ""), ("host:abc", ""), ("[]:80", ""),
])
def test_host_only(raw, host):
    assert gw_app.host_only(raw) == host


def test_allowed_hosts_defaults_and_deployment_shape():
    assert gw_app.allowed_hosts(make_settings()) == {"localhost", "127.0.0.1", "::1"}
    # bound to every address: only loopback names, never the wildcard
    assert gw_app.allowed_hosts(make_settings(host="0.0.0.0")) == {"localhost", "127.0.0.1", "::1"}
    assert gw_app.allowed_hosts(make_settings(host="::")) == {"localhost", "127.0.0.1", "::1"}
    # LAN bind + public URL behind a reverse proxy that passes the public Host
    s = make_settings(host="10.20.30.40", public_url="https://Goose.Example.net/", allowed_hosts=["Alias.Lan:8710"])
    assert gw_app.allowed_hosts(s) == {"localhost", "127.0.0.1", "::1", "10.20.30.40", "goose.example.net",
                                       "alias.lan"}
    assert "x.lan" in gw_app.allowed_hosts(make_settings(allowed_hosts="x.lan, y.lan"))


def _ping_app(settings: Settings) -> Starlette:
    async def ping(request):
        return PlainTextResponse("pong")

    app = Starlette(routes=[Route("/healthz", ping), Route("/api/ping", ping, methods=["GET", "POST"])])
    app.add_middleware(gw_app.HostGuard, settings=settings)
    return app


def test_host_guard_http():
    s = make_settings(host="10.20.30.40", public_url="https://goose.example.net")
    with TestClient(_ping_app(s), base_url="http://localhost:8710") as client:
        for host in ("localhost:8710", "127.0.0.1:8710", "[::1]:8710", "LOCALHOST", "goose.example.net",
                     "10.20.30.40:8710"):
            assert client.get("/api/ping", headers={"Host": host}).text == "pong", host
        for host in ("evil.example", "rebind.attacker.test:8710", "goose.example.net.evil.test", "[::1"):
            r = client.get("/api/ping", headers={"Host": host})
            assert r.status_code == 400 and r.text == "invalid host", host
            assert client.post("/api/ping", headers={"Host": host}).status_code == 400
        # health checks work with any Host (GET/HEAD only)
        assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 200
        assert client.head("/healthz", headers={"Host": "evil.example"}).status_code == 200


def test_host_guard_wildcard_bind():
    with TestClient(_ping_app(make_settings(host="0.0.0.0")), base_url="http://127.0.0.1:8710") as client:
        assert client.get("/api/ping").status_code == 200
        assert client.get("/api/ping", headers={"Host": "localhost:8710"}).status_code == 200
        assert client.get("/api/ping", headers={"Host": "0.0.0.0:8710"}).status_code == 400


def test_host_guard_forwarded_host_only_from_trusted_proxy():
    s = make_settings(public_url="https://goose.example.net")
    with TestClient(_ping_app(s), base_url="http://goose.example.net", client=("127.0.0.1", 5000)) as proxy:
        assert proxy.get("/api/ping", headers={"X-Forwarded-Host": "goose.example.net"}).status_code == 200
        assert proxy.get("/api/ping", headers={"X-Forwarded-Host": "evil.example"}).status_code == 400
    with TestClient(_ping_app(s), base_url="http://goose.example.net", client=("203.0.113.9", 5000)) as direct:
        # not a trusted proxy: the header is ignored everywhere, so it is not checked either
        assert direct.get("/api/ping", headers={"X-Forwarded-Host": "evil.example"}).status_code == 200


def test_host_guard_websocket(stack):
    _, db, auth, c, _ = stack()
    _, token = auth.create_api_token(mk_user(db, "erin"), "script", None)
    with TestClient(make_app(c), base_url="http://evil.example") as client:
        with pytest.raises(WebSocketDenialResponse) as e:
            with client.websocket_connect("ws://evil.example/ws", headers={"Authorization": f"Bearer {token}"}):
                pass
        assert e.value.status_code == 400 and e.value.content == b"invalid host"


def test_create_app_installs_host_guard():
    app = gw_app.create_app(make_settings())
    assert any(m.cls is gw_app.HostGuard for m in app.user_middleware)


def _conn(host: str, scheme: str = "http") -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "scheme": scheme, "query_string": b"",
                    "headers": [(b"host", host.encode())], "client": ("203.0.113.9", 1), "server": None})


def test_allowed_origins_with_public_url_ignore_host(stack):
    *_, c, _ = stack(public_url="https://Goose.Example.net:443", allowed_origins=["http://127.0.0.1:8710"])
    out = c.allowed_origins(_conn("evil.example"))
    assert "https://goose.example.net" in out and "http://127.0.0.1:8710" in out
    assert not any("evil" in o for o in out)


def test_allowed_origins_without_public_url_use_host(stack):
    *_, c, _ = stack()
    assert c.allowed_origins(_conn("localhost:8710")) == {"http://localhost:8710"}


@pytest.mark.parametrize("url,origin", [
    ("https://goose.example.net", "https://goose.example.net"), ("https://GOOSE.example.net:443/x", "https://goose.example.net"),
    ("http://h:8080/", "http://h:8080"), ("https://[::1]:8443", "https://[::1]:8443"), ("ftp://x", ""), ("", ""),
])
def test_url_origin(url, origin):
    assert url_origin(url) == origin


def test_oidc_refused_without_public_url(stack):
    *_, c, _ = stack()
    req = _conn("localhost")
    with pytest.raises(AuthError) as e:
        api._redirect_uri(c, req, "corp")
    assert e.value.code == "oidc_needs_public_url" and "public_url" in e.value.message
    with TestClient(make_app(c), base_url="http://localhost") as client:
        r = client.get("/api/auth/oidc/corp/start", follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == "/#/login?error=oidc_needs_public_url"
    *_, c2, _ = stack(public_url="https://goose.example.net/")
    assert api._redirect_uri(c2, _conn("evil.example"), "corp") == \
        "https://goose.example.net/api/auth/oidc/corp/callback"


# ---------------------------------------------------------------- NEW-01: tools/call extension prefix
def _chk(params, admin=False, policy=None):
    pol.check(P + "tools/call", params, is_admin=admin, policy=policy or dict(MEMBER), roots=["/x"])


@pytest.mark.parametrize("admin", [False, True])
def test_tools_call_prefix_must_match_extension(admin):
    policy = dict(pol.ADMIN_POLICY if admin else MEMBER)
    with pytest.raises(pol.Denied, match="does not belong to extension"):
        _chk({"sessionId": "s", "extensionName": "todo", "name": "developer__shell"}, admin, policy)
    with pytest.raises(pol.Denied, match="does not belong to extension"):
        _chk({"sessionId": "s", "extensionName": "todo", "toolName": "computercontroller__x"}, admin, policy)
    _chk({"sessionId": "s", "extensionName": "Todo", "name": "todo__write"}, admin, policy)
    _chk({"sessionId": "s", "extensionName": "todo", "name": "write"}, admin, policy)


def test_tools_call_keeps_allow_shell_check():
    with pytest.raises(pol.Denied, match="allow_shell"):
        _chk({"sessionId": "s", "extensionName": "developer", "name": "developer__shell"})
    with pytest.raises(pol.Denied, match="allow_shell"):
        _chk({"sessionId": "s", "extensionName": "developer", "name": "shell"})
    _chk({"sessionId": "s", "extensionName": "developer", "name": "developer__shell"}, admin=True,
         policy=dict(pol.ADMIN_POLICY))


# ---------------------------------------------------------------- NEW-05: upload names
@pytest.mark.parametrize("raw,name", [
    ("report.pdf", "report.pdf"), ("CON", "_CON"), ("con.txt", "_con.txt"), ("COM1.tar.gz", "_COM1.tar.gz"),
    ("lpt9.log", "_lpt9.log"), ("CONIN$", "_CONIN$"), ("conout$.txt", "_conout$.txt"), ("NUL", "_NUL"),
    ("aux .txt", "_aux .txt"), ("CONSOLE.txt", "CONSOLE.txt"), ("COM10.txt", "COM10.txt"),
    ("a.txt. . ", "a.txt"), ("  b.txt", "b.txt"), ("...", "upload.bin"), ("", "upload.bin"), (None, "upload.bin"),
    (r"..\..\evil.txt", "evil.txt"), ("../../x/y.txt", "y.txt"), ('bad<>:"|?*\x00\x1fname.txt', "badname.txt"),
    ("NUL.", "_NUL"),
])
def test_safe_upload_name(raw, name):
    assert api.safe_upload_name(raw) == name


def test_safe_upload_name_truncation_strips_trailing_dots():
    assert api.safe_upload_name("a" * 179 + ". tail.txt") == "a" * 179
    assert len(api.safe_upload_name("x" * 500 + ".txt")) == 180
    assert len(api.safe_upload_name("é" * 300).encode()) <= 200


def test_create_exclusive_never_overwrites(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"original")
    (tmp_path / "a (1).txt").write_bytes(b"original 1")
    target, fh = api._create_exclusive(tmp_path, "a.txt")
    with fh:
        fh.write(b"new")
        assert fh.mode == "xb"
    assert target.name == "a (2).txt"
    assert (tmp_path / "a.txt").read_bytes() == b"original"
    assert (tmp_path / "a (1).txt").read_bytes() == b"original 1"


def test_upload_endpoint_sanitises_and_keeps_existing(stack, tmp_path):
    _, db, auth, c, _ = stack()
    root = mk_user(db, "root", role="admin")
    d = tmp_path / "up"
    d.mkdir()
    (d / "_CON.txt").write_bytes(b"keep me")
    with TestClient(make_app(c), base_url="http://localhost") as client:
        h = sign_in(client, auth, root)
        r = client.post("/api/fs/upload", params={"dir": str(d)}, headers=h,
                        files=[("f", ("CON.txt", b"one")), ("f", ("notes.md. ", b"two"))])
        assert r.status_code == 200, r.text
        names = [f["name"] for f in r.json()["files"]]
    assert names == ["_CON (1).txt", "notes.md"]
    assert (d / "_CON.txt").read_bytes() == b"keep me"
    assert (d / "_CON (1).txt").read_bytes() == b"one"


# ---------------------------------------------------------------- NEW-08: downloads
def test_download_is_octet_stream_attachment(stack, tmp_path):
    _, db, auth, c, _ = stack()
    f = tmp_path / "page.html"
    f.write_text("<script>alert(1)</script>", encoding="utf-8")
    with TestClient(make_app(c), base_url="http://localhost") as client:
        sign_in(client, auth, mk_user(db, "root", role="admin"))
        r = client.get("/api/fs/download", params={"path": str(f)})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"].startswith("attachment")
    assert r.headers["content-security-policy"].startswith("sandbox")


# ---------------------------------------------------------------- NEW-07: apps frame
def test_app_frame_csp_has_no_popup_escape():
    assert "allow-popups-to-escape-sandbox" not in api.APP_FRAME_CSP
    assert api.APP_FRAME_CSP.startswith("sandbox ")


def test_apps_frame_runs_policy_check_and_audits_denial(stack, monkeypatch):
    _, db, auth, c, up = stack()
    u = mk_user(db, "fred")
    seen = []
    real_check = pol.check

    def spy(method, params, **kw):
        seen.append((method, kw["is_admin"]))
        real_check(method, params, **kw)

    monkeypatch.setattr(api.acp_policy, "check", spy)
    with TestClient(make_app(c), base_url="http://localhost") as client:
        sign_in(client, auth, u)
        r = client.get("/api/apps/frame", params={"name": "clock"})
        assert r.status_code == 200 and r.text == "<p>app</p>"
        assert "allow-popups-to-escape-sandbox" not in r.headers["content-security-policy"]
        assert seen == [(P + "apps/export", False)]
        r = client.get("/api/apps/frame", params={"uri": "ui://x/app", "sessionId": "s1", "ext": "todo"})
        assert seen[-1] == (P + "resources/read", False)

        def deny(method, params, **kw):
            raise pol.Denied("not today")

        monkeypatch.setattr(api.acp_policy, "check", deny)
        n = len(up.calls)
        r = client.get("/api/apps/frame", params={"name": "clock"})
        assert r.status_code == 403 and "not today" in r.json()["message"]
        assert len(up.calls) == n  # the upstream was never asked
    row = db.one("SELECT * FROM audit WHERE action='acp.denied' ORDER BY id DESC LIMIT 1")
    assert row is not None and row["ok"] == 0 and row["target"] == P + "apps/export"


# ---------------------------------------------------------------- webhooks
def test_notify_webhook_validated_at_save(stack, monkeypatch):
    _, db, auth, c, _ = stack()
    root = mk_user(db, "root", role="admin")  # admins have notify_webhook

    async def fake_resolve(host, port):
        return {"hooks.example.org": ["93.184.215.14"], "internal.example.org": ["10.1.2.3"]}.get(host, [])

    monkeypatch.setattr(gw_app, "_resolve", fake_resolve)
    with TestClient(make_app(c), base_url="http://localhost") as client:
        h = sign_in(client, auth, root)
        for bad in ("http://127.0.0.1:9000/x", "http://169.254.169.254/latest", "https://internal.example.org/x",
                    "https://nowhere.example.org/x"):
            r = client.put("/api/me/notify", headers=h, json={"webhook": bad, "events": ["done"]})
            assert r.status_code == 400 and r.json()["error"] == "webhook_blocked", bad
            assert "not allowed" in r.json()["message"]
        r = client.put("/api/me/notify", headers=h, json={"webhook": "https://hooks.example.org/x", "events": ["done"]})
        assert r.status_code == 200
        r = client.put("/api/me/notify", headers=h, json={"webhook": ["x"], "events": []})
        assert r.status_code == 400 and r.json()["error"] == "bad_url"
    c.settings.data["notify"]["allow_private_targets"] = True
    with TestClient(make_app(c), base_url="http://localhost") as client:
        h = sign_in(client, auth, root)
        r = client.put("/api/me/notify", headers=h, json={"webhook": "https://internal.example.org/x"})
        assert r.status_code == 200


async def test_send_webhook_ignores_environment_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")

    async def fake_resolve(host, port):
        return ["93.184.215.14"]

    monkeypatch.setattr(gw_app, "_resolve", fake_resolve)
    seen = {}
    real = httpx.AsyncClient

    class Recording(real):
        def __init__(self, *a, **kw):
            seen.update(kw)
            super().__init__(*a, **kw)

    monkeypatch.setattr(gw_app.httpx, "AsyncClient", Recording)
    r = await gw_app.send_webhook("https://hooks.example.org/x", json={},
                                  transport=httpx.MockTransport(lambda req: httpx.Response(204)))
    assert r.status_code == 204 and seen["trust_env"] is False


# ---------------------------------------------------------------- CLI user reset
def test_cli_user_reset_revokes_tokens_and_sessions(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("GOOSE_WEB__") or k == "GOOSE_WEB_CONFIG":
            monkeypatch.delenv(k, raising=False)
    root = tmp_path / "profiles"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"paths": {"profiles_root": str(root)}}), encoding="utf-8")
    assert cli.main(["--config", str(path), "init", "--admin", "alice", "--native-root", "fresh"]) == 0
    db = Database(root / "_system" / "goose-web.db")
    try:
        auth = AuthService(db, make_settings())
        u = db.user_by_name("alice")
        auth.create_api_token(u, "t", None)
        auth.create_session(u, "127.0.0.1", "pytest", "password")
        assert cli.main(["--config", str(path), "user", "reset", "alice", "--password", "Temp-Pass-1234"]) == 0
        assert db.one("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id=?", (u["id"],))["n"] == 0
        assert db.one("SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?", (u["id"],))["n"] == 0
    finally:
        db.close()


# ---------------------------------------------------------------- repo hygiene
def test_vendor_files_are_not_eol_converted():
    lines = (REPO / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "goose_web/static/vendor/* -text" in lines
    assert "goose_web/static/vendor/SHA256SUMS -text" in lines
