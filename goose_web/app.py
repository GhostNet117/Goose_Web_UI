"""ASGI application: lifespan wiring, security headers, static SPA and the /ws real-time channel."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect

from . import __version__, activity, api, logjanitor, security, tls
from .auth import AuthService
from .config import Settings
from .context import DEFAULT_BODY_LIMIT, BodyTooLarge, Ctx, HTTPError, _ip_in
from .db import Database
from .hub import Client, Hub
from .ipblock import BLOCKED_MESSAGE
from .profiles import Profiles
from .workers import WorkerManager, goose_version

log = logging.getLogger("goose_web")
STATIC = Path(__file__).parent / "static"

SPA_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
           "media-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; font-src 'self' data:; "
           "worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
           "frame-ancestors 'none'")


class SecurityHeaders:
    """Adds security headers to every HTTP response (apps frames set their own CSP)."""

    def __init__(self, app: ASGIApp, hsts: bool):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                have = {bytes(k).lower() for k, _ in headers}
                # A header the route already set (the apps frame sends Referrer-Policy: no-referrer) is never
                # given a second value: browsers would use the last one (D-9).
                add = [(k, v) for k, v in (
                       (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"same-origin"),
                       (b"cross-origin-opener-policy", b"same-origin"),
                       (b"cross-origin-resource-policy", b"same-origin"),
                       (b"permissions-policy", b"camera=(), geolocation=(), payment=(), usb=(), microphone=(self)"))
                       if k not in have]
                if b"content-security-policy" not in have:
                    add.append((b"content-security-policy", SPA_CSP.encode()))
                if b"x-frame-options" not in have:
                    add.append((b"x-frame-options", b"DENY"))
                if path.startswith("/api/") and b"cache-control" not in have:
                    add.append((b"cache-control", b"no-store"))
                if self.hsts and b"strict-transport-security" not in have:
                    add.append((b"strict-transport-security", b"max-age=31536000"))
                headers.extend(add)
            await send(message)
        await self.app(scope, receive, wrapped)


# ---------------------------------------------------------------------- request body cap (A-1, A-2)
# Routes that take more than DEFAULT_BODY_LIMIT: (path pattern, bytes). /api/fs/upload follows server.max_upload_mb.
_LARGE_BODY_ROUTES = ((re.compile(r"^/api/admin/teams/\d+/items$"), 8 * 1024 * 1024),)
_MULTIPART_SLACK = 64 * 1024   # multipart boundaries and part headers on top of the file bytes


def upload_limit_mb(settings: Settings) -> int:
    return int(settings.get("server", "max_upload_mb") or 25)


class BodyLimit:
    """Caps every HTTP request body before anything buffers it (A-1, A-2).

    A Content-Length above the route's cap is refused with 413 at once. Bodies without one (chunked transfer
    encoding) are counted while the route receives them; the receive call raises BodyTooLarge (413) as soon as
    the running total passes the cap, so neither memory (body_json) nor the temp files of a multipart form
    (request.form) ever hold more than the cap. Caps: /api/fs/upload = server.max_upload_mb (+ multipart
    overhead), a few large admin routes per _LARGE_BODY_ROUTES, everything else DEFAULT_BODY_LIMIT (2 MB).
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    def limit_for(self, path: str) -> tuple[int, str]:
        if path == "/api/fs/upload":
            mb = upload_limit_mb(self.settings)
            return mb * 1024 * 1024 + _MULTIPART_SLACK, f"Uploads are limited to {mb} MB"
        for pattern, limit in _LARGE_BODY_ROUTES:
            if pattern.match(path):
                return limit, "Request body too large"
        return DEFAULT_BODY_LIMIT, "Request body too large"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit, message = self.limit_for(str(scope.get("path") or ""))
        try:
            declared = int(Headers(scope=scope).get("content-length") or 0)
        except ValueError:
            return await HTTPError(400, "bad_request", "Invalid Content-Length").response()(scope, receive, send)
        if declared > limit:
            return await BodyTooLarge(message).response()(scope, receive, send)
        received = 0
        started = False

        async def counted_receive():
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body") or b"")
                if received > limit:
                    raise BodyTooLarge(message)
            return msg

        async def tracked_send(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except BodyTooLarge as e:   # normally answered by the HTTPError handler; this covers everything else
            if not started:
                await e.response()(scope, receive, send)


# ---------------------------------------------------------------------- Host allow-list (NEW-04)
_WILDCARD_BINDS = {"", "0.0.0.0", "::", "*"}  # nosec B104 - used to detect a wildcard bind, never to bind


def host_only(value: str | None) -> str:
    """The host part of a Host header (or a configured host): port removed, IPv6 brackets removed,
    lower-cased, trailing dot removed. Returns "" for a malformed value."""
    v = (value or "").strip().lower()
    if not v:
        return ""
    if v.startswith("["):
        end = v.find("]")
        rest = v[end + 1:] if end > 0 else "x"
        if end <= 1 or (rest and not (rest[0] == ":" and rest[1:].isdigit())):
            return ""
        return v[1:end]
    if v.count(":") == 1:
        v, _, port = v.partition(":")
        if port and not port.isdigit():
            return ""
    # more than one ':' = a bare IPv6 literal (only meaningful in configuration values)
    return v.rstrip(".") if v.count(":") <= 1 else v


def allowed_hosts(settings: Settings) -> set[str]:
    """Effective Host allow-list: public_url's host name, loopback names, the bind address (unless it is a
    wildcard address) and server.allowed_hosts."""
    out = {"localhost", "127.0.0.1", "::1"}
    if settings.public_url:
        try:
            name = urlsplit(settings.public_url).hostname
        except ValueError:
            name = None
        if name:
            out.add(name.lower().rstrip("."))
    bind = host_only(str(settings.get("server", "host") or ""))
    if bind not in _WILDCARD_BINDS:
        out.add(bind)
    extra = settings.get("server", "allowed_hosts") or []
    if isinstance(extra, str):
        extra = extra.split(",")
    for h in extra:
        h = host_only(str(h))
        if h:
            out.add(h)
    return out


class HostGuard:
    """Refuses HTTP and WebSocket requests whose Host is not on the allow-list (DNS rebinding).

    X-Forwarded-Host is only looked at when the peer is a trusted proxy (the same rule `Ctx.allowed_origins`
    uses before it honours that header); then it must be allow-listed as well. GET/HEAD /healthz is exempt
    so container and load-balancer health checks work with any Host.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings
        self.hosts = allowed_hosts(settings)

    def host_ok(self, scope: Scope) -> bool:
        headers = Headers(scope=scope)
        if host_only(headers.get("host")) not in self.hosts:
            return False
        fwd = headers.get("x-forwarded-host")
        if fwd is not None:
            peer = (scope.get("client") or ("", 0))[0] or ""
            if _ip_in(peer, self.settings.get("server", "trusted_proxies") or []):
                return all(host_only(h) in self.hosts for h in fwd.split(","))
        return True

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if scope["type"] == "http" and scope.get("path") == "/healthz" and scope.get("method") in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        if self.host_ok(scope):
            return await self.app(scope, receive, send)
        bad = PlainTextResponse("invalid host", status_code=400)
        if scope["type"] == "http":
            return await bad(scope, receive, send)
        if "websocket.http.response" in (scope.get("extensions") or {}):
            return await WebSocket(scope, receive, send).send_denial_response(bad)
        await send({"type": "websocket.close", "code": 1008, "reason": "invalid host"})


class IPBlockGuard:
    """Refuses every HTTP request and WebSocket handshake from a blocked client address (spec 007).

    The address is `Ctx.client_ip` (X-Forwarded-For only from trusted proxies). GET/HEAD /healthz stays open.
    Before the lifespan has created the context, everything passes.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        if scope["type"] == "http" and scope.get("path") == "/healthz" and scope.get("method") in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        app = scope.get("app")
        c = getattr(getattr(app, "state", None), "ctx", None)
        if c is None or not c.auth.ipblock.is_blocked(c.client_ip(HTTPConnection(scope))):
            return await self.app(scope, receive, send)
        if str(scope.get("path") or "").startswith("/api/"):
            deny: Response = JSONResponse({"error": "ip_blocked", "message": BLOCKED_MESSAGE}, status_code=403,
                                          headers={"Cache-Control": "no-store"})
        else:
            deny = PlainTextResponse(BLOCKED_MESSAGE, status_code=403, headers={"Cache-Control": "no-store"})
        if scope["type"] == "http":
            return await deny(scope, receive, send)
        if "websocket.http.response" in (scope.get("extensions") or {}):
            return await WebSocket(scope, receive, send).send_denial_response(deny)
        await send({"type": "websocket.close", "code": 1008, "reason": "address blocked"})


async def index(request: Request):
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


async def sw(request: Request):
    return FileResponse(STATIC / "sw.js", media_type="text/javascript",
                        headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})


async def manifest(request: Request):
    return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json",
                        headers={"Cache-Control": "no-cache"})


class Static(StaticFiles):
    async def get_response(self, path: str, scope):
        # Windows aliases of the same file (index.html::$DATA, index~1.htm, "index.html.") are not served (A-14).
        if ":" in path or "~" in path or any(seg.endswith((".", " ")) for seg in re.split(r"[\\/]", path) if seg):
            raise StarletteHTTPException(status_code=404)
        resp = await super().get_response(path, scope)
        resp.headers.setdefault("Cache-Control", "no-cache")  # revalidate (ETag) so updates apply at once
        return resp


# ---------------------------------------------------------------------- websocket
async def _maintenance_loop(c: Ctx) -> None:
    """Spec 015: keep logs under the disk budget, prune the audit table, renew the built-in certificate."""
    minutes = max(1.0, float(c.settings.get("logs", "check_minutes") or 30))
    while True:
        try:
            native = c.db.get_setting("native_root") or ""
            in_use = {str(c.settings.system_dir / "logs" / f"worker-{k}.log")
                      for k, w in c.workers.workers.items() if w.proc and w.proc.poll() is None}
            rep = await asyncio.to_thread(logjanitor.enforce, c.settings, native, in_use)
            c.log_report = dict(rep, at=time.time())
            pruned = await asyncio.to_thread(logjanitor.prune_audit, c.settings, c.db)
            if pruned:
                log.info("audit: pruned %d old row(s)", pruned)
            # SC-7: queued messages and herd marks do not live forever (a restart no longer is the only cleanup)
            from .hub import MARK_MAX_AGE, QUEUE_MAX_AGE
            swept = await asyncio.to_thread(c.db.sweep_chat_state, queue_age=QUEUE_MAX_AGE, mark_age=MARK_MAX_AGE)
            if swept:
                log.info("chat state: removed %d expired queue/mark row(s)", swept)
            c.hub.expire_queues(QUEUE_MAX_AGE)
            if tls.is_active() and tls.ACTIVE.get("mode") == "self-signed":
                st = await asyncio.to_thread(tls.ensure, c.settings)
                if st.get("renewed"):
                    tls.reload_active()
                    c.db.audit("tls.renewed", detail={"reason": st.get("reason"),
                                                      "until": (st.get("cert") or {}).get("notAfter")})
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("maintenance")
        await asyncio.sleep(minutes * 60)


LIBRARY_REFRESH_SECONDS = 300


async def _library_loop(c: Ctx) -> None:
    """What an administrator changes in his own profile - a provider, an extension, a skill, a recipe - reaches the
    teams he gave it to within a few minutes (api.refresh_library), without removing and adding the item again."""
    from . import api as _api
    await asyncio.sleep(45)
    while True:
        try:
            await _api.refresh_library(c)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("library refresh")
        await asyncio.sleep(LIBRARY_REFRESH_SECONDS)


async def ca_cert(request: Request):
    """The built-in local CA certificate (public), so users can trust the self-signed HTTPS certificate."""
    p = tls.tls_dir(request.app.state.ctx.settings) / "ca.crt"
    if not p.exists():
        raise HTTPError(404, "not_found", "No local CA (built-in HTTPS is not in use)")
    return Response(p.read_bytes(), media_type="application/x-x509-ca-cert",
                    headers={"Content-Disposition": 'attachment; filename="goose-web-ca.crt"', "Cache-Control": "no-cache"})


async def _close_ws(websocket: WebSocket) -> None:
    try:
        await websocket.close(code=4401)
    except Exception:
        pass


async def ws_endpoint(websocket: WebSocket):
    c: Ctx = websocket.app.state.ctx
    origin = websocket.headers.get("origin")
    ident = None
    # API tokens come only in the handshake's "Authorization: Bearer gwt_..." header, never in the URL (where
    # access and proxy logs would record them). Browsers cannot set that header, and a token socket must not
    # carry an Origin; browser sockets authenticate with the session cookie from an allowed Origin.
    authz = websocket.headers.get("authorization") or ""
    token_hash = ""
    if authz:
        if not origin and authz[:7].lower() == "bearer ":
            ident = c.auth.resolve_token(authz[7:].strip())
            token_hash = security.token_hash(authz[7:].strip())
    elif origin and origin in c.allowed_origins(websocket):
        ident = c.identity(websocket)
    if ident is None or c.must_enrol_or_change(ident.user):   # password change / two-factor enrolment first (A-8)
        await websocket.close(code=4401)  # before accept -> HTTP 403 for the browser
        return
    user = ident.user
    target = user
    want = websocket.query_params.get("profile")
    if want and want.lower() != user["username"].lower():
        if user["role"] != "admin":
            await websocket.close(code=4403)
            return
        target = c.db.user_by_name(want)
        if not target:
            await websocket.close(code=4404)
            return
    await websocket.accept()
    ip = c.client_ip(websocket)
    if target is not user:
        c.db.audit("ws.impersonate", user=user, ip=ip, target=target["username"])
    # Only admins can target another profile, and admins are unrestricted; calls on another
    # profile are audited by the hub (profile key differs from the caller's).
    policy = c.policy_for(user)
    roots = c.roots_for(target, policy)
    up = c.upstream_for(target)
    client = Client(websocket.send_text, user, policy, roots, ip)
    # SC-3: the hub can end this socket (user deleted / disabled / signed out) and re-checks its sign-in
    session_hash = (ident.session or {}).get("token_hash") if ident.session else None

    def kick() -> None:
        asyncio.get_running_loop().create_task(_close_ws(websocket))

    def still_valid() -> bool:
        now = time.time()
        if session_hash:
            row = c.db.one("SELECT expires_at FROM auth_sessions WHERE token_hash=?", (session_hash,))
        elif token_hash:
            row = c.db.one("SELECT expires_at FROM api_tokens WHERE token_hash=?", (token_hash,))
            if row is not None and not row["expires_at"]:
                row = {"expires_at": now + 1}
        else:
            return True
        u = c.db.user_by_id(user["id"])
        if not (row and row["expires_at"] > now and u and not u["disabled"]):
            return False
        if c.must_enrol_or_change(u):       # spec 029: two-factor became a requirement for this account
            return False
        # A-1: the rights this socket was opened with (role, policy, folders) must still be the current ones
        try:
            t = u if target["id"] == user["id"] else c.db.user_by_id(target["id"])
            return t is not None and c.rights_fingerprint(u, t) == rights
        except Exception:
            # fail closed (second review 2026-11-12, R-6): a socket whose rights cannot be checked is ended; the
            # browser reconnects and the new socket gets the rights of that moment, or the failure becomes visible
            log.exception("socket re-validation (rights)")
            return False
    try:
        rights = c.rights_fingerprint(user, target)
    except Exception:
        log.exception("socket rights fingerprint")
        rights = ""
    client.kick, client.still_valid = kick, still_valid
    client.start()
    c.hub.attach(up, client)
    opened = time.time()
    activity.record("ws.connect", user=user, ip=ip, target=target["username"])
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw) > 64 * 1024 * 1024:
                break
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            try:
                await up.from_client(client, msg)
            except Exception as e:  # never let one bad frame kill the socket
                log.exception("ws frame error")
                if msg.get("id") is not None and msg.get("method"):
                    # internal detail stays in the gateway log (A-13)
                    client.send({"jsonrpc": "2.0", "id": msg["id"],
                                 "error": {"code": -32603, "message": f"Internal error ({e.__class__.__name__}, "
                                                                     "see the gateway log)"}})
            if client.closed:
                break
    except WebSocketDisconnect:
        pass
    except RuntimeError:
        pass
    finally:
        c.hub.detach(up, client)
        activity.record("ws.disconnect", user=user, ip=ip, target=target["username"],
                        detail={"seconds": round(time.time() - opened)})


# ---------------------------------------------------------------------- notifications (webhooks)
class WebhookBlocked(Exception):
    """The webhook target is not an allowed destination (SSRF guard, GW-20)."""


# Well-known NAT64 prefix: a "global" IPv6 address that reaches an embedded IPv4 address.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def address_blocked(address: str) -> bool:
    """True if `address` (an IP literal, optionally with an IPv6 %scope) must not receive webhooks.

    Refuses loopback, private, link-local, reserved, multicast, unspecified and every other non-global
    address (for example 100.64.0.0/10 carrier-grade NAT). IPv6 addresses that embed an IPv4 address
    (IPv4-mapped, 6to4, Teredo, NAT64) are judged by the embedded IPv4 address as well. Anything that
    cannot be parsed is blocked.
    """
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0].strip("[]"))
    except ValueError:
        return True
    candidates = [ip]
    if ip.version == 6 and ip.ipv4_mapped is not None:
        candidates = [ip.ipv4_mapped]   # ::ffff:a.b.c.d is a.b.c.d (Python versions classify the v6 form differently)
    elif ip.version == 6:
        if ip.sixtofour is not None:
            candidates.append(ip.sixtofour)
        if ip.teredo is not None:
            candidates.extend(ip.teredo)
        if ip in _NAT64:
            candidates.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    for a in candidates:
        if (a.is_loopback or a.is_private or a.is_link_local or a.is_reserved or a.is_multicast
                or a.is_unspecified or not a.is_global):
            return True
    return False


async def _resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def webhook_target(url: str, allow_private: bool = False) -> tuple[httpx.URL, str, str]:
    """Validate a webhook URL and pin it to a resolved address.

    Returns (url_with_ip, host_header, sni_hostname). Every address the host resolves to must pass
    `address_blocked` unless `allow_private`; the request then goes to the checked address, so a DNS
    answer that changes between the check and the connection (DNS rebinding) cannot redirect it.
    """
    try:
        u = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError) as e:
        raise WebhookBlocked(f"invalid URL: {e}") from None
    if u.scheme not in ("http", "https") or not u.host:
        raise WebhookBlocked("webhook must be an absolute http(s) URL")
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        addresses = await _resolve(u.host, port)
    except (OSError, UnicodeError) as e:
        raise WebhookBlocked(f"cannot resolve {u.host}: {e}") from None
    if not addresses:
        raise WebhookBlocked(f"cannot resolve {u.host}")
    if not allow_private:
        bad = [a for a in addresses if address_blocked(a)]
        if bad:
            raise WebhookBlocked(f"{u.host} resolves to a non-public address ({', '.join(bad)}); "
                                 "set notify.allow_private_targets to allow internal targets")
    pinned = u.copy_with(host=addresses[0].split("%", 1)[0])
    return pinned, u.netloc.decode("ascii"), u.host


async def send_webhook(url: str, *, allow_private: bool = False, transport: httpx.AsyncBaseTransport | None = None,
                       **kwargs) -> httpx.Response:
    """POST to a user webhook after the SSRF checks. Redirects are never followed."""
    pinned, host_header, sni = await webhook_target(url, allow_private)
    headers = {**(kwargs.pop("headers", None) or {}), "Host": host_header}
    # trust_env=False: an HTTP(S)_PROXY / ALL_PROXY from the environment would connect on our behalf and
    # bypass the pinned, checked address.
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, transport=transport, trust_env=False) as client:
        return await client.post(pinned, headers=headers, extensions={"sni_hostname": sni}, **kwargs)


def make_event_handler(c: Ctx):
    async def post(url: str, event: str, agent: dict):
        title = {"needs_you": "Goose needs you", "done": "Goose finished", "error": "Goose hit an error"}[event]
        link = f"{c.settings.public_url}/#/chat/{agent['sessionId']}" if c.settings.public_url else ""
        msg = f"{agent.get('title') or agent['sessionId']}: {agent.get('lastText') or ''}"[:500]
        allow_private = bool(c.settings.get("notify", "allow_private_targets"))
        try:
            if "ntfy" in url:
                await send_webhook(url, allow_private=allow_private, content=msg.encode(), headers={
                    "Title": title, "Tags": "goose", "Click": link,
                    "Priority": "high" if event == "needs_you" else "default"})
            else:
                await send_webhook(url, allow_private=allow_private,
                                   json={"event": event, "title": title, "message": msg, "url": link,
                                         "agent": agent})
        except WebhookBlocked as e:
            log.warning("webhook refused for %s: %s", agent.get("username"), e)
        except httpx.HTTPError as e:
            log.info("webhook failed for %s: %s", agent.get("username"), e)

    def handler(username: str, event: str, agent: dict, watched: bool):
        if watched:
            return
        u = c.db.user_by_name(username)
        if not u:
            return
        n = (u.get("prefs") or {}).get("_notify") or {}
        if n.get("webhook") and event in (n.get("events") or []) and c.policy_for(u).get("notify_webhook"):
            asyncio.get_running_loop().create_task(post(n["webhook"], event, agent))
    return handler


def _ext_fingerprint(e: Any) -> tuple:
    e = e if isinstance(e, dict) else {}
    return tuple(str(e.get(k) or "") for k in ("type", "cmd", "uri", "url", "name")) + \
        (json.dumps(e.get("args") or [], sort_keys=True),)


def wire_security_hooks(c: Ctx) -> None:
    """Security review 2026-11-11 hooks between the hub, the workers, the guard and the profiles."""
    from . import guard as guardmod
    from . import policy as pol
    from .profiles import _read_yaml, strip_always_allow

    def pre_start(w) -> None:
        """SA-1: before EVERY worker start an isolated profile is provisioned again, so whatever the agent wrote
        into its own config files (permission.yaml 'always allow', config.yaml extensions / mode / provider) is
        reset to the team policy before Goose reads them. The native profile is never rewritten (shared with
        Goose Desktop); the bypass detector covers it."""
        u = c.db.user_by_name(w.username)
        if not u or c.profiles.is_native(u):
            return
        changes = c.profiles.provision(u)
        if u.get("role") == "admin" and c.guard is not None and c.guard.admin_config()["enabled"]:
            if strip_always_allow(c.profiles.config_dir(u) / "permission.yaml"):
                changes.append("prompt guard: 'always allow' tool permissions removed")
        # Spec 026: Goose's own security settings also go into the worker's environment, which Goose ranks above
        # the profile's files. (For an AppContainer the worker manager replaces the endpoint's address with the
        # relay forwarder's when it builds the environment.) A failure fails the start, like provisioning.
        w.security_env = dict(c.profiles.security_plan(u)["env"])
        if changes:
            log.info("worker %s: provisioned before start (%s)", w.key, "; ".join(changes)[:500])
    c.workers.pre_start = pre_start

    def profile_paths(username: str) -> list[str]:
        u = c.db.user_by_name(username)
        return [str(c.profiles.config_dir(u))] if u else []
    c.guard.profile_paths = profile_paths

    def ext_identity(username: str, ext: str) -> bool:
        """SA-8: a trusted extension is the team's only while the profile's config entry for it is the entry the
        team provides (or a bundled platform/builtin one) - not a member's own extension with that name."""
        u = c.db.user_by_name(username)
        if not u:
            return False
        want = guardmod.ext_key(ext)
        team = {}
        for it in c.profiles.team_items(u):
            if it["kind"] == "extension":
                p = it.get("payload") or {}
                for n in (p.get("key"), it["name"], pol._ext_name(p.get("entry"))):
                    if n and guardmod.ext_key(n) == want and isinstance(p.get("entry"), dict):
                        team = p["entry"]
        exts = (_read_yaml(c.profiles.config_dir(u) / "config.yaml").get("extensions") or {})
        mine = [e for k, e in exts.items() if isinstance(e, dict) and want in (guardmod.ext_key(k),
                                                                              guardmod.ext_key(e.get("name")))]
        if not mine:
            return False
        if team:
            relays = c.profiles.relay_mapping(u) if hasattr(c.profiles, "relay_mapping") else {}
            if relays:   # a sandboxed member's entry carries the relay forwarder's URL (spec 014, closeout F1)
                from . import relay as rl
                team = json.loads(rl.rewrite_text(json.dumps(team), relays))
            return all(_ext_fingerprint(e) == _ext_fingerprint(team) for e in mine)
        return all(str(e.get("type") or "").lower() in ("platform", "builtin") and e.get("bundled") is not False
                   for e in mine)
    c.guard.ext_identity = ext_identity

    def on_burst(username: str) -> None:
        c.db.audit("guard.burst", user=c.db.user_by_name(username), target=username,
                   detail={"limit": guardmod.BURST_LIMIT, "windowSeconds": guardmod.BURST_WINDOW}, ok=False)
        c.hub.broadcast_admins({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
            "level": "warning", "kind": "guard",
            "message": f"The prompt guard blocked {guardmod.BURST_LIMIT} requests of {username} within "
                       f"{int(guardmod.BURST_WINDOW // 60)} minutes; their guarded requests are refused for now."}})
    c.guard.on_burst = on_burst

    def on_bypass(key: str, username: str) -> None:
        """SA-1: re-provision the isolated profile (strips 'always allow') and restart its worker, so the next run
        asks again. The native profile is left alone (its chats are cancelled each time instead)."""
        u = c.db.user_by_name(username)
        if not u or c.profiles.is_native(u):
            return

        async def run():
            try:
                await c.workers.restart(key)   # pre_start provisions before Goose starts again
            except Exception:
                log.exception("restarting %s after a guard bypass", key)
        asyncio.get_running_loop().create_task(run())
    c.hub.on_guard_bypass = on_bypass

    def member_writable(path: str) -> bool:
        """SD-2: folders members can write: the profiles root (their profiles, the default team folders) and
        every team's share folder and extra folders."""
        roots = [str(c.settings.profiles_root)]
        for t in c.db.query("SELECT * FROM teams"):
            roots.append(str(c.profiles.team_folder(t)))
            roots += [r for r in ((t.get("policy") or {}).get("allowed_roots") or []) if r and r != pol.ANY]
        try:
            return any(pol._within(pol._norm(path), pol._norm(r)) or
                       ((pol._real(path) or "") and pol._real(r) and pol._within(pol._real(path), pol._real(r)))
                       for r in roots)
        except (OSError, ValueError):
            return True
    c.hub.member_writable = member_writable


def make_audit_handler(c: Ctx):
    def handler(client: Client, action: str, target: str, detail: dict, ok: bool):
        try:
            c.db.audit(action, user=client.user, ip=client.ip, target=target, detail=detail, ok=ok)
        except Exception:
            log.exception("audit write failed")
    return handler


# ---------------------------------------------------------------------- app factory
def create_app(settings: Settings) -> Starlette:
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        settings.system_dir.mkdir(parents=True, exist_ok=True)
        db = Database(settings.system_dir / "goose-web.db")
        workers = WorkerManager(settings)
        hub = Hub(workers)
        profiles = Profiles(settings, db)
        c = Ctx(settings=settings, db=db, auth=AuthService(db, settings), profiles=profiles, workers=workers,
                hub=hub, version=__version__)
        c.goose_version = await asyncio.to_thread(goose_version, settings.goose_binary)
        hub.on_audit = make_audit_handler(c)
        hub.on_event = make_event_handler(c)
        hub.db = db   # spec 019: composer queues and herd marks survive a restart
        hub.profile_root_for = lambda username: str(profiles.root_for(db.user_by_name(username) or {"username": username}))
        # Prompt guard (spec 018): rules + the local classifier; loads nothing until some guard is on.
        from .guard import GuardService
        c.guard = hub.guard = GuardService(settings, db)
        # SA-10: who and which chat made the classifier unavailable (the user's own row in the audit)
        c.guard.on_unavailable = lambda reason, point, who: db.audit(
            "guard.unavailable", user=db.user_by_name(who.get("username") or "") if who.get("username") else None,
            target=point, detail={"reason": reason[:300], "point": point, **{k: v for k, v in who.items() if v}},
            ok=False)
        c.guard.on_health = lambda h: hub.broadcast_admins({"jsonrpc": "2.0", "method": "_gw/guard", "params": h})
        wire_security_hooks(c)
        # Spec 026: the classification endpoint Goose's own prompt injection detection asks (loopback, its own
        # port). Started before any worker is registered, so profiles and sandbox policies get its address; a port
        # that cannot be bound is logged and Goose-native detection then uses patterns only.
        from .classifyapi import ClassifyService
        c.classify = ClassifyService(settings, db, c.guard)
        c.guard.extra_in_use = c.classify.in_use
        profiles.security_endpoint = lambda: c.classify.endpoint
        await c.classify.start()

        def sandbox_event(action: str, w, detail: dict) -> None:
            # spec 025: MXC fallbacks and fail-closed refusals of members' workers are audited (admin-visible)
            db.audit(action, user=db.user_by_name(w.username), target=w.username, detail=detail, ok=False)
        workers.on_sandbox_event = sandbox_event
        app.state.ctx = c
        hub.start()
        workers.start_monitor()
        from .config import sandbox_backend, sandbox_on
        if sandbox_on(settings) and sandbox_backend(settings) != "appcontainer":
            # spec 025 R3: probe MXC at start (logged: "sandbox mxc: available ..." / "UNAVAILABLE: <reason>")
            from . import mxc
            asyncio.get_running_loop().run_in_executor(None, mxc.availability, settings, True)
        from .config import sandbox_fallback
        if sandbox_on(settings) and "appcontainer" in (sandbox_backend(settings), sandbox_fallback(settings)):
            # The folders the AppContainer backend must be able to prepare, judged for the account the gateway really
            # runs as (`check` and `sandbox status` judge them for whoever runs them): logged at every start.
            def _sandbox_folders() -> None:
                try:
                    from . import mxc as _mxc
                    for fp in _mxc.summary(settings).get("folderProblems") or []:
                        log.error("sandbox folders: %s", fp["why"])
                except Exception:
                    log.exception("sandbox folders: check failed")
            asyncio.get_running_loop().run_in_executor(None, _sandbox_folders)
        # FIX deploy-interrupts-running-turns: local scripts ask "is anything running?" and drain before a restart
        from .control import ControlChannel
        control = ControlChannel(hub, settings, __version__)
        control.start()
        # profiles with schedules must run even when nobody is connected
        for u in db.users():
            if u["disabled"]:
                continue
            try:
                c.upstream_for(u)
            except Exception:
                log.exception("register %s", u["username"])
        db.audit("system.start", detail={"version": __version__, "goose": c.goose_version,
                                          "https": tls.ACTIVE.get("mode") if tls.is_active() else "off"})
        maintenance = asyncio.create_task(_maintenance_loop(c))
        library = asyncio.create_task(_library_loop(c))
        warm = asyncio.create_task(c.guard.warm_up()) if settings.get("guard", "warm_up") else None

        async def native_security() -> None:
            # Spec 026: the administrator's own Goose profile (shared with Goose Desktop, the CLI and scheduled
            # recipes) gets the same settings, through Goose's configuration API, only when something differs.
            from . import goosesec
            await asyncio.sleep(5)
            await goosesec.sync_native(c)
        native_sec = asyncio.create_task(native_security())
        log.info("Goose Web %s ready (goose %s)", __version__, c.goose_version or "?")
        try:
            yield
        finally:
            control.stop()
            maintenance.cancel()
            library.cancel()
            native_sec.cancel()
            await c.classify.stop()
            if warm is not None:
                warm.cancel()
            c.guard.shutdown()
            from . import rulematch
            rulematch.shutdown()
            try:
                hub.flush_state_now()   # queued messages changed in the last half second
            except Exception:
                log.exception("saving chat state at shutdown")
            await workers.shutdown()
            db.audit("system.stop")
            db.close()

    async def http_error(request: Request, exc: HTTPError):
        return exc.response()

    async def not_found(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"error": "not_found", "message": "Not found"}, status_code=404)
        return Response("Not found", status_code=404, media_type="text/plain")

    async def server_error(request: Request, exc: Exception):
        log.exception("unhandled error on %s", request.url.path)
        return JSONResponse({"error": "server_error", "message": "Internal error (see the gateway log)"},
                            status_code=500)

    routes = [
        Route("/", index),
        Route("/index.html", index),
        Route("/sw.js", sw),
        Route("/manifest.webmanifest", manifest),
        Route("/tls/ca.crt", ca_cert),
        *api.routes,
        WebSocketRoute("/ws", ws_endpoint),
        Mount("/static", Static(directory=str(STATIC)), name="static"),
    ]
    app = Starlette(routes=routes, lifespan=lifespan,
                    exception_handlers={HTTPError: http_error, 404: not_found, 500: server_error,
                                        ValueError: _bad_request})
    app.add_middleware(BodyLimit, settings=settings)   # innermost: request body cap while streaming (A-1, A-2)
    app.add_middleware(IPBlockGuard)                   # blocked addresses (spec 007), after the Host check
    app.add_middleware(HostGuard, settings=settings)   # inner: its 400 still gets the security headers
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.add_middleware(SecurityHeaders, hsts=settings.public_url.startswith("https://"))
    return app


async def _bad_request(request: Request, exc: ValueError):
    # The exception text can describe internals (A-13): it goes to the gateway log, the client gets a generic reply.
    log.info("bad request on %s: %s", request.url.path, exc)
    return JSONResponse({"error": "bad_request", "message": "The request is not valid (see the gateway log)"},
                        status_code=400)
