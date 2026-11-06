"""ASGI application: lifespan wiring, security headers, static SPA and the /ws real-time channel."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect

from . import __version__, api
from .auth import AuthService
from .config import Settings
from .context import Ctx, HTTPError
from .db import Database
from .hub import Client, Hub
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
                have = {k.lower() for k, _ in headers}
                add = [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"same-origin"),
                       (b"cross-origin-opener-policy", b"same-origin"),
                       (b"cross-origin-resource-policy", b"same-origin"),
                       (b"permissions-policy", b"camera=(), geolocation=(), payment=(), usb=(), microphone=(self)")]
                if b"content-security-policy" not in have:
                    add.append((b"content-security-policy", SPA_CSP.encode()))
                if b"x-frame-options" not in have:
                    add.append((b"x-frame-options", b"DENY"))
                if path.startswith("/api/") and b"cache-control" not in have:
                    add.append((b"cache-control", b"no-store"))
                if self.hsts:
                    add.append((b"strict-transport-security", b"max-age=31536000"))
                headers.extend(add)
            await send(message)
        await self.app(scope, receive, wrapped)


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
        resp = await super().get_response(path, scope)
        resp.headers.setdefault("Cache-Control", "no-cache")  # revalidate (ETag) so updates apply at once
        return resp


# ---------------------------------------------------------------------- websocket
async def ws_endpoint(websocket: WebSocket):
    c: Ctx = websocket.app.state.ctx
    origin = websocket.headers.get("origin")
    ident = None
    token = websocket.query_params.get("token")
    if token and not origin:
        ident = c.auth.resolve_token(token)
    elif origin and origin in c.allowed_origins(websocket):
        ident = c.identity(websocket)
    if ident is None or ident.user["must_change_pw"]:
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
    client.start()
    c.hub.attach(up, client)
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
                    client.send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": str(e)}})
            if client.closed:
                break
    except WebSocketDisconnect:
        pass
    except RuntimeError:
        pass
    finally:
        c.hub.detach(up, client)


# ---------------------------------------------------------------------- notifications (webhooks)
def make_event_handler(c: Ctx):
    async def post(url: str, event: str, agent: dict):
        title = {"needs_you": "Goose needs you", "done": "Goose finished", "error": "Goose hit an error"}[event]
        link = f"{c.settings.public_url}/#/chat/{agent['sessionId']}" if c.settings.public_url else ""
        msg = f"{agent.get('title') or agent['sessionId']}: {agent.get('lastText') or ''}"[:500]
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                if "ntfy" in url:
                    await client.post(url, content=msg.encode(), headers={
                        "Title": title, "Tags": "goose", "Click": link,
                        "Priority": "high" if event == "needs_you" else "default"})
                else:
                    await client.post(url, json={"event": event, "title": title, "message": msg, "url": link,
                                                 "agent": agent})
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
        hub.profile_root_for = lambda username: str(profiles.root_for(db.user_by_name(username) or {"username": username}))
        app.state.ctx = c
        hub.start()
        workers.start_monitor()
        # profiles with schedules must run even when nobody is connected
        for u in db.users():
            if u["disabled"]:
                continue
            try:
                c.upstream_for(u)
            except Exception:
                log.exception("register %s", u["username"])
        db.audit("system.start", detail={"version": __version__, "goose": c.goose_version})
        log.info("Goose Web %s ready (goose %s)", __version__, c.goose_version or "?")
        try:
            yield
        finally:
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
        *api.routes,
        WebSocketRoute("/ws", ws_endpoint),
        Mount("/static", Static(directory=str(STATIC)), name="static"),
    ]
    app = Starlette(routes=routes, lifespan=lifespan,
                    exception_handlers={HTTPError: http_error, 404: not_found, 500: server_error,
                                        ValueError: _bad_request})
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.add_middleware(SecurityHeaders, hsts=settings.public_url.startswith("https://"))
    return app


async def _bad_request(request: Request, exc: ValueError):
    return JSONResponse({"error": "bad_request", "message": str(exc)}, status_code=400)
