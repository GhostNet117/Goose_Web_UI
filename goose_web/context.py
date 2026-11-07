"""Shared runtime context and request helpers (auth, CSRF, client IP, JSON errors)."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse

from . import policy as pol
from . import security
from .auth import AuthService, Identity
from .config import Settings
from .db import Database
from .hub import Hub, Upstream
from .profiles import Profiles
from .workers import WorkerManager

log = logging.getLogger("goose_web")


class HTTPError(Exception):
    def __init__(self, status: int, code: str, message: str = "", **extra: Any):
        super().__init__(message or code)
        self.status, self.code, self.message, self.extra = status, code, message or code, extra

    def response(self) -> JSONResponse:
        return JSONResponse({"error": self.code, "message": self.message, **self.extra}, status_code=self.status)


@dataclass
class Ctx:
    settings: Settings
    db: Database
    auth: AuthService
    profiles: Profiles
    workers: WorkerManager
    hub: Hub
    version: str
    goose_version: str = ""
    started_at: float = field(default_factory=time.time)

    # ---------------------------------------------------------- cookies / origin
    @property
    def secure(self) -> bool:
        return self.settings.public_url.startswith("https://")

    @property
    def cookie_name(self) -> str:
        return "__Host-gw" if self.secure else "gw"

    def allowed_origins(self, conn: HTTPConnection) -> set[str]:
        out = set(self.settings.get("server", "allowed_origins") or [])
        if self.settings.public_url:
            # A public URL is configured: only its origin (and configured extras) count. The request's Host
            # is not used, so a rebound DNS name cannot make its own origin acceptable. Add other direct-access
            # origins (for example http://127.0.0.1:8710) to server.allowed_origins if they are needed.
            out.add(self.settings.public_url)
            origin = url_origin(self.settings.public_url)
            if origin:
                out.add(origin)
            return out
        host = conn.headers.get("host")
        if host:
            # No public URL: direct access (e.g. http://127.0.0.1:8710 on the gateway host itself). The Host
            # header is on the allow-list here (app.HostGuard refuses any other Host).
            scheme = "https" if conn.url.scheme in ("https", "wss") else "http"
            out.add(f"{scheme}://{host}")
            fwd = conn.headers.get("x-forwarded-proto") if self.from_trusted_proxy(conn) else None
            if fwd:
                out.add(f"{fwd}://{conn.headers.get('x-forwarded-host') or host}")
        return out

    def from_trusted_proxy(self, conn: HTTPConnection) -> bool:
        peer = conn.client.host if conn.client else ""
        return _ip_in(peer, self.settings.get("server", "trusted_proxies") or [])

    def client_ip(self, conn: HTTPConnection) -> str:
        peer = conn.client.host if conn.client else ""
        if self.from_trusted_proxy(conn):
            xff = conn.headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[-1].strip()[:64]
        return peer

    # ---------------------------------------------------------- identity
    def identity(self, conn: HTTPConnection) -> Identity | None:
        authz = conn.headers.get("authorization") or ""
        if authz.lower().startswith("bearer "):
            return self.auth.resolve_token(authz[7:].strip())
        token = conn.cookies.get(self.cookie_name)
        return self.auth.resolve_cookie(token) if token else None

    def require(self, request: Request, admin: bool = False, allow_pw_change: bool = False) -> Identity:
        ident = self.identity(request)
        if ident is None:
            raise HTTPError(401, "unauthorized", "Sign in required")
        if request.method not in ("GET", "HEAD", "OPTIONS") and ident.via == "cookie":
            origin = request.headers.get("origin")
            if origin and origin not in self.allowed_origins(request):
                raise HTTPError(403, "bad_origin", "Cross-origin request refused")
            if not security.consteq(request.headers.get("x-csrf-token"), ident.session["csrf"]):
                raise HTTPError(403, "csrf", "Missing or invalid CSRF token. Reload the page.")
        if ident.user["must_change_pw"] and not allow_pw_change:
            raise HTTPError(403, "password_change_required", "Change your password first")
        if admin and ident.user["role"] != "admin":
            raise HTTPError(403, "forbidden", "Administrators only")
        return ident

    # ---------------------------------------------------------- users / profiles / policy
    def policy_for(self, user: dict) -> dict:
        teams = self.db.user_teams(user["id"])
        p = pol.effective_policy(user, teams)
        if teams and user.get("role") != "admin":
            folder = self.profiles.ensure_team_folder(teams[0])
            p["team_folder"] = str(folder or self.profiles.team_folder(teams[0]))
        return p

    def roots_for(self, user: dict, policy: dict | None = None) -> list[str]:
        policy = policy or self.policy_for(user)
        return pol.user_roots(policy, str(self.profiles.workspace(user)))

    def path_ok(self, user: dict, path: str) -> bool:
        if user["role"] == "admin":
            import os
            return bool(path) and os.path.isabs(path)
        return pol.path_allowed(path, self.roots_for(user))

    def upstream_for(self, user: dict) -> Upstream:
        key = user["username"].lower()
        native = self.profiles.is_native(user)
        if not native:
            manifest = self.profiles.root_for(user) / ".goose-web" / "managed.json"
            if not manifest.exists():
                try:
                    self.profiles.provision(user)
                except Exception:
                    log.exception("provisioning %s failed", user["username"])
        self.workers.register(key, user["username"], self.profiles.path_root_env(user), native,
                              self.profiles.team_recipe_dirs(user) if not native else [])
        return self.hub.upstream(key, user["username"])

    def public_user(self, u: dict) -> dict:
        return {"id": u["id"], "username": u["username"], "displayName": u["display_name"] or u["username"],
                "email": u["email"], "role": u["role"], "authSource": u["auth_source"],
                "totpEnabled": bool(u["totp_enabled"]), "mustChangePassword": bool(u["must_change_pw"]),
                "profileMode": u["profile_mode"], "disabled": bool(u["disabled"]),
                "locked": u["locked_until"] > time.time(), "createdAt": u["created_at"],
                "lastLoginAt": u["last_login_at"], "lastLogin": u["last_login_at"]}

    def audit(self, request: HTTPConnection, action: str, user: dict | None, target: str = "",
              detail: dict | None = None, ok: bool = True) -> None:
        self.db.audit(action, user=user, ip=self.client_ip(request), target=target, detail=detail, ok=ok)


def url_origin(url: str) -> str:
    """The browser Origin of an absolute URL: scheme://host[:port], lower-cased, default port omitted."""
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return ""
    if u.scheme not in ("http", "https") or not u.hostname:
        return ""
    host = u.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port and port != {"http": 80, "https": 443}[u.scheme]:
        host = f"{host}:{port}"
    return f"{u.scheme}://{host}"


_ip_in = security.ip_in  # one implementation, shared with the IP block (ipblock.py)


async def body_json(request: Request, limit: int = 2 * 1024 * 1024) -> dict:
    raw = await request.body()
    if len(raw) > limit:
        raise HTTPError(413, "too_large", "Request body too large")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise HTTPError(400, "bad_json", "Body must be JSON")
    if not isinstance(data, dict):
        raise HTTPError(400, "bad_json", "Body must be a JSON object")
    return data
