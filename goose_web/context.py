"""Shared runtime context and request helpers (auth, CSRF, client IP, JSON errors)."""
from __future__ import annotations

import json
import logging
import os
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

TOTP_ENROL_MESSAGE = ("Administrators must use two-factor sign-in. Turn it on first in Settings > Two-factor "
                      "authentication; until then only that page, your password and sign-out are available.")


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


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
        from . import tls
        return self.settings.public_url.startswith("https://") or tls.is_active()

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
        """The client address: the peer, or (from a trusted proxy) the right-most X-Forwarded-For entry that is
        not itself a trusted proxy. Only entries that parse as IP addresses are used; an entry that does not
        falls back to the peer, so a non-address can never dodge the IP block or reach the audit log (A-7)."""
        peer = conn.client.host if conn.client else ""
        if not self.from_trusted_proxy(conn):
            return peer
        xff = conn.headers.get("x-forwarded-for")
        if not xff:
            return peer
        trusted = self.settings.get("server", "trusted_proxies") or []
        found = ""
        for entry in reversed(xff.split(",")[-32:]):
            ip = security.parse_ip(entry)
            if ip is None:
                return found or peer
            found = ip
            if not _ip_in(ip, trusted):
                return ip
        return found or peer

    # ---------------------------------------------------------- identity
    def identity(self, conn: HTTPConnection) -> Identity | None:
        authz = conn.headers.get("authorization") or ""
        if authz.lower().startswith("bearer "):
            return self.auth.resolve_token(authz[7:].strip())
        token = conn.cookies.get(self.cookie_name)
        return self.auth.resolve_cookie(token) if token else None

    def require(self, request: Request, admin: bool = False, allow_pw_change: bool = False,
                allow_totp_enrol: bool = False) -> Identity:
        """The signed-in identity, after the CSRF/Origin checks for cookie writes.

        allow_pw_change: the route stays open to an account that must change its password (and to one that must
        enrol two-factor). allow_totp_enrol: the route stays open to an administrator who must enrol two-factor
        first ("require two-factor for administrators", A-8) - the enrolment routes themselves."""
        ident = self.identity(request)
        if ident is None:
            raise HTTPError(401, "unauthorized", "Sign in required")
        if request.method not in ("GET", "HEAD", "OPTIONS") and ident.via == "cookie":
            self.check_csrf(request, ident)
        if ident.user["must_change_pw"] and not allow_pw_change:
            raise HTTPError(403, "password_change_required", "Change your password first")
        if not (allow_pw_change or allow_totp_enrol) and self.auth.totp_enrolment_required(ident.user):
            raise HTTPError(403, "totp_enrolment_required", TOTP_ENROL_MESSAGE)
        if admin and ident.user["role"] != "admin":
            raise HTTPError(403, "forbidden", "Administrators only")
        return ident

    def check_csrf(self, request: Request, ident: Identity) -> None:
        """Origin allow-list + double-submit CSRF token for a cookie-authenticated write."""
        origin = request.headers.get("origin")
        if origin and origin not in self.allowed_origins(request):
            raise HTTPError(403, "bad_origin", "Cross-origin request refused")
        if not security.consteq(request.headers.get("x-csrf-token"), (ident.session or {}).get("csrf")):
            raise HTTPError(403, "csrf", "Missing or invalid CSRF token. Reload the page.")

    def must_enrol_or_change(self, user: dict) -> bool:
        """True while the account may only use the password / two-factor enrolment routes (no WebSocket)."""
        return bool(user["must_change_pw"]) or self.auth.totp_enrolment_required(user)

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
        """May `user` reach `path` through the file API? Never inside system_dir (database, TLS keys, backups,
        logs, sandbox records) and never a UNC/device path - for administrators too (A-6, A-12)."""
        if not path or security.is_unc_path(path) or self.in_system_dir(path):
            return False
        if user["role"] == "admin":
            return os.path.isabs(path)
        return pol.path_allowed(path, self.roots_for(user))

    def in_system_dir(self, path: str) -> bool:
        """True when `path` is system_dir or below it, compared both as written and after resolving links
        (realpath), case-insensitively on Windows. Anything that cannot be resolved counts as inside."""
        try:
            base = self.settings.system_dir
            bases = {_norm(os.path.abspath(base)), _norm(os.path.realpath(base))}
            cands = {_norm(os.path.abspath(path)), _norm(os.path.realpath(path))}
        except (OSError, ValueError):
            return True
        return any(c == b or c.startswith(b.rstrip(os.sep) + os.sep) for c in cands for b in bases)

    def upstream_for(self, user: dict) -> Upstream:
        key = user["username"].lower()
        native = self.profiles.is_native(user)
        if not native:
            # The provisioning manifest lives in <system_dir>/manifests (C-3); a profile without one (new, or
            # provisioned by 1.11 or older) is provisioned now, which also applies the 1.12 extension pinning.
            if not self.profiles.manifest_path(user).exists():
                try:
                    self.profiles.provision(user)
                except Exception:
                    log.exception("provisioning %s failed", user["username"])
        self.workers.register(key, user["username"], self.profiles.path_root_env(user), native,
                              self.profiles.team_recipe_dirs(user) if not native else [],
                              sandbox=self.sandbox_spec(user))
        return self.hub.upstream(key, user["username"])

    def sandboxed(self, user: dict) -> bool:
        """Spec 012: isolated non-admin users run in their own AppContainer when sandbox.enabled is on."""
        from .config import sandbox_on
        return sandbox_on(self.settings) and not self.profiles.is_native(user) \
            and user.get("role") != "admin"

    def sandbox_spec(self, user: dict) -> dict | None:
        if not self.sandboxed(user):
            return None
        from . import sandbox as sb
        root = str(self.profiles.root_for(user))
        read_dirs = [str(d) for d in (self.settings.get("sandbox", "read_dirs") or []) if d]
        net = str(self.settings.get("sandbox", "network") or "internet").lower()
        from . import relay as rl
        name = sb.container_name(str(self.settings.profiles_root), user["username"])
        targets = [str(t) for t in (self.settings.get("sandbox", "relays") or []) if t]
        relays = rl.relay_specs(name, int(user["id"]), targets) if targets else []
        if relays:   # the forwarder inside the container runs on the gateway's base Python
            read_dirs = read_dirs + [rl.python_for_container()[1]]
        return {"name": name, "profile_root": root, "relays": relays,
                "grants": sb.desired_grants(root, self.roots_for(user), read_dirs, self.settings.goose_binary),
                "caps": sb.NETWORK_CAPS.get(net, sb.NETWORK_CAPS["internet"])}

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


DEFAULT_BODY_LIMIT = 2 * 1024 * 1024


class BodyTooLarge(HTTPError):
    """413 raised while a request body is being received (A-1/A-2); app.BodyLimit turns it into a response."""

    def __init__(self, message: str = "Request body too large"):
        super().__init__(413, "too_large", message)


async def read_body(request: Request, limit: int) -> bytes:
    """The request body, refused with 413 as soon as it is known to exceed `limit`: up front from Content-Length,
    otherwise while streaming (chunked bodies), so at most `limit` bytes are ever held in memory (A-1)."""
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        raise HTTPError(400, "bad_request", "Invalid Content-Length")
    if declared > limit:
        raise BodyTooLarge()
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise BodyTooLarge()
    return bytes(buf)


async def body_json(request: Request, limit: int = DEFAULT_BODY_LIMIT) -> dict:
    raw = await read_body(request, limit)
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise HTTPError(400, "bad_json", "Body must be JSON")
    if not isinstance(data, dict):
        raise HTTPError(400, "bad_json", "Body must be a JSON object")
    return data
