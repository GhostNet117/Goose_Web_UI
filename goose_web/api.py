"""REST endpoints (see docs/API.md)."""
from __future__ import annotations

import asyncio
import html
import logging
import math
import mimetypes
import os
import re
import secrets
import shutil
import string
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
from starlette.requests import Request
from starlette.responses import (FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
                                 Response)
from starlette.routing import Route

from . import guard as guardmod
from . import guardmodel, hosttasks, logjanitor, prefsync, security, tls, winsec
from . import policy as acp_policy
from .auth import AuthError
from .context import Ctx, HTTPError, body_json, read_body
from .hub import RpcError
from .policy import ANY, BOOL_KEYS, CHAT_LISTS, DEFAULT_POLICY, LIST_KEYS
from .profiles import HINT_FILE_NAMES

MAX_PREFS = 64 * 1024
log = logging.getLogger("goose_web")


def ctx(request: Request) -> Ctx:
    return request.app.state.ctx


def ok(data: Any = None, status: int = 200) -> JSONResponse:
    return JSONResponse({"ok": True} if data is None else data, status_code=status,
                        headers={"Cache-Control": "no-store"})


def temp_password() -> str:
    """A random temporary password (XXXX-XXXX-XXXX!d) that always meets the password policy."""
    alphabet = string.ascii_letters + string.digits
    while True:
        core = "".join(secrets.choice(alphabet) for _ in range(12))
        pw = f"{core[:4]}-{core[4:8]}-{core[8:]}!{secrets.randbelow(10)}"
        if not security.password_problems(pw):
            return pw


def _min_pw(c: Ctx) -> int:
    return int(c.settings.get("auth", "min_password_length") or security.PASSWORD_MIN_LENGTH)


def int_param(value: Any, name: str, default: int | None = None, lo: int | None = None,
              hi: int | None = None) -> int | None:
    """A whole number from a query string or JSON value, or 400 (A-13): "12", 12 and 12.0 are fine; text,
    booleans, inf, nan and absurd sizes are refused instead of turning into a 500."""
    if value is None or value == "":
        return default
    try:
        if isinstance(value, bool):
            raise ValueError
        num = float(value) if isinstance(value, (int, float)) else float(str(value).strip())
        if not math.isfinite(num) or abs(num) > 2 ** 62:
            raise ValueError
        out = int(num)
    except (TypeError, ValueError, OverflowError):
        raise HTTPError(400, "bad_request", f"{name} must be a whole number")
    if lo is not None:
        out = max(lo, out)
    if hi is not None:
        out = min(hi, out)
    return out


def _weak(problems: list[str]) -> HTTPError:
    # the UI shows message + ": " + problems, so the message itself does not repeat them
    return HTTPError(400, "weak_password", "The password does not meet the rules", problems=problems)


# ====================================================================== auth
async def auth_config(request: Request):
    c = ctx(request)
    brand = c.db.get_setting("brand") or {"name": "Goose Web", "tagline": "Your Goose, anywhere"}
    return ok({"brand": brand, "version": c.version, **c.auth.public_auth_config()})


def _set_cookie(c: Ctx, resp: Response, token: str, remember: bool) -> None:
    resp.set_cookie(c.cookie_name, token, httponly=True, secure=c.secure, samesite="strict", path="/",
                    max_age=int(c.auth.session_seconds(remember)) if remember else None)


async def login(request: Request):
    c = ctx(request)
    b = await body_json(request, 16 * 1024)
    ip = c.client_ip(request)
    origin = request.headers.get("origin")
    if origin and origin not in c.allowed_origins(request):
        raise HTTPError(403, "bad_origin", "Cross-origin request refused")
    try:
        user = await asyncio.to_thread(c.auth.login, str(b.get("username") or ""), str(b.get("password") or ""),
                                       b.get("totp"), ip)
    except AuthError as e:
        return JSONResponse({"error": e.code, "message": e.message}, status_code=e.status)
    remember = bool(b.get("remember"))
    token, csrf = c.auth.create_session(user, ip, request.headers.get("user-agent", ""), "password", remember)
    c.audit(request, "auth.login", user)
    if not c.profiles.is_native(user) and not (c.profiles.root_for(user) / ".goose-web").exists():
        await asyncio.to_thread(c.profiles.provision, user)
    resp = ok({"user": c.public_user(user), "csrf": csrf, "mustChangePassword": bool(user["must_change_pw"]),
               "totpEnrolmentRequired": c.auth.totp_enrolment_required(user)})
    _set_cookie(c, resp, token, remember)
    return resp


async def logout(request: Request):
    c = ctx(request)
    token = request.cookies.get(c.cookie_name)
    ident = c.identity(request)
    if ident and ident.via == "cookie":
        c.check_csrf(request, ident)   # a valid session is only ended by the page that holds it (A-14)
    if token:
        c.auth.logout(token)
        if c.hub is not None:   # SC-3: sockets signed in with what was just revoked close now
            c.hub.revalidate_clients()
    if ident:
        c.audit(request, "auth.logout", ident.user)
    resp = ok()
    resp.delete_cookie(c.cookie_name, path="/", secure=c.secure, httponly=True, samesite="strict")
    return resp


OIDC_NEEDS_PUBLIC_URL = ("Single sign-on (OIDC) needs server.public_url (the https:// address users open) so the "
                         "redirect URI never depends on the request's Host header")


def _redirect_uri(c: Ctx, request: Request, pid: str) -> str:
    if not c.settings.public_url:
        log.warning("OIDC sign-in refused: %s", OIDC_NEEDS_PUBLIC_URL)
        raise AuthError("oidc_needs_public_url", OIDC_NEEDS_PUBLIC_URL, 400)
    return f"{c.settings.public_url}/api/auth/oidc/{pid}/callback"


def _oidc_cookie(c: Ctx) -> str:
    return "__Host-gw_oidc" if c.secure else "gw_oidc"


def _mfa_cookie(c: Ctx) -> str:
    return "__Host-gw_mfa" if c.secure else "gw_mfa"


def _clear_cookie(c: Ctx, resp: Response, name: str) -> None:
    resp.delete_cookie(name, path="/", secure=c.secure, httponly=True, samesite="lax")


async def oidc_start(request: Request):
    c = ctx(request)
    pid = request.path_params["pid"]
    # A-4: the state is bound to this browser through a short-lived pre-sign-in cookie. SameSite=Lax because the
    # IdP sends the browser back with a cross-site top-level GET, which Lax cookies (unlike Strict) accompany.
    binding = security.new_token()
    try:
        url = await c.auth.oidc_start(pid, _redirect_uri(c, request, pid), binding)
    except AuthError as e:
        return RedirectResponse(f"/#/login?error={e.code}", 302)
    except Exception:
        log.exception("OIDC start failed for provider %s", pid)
        return RedirectResponse("/#/login?error=oidc_unavailable", 302)
    resp = RedirectResponse(url, 302)
    resp.set_cookie(_oidc_cookie(c), binding, max_age=600, path="/", httponly=True, secure=c.secure, samesite="lax")
    return resp


async def oidc_callback(request: Request):
    c = ctx(request)
    pid = request.path_params["pid"]
    q = request.query_params
    binding = request.cookies.get(_oidc_cookie(c)) or ""

    def fail(code: str) -> Response:
        r = RedirectResponse(f"/#/login?error={code}", 302)
        _clear_cookie(c, r, _oidc_cookie(c))
        return r

    if q.get("error"):
        return fail("oidc_denied")
    try:
        user = await c.auth.oidc_callback(pid, q.get("code", ""), q.get("state", ""), _redirect_uri(c, request, pid),
                                          c.client_ip(request), binding)
    except AuthError as e:
        c.db.audit("auth.oidc", ip=c.client_ip(request), target=pid, detail={"error": e.code}, ok=False)
        return fail(e.code)
    except Exception:
        log.exception("OIDC callback failed for provider %s", pid)
        return fail("oidc_failed")
    if user["totp_enabled"]:
        # A-8: the account uses two-factor; the IdP sign-in alone does not open a session.
        pending = c.auth.begin_mfa(user, f"oidc:{pid}")
        c.audit(request, "auth.oidc.mfa", user, target=f"oidc:{pid}")
        resp = RedirectResponse("/api/auth/mfa", 302)
        _clear_cookie(c, resp, _oidc_cookie(c))
        resp.set_cookie(_mfa_cookie(c), pending, max_age=300, path="/", httponly=True, secure=c.secure,
                        samesite="lax")
        return resp
    return await _finish_sign_in(c, request, user, f"oidc:{pid}", Response(status_code=302))


async def _finish_sign_in(c: Ctx, request: Request, user: dict, method: str, resp: Response) -> Response:
    """Open the session of an OIDC sign-in (after the second factor, if any) and redirect to the app."""
    token, _ = c.auth.create_session(user, c.client_ip(request), request.headers.get("user-agent", ""), method)
    c.audit(request, "auth.login", user, target=method)
    if not c.profiles.is_native(user):
        await asyncio.to_thread(c.profiles.provision, user)
    resp.status_code = 302
    resp.headers["location"] = "/"
    _clear_cookie(c, resp, _oidc_cookie(c))
    _clear_cookie(c, resp, _mfa_cookie(c))
    _set_cookie(c, resp, token, False)
    return resp


_MFA_ERRORS = {"totp_invalid": "That code is not valid. Try the next code.",
               "locked": "Account temporarily locked after failed attempts. Try again later.",
               "rate_limited": "Too many attempts. Wait a few minutes.",
               "ip_blocked": "Sign-in from your network address is blocked. Ask an administrator."}


def _mfa_page(message: str = "", expired: bool = False) -> HTMLResponse:
    """A minimal server-rendered page for the TOTP step after OIDC (no scripts: the SPA's CSP applies)."""
    note = f'<p class="err">{html.escape(message)}</p>' if message else ""
    if expired:
        body = (f"{note}<p>This sign-in has expired.</p><p><a href=\"/\">Sign in again</a></p>")
    else:
        body = (f"{note}<form method=\"post\" action=\"/api/auth/mfa\">"
                "<label for=\"code\">Code from your authenticator app</label>"
                "<input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" "
                "maxlength=\"8\" required autofocus>"
                "<button type=\"submit\">Sign in</button></form>"
                "<p><a href=\"/\">Cancel</a></p>")
    page = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Two-factor sign-in</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}"
            "input,button{display:block;width:100%;margin:.5rem 0;padding:.5rem;font-size:1.1rem;box-sizing:border-box}"
            ".err{color:#b00020}</style></head><body><h1>Two-factor sign-in</h1>" + body + "</body></html>")
    return HTMLResponse(page, status_code=400 if expired else 200, headers={"Cache-Control": "no-store"})


async def mfa_step(request: Request):
    """A-8: second factor for an OIDC sign-in of an account with two-factor enrolled.
    GET shows the code form; POST (same-origin form) checks the code and opens the session."""
    c = ctx(request)
    pending = request.cookies.get(_mfa_cookie(c)) or ""
    if request.method == "GET":
        expired = c.auth.mfa_pending(pending) is None
        page = _mfa_page(expired=expired)
        if expired:
            _clear_cookie(c, page, _mfa_cookie(c))
        return page
    origin = request.headers.get("origin")
    if origin and origin not in c.allowed_origins(request):
        raise HTTPError(403, "bad_origin", "Cross-origin request refused")
    raw = await read_body(request, 4096)
    code = (parse_qs(raw.decode("utf-8", "replace")).get("code") or [""])[0]
    try:
        user, method = await asyncio.to_thread(c.auth.finish_mfa, pending, code, c.client_ip(request))
    except AuthError as e:
        expired = c.auth.mfa_pending(pending) is None
        page = _mfa_page(_MFA_ERRORS.get(e.code, e.message), expired=expired)
        if expired:
            _clear_cookie(c, page, _mfa_cookie(c))
        return page
    return await _finish_sign_in(c, request, user, method, Response(status_code=302))


# ====================================================================== me
async def me(request: Request):
    c = ctx(request)
    ident = c.require(request, allow_pw_change=True)
    u = ident.user
    if request.method == "PATCH":
        b = await body_json(request)
        fields = {}
        if "displayName" in b:
            fields["display_name"] = str(b["displayName"])[:120]
        if "email" in b:
            fields["email"] = str(b["email"])[:200]
        c.db.update_user(u["id"], **fields)
        return ok({"user": c.public_user(c.db.user_by_id(u["id"]))})
    policy = c.policy_for(u)
    key = u["username"].lower()
    w = c.workers.get(key)
    if w is None:
        c.upstream_for(u)
        w = c.workers.get(key)
    sched_on, reason = c.workers.wants_scheduler(w) if w else (True, "")
    return ok({"user": c.public_user(u), "csrf": ident.session["csrf"] if ident.session else "",
               "policy": policy, "isAdmin": u["role"] == "admin",
               "totpEnrolmentRequired": c.auth.totp_enrolment_required(u),
               "teams": [{"id": t["id"], "name": t["name"]} for t in c.db.user_teams(u["id"])],
               "team": (policy.get("team") if u["role"] != "admin" else
                        next(({"id": t["id"], "name": t["name"]} for t in c.db.user_teams(u["id"])), None)),
               "scheduler": {"enabled": sched_on, "owner": "gateway" if sched_on else "desktop", "reason": reason},
               "workspace": str(c.profiles.workspace(u)), "version": c.version, "gooseVersion": c.goose_version,
               # spec 018: classifier health for the admin banner while some prompt guard is on
               "guard": c.guard.health() if c.guard is not None and u["role"] == "admin" and c.guard.in_use()
               else None})


# Attempts to prove the current password of a signed-in account (change password): 8 per user in 5 minutes.
_REAUTH_LIMIT = security.RateLimiter(8, 300.0)


async def me_password(request: Request):
    c = ctx(request)
    ident = c.require(request, allow_pw_change=True)
    u = ident.user
    b = await body_json(request, 16 * 1024)
    if u["auth_source"] != "local":
        raise HTTPError(400, "external_account", "This account's password is managed by your directory")
    # A-3 (review 2026-11-12): the password check (scrypt) ran on the event loop, so a member repeating this request
    # could stall the gateway for everyone, and nothing limited guesses of the current password with a stolen session
    if not _REAUTH_LIMIT.hit(f"pw:{u['id']}"):
        c.audit(request, "user.password", u, ok=False, detail={"reason": "rate limited"})
        raise HTTPError(429, "rate_limited", "Too many attempts. Try again in a few minutes.")
    if not await asyncio.to_thread(security.verify_password, str(b.get("current") or ""), u["password_hash"]):
        c.audit(request, "user.password", u, ok=False)
        raise HTTPError(400, "wrong_password", "Your current password is not correct")
    _REAUTH_LIMIT.reset(f"pw:{u['id']}")
    new = str(b.get("new") or "")
    problems = security.password_problems(new, _min_pw(c), u["username"])
    if new == b.get("current"):
        problems.append("must differ from the current password")
    if problems:
        raise _weak(problems)
    c.db.update_user(u["id"], password_hash=await asyncio.to_thread(security.hash_password, new), must_change_pw=0)
    c.auth.revoke_user_sessions(u["id"], keep_hash=ident.session["token_hash"] if ident.session else None)
    if c.hub is not None:   # SC-3: sockets signed in with what was just revoked close now
        c.hub.revalidate_clients()
    revoked = c.auth.revoke_user_tokens(u["id"])  # a password change also ends API-token access (GW-21)
    c.audit(request, "user.password", u, detail={"tokensRevoked": revoked})
    return ok()


async def me_prefs(request: Request):
    c = ctx(request)
    u = c.require(request, allow_totp_enrol=request.method == "GET").user
    if request.method == "GET":
        return ok(prefsync.public(c.db.user_by_id(u["id"])["prefs"] or {}))
    b = await body_json(request, MAX_PREFS)
    # 1.18.2 (bug prefs-stale-tab-overwrite): a save is merged, never a replacement. PATCH = this front end
    # {baseRev, set, unset, client}: a key changed on the server after baseRev is a conflict (409, nothing applied).
    # PUT = a front end before 1.18.2 posting its whole object: merge-only, never deletes, stale echoes skipped.
    # Keys starting with "_" belong to the server (_notify, _rev, ...): never written from here (A-14).
    if request.method == "PATCH":
        base = b.get("baseRev")
        if isinstance(base, bool) or not isinstance(base, int) or base < 0:
            raise HTTPError(400, "bad_request", "baseRev (the prefs revision this change is based on) is required")
        sets, unsets, client, mode = b.get("set", {}), b.get("unset", []), prefsync.client_id(b.get("client")), "patch"
    else:
        base, sets, unsets, client, mode = None, b, [], "", "legacy-put"
    res: list = []

    def merge(stored: dict) -> dict | None:
        r = prefsync.apply(stored, sets, unsets, base_rev=base, clean=PREFS_CLEAN)
        res.append(r)
        return r.prefs if (r.changed or r.deleted) else None

    try:
        c.db.update_prefs(u["id"], merge)
    except prefsync.PrefsError as e:
        c.audit(request, "prefs.update", u, detail={"mode": mode, "client": client, "error": e.code,
                                                     "keys": e.keys[:50]}, ok=False)
        if e.code == "prefs_conflict":
            raise HTTPError(409, e.code, str(e), conflicts=e.keys)
        raise HTTPError(413 if e.code == "prefs_too_large" else 400, e.code, str(e), keys=e.keys[:50])
    r = res[-1]
    if r.changed or r.deleted or r.skipped:   # key NAMES only, never values
        c.audit(request, "prefs.update", u, detail={"mode": mode, "client": client, "rev": r.rev,
                                                     "keys": r.changed, "deleted": r.deleted, "skipped": r.skipped})
    pub = prefsync.public(r.prefs)
    if (r.changed or r.deleted) and c.hub is not None:   # the user's other tabs and browsers update live
        c.hub.broadcast_user(u["id"], {"jsonrpc": "2.0", "method": "_gw/prefs", "params": {
            "rev": r.rev, "keys": r.changed + r.deleted, "client": client, "prefs": pub}})
    return ok({"ok": True, "rev": r.rev, "changed": r.changed, "deleted": r.deleted, "skipped": r.skipped,
               "prefs": pub})


_GROUP_ID = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _clean_provider_groups(v) -> dict:
    """Spec 024: provider groups and model display names for the chat pickers (a display alias, not a policy).
    Kept: {"groups": [{"id", "name", "members": [{"provider", "prefix"}]}], "modelNames": {model id: name}}.
    Groups <= 50 (id [A-Za-z0-9_-]{1,40}, a missing or repeated id gets a new one; name trimmed <= 80, empty ->
    "Group"); members <= 100 per group (provider <= 200 chars, in the first group that lists it only; prefix trimmed
    <= 40); modelNames <= 1000 (id <= 200 chars, name trimmed 1..120)."""
    groups: list[dict] = []
    ids: set[str] = set()
    taken: set[str] = set()
    raw = v.get("groups") if isinstance(v, dict) else None
    for g in (raw if isinstance(raw, list) else [])[:50]:
        if not isinstance(g, dict):
            continue
        gid = g.get("id") if isinstance(g.get("id"), str) and _GROUP_ID.match(g.get("id")) else ""
        if not gid or gid in ids:
            n = len(groups) + 1
            while f"g{n}" in ids:
                n += 1
            gid = f"g{n}"
        ids.add(gid)
        name = g.get("name").strip()[:80] if isinstance(g.get("name"), str) else ""
        members: list[dict] = []
        for m in g.get("members") if isinstance(g.get("members"), list) else []:
            if len(members) >= 100:
                break
            p = m.get("provider") if isinstance(m, dict) else None
            if not isinstance(p, str) or not p or len(p) > 200 or p in taken:
                continue
            taken.add(p)
            prefix = m.get("prefix")
            members.append({"provider": p, "prefix": prefix.strip()[:40] if isinstance(prefix, str) else ""})
        groups.append({"id": gid, "name": name or "Group", "members": members})
    names: dict[str, str] = {}
    rawn = v.get("modelNames") if isinstance(v, dict) else None
    for k, x in (rawn.items() if isinstance(rawn, dict) else []):
        if len(names) >= 1000:
            break
        if isinstance(k, str) and k and len(k) <= 200 and isinstance(x, str) and x.strip():
            names[k] = x.strip()[:120]
    return {"groups": groups, "modelNames": names}


def _clean_provider_visibility(v) -> dict:
    """Spec 023: the providers a user left out of the chat pickers (a display preference, not a policy).
    Only {"hidden": [provider ids]} is kept: unique non-empty strings of at most 200 characters, at most 500."""
    hidden: list[str] = []
    raw = v.get("hidden") if isinstance(v, dict) else None
    for x in raw if isinstance(raw, list) else []:
        if isinstance(x, str) and x and len(x) <= 200 and x not in hidden:
            hidden.append(x)
    return {"hidden": hidden[:500]}


# Prefs values the server cleans on every save (PUT and PATCH).
PREFS_CLEAN = {"providerVisibility": _clean_provider_visibility, "providerGroups": _clean_provider_groups}


def _check_self_totp_allowed(c: Ctx, u: dict) -> None:
    """Admin setting 'Users may enable two-factor themselves' (allow_self_totp, default on).
    Administrators can always enrol, so 'require two-factor for admins' stays satisfiable."""
    if u["role"] != "admin" and not c.db.get_setting("allow_self_totp", True):
        raise HTTPError(403, "totp_self_disabled",
                        "Your administrator has turned off self-service two-factor enrolment")


async def totp_setup(request: Request):
    c = ctx(request)
    u = c.require(request, allow_totp_enrol=True).user
    if u["totp_enabled"]:
        raise HTTPError(409, "already_enabled", "Two-factor is already on")
    _check_self_totp_allowed(c, u)
    secret = security.new_totp_secret()
    # new secret: forget the previous secret's last-used time step
    c.db.update_user(u["id"], totp_secret=secret, totp_last_counter=None)
    brand = (c.db.get_setting("brand") or {}).get("name") or "Goose Web"
    return ok({"secret": secret, "uri": security.totp_uri(secret, u["username"], brand)})


async def totp_enable(request: Request):
    c = ctx(request)
    u = c.require(request, allow_totp_enrol=True).user
    if u["totp_enabled"]:
        raise HTTPError(409, "already_enabled", "Two-factor is already on")
    _check_self_totp_allowed(c, u)
    b = await body_json(request)
    # accept_totp consumes the code's time step, so the enrolment code cannot be replayed at sign-in
    if not u["totp_secret"] or not c.auth.accept_totp(u, str(b.get("code") or "")):
        raise HTTPError(400, "totp_invalid", "That code is not valid. Check the time on your phone.")
    c.db.update_user(u["id"], totp_enabled=1)
    c.audit(request, "user.totp.enable", u)
    return ok()


async def totp_disable(request: Request):
    c = ctx(request)
    u = c.require(request).user
    b = await body_json(request, 16 * 1024)
    if u["role"] == "admin" and c.db.get_setting("require_totp_admins"):
        raise HTTPError(403, "required", "Two-factor is required for administrators")
    # A-8: every account type re-authenticates - local and directory accounts with the current password,
    # accounts without a password here (OIDC) with a current authenticator code.
    if not await asyncio.to_thread(c.auth.reauthenticate, u, str(b.get("password") or ""), str(b.get("code") or "")):
        c.audit(request, "user.totp.disable", u, ok=False)
        if u["auth_source"] in ("local", "ldap"):
            raise HTTPError(400, "wrong_password", "Password is not correct")
        raise HTTPError(400, "totp_invalid", "Enter a current code from your authenticator app to turn two-factor off")
    c.db.update_user(u["id"], totp_enabled=0, totp_secret=None, totp_last_counter=None)
    c.audit(request, "user.totp.disable", u)
    return ok()


async def me_tokens(request: Request):
    c = ctx(request)
    ident = c.require(request)
    u = ident.user
    if request.method == "GET":
        rows = c.db.query("SELECT id, name, prefix, created_at, last_used, expires_at FROM api_tokens WHERE user_id=?"
                          " ORDER BY id DESC", (u["id"],))
        return ok([{"id": r["id"], "name": r["name"], "prefix": r["prefix"], "createdAt": r["created_at"],
                    "lastUsed": r["last_used"], "expiresAt": r["expires_at"]} for r in rows])
    if ident.via != "cookie":
        raise HTTPError(403, "forbidden", "API tokens cannot create tokens")
    b = await body_json(request)
    days = int_param(b.get("days") or None, "days", None, 1, 3650)
    tid, token = c.auth.create_api_token(u, str(b.get("name") or "token"), days)
    c.audit(request, "user.token.create", u, target=str(b.get("name") or ""))
    return ok({"id": tid, "token": token})


async def me_token_delete(request: Request):
    c = ctx(request)
    u = c.require(request).user
    c.db.execute("DELETE FROM api_tokens WHERE id=? AND user_id=?", (int(request.path_params["tid"]), u["id"]))
    if c.hub is not None:   # SC-3: sockets signed in with what was just revoked close now
        c.hub.revalidate_clients()
    c.audit(request, "user.token.delete", u, target=request.path_params["tid"])
    return ok()


async def me_logins(request: Request):
    c = ctx(request)
    ident = c.require(request)
    rows = c.db.query("SELECT * FROM auth_sessions WHERE user_id=? AND expires_at>? ORDER BY last_seen DESC",
                      (ident.user["id"], time.time()))
    cur = ident.session["token_hash"] if ident.session else ""
    return ok([{"id": r["token_hash"][:12], "createdAt": r["created_at"], "lastSeen": r["last_seen"], "ip": r["ip"],
                "userAgent": r["user_agent"], "method": r["method"], "current": r["token_hash"] == cur} for r in rows])


async def me_login_delete(request: Request):
    c = ctx(request)
    ident = c.require(request)
    lid = request.path_params["lid"]
    if not lid.isalnum() or len(lid) != 12:
        raise HTTPError(400, "bad_id")
    c.db.execute("DELETE FROM auth_sessions WHERE user_id=? AND substr(token_hash,1,12)=?", (ident.user["id"], lid))
    if c.hub is not None:   # SC-3: sockets signed in with what was just revoked close now
        c.hub.revalidate_clients()
    return ok()


async def me_hints(request: Request):
    c = ctx(request)
    u = c.require(request).user
    pol = c.policy_for(u)
    native = c.profiles.is_native(u)
    if request.method == "GET":
        assigned = [{"id": h["id"], "name": h["name"], "description": h["description"], "content": h["content"]}
                    for h in c.profiles.assigned_hints(u)]
        managed = native and c.profiles.native_hints_managed(u)
        if native and not managed:
            text = await asyncio.to_thread(c.profiles.read_native_hints, u)
            return ok({"personal": text, "assigned": assigned, "effective": text, "editable": True, "native": True,
                       "managed": False, "path": str(c.profiles.native_hints_path(u))})
        sec = c.profiles.hint_sections(u)
        if managed:
            return ok({"personal": u["personal_hints"], "assigned": assigned, "effective": c.profiles.compose_hints(u),
                       "editable": True, "native": True, "managed": True, "path": str(c.profiles.native_hints_path(u)),
                       "personalDropped": False,
                       "team": {"id": sec["team"]["id"], "name": sec["team"]["name"]} if sec["team"] else None})
        return ok({"personal": u["personal_hints"], "assigned": assigned, "effective": c.profiles.compose_hints(u),
                   "editable": bool(pol.get("hints_edit")), "native": False,
                   "personalDropped": sec["personalDropped"],
                   "team": {"id": sec["team"]["id"], "name": sec["team"]["name"]} if sec["team"] else None})
    if not pol.get("hints_edit"):
        raise HTTPError(403, "forbidden", "Your administrator manages your goose hints")
    b = await body_json(request, 512 * 1024)
    text = str(b.get("personal") or "")
    if native and not c.profiles.native_hints_managed(u):
        backup = await asyncio.to_thread(c.profiles.write_native_hints, u, text)
        c.audit(request, "hints.native.save", u, detail={"backup": backup})
    else:
        c.db.update_user(u["id"], personal_hints=text)
        await asyncio.to_thread(c.profiles.write_hints, c.db.user_by_id(u["id"]))
        c.audit(request, "hints.personal.save", u)
    return ok()


async def me_notify(request: Request):
    c = ctx(request)
    u = c.require(request).user
    prefs = u.get("prefs") or {}
    if request.method == "GET":
        return ok(prefs.get("_notify") or {"webhook": None, "events": ["needs_you", "done", "error"]})
    b = await body_json(request)
    hook = b.get("webhook") or None
    if hook:
        if not c.policy_for(u).get("notify_webhook"):
            raise HTTPError(403, "forbidden", "Webhooks are not enabled for your account")
        if not isinstance(hook, str) or not hook.startswith(("https://", "http://")) or len(hook) > 500:
            raise HTTPError(400, "bad_url", "Webhook must be an http(s) URL")
        from .app import WebhookBlocked, webhook_target  # local import: app imports this module
        try:
            await webhook_target(hook, bool(c.settings.get("notify", "allow_private_targets")))
        except WebhookBlocked as e:
            raise HTTPError(400, "webhook_blocked", f"This webhook address is not allowed: {e}")
    events = [e for e in (b.get("events") or []) if e in ("needs_you", "done", "error")]
    # re-read inside one transaction: the webhook check above awaited, a prefs save may have landed meanwhile
    c.db.update_prefs(u["id"], lambda cur: prefsync.set_server_key(cur, "_notify", {"webhook": hook, "events": events}))
    return ok()


# ====================================================================== files
def _stat_entry(p: Path) -> dict | None:
    try:
        st = p.stat()
    except OSError:
        return None
    return {"name": p.name, "path": str(p), "dir": p.is_dir(), "size": st.st_size, "mtime": st.st_mtime}


async def fs_roots(request: Request):
    c = ctx(request)
    u = c.require(request).user
    ws = c.profiles.workspace(u)
    if u["role"] == "admin":
        roots = [{"path": str(ws), "label": "Home" if c.profiles.is_native(u) else "Workspace"}]
        if os.name == "nt":
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            roots += [{"path": f"{chr(65 + i)}:\\", "label": f"{chr(65 + i)}:"} for i in range(26) if mask >> i & 1]
        else:
            roots.append({"path": "/", "label": "/"})
    else:
        c.profiles.ensure_layout(u)
        p = c.policy_for(u)
        team_folder = p.get("team_folder")
        team_label = "Team: " + str((p.get("team") or {}).get("name") or "")
        roots = [{"path": r, "label": "Workspace" if i == 0 else team_label if r == team_folder else
                  os.path.basename(r.rstrip("\\/")) or r}
                 for i, r in enumerate(c.roots_for(u, p))]
    return ok({"roots": roots, "home": str(ws), "defaultCwd": str(ws)})


def _check_path(c: Ctx, u: dict, p: str) -> Path:
    if not p or not c.path_ok(u, p):
        raise HTTPError(403, "path_forbidden", "That folder is outside your allowed folders")
    return Path(p)


async def fs_list(request: Request):
    c = ctx(request)
    u = c.require(request).user
    path = request.query_params.get("path") or str(c.profiles.workspace(u))
    p = _check_path(c, u, os.path.abspath(path))
    if not p.is_dir():
        raise HTTPError(404, "not_found", "Folder not found")

    def scan():
        out = []
        with os.scandir(p) as it:
            for i, e in enumerate(it):
                if i >= 5000:
                    break
                try:
                    st = e.stat()
                    out.append({"name": e.name, "path": e.path, "dir": e.is_dir(), "size": st.st_size,
                                "mtime": st.st_mtime})
                except OSError:
                    continue
        out.sort(key=lambda x: (not x["dir"], x["name"].lower()))
        return out[:2000]
    try:
        entries = await asyncio.to_thread(scan)
    except PermissionError:
        raise HTTPError(403, "denied", "Access denied by the file system")
    parent = str(p.parent) if p.parent != p and c.path_ok(u, str(p.parent)) else None
    return ok({"path": str(p), "parent": parent, "entries": entries})


async def fs_mkdir(request: Request):
    c = ctx(request)
    u = c.require(request).user
    b = await body_json(request)
    p = _check_path(c, u, os.path.abspath(str(b.get("path") or "")))
    _refuse_hint_name(u, p.name)
    _refuse_agents_dir(u, p)
    p.mkdir(parents=True, exist_ok=True)
    return ok({"path": str(p)})


def _disconnect(c: Ctx, username: str, reason: str = "") -> None:
    """SC-3: close the open sockets of a user whose sign-ins were just revoked."""
    if c.hub is not None:
        c.hub.disconnect_user(username, reason=reason)


def _refuse_agents_dir(u: dict, path) -> None:
    """NEW-36: a non-admin may not create or write into a `.agents` folder (any component of the path, also as an
    8.3 short name or an NTFS stream name). Goose starts the MCP servers of every plugin in <cwd>/.agents/plugins
    when a chat starts there, i.e. runs their commands, and also reads skills and agent definitions from .agents."""
    if u["role"] != "admin" and acp_policy.has_agents_component(str(path)):
        raise HTTPError(403, "agents_folder_refused",
                        "'.agents' folders hold Goose plugins and agent settings, which can run programs; they "
                        "cannot be created or changed from the file browser. Ask your administrator.")


def _refuse_hint_name(u: dict, name: str) -> None:
    """Spec 009: a non-admin may not place a Goose context file (AGENTS.md, .goosehints, .goose-web-hints.md) in
    any folder: it would sit beside the team hints that the administrator controls."""
    # SD-6: like is_agents_name - an NTFS stream suffix (AGENTS.md::$INDEX_ALLOCATION) names the same file/folder
    if u["role"] != "admin" and str(name or "").split(":", 1)[0].strip().rstrip(". ").lower() in HINT_FILE_NAMES:
        raise HTTPError(403, "hint_file_refused",
                        f"'{name}' is a Goose hints file name. Your team's hints are managed by your administrator.")


# Windows device names: "CON", "con.txt", "COM1.tar.gz" all open the device instead of a file. Same list as
# security.safe_name plus the console devices and the superscript-digit COM/LPT aliases.
_RESERVED_DEVICE_NAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$",
                                    *(f"COM{i}" for i in [*"0123456789", "¹", "²", "³"]),
                                    *(f"LPT{i}" for i in [*"0123456789", "¹", "²", "³"])})
_BAD_NAME_CHARS = frozenset('<>:"/\\|?*') | {chr(i) for i in range(32)} | {"\x7f"}


def safe_upload_name(raw: str | None) -> str:
    """A safe file name for an uploaded file (NEW-05).

    Keeps only the last path component, drops characters Windows does not allow, strips leading spaces and
    trailing dots/spaces (Windows silently removes them, so "a.txt." would land on "a.txt") before and after
    truncating, prefixes Windows device names (CON, con.txt, COM1, ...) with "_" and falls back to
    "upload.bin" when nothing usable is left.
    """
    name = os.path.basename(str(raw or "").replace("\\", "/"))
    name = "".join(ch for ch in name if ch not in _BAD_NAME_CHARS)
    name = name.strip().rstrip(". ")
    name = name[:180]
    while len(name.encode("utf-8")) > 200:  # stay below the 255-byte limit of common Linux file systems
        name = name[:-1]
    name = name.rstrip(". ")
    if not name:
        return "upload.bin"
    if name.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_DEVICE_NAMES:
        name = "_" + name
    return name


def _create_exclusive(d: Path, name: str):
    """Open d/name for writing with exclusive create ('xb'); on a clash try 'name (1).ext', 'name (2).ext', ...
    An existing file is never truncated or overwritten, even if it appears between two attempts."""
    first = Path(name)
    stem, suf = first.stem, first.suffix
    target = d / name
    for n in range(1, 1001):
        try:
            return target, open(target, "xb")
        except (FileExistsError, IsADirectoryError, PermissionError):
            if not os.path.lexists(target):
                raise
        target = d / f"{stem} ({n}){suf}"
    raise HTTPError(409, "name_taken", "Too many files with that name in this folder")


async def fs_upload(request: Request):
    c = ctx(request)
    u = c.require(request).user
    d = _check_path(c, u, os.path.abspath(request.query_params.get("dir") or ""))
    limit = int(c.settings.get("server", "max_upload_mb") or 25) * 1024 * 1024
    # app.BodyLimit caps the whole body while it streams in (chunked bodies too), so request.form() never
    # spools more than max_upload_mb to disk (A-2); this early check only gives the same 413 without the middleware.
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        raise HTTPError(400, "bad_request", "Invalid Content-Length")
    if declared > limit + 64 * 1024:
        raise HTTPError(413, "too_large", f"Uploads are limited to {limit // 1048576} MB")
    form = await request.form(max_files=20, max_fields=20)
    saved = []
    try:
        files = [(f, safe_upload_name(f.filename)) for _, f in form.multi_items()
                 if hasattr(f, "filename") and f.filename]
        _refuse_agents_dir(u, d)
        for _, name in files:   # every name is checked before anything is written (A-14)
            _refuse_hint_name(u, name)
            _refuse_agents_dir(u, d / name)
        d.mkdir(parents=True, exist_ok=True)
        for f, name in files:
            target, out = _create_exclusive(d, name)
            size = 0
            with out:
                while chunk := await f.read(1024 * 1024):
                    size += len(chunk)
                    if size > limit:
                        out.close()
                        target.unlink(missing_ok=True)
                        raise HTTPError(413, "too_large", f"Uploads are limited to {limit // 1048576} MB")
                    out.write(chunk)
            saved.append({"name": target.name, "path": str(target), "size": size,
                          "mime": f.content_type or mimetypes.guess_type(target.name)[0] or "application/octet-stream"})
    finally:
        await form.close()
    c.audit(request, "fs.upload", u, target=str(d), detail={"files": [s["name"] for s in saved]})
    return ok({"files": saved})


async def fs_download(request: Request):
    c = ctx(request)
    u = c.require(request).user
    p = _check_path(c, u, os.path.abspath(request.query_params.get("path") or ""))
    if not p.is_file():
        raise HTTPError(404, "not_found", "File not found")
    # Always a download: octet-stream (never a type a browser renders inline) + attachment + sandbox CSP.
    return FileResponse(p, filename=p.name, media_type="application/octet-stream",
                        content_disposition_type="attachment",
                        headers={"Cache-Control": "no-store", "Content-Security-Policy": "sandbox; default-src 'none'"})


async def fs_read(request: Request):
    c = ctx(request)
    u = c.require(request).user
    p = _check_path(c, u, os.path.abspath(request.query_params.get("path") or ""))
    if not p.is_file():
        raise HTTPError(404, "not_found", "File not found")
    data = await asyncio.to_thread(lambda: p.open("rb").read(1024 * 1024 + 1))
    return ok({"path": str(p), "content": data[:1024 * 1024].decode("utf-8", "replace"),
               "truncated": len(data) > 1024 * 1024})


# ====================================================================== apps frame + herd
APP_FRAME_CSP = ("sandbox allow-scripts allow-forms allow-popups; "
                 "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'")


def _resource_html(contents: list) -> str | None:
    """First HTML document in an MCP ReadResourceResult's contents (text or base64 blob)."""
    import base64
    best = None
    for item in contents:
        if not isinstance(item, dict):
            continue
        mime = str(item.get("mimeType") or "")
        if isinstance(item.get("text"), str):
            text = item["text"]
        elif isinstance(item.get("blob"), str):
            try:
                text = base64.b64decode(item["blob"]).decode("utf-8", "replace")
            except ValueError:
                continue
        else:
            continue
        if mime.startswith("text/html"):
            return text
        if best is None:
            best = text
    return best


async def _acp_request(c: Ctx, request: Request, user: dict, up, method: str, params: dict,
                       timeout: float = 30) -> Any:
    """An ACP call the gateway makes for a REST route: runs the same method firewall as calls sent over /ws
    (policy.check) and audits a denial the same way the hub does ("acp.denied")."""
    policy = c.policy_for(user)
    try:
        acp_policy.check(method, params, is_admin=user["role"] == "admin", policy=policy,
                         roots=c.roots_for(user, policy))
    except acp_policy.Denied as e:
        c.audit(request, "acp.denied", user, target=method, detail={"reason": str(e), "via": "rest"}, ok=False)
        raise HTTPError(403, "forbidden", f"forbidden: {e}")
    return await up.request(method, params, timeout=timeout)


async def apps_frame(request: Request):
    c = ctx(request)
    u = c.require(request).user
    q = request.query_params
    up = c.upstream_for(u)
    uri = q.get("uri") or ""
    if uri:
        # Inline MCP App for a tool call in a chat (Desktop parity): the ui:// resource is read
        # through the user's own upstream for their own session, like Goose Desktop's app proxy.
        sid, ext = q.get("sessionId") or "", q.get("ext") or ""
        if not uri.startswith("ui://") or len(uri) > 2000 or not sid or len(sid) > 200 or not ext or len(ext) > 200:
            raise HTTPError(400, "bad_app_ref")
        try:
            res = await _acp_request(c, request, u, up, "_goose/unstable/resources/read",
                                     {"sessionId": sid, "uri": uri, "extensionName": ext})
        except RpcError as e:
            raise HTTPError(404, "app_not_found", e.message)
        html = _resource_html(((res or {}).get("result") or {}).get("contents") or [])
        if html is None:
            raise HTTPError(404, "app_not_found", "resource has no HTML content")
    else:
        name = q.get("name") or ""
        if not name or len(name) > 200:
            raise HTTPError(400, "bad_name")
        try:
            res = await _acp_request(c, request, u, up, "_goose/unstable/apps/export", {"name": name})
        except RpcError as e:
            raise HTTPError(404, "app_not_found", e.message)
        html = (res or {}).get("html") or ""
    return Response(html, media_type="text/html; charset=utf-8",
                    headers={"Content-Security-Policy": APP_FRAME_CSP, "X-Frame-Options": "SAMEORIGIN",
                             "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


_peer_cache: dict[str, tuple[float, dict]] = {}


async def _peer_herd(peer: dict) -> dict:
    key = peer.get("url", "")
    hit = _peer_cache.get(key)
    if hit and time.time() - hit[0] < 5:
        return hit[1]
    out = {"name": peer.get("name") or key, "url": key, "ok": False, "agents": []}
    try:
        async with httpx.AsyncClient(timeout=4, verify=peer.get("verifyTls", True)) as client:
            r = await client.get(key.rstrip("/") + "/api/herd",
                                 headers={"Authorization": f"Bearer {peer.get('token', '')}"})
            if r.status_code == 200:
                out.update(ok=True, agents=r.json().get("agents") or [])
            else:
                out["error"] = f"HTTP {r.status_code}"
    except httpx.HTTPError as e:
        out["error"] = str(e) or e.__class__.__name__
    _peer_cache[key] = (time.time(), out)
    return out


async def herd(request: Request):
    c = ctx(request)
    ident = c.require(request)
    u = ident.user
    if request.query_params.get("all") and u["role"] == "admin":
        agents = c.hub.all_herd()
    else:
        up = c.upstream_for(u)
        agents = up.herd()
    peers = []
    if ident.via == "cookie" and u["role"] == "admin":  # peers do not recurse; peer data is admin-only
        peers = await asyncio.gather(*[_peer_herd(p) for p in (c.db.get_setting("peers") or []) if p.get("url")])
    import socket
    name = (c.db.get_setting("brand") or {}).get("machine") or os.environ.get("COMPUTERNAME") or socket.gethostname()
    return ok({"machine": {"name": name, "url": c.settings.public_url}, "agents": agents, "peers": list(peers)})


# ====================================================================== admin: users
# (table, linked column, owner column) combinations _set_links may touch.
_LINK_TABLES = frozenset({("team_members", "team_id", "user_id"), ("user_hints", "hints_id", "user_id"),
                          ("team_hints", "hints_id", "team_id")})


def _set_links(c: Ctx, table: str, col: str, owner_col: str, owner_id: int, ids: list) -> None:
    if (table, col, owner_col) not in _LINK_TABLES:
        raise ValueError(f"unsupported link table {table}.{col}/{owner_col}")
    # The identifiers are checked against the constant _LINK_TABLES allow-list (never user input);
    # owner_id and ids are bound parameters (ids are int()-converted).
    stmts = [(f"DELETE FROM {table} WHERE {owner_col}=?", (int(owner_id),))]  # nosec B608
    for i in ids or []:
        stmts.append((f"INSERT OR IGNORE INTO {table}({owner_col}, {col}) VALUES(?,?)",  # nosec B608
                       (int(owner_id), int(i))))
    c.db.transaction(stmts)


def _admin_user_view(c: Ctx, u: dict) -> dict:
    d = c.public_user(u)
    d["teams"] = [t["id"] for t in c.db.user_teams(u["id"])]
    d["team"] = d["teams"][0] if d["teams"] else None
    d["hints"] = [r["hints_id"] for r in c.db.query("SELECT hints_id FROM user_hints WHERE user_id=?", (u["id"],))]
    d["policyOverrides"] = u.get("policy_overrides") or {}
    d["profilePath"] = str(c.profiles.root_for(u))
    return d


async def _reprovision(c: Ctx, users: list[dict]) -> dict:
    out = {}
    _guard_changed(c)   # team / user / policy changes can switch someone's prompt guard on or off
    for u in users:
        if c.profiles.is_native(u):
            await asyncio.to_thread(c.profiles.write_hints, u)   # managed native hints only (spec 011)
            continue
        try:
            changes = await asyncio.to_thread(c.profiles.provision, u)
        except Exception as e:
            out[u["username"]] = [f"error: {e}"]
            continue
        out[u["username"]] = changes
        w = c.workers.get(u["username"].lower())
        if w and changes and w.state == "ready":
            w.restart_pending = True
        if w:
            # recipe folders and (spec 012) the sandbox's folder grants follow team/folder changes; a changed
            # sandbox spec marks the worker for a restart when it is quiet
            c.workers.register(w.key, u["username"], c.profiles.path_root_env(u), False,
                               c.profiles.team_recipe_dirs(u), sandbox=c.sandbox_spec(u))
    if c.hub is not None:
        # A-1: a team, policy or membership change takes effect on open sockets now, not at the next 30 s check:
        # a socket whose role, policy or folders changed is closed and the browser reconnects with the new ones
        try:
            c.hub.revalidate_clients()
        except Exception:
            log.exception("revalidating sockets after a policy change")
    return out


async def _drop_sandbox(c: Ctx, u: dict) -> None:
    """Spec 012: stop the user's sandboxed worker, revoke its folder grants and delete its AppContainer. Spec 025
    (MX-10): the user's MXC egress proxy is closed too (deleted, or no longer sandboxed)."""
    from . import sandbox as sb
    if hasattr(c.workers, "proxies"):
        await c.workers.proxies.drop(u["username"].lower())
    name = sb.container_name(str(c.settings.profiles_root), u["username"])
    state_dir = str(c.settings.system_dir / "sandbox")
    # A container under the 1.11 name (C-5) is revoked and deleted too.
    legacy = await asyncio.to_thread(sb.migrate_legacy, state_dir, str(c.settings.profiles_root), u["username"])
    if legacy:
        c.db.audit("sandbox.remove", target=u["username"], detail={"container": "(1.11 name)", "legacy": True})
    if not sb.load_state(state_dir, name):
        return
    key = u["username"].lower()
    if c.workers.get(key):
        await c.workers.stop(key, "(sandbox removed)")
    from . import relay as rl
    await asyncio.to_thread(rl.undo_relays, state_dir, name, str(c.profiles.root_for(u)))
    st = await asyncio.to_thread(sb.remove, state_dir, name)
    c.db.audit("sandbox.remove", target=u["username"], detail={"container": name, "grants": sorted(st.get("grants", {}))})


async def admin_users(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        return ok([_admin_user_view(c, u) for u in c.db.users()])
    b = await body_json(request)
    try:
        username = security.safe_name(str(b.get("username") or ""))
    except ValueError as e:
        raise HTTPError(400, "bad_username", str(e))
    if c.db.user_by_name(username):
        raise HTTPError(409, "exists", "A user with that name already exists")
    role = "admin" if b.get("role") == "admin" else "user"
    mode = "native" if b.get("profileMode") == "native" and role == "admin" else "isolated"
    source = b.get("authSource") if b.get("authSource") in ("local", "ldap", "oidc") else "local"
    temp = None
    pw = b.get("password")
    if source == "local":
        if pw:
            probs = security.password_problems(pw, _min_pw(c), username)
            if probs:
                raise _weak(probs)
        else:
            temp = pw = temp_password()
    native_path = ""
    if mode == "native":
        native_path = c.db.get_setting("native_root") or ""
    uid = c.db.create_user(username=username, display_name=str(b.get("displayName") or username)[:120],
                           email=str(b.get("email") or "")[:200], role=role, auth_source=source,
                           password_hash=await asyncio.to_thread(security.hash_password, pw) if pw else None,
                           # spec 007: a password set by an administrator is always changed at first sign-in
                           must_change_pw=1 if source == "local" else 0,
                           profile_mode=mode, profile_path=native_path)
    team = _team_from_body(c, b)
    if team is _UNSET:
        team = c.db.get_setting("default_team_id") or None
    c.db.set_user_team(uid, team)
    _set_links(c, "user_hints", "hints_id", "user_id", uid, b.get("hints") or [])
    user = c.db.user_by_id(uid)
    if mode == "isolated":
        await asyncio.to_thread(c.profiles.provision, user)
    c.audit(request, "user.create", admin, target=username, detail={"role": role, "mode": mode, "source": source})
    return ok({"user": _admin_user_view(c, user), "tempPassword": temp})


_UNSET = object()


def _team_from_body(c: Ctx, b: dict):
    """The one team in a user create/update body: "team": id|null, or the older "teams": [id] (at most one).
    Returns _UNSET when the body names no team."""
    if "team" in b:
        raw = b["team"]
    elif "teams" in b:
        lst = b["teams"] or []
        if not isinstance(lst, list) or len(lst) > 1:
            raise HTTPError(400, "one_team", "A user belongs to one team at most")
        raw = lst[0] if lst else None
    else:
        return _UNSET
    if raw in (None, "", 0):
        return None
    try:
        tid = int(raw)
    except (TypeError, ValueError):
        raise HTTPError(400, "bad_team", "team must be a team id or null")
    if not c.db.one("SELECT id FROM teams WHERE id=?", (tid,)):
        raise HTTPError(400, "bad_team", "Team not found")
    return tid


async def admin_user_hints(request: Request):
    """What a user's Goose loads as hints (spec 009 'View effective hints')."""
    c = ctx(request)
    c.require(request, admin=True)
    u = _get_user(c, request)
    if c.profiles.native_hints_managed(u):
        sec = c.profiles.hint_sections(u)
        return ok({"username": u["username"], "native": True, "managed": True, "effective": c.profiles.compose_hints(u),
                   "path": str(c.profiles.native_hints_path(u)), "team": sec["team"]["name"] if sec["team"] else None,
                   "personalDropped": False,
                   "note": "Native profile with managed native hints: Goose Web writes this text to the native "
                           ".goosehints, which Goose Desktop, the goose CLI and scheduled runs on this account load "
                           "too. Goose also loads AGENTS.md and .goosehints from the chat's working folder up to its "
                           "git root."})
    if c.profiles.is_native(u):
        text = await asyncio.to_thread(c.profiles.read_native_hints, u)
        return ok({"username": u["username"], "native": True, "effective": text,
                   "path": str(c.profiles.native_hints_path(u)),
                   "note": "Native profile: Goose also loads AGENTS.md and .goosehints from the chat's working "
                           "folder up to its git root."})
    sec = c.profiles.hint_sections(u)
    return ok({"username": u["username"], "native": False, "effective": c.profiles.compose_hints(u),
               "path": str(c.profiles.hints_path(u)), "team": sec["team"]["name"] if sec["team"] else None,
               "personalDropped": sec["personalDropped"],
               "note": "Isolated profile: Goose loads only this file (CONTEXT_FILE_NAMES); hints files in "
                       "working folders are ignored."})


def _get_user(c: Ctx, request: Request) -> dict:
    u = c.db.user_by_id(int(request.path_params["uid"]))
    if not u:
        raise HTTPError(404, "not_found", "User not found")
    return u


def _admin_count(c: Ctx) -> int:
    return c.db.one("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0")["n"]


async def admin_user(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    u = _get_user(c, request)
    if request.method == "GET":
        return ok(_admin_user_view(c, u))
    if request.method == "DELETE":
        if u["id"] == admin["id"]:
            raise HTTPError(400, "self", "You cannot delete your own account")
        if u["role"] == "admin" and _admin_count(c) <= 1:
            raise HTTPError(400, "last_admin", "Keep at least one administrator")
        # SC-3: close the user's sockets (and sockets viewing the profile) first, so nothing writes after the delete
        if c.hub is not None:
            c.hub.drop_profile(u["username"])
        await c.workers.stop(u["username"].lower(), "(user deleted)")
        c.db.delete_chat_state(u["username"].lower())   # spec 019: the user's queues and herd marks
        await _drop_sandbox(c, u)
        where = await asyncio.to_thread(c.profiles.archive_profile, u, request.query_params.get("purgeProfile") == "1")
        c.db.execute("DELETE FROM users WHERE id=?", (u["id"],))
        c.audit(request, "user.delete", admin, target=u["username"], detail={"profile": where})
        return ok({"profile": where})
    b = await body_json(request)
    fields: dict[str, Any] = {}
    if "displayName" in b:
        fields["display_name"] = str(b["displayName"])[:120]
    if "email" in b:
        fields["email"] = str(b["email"])[:200]
    if "role" in b and b["role"] in ("admin", "user"):
        if u["id"] == admin["id"] and b["role"] != "admin":
            raise HTTPError(400, "self", "You cannot remove your own admin role")
        if u["profile_mode"] == "native" and b["role"] != "admin":
            raise HTTPError(400, "native", "The native profile belongs to an administrator")
        fields["role"] = b["role"]
    if "disabled" in b:
        if u["id"] == admin["id"]:
            raise HTTPError(400, "self", "You cannot disable your own account")
        fields["disabled"] = 1 if b["disabled"] else 0
    if "authSource" in b and b["authSource"] in ("local", "ldap", "oidc"):
        fields["auth_source"] = b["authSource"]
    if "policyOverrides" in b and isinstance(b["policyOverrides"], dict):
        fields["policy_overrides"] = {k: v for k, v in b["policyOverrides"].items() if k in DEFAULT_POLICY}
    if b.get("password"):
        probs = security.password_problems(b["password"], _min_pw(c), u["username"])
        if probs:
            raise _weak(probs)
        fields["password_hash"] = await asyncio.to_thread(security.hash_password, b["password"])
        fields["must_change_pw"] = 1  # spec 007: always; "mustChangePassword" in the request is ignored
    team = _team_from_body(c, b)
    c.db.update_user(u["id"], **fields)
    if team is not _UNSET:
        c.db.set_user_team(u["id"], team)
    if "hints" in b:
        _set_links(c, "user_hints", "hints_id", "user_id", u["id"], b["hints"])
    if fields.get("disabled") or "password_hash" in fields:
        # disabling or an admin password reset ends every session and API token of the user (GW-21)
        c.auth.revoke_user_sessions(u["id"])
        c.auth.revoke_user_tokens(u["id"])
        _disconnect(c, u["username"], reason="disabled or password reset")   # SC-3: open sockets too
    u2 = c.db.user_by_id(u["id"])
    changes = await _reprovision(c, [u2]) if {"team", "teams", "hints", "policyOverrides"} & b.keys() else {}
    if "role" in b and c.workers.get(u2["username"].lower()) and not c.profiles.is_native(u2):
        c.workers.register(u2["username"].lower(), u2["username"], c.profiles.path_root_env(u2), False,
                           c.profiles.team_recipe_dirs(u2), sandbox=c.sandbox_spec(u2))
        if not c.sandboxed(u2):
            await _drop_sandbox(c, u2)
    c.audit(request, "user.update", admin, target=u["username"], detail={"fields": sorted(b.keys() - {"password"})})
    return ok({"user": _admin_user_view(c, u2), "changes": changes.get(u["username"], [])})


async def admin_user_reset(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    u = _get_user(c, request)
    temp = temp_password()
    c.db.update_user(u["id"], password_hash=await asyncio.to_thread(security.hash_password, temp), must_change_pw=1,
                     auth_source="local", failed_logins=0, locked_until=0)
    c.auth.revoke_user_sessions(u["id"])
    c.auth.revoke_user_tokens(u["id"])  # GW-21: a reset must also cut off API-token access
    _disconnect(c, u["username"], reason="password reset")   # SC-3
    c.audit(request, "user.reset_password", admin, target=u["username"])
    return ok({"tempPassword": temp})


async def admin_user_unlock(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    u = _get_user(c, request)
    c.db.update_user(u["id"], failed_logins=0, locked_until=0)
    c.audit(request, "user.unlock", admin, target=u["username"])
    return ok()


async def admin_ip_blocks(request: Request):
    """Addresses blocked after repeated failed sign-ins, and addresses collecting failures (spec 007)."""
    c = ctx(request)
    c.require(request, admin=True)
    return ok({"items": c.auth.ipblock.list(), **c.auth.ipblock.describe()})


async def admin_ip_unblock(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    b = await body_json(request, 16 * 1024)
    if b.get("all") is True:
        n = c.auth.ipblock.unblock_all()
        c.audit(request, "auth.ip.unblocked", admin, target="*", detail={"removed": n})
        return ok({"removed": n})
    ip = str(b.get("ip") or "").strip()[:64]
    if not ip:
        raise HTTPError(400, "bad_request", "ip is required")
    if not c.auth.ipblock.unblock(ip):
        raise HTTPError(404, "not_found", "That address is not blocked or counted")
    c.audit(request, "auth.ip.unblocked", admin, target=ip)
    return ok({"removed": 1})


async def admin_user_reset_totp(request: Request):
    """Remove a user's two-factor enrolment (lost authenticator). The user signs in with the password only and can
    enrol again. Ends every session and API token, like a password reset: the lost device may still be signed in."""
    c = ctx(request)
    admin = c.require(request, admin=True).user
    u = _get_user(c, request)
    if u["id"] == admin["id"]:
        # your own two-factor is turned off in Account settings, where the password is checked
        raise HTTPError(400, "self", "Turn off your own two-factor in your account settings")
    if not u["totp_enabled"]:
        raise HTTPError(409, "totp_not_enabled", "This user does not use two-factor")
    c.db.update_user(u["id"], totp_enabled=0, totp_secret=None, totp_last_counter=None, failed_logins=0,
                     locked_until=0)
    c.auth.revoke_user_sessions(u["id"])
    revoked = c.auth.revoke_user_tokens(u["id"])
    _disconnect(c, u["username"], reason="two-factor reset")   # SC-3
    c.audit(request, "user.totp.reset", admin, target=u["username"], detail={"tokensRevoked": revoked})
    return ok({"user": _admin_user_view(c, c.db.user_by_id(u["id"])), "sessionsEnded": True,
               "tokensRevoked": revoked})


async def admin_user_provision(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    u = _get_user(c, request)
    if c.profiles.is_native(u):
        return ok({"changes": [], "restartPending": False, "note": "The native profile is never provisioned"})
    changes = (await _reprovision(c, [u])).get(u["username"], [])
    w = c.workers.get(u["username"].lower())
    c.audit(request, "user.provision", admin, target=u["username"], detail={"changes": len(changes)})
    return ok({"changes": changes, "restartPending": bool(w and w.restart_pending)})


# ====================================================================== admin: teams
def _clean_policy(p: dict, c: Ctx | None = None) -> dict:
    out = _clean_policy_fields(p)
    if c is not None:
        # C-11: no drive roots, system folders, the profiles root, Goose's own data or other users' folders.
        from .config import default_native_goose_root
        natives = [default_native_goose_root(), str(c.db.get_setting("native_root") or "")]
        natives += [str(u.get("profile_path") or "") for u in c.db.users() if u.get("profile_mode") == "native"]
        try:
            acp_policy.check_team_folders(out, profiles_root=str(c.settings.profiles_root),
                                          system_dir=str(c.settings.system_dir),
                                          native_roots=[n for n in natives if n],
                                          users_root=os.path.dirname(os.path.expanduser("~")))
        except ValueError as e:
            raise HTTPError(400, "bad_folder", f"Not allowed as a team folder: {e}")
    return out


def _clean_policy_fields(p: dict) -> dict:
    out: dict[str, Any] = {}
    for k in BOOL_KEYS:
        if k in p:
            out[k] = bool(p[k])
    for k in LIST_KEYS:
        if k in p:
            v = p[k]
            if isinstance(v, str):
                v = [x.strip() for x in v.replace("\n", ",").split(",")]
            v = [str(x).strip() for x in (v or []) if str(x).strip()][:200]
            if k in CHAT_LISTS and ANY in v:
                v = [ANY]                     # "Any" makes the rest of the list meaningless
            if k == "allowed_roots":
                bad = [r for r in v if r == ANY or not os.path.isabs(r)]
                if bad:
                    raise HTTPError(400, "bad_folder", f"Extra folders must be absolute paths: {bad[0]}")
            out[k] = v
    if p.get("max_concurrent_runs") not in (None, ""):
        out["max_concurrent_runs"] = max(0, min(100, int(p.get("max_concurrent_runs") or 0)))
    for k in ("default_provider", "default_model"):
        if p.get(k):
            out[k] = str(p[k]).strip()[:200]
    if str(p.get("share_folder") or "").strip():
        sf = str(p["share_folder"]).strip()[:500]
        if not os.path.isabs(sf):
            raise HTTPError(400, "bad_folder", "The team folder must be an absolute path")
        out["share_folder"] = sf
    if isinstance(p.get("guard"), dict):
        out["guard"] = guardmod.clean_team_guard(p["guard"])   # spec 018
    return out


def _team_view(c: Ctx, t: dict) -> dict:
    members = [r["user_id"] for r in c.db.query("SELECT user_id FROM team_members WHERE team_id=?", (t["id"],))]
    hints = [r["hints_id"] for r in c.db.query("SELECT hints_id FROM team_hints WHERE team_id=?", (t["id"],))]
    n = c.db.one("SELECT COUNT(*) AS n FROM team_items WHERE team_id=?", (t["id"],))["n"]
    pol = {**DEFAULT_POLICY, **(t.get("policy") or {})}
    return {"id": t["id"], "name": t["name"], "description": t["description"],
            "policy": pol, "members": members, "hints": hints,
            "itemCount": n, "createdAt": t["created_at"], "teamFolder": str(c.profiles.team_folder(t)),
            "warnings": acp_policy.team_warnings(pol, hints=len(hints), members=len(members))}


def _team_members(c: Ctx, team_id: int) -> list[dict]:
    return c.db.query("SELECT u.* FROM users u JOIN team_members m ON m.user_id=u.id WHERE m.team_id=?", (team_id,))


async def admin_teams(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        return ok([_team_view(c, t) for t in c.db.query("SELECT * FROM teams ORDER BY name")])
    b = await body_json(request)
    name = str(b.get("name") or "").strip()[:80]
    if not name:
        raise HTTPError(400, "bad_name", "Team name required")
    if c.db.one("SELECT id FROM teams WHERE name=?", (name,)):
        raise HTTPError(409, "exists", "A team with that name exists")
    import json as _json
    tid = c.db.execute("INSERT INTO teams(name, description, policy, created_at) VALUES(?,?,?,?)",
                       (name, str(b.get("description") or "")[:500], _json.dumps(_clean_policy(b.get("policy") or {}, c)),
                        time.time()))
    _guard_changed(c)
    c.audit(request, "team.create", admin, target=name)
    return ok({"id": tid, "team": _team_view(c, c.db.one("SELECT * FROM teams WHERE id=?", (tid,)))})


async def admin_team(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    tid = int(request.path_params["tid"])
    t = c.db.one("SELECT * FROM teams WHERE id=?", (tid,))
    if not t:
        raise HTTPError(404, "not_found", "Team not found")
    if request.method == "GET":
        return ok(_team_view(c, t))
    before = _team_members(c, tid)
    if request.method == "DELETE":
        c.db.execute("DELETE FROM teams WHERE id=?", (tid,))
        shutil.rmtree(c.profiles.library_dir / "teams" / str(tid), ignore_errors=True)
        await _reprovision(c, before)
        c.audit(request, "team.delete", admin, target=t["name"])
        return ok()
    b = await body_json(request)
    import json as _json
    if "name" in b or "description" in b or "policy" in b:
        c.db.execute("UPDATE teams SET name=?, description=?, policy=? WHERE id=?",
                     (str(b.get("name", t["name"]))[:80], str(b.get("description", t["description"]))[:500],
                      _json.dumps(_clean_policy(b["policy"], c) if "policy" in b else (t.get("policy") or {})), tid))
    moved: list[str] = []
    if "members" in b:
        ids = sorted({int(m) for m in b["members"] or []})
        # one team per user (spec 009): a new member leaves their previous team
        for r in c.db.query("SELECT m.user_id, u.username, t.name AS team FROM team_members m JOIN users u "
                            "ON u.id=m.user_id JOIN teams t ON t.id=m.team_id WHERE m.team_id<>?", (tid,)):
            if r["user_id"] in ids:
                moved.append(f"{r['username']} (from {r['team']})")
                before.append(c.db.user_by_id(r["user_id"]))
        c.db.transaction([("DELETE FROM team_members WHERE team_id=?", (tid,))] +
                         [("DELETE FROM team_members WHERE user_id=?", (m,)) for m in ids] +
                         [("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, m)) for m in ids])
    if "hints" in b:
        _set_links(c, "team_hints", "hints_id", "team_id", tid, b["hints"])
    after = _team_members(c, tid)
    seen = {u["id"]: u for u in before + after}
    changes = await _reprovision(c, [c.db.user_by_id(i) for i in seen])
    c.audit(request, "team.update", admin, target=t["name"], detail={"fields": sorted(b.keys()), "moved": moved})
    return ok({"team": _team_view(c, c.db.one("SELECT * FROM teams WHERE id=?", (tid,))), "changes": changes,
               "moved": moved})


async def admin_team_items(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    tid = int(request.path_params["tid"])
    if not c.db.one("SELECT id FROM teams WHERE id=?", (tid,)):
        raise HTTPError(404, "not_found", "Team not found")
    if request.method == "GET":
        rows = c.db.query("SELECT id, kind, name, source, created_at, payload FROM team_items WHERE team_id=? "
                          "ORDER BY kind, name", (tid,))
        return ok([{"id": r["id"], "kind": r["kind"], "name": r["name"], "source": r["source"],
                    "createdAt": r["created_at"],
                    "description": (r["payload"] or {}).get("origin") or (r["payload"] or {}).get("key") or ""}
                   for r in rows])
    b = await body_json(request, 8 * 1024 * 1024)
    kind = b.get("kind")
    if kind not in ("recipe", "skill", "extension", "provider"):
        raise HTTPError(400, "bad_kind", "kind must be recipe, skill, extension or provider")
    if b.get("fromProfile"):
        src = c.db.user_by_name(str(b["fromProfile"]))
        if not src:
            raise HTTPError(404, "not_found", "Profile not found")
        try:
            name, payload = await asyncio.to_thread(c.profiles.export_item, src, kind, str(b.get("ref") or ""))
        except (ValueError, KeyError, OSError) as e:
            raise HTTPError(400, "bad_ref", str(e))
        source = f"{src['username']}:{b.get('ref')}"
    else:
        name, payload, source = str(b.get("name") or ""), b.get("payload") or {}, "manual"
        if kind == "extension" and "secretsFrom" in payload:
            payload.pop("secretsFrom")   # only library copies may reference another profile's secrets
    try:
        name = security.safe_name(name.replace(" ", "-"), 128)
    except ValueError as e:
        raise HTTPError(400, "bad_name", str(e))
    import json as _json
    c.db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,?) "
                 "ON CONFLICT(team_id, kind, name) DO UPDATE SET payload=excluded.payload, source=excluded.source",
                 (tid, kind, name, _json.dumps(payload), source, time.time()))
    await asyncio.to_thread(c.profiles.store_team_item_files, tid, kind, name, payload)
    changes = await _reprovision(c, _team_members(c, tid))
    c.audit(request, "team.item.add", admin, target=f"{tid}:{kind}:{name}", detail={"source": source})
    return ok({"name": name, "changes": changes})


async def admin_team_item_delete(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    tid, iid = int(request.path_params["tid"]), int(request.path_params["iid"])
    it = c.db.one("SELECT * FROM team_items WHERE id=? AND team_id=?", (iid, tid))
    if not it:
        raise HTTPError(404, "not_found")
    c.db.execute("DELETE FROM team_items WHERE id=?", (iid,))
    await asyncio.to_thread(c.profiles.remove_team_item_files, tid, it["kind"], it["name"])
    await _reprovision(c, _team_members(c, tid))
    c.audit(request, "team.item.remove", admin, target=f"{tid}:{it['kind']}:{it['name']}")
    return ok()


async def admin_library(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    u = c.db.user_by_name(request.query_params.get("profile") or "")
    kind = request.query_params.get("kind") or "recipe"
    if not u:
        raise HTTPError(404, "not_found", "Profile not found")
    if kind not in ("recipe", "skill", "extension", "provider"):
        raise HTTPError(400, "bad_kind")
    return ok(await asyncio.to_thread(c.profiles.library, u, kind))


# ====================================================================== admin: hints
def _hint_users(c: Ctx, hid: int) -> list[dict]:
    return c.db.query("SELECT DISTINCT u.* FROM users u WHERE u.id IN (SELECT user_id FROM user_hints WHERE hints_id=?)"
                      " OR u.id IN (SELECT m.user_id FROM team_members m JOIN team_hints th ON th.team_id=m.team_id"
                      " WHERE th.hints_id=?)", (hid, hid))


async def admin_hints(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        return ok([{"id": h["id"], "name": h["name"], "description": h["description"], "updatedAt": h["updated_at"],
                    "size": len(h["content"])} for h in c.db.query("SELECT * FROM hints_docs ORDER BY name")])
    b = await body_json(request, 1024 * 1024)
    name = str(b.get("name") or "").strip()[:100]
    if not name:
        raise HTTPError(400, "bad_name", "Name required")
    if c.db.one("SELECT id FROM hints_docs WHERE name=?", (name,)):
        raise HTTPError(409, "exists", "A hints file with that name exists")
    hid = c.db.execute("INSERT INTO hints_docs(name, description, content, updated_at) VALUES(?,?,?,?)",
                       (name, str(b.get("description") or "")[:300], str(b.get("content") or ""), time.time()))
    c.audit(request, "hints.create", admin, target=name)
    return ok({"id": hid})


async def admin_hint(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    hid = int(request.path_params["hid"])
    h = c.db.one("SELECT * FROM hints_docs WHERE id=?", (hid,))
    if not h:
        raise HTTPError(404, "not_found")
    if request.method == "GET":
        return ok({"id": h["id"], "name": h["name"], "description": h["description"], "content": h["content"],
                   "updatedAt": h["updated_at"], "users": [u["username"] for u in _hint_users(c, hid)]})
    users = _hint_users(c, hid)
    if request.method == "DELETE":
        c.db.execute("DELETE FROM hints_docs WHERE id=?", (hid,))
        c.audit(request, "hints.delete", admin, target=h["name"])
    else:
        b = await body_json(request, 1024 * 1024)
        c.db.execute("UPDATE hints_docs SET name=?, description=?, content=?, updated_at=? WHERE id=?",
                     (str(b.get("name", h["name"]))[:100], str(b.get("description", h["description"]))[:300],
                      str(b.get("content", h["content"])), time.time(), hid))
        c.audit(request, "hints.update", admin, target=h["name"])
    for u in users:
        await asyncio.to_thread(c.profiles.write_hints, c.db.user_by_id(u["id"]) or u)
    return ok({"updatedUsers": [u["username"] for u in users]})


# ====================================================================== admin: Goose-native security (spec 026)
def _goosesec_view(c: Ctx) -> dict:
    """Goose's own prompt injection detection and adversary mode: the settings, where they apply and their state."""
    from . import goosesec
    members = [u for u in c.db.users() if not u["disabled"] and not c.profiles.is_native(u)]
    return {"settings": goosesec.load(c.db), "chosen": goosesec.chosen(c.db), "defaults": goosesec.DEFAULTS,
            "listener": c.classify.describe() if c.classify is not None else None,
            "native": goosesec.native_state(c.db), "hasNative": bool(c.profiles._native_admin()),
            "members": len(members), "gooseVersion": c.goose_version,
            "limits": {"rulesChars": goosesec.MAX_RULES_CHARS, "tools": goosesec.MAX_TOOLS}}


async def _goosesec_apply(c: Ctx, adopt: bool = False) -> dict:
    """Settings or tokens changed: members' profiles are provisioned again (a running worker restarts when it is
    idle, Goose reads these settings at start), and the native profile is brought in line through Goose itself."""
    from . import goosesec
    if c.classify is not None:
        c.classify.invalidate()
    members = [u for u in c.db.users() if not u["disabled"] and not c.profiles.is_native(u)]
    changed = await _reprovision(c, members)
    native = await goosesec.sync_native(c, adopt=adopt, force=True)
    return {"members": {name: len(ch) for name, ch in changed.items() if ch}, "native": native}


async def admin_goose_security(request: Request):
    from . import goosesec
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "PUT":
        b = await body_json(request)
        body = b.get("settings") if isinstance(b.get("settings"), dict) else b
        try:
            cfg = goosesec.clean({k: v for k, v in body.items() if k != "adoptNative"}, goosesec.load(c.db))
        except goosesec.SettingsError as e:
            raise HTTPError(400, "bad_settings", str(e))
        goosesec.save(c.db, cfg)
        c.audit(request, "goosesec.update", admin, detail=goosesec.summary(cfg))   # never the rules text
        applied = await _goosesec_apply(c, adopt=bool(b.get("adoptNative")))
        return ok({**_goosesec_view(c), "applied": applied})
    return ok(_goosesec_view(c))


async def admin_goose_security_check(request: Request):
    """A real request to the classification endpoint, the way Goose makes it (token, format, scores)."""
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if c.classify is None:
        raise HTTPError(503, "unavailable", "The classification endpoint is not available")
    res = await c.classify.self_test(admin)
    c.audit(request, "goosesec.check", admin, detail={"ok": bool(res.get("ok")), "state": res["listener"]["state"],
                                                     "error": str(res.get("error") or "")[:200]},
            ok=bool(res.get("ok")))
    return ok(res)


async def admin_goose_security_rotate(request: Request):
    """Replace every classifier token (a token may have leaked). Profiles get new ones at once."""
    from . import goosesec
    c = ctx(request)
    admin = c.require(request, admin=True).user
    goosesec.rotate_key(c.db)
    c.audit(request, "goosesec.rotate", admin)
    applied = await _goosesec_apply(c)
    return ok({**_goosesec_view(c), "applied": applied})


# ====================================================================== admin: prompt guard (spec 018)
def _guard_changed(c: Ctx) -> None:
    """Rule sets, a team's guard or the admin guard changed: contexts are rebuilt on next use, and the model is
    loaded in the background if a guard is on now (warm-up)."""
    if c.guard is None:
        return
    c.guard.invalidate()
    if c.settings.get("guard", "warm_up"):
        try:
            asyncio.get_running_loop().create_task(c.guard.warm_up())
        except RuntimeError:
            pass


def _ruleset_view(c: Ctx, r: dict, full: bool = False) -> dict:
    rules = r.get("rules") if isinstance(r.get("rules"), list) else []
    teams = [t["name"] for t in c.db.query("SELECT name, policy FROM teams ORDER BY name")
             if r["id"] in guardmod.clean_team_guard((t.get("policy") or {}).get("guard"))["rulesets"]]
    out = {"id": r["id"], "name": r["name"], "description": r["description"], "builtin": r["builtin"] or "",
           "ruleCount": len(rules), "updatedAt": r["updated_at"], "teams": teams,
           "admins": r["id"] in (c.guard.admin_config()["rulesets"] if c.guard else [])}
    if full:
        out["rules"] = rules
    return out


def _ruleset_body(b: dict, stored: dict | None = None) -> dict:
    try:
        return guardmod.clean_ruleset(b, partial_of=stored)
    except guardmod.RuleError as e:
        raise HTTPError(400, "bad_rules", str(e))


async def admin_guard(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "PUT":
        b = await body_json(request)
        if isinstance(b.get("admin"), dict):
            cfg = guardmod.clean_admin_guard(b["admin"])
            c.db.set_setting("guard_admin", cfg)
            c.audit(request, "guard.admin.update", admin, detail=cfg)
            _guard_changed(c)
    g = c.guard
    s = c.settings
    return ok({"health": g.health() if g else None, "admin": g.admin_config() if g else {},
               "settings": {k: s.get("guard", k) for k in ("threshold", "min_chars", "window_tokens", "max_windows",
                                                            "timeout_ms", "threads", "cache_size", "warm_up")},
               "model": guardmodel.describe(s), "hfRepo": guardmodel.HF_REPO, "hfRevision": guardmodel.HF_REVISION,
               "rulesets": [_ruleset_view(c, r) for r in c.db.query("SELECT * FROM guard_rulesets ORDER BY name")],
               "defaults": [{"key": k, "name": v["name"]} for k, v in guardmod.DEFAULT_RULESETS.items()]})


async def admin_guard_check(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if c.guard is None:
        raise HTTPError(503, "unavailable", "The prompt guard is not available")
    res = await c.guard.self_test()
    c.audit(request, "guard.check", admin, detail={"state": res["health"]["state"]}, ok=res["health"]["healthy"])
    return ok(res)


async def admin_guard_test(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    if c.guard is None:
        raise HTTPError(503, "unavailable", "The prompt guard is not available")
    b = await body_json(request, 512 * 1024)
    ids = [int(x) for x in b.get("rulesets") or [] if str(x).lstrip("-").isdigit()]
    args = b.get("args")
    if isinstance(args, str) and args.strip():
        import json as _json
        try:
            args = _json.loads(args)
        except ValueError:
            raise HTTPError(400, "bad_json", "Arguments must be JSON (an object)")
    if args is not None and not isinstance(args, (dict, str)):
        raise HTTPError(400, "bad_json", "Arguments must be a JSON object")
    # SA-11: the same child processes and deadline as real checks (a catastrophic regex cannot freeze the gateway)
    out = await c.guard.dry_run(ids, text=str(b.get("text") or "")[:100_000], tool=str(b.get("tool") or "")[:200],
                                ext=str(b.get("extension") or "")[:100], args=args if args not in ("", None) else None)
    if b.get("classify") and b.get("text"):
        s, st = await c.guard.classify(str(b["text"])[:100_000], point="test")
        out["classifier"] = {"score": None if s is None else round(s, 4), "status": st,
                             "blocked": s is not None and s >= c.guard.threshold, "threshold": c.guard.threshold}
        own = []   # closeout F3: guarded teams with their own threshold, and what the score means for them
        for t in c.db.query("SELECT name, policy FROM teams ORDER BY name"):
            tg = guardmod.clean_team_guard((t.get("policy") or {}).get("guard"))
            if tg["enabled"] and tg["threshold"] is not None:
                own.append({"team": t["name"], "threshold": tg["threshold"],
                            "blocked": s is not None and s >= tg["threshold"]})
        out["classifier"]["teams"] = own
    return ok(out)


async def admin_guard_rulesets(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        return ok([_ruleset_view(c, r) for r in c.db.query("SELECT * FROM guard_rulesets ORDER BY name")])
    b = await body_json(request, 1024 * 1024)
    rs = _ruleset_body(b)
    if c.db.one("SELECT id FROM guard_rulesets WHERE name=?", (rs["name"],)):
        raise HTTPError(409, "exists", "A rule set with that name exists")
    import json as _json
    rid = c.db.execute("INSERT INTO guard_rulesets(name, description, rules, builtin, updated_at) VALUES(?,?,?,?,?)",
                       (rs["name"], rs["description"], _json.dumps(rs["rules"]), "", time.time()))
    c.audit(request, "guard.ruleset.create", admin, target=rs["name"], detail={"rules": len(rs["rules"])})
    _guard_changed(c)
    return ok({"id": rid, "ruleset": _ruleset_view(c, c.db.one("SELECT * FROM guard_rulesets WHERE id=?", (rid,)), True)})


async def admin_guard_ruleset(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    rid = int(request.path_params["rid"])
    r = c.db.one("SELECT * FROM guard_rulesets WHERE id=?", (rid,))
    if not r:
        raise HTTPError(404, "not_found", "Rule set not found")
    if request.method == "GET":
        return ok(_ruleset_view(c, r, True))
    if request.method == "DELETE":
        c.db.execute("DELETE FROM guard_rulesets WHERE id=?", (rid,))
        c.audit(request, "guard.ruleset.delete", admin, target=r["name"])
        _guard_changed(c)
        return ok()
    b = await body_json(request, 1024 * 1024)
    rs = _ruleset_body(b, r)
    other = c.db.one("SELECT id FROM guard_rulesets WHERE name=? AND id<>?", (rs["name"], rid))
    if other:
        raise HTTPError(409, "exists", "A rule set with that name exists")
    import json as _json
    c.db.execute("UPDATE guard_rulesets SET name=?, description=?, rules=?, updated_at=? WHERE id=?",
                 (rs["name"], rs["description"], _json.dumps(rs["rules"]), time.time(), rid))
    c.audit(request, "guard.ruleset.update", admin, target=rs["name"], detail={"rules": len(rs["rules"])})
    _guard_changed(c)
    return ok({"ruleset": _ruleset_view(c, c.db.one("SELECT * FROM guard_rulesets WHERE id=?", (rid,)), True)})


async def admin_guard_ruleset_reset(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    rid = int(request.path_params["rid"])
    r = c.db.one("SELECT * FROM guard_rulesets WHERE id=?", (rid,))
    if not r:
        raise HTTPError(404, "not_found", "Rule set not found")
    if r["builtin"] not in guardmod.DEFAULT_RULESETS:
        raise HTTPError(400, "not_builtin", "Only a shipped rule set can be reset to its default")
    clash = c.db.one("SELECT id FROM guard_rulesets WHERE name=? AND id<>?",
                     (guardmod.DEFAULT_RULESETS[r["builtin"]]["name"], rid))
    if clash:
        raise HTTPError(409, "exists", "Another rule set uses the default name; rename it first")
    guardmod.seed_defaults(c.db, only=r["builtin"], overwrite=True)
    c.audit(request, "guard.ruleset.reset", admin, target=r["name"])
    _guard_changed(c)
    return ok({"ruleset": _ruleset_view(c, c.db.one("SELECT * FROM guard_rulesets WHERE id=?", (rid,)), True)})


async def admin_guard_restore_defaults(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    names = guardmod.seed_defaults(c.db)
    if names:
        c.audit(request, "guard.ruleset.restore", admin, detail={"restored": names})
        _guard_changed(c)
    return ok({"restored": names})


# ====================================================================== admin: auth, settings
async def admin_auth(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        return ok(c.auth.masked_auth_config())
    b = await body_json(request)
    try:
        c.auth.save_auth_config(b)
    except ValueError as e:
        raise HTTPError(400, "bad_config", str(e))
    c.audit(request, "settings.auth", admin)
    return ok(c.auth.masked_auth_config())


async def admin_settings(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "GET":
        peers = [{**p, "token": "********" if p.get("token") else ""} for p in (c.db.get_setting("peers") or [])]
        return ok({"brand": c.db.get_setting("brand") or {"name": "Goose Web", "tagline": ""},
                   "defaultTeamId": c.db.get_setting("default_team_id"),
                   "sessionHours": c.db.get_setting("session_hours") or c.settings.get("auth", "session_hours"),
                   "allowSelfTotp": c.db.get_setting("allow_self_totp", True),
                   "requireTotpForAdmins": bool(c.db.get_setting("require_totp_admins")), "peers": peers})
    b = await body_json(request)
    # Validate before writing anything (the UI saves every field in one request).
    if b.get("requireTotpForAdmins") and not c.db.get_setting("require_totp_admins") and not admin["totp_enabled"]:
        # Only an admin who already uses two-factor may switch the requirement on.
        raise HTTPError(409, "totp_needed_first",
                        "Turn on two-factor for your own account before requiring it for administrators")
    if "brand" in b and isinstance(b["brand"], dict):
        c.db.set_setting("brand", {k: str(v)[:120] for k, v in b["brand"].items() if k in ("name", "tagline", "machine")})
    if "defaultTeamId" in b:
        c.db.set_setting("default_team_id", int(b["defaultTeamId"]) if b["defaultTeamId"] else None)
    if "sessionHours" in b:
        c.db.set_setting("session_hours", max(1, min(720, int(b["sessionHours"] or 12))))
    if "allowSelfTotp" in b:
        c.db.set_setting("allow_self_totp", bool(b["allowSelfTotp"]))
    if "requireTotpForAdmins" in b:
        c.db.set_setting("require_totp_admins", bool(b["requireTotpForAdmins"]))
    if "peers" in b and isinstance(b["peers"], list):
        old = {p.get("url"): p for p in (c.db.get_setting("peers") or [])}
        peers = []
        for p in b["peers"][:50]:
            url = str(p.get("url") or "").rstrip("/")
            if not url.startswith(("https://", "http://")):
                continue
            tok = p.get("token") or ""
            if tok == "********":
                tok = (old.get(url) or {}).get("token", "")
            peers.append({"name": str(p.get("name") or url)[:80], "url": url, "token": tok,
                          "verifyTls": bool(p.get("verifyTls", True))})
        c.db.set_setting("peers", peers)
    c.audit(request, "settings.update", admin, detail={"fields": sorted(b.keys())})
    return ok()


# ====================================================================== admin: audit, system, ownership, tasks, logs
async def admin_audit(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    q = request.query_params
    sql, params = "SELECT * FROM audit WHERE 1=1", []
    if q.get("before"):
        sql += " AND id < ?"
        params.append(int_param(q["before"], "before"))
    if q.get("user"):
        sql += " AND username LIKE ?"
        params.append(q["user"].replace("%", "") + "%")
    if q.get("action"):
        sql += " AND action LIKE ?"
        params.append("%" + q["action"].replace("%", "") + "%")
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int_param(q.get("limit"), "limit", 100, 1, 500))
    rows = c.db.query(sql, params)
    return ok([{"id": r["id"], "ts": r["ts"], "username": r["username"], "ip": r["ip"], "action": r["action"],
                "target": r["target"], "detail": r["detail"], "ok": bool(r["ok"])} for r in rows])


async def admin_system(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    workers = []
    for w in c.workers.workers.values():
        d = w.describe()
        up = c.hub.upstreams.get(w.key)
        d["clients"], d["activeRuns"] = up.activity() if up else (0, 0)
        workers.append(d)
    native = c.db.get_setting("native_root") or ""
    from . import mxc
    sandbox = await asyncio.to_thread(mxc.summary, c.settings)
    sandbox["proxies"] = c.workers.proxies.describe() if hasattr(c.workers, "proxies") else {}
    return ok({"version": c.version, "gooseVersion": c.goose_version, "gooseBinary": c.settings.goose_binary,
               "sandbox": sandbox,
               "integrity": winsec.integrity_level(), "elevated": winsec.is_elevated(), "user": winsec.current_user(),
               "profilesRoot": str(c.settings.profiles_root), "nativeRoot": native,
               "desktopRunning": c.workers.desktop_running(), "nativeScheduler": c.settings.get("goose", "native_scheduler"),
               "uptime": time.time() - c.started_at, "pid": os.getpid(), "workers": workers,
               "bufferBytes": c.hub.total_buffer, "configFile": c.settings.source,
               "logs": dict(await asyncio.to_thread(logjanitor.usage, c.settings, native),
                            lastCheck=getattr(c, "log_report", None),
                            activity=str(c.settings.system_dir / "logs" / "activity.jsonl")
                            if c.settings.get("logs", "activity") else "")})


_PEM_MAX_BYTES = 1024 * 1024


def _tls_pair_problem(cert_file: str, key_file: str) -> str:
    """Why a certificate/key pair cannot serve HTTPS, or "" when it can (A-12): the key file must be an
    unencrypted PEM private key whose public key is the certificate's (the first certificate in certFile)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        if Path(key_file).stat().st_size > _PEM_MAX_BYTES or Path(cert_file).stat().st_size > _PEM_MAX_BYTES:
            return "keyFile/certFile is too large to be a PEM file"
        key = serialization.load_pem_private_key(Path(key_file).read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        return "keyFile is not an unencrypted PEM private key"
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    except (OSError, ValueError):
        return "certFile is not a PEM certificate"
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != cert.public_key().public_bytes(*spki):
        return "keyFile does not belong to the certificate in certFile"
    return ""


async def admin_tls(request: Request):
    """Spec 015: built-in HTTPS - status (GET), choose the mode (PUT), renew now (POST)."""
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if request.method == "PUT":
        b = await body_json(request)
        mode = str(b.get("mode") or "").strip().lower()
        if mode in ("", "config"):
            c.db.set_setting(tls.SETTING_KEY, None)          # back to config.yaml / environment
            new = None
        else:
            if mode not in tls.MODES:
                raise HTTPError(400, "bad_mode", "mode must be one of " + ", ".join(tls.MODES))
            new = {"mode": mode, "certFile": str(b.get("certFile") or "").strip(),
                   "keyFile": str(b.get("keyFile") or "").strip()}
            if mode == "files":
                for k in ("certFile", "keyFile"):
                    if security.is_unc_path(new[k]):   # never make the gateway open an SMB connection (A-12)
                        raise HTTPError(400, "bad_file", f"{k}: network (UNC) and device paths are not accepted; "
                                                         "copy the file to a local folder")
                    if not new[k] or not Path(new[k]).is_file():
                        raise HTTPError(400, "bad_file", f"{k}: file not found on the gateway machine")
                if (tls.describe_cert(new["certFile"]) or {}).get("error"):
                    raise HTTPError(400, "bad_cert", "certFile is not a PEM certificate")
                problem = await asyncio.to_thread(_tls_pair_problem, new["certFile"], new["keyFile"])
                if problem:
                    raise HTTPError(400, "bad_key", problem)
            c.db.set_setting(tls.SETTING_KEY, new)
        c.audit(request, "settings.tls", admin, detail={"mode": mode or "config"})
    elif request.method == "POST":
        if tls.configured(c.settings, c.db.get_setting(tls.SETTING_KEY))["effective"] != "self-signed":
            raise HTTPError(400, "not_self_signed", "Renewal applies to the built-in certificate only")
        st = await asyncio.to_thread(tls.ensure, c.settings, True)
        live = tls.ACTIVE.get("mode") == "self-signed" and tls.reload_active()
        c.audit(request, "tls.renewed", admin, detail={"reason": "admin", "live": bool(live)})
    st = await asyncio.to_thread(tls.status, c.settings, c.db.get_setting(tls.SETTING_KEY))
    st["restartRequired"] = st.get("effective") != (tls.ACTIVE.get("mode") if tls.is_active() else "off") or (
        st.get("effective") == "files" and tls.ACTIVE.get("cert") != st.get("certFile"))
    st["caUrl"] = "/tls/ca.crt"
    return ok(st)


async def admin_worker_action(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    key, action = request.path_params["key"], request.path_params["action"]
    if key not in c.workers.workers or action not in ("restart", "stop"):
        raise HTTPError(404, "not_found")
    if action == "restart":
        try:
            await c.workers.restart(key)
        except RuntimeError as e:
            log.error("worker %s restart failed: %s", key, e)   # detail in the gateway log only (A-13)
            raise HTTPError(500, "start_failed", "The worker did not start (see the gateway log)")
    else:
        up = c.hub.upstreams.get(key)
        await c.workers.stop(key, "(admin)")
        if up:
            await up.reset("stopped by an administrator")
    c.audit(request, f"worker.{action}", admin, target=key)
    return ok()


async def admin_ownership(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    u = c.db.user_by_name(request.query_params.get("profile") or "")
    if not u:
        raise HTTPError(404, "not_found", "Profile not found")
    root = c.profiles.root_for(u)
    rep = await asyncio.to_thread(winsec.ownership_report, str(root / "config"))
    rep["root"] = str(root)
    rep["user"] = winsec.current_user()
    return ok(rep)


async def admin_hosttasks(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    if not c.settings.get("host_tasks", "enabled"):
        raise HTTPError(404, "disabled", "Host task view is disabled in config")
    try:
        return ok(await hosttasks.list_tasks(c.settings.get("host_tasks", "path_filter") or "\\*"))
    except Exception:
        log.exception("host task list failed")   # detail in the gateway log only (A-13)
        raise HTTPError(500, "tasks_failed", "Could not read the scheduled tasks (see the gateway log)")


async def admin_hosttask_action(request: Request):
    c = ctx(request)
    admin = c.require(request, admin=True).user
    if not c.settings.get("host_tasks", "enabled"):
        raise HTTPError(404, "disabled")
    b = await body_json(request)
    try:
        await hosttasks.task_action(str(b.get("path") or ""), str(b.get("action") or ""))
    except (ValueError, RuntimeError) as e:
        c.audit(request, "hosttask." + str(b.get("action")), admin, target=str(b.get("path")), ok=False,
                detail={"error": str(e)})
        raise HTTPError(400, "task_failed", str(e))
    c.audit(request, "hosttask." + str(b.get("action")), admin, target=str(b.get("path")))
    return ok()


async def admin_logs(request: Request):
    c = ctx(request)
    c.require(request, admin=True)
    key = request.query_params.get("worker") or ""
    lines = int_param(request.query_params.get("lines"), "lines", 500, 10, 5000)
    if key:
        try:
            security.safe_name(key)
        except ValueError:
            raise HTTPError(400, "bad_worker", "worker must be a worker key (a user name)")
        p = c.settings.system_dir / "logs" / f"worker-{key}.log"
    else:
        p = c.settings.system_dir / "logs" / "gateway.log"
    if not p.exists():
        return ok({"lines": [], "path": str(p)})

    def tail():
        with open(p, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 400 * lines))
            return fh.read().decode("utf-8", "replace").splitlines()[-lines:]
    return ok({"lines": await asyncio.to_thread(tail), "path": str(p)})


async def healthz(request: Request):
    return PlainTextResponse("ok", headers={"Cache-Control": "no-store"})


routes = [
    Route("/healthz", healthz),
    Route("/api/auth/config", auth_config),
    Route("/api/auth/login", login, methods=["POST"]),
    Route("/api/auth/logout", logout, methods=["POST"]),
    Route("/api/auth/oidc/{pid}/start", oidc_start),
    Route("/api/auth/oidc/{pid}/callback", oidc_callback),
    Route("/api/auth/mfa", mfa_step, methods=["GET", "POST"]),
    Route("/api/me", me, methods=["GET", "PATCH"]),
    Route("/api/me/password", me_password, methods=["POST"]),
    Route("/api/me/prefs", me_prefs, methods=["GET", "PUT", "PATCH"]),
    Route("/api/me/totp/setup", totp_setup, methods=["POST"]),
    Route("/api/me/totp/enable", totp_enable, methods=["POST"]),
    Route("/api/me/totp/disable", totp_disable, methods=["POST"]),
    Route("/api/me/tokens", me_tokens, methods=["GET", "POST"]),
    Route("/api/me/tokens/{tid:int}", me_token_delete, methods=["DELETE"]),
    Route("/api/me/logins", me_logins),
    Route("/api/me/logins/{lid}", me_login_delete, methods=["DELETE"]),
    Route("/api/me/hints", me_hints, methods=["GET", "PUT"]),
    Route("/api/me/notify", me_notify, methods=["GET", "PUT"]),
    Route("/api/fs/roots", fs_roots),
    Route("/api/fs/list", fs_list),
    Route("/api/fs/mkdir", fs_mkdir, methods=["POST"]),
    Route("/api/fs/upload", fs_upload, methods=["POST"]),
    Route("/api/fs/download", fs_download),
    Route("/api/fs/read", fs_read),
    Route("/api/apps/frame", apps_frame),
    Route("/api/herd", herd),
    Route("/api/admin/users", admin_users, methods=["GET", "POST"]),
    Route("/api/admin/users/{uid:int}", admin_user, methods=["GET", "PATCH", "DELETE"]),
    Route("/api/admin/users/{uid:int}/reset-password", admin_user_reset, methods=["POST"]),
    Route("/api/admin/users/{uid:int}/unlock", admin_user_unlock, methods=["POST"]),
    Route("/api/admin/users/{uid:int}/reset-totp", admin_user_reset_totp, methods=["POST"]),
    Route("/api/admin/users/{uid:int}/provision", admin_user_provision, methods=["POST"]),
    Route("/api/admin/users/{uid:int}/hints", admin_user_hints, methods=["GET"]),
    Route("/api/admin/ip-blocks", admin_ip_blocks),
    Route("/api/admin/ip-blocks/unblock", admin_ip_unblock, methods=["POST"]),
    Route("/api/admin/teams", admin_teams, methods=["GET", "POST"]),
    Route("/api/admin/teams/{tid:int}", admin_team, methods=["GET", "PATCH", "DELETE"]),
    Route("/api/admin/teams/{tid:int}/items", admin_team_items, methods=["GET", "POST"]),
    Route("/api/admin/teams/{tid:int}/items/{iid:int}", admin_team_item_delete, methods=["DELETE"]),
    Route("/api/admin/library", admin_library),
    Route("/api/admin/hints", admin_hints, methods=["GET", "POST"]),
    Route("/api/admin/hints/{hid:int}", admin_hint, methods=["GET", "PUT", "DELETE"]),
    Route("/api/admin/goose-security", admin_goose_security, methods=["GET", "PUT"]),
    Route("/api/admin/goose-security/check", admin_goose_security_check, methods=["POST"]),
    Route("/api/admin/goose-security/rotate", admin_goose_security_rotate, methods=["POST"]),
    Route("/api/admin/guard", admin_guard, methods=["GET", "PUT"]),
    Route("/api/admin/guard/check", admin_guard_check, methods=["POST"]),
    Route("/api/admin/guard/test", admin_guard_test, methods=["POST"]),
    Route("/api/admin/guard/rulesets", admin_guard_rulesets, methods=["GET", "POST"]),
    Route("/api/admin/guard/rulesets/restore-defaults", admin_guard_restore_defaults, methods=["POST"]),
    Route("/api/admin/guard/rulesets/{rid:int}", admin_guard_ruleset, methods=["GET", "PUT", "DELETE"]),
    Route("/api/admin/guard/rulesets/{rid:int}/reset", admin_guard_ruleset_reset, methods=["POST"]),
    Route("/api/admin/auth", admin_auth, methods=["GET", "PUT"]),
    Route("/api/admin/settings", admin_settings, methods=["GET", "PUT"]),
    Route("/api/admin/audit", admin_audit),
    Route("/api/admin/system", admin_system),
    Route("/api/admin/system/workers/{key}/{action}", admin_worker_action, methods=["POST"]),
    Route("/api/admin/tls", admin_tls, methods=["GET", "PUT", "POST"]),
    Route("/api/admin/ownership", admin_ownership),
    Route("/api/admin/hosttasks", admin_hosttasks),
    Route("/api/admin/hosttasks/action", admin_hosttask_action, methods=["POST"]),
    Route("/api/admin/logs", admin_logs),
]
