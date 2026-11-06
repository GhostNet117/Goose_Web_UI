"""Authentication: local accounts, LDAP/Active Directory, OpenID Connect, TOTP, sessions and API tokens."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from . import security
from .config import Settings
from .db import Database

log = logging.getLogger("goose_web.auth")

API_TOKEN_PREFIX = "gwt_"
MASK = "********"

DEFAULT_AUTH = {
    "localEnabled": True,
    "ldap": {"enabled": False, "label": "Active Directory", "url": "", "bindDn": "", "bindPassword": "",
             "userBase": "", "userFilter": "(&(objectClass=user)(sAMAccountName={username}))",
             "adminGroupDn": "", "groupTeamMap": {}, "startTls": False, "autoCreate": True, "caFile": ""},
    "oidc": [],   # [{id,label,issuer,clientId,clientSecret,scopes,adminClaim,adminValue,teamClaim,autoCreate}]
}


class AuthError(Exception):
    def __init__(self, code: str, message: str, status: int = 401, **extra: Any):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


@dataclass
class Identity:
    user: dict
    session: dict | None      # auth_sessions row for cookie logins
    via: str                  # cookie | token


class AuthService:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.s = settings
        self.ip_limiter = security.RateLimiter(40, 300)
        self.user_limiter = security.RateLimiter(10, 300)
        self._oidc_meta: dict[str, tuple[float, dict]] = {}

    # ------------------------------------------------------------ config
    def auth_config(self) -> dict:
        cfg = self.db.get_setting("auth") or {}
        out = json.loads(json.dumps(DEFAULT_AUTH))
        out["localEnabled"] = cfg.get("localEnabled", True)
        out["ldap"].update(cfg.get("ldap") or {})
        out["oidc"] = cfg.get("oidc") or []
        return out

    def public_auth_config(self) -> dict:
        c = self.auth_config()
        return {"local": c["localEnabled"], "ldap": {"enabled": bool(c["ldap"].get("enabled")),
                                                     "label": c["ldap"].get("label") or "Directory"},
                "oidc": [{"id": o["id"], "label": o.get("label") or o["id"]} for o in c["oidc"] if o.get("id")]}

    def masked_auth_config(self) -> dict:
        c = self.auth_config()
        if c["ldap"].get("bindPassword"):
            c["ldap"]["bindPassword"] = MASK
        for o in c["oidc"]:
            if o.get("clientSecret"):
                o["clientSecret"] = MASK
        return c

    def save_auth_config(self, new: dict) -> None:
        old = self.auth_config()
        ldap = {**old["ldap"], **(new.get("ldap") or {})}
        if ldap.get("bindPassword") == MASK:
            ldap["bindPassword"] = old["ldap"].get("bindPassword", "")
        oidc_old = {o["id"]: o for o in old["oidc"] if o.get("id")}
        oidc = []
        for o in new.get("oidc") or []:
            if not o.get("id"):
                continue
            security.safe_name(o["id"])
            if o.get("clientSecret") == MASK:
                o["clientSecret"] = (oidc_old.get(o["id"]) or {}).get("clientSecret", "")
            oidc.append(o)
        self.db.set_setting("auth", {"localEnabled": bool(new.get("localEnabled", old["localEnabled"])),
                                     "ldap": ldap, "oidc": oidc})
        self._oidc_meta.clear()

    # ------------------------------------------------------------ password login
    def login(self, username: str, password: str, totp: str | None, ip: str) -> dict:
        username = (username or "").strip()
        if not self.ip_limiter.hit(ip) or not self.user_limiter.hit(f"{ip}|{username.lower()}"):
            raise AuthError("rate_limited", "Too many attempts. Wait a few minutes.", 429)
        if not username or not password or len(password) > 1024:
            raise AuthError("invalid_credentials", "Invalid username or password")
        user = self.db.user_by_name(username)
        cfg = self.auth_config()
        if user and user["locked_until"] > time.time():
            raise AuthError("locked", "Account temporarily locked after failed attempts. Try again later.", 423)
        ok = False
        if user is None or user["auth_source"] == "ldap":
            if cfg["ldap"].get("enabled"):
                user = self._ldap_login(username, password, user, cfg["ldap"])
                ok = user is not None
            else:
                security.verify_password(password, None)  # constant-ish time
        elif user["auth_source"] == "local":
            if not cfg["localEnabled"] and user["role"] != "admin":
                raise AuthError("invalid_credentials", "Local sign-in is disabled")
            ok = security.verify_password(password, user["password_hash"])
            if ok and security.needs_rehash(user["password_hash"]):
                self.db.update_user(user["id"], password_hash=security.hash_password(password))
        if not ok or not user:
            if user:
                fails = user["failed_logins"] + 1
                fields: dict[str, Any] = {"failed_logins": fails}
                if fails >= int(self.s.get("auth", "lockout_threshold") or 8):
                    fields["locked_until"] = time.time() + 60 * float(self.s.get("auth", "lockout_minutes") or 15)
                    fields["failed_logins"] = 0
                self.db.update_user(user["id"], **fields)
            self.db.audit("auth.login", user=user, ip=ip, target=username, ok=False)
            raise AuthError("invalid_credentials", "Invalid username or password")
        if user["disabled"]:
            self.db.audit("auth.login", user=user, ip=ip, target=username, detail={"reason": "disabled"}, ok=False)
            raise AuthError("invalid_credentials", "Invalid username or password")
        if user["totp_enabled"]:
            if not totp:
                raise AuthError("totp_required", "Enter the code from your authenticator app")
            if not security.verify_totp(user["totp_secret"], totp):
                self.db.update_user(user["id"], failed_logins=user["failed_logins"] + 1)
                self.db.audit("auth.totp", user=user, ip=ip, ok=False)
                raise AuthError("totp_invalid", "That code is not valid")
        self.db.update_user(user["id"], failed_logins=0, locked_until=0, last_login_at=time.time())
        self.user_limiter.reset(f"{ip}|{username.lower()}")
        return self.db.user_by_id(user["id"])

    # ------------------------------------------------------------ LDAP / AD
    def _ldap_login(self, username: str, password: str, existing: dict | None, c: dict) -> dict | None:
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
        except ImportError:  # pragma: no cover
            log.error("ldap3 is not installed")
            return None
        try:
            tls = None
            if c.get("caFile") or str(c.get("url", "")).startswith("ldaps") or c.get("startTls"):
                import ssl
                tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=c.get("caFile") or None)
            server = ldap3.Server(c["url"], get_info=ldap3.NONE, tls=tls, connect_timeout=8)
            svc = ldap3.Connection(server, user=c.get("bindDn") or None, password=c.get("bindPassword") or None,
                                   auto_bind=False, receive_timeout=10, raise_exceptions=False)
            if c.get("startTls"):
                svc.open()
                svc.start_tls()
            if not svc.bind():
                log.warning("LDAP service bind failed: %s", svc.result)
                return None
            flt = (c.get("userFilter") or DEFAULT_AUTH["ldap"]["userFilter"]).replace(
                "{username}", escape_filter_chars(username))
            svc.search(c["userBase"], flt, attributes=["memberOf", "displayName", "mail", "cn"], size_limit=2)
            if len(svc.entries) != 1:
                svc.unbind()
                return None
            entry = svc.entries[0]
            dn = entry.entry_dn
            groups = [str(g).lower() for g in (entry.memberOf.values if "memberOf" in entry else [])]
            display = str(entry.displayName) if "displayName" in entry and entry.displayName else username
            mail = str(entry.mail) if "mail" in entry and entry.mail else ""
            svc.unbind()
            uconn = ldap3.Connection(server, user=dn, password=password, auto_bind=False, raise_exceptions=False,
                                     receive_timeout=10)
            if c.get("startTls"):
                uconn.open()
                uconn.start_tls()
            if not uconn.bind():
                return None
            uconn.unbind()
        except Exception as e:
            log.warning("LDAP error: %s", e)
            return None
        role = "admin" if c.get("adminGroupDn") and c["adminGroupDn"].lower() in groups else "user"
        teams = [int(t) for g, t in (c.get("groupTeamMap") or {}).items() if g.lower() in groups]
        return self._upsert_external(existing, username, "ldap", display, mail, role, teams,
                                     auto_create=c.get("autoCreate", True))

    def _upsert_external(self, existing: dict | None, username: str, source: str, display: str, email: str,
                         role: str, teams: list[int], auto_create: bool) -> dict | None:
        if existing is None:
            if not auto_create:
                return None
            security.safe_name(username)
            uid = self.db.create_user(username=username, display_name=display, email=email, role=role,
                                      auth_source=source, profile_mode="isolated")
            self.db.audit("user.create", target=username, detail={"source": source, "role": role})
            existing = self.db.user_by_id(uid)
            if not teams and self.db.get_setting("default_team_id"):
                teams = [int(self.db.get_setting("default_team_id"))]
        else:
            if existing["profile_mode"] != "native":  # never demote the native admin from the directory
                self.db.update_user(existing["id"], role=role, display_name=display or existing["display_name"],
                                    email=email or existing["email"])
        for t in teams:
            self.db.execute("INSERT OR IGNORE INTO team_members(team_id, user_id) VALUES(?,?)", (t, existing["id"]))
        return self.db.user_by_id(existing["id"])

    # ------------------------------------------------------------ OIDC (auth code + PKCE)
    def _oidc_provider(self, pid: str) -> dict:
        for o in self.auth_config()["oidc"]:
            if o.get("id") == pid:
                return o
        raise AuthError("unknown_provider", "Unknown sign-in provider", 404)

    async def _oidc_discovery(self, o: dict) -> dict:
        cached = self._oidc_meta.get(o["id"])
        if cached and time.time() - cached[0] < 3600:
            return cached[1]
        url = o["issuer"].rstrip("/") + "/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            r.raise_for_status()
            meta = r.json()
        self._oidc_meta[o["id"]] = (time.time(), meta)
        return meta

    async def oidc_start(self, pid: str, redirect_uri: str) -> str:
        o = self._oidc_provider(pid)
        meta = await self._oidc_discovery(o)
        state, verifier, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(48), secrets.token_urlsafe(16)
        self.db.execute("DELETE FROM oidc_states WHERE created_at < ?", (time.time() - 600,))
        self.db.execute("INSERT INTO oidc_states(state, verifier, nonce, created_at) VALUES(?,?,?,?)",
                        (state, verifier, f"{pid}|{nonce}", time.time()))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        q = {"response_type": "code", "client_id": o["clientId"], "redirect_uri": redirect_uri,
             "scope": o.get("scopes") or "openid profile email", "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)

    async def oidc_callback(self, pid: str, code: str, state: str, redirect_uri: str, ip: str) -> dict:
        row = self.db.one("SELECT * FROM oidc_states WHERE state=?", (state or "",))
        self.db.execute("DELETE FROM oidc_states WHERE state=?", (state or "",))
        if not row or time.time() - row["created_at"] > 600:
            raise AuthError("oidc_state", "Sign-in expired, try again", 400)
        rpid, nonce = row["nonce"].split("|", 1)
        if rpid != pid:
            raise AuthError("oidc_state", "Sign-in mismatch", 400)
        o = self._oidc_provider(pid)
        meta = await self._oidc_discovery(o)
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(meta["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": o["clientId"], "client_secret": o.get("clientSecret") or "",
                "code_verifier": row["verifier"]}, headers={"Accept": "application/json"})
            if r.status_code != 200:
                raise AuthError("oidc_token", "The identity provider rejected the sign-in", 401)
            tok = r.json()
        # The ID token came straight from the token endpoint over TLS (OIDC Core 3.1.3.7), so the TLS
        # server check replaces the signature check; the claims are still validated.
        claims = _jwt_claims(tok.get("id_token") or "")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if claims.get("iss", "").rstrip("/") != o["issuer"].rstrip("/") or o["clientId"] not in auds or \
                float(claims.get("exp") or 0) < time.time() - 60 or claims.get("nonce") != nonce:
            raise AuthError("oidc_claims", "The identity token failed validation", 401)
        if meta.get("userinfo_endpoint") and tok.get("access_token"):
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    ui = await c.get(meta["userinfo_endpoint"],
                                     headers={"Authorization": f"Bearer {tok['access_token']}"})
                    if ui.status_code == 200:
                        claims = {**ui.json(), **claims}
            except httpx.HTTPError:
                pass
        raw_name = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
        username = str(raw_name).split("@")[0] if o.get("stripDomain", True) else str(raw_name)
        username = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in username)[:64]
        role = "user"
        if o.get("adminClaim"):
            v = claims.get(o["adminClaim"])
            vals = v if isinstance(v, list) else [v]
            if o.get("adminValue") in vals or (not o.get("adminValue") and v is True):
                role = "admin"
        teams = []
        if o.get("teamClaim"):
            tv = claims.get(o["teamClaim"]) or []
            tv = tv if isinstance(tv, list) else [tv]
            names = {str(x).lower() for x in tv}
            teams = [t["id"] for t in self.db.query("SELECT id, name FROM teams") if t["name"].lower() in names]
        existing = self.db.user_by_name(username)
        if existing and existing["auth_source"] not in ("oidc", f"oidc:{pid}"):
            raise AuthError("oidc_conflict", "A local account with this name already exists", 409)
        user = self._upsert_external(existing, username, "oidc", claims.get("name") or username,
                                     claims.get("email") or "", role, teams, o.get("autoCreate", True))
        if not user or user["disabled"]:
            raise AuthError("oidc_denied", "This account is not allowed to sign in", 403)
        self.db.update_user(user["id"], last_login_at=time.time())
        return user

    # ------------------------------------------------------------ sessions
    def session_seconds(self, remember: bool) -> float:
        if remember:
            return 86400 * float(self.s.get("auth", "remember_days") or 30)
        return 3600 * float(self.db.get_setting("session_hours") or self.s.get("auth", "session_hours") or 12)

    def create_session(self, user: dict, ip: str, ua: str, method: str, remember: bool = False) -> tuple[str, str]:
        token = security.new_token()
        csrf = security.new_token(24)
        now = time.time()
        self.db.execute(
            "INSERT INTO auth_sessions(token_hash, user_id, csrf, created_at, expires_at, last_seen, ip, user_agent,"
            " method) VALUES(?,?,?,?,?,?,?,?,?)",
            (security.token_hash(token), user["id"], csrf, now, now + self.session_seconds(remember), now, ip,
             (ua or "")[:300], method))
        self.db.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
        return token, csrf

    def resolve_cookie(self, token: str) -> Identity | None:
        if not token or len(token) > 200:
            return None
        row = self.db.one("SELECT * FROM auth_sessions WHERE token_hash=?", (security.token_hash(token),))
        now = time.time()
        if not row or row["expires_at"] < now:
            return None
        user = self.db.user_by_id(row["user_id"])
        if not user or user["disabled"]:
            return None
        if now - row["last_seen"] > 60:
            # sliding expiry for non-remembered sessions: extend while in use (bounded by session length)
            self.db.execute("UPDATE auth_sessions SET last_seen=? WHERE token_hash=?", (now, row["token_hash"]))
        return Identity(user=user, session=row, via="cookie")

    def resolve_token(self, token: str) -> Identity | None:
        if not token.startswith(API_TOKEN_PREFIX) or len(token) > 200:
            return None
        row = self.db.one("SELECT * FROM api_tokens WHERE token_hash=?", (security.token_hash(token),))
        if not row or (row["expires_at"] and row["expires_at"] < time.time()):
            return None
        user = self.db.user_by_id(row["user_id"])
        if not user or user["disabled"] or user["must_change_pw"]:
            return None
        if not row["last_used"] or time.time() - row["last_used"] > 300:
            self.db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), row["id"]))
        return Identity(user=user, session=None, via="token")

    def logout(self, token: str) -> None:
        self.db.execute("DELETE FROM auth_sessions WHERE token_hash=?", (security.token_hash(token or ""),))

    def revoke_user_sessions(self, uid: int, keep_hash: str | None = None) -> None:
        if keep_hash:
            self.db.execute("DELETE FROM auth_sessions WHERE user_id=? AND token_hash<>?", (uid, keep_hash))
        else:
            self.db.execute("DELETE FROM auth_sessions WHERE user_id=?", (uid,))

    def create_api_token(self, user: dict, name: str, days: int | None) -> tuple[int, str]:
        token = API_TOKEN_PREFIX + security.new_token(32)
        exp = time.time() + 86400 * days if days else None
        tid = self.db.execute(
            "INSERT INTO api_tokens(user_id, name, token_hash, prefix, created_at, expires_at) VALUES(?,?,?,?,?,?)",
            (user["id"], (name or "token")[:80], security.token_hash(token), token[:10], time.time(), exp))
        return tid, token


def _jwt_claims(jwt: str) -> dict:
    try:
        payload = jwt.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return {}
