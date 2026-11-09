"""Authentication: local accounts, LDAP/Active Directory, OpenID Connect, TOTP, sessions and API tokens."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from . import security
from .config import Settings
from .db import Database
from .ipblock import BLOCKED_MESSAGE, IPBlocker

log = logging.getLogger("goose_web.auth")

API_TOKEN_PREFIX = "gwt_"
MASK = "********"

DEFAULT_AUTH = {
    "localEnabled": True,
    "ldap": {"enabled": False, "label": "Active Directory", "url": "", "bindDn": "", "bindPassword": "",
             "userBase": "", "userFilter": "(&(objectClass=user)(sAMAccountName={username}))",
             "adminGroupDn": "", "groupTeamMap": {}, "startTls": False, "autoCreate": True, "caFile": "",
             # Plain ldap:// without StartTLS sends passwords in cleartext; refused unless this is true (GW-13).
             "allowInsecure": False},
    "oidc": [],   # [{id,label,issuer,clientId,clientSecret,scopes,adminClaim,adminValue,teamClaim,autoCreate}]
}


LDAP_INSECURE_MESSAGE = ("The LDAP URL uses plain ldap:// without StartTLS, which would send passwords in "
                         "cleartext. Use an ldaps:// URL, turn on StartTLS, or (only on a trusted network) set "
                         "allowInsecure to true in the LDAP settings.")


def ldap_transport_insecure(c: dict) -> bool:
    """True when an LDAP config would bind without TLS and the admin has not opted in to that."""
    url = str(c.get("url") or "").strip().lower()
    return not (url.startswith("ldaps://") or bool(c.get("startTls")) or c.get("allowInsecure") is True)


def _same_endpoint(a: Any, b: Any) -> bool:
    """True when two server URLs / issuers name the same endpoint (case and a trailing slash ignored)."""
    def norm(v: Any) -> str:
        return str(v or "").strip().rstrip("/").lower()
    return norm(a) == norm(b)


OIDC_STATE_CAP = 1000          # pending OIDC sign-ins kept at most (oldest dropped first, A-14)
OIDC_STATE_SECONDS = 600
MFA_PENDING_SECONDS = 300      # OIDC sign-in waiting for the TOTP code (A-8)
MFA_MAX_ATTEMPTS = 5
OIDC_UNLINKED_MESSAGE = ("An account with this name already exists but is not linked to your sign-in identity. "
                         "Ask an administrator to link the account.")


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
        self.ipblock = IPBlocker(db, settings)
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
            # The stored secret is only kept for the same server: a new URL needs the password again, so the
            # old one is never sent to a server it was not meant for (A-11).
            same = _same_endpoint(ldap.get("url"), old["ldap"].get("url"))
            ldap["bindPassword"] = old["ldap"].get("bindPassword", "") if same else ""
        ldap["allowInsecure"] = ldap.get("allowInsecure") is True  # strict bool; anything else = secure default
        if ldap.get("enabled") and ldap_transport_insecure(ldap):
            raise ValueError(LDAP_INSECURE_MESSAGE)
        oidc_old = {o["id"]: o for o in old["oidc"] if o.get("id")}
        oidc = []
        for o in new.get("oidc") or []:
            if not o.get("id"):
                continue
            security.safe_name(o["id"])
            prev = oidc_old.get(o["id"])
            if o.get("clientSecret") == MASK:
                # kept only while the issuer is unchanged (A-11)
                same = prev is not None and _same_endpoint(o.get("issuer"), prev.get("issuer"))
                o["clientSecret"] = prev.get("clientSecret", "") if same else ""
            if "stripDomain" not in o:
                # A-5: a new provider keeps the whole e-mail address / user name; an existing one keeps the
                # behaviour it had (the old default removed the domain).
                o["stripDomain"] = bool(prev.get("stripDomain", True)) if prev is not None else False
            oidc.append(o)
        self.db.set_setting("auth", {"localEnabled": bool(new.get("localEnabled", old["localEnabled"])),
                                     "ldap": ldap, "oidc": oidc})
        self._oidc_meta.clear()

    # ------------------------------------------------------------ password login
    def _fail(self, ip: str, username: str, code: str, message: str, status: int = 401) -> AuthError:
        """Count a failed sign-in against the client address (spec 007) and return the error to raise."""
        if self.ipblock.record_failure(ip, username):
            return AuthError("ip_blocked", BLOCKED_MESSAGE, 403)
        return AuthError(code, message, status)

    def _refuse_locked(self, user: dict, username: str, password: str, ip: str, cfg: dict) -> AuthError:
        """The answer for a sign-in to a locked account (A-3).

        With a wrong password it is exactly the wrong-password answer (401 invalid_credentials after the same
        scrypt work, counted toward the caller's IP block like any failure), so the lock is neither visible to
        a guesser nor a user-name oracle. Only the correct password learns "temporarily locked" (423), and that
        refusal is not counted toward the caller's address: the owner retrying cannot get their own network
        blocked. The account's failure counter is not raised while it is locked, so the lock is not extended."""
        right = False
        if user["disabled"]:
            security.verify_password(password, None)
        elif user["auth_source"] == "local":
            hashed = user["password_hash"] if (cfg["localEnabled"] or user["role"] == "admin") else None
            right = security.verify_password(password, hashed) and hashed is not None
        elif user["auth_source"] == "ldap" and cfg["ldap"].get("enabled") and not ldap_transport_insecure(cfg["ldap"]):
            checked = self._ldap_login(username, password, user, cfg["ldap"])
            right = bool(checked and checked["id"] == user["id"])
        else:
            security.verify_password(password, None)
        self.db.audit("auth.login", user=user, ip=ip, target=username, ok=False,
                      detail={"reason": "locked", "passwordCorrect": right})
        if right:
            return AuthError("locked", "Account temporarily locked after failed attempts. Try again later.", 423)
        return self._fail(ip, username, "invalid_credentials", "Invalid username or password")

    def login(self, username: str, password: str, totp: str | None, ip: str) -> dict:
        username = (username or "").strip()
        if self.ipblock.is_blocked(ip):
            raise AuthError("ip_blocked", BLOCKED_MESSAGE, 403)
        if not self.ip_limiter.hit(ip) or not self.user_limiter.hit(f"{ip}|{username.lower()}"):
            raise AuthError("rate_limited", "Too many attempts. Wait a few minutes.", 429)
        if not username or not password:
            raise AuthError("invalid_credentials", "Invalid username or password")
        if len(password) > 1024:
            raise self._fail(ip, username, "invalid_credentials", "Invalid username or password")
        user = self.db.user_by_name(username)
        cfg = self.auth_config()
        if user and user["locked_until"] > time.time():
            raise self._refuse_locked(user, username, password, ip, cfg)
        ok = False
        if user is None or user["auth_source"] == "ldap":
            if cfg["ldap"].get("enabled") and ldap_transport_insecure(cfg["ldap"]):
                # Refuse before any bind: never send the password in cleartext (GW-13). Not counted as a
                # failed attempt - it is a server configuration problem, not a wrong password.
                log.error("LDAP sign-in refused: %s", LDAP_INSECURE_MESSAGE)
                self.db.audit("auth.ldap", ip=ip, target=username, ok=False,
                              detail={"error": "ldap_insecure", "fix": LDAP_INSECURE_MESSAGE})
                raise AuthError("ldap_insecure", "Directory sign-in is not configured securely. "
                                "Ask an administrator to check the LDAP settings.", 503)
            if cfg["ldap"].get("enabled"):
                user = self._ldap_login(username, password, user, cfg["ldap"])
                ok = user is not None
            else:
                security.verify_password(password, None)  # constant-ish time
        elif user["auth_source"] == "local":
            if not cfg["localEnabled"] and user["role"] != "admin":
                # Same reply and the same scrypt cost as an unknown name (A-9): the name stays undisclosed.
                security.verify_password(password, None)
                self.db.audit("auth.login", user=user, ip=ip, target=username, ok=False,
                              detail={"reason": "local sign-in disabled"})
                raise self._fail(ip, username, "invalid_credentials", "Invalid username or password")
            ok = security.verify_password(password, user["password_hash"])
            if ok and security.needs_rehash(user["password_hash"]):
                self.db.update_user(user["id"], password_hash=security.hash_password(password))
        else:
            # OIDC accounts have no password here: pay the same scrypt cost as every other refusal (A-9).
            security.verify_password(password, None)
        if not ok or not user:
            if user:
                self._record_failure(user)
            self.db.audit("auth.login", user=user, ip=ip, target=username, ok=False)
            raise self._fail(ip, username, "invalid_credentials", "Invalid username or password")
        if user["disabled"]:
            self.db.audit("auth.login", user=user, ip=ip, target=username, detail={"reason": "disabled"}, ok=False)
            raise self._fail(ip, username, "invalid_credentials", "Invalid username or password")
        if user["totp_enabled"]:
            if not totp:
                raise AuthError("totp_required", "Enter the code from your authenticator app")
            # A wrong or replayed code counts toward the same lockout as a wrong password.
            if not self.accept_totp(user, str(totp)):
                self._record_failure(user)
                self.db.audit("auth.totp", user=user, ip=ip, ok=False)
                raise self._fail(ip, username, "totp_invalid", "That code is not valid")
        fields: dict[str, Any] = {"failed_logins": 0, "locked_until": 0, "last_login_at": time.time()}
        if user["auth_source"] == "local" and not user["must_change_pw"]:
            # Passwords set before the strong-password policy (spec 007) must be replaced: the plain text is
            # only available here, so a weak one is flagged now and the user changes it before going further.
            min_len = int(self.s.get("auth", "min_password_length") or security.PASSWORD_MIN_LENGTH)
            if security.password_problems(password, min_len, user["username"]):
                fields["must_change_pw"] = 1
                self.db.audit("auth.password.weak", user=user, ip=ip, target=user["username"],
                              detail={"forcedChange": True})
        self.db.update_user(user["id"], **fields)
        self.user_limiter.reset(f"{ip}|{username.lower()}")
        self.ipblock.record_success(ip)
        return self.db.user_by_id(user["id"])

    def _record_failure(self, user: dict) -> None:
        """Count one failed sign-in factor (password or TOTP) toward the account lockout."""
        fresh = self.db.user_by_id(user["id"]) or user
        fails = int(fresh["failed_logins"] or 0) + 1
        fields: dict[str, Any] = {"failed_logins": fails}
        if fails >= int(self.s.get("auth", "lockout_threshold") or 8):
            fields["locked_until"] = time.time() + 60 * float(self.s.get("auth", "lockout_minutes") or 15)
            fields["failed_logins"] = 0
        self.db.update_user(user["id"], **fields)

    def accept_totp(self, user: dict, code: str, secret: str | None = None) -> bool:
        """Verify a TOTP code and consume its time step so it can never be used again (GW-14).

        The step is claimed with a conditional UPDATE, so two concurrent requests carrying the same
        code cannot both succeed."""
        secret = secret if secret is not None else user.get("totp_secret")
        last = (self.db.user_by_id(user["id"]) or user).get("totp_last_counter")
        counter = security.totp_match(secret or "", code, last_counter=last)
        if counter is None:
            return False
        return self.db.execute_count(
            "UPDATE users SET totp_last_counter=? WHERE id=? AND (totp_last_counter IS NULL OR totp_last_counter < ?)",
            (counter, user["id"], counter)) == 1

    # ------------------------------------------------------------ LDAP / AD
    def _ldap_login(self, username: str, password: str, existing: dict | None, c: dict) -> dict | None:
        if ldap_transport_insecure(c):  # defence in depth; login() already refuses with a clear error
            log.error("LDAP bind refused: %s", LDAP_INSECURE_MESSAGE)
            return None
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
        except ImportError:  # pragma: no cover
            log.error("ldap3 is not installed")
            return None
        try:
            tls = None
            if c.get("caFile") or str(c.get("url", "")).strip().lower().startswith("ldaps") or c.get("startTls"):
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
        if teams:
            # one team per user (spec 009): the directory decides; with several mapped groups the first one wins
            if len(teams) > 1:
                self.db.audit("user.team.directory", target=username,
                              detail={"mapped": teams, "used": teams[0], "reason": "one team per user"})
            if (self.db.user_team(existing["id"]) or {}).get("id") != int(teams[0]):
                self.db.set_user_team(existing["id"], int(teams[0]))
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

    async def oidc_start(self, pid: str, redirect_uri: str, binding: str = "") -> str:
        """The IdP authorization URL for a new sign-in. `binding` is the random value of the pre-sign-in browser
        cookie set by the API (A-4); its hash is kept with the state, and the callback must present it."""
        o = self._oidc_provider(pid)
        meta = await self._oidc_discovery(o)
        state, verifier, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(48), secrets.token_urlsafe(16)
        now = time.time()
        self.db.execute("DELETE FROM oidc_states WHERE created_at < ?", (now - OIDC_STATE_SECONDS,))
        # Anonymous callers create these rows: keep at most OIDC_STATE_CAP, the oldest go first (A-14).
        self.db.execute("DELETE FROM oidc_states WHERE state IN (SELECT state FROM oidc_states "
                        "ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (OIDC_STATE_CAP - 1,))
        self.db.execute("INSERT INTO oidc_states(state, verifier, nonce, created_at, binding) VALUES(?,?,?,?,?)",
                        (state, verifier, f"{pid}|{nonce}", now, security.token_hash(binding) if binding else None))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        q = {"response_type": "code", "client_id": o["clientId"], "redirect_uri": redirect_uri,
             "scope": o.get("scopes") or "openid profile email", "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        return meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)

    async def oidc_callback(self, pid: str, code: str, state: str, redirect_uri: str, ip: str,
                            binding: str | None = None) -> dict:
        """Finish an OIDC sign-in. `binding` is the pre-sign-in cookie value (None only for internal callers
        that never set one): when the state was bound to a browser, only that browser may finish it (A-4)."""
        row = self.db.one("SELECT * FROM oidc_states WHERE state=?", (state or "",))
        self.db.execute("DELETE FROM oidc_states WHERE state=?", (state or "",))
        if not row or time.time() - row["created_at"] > OIDC_STATE_SECONDS:
            raise AuthError("oidc_state", "Sign-in expired, try again", 400)
        stored = row.get("binding") or ""
        if (stored or binding is not None) and not (binding and security.consteq(security.token_hash(binding), stored)):
            log.warning("OIDC callback refused: the state was not started by this browser (provider %s)", pid)
            raise AuthError("oidc_browser", "This sign-in was started in another browser. Start it again here.", 400)
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
        # Accounts are bound to the stable (issuer, subject) pair, not to the display username (GW-12).
        iss = str(claims.get("iss") or "").rstrip("/")
        sub = str(claims.get("sub") or "")
        if not iss or not sub or len(sub) > 255:
            raise AuthError("oidc_claims", "The identity token failed validation", 401)
        oidc_sources = ("oidc", f"oidc:{pid}")
        existing = self.db.one("SELECT * FROM users WHERE oidc_issuer=? AND oidc_subject=?", (iss, sub))
        if existing:
            if existing["auth_source"] not in oidc_sources:
                # bound once, but an admin has since switched it to local/LDAP: keep it protected
                raise AuthError("oidc_conflict", "A local account with this name already exists", 409)
        else:
            existing = self.db.user_by_name(username)
            if existing and existing["auth_source"] not in oidc_sources:
                raise AuthError("oidc_conflict", "A local account with this name already exists", 409)
            if existing and existing.get("oidc_subject"):
                # same username, but bound to a different identity (other provider or other person)
                log.warning("OIDC sign-in for %s refused: account is bound to a different identity", username)
                raise AuthError("oidc_conflict", "This account is linked to a different sign-in identity", 409)
            if existing and not _verified_email_matches(claims, existing.get("email")):
                # A-5: an existing, unbound account (pre-provisioned, switched to OIDC, or created before GW-12) is
                # never claimed by its name alone: only by the verified e-mail address an admin recorded on it.
                log.warning("OIDC sign-in for %s refused: unbound account and no verified matching e-mail", username)
                self.db.audit("auth.oidc.unlinked", ip=ip, target=existing["username"], ok=False,
                              detail={"issuer": iss, "provider": pid})
                raise AuthError("oidc_unlinked", OIDC_UNLINKED_MESSAGE, 409)
        user = self._upsert_external(existing, username, "oidc", claims.get("name") or username,
                                     claims.get("email") or "", role, teams, o.get("autoCreate", True))
        if not user or user["disabled"]:
            raise AuthError("oidc_denied", "This account is not allowed to sign in", 403)
        if not user.get("oidc_subject"):
            # First sign-in of a new account, or migration of an account created before binding existed.
            try:
                bound = self.db.execute_count(
                    "UPDATE users SET oidc_issuer=?, oidc_subject=? WHERE id=? AND oidc_subject IS NULL",
                    (iss, sub, user["id"]))
            except sqlite3.IntegrityError:  # (iss, sub) bound to another account concurrently
                bound = 0
            if bound != 1:
                raise AuthError("oidc_conflict", "This account is linked to a different sign-in identity", 409)
            self.db.audit("user.oidc.bind", user=user, target=user["username"], detail={"issuer": iss, "provider": pid})
        if not user["totp_enabled"]:   # with two-factor, the sign-in completes in finish_mfa (A-8)
            self.db.update_user(user["id"], last_login_at=time.time())
        return self.db.user_by_id(user["id"])

    # ------------------------------------------------------------ second factor after OIDC (A-8)
    def begin_mfa(self, user: dict, method: str) -> str:
        """Park a sign-in that still needs the account's TOTP code; returns the token for the pending cookie."""
        token = security.new_token()
        now = time.time()
        self.db.execute("DELETE FROM mfa_pending WHERE created_at < ? OR user_id=?", (now - MFA_PENDING_SECONDS, user["id"]))
        self.db.execute("DELETE FROM mfa_pending WHERE token_hash IN (SELECT token_hash FROM mfa_pending "
                        "ORDER BY created_at DESC LIMIT -1 OFFSET ?)", (OIDC_STATE_CAP - 1,))
        self.db.execute("INSERT INTO mfa_pending(token_hash, user_id, method, created_at, attempts) VALUES(?,?,?,?,0)",
                        (security.token_hash(token), user["id"], method[:64], now))
        return token

    def mfa_pending(self, token: str) -> dict | None:
        """The pending row for a cookie value, if it is still valid."""
        if not token or len(token) > 200:
            return None
        row = self.db.one("SELECT * FROM mfa_pending WHERE token_hash=?", (security.token_hash(token),))
        if not row or time.time() - row["created_at"] > MFA_PENDING_SECONDS or row["attempts"] >= MFA_MAX_ATTEMPTS:
            return None
        return row

    def finish_mfa(self, token: str, code: str, ip: str) -> tuple[dict, str]:
        """Check the TOTP code of a pending OIDC sign-in; returns (user, method) or raises AuthError.
        Wrong codes count toward the account lockout and the IP block, like a wrong code at password sign-in."""
        if self.ipblock.is_blocked(ip):
            raise AuthError("ip_blocked", BLOCKED_MESSAGE, 403)
        if not self.ip_limiter.hit(ip):
            raise AuthError("rate_limited", "Too many attempts. Wait a few minutes.", 429)
        row = self.mfa_pending(token)
        if row is None:
            raise AuthError("mfa_expired", "This sign-in has expired. Sign in again.", 400)
        user = self.db.user_by_id(row["user_id"])
        if not user or user["disabled"] or not user["totp_enabled"]:
            self.db.execute("DELETE FROM mfa_pending WHERE token_hash=?", (row["token_hash"],))
            raise AuthError("mfa_expired", "This sign-in has expired. Sign in again.", 400)
        if user["locked_until"] > time.time():
            raise AuthError("locked", "Account temporarily locked after failed attempts. Try again later.", 423)
        if not self.accept_totp(user, str(code or "").strip()):
            self.db.execute("UPDATE mfa_pending SET attempts=attempts+1 WHERE token_hash=?", (row["token_hash"],))
            self._record_failure(user)
            self.db.audit("auth.totp", user=user, ip=ip, ok=False, detail={"method": row["method"]})
            raise self._fail(ip, user["username"], "totp_invalid", "That code is not valid")
        self.db.execute("DELETE FROM mfa_pending WHERE token_hash=?", (row["token_hash"],))
        self.db.update_user(user["id"], failed_logins=0, locked_until=0, last_login_at=time.time())
        self.ipblock.record_success(ip)
        return self.db.user_by_id(user["id"]), row["method"]

    def reauthenticate(self, user: dict, password: str, code: str = "") -> bool:
        """Re-check who is at the keyboard before a sensitive change (turning two-factor off, A-8).

        Local accounts: the current password. Directory (LDAP) accounts: a bind with the current password.
        Accounts without a password here (OIDC): a current code from the authenticator app."""
        password = str(password or "")
        if user["auth_source"] == "local":
            return bool(password) and security.verify_password(password, user["password_hash"])
        if user["auth_source"] == "ldap":
            cfg = self.auth_config()["ldap"]
            if not password or not cfg.get("enabled") or ldap_transport_insecure(cfg):
                security.verify_password(password, None)
                return False
            checked = self._ldap_login(user["username"], password, user, cfg)
            return bool(checked and checked["id"] == user["id"])
        code = str(code or password).strip()
        return bool(user.get("totp_enabled")) and bool(code) and self.accept_totp(user, code)

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
            # Session lifetimes are fixed: expires_at is set once at sign-in and never extended (no sliding
            # expiry). last_seen is only activity bookkeeping for the "signed-in devices" list.
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

    def totp_enrolment_required(self, user: dict) -> bool:
        """True for an administrator without two-factor while 'require two-factor for admins' is on."""
        return bool(user.get("role") == "admin" and not user.get("totp_enabled")
                    and self.db.get_setting("require_totp_admins"))

    def revoke_user_tokens(self, uid: int) -> int:
        """Delete every API token of a user (password reset/change, account disabled - GW-21)."""
        return self.db.execute_count("DELETE FROM api_tokens WHERE user_id=?", (uid,))

    def create_api_token(self, user: dict, name: str, days: int | None) -> tuple[int, str]:
        token = API_TOKEN_PREFIX + security.new_token(32)
        exp = time.time() + 86400 * days if days else None
        tid = self.db.execute(
            "INSERT INTO api_tokens(user_id, name, token_hash, prefix, created_at, expires_at) VALUES(?,?,?,?,?,?)",
            (user["id"], (name or "token")[:80], security.token_hash(token), token[:10], time.time(), exp))
        return tid, token


def _verified_email_matches(claims: dict, stored: Any) -> bool:
    """True when the IdP vouches for an e-mail address (email_verified true) equal to the account's stored one."""
    verified = claims.get("email_verified")
    if not (verified is True or str(verified).strip().lower() == "true"):
        return False
    email = str(claims.get("email") or "").strip().lower()
    return bool(email) and "@" in email and email == str(stored or "").strip().lower()


def _jwt_claims(jwt: str) -> dict:
    try:
        payload = jwt.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return {}
