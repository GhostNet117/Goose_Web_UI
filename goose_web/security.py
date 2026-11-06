"""Security primitives: password hashing, tokens, TOTP, rate limiting.

Only the standard library is used so the primitives are easy to audit.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time
import urllib.parse
from collections import defaultdict, deque

# ---------------------------------------------------------------- passwords
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 128 * _SCRYPT_R * (_SCRYPT_N + 2) * 2


def hash_password(password: str) -> str:
    """Return 'scrypt$N$r$p$salt_b64$hash_b64'."""
    if not isinstance(password, str) or not password:
        raise ValueError("password required")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


# A fixed dummy hash so unknown users cost the same time as known ones.
_DUMMY_HASH: str | None = None


def verify_password(password: str, stored: str | None) -> bool:
    global _DUMMY_HASH
    if not stored:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = hash_password("dummy-password-for-timing")
        stored = _DUMMY_HASH
        password = (password or "") + "\x00never"
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt((password or "").encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=len(expected), maxmem=128 * r * (n + 2) * 2)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def needs_rehash(stored: str | None) -> bool:
    try:
        algo, n, r, p, *_ = (stored or "").split("$")
        return algo != "scrypt" or int(n) < _SCRYPT_N or int(r) != _SCRYPT_R
    except Exception:
        return True


def password_problems(password: str, min_length: int = 10, username: str = "") -> list[str]:
    problems = []
    if len(password or "") < min_length:
        problems.append(f"must be at least {min_length} characters")
    if password and username and password.lower() == username.lower():
        problems.append("must not equal the username")
    if password and password.lower() in {"changeme", "password", "temp123", "goose", "letmein",
                                         "password123", "changeme123", "1234567890"}:
        problems.append("is too common")
    classes = sum([any(c.islower() for c in password or ""), any(c.isupper() for c in password or ""),
                   any(c.isdigit() for c in password or ""), any(not c.isalnum() for c in password or "")])
    if password and len(password) < 16 and classes < 3:
        problems.append("needs 3 of: lower, upper, digit, symbol (or be 16+ characters)")
    return problems


# ---------------------------------------------------------------- tokens
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def consteq(a: str | None, b: str | None) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def totp(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(_b32(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, at: float | None = None, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != 6:
        return False
    now = time.time() if at is None else at
    ok = False
    for w in range(-window, window + 1):
        ok |= hmac.compare_digest(totp(secret, now + w * 30), code)
    return ok


def totp_uri(secret: str, account: str, issuer: str = "Goose Web") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    q = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{q}"


# ---------------------------------------------------------------- rate limiting
class RateLimiter:
    """Sliding-window limiter keyed by arbitrary strings (ip, ip+user...)."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Record a hit; return True if still within the limit."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under abuse
                for k in list(self._hits)[:10_000]:
                    self._hits.pop(k, None)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


def safe_name(value: str, max_len: int = 64) -> str:
    """Validate a user/team/profile name usable as a folder name."""
    import re
    v = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,%d}" % (max_len - 1), v):
        raise ValueError("names may contain letters, digits, '.', '_' and '-' and must start with a letter or digit")
    if v.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                   *(f"LPT{i}" for i in range(10))} or v.startswith("_") or v.endswith("."):
        raise ValueError("reserved name")
    return v
