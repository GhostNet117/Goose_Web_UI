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


# Strong-password policy (spec 007). auth.min_password_length may raise the minimum, never lower it.
PASSWORD_MIN_LENGTH = 12

# Common passwords and the words they are built from. A password is refused when it is one of these, or when
# it is one of these words with digits/symbols added at the start or end and simple letter swaps
# (P@ssw0rd123!, Summer2026!, !Qwerty2026).
_COMMON_WORDS = frozenset("""
password passwd passw0rd pass changeme letmein welcome welcomeback admin administrator root guest user login
default secret temp temporary test tester qwerty qwertyuiop qwertz azerty asdf asdfgh asdfghjkl zxcvbn
zxcvbnm iloveyou loveyou monkey dragon sunshine princess football baseball soccer hockey master shadow
superman batman trustno trustnoone abc abcd abcdef abcdefg abcdefgh abc123 goose gooseweb goosegoose
summer winter spring autumn fall january february march april may june july august september october
november december monday friday hello hellothere freedom whatever starwars pokemon computer internet
mypassword yourpassword company letmeinnow access accessgranted
""".split())
_COMMON_EXACT = frozenset({"123456789012", "1234567890ab", "qwerty123456", "password1234", "1q2w3e4r5t6y",
                           "1qaz2wsx3edc", "zaq12wsxcde3"})
_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s",
                       "7": "t", "+": "t", "8": "b", "9": "g"})


def _common_base(password: str) -> bool:
    low = password.lower()
    if low in _COMMON_EXACT or low in _COMMON_WORDS:
        return True
    # strip what people append/prepend (digits, symbols, spaces), then undo letter swaps in the middle
    core = low.strip("0123456789!@#$%^&*()_+-=[]{};:'\",.<>/?\\|`~ ")
    for cand in (core, core.translate(_LEET)):
        letters = "".join(ch for ch in cand if ch.isalpha())
        if letters and (letters in _COMMON_WORDS or letters.rstrip("s") in _COMMON_WORDS):
            return True
    return False


def password_problems(password: str, min_length: int = PASSWORD_MIN_LENGTH, username: str = "") -> list[str]:
    """Return what is wrong with `password` under the strong-password policy ([] = acceptable)."""
    pw = password or ""
    need = max(int(min_length or 0), PASSWORD_MIN_LENGTH)
    problems = []
    if len(pw) < need:
        problems.append(f"must be at least {need} characters")
    if not any(c.islower() for c in pw):
        problems.append("needs a lowercase letter")
    if not any(c.isupper() for c in pw):
        problems.append("needs an uppercase letter")
    if not any(c.isdigit() for c in pw):
        problems.append("needs a number")
    if not any(not c.isalnum() for c in pw):
        problems.append("needs a symbol")
    name = (username or "").strip().lower()
    if pw and name and len(name) >= 3 and name in pw.lower():
        problems.append("must not contain the username")
    if pw and _common_base(pw):
        problems.append("is too common or built from a common word")
    low = pw.lower()
    if any(low[i] == low[i + 1] == low[i + 2] == low[i + 3] for i in range(len(low) - 3)):
        problems.append("must not repeat a character 4 or more times in a row")
    return problems


def ip_in(ip: str, nets: list[str]) -> bool:
    """True when `ip` is inside any of the networks/addresses in `nets` (invalid entries are ignored)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    for n in nets or []:
        try:
            if addr in ipaddress.ip_network(str(n).strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


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


def totp_match(secret: str, code: str, at: float | None = None, window: int = 1,
               last_counter: int | None = None) -> int | None:
    """Return the time-step counter that `code` matches within +/-window steps, or None.

    Replay protection (RFC 6238 section 5.2): a counter <= `last_counter` (the last step this
    user successfully used) is never accepted, so each code works at most once.
    """
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != 6:
        return None
    now = time.time() if at is None else at
    base = int(now // 30)
    found: int | None = None
    for w in range(-window, window + 1):
        try:
            hit = hmac.compare_digest(totp(secret, (base + w) * 30), code)
        except (ValueError, TypeError):  # malformed secret
            return None
        if hit and found is None:  # keep looping: constant work regardless of which step matched
            found = base + w
    if found is None or (last_counter is not None and found <= last_counter):
        return None
    return found


def verify_totp(secret: str, code: str, at: float | None = None, window: int = 1,
                last_counter: int | None = None) -> bool:
    return totp_match(secret, code, at, window, last_counter) is not None


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
