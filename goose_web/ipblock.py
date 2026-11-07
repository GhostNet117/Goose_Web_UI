"""Block client addresses after repeated failed sign-ins (spec 007).

Every failed password sign-in counts against the client address. When `auth.ip_block_threshold` failures in a
row (no successful sign-in from that address in between) fall inside `auth.ip_block_window_days`, the address is
blocked for `auth.ip_block_days` (0 = until an administrator unblocks it). The state lives in the `ip_blocks`
table, so it survives restarts and the `goose-web ip` console commands see and change the same data.

IPv4 addresses are blocked one by one. IPv6 addresses are grouped by their /64 network, because one host normally
owns a whole /64 and can change addresses inside it at will. Trusted proxies and `auth.ip_block_exempt` networks
are never counted or blocked.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time

from . import security
from .config import Settings
from .db import Database

log = logging.getLogger("goose_web.auth")

BLOCKED_MESSAGE = ("Sign-in from your network address is blocked after too many failed attempts. "
                   "Ask an administrator to unblock it.")
_REFRESH_SECONDS = 15.0


def address_key(ip: str) -> str:
    """The key an address is counted and blocked under ('' when it is not a usable IP address)."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


class IPBlocker:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.s = settings
        self._lock = threading.Lock()
        self._blocked: dict[str, float] = {}   # key -> blocked_until (0 = no expiry)
        self._loaded_at = float("-inf")

    # ------------------------------------------------------------ settings
    def _num(self, key: str, default: float) -> float:
        v = self.s.get("auth", key)
        try:
            return float(default if v is None else v)
        except (TypeError, ValueError):
            return float(default)

    @property
    def threshold(self) -> int:
        return max(0, int(self._num("ip_block_threshold", 10)))

    @property
    def window_seconds(self) -> float:
        return max(1.0, self._num("ip_block_window_days", 30)) * 86400

    @property
    def block_seconds(self) -> float:
        return max(0.0, self._num("ip_block_days", 30)) * 86400

    def exempt(self, ip: str) -> bool:
        nets = list(self.s.get("server", "trusted_proxies") or []) + list(self.s.get("auth", "ip_block_exempt") or [])
        return security.ip_in(ip, nets)

    def describe(self) -> dict:
        return {"threshold": self.threshold, "windowDays": self.window_seconds / 86400,
                "blockDays": self.block_seconds / 86400,
                "exempt": list(self.s.get("auth", "ip_block_exempt") or [])}

    # ------------------------------------------------------------ checks
    def _refresh(self, force: bool = False) -> None:
        now = time.time()
        if not force and time.monotonic() - self._loaded_at < _REFRESH_SECONDS:
            return
        # expired blocks end here: the address starts again from zero
        self.db.execute("DELETE FROM ip_blocks WHERE blocked_at > 0 AND blocked_until > 0 AND blocked_until <= ?",
                        (now,))
        rows = self.db.query("SELECT ip, blocked_until FROM ip_blocks WHERE blocked_at > 0")
        self._blocked = {r["ip"]: float(r["blocked_until"] or 0) for r in rows}
        self._loaded_at = time.monotonic()

    def is_blocked(self, ip: str) -> bool:
        key = address_key(ip)
        if not key or self.threshold <= 0:
            return False
        with self._lock:
            self._refresh()
            until = self._blocked.get(key)
        if until is None:
            return False
        if until and until <= time.time():
            return False
        return not self.exempt(ip)

    # ------------------------------------------------------------ updates
    def record_failure(self, ip: str, username: str = "") -> bool:
        """Count one failed sign-in from `ip`; return True when the address is (now) blocked."""
        key = address_key(ip)
        limit = self.threshold
        if not key or limit <= 0 or self.exempt(ip):
            return False
        now = time.time()
        with self._lock:
            row = self.db.one("SELECT * FROM ip_blocks WHERE ip=?", (key,))
            if row and row["blocked_at"] and (not row["blocked_until"] or row["blocked_until"] > now):
                return True
            # after an expired block the count starts again from zero
            previous = [] if (row and row["blocked_at"]) else ((row or {}).get("failures") or [])
            fails = [float(t) for t in previous if isinstance(t, (int, float)) and now - float(t) <= self.window_seconds]
            fails = (fails + [now])[-limit:]
            blocked = len(fails) >= limit
            until = (now + self.block_seconds if self.block_seconds else 0.0) if blocked else 0.0
            self.db.execute(
                "INSERT INTO ip_blocks(ip, failures, last_username, blocked_at, blocked_until, updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures, "
                "last_username=excluded.last_username, blocked_at=excluded.blocked_at, "
                "blocked_until=excluded.blocked_until, updated_at=excluded.updated_at",
                (key, json.dumps(fails), (username or "")[:128], now if blocked else 0.0, until, now))
            if blocked:
                self._blocked[key] = until
        if blocked:
            log.warning("blocked %s after %d failed sign-ins (last user name tried: %r)", key, len(fails), username)
            self.db.audit("auth.ip.blocked", ip=key, target=(username or "")[:128], ok=False,
                          detail={"failures": len(fails), "windowDays": self.window_seconds / 86400,
                                  "until": until or None})
        return blocked

    def record_success(self, ip: str) -> None:
        """A successful sign-in ends the run of failures from this address."""
        key = address_key(ip)
        if key:
            self.db.execute("DELETE FROM ip_blocks WHERE ip=? AND blocked_at = 0", (key,))

    def unblock(self, ip: str) -> bool:
        key = address_key(ip) or (ip or "").strip()
        with self._lock:
            n = self.db.execute_count("DELETE FROM ip_blocks WHERE ip=?", (key,))
            self._blocked.pop(key, None)
        return n > 0

    def unblock_all(self) -> int:
        with self._lock:
            n = self.db.execute_count("DELETE FROM ip_blocks")
            self._blocked.clear()
        return n

    def list(self) -> list[dict]:
        """Blocked addresses and addresses with failures inside the window, blocked first, newest first."""
        now = time.time()
        with self._lock:
            self._refresh(force=True)
            self.db.execute("DELETE FROM ip_blocks WHERE blocked_at = 0 AND updated_at < ?",
                            (now - self.window_seconds,))
            rows = self.db.query("SELECT * FROM ip_blocks")
        out = []
        for r in rows:
            fails = [float(t) for t in (r.get("failures") or []) if isinstance(t, (int, float))]
            recent = [t for t in fails if now - t <= self.window_seconds]
            blocked = bool(r["blocked_at"])
            if not blocked and not recent:
                continue
            out.append({"ip": r["ip"], "blocked": blocked, "failures": len(fails if blocked else recent),
                        "lastFailureAt": max(fails) if fails else None, "lastUsername": r["last_username"],
                        "blockedAt": r["blocked_at"] or None, "blockedUntil": r["blocked_until"] or None})
        out.sort(key=lambda x: (not x["blocked"], -(x["lastFailureAt"] or 0)))
        return out