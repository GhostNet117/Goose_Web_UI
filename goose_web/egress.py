"""Per-member egress proxy for MXC workers (spec 025 R6).

An MXC member's container has no network of its own: MXC (proxy mode, `runtimeConfig.networkProxy`) lets it reach
exactly one loopback endpoint, this member's proxy in the gateway, and sets HTTP_PROXY / HTTPS_PROXY for the agent
and everything it starts (MCP servers, npm, uv, pip, git, curl). The proxy then decides every destination:

- `sandbox.relays` targets (for example the local model proxy 127.0.0.1:8317): allowed, connected to the configured
  target (localhost, 127.0.0.1 and ::1 are the same host). A relay forwards everything the relayed service exposes on
  that port (every path, every virtual host behind a local reverse proxy);
- public internet addresses: allowed when the member's network is `internet` or `internet+lan`;
- private, CGNAT and unique-local addresses: only for `internet+lan`;
- everything else is refused: other loopback ports, this machine's own addresses (the gateway, other local
  services), link-local and cloud metadata addresses, multicast/reserved/unspecified/site-local addresses, 6to4 and
  Teredo tunnel addresses, and host names that resolve to any refused address (no DNS rebinding: the vetted address
  is the one connected to). Addresses are compared as parsed, normalised `ipaddress` objects (case, zero
  compression and scope ids do not matter; IPv4-mapped, IPv4-compatible, NAT64, 6to4 and Teredo forms are unwrapped
  for the loopback / own-address check) - security review 2026-11-12, MX-1/MX-11.

Name resolution runs in a small pool of its own (never the gateway's default executor, which sign-in, MFA and file
operations use), at most RESOLVE_PER_MEMBER lookups of one member at a time (more: HTTP 503), with a per-lookup
timeout and a short negative cache; single-label names (no dot) and `.local` names are not resolved at all
(LLMNR/NetBIOS/mDNS, slow by design) unless they are a relay target (MX-2).

It listens on 127.0.0.1 with an OS-assigned port and accepts only requests that carry the member's credential (HTTP
Basic in Proxy-Authorization, compared in constant time; MXC passes `http://<user>:<token>@127.0.0.1:<port>` on). The
credential is rotated at every worker start and revoked when the worker stops (MX-10).
CONNECT tunnels (HTTPS and any TCP the member's network allows) and plain http:// requests (one request per
connection, `Connection: close`, so a reused connection cannot reach another host). Limits: concurrent connections
per member, idle timeout, header size and time; host names must be valid (labels <= 63, total <= 253 characters,
else 400). Every decided destination is written to the activity log as `sandbox.egress` with host:port and the
decision only - never a path, header or content; per member the first AUDIT_VERBATIM_PER_MINUTE decisions of a
minute are written one by one, the rest as one summary line with counts per destination (MX-4). Everything a member
controls is passed through activity.clean_text before it reaches a log (MX-5).

Raw TCP that does not speak HTTP CONNECT (ssh, database clients) has no way out: accepted for MXC members (Q1).
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hmac
import ipaddress
import logging
import re
import secrets
import socket
import threading
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

from .activity import clean_text

log = logging.getLogger("goose_web.egress")

MAX_HEADER = 16 * 1024
HEADER_TIMEOUT = 30.0
CONNECT_TIMEOUT = 15.0
RESOLVE_TIMEOUT = 5.0              # per lookup (the lookup thread itself ends with the OS resolver's own timeout)
RESOLVER_THREADS = 4               # the proxies' own resolver pool (all members together)
RESOLVE_PER_MEMBER = 2             # lookups of one member in flight at once; more -> 503
NEGATIVE_TTL = 30.0                # a name that failed or timed out is not looked up again for this long
NEGATIVE_MAX = 4096
LOCAL_REFRESH = 60.0
AUDIT_WINDOW = 60.0
AUDIT_VERBATIM_PER_MINUTE = 30     # per member; the rest of the minute goes into one summary line
AUDIT_SUMMARY_TARGETS = 50
METADATA = {ipaddress.ip_address(a) for a in (
    "169.254.169.254",             # AWS / GCP / Azure / OpenStack instance metadata
    "169.254.170.2",               # AWS ECS task metadata
    "fd00:ec2::254",               # AWS IMDS over IPv6
    "100.100.100.200",             # Alibaba Cloud metadata
    "168.63.129.16",               # Azure WireServer / host DNS
    "192.0.0.192",                 # Oracle Cloud metadata
)}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
NAT64 = ipaddress.ip_network("64:ff9b::/96")
IPV4_COMPAT = ipaddress.ip_network("::/96")
REFUSED_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",                   # "this network"
    "fec0::/10",                   # IPv6 site-local (deprecated, private in practice)
    "2002::/16",                   # 6to4 (embeds an IPv4 address; tunnel, never a member's destination)
    "2001::/32",                   # Teredo (embeds an IPv4 address)
    "64:ff9b:1::/48",              # local-use NAT64
    "::/96",                       # IPv4-compatible (deprecated)
    "100::/64",                    # discard-only
)]
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
HOP_HEADERS = {b"proxy-authorization", b"proxy-connection", b"connection", b"keep-alive", b"proxy-authenticate",
               b"te", b"trailer", b"upgrade"}
NETWORKS = ("none", "internet", "internet+lan")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_METHOD = re.compile(r"[A-Za-z]{1,20}")
_VERSION = re.compile(r"HTTP/1\.[01]")
_SCOPE = re.compile(r"[A-Za-z0-9_.-]{1,32}")

IP = ipaddress.IPv4Address | ipaddress.IPv6Address


# ------------------------------------------------------------------ addresses
def parse_ip(text: Any) -> IP | None:
    """The address in `text` (IPv4 or IPv6 literal, brackets and scope id dropped, IPv4-mapped unwrapped), or None."""
    if isinstance(text, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        a = text
    else:
        s = str(text or "").strip()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        try:
            a = ipaddress.ip_address(s.split("%", 1)[0])
        except ValueError:
            return None
    if a.version == 6:
        if a.scope_id:
            a = ipaddress.IPv6Address(int(a))
        if a.ipv4_mapped is not None:
            a = a.ipv4_mapped
    return a


def _in(a: IP, nets) -> bool:
    return any(a.version == n.version and a in n for n in nets)


def variants(a: IP) -> list[IP]:
    """`a` and every IPv4 address embedded in it (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo)."""
    out: list[IP] = [a]
    if a.version == 6:
        if a.ipv4_mapped is not None:
            out.append(a.ipv4_mapped)
        if a.sixtofour is not None:
            out.append(a.sixtofour)
        if a.teredo is not None:
            out.extend(a.teredo)
        if (a in NAT64) or (a in IPV4_COMPAT and int(a) > 1):
            out.append(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
    return out


def classify(ip: Any) -> str:
    """'loopback' | 'public' | 'lan' | 'blocked' for one address."""
    a = parse_ip(ip)
    if a is None:
        return "blocked"
    if a.version == 6 and a in NAT64:
        return classify(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
    if a.is_loopback:
        return "loopback"
    if a in METADATA or _in(a, REFUSED_NETS) or a.is_unspecified or a.is_multicast or a.is_link_local or \
            a.is_reserved or (a.version == 6 and a.is_site_local):
        return "blocked"
    if a.is_global:
        return "public"
    if a.is_private or (a.version == 4 and a in CGNAT):
        return "lan"
    return "blocked"


def local_addresses() -> set[str]:
    """This machine's own addresses (a container must not reach the host's services through its LAN address)."""
    out = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            out.add(str(info[4][0]).split("%", 1)[0])
    except OSError:
        pass
    return out


def _canon_host(h: str) -> str:
    h = h.strip().strip("[]").lower()
    a = parse_ip(h)
    if a is not None:
        return "loopback" if a.is_loopback else str(a)
    h = h.rstrip(".")
    return "loopback" if h in LOOPBACK_NAMES else h


def host_problem(host: str) -> str:
    """'' when `host` is an IP literal or a valid DNS host name (labels of 1-63 letters, digits, '-' or '_', at most
    253 characters; IDNA names allowed), else why not (MX-5/MX-12: such a request gets 400, never a lookup)."""
    h = str(host or "").strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if parse_ip(h) is not None:
        addr, _, scope = h.partition("%")
        return "" if not scope or _SCOPE.fullmatch(scope) else "bad scope id in the address"
    name = h[:-1] if h.endswith(".") else h
    if not name or len(name) > 253:
        return "the host name is empty or longer than 253 characters"
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return "not a valid host name"
    for label in name.lower().split("."):
        if not 1 <= len(label) <= 63 or not _LABEL.fullmatch(label):
            return "not a valid host name"
    return "" if len(name) <= 253 else "the host name is longer than 253 characters"


def parse_hostport(t: str, default_port: int | None = None) -> tuple[str, int]:
    t = t.strip()
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port = t.rpartition(":")
        if not sep or ":" in host:      # no port, or a bare IPv6 address
            host, port = t, ""
    if not port and default_port is not None:
        port = str(default_port)
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"not host:port: {t!r}")
    return host, int(port)


class Decision:
    __slots__ = ("allowed", "reason", "host", "port", "kind", "status")

    def __init__(self, allowed: bool, reason: str = "", host: str = "", port: int = 0, kind: str = "",
                 status: int = 403):
        self.allowed, self.reason, self.host, self.port, self.kind = allowed, reason, host, port, kind
        self.status = status


Resolver = Callable[[str, int], Awaitable[list[str]]]


# ------------------------------------------------------------------ name resolution (MX-2)
class ResolverBusy(Exception):
    """This member already has RESOLVE_PER_MEMBER lookups in flight."""


_POOL: concurrent.futures.ThreadPoolExecutor | None = None
_POOL_LOCK = threading.Lock()


def resolver_pool() -> concurrent.futures.ThreadPoolExecutor:
    """The proxies' own resolver threads: a slow lookup never takes a thread of the gateway's default executor."""
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = concurrent.futures.ThreadPoolExecutor(RESOLVER_THREADS, thread_name_prefix="gw-egress-dns")
        return _POOL


def system_lookup(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(i[4][0]) for i in infos))


class _AuditLimiter:
    """MX-4: per member, the first AUDIT_VERBATIM_PER_MINUTE egress decisions of a minute are written one by one;
    the rest is counted per destination + decision and written as one summary line when the minute ends."""

    def __init__(self, emit: Callable[[int, list[dict]], None]):
        self.emit = emit
        self.start = time.monotonic()
        self.count = 0
        self.suppressed: dict[tuple[str, str], int] = {}
        self.total = 0
        self.timer: asyncio.TimerHandle | None = None

    def allow(self, target: str, decision: str) -> bool:
        now = time.monotonic()
        if now - self.start >= AUDIT_WINDOW:
            self.flush()
            self.start, self.count = now, 0
        self.count += 1
        if self.count <= AUDIT_VERBATIM_PER_MINUTE:
            return True
        key = (target, decision)
        if key not in self.suppressed and len(self.suppressed) >= AUDIT_SUMMARY_TARGETS:
            key = ("(other destinations)", decision)
        self.suppressed[key] = self.suppressed.get(key, 0) + 1
        self.total += 1
        if self.timer is None:
            try:
                self.timer = asyncio.get_running_loop().call_later(
                    max(0.0, AUDIT_WINDOW - (now - self.start)), self._timer)
            except RuntimeError:
                pass
        return False

    def _timer(self) -> None:
        self.timer = None
        self.flush()

    def flush(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        if not self.suppressed:
            return
        items = sorted(self.suppressed.items(), key=lambda kv: -kv[1])
        self.suppressed = {}
        self.emit(sum(n for _, n in items), [{"target": t, "decision": d, "count": n} for (t, d), n in items])


class EgressProxy:
    """One member's proxy. Kept across that member's worker restarts (a new credential per start: rotate(); none
    valid while the worker is stopped: revoke())."""

    def __init__(self, username: str, *, network: str = "internet", relays: list[str] | None = None,
                 protected_ports: Callable[[], set[int]] | None = None, max_connections: int = 64,
                 idle_seconds: float = 900, resolver: Resolver | None = None,
                 audit: Callable[[str, str, dict], None] | None = None, local: Callable[[], set[str]] | None = None,
                 lookup: Callable[[str], list[str]] | None = None):
        self.username = username
        self.user = "gw-" + secrets.token_hex(4)
        self.token = secrets.token_urlsafe(24)
        self.revoked = False
        self.max_connections = max(1, int(max_connections))
        self.idle = max(1.0, float(idle_seconds))
        self._resolver = resolver or self._pooled_resolve
        self._lookup = lookup or system_lookup
        self._audit = audit or _activity_audit
        self._protected = protected_ports or (lambda: set())
        self._local_fn = local or local_addresses
        self._local: set[IP] = set()
        self._local_at = 0.0
        self._dns_lock = threading.RLock()
        self._dns_busy = 0
        self._inflight: dict[str, concurrent.futures.Future] = {}
        self._negative: dict[str, float] = {}
        self._limiter = _AuditLimiter(self._summary)
        self.server: asyncio.base_events.Server | None = None
        self.port = 0
        self.active = 0
        self.counts = {"allowed": 0, "refused": 0, "unauthorized": 0, "auditSummarised": 0}
        self.network = "none"
        self.relays: dict[tuple[str, int], tuple[str, int]] = {}
        self.update(network, relays or [])

    # ---------------------------------------------------------- configuration
    def update(self, network: str, relays: list[str]) -> None:
        self.network = network if network in NETWORKS else "none"
        out: dict[tuple[str, int], tuple[str, int]] = {}
        for t in relays:
            try:
                host, port = parse_hostport(str(t))
            except ValueError:
                log.warning("sandbox mxc proxy: relay target %r is not host:port; ignored", t)
                continue
            if _canon_host(host) == "loopback" and port in self._protected():
                log.warning("sandbox mxc proxy: relay target %s:%s is the gateway or a proxy; ignored", host, port)
                continue
            out[(_canon_host(host), port)] = (host, port)
        self.relays = out

    def rotate(self) -> None:
        """A new credential (every worker start)."""
        self.token = secrets.token_urlsafe(24)
        self.revoked = False

    def revoke(self) -> None:
        """The worker stopped: the credential it was given is no longer accepted (a fresh one nobody has)."""
        self.token = secrets.token_urlsafe(24)
        self.revoked = True

    def url(self) -> str:
        return f"http://{self.user}:{self.token}@127.0.0.1:{self.port}"

    async def start(self) -> "EgressProxy":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        sock.setblocking(False)
        self.server = await asyncio.start_server(self._client, sock=sock, limit=MAX_HEADER * 2)
        self.port = sock.getsockname()[1]
        log.info("sandbox mxc proxy: %s listening on 127.0.0.1:%s (network %s, relays %s)", self.username,
                 self.port, self.network, sorted(f"{h}:{p}" for h, p in self.relays.values()) or "-")
        return self

    async def close(self) -> None:
        self._limiter.flush()
        s, self.server = self.server, None
        if s is not None:
            s.close()
            try:
                await asyncio.wait_for(s.wait_closed(), 5)
            except (asyncio.TimeoutError, Exception):
                pass

    def describe(self) -> dict:
        return {"port": self.port, "network": self.network, "connections": self.active, "revoked": self.revoked,
                "relays": sorted(f"{h}:{p}" for h, p in self.relays.values()), **self.counts}

    # ---------------------------------------------------------- name resolution
    async def _pooled_resolve(self, host: str, port: int) -> list[str]:
        """MX-2: the lookup runs in the resolver pool; one member has at most RESOLVE_PER_MEMBER in flight (a slot is
        held until the lookup thread is done, not just until our timeout); concurrent lookups of one name share one
        thread; a failed or timed-out name is answered from the negative cache for NEGATIVE_TTL."""
        key = host.lower().rstrip(".")
        with self._dns_lock:
            until = self._negative.get(key)
            if until is not None:
                if until > time.monotonic():
                    raise OSError(f"{key} did not resolve a moment ago")
                del self._negative[key]
            fut = self._inflight.get(key)
            if fut is None:
                if self._dns_busy >= RESOLVE_PER_MEMBER:
                    raise ResolverBusy()
                self._dns_busy += 1
                fut = resolver_pool().submit(self._lookup, key)
                self._inflight[key] = fut
                fut.add_done_callback(lambda f, k=key: self._lookup_done(k, f))
        try:
            return await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(fut)), RESOLVE_TIMEOUT)
        except asyncio.TimeoutError:
            self._remember_failure(key)
            raise

    def _lookup_done(self, key: str, f: concurrent.futures.Future) -> None:
        with self._dns_lock:
            self._dns_busy = max(0, self._dns_busy - 1)
            if self._inflight.get(key) is f:
                del self._inflight[key]
            if f.cancelled() or f.exception() is not None:
                self._remember_failure(key)

    def _remember_failure(self, key: str) -> None:
        with self._dns_lock:
            if len(self._negative) >= NEGATIVE_MAX:
                self._negative.clear()
            self._negative[key] = time.monotonic() + NEGATIVE_TTL

    # ---------------------------------------------------------- decisions
    def _locals(self) -> set[IP]:
        if time.monotonic() - self._local_at > LOCAL_REFRESH:
            try:
                raw = set(self._local_fn())
            except Exception:
                raw = {"127.0.0.1", "::1"}
            self._local = {a for a in (parse_ip(x) for x in raw | {"127.0.0.1", "::1"}) if a is not None}
            self._local_at = time.monotonic()
        return self._local

    async def decide(self, host: str, port: int) -> Decision:
        key = (_canon_host(host), port)
        if key in self.relays:
            th, tp = self.relays[key]
            return Decision(True, "relay", th, tp, "relay")
        if self.network == "none":
            return Decision(False, "this member's sandbox has no network (sandbox.network: none); only the relayed "
                                   "local services are reachable")
        h = host.strip().strip("[]")
        lit = parse_ip(h)
        if lit is not None:
            addrs: list[IP] = [lit]
        else:
            name = h.rstrip(".").lower()
            if _canon_host(name) == "loopback":
                addrs = [ipaddress.IPv4Address("127.0.0.1")]
            elif "." not in name:
                return Decision(False, "single-label host names (no dot) are not resolved for sandboxed members; use "
                                       "the full name, or ask the administrator for a sandbox.relays entry")
            elif name.endswith(".local"):
                return Decision(False, ".local (mDNS) names are not resolved for sandboxed members")
            else:
                try:
                    raw = await self._resolver(name, port)
                except ResolverBusy:
                    return Decision(False, "too many name lookups of this member at once; try again", status=503)
                except (OSError, asyncio.TimeoutError, UnicodeError, ValueError) as e:
                    return Decision(False, f"cannot resolve {name} ({e.__class__.__name__})")
                addrs = [a for a in (parse_ip(x) for x in raw or []) if a is not None]
                if len(addrs) != len(raw or []):
                    return Decision(False, f"{name} resolved to an address that is not an IP address")
        if not addrs:
            return Decision(False, f"cannot resolve {h}")
        local = self._locals()
        kinds = []
        for a in addrs:
            if any(v in local or classify(v) == "loopback" for v in variants(a)):
                return Decision(False, "this machine (loopback or one of its own addresses) is reachable only "
                                       "through sandbox.relays")
            cls = classify(a)
            if cls == "blocked":
                return Decision(False, f"{a} is a link-local, metadata, multicast, reserved or tunnel address")
            if cls == "lan" and self.network != "internet+lan":
                return Decision(False, f"{a} is a private (LAN) address; sandbox.network is {self.network}")
            kinds.append(cls)
        return Decision(True, "", str(addrs[0]), port, "lan" if "lan" in kinds else "public")

    async def _relay_address(self, host: str) -> str:
        """The address a relay target is connected to: loopback names -> 127.0.0.1, IP literals as they are, other
        names (admin configuration) through the resolver pool - never the gateway's default executor."""
        if _canon_host(host) == "loopback" and parse_ip(host) is None:
            return "127.0.0.1"
        a = parse_ip(host)
        if a is not None:
            return str(a)
        loop = asyncio.get_running_loop()
        addrs = await asyncio.wait_for(loop.run_in_executor(resolver_pool(), self._lookup, host), RESOLVE_TIMEOUT)
        if not addrs:
            raise OSError(f"cannot resolve {host}")
        return addrs[0]

    # ---------------------------------------------------------- connection handling
    def _authorized(self, headers: dict[bytes, bytes]) -> bool:
        raw = headers.get(b"proxy-authorization", b"")
        user, token = b"", b""
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == b"basic":
            try:
                user, _, token = base64.b64decode(parts[1].strip(), validate=True).partition(b":")
            except (ValueError, TypeError):
                user, token = b"", b""
        ok_user = hmac.compare_digest(user, self.user.encode())
        ok_token = hmac.compare_digest(token, self.token.encode())
        return ok_user & ok_token & (not self.revoked)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.active >= self.max_connections:
            try:   # read the request first: answering unread input would reset the connection (see _reply)
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
                pass
            await _reply(writer, reader, 503, "Goose Web sandbox proxy: too many connections for this member")
            self._note_refused("-", "too many connections", audit=False)
            return
        self.active += 1
        try:
            await self._serve(reader, writer)
        except Exception as e:   # never let one connection hurt the gateway
            log.debug("sandbox mxc proxy %s: connection error %r", self.username, e)
        finally:
            self.active -= 1
            _close(writer)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT)
        except asyncio.LimitOverrunError:
            await _reply(writer, reader, 431, "request header too large")
            return
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            return
        if len(head) > MAX_HEADER:
            await _reply(writer, reader, 431, "request header too large")
            return
        lines = head[:-4].split(b"\r\n")
        try:
            method, target, version = lines[0].decode("latin-1").split(" ", 2)
        except ValueError:
            await _reply(writer, reader, 400, "bad request line")
            return
        headers: dict[bytes, bytes] = {}
        for ln in lines[1:]:
            k, sep, v = ln.partition(b":")
            if sep:
                headers[k.strip().lower()] = v.strip()
        if not self._authorized(headers):
            self.counts["unauthorized"] += 1
            await _reply(writer, reader, 407, "proxy authentication required", extra=b'Proxy-Authenticate: Basic realm="goose-web"\r\n')
            return
        # MX-5: nothing that could break a log line or the forwarded request line gets any further
        if not _METHOD.fullmatch(method) or not _VERSION.fullmatch(version) or \
                any(ord(c) < 0x21 or ord(c) == 0x7F for c in target):
            self._note_refused(clean_text(target, 200), "bad request line", method=clean_text(method, 20))
            await _reply(writer, reader, 400, "bad request line")
            return
        method = method.upper()
        if method == "CONNECT":
            try:
                host, port = parse_hostport(target)
            except ValueError:
                await _reply(writer, reader, 400, "CONNECT needs host:port")
                return
        else:
            u = urlsplit(target)
            if u.scheme.lower() != "http" or not u.hostname:
                await _reply(writer, reader, 400, "only http:// URLs and CONNECT are proxied")
                return
            try:
                host, port = u.hostname, u.port or 80
            except ValueError:
                await _reply(writer, reader, 400, "bad port")
                return
        bad = host_problem(host)
        if bad:      # MX-12: over-long or malformed names: an answer, never a lookup
            self._note_refused(clean_text(f"{host}:{port}", 200), bad, method=method)
            await _reply(writer, reader, 400, f"Goose Web sandbox: bad host name: {bad}")
            return
        shown = clean_text(f"{host}:{port}", 300)
        d = await self.decide(host, port)
        if not d.allowed:
            self._note_refused(shown, d.reason, method=method)
            await _reply(writer, reader, d.status, f"Goose Web sandbox: {shown} is not allowed: {d.reason}")
            return
        try:
            target_ip = await self._relay_address(d.host) if d.kind == "relay" else d.host
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(target_ip, d.port), CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            self._record(shown, method, "failed", "connect timeout")
            await _reply(writer, reader, 504, f"{shown} did not answer")
            return
        except OSError as e:
            self._record(shown, method, "failed", e.__class__.__name__)
            await _reply(writer, reader, 502, f"{shown} cannot be reached ({e.__class__.__name__})")
            return
        self.counts["allowed"] += 1
        self._record(shown, method, "allowed", d.kind)
        try:
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            else:
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                out = [f"{method} {path} {version}".encode("latin-1")]
                for ln in lines[1:]:
                    k = ln.partition(b":")[0].strip().lower()
                    if k and k not in HOP_HEADERS:
                        out.append(ln)
                if b"host" not in headers:
                    out.append(b"Host: " + f"{host}:{port}".encode("idna"))
                out.append(b"Connection: close")
                up_w.write(b"\r\n".join(out) + b"\r\n\r\n")
                await up_w.drain()
            await self._pipe(reader, writer, up_r, up_w)
        finally:
            _close(up_w)

    async def _pipe(self, cr, cw, ur, uw) -> None:
        last = [time.monotonic()]

        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            while True:
                try:
                    data = await asyncio.wait_for(src.read(65536), min(30.0, self.idle))
                except asyncio.TimeoutError:
                    if time.monotonic() - last[0] > self.idle:
                        return
                    continue
                except (ConnectionError, OSError):
                    return
                if not data:
                    try:
                        if dst.can_write_eof():
                            dst.write_eof()
                    except (OSError, RuntimeError):
                        pass
                    return
                last[0] = time.monotonic()
                try:
                    dst.write(data)
                    await dst.drain()
                except (ConnectionError, OSError, RuntimeError):
                    return
        a = asyncio.create_task(copy(cr, uw))
        b = asyncio.create_task(copy(ur, cw))
        done, pending = await asyncio.wait({a, b}, return_when=asyncio.FIRST_COMPLETED)
        # one direction ended: give the other until the idle limit to finish (a response after the request's EOF)
        if pending:
            await asyncio.wait(pending, timeout=self.idle)
        for t in pending:
            t.cancel()

    # ---------------------------------------------------------- audit
    def _record(self, target: str, method: str, decision: str, reason: str = "") -> None:
        target = clean_text(target, 300)
        if not self._limiter.allow(target, decision):
            self.counts["auditSummarised"] += 1
            return
        self._write_audit(target, method, decision, reason)

    def _write_audit(self, target: str, method: str, decision: str, reason: str = "") -> None:
        detail = {"method": clean_text(method, 20), "decision": decision}
        if reason:   # allowed: the kind of destination (relay | public | lan); refused/failed: why
            detail["kind" if decision == "allowed" else "reason"] = clean_text(reason, 200)
        try:
            self._audit(self.username, target, detail)
        except Exception:
            pass

    def _summary(self, total: int, items: list[dict]) -> None:
        top = ", ".join(f"{i['target']} {i['decision']} x{i['count']}" for i in items[:5])
        log.info("sandbox mxc proxy: %s: %d more egress decisions in the last minute, summarised (%s%s)",
                 self.username, total, top, ", ..." if len(items) > 5 else "")
        try:
            self._audit(self.username, "(summary)", {"method": "-", "decision": "summary", "window": int(AUDIT_WINDOW),
                                                     "count": total, "destinations": items})
        except Exception:
            pass

    def _note_refused(self, target: str, reason: str, method: str = "", audit: bool = True) -> None:
        self.counts["refused"] += 1
        target = clean_text(target, 300)
        if not self._limiter.allow(target, "refused"):
            self.counts["auditSummarised"] += 1
            return
        log.info("sandbox mxc proxy: %s refused %s: %s", self.username, target, clean_text(reason, 200))
        if audit:
            self._write_audit(target, method, "refused", reason)


def _activity_audit(username: str, target: str, detail: dict) -> None:
    from . import activity
    activity.record("sandbox.egress", username=username, target=target, detail=detail,
                    ok=detail.get("decision") == "allowed")


async def _reply(writer: asyncio.StreamWriter, reader: asyncio.StreamReader | None, status: int, text: str,
                 extra: bytes = b"") -> None:
    """Answer and close. With `reader`: a lingering close (send, half-close, discard what the client still sends for
    up to a second): closing a socket with unread input makes Windows reset the connection, and the client would
    lose the answer."""
    reasons = {400: "Bad Request", 403: "Forbidden", 407: "Proxy Authentication Required",
               431: "Request Header Fields Too Large", 502: "Bad Gateway", 503: "Service Unavailable",
               504: "Gateway Timeout"}
    body = (text + "\n").encode("utf-8", "replace")
    try:
        writer.write(f"HTTP/1.1 {status} {reasons.get(status, 'Error')}\r\n".encode() + extra +
                     b"Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\n" +
                     f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        await asyncio.wait_for(writer.drain(), 5)
        if reader is not None:
            if writer.can_write_eof():
                writer.write_eof()
            end = time.monotonic() + 1.0
            got = 0
            while got < 256 * 1024 and time.monotonic() < end:
                chunk = await asyncio.wait_for(reader.read(65536), max(0.05, end - time.monotonic()))
                if not chunk:
                    break
                got += len(chunk)
    except (ConnectionError, OSError, asyncio.TimeoutError, RuntimeError, ValueError):
        pass
    _close(writer)


def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except (OSError, RuntimeError):
        pass


class ProxyRegistry:
    """The gateway's proxies, one per MXC member (worker key). Survive worker restarts; closed at shutdown, when the
    member no longer runs on MXC, and when the user is deleted or no longer sandboxed."""

    def __init__(self, settings: Any, audit: Callable[[str, str, dict], None] | None = None):
        self.s = settings
        self.audit = audit
        self.proxies: dict[str, EgressProxy] = {}
        self._lock = asyncio.Lock()

    def protected_ports(self) -> set[int]:
        out = {p.port for p in self.proxies.values() if p.port}
        try:
            out.add(int(self.s.get("server", "port")))
        except (TypeError, ValueError):
            pass
        return out

    async def ensure(self, key: str, username: str, network: str, relays: list[str]) -> EgressProxy:
        async with self._lock:
            p = self.proxies.get(key)
            if p is None or p.server is None:
                p = EgressProxy(username, network=network, relays=relays, protected_ports=self.protected_ports,
                                max_connections=int(self.s.get("sandbox", "proxy_max_connections") or 64),
                                idle_seconds=float(self.s.get("sandbox", "proxy_idle_seconds") or 900),
                                audit=self.audit)
                await p.start()
                self.proxies[key] = p
            else:
                p.update(network, relays)
            p.rotate()
            return p

    def revoke(self, key: str) -> None:
        """MX-10: the member's worker stopped - its credential stops working now (a new one at the next start)."""
        p = self.proxies.get(key)
        if p is not None:
            p.revoke()

    async def drop(self, key: str) -> None:
        async with self._lock:
            p = self.proxies.pop(key, None)
        if p is not None:
            await p.close()
            log.info("sandbox mxc proxy: %s closed", p.username)

    async def close_all(self) -> None:
        for k in list(self.proxies):
            await self.drop(k)

    def describe(self) -> dict:
        return {k: p.describe() for k, p in self.proxies.items()}
