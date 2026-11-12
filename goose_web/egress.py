"""Per-member egress proxy for MXC workers (spec 025 R6).

An MXC member's container has no network of its own: MXC (proxy mode, `runtimeConfig.networkProxy`) lets it reach
exactly one loopback endpoint, this member's proxy in the gateway, and sets HTTP_PROXY / HTTPS_PROXY for the agent
and everything it starts (MCP servers, npm, uv, pip, git, curl). The proxy then decides every destination:

- `sandbox.relays` targets (for example the local model proxy 127.0.0.1:8317): allowed, connected to the configured
  target (localhost, 127.0.0.1 and ::1 are the same host);
- public internet addresses: allowed when the member's network is `internet` or `internet+lan`;
- private, CGNAT and unique-local addresses: only for `internet+lan`;
- everything else is refused: other loopback ports, this machine's own addresses (the gateway, other local
  services), link-local and cloud metadata addresses, multicast/reserved/unspecified addresses, and host names that
  resolve to any refused address (no DNS rebinding: the vetted address is the one connected to).

It listens on 127.0.0.1 with an OS-assigned port and accepts only requests that carry the member's credential (HTTP
Basic in Proxy-Authorization, compared in constant time; MXC passes `http://<user>:<token>@127.0.0.1:<port>` on).
CONNECT tunnels (HTTPS and any TCP the member's network allows) and plain http:// requests (one request per
connection, `Connection: close`, so a reused connection cannot reach another host). Limits: concurrent connections
per member, idle timeout, header size and time. Every decided destination is written to the activity log as
`sandbox.egress` with host:port and the decision only - never a path, header or content.

Raw TCP that does not speak HTTP CONNECT (ssh, database clients) has no way out: accepted for MXC members (Q1).
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import logging
import secrets
import socket
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

log = logging.getLogger("goose_web.egress")

MAX_HEADER = 16 * 1024
HEADER_TIMEOUT = 30.0
CONNECT_TIMEOUT = 15.0
RESOLVE_TIMEOUT = 10.0
LOCAL_REFRESH = 60.0
METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254"),
            ipaddress.ip_address("100.100.100.200")}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
HOP_HEADERS = {b"proxy-authorization", b"proxy-connection", b"connection", b"keep-alive", b"proxy-authenticate",
               b"te", b"trailer", b"upgrade"}
NETWORKS = ("none", "internet", "internet+lan")


def classify(ip: str) -> str:
    """'loopback' | 'public' | 'lan' | 'blocked' for one address."""
    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "blocked"
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if a.is_loopback:
        return "loopback"
    if a in METADATA or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
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
    return "loopback" if h in LOOPBACK_NAMES else h


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
    __slots__ = ("allowed", "reason", "host", "port", "kind")

    def __init__(self, allowed: bool, reason: str = "", host: str = "", port: int = 0, kind: str = ""):
        self.allowed, self.reason, self.host, self.port, self.kind = allowed, reason, host, port, kind


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def _default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT)
    return list(dict.fromkeys(str(i[4][0]) for i in infos))


class EgressProxy:
    """One member's proxy. Kept across that member's worker restarts (a new credential per start: rotate())."""

    def __init__(self, username: str, *, network: str = "internet", relays: list[str] | None = None,
                 protected_ports: Callable[[], set[int]] | None = None, max_connections: int = 64,
                 idle_seconds: float = 900, resolver: Resolver | None = None,
                 audit: Callable[[str, str, dict], None] | None = None, local: Callable[[], set[str]] | None = None):
        self.username = username
        self.user = "gw-" + secrets.token_hex(4)
        self.token = secrets.token_urlsafe(24)
        self.max_connections = max(1, int(max_connections))
        self.idle = max(1.0, float(idle_seconds))
        self._resolver = resolver or _default_resolver
        self._audit = audit or _activity_audit
        self._protected = protected_ports or (lambda: set())
        self._local_fn = local or local_addresses
        self._local: set[str] = set()
        self._local_at = 0.0
        self.server: asyncio.base_events.Server | None = None
        self.port = 0
        self.active = 0
        self.counts = {"allowed": 0, "refused": 0, "unauthorized": 0}
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
        self.token = secrets.token_urlsafe(24)

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
        s, self.server = self.server, None
        if s is not None:
            s.close()
            try:
                await asyncio.wait_for(s.wait_closed(), 5)
            except (asyncio.TimeoutError, Exception):
                pass

    def describe(self) -> dict:
        return {"port": self.port, "network": self.network, "connections": self.active,
                "relays": sorted(f"{h}:{p}" for h, p in self.relays.values()), **self.counts}

    # ---------------------------------------------------------- decisions
    def _locals(self) -> set[str]:
        if time.monotonic() - self._local_at > LOCAL_REFRESH:
            try:
                self._local = set(self._local_fn())
            except Exception:
                self._local = {"127.0.0.1", "::1"}
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
        try:
            ipaddress.ip_address(h.split("%", 1)[0])
            addrs = [h]
        except ValueError:
            if _canon_host(h) == "loopback":
                addrs = ["127.0.0.1"]
            else:
                try:
                    addrs = await self._resolver(h, port)
                except (OSError, asyncio.TimeoutError) as e:
                    return Decision(False, f"cannot resolve {h} ({e.__class__.__name__})")
        if not addrs:
            return Decision(False, f"cannot resolve {h}")
        local = self._locals()
        for a in addrs:
            cls = classify(a)
            if a.split("%", 1)[0] in local or cls == "loopback":
                return Decision(False, "this machine (loopback or one of its own addresses) is reachable only "
                                       "through sandbox.relays")
            if cls == "blocked":
                return Decision(False, f"{a} is a link-local, metadata, multicast or reserved address")
            if cls == "lan" and self.network != "internet+lan":
                return Decision(False, f"{a} is a private (LAN) address; sandbox.network is {self.network}")
        return Decision(True, "", addrs[0], port, "lan" if any(classify(a) == "lan" for a in addrs) else "public")

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
        return ok_user & ok_token

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
        if method.upper() == "CONNECT":
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
        shown = f"{host}:{port}"
        d = await self.decide(host, port)
        if not d.allowed:
            self._note_refused(shown, d.reason, method=method.upper())
            await _reply(writer, reader, 403, f"Goose Web sandbox: {shown} is not allowed: {d.reason}")
            return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(d.host, d.port), CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            self._record(shown, method.upper(), "failed", "connect timeout")
            await _reply(writer, reader, 504, f"{shown} did not answer")
            return
        except OSError as e:
            self._record(shown, method.upper(), "failed", e.__class__.__name__)
            await _reply(writer, reader, 502, f"{shown} cannot be reached ({e.__class__.__name__})")
            return
        self.counts["allowed"] += 1
        self._record(shown, method.upper(), "allowed", d.kind)
        try:
            if method.upper() == "CONNECT":
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
                    out.append(b"Host: " + shown.encode("idna"))
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
        detail = {"method": method, "decision": decision}
        if reason:   # allowed: the kind of destination (relay | public | lan); refused/failed: why
            detail["kind" if decision == "allowed" else "reason"] = reason[:200]
        try:
            self._audit(self.username, target, detail)
        except Exception:
            pass

    def _note_refused(self, target: str, reason: str, method: str = "", audit: bool = True) -> None:
        self.counts["refused"] += 1
        log.info("sandbox mxc proxy: %s refused %s: %s", self.username, target, reason)
        if audit:
            self._record(target, method, "refused", reason)


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
    """The gateway's proxies, one per MXC member (worker key). Survive worker restarts; closed at shutdown or when
    the member no longer runs on MXC."""

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
