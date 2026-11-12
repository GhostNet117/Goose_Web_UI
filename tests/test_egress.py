"""Spec 025 R6: the per-member egress proxy of MXC workers (egress.py)."""
import asyncio
import base64

import pytest

from goose_web import egress as eg


def test_classify_addresses():
    assert eg.classify("127.0.0.1") == "loopback" and eg.classify("::1") == "loopback"
    assert eg.classify("::ffff:127.0.0.1") == "loopback"                       # IPv4-mapped is unwrapped
    assert eg.classify("140.82.112.3") == "public" and eg.classify("2606:4700::1111") == "public"
    for lan in ("10.1.2.3", "192.168.1.10", "172.16.0.5", "100.64.1.1", "fd12::1"):
        assert eg.classify(lan) == "lan", lan
    for bad in ("169.254.169.254", "169.254.1.1", "fe80::1", "0.0.0.0", "224.0.0.1", "240.0.0.1",
                "fd00:ec2::254", "not-an-ip"):
        assert eg.classify(bad) == "blocked", bad


def test_parse_hostport():
    assert eg.parse_hostport("example.org:443") == ("example.org", 443)
    assert eg.parse_hostport("[::1]:8317") == ("::1", 8317)
    assert eg.parse_hostport("example.org", 80) == ("example.org", 80)
    for bad in ("example.org", "x:0", "x:70000", ":80", "[::1]"):
        with pytest.raises(ValueError):
            eg.parse_hostport(bad)


def _proxy(network="internet", relays=(), addrs=None, protected=(), **kw):
    table = addrs or {}

    async def resolver(host, port):
        if host not in table:
            raise OSError("no such host")
        return table[host]
    return eg.EgressProxy("alice", network=network, relays=list(relays), resolver=resolver,
                          protected_ports=lambda: set(protected), local=lambda: {"127.0.0.1", "::1", "10.0.0.50"},
                          audit=kw.pop("audit", lambda *a: None), **kw)


async def test_decision_matrix():
    names = {"api.example.org": ["140.82.112.3"], "nas.lan": ["192.168.1.20"], "rebind.example": ["127.0.0.1"],
             "mixed.example": ["140.82.112.3", "10.0.0.50"], "meta.example": ["169.254.169.254"],
             "self.example": ["10.0.0.50"]}
    p = _proxy("internet", ["127.0.0.1:8317"], names)

    async def ok(host, port):
        return (await p.decide(host, port)).allowed
    # relays: localhost, 127.0.0.1 and ::1 are one host; only the listed port
    assert await ok("127.0.0.1", 8317) and await ok("localhost", 8317) and await ok("::1", 8317)
    d = await p.decide("localhost", 8317)
    assert (d.host, d.port, d.kind) == ("127.0.0.1", 8317, "relay")     # connected to the configured target
    assert not await ok("127.0.0.1", 9222) and not await ok("localhost", 8318)
    assert await ok("api.example.org", 443) and await ok("140.82.112.3", 22)
    assert not await ok("nas.lan", 445) and not await ok("192.168.1.20", 80)       # LAN needs internet+lan
    assert not await ok("rebind.example", 443)                                       # DNS name -> loopback
    assert not await ok("mixed.example", 443)                                        # any refused address refuses
    assert not await ok("meta.example", 80) and not await ok("169.254.169.254", 80)
    assert not await ok("self.example", 80) and not await ok("10.0.0.50", 8710)      # this machine's own address
    assert not await ok("::ffff:127.0.0.1", 8317 + 1)
    assert not await ok("unknown.example", 443)
    p.update("internet+lan", ["127.0.0.1:8317"])
    assert await ok("nas.lan", 445) and not await ok("self.example", 80)
    p.update("none", ["127.0.0.1:8317"])
    assert await ok("127.0.0.1", 8317) and not await ok("api.example.org", 443)


async def test_relay_on_a_protected_port_is_dropped():
    p = _proxy("internet", ["127.0.0.1:8710", "127.0.0.1:8317", "bad"], protected={8710})
    assert set(p.relays) == {("loopback", 8317)}


# ------------------------------------------------------------------ live proxy
async def _echo_server():
    async def h(r, w):
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
        w.close()
    s = await asyncio.start_server(h, "127.0.0.1", 0)
    return s, s.sockets[0].getsockname()[1]


async def _http_server(seen):
    async def h(r, w):
        head = await r.readuntil(b"\r\n\r\n")
        seen.append(head)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
        await w.drain()
        w.close()
    s = await asyncio.start_server(h, "127.0.0.1", 0)
    return s, s.sockets[0].getsockname()[1]


def _auth(p, token=None):
    cred = base64.b64encode(f"{p.user}:{token or p.token}".encode()).decode()
    return f"Proxy-Authorization: Basic {cred}\r\n"


async def _ask(port, text, read_all=False):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(text.encode())
    await w.drain()
    data = await asyncio.wait_for(r.read() if read_all else r.readuntil(b"\r\n\r\n"), 10)
    return r, w, data


async def test_auth_connect_tunnel_plain_http_and_audit():
    audit = []
    echo, eport = await _echo_server()
    seen = []
    web, wport = await _http_server(seen)
    p = await _proxy("none", [f"127.0.0.1:{eport}", f"localhost:{wport}"],
                     audit=lambda u, t, d: audit.append((u, t, d))).start()
    try:
        assert p.url().startswith(f"http://{p.user}:") and p.url().endswith(f"@127.0.0.1:{p.port}")
        # no credential / wrong credential -> 407, nothing forwarded, nothing audited
        _, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\nHost: x\r\n\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 407") and b"Proxy-Authenticate: Basic" in data
        _, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n{_auth(p, 'wrong')}\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 407") and p.counts["unauthorized"] == 2 and audit == []
        # CONNECT to a relay target: a tunnel, bytes both ways
        r, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n{_auth(p)}\r\n")
        assert data.startswith(b"HTTP/1.1 200")
        w.write(b"ping-through-the-tunnel")
        await w.drain()
        assert await asyncio.wait_for(r.readexactly(23), 5) == b"ping-through-the-tunnel"
        w.close()
        # plain http:// through the proxy: origin-form, no Proxy-* header, Connection: close; path never audited
        _, w, data = await _ask(p.port, f"GET http://127.0.0.1:{wport}/v1/models?key=SECRET HTTP/1.1\r\n"
                                        f"Host: 127.0.0.1:{wport}\r\n{_auth(p)}Proxy-Connection: keep-alive\r\n\r\n",
                                read_all=True)
        assert data.startswith(b"HTTP/1.1 200") and data.endswith(b"HELLO")
        assert seen[0].startswith(b"GET /v1/models?key=SECRET HTTP/1.1\r\n")
        assert b"proxy-" not in seen[0].lower() and b"Connection: close" in seen[0]
        # a refused destination: 403 and an audit line with host:port only
        _, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:9222 HTTP/1.1\r\n{_auth(p)}\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 403") and b"sandbox.network: none" in data
        assert [(t, d["decision"]) for _, t, d in audit] == [(f"127.0.0.1:{eport}", "allowed"),
                                                              (f"127.0.0.1:{wport}", "allowed"),
                                                              ("127.0.0.1:9222", "refused")]
        assert all(u == "alice" and "SECRET" not in str(d) and "/v1" not in t for u, t, d in audit)
        # the credential rotates (a new worker start): the old one is refused
        old = p.token
        p.rotate()
        _, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n{_auth(p, old)}\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 407")
    finally:
        await p.close()
        echo.close()
        web.close()


async def test_limits_header_size_connections_idle():
    echo, eport = await _echo_server()
    p = await _proxy("none", [f"127.0.0.1:{eport}"], max_connections=2, idle_seconds=1).start()
    try:
        _, w, data = await _ask(p.port, "CONNECT a:1 HTTP/1.1\r\nX: " + "y" * 40000 + "\r\n\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 431")
        w.close()
        for _ in range(100):                     # the refused connection lingers up to 1 s (it still counts)
            if p.active == 0:
                break
            await asyncio.sleep(0.05)
        held = []
        for _ in range(2):
            r, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n{_auth(p)}\r\n")
            assert data.startswith(b"HTTP/1.1 200")
            held.append((r, w))
        _, w, data = await _ask(p.port, f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n{_auth(p)}\r\n", read_all=True)
        assert data.startswith(b"HTTP/1.1 503")
        # idle tunnels are closed after proxy_idle_seconds without traffic
        r, _ = held[0]
        assert await asyncio.wait_for(r.read(), 40) == b""
    finally:
        await p.close()
        echo.close()


async def test_registry_keeps_port_and_rotates_credential():
    class S:
        def get(self, section, key, default=None):
            return {("server", "port"): 8710, ("sandbox", "proxy_max_connections"): 8,
                    ("sandbox", "proxy_idle_seconds"): 60}.get((section, key), default)
    reg = eg.ProxyRegistry(S(), audit=lambda *a: None)
    a = await reg.ensure("alice", "alice", "internet", ["127.0.0.1:8317", "127.0.0.1:8710"])
    tok, port = a.token, a.port
    assert ("loopback", 8710) not in a.relays and 8710 in reg.protected_ports() and port in reg.protected_ports()
    b = await reg.ensure("alice", "alice", "internet+lan", ["127.0.0.1:8317"])
    assert b is a and b.port == port and b.token != tok and b.network == "internet+lan"
    assert reg.describe()["alice"]["port"] == port
    await reg.drop("alice")
    assert reg.proxies == {} and a.server is None
    await reg.close_all()
