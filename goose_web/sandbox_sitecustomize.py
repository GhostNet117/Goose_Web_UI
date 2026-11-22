"""sitecustomize for the Python programs of a Goose Web member's MXC sandbox (FIX mxc-asyncio-socketpair, 1.26.2).

Goose Web writes this file into each sandboxed member's profile as `.goose-web/python/sitecustomize.py` and starts the
member's agent with that folder first on PYTHONPATH and GOOSE_WEB_SOCKETPAIR=proxy, so every Python program the
agent starts imports it (not when started with -I, -E or -S).

Why: on Windows `socket.socketpair()` is a TCP connection to a listener on 127.0.0.1, and asyncio (every event loop),
anyio and trio make their wake-up channel with it. An MXC sandbox reaches no loopback address but the member's egress
proxy, so that connection never arrives and the program hangs as its event loop starts - every Python MCP server.

Here `socket.socketpair()` for TCP-like stream sockets asks the member's proxy for the pair instead: two connections,
each `CONNECT <random token>.pair.goose-web.invalid:1` with the proxy credential from HTTP_PROXY, which the proxy
joins to each other. If that is not possible it fails at once with an explanation instead of hanging. Nothing else
changes. A `sitecustomize` found further along the path is run afterwards, as Python would have run it.

Standard library only.
"""
import os
import sys

PAIR_DOMAIN = "pair.goose-web.invalid"
TIMEOUT = 15.0


LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _proxy():
    """(host, port, "user:password") of the member's egress proxy, from HTTP_PROXY (as MXC sets it), or None. Only a
    proxy on this machine's loopback counts: the credential is never sent anywhere else."""
    from urllib.parse import unquote, urlsplit
    for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        value = os.environ.get(key)
        if not value:
            continue
        u = urlsplit(value if "://" in value else "http://" + value)
        try:
            port = u.port
        except ValueError:
            continue
        if u.hostname and u.hostname.lower() in LOOPBACK and port:
            return u.hostname, port, f"{unquote(u.username or '')}:{unquote(u.password or '')}"
    return None


def pair_through_proxy(socket_module=None):
    """Two connected stream sockets, joined by the member's egress proxy."""
    import base64
    import secrets
    socket = socket_module or __import__("socket")
    proxy = _proxy()
    if proxy is None:
        raise OSError("socket.socketpair() is not possible in this Goose Web sandbox: it has no egress proxy "
                      "(HTTP_PROXY), and the sandbox may not connect to loopback addresses")
    host, port, cred = proxy
    target = f"{secrets.token_hex(16)}.{PAIR_DOMAIN}:1"
    request = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic "
               f"{base64.b64encode(cred.encode('utf-8')).decode('ascii')}\r\n\r\n").encode("ascii")
    socks = []
    try:
        for _ in range(2):                       # both requests first: the proxy answers when the second arrives
            s = socket.create_connection((host, port), timeout=TIMEOUT)
            socks.append(s)
            s.sendall(request)
        for s in socks:
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                chunk = s.recv(1)                # byte by byte: never read past the proxy's answer
                if not chunk:
                    raise OSError("the Goose Web sandbox proxy closed a socket pair request")
                head += chunk
                if len(head) > 4096:
                    raise OSError("the Goose Web sandbox proxy's answer to a socket pair request is too long")
            status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if status.split(" ")[1:2] != ["200"]:
                raise OSError(f"the Goose Web sandbox proxy refused a socket pair: {status}")
        for s in socks:
            s.settimeout(None)                   # blocking, like the sockets of the original socketpair()
        return socks[0], socks[1]
    except BaseException:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
        raise


def install():
    """Replace socket.socketpair (stream sockets) when Goose Web asked for it; True if installed."""
    if os.name != "nt" or os.environ.get("GOOSE_WEB_SOCKETPAIR", "").strip().lower() != "proxy":
        return False
    import socket
    original = socket.socketpair
    if getattr(original, "_goose_web", False):
        return True
    stream = {socket.AF_INET, getattr(socket, "AF_INET6", socket.AF_INET)}

    def socketpair(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
        if family in stream and type == socket.SOCK_STREAM and proto in (0, socket.IPPROTO_TCP):
            return pair_through_proxy(socket)
        return original(family, type, proto)

    socketpair.__doc__ = original.__doc__
    socketpair._goose_web = True
    socketpair._goose_web_original = original
    socket.socketpair = socketpair
    return True


def _run_next_sitecustomize():
    """Run the sitecustomize Python would have found next on sys.path (this one shadows it): a module, package or
    compiled file, run as `sitecustomize` (its `if __name__ == "sitecustomize"` code runs too)."""
    import importlib.machinery
    import importlib.util
    if getattr(sys, "_goose_web_sitecustomize_chained", False):
        return                       # once per process (another copy of this file further on would loop)
    sys._goose_web_sitecustomize_chained = True
    here = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))
    rest = [e for e in sys.path if os.path.normcase(os.path.abspath(e or os.curdir)) != here]
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", rest)
    if spec is None or spec.loader is None:
        return
    if spec.origin and os.path.normcase(os.path.dirname(os.path.abspath(spec.origin))) == here:
        return
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


if __name__ == "sitecustomize":
    try:
        install()
    except Exception:     # never keep a program from starting
        pass
    _run_next_sitecustomize()
