"""FIX mxc-asyncio-socketpair (1.26.2): socket pairs for the Python programs of an MXC member's sandbox.

An MXC container may connect to no loopback address but the member's egress proxy, so Python's socket.socketpair()
(a loopback connection on Windows) - asyncio's wake-up channel - hangs there, and with it every Python MCP server.
The proxy joins two `CONNECT <token>.pair.goose-web.invalid` requests of the same member into a pair, and Goose Web's
sitecustomize.py (sandbox_sitecustomize.py, first on the member's PYTHONPATH) asks for pairs that way.
"""
import asyncio
import base64
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from goose_web import egress as eg
from goose_web import sandbox_sitecustomize as shim
from goose_web.workers import with_python_shim

SHIM = Path(__file__).resolve().parents[1] / "goose_web" / "sandbox_sitecustomize.py"


def _proxy(**kw):
    return eg.EgressProxy("alice", network="none", relays=[], local=lambda: {"127.0.0.1", "::1"},
                          audit=kw.pop("audit", lambda *a: None), **kw)


def _auth(p, token=None):
    return "Proxy-Authorization: Basic " + base64.b64encode(f"{p.user}:{token or p.token}".encode()).decode() + "\r\n"


async def _half(port, token, auth, method="CONNECT"):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    target = f"{token}.pair.goose-web.invalid:1"
    w.write(f"{method} {target if method == 'CONNECT' else 'http://' + target + '/'} HTTP/1.1\r\n"
            f"Host: {target}\r\n{auth}\r\n".encode())
    await w.drain()
    return r, w


async def _answer(r, secs=10):
    return await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), secs)


async def _until(cond, secs=10):
    end = asyncio.get_running_loop().time() + secs
    while not cond():
        assert asyncio.get_running_loop().time() < end, "condition not reached"
        await asyncio.sleep(0.02)


async def _pair_of(p, tok=None):
    """Both halves of one pair, the second sent only when the first is waiting."""
    tok = tok or secrets.token_hex(16)
    a = await _half(p.port, tok, _auth(p))
    await _until(lambda: tok.lower() in p._pairs)
    b = await _half(p.port, tok, _auth(p))
    assert (await _answer(a[0])).startswith(b"HTTP/1.1 200") and (await _answer(b[0])).startswith(b"HTTP/1.1 200")
    return a, b


async def test_two_halves_with_one_token_are_joined():
    audit = []
    p = await _proxy(audit=lambda *a: audit.append(a)).start()
    try:
        tok = secrets.token_hex(16)
        r1, w1 = await _half(p.port, tok, _auth(p))
        await _until(lambda: tok in p._pairs)
        assert p.pair_connections == 1 and p.active == 0              # waiting, and not counted as egress
        r2, w2 = await _half(p.port, tok.upper(), _auth(p))         # the token's case does not matter
        assert (await _answer(r1)).startswith(b"HTTP/1.1 200") and (await _answer(r2)).startswith(b"HTTP/1.1 200")
        w1.write(b"wake")
        await w1.drain()
        assert await asyncio.wait_for(r2.readexactly(4), 5) == b"wake"
        w2.write(b"up")
        await w2.drain()
        assert await asyncio.wait_for(r1.readexactly(2), 5) == b"up"
        assert p.counts["pairs"] == 1 and p.describe()["pairConnections"] == 2
        w1.close()                                                     # one end closes: the other sees the end
        assert await asyncio.wait_for(r2.read(), 5) == b""
        assert p.pair_connections == 2                                 # as with a socket pair: open until both close
        w2.close()
        await _until(lambda: p.pair_connections == 0)
        assert p.active == 0
        assert audit == []                                             # not egress: never audited
    finally:
        await p.close()


async def test_an_unmatched_half_is_answered_504(monkeypatch):
    monkeypatch.setattr(eg, "PAIR_WAIT", 0.5)
    p = await _proxy().start()
    try:
        r, w = await _half(p.port, secrets.token_hex(16), _auth(p))
        assert (await asyncio.wait_for(r.read(), 10)).startswith(b"HTTP/1.1 504")
        assert p._pairs == {}
    finally:
        await p.close()


async def test_pairs_need_the_member_s_credential_and_connect():
    p = await _proxy().start()
    try:
        tok = secrets.token_hex(16)
        r, _ = await _half(p.port, tok, _auth(p, "wrong"))
        assert (await asyncio.wait_for(r.read(), 10)).startswith(b"HTTP/1.1 407")
        r, _ = await _half(p.port, tok, _auth(p), method="GET")
        assert (await asyncio.wait_for(r.read(), 10)).startswith(b"HTTP/1.1 400")
        assert p._pairs == {}
        # a name that is not a pair token is no pair: an ordinary (refused) destination
        r, w = await asyncio.open_connection("127.0.0.1", p.port)
        w.write(f"CONNECT abc.pair.goose-web.invalid:1 HTTP/1.1\r\n{_auth(p)}\r\n".encode())
        await w.drain()
        assert not (await asyncio.wait_for(r.read(), 10)).startswith(b"HTTP/1.1 200")
    finally:
        await p.close()


async def test_pair_limits(monkeypatch):
    monkeypatch.setattr(eg, "PAIR_PENDING_MAX", 1)
    monkeypatch.setattr(eg, "PAIR_CONNECTIONS_MAX", 3)
    monkeypatch.setattr(eg, "PAIR_WAIT", 1.0)
    p = await _proxy().start()
    try:
        a, b = await _pair_of(p)
        c = await _half(p.port, secrets.token_hex(16), _auth(p))     # waiting for its other half: 3 of 3 open
        await _until(lambda: p.pair_connections == 3)
        r, _ = await _half(p.port, secrets.token_hex(16), _auth(p))
        data = await asyncio.wait_for(r.read(), 10)
        assert data.startswith(b"HTTP/1.1 503") and b"too many socket pairs" in data
        assert (await asyncio.wait_for(c[0].read(), 10)).startswith(b"HTTP/1.1 504")   # never matched
        for _, w in (a, b):
            w.close()
        for _ in range(100):
            if p.pair_connections == 0:
                break
            await asyncio.sleep(0.05)
        assert p.pair_connections == 0
        r, _ = await _half(p.port, secrets.token_hex(16), _auth(p))  # 1 of 1 unmatched now ...
        await _until(lambda: len(p._pairs) == 1)
        r2, _ = await _half(p.port, secrets.token_hex(16), _auth(p))  # ... so a second one is refused
        data = await asyncio.wait_for(r2.read(), 10)
        assert data.startswith(b"HTTP/1.1 503") and b"unmatched" in data
    finally:
        await p.close()


async def test_pair_connections_do_not_use_up_the_egress_limit():
    p = await _proxy(max_connections=1).start()
    try:
        pairs = []
        for _ in range(3):                                             # six connections with a limit of one
            pairs += list(await _pair_of(p))
        assert p.active == 0 and p.pair_connections == 6
        # the egress limit is reached (an open request counts) - a socket pair is still made
        held_r, held_w = await asyncio.open_connection("127.0.0.1", p.port)
        await _until(lambda: p.active == 1)
        pairs += list(await _pair_of(p))
        assert p.active == 1 and p.pair_connections == 8
        held_w.close()
        for _, w in pairs:
            w.close()
    finally:
        await p.close()


# ------------------------------------------------------------------------------------------------ the shim
CHILD = r"""
import asyncio, socket, sys, threading, time
installed = getattr(socket.socketpair, "_goose_web", False)
print("installed", installed, flush=True)
if sys.argv[1] == "pair":
    a, b = socket.socketpair()
    a.sendall(b"ping")
    print("pair", b.recv(4).decode(), flush=True)
elif sys.argv[1] == "loop":
    loop = asyncio.new_event_loop()
    async def main():
        fut = loop.create_future()
        threading.Thread(target=lambda: (time.sleep(0.2), loop.call_soon_threadsafe(fut.set_result, "woke")),
                         daemon=True).start()
        r = await asyncio.wait_for(fut, 10)
        n = 0
        for _ in range(20):
            f = loop.create_future()
            threading.Thread(target=lambda f=f: loop.call_soon_threadsafe(f.set_result, 1), daemon=True).start()
            n += await asyncio.wait_for(f, 10)
        return f"{type(loop).__name__} {r} {n}"
    print("loop", loop.run_until_complete(main()), flush=True)
    loop.close()
elif sys.argv[1] == "fail":
    t = time.time()
    try:
        socket.socketpair()
        print("no error", flush=True)
    except OSError as e:
        print("error", round(time.time() - t, 1), str(e)[:200], flush=True)
"""


def _child_env(tmp_path, proxy_url, switch="proxy"):
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    (d / "sitecustomize.py").write_bytes(SHIM.read_bytes())
    env = {k: v for k, v in os.environ.items() if k.upper() not in ("PYTHONPATH", "GOOSE_WEB_SOCKETPAIR")
           and "proxy" not in k.lower()}
    env = with_python_shim(env, str(d))
    if switch is None:
        env.pop("GOOSE_WEB_SOCKETPAIR")
    if proxy_url:
        env["HTTP_PROXY"] = env["HTTPS_PROXY"] = proxy_url
    (tmp_path / "child.py").write_text(CHILD, encoding="utf-8")
    return env


async def _run(tmp_path, env, mode):
    proc = await asyncio.create_subprocess_exec(sys.executable, str(tmp_path / "child.py"), mode, env=env,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(proc.communicate(), 60)
    return out.decode(errors="replace"), err.decode(errors="replace")


@pytest.mark.skipif(os.name != "nt", reason="the shim acts on Windows only")
async def test_the_shim_gives_python_a_socket_pair_and_an_event_loop_through_the_proxy(tmp_path):
    p = await _proxy().start()
    try:
        env = _child_env(tmp_path, p.url())
        out, err = await _run(tmp_path, env, "pair")
        assert "installed True" in out and "pair ping" in out, (out, err)
        out, err = await _run(tmp_path, env, "loop")
        assert "loop ProactorEventLoop woke 20" in out, (out, err)
        assert p.counts["pairs"] >= 2
    finally:
        await p.close()


@pytest.mark.skipif(os.name != "nt", reason="the shim acts on Windows only")
async def test_without_the_switch_python_keeps_its_own_socketpair(tmp_path):
    env = _child_env(tmp_path, "", switch=None)
    out, err = await _run(tmp_path, env, "pair")
    assert "installed False" in out and "pair ping" in out, (out, err)


@pytest.mark.skipif(os.name != "nt", reason="the shim acts on Windows only")
async def test_without_a_proxy_the_shim_fails_at_once(tmp_path):
    env = _child_env(tmp_path, "")
    out, err = await _run(tmp_path, env, "fail")
    assert "installed True" in out and "no egress proxy" in out, (out, err)
    assert float(out.split("error ", 1)[1].split()[0]) < 2.0, out              # at once, not a hang
    p = await _proxy().start()
    try:
        env = _child_env(tmp_path, p.url().replace(p.token, "wrong"))   # a stale credential: refused, at once
        out, err = await _run(tmp_path, env, "fail")
        assert "refused a socket pair" in out and "407" in out, (out, err)
    finally:
        await p.close()


def test_a_sitecustomize_further_on_the_path_still_runs(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins\nbuiltins.OTHER_SITECUSTOMIZE_RAN = True\n",
                                            encoding="utf-8")
    d = tmp_path / "shim"
    d.mkdir()
    (d / "sitecustomize.py").write_bytes(SHIM.read_bytes())
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONPATH"}
    env["PYTHONPATH"] = os.pathsep.join([str(d), str(other)])
    out = subprocess.run([sys.executable, "-c", "import builtins; print(getattr(builtins, "
                          "'OTHER_SITECUSTOMIZE_RAN', False))"], env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "True", out


def test_with_python_shim_env():
    shim_dir, admin = os.path.join("x", "shim"), os.path.join("x", "admin")
    env = with_python_shim({"PATH": "x", "PythonPath": os.pathsep.join([admin, shim_dir]),
                            "PYTHONPATH": os.path.join("x", "more")}, shim_dir)
    assert env["PYTHONPATH"].split(os.pathsep)[0] == shim_dir
    assert set(env["PYTHONPATH"].split(os.pathsep)) == {shim_dir, admin, os.path.join("x", "more")}
    assert [k for k in env if k.upper() == "PYTHONPATH"] == ["PYTHONPATH"]
    assert env["GOOSE_WEB_SOCKETPAIR"] == "proxy" and env["PATH"] == "x"
    assert with_python_shim({"PATH": "x"}, "") == {"PATH": "x"}                  # off: unchanged


def test_proxy_url_parsing(monkeypatch):
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    assert shim._proxy() is None
    user, word = "gw-ab", "t%2Fok"                    # a made-up credential, as MXC passes the proxy's on
    monkeypatch.setenv("HTTP_PROXY", f"http://{user}:{word}@127.0.0.1:4711")
    assert shim._proxy() == ("127.0.0.1", 4711, "gw-ab:t/ok")
    monkeypatch.setenv("HTTP_PROXY", "127.0.0.1:4712")
    assert shim._proxy() == ("127.0.0.1", 4712, ":")


# ------------------------------------------------------------------------------------------------ provisioning
def test_the_shim_is_written_into_the_profile_and_kept_current(tmp_path, monkeypatch):
    from goose_web.config import load_settings
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    from tests.test_team_profiles import user
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    try:
        pr = Profiles(s, db)
        bob = user(db, "bob")
        d = pr.python_shim(bob)
        f = Path(d) / "sitecustomize.py"
        assert Path(d) == pr.root_for(bob) / ".goose-web" / "python"
        assert f.read_bytes() == SHIM.read_bytes()
        f.write_text("changed by the member", encoding="utf-8")
        assert pr.python_shim(bob) == d and f.read_bytes() == SHIM.read_bytes()      # rewritten when it differs
        s.data["sandbox"]["python_socketpair"] = False
        assert pr.python_shim(bob) == ""                                             # off
        s.data["sandbox"]["python_socketpair"] = "yes"
        assert pr.python_shim(bob) == d
    finally:
        db.close()


# ------------------------------------------------------------------------------------- independent review, 1.26.2
async def test_only_exact_tokens_are_pairs():
    p = await _proxy().start()
    try:
        for host in ("a" * 31, "a" * 33, "g" * 32, "x" + "a" * 32):
            r, w = await asyncio.open_connection("127.0.0.1", p.port)
            w.write(f"CONNECT {host}.pair.goose-web.invalid:1 HTTP/1.1\r\n{_auth(p)}\r\n".encode())
            await w.drain()
            assert not (await asyncio.wait_for(r.read(), 10)).startswith(b"HTTP/1.1 200"), host
        assert p._pairs == {} and p.counts["pairs"] == 0
    finally:
        await p.close()


async def test_a_pair_is_rate_limited_and_counted(monkeypatch):
    monkeypatch.setattr(eg, "PAIR_RATE", 64 * 1024)
    monkeypatch.setattr(eg, "PAIR_BURST", 64 * 1024)
    p = await _proxy().start()
    try:
        (r1, w1), (r2, w2) = await _pair_of(p)
        t0 = asyncio.get_running_loop().time()
        w1.write(b"x" * (192 * 1024))                                  # 3 x the burst at 64 KiB/s: ~2 s
        await w1.drain()
        got = await asyncio.wait_for(r2.readexactly(192 * 1024), 30)
        took = asyncio.get_running_loop().time() - t0
        assert len(got) == 192 * 1024 and took > 1.0, took
        assert p.counts["pairBytes"] >= 192 * 1024 and p.describe()["pairBytes"] >= 192 * 1024
    finally:
        await p.close()


async def test_half_close_and_closing_the_proxy_end_pairs():
    p = await _proxy().start()
    try:
        (r1, w1), (r2, w2) = await _pair_of(p)
        w1.write_eof()                                                 # half-close: the other side still talks
        assert await asyncio.wait_for(r2.read(), 5) == b""
        w2.write(b"still here")
        await w2.drain()
        assert await asyncio.wait_for(r1.readexactly(10), 5) == b"still here"
        await p.close()                                                # the proxy goes: its pairs end
        try:
            end = await asyncio.wait_for(r1.read(), 5)
        except ConnectionError:
            end = b""                                                  # aborted: a reset is an end too
        assert end == b""
        await _until(lambda: p.pair_connections == 0)
    finally:
        await p.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions")
def test_the_shim_folder_holds_nothing_else_and_is_never_written_through_a_link(tmp_path, monkeypatch):
    from goose_web.config import load_settings
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    from tests.test_team_profiles import user
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "gw.db")
    try:
        pr = Profiles(s, db)
        bob = user(db, "bob")
        d = Path(pr.python_shim(bob))
        (d / "json.py").write_text("raise SystemExit('planted')", encoding="utf-8")   # would shadow the stdlib
        (d / "pkg").mkdir()
        (d / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("not ours", encoding="utf-8")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(d / "link"), str(outside)], capture_output=True, check=True)
        assert pr.python_shim(bob) == str(d)
        assert sorted(x.name for x in d.iterdir()) == ["sitecustomize.py"]
        assert (outside / "keep.txt").exists()                         # the link went, not what it pointed to
        # the folder itself a link: nothing is written through it
        import shutil
        shutil.rmtree(d)
        target = tmp_path / "elsewhere"
        target.mkdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(d), str(target)], capture_output=True, check=True)
        assert pr.python_shim(bob) == ""
        assert list(target.iterdir()) == []
    finally:
        db.close()


def test_the_next_sitecustomize_runs_as_sitecustomize(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins\nif __name__ == 'sitecustomize':\n"
                                            "    builtins.NEXT_AS_SITECUSTOMIZE = True\n", encoding="utf-8")
    d = tmp_path / "shim"
    d.mkdir()
    (d / "sitecustomize.py").write_bytes(SHIM.read_bytes())
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONPATH"}
    env["PYTHONPATH"] = os.pathsep.join([str(d), str(other), str(d)])     # also: no loop over a second copy
    out = subprocess.run([sys.executable, "-c", "import builtins; print(getattr(builtins, "
                          "'NEXT_AS_SITECUSTOMIZE', False))"], env=env, capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "True", out


def test_the_shim_sends_the_credential_only_to_a_loopback_proxy(monkeypatch):
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    user, word = "gw-ab", "secret-token"
    monkeypatch.setenv("HTTP_PROXY", f"http://{user}:{word}@proxy.example.org:8080")
    assert shim._proxy() is None
    monkeypatch.setenv("HTTPS_PROXY", f"http://{user}:{word}@localhost:4713")
    assert shim._proxy() == ("localhost", 4713, f"{user}:{word}")
