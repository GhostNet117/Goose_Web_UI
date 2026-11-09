"""Security assessment 2026-11-09, slice C (OS layer) and A-6: regression tests.

C-1 relay pipe squatting, C-2 sandboxed worker environment, C-4 install folder permissions (check), C-5 container
name collisions, C-6 sparse logs / per-owner log budget, C-7 orphaned agent processes, C-8 janitor and junctions,
A-6/C-9 local CA name constraints and key ACLs, C-10 grants on missing folders, C-12 upgrade restart command.
"""
import asyncio
import datetime as dt
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from goose_web import logjanitor, tls
from goose_web import relay as rl
from goose_web import sandbox as sb
from goose_web.config import load_settings

WIN = sys.platform == "win32"
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def settings(tmp_path, monkeypatch):
    (tmp_path / "empty.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "empty.yaml"))
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    s = load_settings()
    s.system_dir.mkdir(parents=True, exist_ok=True)
    return s


def _base_python() -> str:
    """The real interpreter (a venv's python.exe may be a launcher that starts it as a child)."""
    exe = os.path.join(sys.base_prefix, "python.exe" if WIN else "bin/python3")
    return exe if os.path.exists(exe) else sys.executable


# ====================================================================== C-1 relay pipe
SQUATTER = r"""
import _winapi, json, sys
name, out = sys.argv[1], sys.argv[2]
h = _winapi.CreateNamedPipe(name, _winapi.PIPE_ACCESS_DUPLEX, 0, 255, 65536, 65536, 0, _winapi.NULL)
print("ready", flush=True)
res = {"connected": False, "got": None}
try:
    _winapi.ConnectNamedPipe(h, False)
    res["connected"] = True
except OSError as e:
    res["connected"] = e.winerror == 535          # ERROR_PIPE_CONNECTED
try:
    data, _ = _winapi.ReadFile(h, 65536)
    res["got"] = data.decode("latin-1")
except OSError as e:
    res["got"] = None
    res["readError"] = e.winerror
open(out, "w").write(json.dumps(res))
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not WIN, reason="named-pipe relay is Windows-only")
def test_relay_fails_closed_when_the_pipe_name_is_taken(tmp_path):
    pipe = rl.new_pipe_name()
    sq = subprocess.Popen([_base_python(), "-c", SQUATTER, pipe, str(tmp_path / "sq.json")], stdout=subprocess.PIPE)
    try:
        assert sq.stdout.readline().strip() == b"ready"
        with pytest.raises(OSError, match="exists already"):
            rl.PipeRelayServer(pipe, "S-1-5-18", "127.0.0.1:9")
    finally:
        sq.kill()
        sq.wait()


@pytest.mark.skipif(not WIN, reason="named-pipe relay is Windows-only")
def test_forwarder_sends_nothing_to_a_pipe_the_gateway_does_not_serve(tmp_path):
    """Even if a squatter knew the name and got it first, the forwarder checks the pipe's server process."""
    pipe = rl.new_pipe_name()
    result = tmp_path / "sq.json"
    sq = subprocess.Popen([_base_python(), "-c", SQUATTER, pipe, str(result)], stdout=subprocess.PIPE)
    port = _free_port()
    listen = f"127.64.200.7:{port}"
    fwd = rl.write_forwarder(str(tmp_path))
    errf = tmp_path / "fwd.err"
    p = subprocess.Popen([sys.executable, "-I", fwd, listen, pipe, str(os.getpid())], stdout=subprocess.PIPE,
                         stderr=open(errf, "wb"))
    try:
        assert sq.stdout.readline().strip() == b"ready"
        assert p.stdout.readline().strip() == b"listening"
        with socket.create_connection(("127.64.200.7", port), timeout=10) as s:
            try:
                s.sendall(b"PROMPT-SECRET")
                got = s.recv(100)
            except ConnectionError:                                # reset/aborted: closed with our request unread
                got = b""
            assert got == b""                                      # refused: nothing comes back
        sq.wait(15)
        res = json.loads(result.read_text())
        assert res["connected"] and not res["got"]                  # the squatter never saw a byte
        for _ in range(50):
            if "not the gateway" in errf.read_text(errors="replace"):
                break
            time.sleep(0.1)
        assert "not the gateway" in errf.read_text(errors="replace")
    finally:
        p.kill()
        p.wait()
        sq.kill()
        sq.wait()


@pytest.mark.skipif(not WIN, reason="named-pipe relay is Windows-only")
def test_pipe_name_stays_owned_by_the_gateway_while_it_relays(tmp_path):
    import _winapi
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(4)

    def serve():
        while True:
            try:
                c, _ = echo.accept()
            except OSError:
                return
            with c:
                d = c.recv(100)
                c.sendall(b"OK:" + d)
    threading.Thread(target=serve, daemon=True).start()
    pipe = rl.new_pipe_name()
    srv = rl.PipeRelayServer(pipe, "S-1-5-18", f"127.0.0.1:{echo.getsockname()[1]}").start()
    port = _free_port()
    fwd = rl.write_forwarder(str(tmp_path))
    p = subprocess.Popen([sys.executable, "-I", fwd, f"127.64.200.8:{port}", pipe, str(os.getpid())],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert p.stdout.readline().strip() == b"listening"
        for i in range(3):
            with socket.create_connection(("127.64.200.8", port), timeout=10) as s:
                s.sendall(b"R%d" % i)
                assert s.recv(100) == b"OK:R%d" % i
            # between and after connections nobody else can create the first instance of the name
            with pytest.raises(OSError):
                _winapi.CloseHandle(_winapi.CreateNamedPipe(
                    pipe, _winapi.PIPE_ACCESS_DUPLEX | 0x00080000, 0, 255, 65536, 65536, 0, _winapi.NULL))
    finally:
        p.kill()
        p.wait()
        srv.stop()
        echo.close()


# ====================================================================== C-2 environment
def test_sandboxed_worker_env_is_an_allow_list(settings, tmp_path, monkeypatch):
    from goose_web.workers import SANDBOX_ENV_ALLOW, Worker, WorkerManager
    monkeypatch.setenv("GW_TEST_SENTINEL_API_KEY", "sentinel-value-123")
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel-value-123")
    monkeypatch.setenv("GOOSE_SERVER__SECRET_KEY", "sentinel-value-123")
    monkeypatch.setenv("GOOSE_WEB_UNELEVATED", "1")
    settings.data.setdefault("goose", {})["extra_env"] = {"ADMIN_CHOSEN": "yes"}
    prof = tmp_path / "profiles" / "bob"
    prof.mkdir(parents=True)
    wm = WorkerManager(settings)
    try:
        w = Worker(key="bob", username="bob", path_root=str(prof), native=False, recipe_dirs=[str(tmp_path / "r")],
                   sandbox={"name": "GooseWeb.x.bob.0", "profile_root": str(prof), "grants": {}})
        env = wm._env(w)
        assert "GW_TEST_SENTINEL_API_KEY" not in env and "OPENAI_API_KEY" not in env
        assert "GOOSE_SERVER__SECRET_KEY" not in env and "GOOSE_WEB_UNELEVATED" not in env
        assert "sentinel-value-123" not in json.dumps(env)
        gateway_set = {"GOOSE_PATH_ROOT", "GOOSE_DISABLE_KEYRING", "GOOSE_RECIPE_PATH", "CONTEXT_FILE_NAMES",
                       "GOOSE_TELEMETRY_ENABLED", "TEMP", "TMP", "UV_CACHE_DIR", "PIP_CACHE_DIR", "npm_config_cache",
                       "XDG_CACHE_HOME", "APPDATA", "USERPROFILE", "HOME", "ADMIN_CHOSEN"}
        assert set(env) <= set(SANDBOX_ENV_ALLOW) | gateway_set, set(env) - set(SANDBOX_ENV_ALLOW) - gateway_set
        assert env["ADMIN_CHOSEN"] == "yes" and env["GOOSE_PATH_ROOT"] == str(prof)
        assert env["PATH"] == os.environ["PATH"]
        if WIN:   # the AppContainer's own temp folder is %LOCALAPPDATA%\Packages\<container>\AC\Temp
            assert env["LOCALAPPDATA"] == os.environ["LOCALAPPDATA"]
        for k in ("TEMP", "APPDATA", "USERPROFILE", "HOME"):
            assert os.path.normcase(env[k]).startswith(os.path.normcase(str(prof))) and os.path.isdir(env[k])
        if WIN:
            assert env["SystemRoot"] and env["ComSpec"]
        # an unsandboxed isolated worker (runs as the gateway account anyway) keeps the account's environment
        w2 = Worker(key="eve", username="eve", path_root=str(tmp_path / "eve"), native=False)
        env2 = wm._env(w2)
        assert env2.get("GW_TEST_SENTINEL_API_KEY") == "sentinel-value-123"
        assert env2["GOOSE_SERVER__SECRET_KEY"] == w2.secret
    finally:
        wm.job.close()


# ====================================================================== C-5 container names
def test_container_names_are_unique_per_exact_user_name(tmp_path):
    root = str(tmp_path / "profiles")
    names = {u: sb.container_name(root, u) for u in
             ("jo.ann", "joann", "j.smith", "jsmith", "a" * 40 + "x", "a" * 40 + "y", "Bob", "bob", "ünï", "_x-y")}
    assert names["Bob"] == names["bob"]                                           # user names are case-insensitive
    distinct = [names[u] for u in names if u != "Bob"]
    assert len(set(distinct)) == len(distinct)
    for n in names.values():
        assert len(n) <= 64 and n.startswith("GooseWeb.") and re.fullmatch(r"[A-Za-z0-9._-]+", n)
    assert sb.container_name(root, "jo.ann") != sb.legacy_container_name(root, "jo.ann")
    assert sb.legacy_container_name(root, "jo.ann") == sb.legacy_container_name(root, "joann")   # the 1.11 bug
    long = "x" * 64
    assert len(sb.container_name(root, long)) <= 64


def test_legacy_container_is_removed_before_the_new_one_is_used(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sb, "revoke", lambda p, sid: calls.append(("revoke", p, sid)))
    monkeypatch.setattr(sb, "delete_container", lambda name: calls.append(("delete", name)) or True)
    state = tmp_path / "state"
    state.mkdir()
    root = str(tmp_path / "profiles")
    folder = tmp_path / "profiles" / "jo.ann"
    folder.mkdir(parents=True)
    old = sb.legacy_container_name(root, "jo.ann")
    new = sb.container_name(root, "jo.ann")
    (state / f"{old}.json").write_text(json.dumps({"name": old, "sid": "S-1-15-2-1", "grants": {str(folder): "modify"}}))
    (state / f"{old}.relays.json").write_text(json.dumps({"127.0.0.1:8317": "127.64.0.9:8317"}))
    st = sb.migrate_legacy(str(state), root, "jo.ann")
    assert st["name"] == old
    assert ("revoke", str(folder), "S-1-15-2-1") in calls and ("delete", old) in calls
    assert not (state / f"{old}.json").exists()
    assert json.loads((state / f"{new}.relays.json").read_text()) == {"127.0.0.1:8317": "127.64.0.9:8317"}
    calls.clear()
    assert sb.migrate_legacy(str(state), root, "jo.ann") == {} and calls == []         # nothing left to do
    assert sb.all_states(str(state)) == []                                           # relay records are not states


# ====================================================================== C-10 grants on missing folders
def test_grants_on_missing_folders_stay_recorded_until_revoked(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sb, "ensure_container", lambda name: "S-1-15-2-77")
    monkeypatch.setattr(sb, "grant", lambda p, sid, r: calls.append(("grant", p, r)))
    monkeypatch.setattr(sb, "revoke", lambda p, sid: calls.append(("revoke", p)))
    monkeypatch.setattr(sb, "delete_container", lambda name: calls.append(("delete", name)) or True)
    state = str(tmp_path / "state")
    a, b = tmp_path / "a", tmp_path / "team"
    a.mkdir()
    b.mkdir()
    st = sb.prepare("GooseWeb.t.u.1", state, {str(a): "modify", str(b): "modify"})
    assert set(st["grants"]) == {str(a), str(b)} and st["pending"] == {}
    b.rename(tmp_path / "team-away")                      # the folder disappears for a while
    calls.clear()
    st = sb.prepare("GooseWeb.t.u.1", state, {str(a): "modify"})   # ... and the team grant is no longer wanted
    assert st["pending"] == {str(b): "modify"} and calls == []     # cannot be revoked now, but is not forgotten
    (tmp_path / "team-away").rename(b)                    # back again
    st = sb.prepare("GooseWeb.t.u.1", state, {str(a): "modify"})
    assert ("revoke", str(b)) in calls and st["pending"] == {} and set(st["grants"]) == {str(a)}
    # remove() keeps a record of grants it could not revoke; a later remove finishes the job
    st = sb.prepare("GooseWeb.t.u.1", state, {str(a): "modify", str(b): "read"})
    b.rename(tmp_path / "team-away")
    calls.clear()
    sb.remove(state, "GooseWeb.t.u.1")
    left = sb.load_state(state, "GooseWeb.t.u.1")
    assert left["pending"] == {str(b): "read"} and left["removed"] and ("revoke", str(a)) in calls
    assert [s["name"] for s in sb.all_states(state)] == ["GooseWeb.t.u.1"]
    (tmp_path / "team-away").rename(b)
    calls.clear()
    sb.remove(state, "GooseWeb.t.u.1")
    assert ("revoke", str(b)) in calls and sb.load_state(state, "GooseWeb.t.u.1") == {}


# ====================================================================== C-6 / C-8 log janitor
def _sparse(p: Path, logical: int) -> None:
    if WIN:
        import _winapi
        import ctypes
        from ctypes import wintypes
        h = _winapi.CreateFile(str(p), 0xC0000000, 0, 0, 2, 0x80, 0)
        br = wintypes.DWORD()
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k32.DeviceIoControl(h, 0x900C4, None, 0, None, 0, ctypes.byref(br), None)   # FSCTL_SET_SPARSE
        _winapi.CloseHandle(h)
    with open(p, "r+b" if p.exists() else "wb") as f:
        f.seek(logical - 1)
        f.write(b"x")


def _old(p: Path, days: float, size: int = 1000) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    t = time.time() - days * 86400
    os.utime(p, (t, t))
    return p


def test_sparse_log_counts_with_its_allocated_size_and_deletes_nothing_else(settings, monkeypatch):
    logs = settings.system_dir / "logs"
    victims = [_old(logs / "activity.jsonl.3", 9), _old(logs / "gateway.log.2", 9),
               _old(settings.profiles_root / "alice" / "state" / "logs" / "alice-old.log", 9)]
    big = settings.profiles_root / "bob" / "state" / "logs" / "fill.log"
    big.parent.mkdir(parents=True)
    _sparse(big, 64 * 2**30)                                   # claims 64 GB
    t = time.time() - 9 * 86400
    os.utime(big, (t, t))
    try:
        if logjanitor.allocated_size(big) > 2**20:
            pytest.skip("this file system does not keep sparse files sparse")
        assert big.stat().st_size == 64 * 2**30
        monkeypatch.setattr(logjanitor, "budget_bytes", lambda s: 10 * 2**20)
        rep = logjanitor.enforce(settings)
        assert rep["before"] < 2**20 and rep["deleted"] == 0
        assert all(v.exists() for v in victims)
    finally:
        big.unlink(missing_ok=True)


def test_each_owner_only_displaces_its_own_logs(settings, monkeypatch):
    logs = settings.system_dir / "logs"
    gw_old = _old(logs / "gateway.log.4", 30, 50_000)
    alice_old = _old(settings.profiles_root / "alice" / "data" / "logs" / "a.log", 30, 50_000)
    bob = [_old(settings.profiles_root / "bob" / "state" / "logs" / f"b{i}.log", 1 + i * 0.1, 100_000) for i in range(5)]
    monkeypatch.setattr(logjanitor, "budget_bytes", lambda s: 300_000)
    rep = logjanitor.enforce(settings)
    # bob (500 kB) is the largest: only his files go (oldest first) until the total is under 90 % of the budget,
    # although the gateway's and alice's files are much older
    assert gw_old.exists() and alice_old.exists()
    assert rep["deleted"] == 4 and rep["after"] <= 270_000
    assert [p.exists() for p in bob] == [True, False, False, False, False]
    # a large owner whose files are all recent (in use) does not make others' logs go either
    hog = settings.profiles_root / "bob" / "state" / "logs" / "hog.log"
    hog.write_bytes(b"y" * 600_000)
    rep = logjanitor.enforce(settings)
    assert rep["deleted"] == 1 and not bob[0].exists()        # only bob's own last old file
    assert gw_old.exists() and alice_old.exists()
    # the gateway's logs go when the gateway is the largest owner
    hog.unlink()
    big_gw = _old(logs / "gateway.log.5", 20, 600_000)
    rep = logjanitor.enforce(settings)
    assert not big_gw.exists() and alice_old.exists()


def _link_dir(target: Path, link: Path) -> None:
    if WIN:
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_janitor_never_follows_junctions(settings, tmp_path, monkeypatch):
    outside = tmp_path / "team"
    precious = _old(outside / "member-notes.txt", 30)
    bob_logs = settings.profiles_root / "bob" / "state" / "logs"
    bob_logs.mkdir(parents=True)
    _link_dir(outside, bob_logs / "j_team")
    assert (bob_logs / "j_team" / "member-notes.txt").exists()          # reachable through the link ...
    assert not any("member-notes" in str(f["path"]) for f in logjanitor.scan(settings))   # ... but not scanned
    # a redirected root: carol's whole state folder is a junction to the outside folder
    carol = settings.profiles_root / "carol"
    carol.mkdir()
    (outside / "logs").mkdir()
    precious2 = _old(outside / "logs" / "x.log", 30)
    _link_dir(outside, carol / "state")
    assert (carol / "state" / "logs" / "x.log").exists()
    assert not any(os.path.normcase(str(carol)) in os.path.normcase(str(r)) for r in logjanitor.roots(settings))
    _old(bob_logs / "own.log", 30, 5000)
    monkeypatch.setattr(logjanitor, "budget_bytes", lambda s: 100)
    rep = logjanitor.enforce(settings)
    assert precious.exists() and precious2.exists() and rep["deleted"] == 1
    # a file that is swapped for a link to somewhere else after the scan is not deleted
    f = _old(bob_logs / "late.log", 30, 5000)
    files = logjanitor.scan(settings)
    real = next(x for x in files if x["path"].name == "late.log")
    f.unlink()
    sub = bob_logs / "sub"
    _link_dir(outside, sub)
    real["path"] = sub / "member-notes.txt"                    # what the path resolves to now: outside the root
    assert not logjanitor._inside(real["path"], real["root"])
    os.rmdir(sub) if WIN else sub.unlink()
    os.rmdir(bob_logs / "j_team") if WIN else (bob_logs / "j_team").unlink()
    os.rmdir(carol / "state") if WIN else (carol / "state").unlink()


def test_janitor_docstring_no_longer_claims_too_much():
    doc = logjanitor.__doc__
    assert "Nothing else is ever deleted" not in doc and "junction" in doc and "allocated" in doc


# ====================================================================== C-7 orphaned processes
CHILD = r"""
import subprocess, sys, time
sys.stdin.readline()                                       # wait until the test has put this worker in its jobs
subprocess.run([sys.executable, "-c", sys.argv[2], sys.argv[1]])   # the middle process exits right away
time.sleep(120)
"""
MIDDLE = r"""
import subprocess, sys
p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], creationflags=0x00000008 | 0x00000200,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
open(sys.argv[1], "w").write(str(p.pid))
"""


def _alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k32.OpenProcess(0x00100000 | 0x1000, False, pid)        # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
    if not h:
        return False
    try:
        return k32.WaitForSingleObject(h, 0) == 0x102            # WAIT_TIMEOUT: still running
    finally:
        k32.CloseHandle(h)


@pytest.mark.skipif(not WIN, reason="job objects are Windows-only")
async def test_detached_grandchild_dies_when_the_worker_stops(settings, tmp_path):
    from goose_web.workers import Worker, WorkerManager, _Job
    wm = WorkerManager(settings)
    pidf = tmp_path / "grandchild.pid"
    w = Worker(key="bob", username="bob", path_root=None, native=False)
    wm.workers["bob"] = w
    w.proc = subprocess.Popen([_base_python(), "-c", CHILD, str(pidf), MIDDLE], stdin=subprocess.PIPE,
                              creationflags=0x08000000 | 0x00000200)
    try:
        wm.job.add(w.proc)                                     # as WorkerManager._start does: gateway job, then
        w.job = _Job()                                         # the worker's own (nested) job
        assert w.job.add(w.proc)
        w.proc.stdin.write(b"go\n")
        w.proc.stdin.flush()
        for _ in range(200):
            if pidf.exists() and pidf.read_text().strip():
                break
            await asyncio.sleep(0.05)
        gc = int(pidf.read_text())
        await asyncio.sleep(0.5)
        assert _alive(gc)                                      # detached, its parent gone: a tree kill misses it
        await wm.stop("bob")
        for _ in range(100):
            if not _alive(gc):
                break
            await asyncio.sleep(0.05)
        assert not _alive(gc) and w.job is None and w.proc is None
    finally:
        if w.proc:
            w.proc.kill()
        wm.job.terminate()
        wm.job.close()


# ====================================================================== A-6 / C-9 local CA
def _mint(ca_key, ca_cert, dns=(), ips=()):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (list(dns) + list(ips))[0])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def _load_ca(d: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return (serialization.load_pem_private_key((d / "ca.key").read_bytes(), None),
            x509.load_pem_x509_certificate((d / "ca.crt").read_bytes()))


def _verify(ca_cert, leaf, name):
    from cryptography import x509
    from cryptography.x509.verification import PolicyBuilder, Store
    subject = x509.IPAddress(ipaddress.ip_address(name)) if tls._is_ip(name) else x509.DNSName(name)
    PolicyBuilder().store(Store([ca_cert])).build_server_verifier(subject).verify(leaf, [])


def test_ca_cannot_sign_for_other_sites(settings):
    from cryptography import x509
    from cryptography.x509.verification import VerificationError
    tls.ensure(settings)
    d = tls.tls_dir(settings)
    ca_key, ca_cert = _load_ca(d)
    ext = ca_cert.extensions.get_extension_for_class(x509.NameConstraints)
    assert ext.critical
    dns, nets = tls.ca_constraints(ca_cert)
    assert "localhost" in dns and "127.0.0.0/8" in nets and "fc00::/7" in nets and "100.64.0.0/10" in nets
    server = x509.load_pem_x509_certificates((d / "server.crt").read_bytes())[0]
    for name in ("localhost", "127.0.0.1", "::1", socket.gethostname().lower()):
        _verify(ca_cert, server, name)                                      # the real certificate still verifies
    for evil_dns, evil_ip in (("login.microsoftonline.com", None), ("evil-localhost.com", None), (None, "8.8.8.8")):
        _, evil = _mint(ca_key, ca_cert, dns=[evil_dns] if evil_dns else [], ips=[evil_ip] if evil_ip else [])
        with pytest.raises(VerificationError):
            _verify(ca_cert, evil, evil_dns or evil_ip)
    _, ok_lan = _mint(ca_key, ca_cert, ips=["192.168.7.9"])                  # private addresses stay possible
    _verify(ca_cert, ok_lan, "192.168.7.9")


def test_ca_constraints_are_enforced_by_tls_clients(settings, tmp_path):
    """OpenSSL (Python's ssl) refuses a stolen-key certificate for another site; localhost still works."""
    from cryptography.hazmat.primitives import serialization
    tls.ensure(settings)
    d = tls.tls_dir(settings)
    ca_key, ca_cert = _load_ca(d)
    key, evil = _mint(ca_key, ca_cert, dns=["login.microsoftonline.com"])
    (tmp_path / "evil.crt").write_bytes(evil.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "evil.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))

    def handshake(certfile, keyfile, hostname):
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(certfile, keyfile)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def accept():
            try:
                c, _ = srv.accept()
                with sctx.wrap_socket(c, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass
        t = threading.Thread(target=accept, daemon=True)
        t.start()
        cctx = ssl.create_default_context(cafile=str(d / "ca.crt"))
        try:
            with socket.create_connection(srv.getsockname(), timeout=10) as s:
                with cctx.wrap_socket(s, server_hostname=hostname):
                    return True
        finally:
            srv.close()
            t.join(5)
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(tmp_path / "evil.crt", tmp_path / "evil.key", "login.microsoftonline.com")
    assert handshake(d / "server.crt", d / "server.key", "localhost")
    assert handshake(d / "server.crt", d / "server.key", "127.0.0.1")


def test_unconstrained_ca_from_111_is_replaced(settings):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    d = tls.tls_dir(settings)
    d.mkdir(parents=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Goose Web local CA (old)")])
    now = dt.datetime.now(dt.timezone.utc)
    old = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
           .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3000))
           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    (d / "ca.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    (d / "ca.crt").write_bytes(old.public_bytes(serialization.Encoding.PEM))
    st = tls.ensure(settings)
    assert st["renewed"] and "no name constraints" in st["reason"]
    _, ca = _load_ca(d)
    assert tls.ca_constraints(ca) is not None and ca.public_key() != old.public_key()
    assert not tls.ensure(settings)["renewed"]                                 # stable from then on


def test_private_keys_are_owner_only(settings):
    tls.ensure(settings)
    d = tls.tls_dir(settings)
    for f in ("ca.key", "server.key"):
        p = d / f
        if WIN:
            from goose_web import winsec
            from goose_web.__main__ import _path_sddl
            sddl = _path_sddl(str(p))
            assert "D:P" in sddl                                              # inheritance removed
            sids = set(re.findall(r"\([^;]*;[^;]*;[^;]*;[^;]*;[^;]*;([^)]*)\)", sddl.split("D:", 1)[1]))
            me = winsec.current_user_sid()
            # SDDL abbreviates the built-in Administrator account (RID 500, e.g. GitHub's Windows runner) as LA
            allowed = {me, "SY"} | ({"LA"} if str(me).endswith("-500") else set())
            assert sids <= allowed, sids
        else:
            assert p.stat().st_mode & 0o077 == 0
    assert not list(d.glob("*.tmp"))


# ====================================================================== C-4 install folder permissions
def test_sddl_broad_writers():
    from goose_web.__main__ import sddl_broad_writers
    c_default = ("O:S-1-5-21-1-2-3-1000G:S-1-5-21-1-2-3-513D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)"
                 "(A;OICIID;0x1200a9;;;BU)(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)")
    assert sddl_broad_writers(c_default) == ["Authenticated Users"]
    hardened = ("O:S-1-5-21-1-2-3-1000D:PAI(A;OICI;FA;;;S-1-5-21-1-2-3-1000)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                "(A;OICI;0x1200a9;;;S-1-5-21-1-2-3-1105)")
    assert sddl_broad_writers(hardened) == []
    assert sddl_broad_writers("D:(A;;0x1200a9;;;WD)(A;OICI;FR;;;BU)") == []          # read & execute only
    assert sddl_broad_writers("D:(A;;FA;;;WD)(A;OICI;0x2;;;S-1-5-32-545)") == ["Everyone", "Users"]
    assert sddl_broad_writers("D:(D;;FA;;;AU)") == []                                # deny ACEs are not grants
    assert sddl_broad_writers("D:(A;OICIIO;GA;;;S-1-5-11)S:(ML;;NW;;;LW)") == ["Authenticated Users"]


def test_check_flags_a_writable_install_folder(settings, monkeypatch, capsys):
    import goose_web.__main__ as m
    import goose_web.workers as wk
    monkeypatch.setattr(m, "_gateway_tasks", lambda: [])
    monkeypatch.setattr(wk, "goose_version", lambda b: "")
    monkeypatch.setattr(wk, "desktop_running", lambda b="": False)
    monkeypatch.setattr(m, "install_paths", lambda: [str(REPO)])
    monkeypatch.setattr(m, "broad_writers", lambda p: ["Authenticated Users"] if p == str(REPO) else [])
    assert m.install_acl_problems() == [(str(REPO), ["Authenticated Users"])]
    m.cmd_check(None, settings)
    out = capsys.readouterr().out
    assert re.search(r"\[!!\] install folder permissions: .* is writable by Authenticated Users", out)
    monkeypatch.setattr(m, "broad_writers", lambda p: [])
    m.cmd_check(None, settings)
    assert "[OK] install folder permissions" in capsys.readouterr().out


def test_install_ps1_restricts_the_install_folder():
    text = (REPO / "scripts" / "install.ps1").read_text(encoding="utf-8")
    fn = re.search(r"function Protect-InstallDir.*?\n}\n", text, re.S)
    assert fn, "install.ps1 has no Protect-InstallDir"
    body = fn.group(0)
    assert "/inheritance:r" in body and "/grant:r" in body and "*S-1-5-18:(OI)(CI)F" in body
    assert "*S-1-5-32-544:(OI)(CI)F" in body and "(OI)(CI)RX" in body
    call = text.index("Protect-InstallDir -Dir $InstallDir")
    assert call < text.index("init --admin")                     # before anything runs from the folder


# ====================================================================== C-12 upgrade restart
def test_upgrade_ps1_does_not_build_an_elevated_command_string_from_task_names():
    text = (REPO / "scripts" / "upgrade.ps1").read_text(encoding="utf-8")
    assert "-EncodedCommand" in text
    assert "'-Command', $restart" not in text
    assert re.search(r"-replace \"'\", \"''\"", text)
