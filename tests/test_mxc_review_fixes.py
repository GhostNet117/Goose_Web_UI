"""Security review 2026-11-12 of the MXC backend (1.19.0): one regression test (or more) per finding MX-1..MX-14.
Each one fails on 3c5c3d1 (1.19.0) and passes from 1.19.1. New APIs are imported inside the tests, so on the old
code each test fails on its own instead of the whole module."""
import asyncio
import base64
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from goose_web import egress as eg
from goose_web import mxc
from goose_web.config import DEFAULTS, IS_WINDOWS, Settings, _deep_merge, sandbox_config_problems, sandbox_on

WIN = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")


@pytest.fixture(autouse=True)
def _fresh_availability(monkeypatch):
    monkeypatch.setattr(mxc, "AVAILABILITY", mxc.Availability())


def settings(tmp_path, **sandbox) -> Settings:
    data = _deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "profiles")},
                                  "sandbox": {"mxc_dir": str(tmp_path / "inst" / "vendor" / "mxc"), **sandbox}})
    return Settings(data, None)


def _auth(p, token=None, user=None):
    cred = base64.b64encode(f"{user or p.user}:{token or p.token}".encode()).decode()
    return f"Proxy-Authorization: Basic {cred}\r\n"


async def _ask(port, text, timeout=20):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(text.encode("latin-1"))
    await w.drain()
    try:
        return await asyncio.wait_for(r.read(), timeout)
    finally:
        w.close()


def _noop(*a):
    pass


# ------------------------------------------------------------------ MX-1
async def test_mx1_own_and_loopback_addresses_are_compared_as_parsed_addresses():
    table = {"self6.example": ["FD12:3456:789A::CD35:7731"], "mapped.example": ["::ffff:10.0.0.5"]}

    async def resolver(host, port):
        if host not in table:
            raise OSError("no such host")
        return table[host]
    p = eg.EgressProxy("alice", network="internet+lan", resolver=resolver, audit=_noop,
                       local=lambda: {"127.0.0.1", "::1", "fd12:3456:789a::cd35:7731", "10.0.0.5", "fe80::1%7"})
    for lit in ("fd12:3456:789a::cd35:7731", "FD12:3456:789A::CD35:7731", "fd12:3456:789a:0:0:0:cd35:7731",
                "[FD12:3456:789A::CD35:7731]", "fd12:3456:789a::cd35:7731%3", "::ffff:10.0.0.5", "::FFFF:a00:5",
                "64:ff9b::a00:5", "10.0.0.5", "self6.example", "mapped.example", "::ffff:7f00:1"):
        d = await p.decide(lit, 22)
        assert not d.allowed and "this machine" in d.reason, (lit, d.reason)
    # what is connected is the normalised address that was checked (no second lookup, no odd spelling)
    d = await p.decide("FD12:0:0:0:0:0:0:2", 443)
    assert d.allowed and d.host == "fd12::2" and d.kind == "lan"
    d = await p.decide("::ffff:192.168.1.20", 80)
    assert d.allowed and d.host == "192.168.1.20"


# ------------------------------------------------------------------ MX-2
async def test_mx2_slow_name_lookups_never_stall_the_gateways_threads(monkeypatch):
    import socket
    real = socket.getaddrinfo
    calls = []

    def slow(host, *a, **k):
        if str(host).startswith(("slow", "gwrv")):
            calls.append(host)
            time.sleep(3)
            raise socket.gaierror(11001, "no such host")
        return real(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", slow)
    p = await eg.EgressProxy("mallory", network="internet", audit=_noop).start()
    try:
        tasks = [asyncio.create_task(_ask(p.port, f"CONNECT slow{i}.example:443 HTTP/1.1\r\n{_auth(p)}\r\n", 40))
                 for i in range(40)]
        await asyncio.sleep(0.5)
        t = time.monotonic()
        await asyncio.to_thread(lambda: None)        # what sign-in, MFA and provisioning do
        lag = time.monotonic() - t
        answers = await asyncio.gather(*tasks)
        assert lag < 0.5, f"asyncio.to_thread waited {lag:.2f} s while a member resolved slow names"
        codes = [a.split(b" ", 2)[1] for a in answers]
        assert codes.count(b"503") >= 30 and len(calls) <= eg.RESOLVE_PER_MEMBER + 2   # per-member cap
        # a name that just failed is answered from the negative cache (no new lookup)
        n = len(calls)
        again = await _ask(p.port, f"CONNECT {calls[0]}:443 HTTP/1.1\r\n{_auth(p)}\r\n")
        assert again.startswith(b"HTTP/1.1 403") and len(calls) == n
        # single-label names (LLMNR/NetBIOS) are refused without a lookup
        r = await _ask(p.port, f"CONNECT gwrvabcd:443 HTTP/1.1\r\n{_auth(p)}\r\n")
        assert r.startswith(b"HTTP/1.1 403") and b"single-label" in r and len(calls) == n
        r = await _ask(p.port, f"CONNECT printer.local:443 HTTP/1.1\r\n{_auth(p)}\r\n")
        assert r.startswith(b"HTTP/1.1 403") and len(calls) == n
    finally:
        await p.close()


async def test_mx2_single_label_relay_target_still_works():
    p = eg.EgressProxy("alice", network="internet", relays=["nas:8080"], audit=_noop)
    d = await p.decide("NAS", 8080)
    assert d.allowed and d.kind == "relay" and (d.host, d.port) == ("nas", 8080)
    assert not (await p.decide("nas", 8081)).allowed


# ------------------------------------------------------------------ MX-3
@WIN
async def test_mx3_a_hard_link_to_a_file_outside_the_grants_stops_the_mxc_start(tmp_path, monkeypatch):
    from goose_web.workers import SandboxUnavailable
    from tests.test_mxc import FAKE_AGENT, _manager, _spec
    wm, s, events = _manager(tmp_path, monkeypatch)
    spec = _spec(tmp_path, s, network="none", relay_targets=[])
    prof = Path(spec["profile_root"])
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.txt").write_text("ORIGINAL", encoding="utf-8")
    os.link(outside / "victim.txt", prof / "workspace" / "hl.txt")         # planted under AppContainer, say
    (prof / "a.txt").write_text("x", encoding="utf-8")
    os.link(prof / "a.txt", prof / "workspace" / "b.txt")                  # both names inside: fine
    launched = []

    def fake_launch(exe, policy_file, stderr_file, jobs, desktop=""):
        launched.append(policy_file)
        return subprocess.Popen([sys.executable, "-c", FAKE_AGENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=stderr_file)
    monkeypatch.setattr(mxc, "launch", fake_launch)
    w = wm.register("alice", "alice", None, False, [], sandbox=spec)
    try:
        with pytest.raises(SandboxUnavailable):
            await wm.ensure("alice")
        assert launched == [] and "hard link" in w.last_error and "victim.txt" in w.last_error
        assert events[-1][0] == "sandbox.unavailable"
        os.unlink(prof / "workspace" / "hl.txt")
        await wm.ensure("alice")
        assert w.state == "ready" and len(launched) == 1
        assert (outside / "victim.txt").read_text(encoding="utf-8") == "ORIGINAL"
    finally:
        await wm.shutdown()


def test_mx3_hard_link_scan_is_bounded(tmp_path):
    for i in range(30):
        (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
    found, complete, seen = mxc.hardlink_escapes([str(tmp_path)], seconds=5, max_entries=10)
    assert not complete and seen == 11 and found == []
    found, complete, seen = mxc.hardlink_escapes([str(tmp_path)])
    assert complete and found == [] and seen == 30


# ------------------------------------------------------------------ MX-4
async def test_mx4_egress_audit_and_log_are_rate_limited_per_member(caplog):
    audit = []
    p = await eg.EgressProxy("mallory", network="none", audit=lambda u, t, d: audit.append((t, d))).start()
    verbatim = getattr(eg, "AUDIT_VERBATIM_PER_MINUTE", 30)
    try:
        with caplog.at_level(logging.INFO, logger="goose_web.egress"):
            for batch in range(10):
                await asyncio.gather(*(_ask(p.port, f"CONNECT z{batch}-{i}.example:443 HTTP/1.1\r\n{_auth(p)}\r\n")
                                       for i in range(20)))
            refusals = [r for r in caplog.records if "refused" in r.getMessage()]
            assert len(audit) <= verbatim and len(refusals) <= verbatim, (len(audit), len(refusals))
            assert p.counts["refused"] == 200
    finally:
        await p.close()                                                  # the minute's summary is written now
    summary = [d for t, d in audit if d.get("decision") == "summary"]
    assert len(summary) == 1 and summary[0]["count"] == 200 - verbatim
    assert sum(x["count"] for x in summary[0]["destinations"]) == 200 - verbatim
    assert len(summary[0]["destinations"]) <= eg.AUDIT_SUMMARY_TARGETS + 1


# ------------------------------------------------------------------ MX-5
async def test_mx5_member_strings_never_break_a_log_line(caplog):
    from goose_web.activity import clean_text
    audit = []
    p = await eg.EgressProxy("mallory", network="internet", audit=lambda u, t, d: audit.append((t, d))).start()
    try:
        with caplog.at_level(logging.DEBUG, logger="goose_web.egress"):
            forged = "x\n2026-11-12\t10.00.00,000\tERROR\tgoose_web.workers.\tworker\tbob\tforged"
            r = await _ask(p.port, f"CONNECT {forged}:443 HTTP/1.1\r\n{_auth(p)}\r\n")
            assert r.startswith(b"HTTP/1.1 400")
            r = await _ask(p.port, f"GET\x1b[2J http://a.example/ HTTP/1.1\r\n{_auth(p)}\r\n")
            assert r.startswith(b"HTTP/1.1 400")
            r = await _ask(p.port, f"CONNECT a.example:443 HTTP/1.1\tX\r\n{_auth(p)}\r\n")
            assert r.startswith(b"HTTP/1.1 400")
        for rec in caplog.records:
            msg = rec.getMessage()
            assert not any(ord(c) < 0x20 for c in msg), repr(msg)
        for t, d in audit:
            assert not any(ord(c) < 0x20 for c in t + json.dumps(d, ensure_ascii=False)), (t, d)
    finally:
        await p.close()
    assert clean_text("a\nb\x1b[31m\u2028\t", 100) == "a\\x0ab\\x1b[31m\\u2028\\x09"
    assert len(clean_text("x" * 5000, 50)) == 50
    out = mxc.explain_exit(1, 'noise\n{"error":{"code":"x\\ny","message":"evil\\r\\nERROR forged\\u001b[2J"}}')
    assert not any(ord(c) < 0x20 for c in out), out
    assert not any(ord(c) < 0x20 for c in mxc.explain_exit(7, "boom \x1b[2J\tlast"))


# ------------------------------------------------------------------ MX-6
@pytest.fixture
def grant_ctx(tmp_path):
    sysd = tmp_path / "Goose_Web_Profiles" / "_system"
    prof_root = tmp_path / "Goose_Web_Profiles"
    (sysd / "sandbox").mkdir(parents=True)
    (prof_root / "alice" / "workspace").mkdir(parents=True)
    (prof_root / "bob").mkdir()
    return dict(profile_root=str(prof_root / "alice"), profiles_root=str(prof_root), system_dir=str(sysd),
                protected_write=[], protected_any=[]), sysd, prof_root


def _short(p):
    import ctypes
    buf = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetShortPathNameW(str(p), buf, 1024)
    return buf.value


@WIN
@pytest.mark.parametrize("form", ["long", "trailing_dot", "short83", "extended", "extended_unc_localhost",
                                  "unc_admin_share", "forward_slashes", "globalroot", "extended_trailing_dot_space",
                                  "extended_upper", "extended_forward"])
def test_mx6_the_system_folder_in_any_spelling_is_refused(grant_ctx, form):
    c, sysd, _ = grant_ctx
    s = str(sysd)
    drive = s[0]
    path = {"long": s, "trailing_dot": s + ".", "short83": _short(sysd), "extended": "\\\\?\\" + s,
            "extended_unc_localhost": "\\\\?\\UNC\\localhost\\" + drive + "$" + s[2:],
            "unc_admin_share": "\\\\localhost\\" + drive + "$" + s[2:], "forward_slashes": s.replace("\\", "/"),
            "globalroot": "\\\\.\\" + s, "extended_trailing_dot_space": "\\\\?\\" + s + ". .",
            "extended_upper": "\\\\?\\" + s.upper(), "extended_forward": "//?/" + s.replace("\\", "/")}[form]
    for mode in ("modify", "read"):
        kept, refused = mxc.filter_grants({path: mode}, **c)
        assert not kept, f"{form}: {path!r} was KEPT as {kept}"


@WIN
def test_mx6_another_members_profile_in_extended_form_is_refused(grant_ctx):
    c, _, prof_root = grant_ctx
    for path in ("\\\\?\\" + str(prof_root / "bob"), "\\\\?\\" + str(prof_root / "bob") + ".",
                 "\\\\?\\" + str(prof_root)):
        kept, _ = mxc.filter_grants({path: "read"}, **c)
        assert not kept, path
    kept, _ = mxc.filter_grants({"\\\\?\\" + str(prof_root / "alice"): "modify"}, **c)
    assert list(kept.values()) == ["modify"] and not next(iter(kept)).startswith("\\\\")   # canonical form to MXC


def test_mx6_python_and_goose_folders_are_never_writable(tmp_path):
    goose_dir = tmp_path / "goosebin"
    goose_dir.mkdir()
    s = settings(tmp_path)
    s.data["goose"]["binary"] = str(goose_dir / "goose.exe")
    prot = mxc.protected_write_paths(s)
    norm = {os.path.normcase(p) for p in prot}
    for p in (sys.base_prefix, sys.prefix, os.path.dirname(sys.executable), str(goose_dir)):
        assert os.path.normcase(p) in norm, p
    (tmp_path / "profiles" / "alice").mkdir(parents=True)
    ctx = dict(profile_root=str(tmp_path / "profiles" / "alice"), profiles_root=str(tmp_path / "profiles"),
               system_dir=str(s.system_dir), protected_write=prot, protected_any=[])
    for p in (sys.base_prefix, os.path.join(sys.base_prefix, "Lib"), str(goose_dir)):
        assert "never writable" in mxc.grant_problem(p, "modify", **ctx), p
        assert mxc.grant_problem(p, "read", **ctx) == "", p                   # reading and running: fine


def test_mx6_read_dirs_naming_protected_folders_are_left_out_for_both_backends(tmp_path):
    from goose_web.auth import AuthService
    from goose_web.context import Ctx
    from goose_web.db import Database
    from goose_web.hub import Hub
    from goose_web.profiles import Profiles
    from goose_web.workers import WorkerManager
    from tests.test_team_profiles import user
    tools = tmp_path / "tools"
    tools.mkdir()
    s = settings(tmp_path, enabled=True)
    s.system_dir.mkdir(parents=True, exist_ok=True)
    bad = ["\\\\?\\" + str(s.system_dir), str(s.profiles_root), "\\\\localhost\\C$\\Windows"]
    s.data["sandbox"]["read_dirs"] = [str(tools), *bad]
    probs = dict(mxc.read_dir_problems(s))
    assert set(probs) == set(bad), probs
    db = Database(tmp_path / "gw.db")
    wm = WorkerManager(s)
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=wm, hub=Hub(wm), version="t")
    try:
        spec = c.sandbox_spec(user(db, "member1"))
        for grants in (spec["mxc_grants"], spec["grants"]):
            keys = {os.path.normcase(k) for k in grants}
            assert os.path.normcase(os.path.normpath(str(tools))) in keys
            assert not any(os.path.normcase(b.replace("\\\\?\\", "")) in keys for b in bad), keys
        assert {p["path"] for p in mxc.summary(s)["readDirProblems"]} == set(bad)
    finally:
        db.close()


# ------------------------------------------------------------------ MX-7
def test_mx7_a_sandbox_enabled_typo_fails_closed(tmp_path):
    for v in ("ture", "yes please", "enable", "Y", 2, "0n"):
        s = settings(tmp_path, enabled=v)
        assert sandbox_on(s) is True, v
        assert any("sandbox.enabled" in p for p in sandbox_config_problems(s)), v
    for v, want in (("auto", IS_WINDOWS), (None, IS_WINDOWS), ("", IS_WINDOWS), (True, True), ("false", False),
                    ("off", False), ("No", False), (0, False), (1, True), (" ON ", True), (False, False)):
        s = settings(tmp_path, enabled=v)
        assert sandbox_on(s) is want, v
        assert not any("sandbox.enabled" in p for p in sandbox_config_problems(s)), v
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "p")}}), None)   # key not set
    assert sandbox_on(s) is IS_WINDOWS and sandbox_config_problems(s) == []


async def test_mx7_a_member_worker_with_the_typo_does_not_start(tmp_path, monkeypatch):
    from goose_web.workers import SandboxUnavailable
    from tests.test_mxc import _manager, _spec
    wm, s, events = _manager(tmp_path, monkeypatch, enabled="ture")
    started = []
    monkeypatch.setattr(mxc, "launch", lambda *a, **k: started.append(a))
    spec = _spec(tmp_path, s, config_problems=sandbox_config_problems(s))
    wm.register("alice", "alice", None, False, [], sandbox=spec)
    with pytest.raises(SandboxUnavailable) as ei:
        await wm.ensure("alice")
    assert "sandbox.enabled" in ei.value.admin_reason and started == []
    await wm.shutdown()


# ------------------------------------------------------------------ MX-8
def _installed(tmp_path, monkeypatch):
    from tests.test_mxc import SIGNED, _fake_package
    tgz = _fake_package(tmp_path, monkeypatch)
    s = settings(tmp_path)
    mxc.install(s, file=str(tgz), log=lambda m: None, signature=lambda p: SIGNED)
    return s, tgz, mxc.exe_path(s)


def _record_starts(monkeypatch):
    started = []

    def fake(*a, **k):
        started.append(a)
        raise AssertionError("the executor must not be started")
    monkeypatch.setattr(subprocess, "Popen", fake)
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(mxc, "_HardenedPopen", fake, raising=False)
    return started


def test_mx8_a_file_next_to_the_executor_stops_every_launch(tmp_path, monkeypatch):
    from tests.test_mxc import SIGNED
    s, tgz, exe = _installed(tmp_path, monkeypatch)
    vdir = exe.parent
    assert mxc.folder_problem(vdir) == "" and mxc.verify_install(vdir) == ""
    (vdir / "userenv.dll").write_bytes(b"MZ planted")
    assert "userenv.dll" in mxc.folder_problem(vdir) and "userenv.dll" in mxc.verify_install(vdir)
    started = _record_starts(monkeypatch)
    with pytest.raises(mxc.MxcError, match="not part of the pinned executor"):
        mxc.launch(exe, tmp_path / "policy.json", None, [])
    data, problem = mxc.run_probe(exe)
    assert data == {} and "userenv.dll" in problem and started == []
    monkeypatch.undo()
    # availability says so (Admin > System, sandbox status) ...
    monkeypatch.setattr(mxc, "AVAILABILITY", mxc.Availability())
    monkeypatch.setattr(mxc, "IS_WINDOWS", True)
    monkeypatch.setattr(mxc, "windows_build", lambda: (26100, 9974))
    st = mxc.availability(s, refresh=True)
    assert not st["available"] and "userenv.dll" in st["reason"]
    # ... and install-mxc --if-missing repairs it (a fresh folder holding only the pinned files)
    from tests.test_mxc import _fake_package
    tgz = _fake_package(tmp_path, monkeypatch, exe=exe.read_bytes())
    mxc.install(s, file=str(tgz), if_missing=True, log=lambda m: None, signature=lambda p: SIGNED)
    assert sorted(p.name for p in vdir.iterdir()) == ["install.json", "wxc-exec.exe"]


def test_mx8_probe_runs_only_a_verified_executor(tmp_path, monkeypatch):
    s, tgz, exe = _installed(tmp_path, monkeypatch)
    data = bytearray(exe.read_bytes())
    data[50] ^= 0xFF
    exe.write_bytes(bytes(data))
    started = _record_starts(monkeypatch)
    out, problem = mxc.run_probe(exe)
    assert out == {} and "does not match the pinned" in problem and started == []


@WIN
def test_mx8_the_executor_is_created_with_image_load_mitigations(tmp_path):
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    p = mxc._HardenedPopen([cmd, "/c", "exit 0"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, creationflags=0x08000000 | 0x00000004, env=mxc.host_env())
    try:
        m = mxc.process_mitigations(p)
        assert m == {"microsoftSignedOnly": True, "noRemoteImages": True, "preferSystem32Images": True}, m
    finally:
        p.kill()
        p.communicate()


# ------------------------------------------------------------------ MX-9
@WIN
def test_mx9_a_kill_on_close_job_that_cannot_be_joined_fails_the_start(tmp_path, monkeypatch):
    real_popen = subprocess.Popen
    started = []
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")

    def fake(argv, **kw):
        p = real_popen([cmd, "/c", "ping -n 30 127.0.0.1 >nul"], stdin=kw.get("stdin"), stdout=kw.get("stdout"),
                       stderr=kw.get("stderr"), creationflags=kw.get("creationflags", 0))
        started.append(p)
        return p

    class Pinned:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def problem(self):
            return ""

        def close(self):
            pass
    monkeypatch.setattr(subprocess, "Popen", fake)
    monkeypatch.setattr(mxc, "_HardenedPopen", fake, raising=False)
    monkeypatch.setattr(mxc, "PinnedFile", Pinned)
    monkeypatch.setattr(mxc, "PinnedSet", Pinned, raising=False)
    monkeypatch.setattr(mxc, "verify_exe", lambda *a, **k: "")
    monkeypatch.setattr(mxc, "folder_problem", lambda v: "", raising=False)

    class NoJob:
        def add(self, proc):
            return False
    try:
        with pytest.raises(mxc.MxcError, match="kill-on-close job"):
            mxc.launch(tmp_path / "1.0.1" / "wxc-exec.exe", tmp_path / "p.json", subprocess.DEVNULL, [NoJob()])
        assert started and started[0].poll() is not None                      # killed, not left suspended
    finally:
        for p in started:
            if p.poll() is None:
                p.kill()


# ------------------------------------------------------------------ MX-10
async def test_mx10_the_proxy_credential_is_revoked_when_the_worker_stops(tmp_path, monkeypatch):
    from goose_web import api
    from tests.test_mxc import FAKE_AGENT, _manager, _spec
    wm, s, events = _manager(tmp_path, monkeypatch)
    monkeypatch.setattr(mxc, "launch", lambda exe, pf, err, jobs, desktop="": subprocess.Popen(
        [sys.executable, "-c", FAKE_AGENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err))
    wm.register("alice", "alice", None, False, [], sandbox=_spec(tmp_path, s, network="none"))
    try:
        await wm.ensure("alice")
        p = wm.proxies.proxies["alice"]
        user, tok = p.user, p.token
        req = "CONNECT 127.0.0.1:9 HTTP/1.1\r\n{}\r\n"
        assert (await _ask(p.port, req.format(_auth(p, tok, user)))).startswith(b"HTTP/1.1 403")   # accepted
        await wm.stop("alice")
        assert (await _ask(p.port, req.format(_auth(p, tok, user)))).startswith(b"HTTP/1.1 407")   # revoked
        await wm.ensure("alice")
        assert p.token != tok
        assert (await _ask(p.port, req.format(_auth(p, tok, user)))).startswith(b"HTTP/1.1 407")
        assert (await _ask(p.port, req.format(_auth(p)))).startswith(b"HTTP/1.1 403")
        # the user is deleted or no longer sandboxed: the proxy is closed

        class C:
            settings, workers = s, wm

            class db:
                @staticmethod
                def audit(*a, **k):
                    pass
        await api._drop_sandbox(C, {"id": 1, "username": "Alice"})
        assert "alice" not in wm.proxies.proxies and p.server is None
    finally:
        await wm.shutdown()


# ------------------------------------------------------------------ MX-11
def test_mx11_cloud_metadata_site_local_and_tunnel_addresses_are_refused():
    for a in ("fec0::1", "FEC0::1", "168.63.129.16", "100.100.100.200", "fd00:ec2::254", "192.0.0.192",
              "169.254.170.2", "2002:7f00:1::1", "2002:a00:5::1", "2002:8c52:7003::1",
              "2001:0:4136:e378:8000:63bf:3fff:fdd2", "0.1.2.3", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
              "64:ff9b:1::a00:1", "::a00:5"):
        assert eg.classify(a) in ("blocked", "loopback"), a
    assert eg.classify("64:ff9b::8c52:7003") == "public"                    # NAT64 of a public address
    assert eg.classify("64:ff9b::c0a8:114") == "lan"                        # NAT64 of 192.168.1.20


# ------------------------------------------------------------------ MX-12
async def test_mx12_malformed_and_over_long_host_names_get_a_400():
    looked = []

    async def resolver(host, port):
        looked.append(host)
        raise OSError("no")
    p = await eg.EgressProxy("alice", network="internet", resolver=resolver, audit=_noop).start()
    try:
        for host in ("a" * 64 + ".example.com", "a" * 7000 + ".example.com", "x..y.example", "-bad.example",
                     ("a" * 60 + ".") * 5 + "com", "ex%ample.com"):
            r = await _ask(p.port, f"CONNECT {host}:443 HTTP/1.1\r\n{_auth(p)}\r\n")
            assert r.startswith(b"HTTP/1.1 400"), (host[:40], r[:60])
        r = await _ask(p.port, f"GET http://{'b' * 70}.example/x HTTP/1.1\r\n{_auth(p)}\r\n")
        assert r.startswith(b"HTTP/1.1 400")
        assert looked == []
        assert eg.host_problem("api.example.org") == "" and eg.host_problem("xn--bcher-kva.example") == "" \
            and eg.host_problem("b\u00fccher.example") == "" and eg.host_problem("fe80::1%12") == ""
    finally:
        await p.close()


# ------------------------------------------------------------------ MX-13 / MX-14
def test_mx13_docs_say_a_relay_forwards_everything_on_its_port():
    root = Path(__file__).resolve().parent.parent / "docs"
    for doc in ("ADMINISTRATION.md", "SECURITY-ASSESSMENT.md"):
        text = (root / doc).read_text(encoding="utf-8")
        assert "forwards everything" in text and "virtual host" in text, doc


def test_mx14_docs_match_the_code():
    assert not hasattr(mxc, "redacted")
    doc = mxc.__doc__
    assert "install folder are refused" not in doc and "for writing" in doc
    src = Path(mxc.__file__).read_text(encoding="utf-8")
    assert "(restricted) ACL" not in src
