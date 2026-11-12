"""Spec 025: the MXC sandbox backend - settings, pinned executor, probe, policy builder, worker start paths."""
import asyncio
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from goose_web import config as cfgmod
from goose_web import mxc
from goose_web.config import DEFAULTS, Settings, _deep_merge

GOOD_PROBE = {"tier": "base-container", "needsDaclAugmentation": False, "warnings": [], "probes": {
    "baseContainerApiPresent": True, "baseContainerSupportsDenyPaths": True,
    "baseContainerSupportsEnumeratePaths": True, "baseContainerSupportsIngressHostLoopbackAllow": True,
    "baseContainerSupportsIdentitylessLoopbackProxy": True,
    "uiCapabilities": {"canBlockClipboardRead": True, "canBlockClipboardWrite": True, "canBlockInputInjection": True}}}
SIGNED = {"status": "Valid", "subject": mxc.MXC_PIN["signer"]}


def settings(tmp_path, **sandbox) -> Settings:
    data = _deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path / "profiles")},
                                  "sandbox": {"mxc_dir": str(tmp_path / "inst" / "vendor" / "mxc"), **sandbox}})
    return Settings(data, None)


@pytest.fixture(autouse=True)
def _fresh_availability(monkeypatch):
    monkeypatch.setattr(mxc, "AVAILABILITY", mxc.Availability())


# ------------------------------------------------------------------ settings
def test_config_defaults_and_validation(tmp_path):
    assert DEFAULTS["sandbox"]["backend"] == "mxc" and DEFAULTS["sandbox"]["fallback"] == "none"
    s = settings(tmp_path)
    assert cfgmod.sandbox_backend(s) == "mxc" and cfgmod.sandbox_fallback(s) == "none"
    assert cfgmod.sandbox_config_problems(s) == []
    s = settings(tmp_path, backend="AppContainer", fallback="appcontainer")
    assert cfgmod.sandbox_backend(s) == "appcontainer" and cfgmod.sandbox_fallback(s) == "appcontainer"
    s = settings(tmp_path, backend="mcx", fallback="off", network="lan", proxy_max_connections=0,
                 proxy_idle_seconds="x")
    assert cfgmod.sandbox_backend(s) == "invalid" and cfgmod.sandbox_fallback(s) == "invalid"
    probs = " | ".join(cfgmod.sandbox_config_problems(s))
    for word in ("sandbox.backend", "sandbox.fallback", "sandbox.network", "proxy_max_connections",
                 "proxy_idle_seconds"):
        assert word in probs


# ------------------------------------------------------------------ pinned package / install
def _fake_package(tmp_path, monkeypatch, exe: bytes = b"MZ" + os.urandom(4000)) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("package/package.json", b"{}"), (mxc.MXC_PIN["member"], exe),
                           ("package/bin/x64/mxc_ffi.dll", b"dll")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    tgz = tmp_path / "mxc-sdk.tgz"
    tgz.write_bytes(buf.getvalue())
    monkeypatch.setitem(mxc.MXC_PIN, "size", tgz.stat().st_size)
    monkeypatch.setitem(mxc.MXC_PIN, "integrity",
                        "sha512-" + base64.b64encode(hashlib.sha512(tgz.read_bytes()).digest()).decode())
    monkeypatch.setitem(mxc.MXC_PIN, "exe_sha256", hashlib.sha256(exe).hexdigest())
    monkeypatch.setitem(mxc.MXC_PIN, "exe_size", len(exe))
    return tgz


def test_install_from_file_verifies_and_is_idempotent(tmp_path, monkeypatch):
    tgz = _fake_package(tmp_path, monkeypatch)
    s = settings(tmp_path)
    out = []
    rec = mxc.install(s, file=str(tgz), log=out.append, signature=lambda p: SIGNED)
    exe = mxc.exe_path(s)
    assert exe.is_file() and mxc.verify_exe(exe) == "" and rec["sha256"] == mxc.MXC_PIN["exe_sha256"]
    assert json.loads((exe.parent / "install.json").read_text())["contract"] == "1.0.0"
    assert sorted(p.name for p in exe.parent.iterdir()) == ["install.json", "wxc-exec.exe"]   # only the executor
    assert [p.name for p in mxc.mxc_dir(s).iterdir()] == [mxc.MXC_PIN["version"]]          # no stage/old left
    out.clear()
    mxc.install(s, file=str(tgz), if_missing=True, log=out.append, signature=lambda p: SIGNED)
    assert "nothing to do" in out[0]
    # a bad signature never installs (and an installed executor with a bad signature is replaced only by a good one)
    with pytest.raises(mxc.MxcError, match="signature"):
        mxc.install(s, file=str(tgz), force=True, log=out.append, signature=lambda p: {"status": "HashMismatch",
                                                                                      "subject": ""})
    with pytest.raises(mxc.MxcError, match="signed by"):
        mxc.install(s, file=str(tgz), force=True, log=out.append,
                    signature=lambda p: {"status": "Valid", "subject": "CN=Someone Else"})
    assert mxc.verify_exe(exe) == "" and [p.name for p in mxc.mxc_dir(s).iterdir()] == [mxc.MXC_PIN["version"]]


def test_install_refuses_a_package_that_does_not_match_the_pin(tmp_path, monkeypatch):
    tgz = _fake_package(tmp_path, monkeypatch)
    s = settings(tmp_path)
    good = tgz.read_bytes()
    bad = tmp_path / "bad.tgz"
    bad.write_bytes(good[:-1] + bytes([good[-1] ^ 1]))                          # same size, other bytes
    with pytest.raises(mxc.MxcError, match="integrity mismatch"):
        mxc.install(s, file=str(bad), log=lambda m: None, signature=lambda p: SIGNED)
    with pytest.raises(mxc.MxcError, match="bytes; the pinned package"):
        mxc.install(s, file=str(tmp_path / "x.tgz") if (tmp_path / "x.tgz").write_bytes(b"x") else "",
                    log=lambda m: None, signature=lambda p: SIGNED)
    # right package integrity, but the executor inside is not the pinned one
    monkeypatch.setitem(mxc.MXC_PIN, "exe_sha256", "0" * 64)
    with pytest.raises(mxc.MxcError, match="does not match the pinned"):
        mxc.install(s, file=str(tgz), log=lambda m: None, signature=lambda p: SIGNED)
    assert not mxc.exe_path(s).exists()
    assert not [p for p in mxc.mxc_dir(s).iterdir()]                              # stage folders removed


def test_install_target_must_be_a_folder_of_its_own(tmp_path):
    for d in (tmp_path / "profiles", tmp_path / "profiles" / "_system" / "mxc", tmp_path, Path("C:\\")):
        s = settings(tmp_path, mxc_dir=str(d))
        assert mxc.target_problem(s, mxc.mxc_dir(s)), d
    s = settings(tmp_path)
    assert mxc.target_problem(s, mxc.mxc_dir(s)) == ""


def test_tampered_executor_is_never_launched(tmp_path, monkeypatch):
    tgz = _fake_package(tmp_path, monkeypatch)
    s = settings(tmp_path)
    mxc.install(s, file=str(tgz), log=lambda m: None, signature=lambda p: SIGNED)
    exe = mxc.exe_path(s)
    data = bytearray(exe.read_bytes())
    data[100] ^= 0xFF                                                             # same size, one byte changed
    exe.write_bytes(bytes(data))
    assert "does not match the pinned" in mxc.verify_exe(exe)
    started = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(a))
    with pytest.raises(mxc.MxcError, match="does not match the pinned"):
        mxc.launch(exe, tmp_path / "policy.json", None, [])
    assert started == [] and mxc.AVAILABILITY._state["available"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="share modes are Windows-only")
def test_pinned_handle_denies_writes_until_closed(tmp_path):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"0" * 100)
    with mxc.PinnedFile(f) as pf:
        assert pf.sha256()[1] == 102
        with pytest.raises(PermissionError):
            open(f, "r+b")
        with pytest.raises(PermissionError):
            os.replace(tmp_path / "x.exe", tmp_path / "y.exe")
        assert open(f, "rb").read(2) == b"MZ"                                     # readers are fine
    open(f, "r+b").close()


# ------------------------------------------------------------------ probe / build / availability
def test_probe_and_build_requirements():
    assert mxc.probe_problems(GOOD_PROBE) == []
    assert "tier" in mxc.probe_problems({**GOOD_PROBE, "tier": "dacl-augmented"})[0]
    bad = json.loads(json.dumps(GOOD_PROBE))
    bad["probes"]["baseContainerSupportsIdentitylessLoopbackProxy"] = False
    del bad["probes"]["uiCapabilities"]["canBlockInputInjection"]
    msg = mxc.probe_problems(bad)[0]
    assert "IdentitylessLoopbackProxy" in msg and "canBlockInputInjection" in msg
    assert mxc.probe_problems({}) and mxc.build_problem((0, 0))
    assert mxc.build_problem((26100, 9277)) and mxc.build_problem((22631, 9999))
    assert mxc.build_problem((26100, 9278)) == "" and mxc.build_problem((26200, 1)) == ""


def test_availability_is_computed_once_and_rechecked_after_a_failure(tmp_path, monkeypatch):
    s = settings(tmp_path)
    calls = {"probe": 0}

    def probe(exe, timeout=30):
        calls["probe"] += 1
        return dict(GOOD_PROBE), ""
    monkeypatch.setattr(mxc, "IS_WINDOWS", True)
    monkeypatch.setattr(mxc, "windows_build", lambda: (26100, 9974))
    monkeypatch.setattr(mxc, "verify_install", lambda vdir: "")
    monkeypatch.setattr(mxc, "authenticode", lambda p, timeout=60: SIGNED)
    monkeypatch.setattr(mxc, "run_probe", probe)
    st = mxc.availability(s)
    assert st["available"] and st["probe"]["tier"] == "base-container" and st["build"] == "26100.9974"
    mxc.availability(s)
    assert calls["probe"] == 1                                                    # cached
    mxc.AVAILABILITY.invalidate()
    monkeypatch.setattr(mxc, "run_probe", lambda exe, timeout=30: ({}, "wxc-exec --probe did not answer"))
    assert mxc.availability(s)["reason"] == "wxc-exec --probe did not answer"
    monkeypatch.setattr(mxc, "run_probe", probe)
    assert not mxc.availability(s)["available"]                                   # failure cached for a while
    monkeypatch.setattr(mxc, "RECHECK_FAILED_SECONDS", 0)
    assert mxc.availability(s)["available"]                                       # then checked again
    monkeypatch.setattr(mxc, "windows_build", lambda: (26100, 1000))
    assert "older than 26100.9278" in mxc.availability(s, refresh=True)["reason"]
    s2 = settings(tmp_path, backend="nope")
    assert "sandbox.backend" in mxc.availability(s2, refresh=True)["reason"]
    sm = mxc.summary(s2)
    assert sm["membersCanStart"] is False and "sandbox.backend" in sm["reason"]


def test_summary_fallback_and_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(mxc, "availability", lambda s, refresh=False: {
        "available": False, "reason": "wxc-exec.exe is not installed", "exe": "x", "version": "1.0.1",
        "contract": "1.0.0", "build": "26100.1", "probe": {}, "signature": {}, "checkedAt": 0})
    s = settings(tmp_path, enabled=True)
    assert mxc.summary(s)["membersCanStart"] is False
    sm = mxc.summary(settings(tmp_path, enabled=True, fallback="appcontainer"))
    assert sm["membersCanStart"] is True and "AppContainer fallback" in sm["reason"]
    assert mxc.summary(settings(tmp_path, enabled=True, backend="appcontainer"))["membersCanStart"] is True


# ------------------------------------------------------------------ policy builder
def _layout(tmp_path):
    pr = tmp_path / "profiles"
    for d in (pr / "_system", pr / "alice" / "workspace", pr / "bob", pr / "_teams" / "1", tmp_path / "code" / "goose_web",
              tmp_path / "native", tmp_path / "tools" / "py", tmp_path / "goose"):
        d.mkdir(parents=True, exist_ok=True)
    return {"profile_root": str(pr / "alice"), "profiles_root": str(pr), "system_dir": str(pr / "_system"),
            "protected_write": [str(tmp_path / "code" / "goose_web")], "protected_any": [str(tmp_path / "native")]}


def test_grant_filter_refuses_the_gateways_folders(tmp_path):
    ctx = _layout(tmp_path)
    pr = Path(ctx["profiles_root"])
    grants = {str(pr / "alice"): "modify", str(pr / "_teams" / "1"): "modify", str(tmp_path / "tools" / "py"): "read",
              str(tmp_path / "goose"): "read", str(pr / "bob"): "modify", str(pr / "bob" / "x"): "read",
              str(pr): "read", str(pr / "_system"): "modify", str(pr / "_system" / "logs"): "read",
              str(tmp_path): "read", "C:\\": "read", "relative\\dir": "modify",
              str(tmp_path / "code"): "modify", str(tmp_path / "code" / "goose_web" / "sub"): "modify",
              str(tmp_path / "native" / "config"): "read"}
    kept, refused = mxc.filter_grants(grants, **ctx)
    why = {os.path.normcase(p): w for p, w in refused}
    assert {os.path.normcase(k) for k in kept} == {os.path.normcase(os.path.realpath(p)) for p in (
        pr / "alice", pr / "_teams" / "1", tmp_path / "tools" / "py", tmp_path / "goose")}
    assert "another member" in why[os.path.normcase(str(pr / "bob"))]
    assert "above it" in why[os.path.normcase(str(pr))] and "above it" in why[os.path.normcase(str(tmp_path))]
    other_sys = {**ctx, "system_dir": str(tmp_path / "elsewhere" / "_system")}       # system folder elsewhere
    assert "profiles root" in mxc.grant_problem(str(pr), "read", **other_sys)
    assert "system folder" in why[os.path.normcase(str(pr / "_system" / "logs"))]
    assert "drive or share root" in why[os.path.normcase("C:\\")] and "absolute" in why[os.path.normcase("relative\\dir")]
    assert "never writable" in why[os.path.normcase(str(tmp_path / "code"))]
    assert "native" in why[os.path.normcase(str(tmp_path / "native" / "config"))]
    # the install folder may be read (program folders), just never written
    kept, _ = mxc.filter_grants({str(tmp_path / "code"): "read"}, **ctx)
    assert kept


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
def test_grant_through_a_junction_into_the_system_folder_is_refused(tmp_path):
    ctx = _layout(tmp_path)
    link = Path(ctx["profile_root"]) / "workspace" / "sys"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), ctx["system_dir"]], check=True, capture_output=True)
    try:
        kept, refused = mxc.filter_grants({str(link): "modify"}, **ctx)
        assert not kept and "system folder" in refused[0][1]
    finally:
        os.rmdir(link)


def test_policy_is_deterministic_and_locked_down(tmp_path):
    grants = {"D:\\Team Share\\x": "modify", str(tmp_path / "p"): "modify", "C:\\Tools\\Py": "read"}
    env = {"PATH": "C:\\Windows\\System32", "HTTPS_PROXY": "http://evil", "no_proxy": "*", "GOOSE_PATH_ROOT": "C:\\p",
           "LOCALAPPDATA": "C:\\LA"}
    kw = dict(command=["C:\\Program Files\\Goose\\goose.exe", "acp"], cwd=str(tmp_path / "p"), env=env, grants=grants,
              proxy_url="http://gw-1:tok@127.0.0.1:5555", system_drive="C:")
    a, b = mxc.build_policy(**kw), mxc.build_policy(**kw)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["version"] == "1.0.0" and a["containment"] == "processcontainer"
    pr = a["process"]
    assert pr["commandLine"] == '"C:\\Program Files\\Goose\\goose.exe" acp' and pr["inheritDefaultEnv"] is False
    assert not any(e.upper().startswith(("HTTPS_PROXY=", "NO_PROXY=")) for e in pr["env"])
    assert "NODE_USE_ENV_PROXY=1" in pr["env"] and "LOCALAPPDATA=C:\\LA" in pr["env"]
    assert a["filesystem"] == {"readwritePaths": sorted(["D:\\Team Share\\x", str(tmp_path / "p")], key=os.path.normcase),
                               "readonlyPaths": ["C:\\Tools\\Py"]}
    assert a["network"] == {"egress": {"default": "deny"}, "ingress": {"default": "allow", "hostLoopback": "allow"}}
    assert a["runtimeConfig"] == {"networkProxy": "http://gw-1:tok@127.0.0.1:5555"}
    assert a["ui"] == {"disable": False, "clipboard": "none", "injection": False}
    pc = a["processContainer"]
    assert pc["ui"] == {"desktopSystemControl": False, "systemSettings": "none", "ime": False}
    assert "C:\\" in pc["filesystem"]["enumeratePaths"] and "D:\\" in pc["filesystem"]["enumeratePaths"]
    assert "telemetry" not in json.dumps(a)
    none = mxc.build_policy(**{**kw, "proxy_url": ""})
    assert none["network"] == {"egress": {"default": "deny"}, "ingress": {"default": "deny", "hostLoopback": "deny"}}
    assert "runtimeConfig" not in none and "NODE_USE_ENV_PROXY=1" not in none["process"]["env"]
    assert not hasattr(mxc, "redacted")                                           # MX-14: dead code removed
    pf = tmp_path / "sys" / "sandbox" / "mxc" / "x.json"
    mxc.write_policy(pf, a)
    assert json.loads(pf.read_text(encoding="utf-8")) == a and [p.name for p in pf.parent.iterdir()] == ["x.json"]


def test_explain_exit():
    js = '{"error":{"code":"policy_validation","message":"missing LOCALAPPDATA"}}'
    assert mxc.explain_exit(1, "noise\n" + js + "\n") == \
        "MXC refused to start the sandbox (policy_validation): missing LOCALAPPDATA"
    assert "Win32k" in mxc.explain_exit(0xC0000142, "")
    assert "Win32k" in mxc.explain_exit(-1073741502, "")                          # the same code, signed
    assert mxc.explain_exit(7, "boom\nlast line") == "wxc-exec exited with code 7: last line"


# ------------------------------------------------------------------ workers
FAKE_AGENT = r"""
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" in m and "method" in m:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": 1}}) + "\n")
        sys.stdout.flush()
"""


def _spec(tmp_path, s, backend="mxc", **extra):
    ctx = _layout(tmp_path)
    return {"name": "GooseWeb.t.alice.x", "profile_root": ctx["profile_root"], "relays": [], "grants": {},
            "caps": [], "backend": backend, "config_problems": [], "network": "internet",
            "relay_targets": ["127.0.0.1:8317"], "mxc_grants": {ctx["profile_root"]: "modify",
                                                                 str(tmp_path / "goose"): "read",
                                                                 ctx["system_dir"]: "modify"},
            "profiles_root": ctx["profiles_root"], "system_dir": str(s.system_dir),
            "protected_write": ctx["protected_write"], "protected_any": ctx["protected_any"], **extra}


def _manager(tmp_path, monkeypatch, available=True, **sandbox):
    from goose_web.workers import WorkerManager
    s = settings(tmp_path, **sandbox)
    s.data["goose"]["binary"] = str(tmp_path / "goose" / "goose.exe")
    monkeypatch.setattr(mxc, "availability", lambda st, refresh=False: {
        "available": available, "reason": "" if available else "wxc-exec.exe is not installed (run: goose-web "
                                                                "sandbox install-mxc)"})
    wm = WorkerManager(s)
    events = []
    wm.on_sandbox_event = lambda action, w, detail: events.append((action, w.key, detail))
    return wm, s, events


async def test_mxc_unavailable_fails_closed(tmp_path, monkeypatch):
    from goose_web.workers import SandboxUnavailable
    wm, s, events = _manager(tmp_path, monkeypatch, available=False)
    w = wm.register("alice", "alice", None, False, [], sandbox=_spec(tmp_path, s))
    w.path_root = w.sandbox["profile_root"]
    started = []
    monkeypatch.setattr(wm, "_start_appcontainer", lambda w: started.append(w))
    monkeypatch.setattr(mxc, "launch", lambda *a, **k: started.append(a))
    with pytest.raises(SandboxUnavailable) as ei:
        await wm.ensure("alice")
    assert str(ei.value) == mxc.SANDBOX_UNAVAILABLE_MSG and "not installed" in ei.value.admin_reason
    assert w.state == "crashed" and "sandbox unavailable (MXC)" in w.last_error and started == []
    assert events == [("sandbox.unavailable", "alice", {"reason": w.last_error})]
    with pytest.raises(SandboxUnavailable):                                       # again: not audited twice
        await wm.ensure("alice")
    assert len(events) == 1
    # an invalid configuration fails closed too, whatever the backend
    w.sandbox = _spec(tmp_path, s, backend="invalid", config_problems=["sandbox.backend is 'x'"])
    with pytest.raises(SandboxUnavailable):
        await wm.ensure("alice")
    assert "sandbox.backend is 'x'" in w.last_error and started == []
    await wm.shutdown()


async def test_mxc_unavailable_with_fallback_starts_appcontainer(tmp_path, monkeypatch):
    wm, s, events = _manager(tmp_path, monkeypatch, available=False, fallback="appcontainer")
    w = wm.register("alice", "alice", None, False, [], sandbox=_spec(tmp_path, s))
    started = []

    async def fake_ac(w):
        started.append(w.key)
        w.backend, w.state = "appcontainer", "ready"
        w.proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    monkeypatch.setattr(wm, "_start_appcontainer", fake_ac)
    await wm.ensure("alice")
    assert started == ["alice"] and events[0][0] == "sandbox.fallback" and events[0][2]["to"] == "appcontainer"
    assert w.describe()["sandboxBackend"] == "appcontainer"
    # MXC becomes available: the fallback worker is marked for a restart (done by the monitor when no run is active)
    assert await wm._back_to_mxc(w) is False
    monkeypatch.setattr(mxc, "availability", lambda st, refresh=False: {"available": True, "reason": ""})
    assert await wm._back_to_mxc(w) is True and w.restart_pending
    w.proc.kill()
    await wm.shutdown()


def test_backend_switch_marks_a_running_worker_for_restart(tmp_path, monkeypatch):
    wm, s, _ = _manager(tmp_path, monkeypatch)
    spec = _spec(tmp_path, s)
    w = wm.register("alice", "alice", None, False, [], sandbox=spec)
    w.state = "ready"
    wm.register("alice", "alice", None, False, [], sandbox=dict(spec))
    assert not w.restart_pending                                                  # same spec: nothing to do
    wm.register("alice", "alice", None, False, [], sandbox={**spec, "backend": "appcontainer"})
    assert w.restart_pending


async def test_mxc_worker_starts_talks_and_stops(tmp_path, monkeypatch):
    wm, s, events = _manager(tmp_path, monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "gateway-secret-value")
    spec = _spec(tmp_path, s)
    w = wm.register("alice", "alice", None, False, [], sandbox=spec)
    w.path_root = spec["profile_root"]
    # an earlier AppContainer relay rewrite is undone for an MXC member (R7)
    cfgd = Path(spec["profile_root"]) / "config"
    cfgd.mkdir(parents=True, exist_ok=True)
    (cfgd / "config.yaml").write_text("OPENAI_HOST: http://127.64.0.2:8317\n", encoding="utf-8")
    (s.system_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    (s.system_dir / "sandbox" / f"{spec['name']}.relays.json").write_text(
        json.dumps({"127.0.0.1:8317": "127.64.0.2:8317"}), encoding="utf-8")
    launched = []

    def fake_launch(exe, policy_file, stderr_file, jobs):
        launched.append(json.loads(Path(policy_file).read_text(encoding="utf-8")))
        return subprocess.Popen([sys.executable, "-c", FAKE_AGENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=stderr_file)
    monkeypatch.setattr(mxc, "launch", fake_launch)
    await wm.ensure("alice")
    assert w.state == "ready" and w.backend == "mxc" and w.transport == "stdio" and w.proxy_port
    assert (cfgd / "config.yaml").read_text(encoding="utf-8") == "OPENAI_HOST: http://127.0.0.1:8317\n"
    pol = launched[0]
    assert pol["runtimeConfig"]["networkProxy"].endswith(f"@127.0.0.1:{w.proxy_port}")
    assert os.path.realpath(spec["profile_root"]) in pol["filesystem"]["readwritePaths"]
    assert not any("_system" in p for p in pol["filesystem"]["readwritePaths"])   # refused grant dropped
    assert "gateway-secret-value" not in json.dumps(pol)                          # allow-listed env only
    assert any(e.startswith("GOOSE_PATH_ROOT=") for e in pol["process"]["env"])
    await w.channel.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
    got = await asyncio.wait_for(w.channel.__aiter__().__anext__(), 10)
    assert json.loads(got)["result"] == {"protocolVersion": 1}
    assert w.describe()["sandboxBackend"] == "mxc" and Path(w.policy_file).is_file()
    port, url = w.proxy_port, pol["runtimeConfig"]["networkProxy"]
    pf = Path(w.policy_file)
    await wm.restart("alice")                                                     # crash/restart parity
    assert w.state == "ready" and w.proxy_port == port                            # the proxy survives restarts
    assert launched[1]["runtimeConfig"]["networkProxy"] != url                    # with a new credential
    await wm.stop("alice")
    assert not pf.exists() and w.state == "stopped"                               # policy file removed on stop
    assert "alice" in wm.proxies.proxies
    await wm.shutdown()
    assert wm.proxies.proxies == {}


async def test_mxc_early_exit_is_explained(tmp_path, monkeypatch):
    from goose_web.workers import SandboxUnavailable
    wm, s, events = _manager(tmp_path, monkeypatch)
    spec = _spec(tmp_path, s, network="none", relay_targets=[])
    w = wm.register("alice", "alice", None, False, [], sandbox=spec)
    code = ("import sys; sys.stderr.write('{\"error\":{\"code\":\"policy_validation\",\"message\":\"bad path\"}}\\n');"
            "sys.stderr.flush(); sys.exit(1)")
    monkeypatch.setattr(mxc, "launch", lambda exe, pf, err, jobs: subprocess.Popen(
        [sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err))
    with pytest.raises(SandboxUnavailable):
        await wm.ensure("alice")
    assert "MXC refused to start the sandbox (policy_validation): bad path" in w.last_error
    assert w.proxy_port == 0 and "alice" not in wm.proxies.proxies                # network none: no proxy
    await wm.shutdown()


def test_stale_policy_files_are_removed_at_start(tmp_path, monkeypatch):
    from goose_web.workers import WorkerManager
    s = settings(tmp_path)
    d = s.system_dir / "sandbox" / "mxc"
    d.mkdir(parents=True)
    (d / "GooseWeb.x.json").write_text("{}", encoding="utf-8")
    WorkerManager(s)
    assert list(d.iterdir()) == []


def test_admin_system_shows_the_sandbox(tmp_path, monkeypatch):
    from tests.test_team_profiles import client_for, sign_in, user
    from goose_web.auth import AuthService
    from goose_web.context import Ctx
    from goose_web.db import Database
    from goose_web.hub import Hub
    from goose_web.profiles import Profiles
    from goose_web.workers import WorkerManager
    s = settings(tmp_path, enabled=True)
    monkeypatch.setattr(mxc, "availability", lambda st, refresh=False: {
        "available": False, "reason": "probe tier is 'none'", "exe": "x", "version": "1.0.1", "contract": "1.0.0",
        "build": "26100.9974", "probe": {"tier": "none"}, "signature": {}, "checkedAt": 0})
    db = Database(tmp_path / "gw.db")
    wm = WorkerManager(s)
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=wm, hub=Hub(wm),
            version="t")
    admin = user(db, "root", role="admin")
    with client_for(c) as tc:
        sign_in(tc, c, admin)
        r = tc.get("/api/admin/system")
        assert r.status_code == 200, r.text
        sb = r.json()["sandbox"]
    assert sb["backend"] == "mxc" and sb["membersCanStart"] is False and "probe tier" in sb["reason"]
    assert sb["mxc"]["build"] == "26100.9974" and sb["proxies"] == {}
    db.close()
