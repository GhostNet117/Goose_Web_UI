"""Spec 015: built-in HTTPS (local CA, renewal, hot reload, live gateway over https), user activity log, log budget."""
import asyncio
import json
import os
import socket
import ssl
import subprocess
import sys
import time

import httpx
import pytest

from goose_web import activity, logjanitor, tls
from goose_web.config import load_settings
from goose_web.db import Database


@pytest.fixture
def settings(tmp_path, monkeypatch):
    (tmp_path / "empty.yaml").write_text("{}\n", encoding="utf-8")       # a missing file would fall back to a real one
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "empty.yaml"))
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    s = load_settings()
    s.system_dir.mkdir(parents=True, exist_ok=True)
    return s


# ------------------------------------------------------------------ TLS
def test_tls_modes(settings):
    assert tls.configured(settings)["effective"] == "self-signed"                  # auto, no public URL
    settings.data["server"]["public_url"] = "https://goose.example.org"
    assert tls.configured(settings)["effective"] == "off"                          # auto behind a proxy
    assert tls.configured(settings, {"mode": "self-signed"})["source"] == "admin"   # Admin UI wins
    assert tls.configured(settings, {"mode": "self-signed"})["effective"] == "self-signed"
    settings.data["server"]["tls"] = "false"
    assert tls.configured(settings)["effective"] == "off"
    settings.data["server"]["tls"] = "bogus"
    with pytest.raises(ValueError):
        tls.configured(settings)


def test_certificate_names_and_renewal(settings, monkeypatch):
    st = tls.ensure(settings)
    assert st["renewed"] and st["reason"] == "new CA"
    cert = st["cert"]
    assert "localhost" in cert["dns"] and "127.0.0.1" in cert["ips"] and "::1" in cert["ips"]
    assert socket.gethostname().lower() in cert["dns"]
    assert 85 <= cert["daysLeft"] <= 90 and st["ca"]["daysLeft"] > 3000
    ca_fp = st["ca"]["sha256"]
    assert not tls.ensure(settings)["renewed"]                                     # nothing to do
    settings.data["server"]["tls_names"] = ["goose.lan", "10.20.30.40"]
    st2 = tls.ensure(settings)
    assert st2["renewed"] and "goose.lan" in st2["reason"] and "10.20.30.40" in st2["cert"]["ips"]
    monkeypatch.setattr(tls, "RENEW_DAYS", 120)                                    # now "about to expire"
    st3 = tls.ensure(settings)
    assert st3["renewed"] and st3["reason"].startswith("expires in")
    assert st3["ca"]["sha256"] == ca_fp                                            # the CA stays: trust survives renewals
    assert st3["cert"]["sha256"] != st2["cert"]["sha256"]


async def test_renewed_certificate_is_loaded_without_restart(settings):
    tls.ensure(settings)
    d = tls.tls_dir(settings)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "server.crt", d / "server.key")
    tls.activate(ctx, "self-signed", str(d / "server.crt"), str(d / "server.key"))
    try:
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        client = ssl.create_default_context(cafile=str(d / "ca.crt"))

        async def serial():
            _, w = await asyncio.open_connection("localhost", port, ssl=client, server_hostname="localhost")
            der = w.get_extra_info("ssl_object").getpeercert(binary_form=True)
            w.close()
            return der
        first = await serial()
        tls.ensure(settings, force=True)
        assert tls.reload_active()
        assert await serial() != first                                             # new connections, new certificate
        server.close()
        await server.wait_closed()
    finally:
        tls.activate(None, "off", "", "")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_gateway_serves_https_on_localhost(tmp_path):
    """A real gateway with the built-in certificate: localhost and 127.0.0.1 verify against the local CA,
    the CA is downloadable, and the session cookie is the Secure __Host- variant."""
    port = _free_port()
    root = tmp_path / "profiles"
    cfg = tmp_path / "config.yaml"
    # allow_elevated: CI's Windows runners are elevated, and the gateway refuses to run elevated by default.
    cfg.write_text(f'server:\n  host: "127.0.0.1"\n  port: {port}\n  tls: self-signed\n  allow_elevated: true\n'
                   f'paths:\n  profiles_root: "{root.as_posix()}"\n'
                   'goose:\n  binary: ""\nsandbox:\n  enabled: false\n', encoding="utf-8")
    run = [sys.executable, "-m", "goose_web", "--config", str(cfg)]
    pw = "Tls-Test-Password-2468!"
    subprocess.run(run + ["init", "--admin", "boss", "--password", pw], check=True, capture_output=True)
    out = tmp_path / "serve.out"
    p = subprocess.Popen(run + ["serve"], stdout=open(out, "wb"), stderr=subprocess.STDOUT)
    ca = root / "_system" / "tls" / "ca.crt"
    try:
        for _ in range(150):
            if p.poll() is not None:
                pytest.fail("gateway exited: " + out.read_text(errors="replace")[-2000:])
            if ca.exists():
                try:
                    if httpx.get(f"https://localhost:{port}/healthz", verify=str(ca), timeout=2).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
            time.sleep(0.2)
        for host in ("localhost", "127.0.0.1"):
            r = httpx.get(f"https://{host}:{port}/healthz", verify=str(ca), timeout=5)
            assert r.status_code == 200 and r.text == "ok"
        r = httpx.get(f"https://localhost:{port}/tls/ca.crt", verify=str(ca), timeout=5)
        assert r.status_code == 200 and r.content == ca.read_bytes()
        with pytest.raises(httpx.HTTPError):                                       # plain http is not served
            httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=3)
        origin = f"https://localhost:{port}"
        r = httpx.post(f"{origin}/api/auth/login", json={"username": "boss", "password": pw},
                       headers={"Origin": origin}, verify=str(ca), timeout=10)
        cookie = r.headers.get("set-cookie", "")
        assert r.status_code == 200 and cookie.startswith("__Host-gw=") and "Secure" in cookie
    finally:
        p.terminate()
        p.wait(20)


# ------------------------------------------------------------------ activity log
def test_audit_events_go_to_the_activity_log(settings):
    logdir = settings.system_dir / "logs"
    activity.setup(logdir, 1, 2, True)
    try:
        db = Database(settings.system_dir / "gw.db")
        db.audit("auth.login", user={"id": 7, "username": "bob"}, ip="10.1.2.3", detail={"method": "password"})
        db.close()
        lines = (logdir / activity.FILE_NAME).read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[-1])
        assert e["user"] == "bob" and e["uid"] == 7 and e["ip"] == "10.1.2.3" and e["action"] == "auth.login"
        assert e["ts"].endswith("+00:00") and e["detail"] == {"method": "password"}
    finally:
        activity.close()


async def test_chat_activity_is_recorded_without_prompt_text():
    from goose_web.hub import CHAT_ACTIVITY, Hub
    from tests.test_hub import mk_client

    class W:
        workers, activity, on_restart = {}, None, None
    hub = Hub(W())
    seen = []
    hub.on_audit = lambda client, action, target, detail, ok: seen.append((action, target, detail))
    c, _ = mk_client()

    class Up:
        key = "alice"
    hub.audit_activity(c, Up(), "session/prompt", {"sessionId": "s1", "prompt": [
        {"type": "text", "text": "my secret plan"}, {"type": "image", "data": "xx"}]})
    hub.audit_activity(c, Up(), "session/new", {"cwd": "C:/work"})
    assert seen[0] == ("chat.prompt", "s1", {"profile": "alice", "chars": 14, "attachments": 1})
    assert "secret" not in json.dumps(seen)
    assert seen[1][0] == "chat.new" and seen[1][2]["cwd"] == "C:/work"
    assert set(CHAT_ACTIVITY.values()) >= {"chat.new", "chat.open", "chat.prompt", "chat.cancel", "chat.fork"}
    c.close()


# ------------------------------------------------------------------ log budget
def test_log_budget_deletes_oldest_unused_files(settings, monkeypatch):
    logs = settings.system_dir / "logs"
    logs.mkdir(parents=True)
    prof_logs = settings.profiles_root / "bob" / "state" / "logs" / "cli"
    prof_logs.mkdir(parents=True)
    now = time.time()
    files = {logs / "gateway.log": 0, logs / "gateway.log.3": 5, logs / "worker-bob.log.2": 4,
             prof_logs / "old.log": 9, prof_logs / "new.log": 0.001, logs / "notes.md": 20}
    for p, age_days in files.items():
        p.write_bytes(b"x" * 1000)
        os.utime(p, (now - age_days * 86400, now - age_days * 86400))
    monkeypatch.setattr(logjanitor, "budget_bytes", lambda s: 2600)
    rep = logjanitor.enforce(settings, now=now)
    assert rep["before"] == 5000 and rep["after"] <= 2600
    assert not (prof_logs / "old.log").exists() and not (logs / "gateway.log.3").exists()
    assert (logs / "gateway.log").exists() and (prof_logs / "new.log").exists()  # active / recent kept
    assert (logs / "notes.md").exists()                                           # not a log: never touched
    assert logjanitor.budget_bytes.__name__ == "<lambda>"


def test_budget_is_half_a_percent_of_the_volume(settings):
    import shutil
    assert logjanitor.budget_bytes(settings) == int(shutil.disk_usage(str(settings.system_dir)).total * 0.5 / 100)


def test_active_worker_log_over_its_share_is_copytruncated(settings, monkeypatch):
    logs = settings.system_dir / "logs"
    logs.mkdir(parents=True)
    w = logs / "worker-bob.log"
    w.write_bytes(b"y" * 3 * 1024 * 1024)
    monkeypatch.setattr(logjanitor, "budget_bytes", lambda s: 5 * 1024 * 1024)
    rep = logjanitor.enforce(settings, in_use={str(w)})
    assert rep["truncated"] == 1 and w.stat().st_size == 0 and (logs / "worker-bob.log.1").stat().st_size == 3 * 1024 * 1024


def test_audit_table_is_capped(settings):
    settings.data["logs"]["audit_max_rows"] = 5
    db = Database(settings.system_dir / "gw.db")
    for i in range(12):
        db.audit("x", target=str(i))
    assert logjanitor.prune_audit(settings, db) >= 7
    assert [r["target"] for r in db.query("SELECT target FROM audit WHERE action='x' ORDER BY id")] == [str(i) for i in range(7, 12)]
    db.close()
