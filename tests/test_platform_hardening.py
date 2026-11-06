"""Platform and supply-chain hardening: GW-09, GW-19, GW-20, GW-23, GW-24."""
import hashlib
import os
import re
import sys
from pathlib import Path

import httpx
import pytest
import yaml

from goose_web import __main__ as cli
from goose_web import app as gw_app
from goose_web import policy, security
from goose_web.config import DEFAULTS
from goose_web.workers import rotate_log

REPO = Path(__file__).resolve().parent.parent
VENDOR = REPO / "goose_web" / "static" / "vendor"


# ------------------------------------------------------------------ GW-09 initial admin password
def test_generated_admin_password_meets_policy():
    seen = set()
    for _ in range(200):
        pw = cli.generate_admin_password()
        assert len(pw) == 20
        assert security.password_problems(pw, 16) == []
        assert security.password_problems(pw, 10, "admin") == []
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(c in cli._PW_SYMBOLS for c in pw)
        assert pw.lower() != "changeme"
        seen.add(pw)
    assert len(seen) == 200


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("GOOSE_WEB__") or k == "GOOSE_WEB_CONFIG":
            monkeypatch.delenv(k, raising=False)
    root = tmp_path / "profiles"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"paths": {"profiles_root": str(root)}}), encoding="utf-8")
    return path, root


def _db(root):
    from goose_web.db import Database
    return Database(root / "_system" / "goose-web.db")


def test_init_generates_password_printed_once(cfg, capsys):
    path, root = cfg
    assert cli.main(["--config", str(path), "init", "--admin", "alice", "--native-root", "fresh"]) == 0
    out = capsys.readouterr().out
    m = re.search(r"^ {6}(\S+)$", out, re.M)
    assert m, out
    pw = m.group(1)
    assert "ChangeMe" not in out
    assert out.count(pw) == 1
    db = _db(root)
    try:
        u = db.user_by_name("alice")
        assert security.verify_password(pw, u["password_hash"])
        assert not security.verify_password("ChangeMe", u["password_hash"])
        assert u["must_change_pw"] == 1 and u["role"] == "admin"
    finally:
        db.close()
    # a second init leaves everything alone and never shows a password again
    assert cli.main(["--config", str(path), "init", "--admin", "alice", "--native-root", "fresh"]) == 0
    out2 = capsys.readouterr().out
    assert "Already initialised" in out2 and pw not in out2 and "password for admin" not in out2


def test_init_explicit_password_and_password_file(cfg, capsys, tmp_path, monkeypatch):
    path, root = cfg
    assert cli.main(["--config", str(path), "init", "--admin", "bob", "--native-root", "fresh",
                     "--password", "Given-Pass-123"]) == 0
    out = capsys.readouterr().out
    assert "Given-Pass-123" not in out and "shown ONLY" not in out
    db = _db(root)
    try:
        assert security.verify_password("Given-Pass-123", db.user_by_name("bob")["password_hash"])
    finally:
        db.close()
    secret = tmp_path / "secret.txt"
    secret.write_text("From-File-Pass-9\r\n", encoding="utf-8")
    assert cli.main(["--config", str(path), "init", "--admin", "bob", "--native-root", "fresh", "--force",
                     "--password-file", str(secret)]) == 0
    db = _db(root)
    try:
        assert security.verify_password("From-File-Pass-9", db.user_by_name("bob")["password_hash"])
    finally:
        db.close()
    import io
    monkeypatch.setattr(sys, "stdin", io.StringIO("Stdin-Pass-77\n"))
    assert cli.main(["--config", str(path), "init", "--admin", "bob", "--native-root", "fresh", "--force",
                     "--password-file", "-"]) == 0
    db = _db(root)
    try:
        assert security.verify_password("Stdin-Pass-77", db.user_by_name("bob")["password_hash"])
    finally:
        db.close()
    capsys.readouterr()


# ------------------------------------------------------------------ GW-19 path confinement
def _link_dir(link: Path, target: Path) -> None:
    """Directory symlink, or a junction on Windows when symlinks need a privilege we lack."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        try:
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
            return
        except (OSError, ImportError, AttributeError):
            pass
    pytest.skip("cannot create a directory symlink or junction here")


def test_path_allowed_lexical_still_enforced(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    assert policy.path_allowed(str(root / "sub"), [str(root)])
    assert policy.path_allowed(str(root), [str(root)])
    assert policy.path_allowed(str(root / "not-yet-created"), [str(root)])
    assert not policy.path_allowed(str(root / ".." / "elsewhere"), [str(root)])
    assert not policy.path_allowed(str(tmp_path / "rootx"), [str(root)])
    assert not policy.path_allowed("relative/path", [str(root)])
    assert not policy.path_allowed(str(root / "sub"), ["", str(tmp_path / "other")])


def test_path_allowed_blocks_symlink_escape(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    (outside / "secret").mkdir(parents=True)
    _link_dir(root / "link", outside)
    assert (root / "link" / "secret").is_dir()
    # lexically inside the root, really outside it
    assert not policy.path_allowed(str(root / "link"), [str(root)])
    assert not policy.path_allowed(str(root / "link" / "secret"), [str(root)])
    assert not policy.path_allowed(str(root / "link" / "new-folder"), [str(root)])
    # allowed when the target is itself inside an allowed root
    assert policy.path_allowed(str(root / "link" / "secret"), [str(root), str(outside)])


def test_path_allowed_root_that_is_a_link(tmp_path):
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    _link_dir(tmp_path / "alias", real)
    assert policy.path_allowed(str(tmp_path / "alias" / "sub"), [str(tmp_path / "alias")])
    inner = real / "inner-link"
    _link_dir(inner, real / "sub")
    assert policy.path_allowed(str(tmp_path / "alias" / "inner-link"), [str(tmp_path / "alias")])
    # the resolved target is in the allowed root, but the path is lexically outside it
    assert not policy.path_allowed(str(real / "sub"), [str(tmp_path / "alias")])


# ------------------------------------------------------------------ GW-20 webhook SSRF
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.8.9.10", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "192.0.2.1",
    "198.18.0.1", "::1", "::", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1", "ff02::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "2002:7f00:1::", "2002:a00:1::1",
    "64:ff9b::7f00:1", "64:ff9b::a00:1", "2001:db8::1", "not-an-ip", "",
])
def test_address_blocked(addr):
    assert gw_app.address_blocked(addr)


@pytest.mark.parametrize("addr", ["93.184.215.14", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111",
                                  "::ffff:93.184.215.14"])
def test_address_public(addr):
    assert not gw_app.address_blocked(addr)


def test_notify_default_is_strict():
    assert DEFAULTS["notify"]["allow_private_targets"] is False


async def test_webhook_target_literal_addresses():
    for url in ("http://127.0.0.1:8710/api", "http://[::1]/x", "http://[::ffff:10.0.0.1]/x", "http://10.0.0.5/x",
                "http://169.254.169.254/latest/meta-data/", "http://localhost/x"):
        with pytest.raises(gw_app.WebhookBlocked):
            await gw_app.webhook_target(url)
    for url in ("ftp://example.org/x", "file:///etc/passwd", "/relative"):
        with pytest.raises(gw_app.WebhookBlocked):
            await gw_app.webhook_target(url)
    pinned, host, sni = await gw_app.webhook_target("http://10.0.0.5:8080/x", allow_private=True)
    assert pinned.host == "10.0.0.5" and host == "10.0.0.5:8080"


async def test_webhook_target_all_addresses_checked_and_pinned(monkeypatch):
    async def fake(host, port):
        return {"hooks.example.org": ["93.184.215.14"], "rebind.example.org": ["93.184.215.14", "10.0.0.1"],
                "v6.example.org": ["2606:4700:4700::1111"]}[host]
    monkeypatch.setattr(gw_app, "_resolve", fake)
    pinned, host, sni = await gw_app.webhook_target("https://hooks.example.org/a?b=1")
    assert str(pinned) == "https://93.184.215.14/a?b=1"
    assert host == "hooks.example.org" and sni == "hooks.example.org"
    pinned, host, _ = await gw_app.webhook_target("https://v6.example.org:8443/a")
    assert pinned.host == "2606:4700:4700::1111" and host == "v6.example.org:8443"
    with pytest.raises(gw_app.WebhookBlocked):
        await gw_app.webhook_target("https://rebind.example.org/a")


async def test_send_webhook_pins_address_and_never_follows_redirects(monkeypatch):
    async def fake(host, port):
        return ["93.184.215.14"]
    monkeypatch.setattr(gw_app, "_resolve", fake)
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/internal"})
    r = await gw_app.send_webhook("https://hooks.example.org/x", json={"a": 1}, headers={"Title": "t"},
                                  transport=httpx.MockTransport(handler))
    assert r.status_code == 302 and len(seen) == 1
    req = seen[0]
    assert req.url.host == "93.184.215.14"
    assert req.headers["Host"] == "hooks.example.org" and req.headers["Title"] == "t"
    assert req.extensions.get("sni_hostname") == "hooks.example.org"


# ------------------------------------------------------------------ GW-23 worker log rotation
def test_rotate_log(tmp_path):
    log = tmp_path / "worker-x.log"
    assert not rotate_log(log, max_bytes=10)            # missing file
    log.write_bytes(b"small")
    assert not rotate_log(log, max_bytes=10)            # below the limit
    for gen in range(1, 6):
        log.write_bytes(b"generation %d " % gen + b"x" * 20)
        assert rotate_log(log, max_bytes=10, backups=3)
        assert not log.exists()
    assert (tmp_path / "worker-x.log.1").read_bytes().startswith(b"generation 5")
    assert (tmp_path / "worker-x.log.2").read_bytes().startswith(b"generation 4")
    assert (tmp_path / "worker-x.log.3").read_bytes().startswith(b"generation 3")
    assert not (tmp_path / "worker-x.log.4").exists()


def test_rotate_log_default_limit_is_about_10mb(tmp_path):
    from goose_web import workers
    assert workers.WORKER_LOG_MAX_BYTES == 10 * 1024 * 1024 and workers.WORKER_LOG_BACKUPS == 3
    log = tmp_path / "worker-y.log"
    with open(log, "wb") as fh:
        fh.truncate(workers.WORKER_LOG_MAX_BYTES + 1)
    assert rotate_log(log)
    assert (tmp_path / "worker-y.log.1").stat().st_size == workers.WORKER_LOG_MAX_BYTES + 1


# ------------------------------------------------------------------ GW-24 supply chain
def test_vendor_files_match_sha256sums():
    sums = {}
    for line in (VENDOR / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        digest, name = line.split("  ", 1)
        assert re.fullmatch(r"[0-9a-f]{64}", digest), line
        sums[name] = digest
    files = {p.name for p in VENDOR.iterdir() if p.is_file() and p.name not in ("README.md", "SHA256SUMS")}
    assert set(sums) == files, "SHA256SUMS must list every vendored file (see vendor/README.md)"
    for name, digest in sums.items():
        data = (VENDOR / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest and b"\r\n" in data:
            # a Windows checkout with core.autocrlf converts LF to CRLF; the sums are over the LF content
            actual = hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
        assert actual == digest, f"{name} does not match SHA256SUMS"


def test_requirements_lock_is_hashed_and_covers_pyproject():
    import tomllib
    lock = (REPO / "requirements.lock").read_text(encoding="utf-8")
    pinned = {m.group(1).lower().replace("_", "-") for m in re.finditer(r"^([A-Za-z0-9_.-]+)==\S+ \\$", lock, re.M)}
    deps = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    for d in deps:
        name = re.match(r"[A-Za-z0-9_.-]+", d).group(0).lower().replace("_", "-")
        assert name in pinned, f"{name} missing from requirements.lock"
    blocks = re.split(r"^(?=[A-Za-z0-9_.-]+==)", lock, flags=re.M)[1:]
    assert blocks and all("--hash=sha256:" in b for b in blocks)


def test_dockerfile_verifies_downloads():
    df = (REPO / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM python:[\w.-]+@sha256:[0-9a-f]{64}", df, re.M)
    assert re.search(r"^ARG GOOSE_SHA256_AMD64=[0-9a-f]{64}$", df, re.M)
    assert re.search(r"^ARG GOOSE_SHA256_ARM64=[0-9a-f]{64}$", df, re.M)
    assert "sha256sum -c" in df and "--no-deps ." in df
    assert re.search(r"pip install --require-hashes .*-r requirements\.lock", df)


def test_github_actions_pinned_by_sha():
    wf = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", wf)
    assert uses
    for u in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u), u
