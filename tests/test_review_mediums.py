"""Review 2026-11-12, Medium findings closed in 1.23.0: D-6 (a setting nobody answers to is named; what the
environment sets over the file is shown), D-5 (a gateway that cannot start leaves its reason in a file), and the
sandbox.desktop setting (WS-1). A-2 is in test_auth_hardening.py, B-7 and B-8 in test_sec_agent.py, D-3 in
test_sec_os.py, the desktop itself in test_appcontainer.py and test_mxc_e2e.py."""
import sys

import pytest

import goose_web.__main__ as cli
from goose_web import sandbox as sb
from goose_web import workers
from goose_web.config import (DEFAULTS, Settings, _deep_merge, load_settings, sandbox_config_problems,
                              sandbox_desktop, unknown_settings)


# ---------------------------------------------------------------- D-6
def test_a_name_no_setting_answers_to_is_reported_not_swallowed(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("sandbox:\n  netwrok: none\n  network: internet\nsanbox:\n  enabled: false\n"
                   "server:\n  port: 8711\npaths:\n  profiles_root: %s\n" % str(tmp_path / "p").replace("\\", "/"),
                   encoding="utf-8")
    for k in [k for k in __import__("os").environ if k.upper().startswith("GOOSE_WEB")]:
        monkeypatch.delenv(k)
    monkeypatch.setenv("GOOSE_WEB__SANDBOX__ENABLED", "false")
    monkeypatch.setenv("GOOSE_WEB__SANDBOX__FALBACK", "appcontainer")
    monkeypatch.setenv("GOOSE_WEB__SANDBOX", "x")
    s = load_settings(str(cfg))
    assert "sandbox.netwrok" in s.unknown and "sanbox" in s.unknown and "server.port" not in " ".join(s.unknown)
    assert any(u.startswith("sandbox.falback (environment variable") for u in s.unknown)
    assert any("GOOSE_WEB__SANDBOX (ignored" in u for u in s.unknown)
    assert s.overrides == ["sandbox.enabled (GOOSE_WEB__SANDBOX__ENABLED)", "sandbox.falback (GOOSE_WEB__SANDBOX__FALBACK)"]
    assert s.get("server", "port") == 8711 and s.get("sandbox", "enabled") is False
    lines = cli._config_lines(s)
    assert sum(1 for mark, _ in lines if mark == "!!") == 4            # each one stands out
    assert any(mark == "--" and "set by the environment" in text and "sandbox.enabled" in text for mark, text in lines)
    # nothing to say about a clean file and no environment
    monkeypatch.delenv("GOOSE_WEB__SANDBOX__ENABLED")
    monkeypatch.delenv("GOOSE_WEB__SANDBOX__FALBACK")
    monkeypatch.delenv("GOOSE_WEB__SANDBOX")
    cfg.write_text("server:\n  port: 8711\n", encoding="utf-8")
    assert cli._config_lines(load_settings(str(cfg))) == []
    assert unknown_settings(DEFAULTS) == [] and unknown_settings(["x"]) and unknown_settings({"server": 5})


# ---------------------------------------------------------------- sandbox.desktop (WS-1)
def test_the_sandbox_desktop_setting(tmp_path, monkeypatch):
    def st(v):
        return Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path)}, "sandbox": {"desktop": v}}), None)
    assert sandbox_desktop(Settings(DEFAULTS, None)) == "private" and sandbox_desktop(st(" Shared")) == "shared"
    assert sandbox_desktop(st("off")) == "invalid" and any("sandbox.desktop" in p for p in sandbox_config_problems(st("off")))
    assert not sandbox_config_problems(st("shared")) and not sandbox_config_problems(st("private"))
    monkeypatch.setitem(sb.PRIVATE_DESKTOP, "on", True)        # put back after the test, whatever it was
    workers.WorkerManager(st("shared"))
    assert sb.PRIVATE_DESKTOP["on"] is False
    workers.WorkerManager(st("off"))                            # a value nobody understands is not "shared"
    assert sb.PRIVATE_DESKTOP["on"] is True
    assert any("sandbox desktop: shared" in text for _m, text in cli._config_lines(st("shared")))
    assert cli._config_lines(st("private")) == []


# ---------------------------------------------------------------- D-5
def test_a_gateway_that_cannot_start_leaves_its_reason_in_a_file(tmp_path, monkeypatch, capsys):
    """The gateway is started by a task with pythonw.exe: nobody sees what it prints. A broken config.yaml, a
    missing module, a refused port used to leave no trace anywhere."""
    sysd = tmp_path / "_system"
    sysd.mkdir()
    cfg, f = sysd / "config.yaml", sysd / "logs" / "startup-error.log"
    cfg.write_text("server: [this is not a section\n", encoding="utf-8")
    with pytest.raises(Exception):
        cli.main(["--config", str(cfg), "serve"])
    text = f.read_text(encoding="utf-8")
    assert "did not start" in text and "Traceback" in text and "config.yaml" in text and cli.__version__ in text
    f.unlink()
    with pytest.raises(Exception):                                  # no subcommand = serve
        cli.main(["--config", str(cfg)])
    assert f.is_file()
    f.unlink()
    with pytest.raises(Exception):                                  # another command says it on the console it has
        cli.main(["--config", str(cfg), "version"])
    assert not f.exists()
    # a start that ends with an exit code, having printed why to a console that is not there
    cfg.write_text("paths:\n  profiles_root: %s\n" % str(tmp_path / "p").replace("\\", "/"), encoding="utf-8")
    null = cli._NullIO()
    monkeypatch.setattr(sys, "stderr", null)

    def refused(args, settings):
        print("goose-web: refusing to run with administrator rights", file=sys.stderr)
        return 3
    monkeypatch.setattr(cli, "cmd_serve", refused)
    assert cli.main(["--config", str(cfg), "serve"]) == 3
    text = f.read_text(encoding="utf-8")
    assert "exit code 3" in text and "refusing to run with administrator rights" in text
    # and `check` says so
    monkeypatch.setattr(sys, "argv", ["goose-web", "--config", str(cfg), "check"])
    capsys.readouterr()
    cli._startup_failure_line()
    out = capsys.readouterr().out
    assert out.startswith("[!!] the gateway did not start on ") and "refusing to run" in out and str(f) in out
    # somebody stopping a gateway that ran in a console is not a failed start (T-14)
    f.unlink()

    def stopped(args, settings):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "cmd_serve", stopped)
    with pytest.raises(KeyboardInterrupt):
        cli.main(["--config", str(cfg), "serve"])
    assert not f.exists()
    # a start that works leaves nothing
    monkeypatch.setattr(cli, "cmd_serve", lambda args, settings: 0)
    assert cli.main(["--config", str(cfg), "serve"]) == 0 and not f.exists()


def test_check_names_a_sign_in_provider_that_is_refused_for_plain_http(tmp_path):
    """A-2 refuses an http issuer at sign-in. Whoever signs in only through it finds out by being locked out -
    unless `check` (which upgrade.ps1 runs) says so first (review of 1.23.0, T-12)."""
    from pathlib import Path
    from goose_web.db import Database
    s = Settings(_deep_merge(DEFAULTS, {"paths": {"profiles_root": str(tmp_path)}}), None)
    assert cli._signin_lines(s) == []                       # no database yet
    Path(s.system_dir).mkdir(parents=True, exist_ok=True)
    db = Database(Path(s.system_dir) / "goose-web.db")
    try:
        db.set_setting("auth", {"oidc": [{"id": "lan", "issuer": "http://idp.lan:8080", "clientId": "gw"},
                                         {"id": "ok", "issuer": "https://idp.example.org", "clientId": "gw"},
                                         {"id": "own", "issuer": "http://127.0.0.1:9000", "clientId": "gw"},
                                         {"id": "opted", "issuer": "http://idp.lan", "allowInsecure": True}]})
    finally:
        db.close()
    lines = cli._signin_lines(s)
    assert len(lines) == 1 and lines[0][0] == "!!" and "'lan'" in lines[0][1] and "refused" in lines[0][1]
