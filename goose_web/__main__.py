"""Command line: `python -m goose_web [serve|init|user|check|version]`."""
from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import socket
import sys
from pathlib import Path

from . import __version__


def _setup_logging(settings) -> None:
    logdir = settings.system_dir / "logs"
    logdir.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(logdir / "gateway.log", maxBytes=5 * 1024 * 1024, backupCount=5,
                                              encoding="utf-8")
    fh.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers[:] = [fh]
    if sys.stderr is not None and not getattr(sys.stderr, "_gw_null", False):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    root.setLevel(os.environ.get("GOOSE_WEB_LOG_LEVEL", "INFO").upper())
    for noisy in ("httpx", "httpcore", "websockets", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def cmd_serve(args, settings) -> int:
    from . import winsec
    winsec.ensure_unelevated(bool(settings.get("server", "allow_elevated")))
    _setup_logging(settings)
    import uvicorn
    from .app import create_app
    host = args.host or settings.get("server", "host")
    port = int(args.port or settings.get("server", "port"))
    settings.data.setdefault("server", {})["host"] = host  # a --host override joins the Host allow-list too
    logging.getLogger("goose_web").info("starting on %s:%s as %s (integrity %s), profiles %s", host, port,
                                        winsec.current_user(), winsec.integrity_level(), settings.profiles_root)
    uvicorn.run(create_app(settings), host=host, port=port, log_config=None, proxy_headers=False,
                ws_max_size=64 * 1024 * 1024, ws_ping_interval=25, ws_ping_timeout=60, timeout_keep_alive=30,
                server_header=False, date_header=True, timeout_graceful_shutdown=10)
    return 0


def _resolve_native_root(value: str | None, settings) -> str:
    from .config import default_native_goose_root
    if not value or value == "auto":
        cand = default_native_goose_root()
        if Path(cand, "config").is_dir():
            return cand
        value = "fresh"
    if value == "fresh":
        p = settings.profiles_root / "appdata"
        for sub in ("config", "data", "state"):
            (p / sub).mkdir(parents=True, exist_ok=True)
        return str(p)
    p = Path(value)
    if p.name.lower() == "config" and (p / "config.yaml").exists():
        p = p.parent  # accept ...\goose\config as well as ...\goose
    if not p.is_dir():
        raise SystemExit(f"Goose profile folder not found: {p}")
    return str(p)


# Symbols that survive copy/paste and shells (no quotes, $, `, \, %, !, # or spaces).
_PW_SYMBOLS = "-_.+=@"


def generate_admin_password(length: int = 20) -> str:
    """A random initial admin password (GW-09) that always satisfies security.password_problems."""
    import secrets
    import string

    from . import security
    alphabet = string.ascii_letters + string.digits + _PW_SYMBOLS
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(max(length, 16)))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in _PW_SYMBOLS for c in pw) and not security.password_problems(pw, 16)):
            return pw


def _read_password_file(path: str) -> str:
    """First line of a file (or of stdin for '-'), e.g. a Docker secret. Trailing CR/LF is removed."""
    if path == "-":
        line = sys.stdin.readline()
    else:
        with open(path, encoding="utf-8") as fh:
            line = fh.readline()
    pw = line.rstrip("\r\n")
    if not pw:
        raise SystemExit(f"empty password in {'stdin' if path == '-' else path}")
    return pw


def _print_initial_password(name: str, pw: str) -> None:
    bar = "=" * 72
    print(bar)
    print(f"  Initial password for admin '{name}' (shown ONLY this once - store it now):")
    print()
    print(f"      {pw}")
    print()
    print("  Sign in with it and choose a new password; the change is enforced at first sign-in.")
    print("  Lost it? Reset it with: goose-web user reset " + name)
    print(bar)
    sys.stdout.flush()


def cmd_init(args, settings) -> int:
    from . import security
    from .db import Database
    settings.system_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.system_dir / "goose-web.db")
    native = _resolve_native_root(args.native_root, settings)
    if not db.get_setting("native_root") or args.force:
        db.set_setting("native_root", native)
    if db.users() and not args.force:
        print(f"Already initialised ({len(db.users())} users). Native profile: {db.get_setting('native_root')}")
        return 0
    name = security.safe_name(args.admin or os.environ.get("USERNAME") or os.environ.get("USER") or "admin")
    existing = db.user_by_name(name)
    generated = False
    if args.password_file:
        password = _read_password_file(args.password_file)
    elif args.password:
        password = args.password
    else:
        password, generated = generate_admin_password(), True
    if not generated:
        problems = security.password_problems(password, int(settings.get("auth", "min_password_length") or 10),
                                              name)
        if problems:
            print(f"warning: the given admin password {'; '.join(problems)} (it must be changed at first "
                  "sign-in anyway)", file=sys.stderr)
    pw_hash = security.hash_password(password)
    if existing:
        db.update_user(existing["id"], role="admin", password_hash=pw_hash, must_change_pw=1, profile_mode="native",
                       profile_path=native, auth_source="local", disabled=0)
    else:
        db.create_user(username=name, display_name=name, role="admin", auth_source="local", password_hash=pw_hash,
                       must_change_pw=1, profile_mode="native", profile_path=native)
    if not db.query("SELECT id FROM teams"):
        import json
        import time
        db.execute("INSERT INTO teams(name, description, policy, created_at) VALUES(?,?,?,?)",
                   ("Everyone", "Default team for new users (no shell, no extension changes).", json.dumps({}),
                    time.time()))
        db.set_setting("default_team_id", db.one("SELECT id FROM teams WHERE name='Everyone'")["id"])
    db.audit("system.init", target=name, detail={"native_root": native, "generated_password": generated})
    print(f"Admin '{name}' created (password must be changed at first sign-in). Native profile: {native}")
    if generated:
        _print_initial_password(name, password)
    return 0


def cmd_user(args, settings) -> int:
    from . import security
    from .api import temp_password
    from .db import Database
    db = Database(settings.system_dir / "goose-web.db")
    if args.action == "list":
        for u in db.users():
            print(f"{u['id']:>4}  {u['username']:<24} {u['role']:<6} {u['profile_mode']:<9} "
                  f"{'disabled' if u['disabled'] else ''}")
        return 0
    u = db.user_by_name(args.name or "")
    if args.action == "reset":
        if not u:
            raise SystemExit("no such user")
        pw = args.password or temp_password()
        db.update_user(u["id"], password_hash=security.hash_password(pw), must_change_pw=1, failed_logins=0,
                       locked_until=0, auth_source="local", disabled=0)
        db.execute("DELETE FROM auth_sessions WHERE user_id=?", (u["id"],))
        # a reset must also end API-token access, like the admin API reset does (GW-21)
        db.execute("DELETE FROM api_tokens WHERE user_id=?", (u["id"],))
        db.audit("user.reset_password", target=u["username"], detail={"via": "cli", "tokensRevoked": True})
        print(f"Temporary password for {u['username']}: {pw}")
        return 0
    if args.action == "reset-totp":
        # break-glass for a lost authenticator, same effect as Admin > Users > Reset two-factor
        if not u:
            raise SystemExit("no such user")
        if not u["totp_enabled"]:
            print(f"{u['username']} does not use two-factor; nothing changed")
            return 0
        db.update_user(u["id"], totp_enabled=0, totp_secret=None, totp_last_counter=None, failed_logins=0,
                       locked_until=0)
        db.execute("DELETE FROM auth_sessions WHERE user_id=?", (u["id"],))
        revoked = db.execute_count("DELETE FROM api_tokens WHERE user_id=?", (u["id"],))
        db.audit("user.totp.reset", target=u["username"], detail={"via": "cli", "tokensRevoked": revoked})
        print(f"Two-factor removed for {u['username']}: signed out everywhere, {revoked} API token(s) revoked. "
              "They sign in with their password and can enrol a new authenticator.")
        return 0
    if args.action == "add":
        if u:
            raise SystemExit("user exists")
        name = security.safe_name(args.name)
        pw = args.password or temp_password()
        uid = db.create_user(username=name, display_name=name, role="admin" if args.admin else "user",
                             password_hash=security.hash_password(pw), must_change_pw=1)
        if db.get_setting("default_team_id"):
            db.execute("INSERT OR IGNORE INTO team_members(team_id, user_id) VALUES(?,?)",
                       (int(db.get_setting("default_team_id")), uid))
        print(f"Created {name}; temporary password: {pw} (provisioned at first sign-in)")
        return 0
    return 1


def cmd_check(args, settings) -> int:
    from . import winsec
    from .workers import desktop_running, goose_version
    ok = True

    def line(label, value, good=True):
        nonlocal ok
        ok &= bool(good)
        print(f"[{'OK' if good else '!!'}] {label}: {value}")
    line("goose-web", __version__)
    line("config file", settings.source or "(defaults)")
    gb = settings.goose_binary
    gv = goose_version(gb)
    line("goose binary", f"{gb} ({gv or 'not runnable'})", bool(gv))
    line("running as", f"{winsec.current_user()} integrity={winsec.integrity_level()}", not winsec.is_elevated())
    line("profiles root", settings.profiles_root, settings.profiles_root.exists())
    if os.name == "nt":
        line("goose desktop running", desktop_running(gb))
    port = int(settings.get("server", "port"))
    with socket.socket() as s:
        free = s.connect_ex(("127.0.0.1", port)) != 0
    line(f"port {port}", "free" if free else "in use (gateway already running?)")
    return 0 if ok else 1


class _NullIO:
    """Stand-in for stdout/stderr under pythonw.exe (no console), where they are None."""
    _gw_null = True

    def write(self, s):
        return len(s)

    def flush(self):
        pass

    def isatty(self):
        return False


def main(argv: list[str] | None = None) -> int:
    from .config import load_settings
    if sys.stdout is None:
        sys.stdout = _NullIO()
    if sys.stderr is None:
        sys.stderr = _NullIO()
    p = argparse.ArgumentParser(prog="goose-web", description="Goose AI Web Interface")
    p.add_argument("--config", help="path to config.yaml")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="run the gateway (default)")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    i = sub.add_parser("init", help="create the database and the first admin")
    i.add_argument("--admin", help="admin username (default: the current OS user)")
    ipw = i.add_mutually_exclusive_group()
    ipw.add_argument("--password", help="initial admin password (default: a random one, printed once)")
    ipw.add_argument("--password-file", metavar="FILE",
                     help="read the initial admin password from the first line of FILE ('-' = stdin)")
    i.add_argument("--native-root", default="auto",
                   help="Goose profile folder to bind the admin to: auto | fresh | <path>")
    i.add_argument("--force", action="store_true")
    u = sub.add_parser("user", help="manage users from the console")
    u.add_argument("action", choices=["list", "add", "reset", "reset-totp"])
    u.add_argument("name", nargs="?")
    u.add_argument("--password")
    u.add_argument("--admin", action="store_true")
    sub.add_parser("check", help="diagnostics")
    sub.add_parser("version")
    args = p.parse_args(argv)
    settings = load_settings(args.config)
    cmd = args.cmd or "serve"
    if cmd == "version":
        print(__version__)
        return 0
    if cmd == "serve" and not hasattr(args, "host"):
        args.host, args.port = None, None
    return {"serve": cmd_serve, "init": cmd_init, "user": cmd_user, "check": cmd_check}[cmd](args, settings)


if __name__ == "__main__":
    sys.exit(main())
