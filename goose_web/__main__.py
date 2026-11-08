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
        # Goose's own GOOSE_PATH_ROOT (a custom appdata folder such as C:\AI\Goose_appdata) wins over the default.
        for cand in (os.environ.get("GOOSE_PATH_ROOT") or "", default_native_goose_root()):
            if cand and Path(cand, "config").is_dir():
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
        problems = security.password_problems(password, int(settings.get("auth", "min_password_length")
                                                            or security.PASSWORD_MIN_LENGTH), name)
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
                   ("Everyone", "Default team for new users. Starts with nothing allowed: choose its providers, models and "
                    "approval modes in Admin > Teams.", json.dumps({}),
                    time.time()))
        db.set_setting("default_team_id", db.one("SELECT id FROM teams WHERE name='Everyone'")["id"])
    db.audit("system.init", target=name, detail={"native_root": native, "generated_password": generated})
    print(f"Admin '{name}' created (password must be changed at first sign-in). Native profile: {native}")
    if generated:
        _print_initial_password(name, password)
    return 0


def cmd_native_root(args, settings) -> int:
    """Show or move the native Goose profile (the Goose appdata folder: <root>\\config, <root>\\data) after install."""
    from .db import Database
    db = Database(settings.system_dir / "goose-web.db")
    old = db.get_setting("native_root") or ""
    if not args.path:
        print(f"Native Goose profile: {old or '(not set)'}")
        return 0
    p = Path(args.path)
    if p.name.lower() == "config" and (p / "config.yaml").exists():
        p = p.parent
    if not (p / "config").is_dir():
        print(f"error: {p} has no config folder; point to the Goose appdata folder that contains config\\ and data\\",
              file=sys.stderr)
        return 2
    new = str(p)
    norm = lambda s: os.path.normcase(os.path.normpath(s)) if s else ""  # noqa: E731
    users = [u for u in db.users() if u["profile_mode"] == "native"
             and (not u["profile_path"] or norm(u["profile_path"]) == norm(old))]
    db.set_setting("native_root", new)
    for u in users:
        db.update_user(u["id"], profile_path=new)
    db.audit("system.native_root", target=new, detail={"old": old, "users": [u["username"] for u in users]})
    print(f"Native Goose profile: {old or '(not set)'} -> {new}; updated {len(users)} native user(s): "
          f"{', '.join(u['username'] for u in users) or '-'}. Restart the gateway to apply.")
    print("Goose Desktop on this account must use the same folder: set the user environment variable "
          f"GOOSE_PATH_ROOT={new} (leave it unset for the default %APPDATA%\\Block\\goose).")
    return 0


def cmd_native_hints(args, settings) -> int:
    """Managed native hints (spec 011): Goose Web writes a native user's composed hints (personal + assigned + team
    documents) into the native profile's config/.goosehints, which Goose Desktop, the CLI and schedules load too."""
    import time
    from .db import Database
    from .profiles import NATIVE_HINTS_HEADER, NATIVE_HINTS_SETTING, Profiles
    db = Database(settings.system_dir / "goose-web.db")
    prof = Profiles(settings, db)
    owner = db.get_setting(NATIVE_HINTS_SETTING)
    if args.action == "status":
        u = db.user_by_id(int(owner)) if owner not in (None, "") else None
        print(f"Managed native hints: {'ON for ' + u['username'] if u else 'off'}")
        for n in [x for x in db.users() if x["profile_mode"] == "native"]:
            sec = prof.hint_sections(n)
            print(f"  native user {n['username']}: team {sec['team']['name'] if sec['team'] else '-'}, "
                  f"{len(sec['user'])} assigned + {len(sec['teamDocs'])} team document(s), file {prof.native_hints_path(n)}")
        return 0
    if args.action == "disable":
        db.execute("DELETE FROM settings WHERE key=?", (NATIVE_HINTS_SETTING,))
        db.audit("hints.native.unmanaged", target=str(owner or ""))
        print("Managed native hints: off. The native .goosehints keeps its current text; edit it in Settings > Goose "
              "hints or directly. Earlier versions: " + str(settings.system_dir / "backups" / "native-hints"))
        return 0
    # enable
    u = db.user_by_name(args.user or "")
    if not u or u["profile_mode"] != "native":
        print(f"error: {args.user!r} is not a native-profile user", file=sys.stderr)
        return 2
    team = None
    if args.team:
        team = db.one("SELECT * FROM teams WHERE name=?", (args.team,))
        if not team:
            tid = db.execute("INSERT INTO teams(name, description, policy, created_at) VALUES(?,?,?,?)",
                             (args.team, "Administrators (created by goose-web native-hints)", "{}", time.time()))
            team = db.one("SELECT * FROM teams WHERE id=?", (tid,))
            print(f"Created team {args.team!r} (administrators bypass team policies; non-admin members get nothing "
                  "until you allow it on its Experience page)")
        cur = db.user_team(u["id"])
        if cur and cur["id"] != team["id"]:
            print(f"Moving {u['username']} from team {cur['name']!r} to {team['name']!r} (one team per user)")
        db.set_user_team(u["id"], team["id"])
    adopted = None
    if args.adopt:
        text = prof.read_native_hints(u)
        if not text.strip():
            print("Nothing to adopt: the native .goosehints is empty or missing.")
        elif text.startswith(NATIVE_HINTS_HEADER[:40]):
            print("Not adopted: the native .goosehints is already written by Goose Web.")
        else:
            name = args.doc_name or f"{u['username']} goose hints"
            base, i = name, 2
            while db.one("SELECT id FROM hints_docs WHERE name=?", (name,)):
                name, i = f"{base} ({i})", i + 1
            hid = db.execute("INSERT INTO hints_docs(name, description, content, updated_at) VALUES(?,?,?,?)",
                             (name, f"Adopted from {prof.native_hints_path(u)} on {time.strftime('%Y-%m-%d')}",
                              text, time.time()))
            if team:
                db.execute("INSERT OR IGNORE INTO team_hints(team_id, hints_id) VALUES(?,?)", (team["id"], hid))
            else:
                db.execute("INSERT OR IGNORE INTO user_hints(user_id, hints_id) VALUES(?,?)", (u["id"], hid))
            adopted = name
            print(f"Adopted the current .goosehints as hints document {name!r} "
                  f"(assigned to {'team ' + team['name'] if team else 'user ' + u['username']})")
    db.set_setting(NATIVE_HINTS_SETTING, u["id"])
    u = db.user_by_id(u["id"])
    before = prof.read_native_hints(u)
    prof.write_hints(u)
    changed = prof.read_native_hints(u) != before
    db.audit("hints.native.managed", target=u["username"], detail={"team": team["name"] if team else None,
                                                                   "adopted": adopted, "rewritten": changed})
    print(f"Managed native hints: ON for {u['username']}. {prof.native_hints_path(u)} "
          f"{'rewritten (previous version backed up to ' + str(settings.system_dir / 'backups' / 'native-hints') + ')' if changed else 'unchanged'}.")
    if not adopted and not args.adopt and before.strip() and not before.startswith(NATIVE_HINTS_HEADER[:40]):
        print("warning: the previous text was replaced, not adopted (use --adopt to keep it as a document). "
              "It is in the backup folder above.")
    return 0


def cmd_sandbox(args, settings) -> int:
    """Spec 012: show the per-user AppContainers and their folder grants, or remove one user's."""
    from . import sandbox as sb
    state_dir = str(settings.system_dir / "sandbox")
    if args.action == "status":
        from .config import sandbox_on
        on = sandbox_on(settings)
        print(f"Sandbox: {'ON' if on else 'off'} (sandbox.enabled), network: {settings.get('sandbox', 'network')}, "
              f"platform: {'Windows AppContainer' if sb.IS_WINDOWS else 'not supported (fail closed when on)'}")
        print(f"Extra program folders (sandbox.read_dirs): {settings.get('sandbox', 'read_dirs') or '-'}")
        for st in sb.all_states(state_dir):
            print(f"  {st.get('name')}  {st.get('sid')}")
            for p, r in sorted((st.get("grants") or {}).items()):
                print(f"      {r:6}  {p}")
        return 0
    from .db import Database
    db = Database(settings.system_dir / "goose-web.db")
    u = db.user_by_name(args.user or "")
    name = sb.container_name(str(settings.profiles_root), u["username"] if u else (args.user or ""))
    st = sb.remove(state_dir, name)
    if not st:
        print(f"No sandbox recorded for {args.user!r} ({name}).")
        return 1
    db.audit("sandbox.remove", target=args.user or "", detail={"container": name, "via": "cli"})
    print(f"Removed {name}: revoked {len(st.get('grants') or {})} grant(s), deleted the AppContainer profile. "
          "Stop the user's worker first if the gateway is running (Admin > System); a new start recreates it.")
    return 0


def _gateway_tasks() -> list[str]:
    """Windows: scheduled tasks that run this install's gateway (empty list if none or not Windows)."""
    if os.name != "nt":
        return []
    import subprocess
    venv = os.path.normcase(os.path.dirname(sys.executable))
    ps = ("Get-ScheduledTask | Where-Object { $_.Actions | Where-Object { $_.Arguments -match 'goose_web' -and "
          "$_.Arguments -match 'serve' } } | ForEach-Object { $_.TaskPath + $_.TaskName + '|' + $_.State + '|' + "
          "(($_.Actions | ForEach-Object { $_.Execute }) -join ';') }")
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    try:  # fixed command, no user input
        out = subprocess.run([exe, "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=60,  # nosec B603
                             stdin=subprocess.DEVNULL).stdout
    except Exception:
        return []
    rows = []
    for ln in out.splitlines():
        parts = ln.strip().split("|")
        if len(parts) == 3 and os.path.normcase(os.path.dirname(parts[2].strip('"'))) == venv:
            rows.append(f"{parts[0]} ({parts[1]})")
    return rows


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


def cmd_ip(args, settings) -> int:
    """Break-glass for the sign-in IP block (spec 007); works while the gateway runs (it re-reads within 15 s)."""
    import datetime

    from .db import Database
    from .ipblock import IPBlocker
    db = Database(settings.system_dir / "goose-web.db")
    blocker = IPBlocker(db, settings)

    def when(ts):
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"
    if args.action == "list":
        d = blocker.describe()
        print(f"Block after {d['threshold']} consecutive failed sign-ins within {d['windowDays']:g} days; "
              f"blocks last {(str(round(d['blockDays'], 2)) + ' days') if d['blockDays'] else 'until unblocked'}.")
        rows = blocker.list()
        if not rows:
            print("No blocked or counted addresses.")
        for r in rows:
            state = f"BLOCKED until {when(r['blockedUntil']) if r['blockedUntil'] else 'unblocked'}" if r["blocked"] \
                else "counting"
            print(f"{r['ip']:<40} {state:<30} failures={r['failures']:<3} last={when(r['lastFailureAt'])} "
                  f"user={r['lastUsername'] or '-'}")
        return 0
    if args.all:
        n = blocker.unblock_all()
        db.audit("auth.ip.unblocked", target="*", detail={"via": "cli", "removed": n})
        print(f"Removed {n} address record(s); nothing is blocked now.")
        return 0
    if not args.address:
        raise SystemExit("give an address, or --all")
    if not blocker.unblock(args.address):
        raise SystemExit(f"{args.address} is not blocked or counted (see: goose-web ip list)")
    db.audit("auth.ip.unblocked", target=args.address, detail={"via": "cli"})
    print(f"Unblocked {args.address} (the gateway picks this up within 15 seconds).")
    return 0


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
    from .config import sandbox_on
    if sandbox_on(settings):
        from . import sandbox as sb
        line("sandbox", "on: isolated non-admin workers run in their own AppContainer" if sb.IS_WINDOWS else
             "on, but this system is not Windows: isolated non-admin workers will not start", sb.IS_WINDOWS)
    if os.name == "nt":
        # Information only (a fresh install runs check before it registers the task): autostart at logon.
        tasks = _gateway_tasks()
        enabled = [t for t in tasks if not t.endswith("(Disabled)")]
        print(f"[{'OK' if enabled else '--'}] autostart task: "
              f"{', '.join(tasks) if tasks else 'none registered for this install (scripts/register-service.ps1)'}")
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
    ipc = sub.add_parser("ip", help="list or unblock addresses blocked after failed sign-ins")
    ipc.add_argument("action", choices=["list", "unblock"])
    ipc.add_argument("address", nargs="?", help="address to unblock (an IPv6 address unblocks its /64)")
    ipc.add_argument("--all", action="store_true", help="unblock every address and clear all counters")
    nr = sub.add_parser("native-root", help="show or move the native Goose profile (Goose appdata folder)")
    nr.add_argument("path", nargs="?", help="new folder that contains config\\ (e.g. C:\\AI\\Goose_appdata)")
    nh = sub.add_parser("native-hints", help="let Goose Web manage the native profile's .goosehints")
    nh.add_argument("action", choices=["status", "enable", "disable"])
    nh.add_argument("user", nargs="?", help="enable: the native-profile user whose hints are written")
    nh.add_argument("--team", help="enable: put the user in this team (created if missing), e.g. Admins")
    nh.add_argument("--adopt", action="store_true",
                    help="enable: keep the current .goosehints as a hints document (on --team, else on the user)")
    nh.add_argument("--doc-name", help="name for the adopted document (default '<user> goose hints')")
    sbx = sub.add_parser("sandbox", help="per-user AppContainer sandbox: status, or remove one user's")
    sbx.add_argument("action", choices=["status", "remove"])
    sbx.add_argument("user", nargs="?")
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
    return {"serve": cmd_serve, "init": cmd_init, "user": cmd_user, "ip": cmd_ip, "check": cmd_check,
            "native-root": cmd_native_root, "native-hints": cmd_native_hints, "sandbox": cmd_sandbox}[cmd](args, settings)


if __name__ == "__main__":
    sys.exit(main())
