"""Settings: defaults < config.yaml < environment (GOOSE_WEB__SECTION__KEY=value)."""
from __future__ import annotations

import copy
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

IS_WINDOWS = sys.platform == "win32"


def _default_profiles_root() -> str:
    if IS_WINDOWS:
        return r"C:\Goose_Web_Profiles"
    return os.environ.get("GOOSE_WEB_PROFILES", "/var/lib/goose-web/profiles")


def _find_goose() -> str:
    found = shutil.which("goose")
    if found:
        return found
    candidates = []
    if IS_WINDOWS:
        # Standard install locations only; a Goose installed anywhere else (e.g. C:\AI\Goose) is set with goose.binary.
        candidates += [os.path.expandvars(r"%LOCALAPPDATA%\Programs\Goose\resources\bin\goose.exe"),
                       os.path.expandvars(r"%ProgramFiles%\Goose\resources\bin\goose.exe"),
                       os.path.expandvars(r"%USERPROFILE%\.local\bin\goose.exe")]
    else:
        candidates += ["/usr/local/bin/goose", os.path.expanduser("~/.local/bin/goose")]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "goose"


def sandbox_on(settings: "Settings") -> bool:
    """sandbox.enabled: true / false (also yes/no, on/off, 1/0), or "auto" (default, also when not set) = on for
    Windows, where the sandbox exists.

    MX-7 (security review 2026-11-12): any other value (a typo such as "ture") counts as ON and is reported by
    sandbox_config_problems, so members' workers refuse to start (fail closed) instead of running unsandboxed."""
    v = _sandbox_enabled_value(settings)
    if v == "auto":
        return IS_WINDOWS
    return v in ("on", "invalid")


SANDBOX_ENABLED_ON = ("1", "true", "yes", "on")
SANDBOX_ENABLED_OFF = ("0", "false", "no", "off")


def _sandbox_enabled_value(settings: "Settings") -> str:
    """'auto' | 'on' | 'off' | 'invalid' for sandbox.enabled (not set / null / "" = auto, the default)."""
    v = settings.get("sandbox", "enabled", "auto")
    if v is None:
        return "auto"
    if isinstance(v, bool):
        return "on" if v else "off"
    if isinstance(v, int) and v in (0, 1):
        return "on" if v else "off"
    s = str(v).strip().lower()
    if s in ("", "auto"):
        return "auto"
    if s in SANDBOX_ENABLED_ON:
        return "on"
    if s in SANDBOX_ENABLED_OFF:
        return "off"
    return "invalid"


SANDBOX_BACKENDS = ("mxc", "appcontainer")
SANDBOX_FALLBACKS = ("none", "appcontainer")


def sandbox_backend(settings: "Settings") -> str:
    """sandbox.backend (spec 025): "mxc" (default, Microsoft Execution Containers) or "appcontainer" (spec 012).
    Anything else is "invalid": sandboxed workers then refuse to start (fail closed), never run unsandboxed."""
    v = str(settings.get("sandbox", "backend") or "mxc").strip().lower()
    return v if v in SANDBOX_BACKENDS else "invalid"


def sandbox_fallback(settings: "Settings") -> str:
    """sandbox.fallback (spec 025): "none" (default: MXC unavailable = fail closed) or "appcontainer"."""
    v = str(settings.get("sandbox", "fallback") or "none").strip().lower()
    return v if v in SANDBOX_FALLBACKS else "invalid"


def sandbox_config_problems(settings: "Settings") -> list[str]:
    """Configuration errors of the sandbox section; each one makes sandboxed workers fail closed."""
    out = []
    if _sandbox_enabled_value(settings) == "invalid":
        out.append(f"sandbox.enabled is {settings.get('sandbox', 'enabled')!r}; use one of: auto, true, false "
                   "(members' agents do not start until it is fixed)")
    if sandbox_backend(settings) == "invalid":
        out.append(f"sandbox.backend is {settings.get('sandbox', 'backend')!r}; use one of: "
                   + ", ".join(SANDBOX_BACKENDS))
    if sandbox_fallback(settings) == "invalid":
        out.append(f"sandbox.fallback is {settings.get('sandbox', 'fallback')!r}; use one of: "
                   + ", ".join(SANDBOX_FALLBACKS))
    net = str(settings.get("sandbox", "network") or "internet").strip().lower()
    if net not in ("none", "internet", "internet+lan"):
        out.append(f"sandbox.network is {net!r}; use one of: none, internet, internet+lan")
    for key, lo, hi in (("proxy_max_connections", 1, 4096), ("proxy_idle_seconds", 10, 86400)):
        try:
            n = int(settings.get("sandbox", key))
            if not lo <= n <= hi:
                raise ValueError
        except (TypeError, ValueError):
            out.append(f"sandbox.{key} is {settings.get('sandbox', key)!r}; use a number from {lo} to {hi}")
    return out


def default_native_goose_root() -> str:
    """Where Goose keeps its profile when GOOSE_PATH_ROOT is not set (config/ and data/ live below it)."""
    if IS_WINDOWS:
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser(r"~\AppData\Roaming")), "Block", "goose")
    return os.path.expanduser("~/.config/goose")


DEFAULTS: dict[str, Any] = {
    "server": {
        "host": "127.0.0.1",
        "port": 8710,
        "public_url": "",                 # e.g. https://goose.example.org (used for Origin checks + OIDC redirect)
        "trusted_proxies": ["127.0.0.1", "::1"],
        "allowed_origins": [],            # extra Origins allowed for the WebSocket (public_url is always allowed)
        # Host header allow-list (DNS-rebinding guard). Always allowed: the host name of public_url, localhost,
        # 127.0.0.1, ::1 and the bind address (server.host unless 0.0.0.0 / ::). Add other names users type
        # in the address bar here (no ports, no wildcards). Other Host values get "400 invalid host".
        "allowed_hosts": [],
        "max_upload_mb": 25,
        "allow_elevated": False,          # Windows: refuse to run with an admin token (ownership guarantee)
        # HTTPS (tls.py, spec 015): auto | self-signed | files | off. auto = self-signed unless public_url is set
        # (then a reverse proxy terminates TLS). Admin > System > HTTPS overrides this. Applies at the next start.
        "tls": "auto",
        "tls_cert_file": "",              # mode files: PEM certificate (chain) and key, e.g. from a company CA
        "tls_key_file": "",
        "tls_names": [],                  # extra names/addresses for the self-signed certificate
    },
    # Logs (spec 015): every log Goose Web writes stays under max_disk_percent of the disk volume (logjanitor.py).
    "logs": {
        "max_disk_percent": 0.5,
        "check_minutes": 30,
        "activity": True,                 # user activity log, <system_dir>/logs/activity.jsonl (activity.py)
        "activity_file_mb": 20,
        "activity_files": 10,
        "gateway_file_mb": 10,
        "gateway_files": 5,
        "include_native_goose_logs": False,   # also trim the native profile's Goose logs (shared with Desktop)
        "audit_days": 365,                # audit table in the database
        "audit_max_rows": 500000,
    },
    "paths": {
        "profiles_root": _default_profiles_root(),
        "system_dir": "",                 # default: <profiles_root>/_system
    },
    "goose": {
        "binary": "",                     # default: auto-detect
        "idle_minutes": 30,               # stop a profile's worker after this long without clients or runs
        "start_timeout_seconds": 45,
        "native_scheduler": "auto",       # auto | on | off  (auto = off while Goose Desktop runs on the same profile)
        "extra_env": {},
        "default_workdir_native": "",     # admin native profile: default folder for new chats (default: home)
    },
    # Windows: run every isolated non-admin user's worker in a sandbox of its own (spec 012, spec 025).
    "sandbox": {
        "enabled": "auto",                # auto = on for Windows, off elsewhere; true | false
        # mxc = Microsoft Execution Containers (mxc.py, spec 025, default) | appcontainer = Goose Web's own
        # AppContainer backend (sandbox.py, spec 012)
        "backend": "mxc",
        # MXC unavailable (not installed, altered, Windows too old, probe failed): none = members' agents do not
        # start (fail closed) | appcontainer = they start in the AppContainer backend (logged and audited)
        "fallback": "none",
        "network": "internet",            # none | internet | internet+lan (loopback is never reachable)
        "read_dirs": [],                  # extra program folders the workers may read and run (Python, node, uv, git)
        # local services sandboxed workers may reach, e.g. ["127.0.0.1:4000"]: AppContainer through relay.py, MXC
        # through the member's egress proxy (egress.py)
        "relays": [],
        "mxc_dir": "",                    # default: <install folder>/vendor/mxc (goose-web sandbox install-mxc)
        "proxy_max_connections": 64,      # MXC egress proxy: concurrent connections per member
        "proxy_idle_seconds": 900,        # MXC egress proxy: a connection without traffic this long is closed
    },
    # Prompt guard (guard.py, spec 018): the local Prompt Guard 2 22M classifier. Teams switch the guard on in
    # Admin > Teams; these are the classifier's knobs. Nothing loads while no team (and not the admins) uses it.
    "guard": {
        "threshold": 0.5,                 # block when the malicious probability is at least this
        "min_chars": 16,                  # shorter text is not classified (rules still apply)
        "window_tokens": 128,             # tokens per window (the model reads at most 512; shorter is much cheaper)
        "window_overlap": 16,             # tokens shared by consecutive windows
        "max_windows": 48,                # windows scored per text (all of them); more = not inspected
        "max_input_chars": 16000,         # longer text is not classified: guarded prompts refused, tool calls asked
        "timeout_ms": 10000,              # slower than this = unavailable: allowed (fail open) and audited
        "rules_timeout_ms": 1500,         # rule matching deadline (child process); slower = blocked (fail closed)
        "load_timeout_s": 60,
        "threads": 4,                     # ONNX Runtime threads for one inference (capped at the CPU count)
        "cache_size": 2048,               # scores remembered by content hash
        "warm_up": True,                  # load the model at start-up when some guard is on
        "model_dir": "",                  # default: <system_dir>/models/prompt-guard-2-22m
        "model_url": "",                  # override of the pinned package URL (https)
        "model_sha256": "",               # its SHA-256 (required with model_url)
        # Classification endpoint (classifyapi.py, spec 026): Goose's own prompt injection detection asks it, for
        # every profile (Goose Web chats, Goose Desktop, the goose CLI, scheduled recipes). Loopback only, its own
        # port, one token per profile. 0 = no endpoint (Goose-native detection then uses patterns only).
        "classifier_port": 8711,
        "classifier_timeout_ms": 4000,    # answer within this or 503 (Goose waits 5 s and does not retry)
        "classifier_max_pieces": 4,       # a text longer than max_input_chars is scored in this many pieces at most
        "classifier_max_body_kb": 256,    # larger request bodies are refused (413)
        "classifier_rate_per_minute": 600,   # requests per profile per minute (429 beyond)
    },
    # Running elsewhere (spec 020, elsewhere.py): administrators see, read-only, the native profile's sessions that
    # Goose Desktop, the goose CLI or a scheduled job are writing. The native sessions.db is only read (read-only
    # connection), only when it changed, and only while an administrator has Goose Web open.
    "elsewhere": {
        "enabled": True,
        "poll_seconds": 20,               # how often the database's size/time is checked (min 5)
        "active_minutes": 5,              # a prompt / tool result without the model's answer this long = not running
        "stale_minutes": 30,              # a tool call without any write for this long = not running any more
        "done_hours": 24,                 # Done: sessions finished elsewhere while nobody watched, looked back this far
        "max_items": 40,                  # entries (groups) in the list
    },
    "auth": {
        "session_hours": 12,
        "remember_days": 30,
        "lockout_threshold": 8,
        "lockout_minutes": 15,
        "min_password_length": 12,        # never below 12 (strong-password floor, security.PASSWORD_MIN_LENGTH)
        # Block a client address after this many consecutive failed sign-ins within the window (0 = off).
        "ip_block_threshold": 10,
        "ip_block_window_days": 30,
        "ip_block_days": 30,              # how long a block lasts; 0 = until an administrator unblocks it
        "ip_block_exempt": [],            # addresses/networks never blocked (trusted proxies always are)
    },
    "notify": {
        # Personal notification webhooks may only reach public internet addresses: loopback, private (RFC 1918,
        # ULA), link-local, CGNAT, reserved, multicast and unspecified targets are refused (SSRF guard).
        # Set true only if users really need internal targets such as a self-hosted ntfy on the LAN.
        "allow_private_targets": False,
    },
    "host_tasks": {
        "enabled": True,
        "path_filter": "\\*",             # Task Scheduler folder filter; \Microsoft\* is always excluded
    },
}


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(value: str) -> Any:
    low = value.strip().lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    if value.startswith("[") or value.startswith("{"):
        try:
            return yaml.safe_load(value)
        except yaml.YAMLError:
            return value
    return value


class Settings:
    def __init__(self, data: dict, source: str | None):
        self.data = data
        self.source = source

    def get(self, section: str, key: str, default: Any = None) -> Any:
        return self.data.get(section, {}).get(key, default)

    @property
    def profiles_root(self) -> Path:
        return Path(self.get("paths", "profiles_root"))

    @property
    def system_dir(self) -> Path:
        sd = self.get("paths", "system_dir")
        return Path(sd) if sd else self.profiles_root / "_system"

    @property
    def goose_binary(self) -> str:
        return self.get("goose", "binary") or _find_goose()

    @property
    def public_url(self) -> str:
        return (self.get("server", "public_url") or "").rstrip("/")


class ConfigError(SystemExit):
    """A configuration file that was asked for explicitly is missing (A-10). A SystemExit, so the command line
    stops with the message and exit code 1 and no caller can quietly carry on with another configuration."""

    def __init__(self, message: str):
        super().__init__(f"goose-web: {message}")
        self.message = message


def config_path_candidates(explicit: str | None) -> list[Path]:
    """The configuration file to read, as a one-element list (empty = built-in defaults only).

    An explicit --config path, or else GOOSE_WEB_CONFIG, is the only candidate when given: it must exist, it is
    never replaced by another file (a typo must not make the gateway open the production configuration).
    Only when neither is given is the default <profiles_root>/_system/config.yaml used, if it exists."""
    if explicit:
        return [Path(explicit)]
    if os.environ.get("GOOSE_WEB_CONFIG"):
        return [Path(os.environ["GOOSE_WEB_CONFIG"])]
    return [Path(_default_profiles_root()) / "_system" / "config.yaml"]


def load_settings(explicit: str | None = None) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    source = None
    for p in config_path_candidates(explicit):
        if not p.is_file():
            if explicit:
                raise ConfigError(f"config file not found: {p} (--config). Check the path; Goose Web does not "
                                  "fall back to another configuration.")
            if os.environ.get("GOOSE_WEB_CONFIG"):
                raise ConfigError(f"config file not found: {p} (GOOSE_WEB_CONFIG). Check the path; Goose Web "
                                  "does not fall back to another configuration.")
            continue
        with open(p, encoding="utf-8") as fh:
            data = _deep_merge(data, yaml.safe_load(fh) or {})
        source = str(p)
    for k, v in os.environ.items():
        if not k.startswith("GOOSE_WEB__"):
            continue
        parts = k[len("GOOSE_WEB__"):].lower().split("__")
        if len(parts) == 2:
            data.setdefault(parts[0], {})[parts[1]] = _coerce(v)
    return Settings(data, source)
