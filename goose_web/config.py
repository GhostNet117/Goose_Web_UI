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
        candidates += [r"C:\Goose\dist-windows\resources\bin\goose.exe",
                       os.path.expandvars(r"%LOCALAPPDATA%\Programs\Goose\resources\bin\goose.exe"),
                       os.path.expandvars(r"%USERPROFILE%\.local\bin\goose.exe")]
    else:
        candidates += ["/usr/local/bin/goose", os.path.expanduser("~/.local/bin/goose")]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "goose"


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
    "auth": {
        "session_hours": 12,
        "remember_days": 30,
        "lockout_threshold": 8,
        "lockout_minutes": 15,
        "min_password_length": 10,
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


def config_path_candidates(explicit: str | None) -> list[Path]:
    out = []
    if explicit:
        out.append(Path(explicit))
    if os.environ.get("GOOSE_WEB_CONFIG"):
        out.append(Path(os.environ["GOOSE_WEB_CONFIG"]))
    out.append(Path(_default_profiles_root()) / "_system" / "config.yaml")
    return out


def load_settings(explicit: str | None = None) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    source = None
    for p in config_path_candidates(explicit):
        if p.is_file():
            with open(p, encoding="utf-8") as fh:
                data = _deep_merge(data, yaml.safe_load(fh) or {})
            source = str(p)
            break
    for k, v in os.environ.items():
        if not k.startswith("GOOSE_WEB__"):
            continue
        parts = k[len("GOOSE_WEB__"):].lower().split("__")
        if len(parts) == 2:
            data.setdefault(parts[0], {})[parts[1]] = _coerce(v)
    return Settings(data, source)
