"""Profile layout, provisioning (teams -> profile files) and the cross-profile library.

Layout of an isolated profile (GOOSE_PATH_ROOT=<profiles_root>/<username>):
    config/  config.yaml, secrets.yaml, .goosehints, custom_providers/, recipes/, skills/
    data/    sessions/sessions.db, logs/        (written by Goose)
    state/                                       (written by Goose)
    workspace/                                   default folder for new chats
    .goose-web/managed.json                      what the gateway provisioned (so it never touches user items)

The admin's native profile (profile_mode = native) is NEVER provisioned. The gateway only reads it, except
when the admin saves their own goose hints in the UI (the previous file is backed up first).
"""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

import yaml

from .config import Settings, default_native_goose_root
from .db import Database
from .policy import SHELL_EXTENSIONS, effective_policy
from .security import safe_name

MANAGED_MARK = ".goose-web-managed"
HINTS_HEADER = ("# Managed by Goose Web. Edit your personal hints in the web UI (Settings > Goose hints);\n"
                "# changes made directly in this file are overwritten.\n")
# Platform extensions every new profile starts with (copied from the admin profile when present there).
BASE_EXTENSIONS = ["todo", "skills", "apps", "chatrecall", "summarize", "extensionmanager", "analyze", "memory",
                   "summon", "tom"]
MAX_SKILL_BYTES = 2 * 1024 * 1024


def _read_yaml(p: Path) -> dict:
    try:
        with open(p, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}


def _atomic_write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp{os.getpid()}")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, p)


def _write_yaml(p: Path, data: dict) -> None:
    _atomic_write(p, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def _same_path(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


class Profiles:
    def __init__(self, settings: Settings, db: Database):
        self.s = settings
        self.db = db
        self.root = settings.profiles_root
        self.library_dir = settings.system_dir / "library"

    # ------------------------------------------------------------ paths
    def is_native(self, user: dict) -> bool:
        return user.get("profile_mode") == "native"

    def root_for(self, user: dict) -> Path:
        if self.is_native(user):
            return Path(user.get("profile_path") or default_native_goose_root())
        return self.root / safe_name(user["username"])

    def path_root_env(self, user: dict) -> str | None:
        """GOOSE_PATH_ROOT for this user's worker (None = Goose's default location)."""
        r = self.root_for(user)
        if self.is_native(user) and _same_path(r, default_native_goose_root()):
            return None
        return str(r)

    def config_dir(self, user: dict) -> Path:
        return self.root_for(user) / "config"

    def workspace(self, user: dict) -> Path:
        if self.is_native(user):
            return Path(self.s.get("goose", "default_workdir_native") or os.path.expanduser("~"))
        return self.root_for(user) / "workspace"

    def team_recipe_dirs(self, user: dict) -> list[str]:
        out = []
        for t in self.db.user_teams(user["id"]):
            d = self.library_dir / "teams" / str(t["id"]) / "recipes"
            if d.is_dir():
                out.append(str(d))
        return out

    def ensure_layout(self, user: dict) -> Path:
        r = self.root_for(user)
        if self.is_native(user):
            return r
        for sub in ("config", "data", "state", "workspace", ".goose-web"):
            (r / sub).mkdir(parents=True, exist_ok=True)
        return r

    # ------------------------------------------------------------ hints
    def assigned_hints(self, user: dict) -> list[dict]:
        return self.db.query(
            "SELECT DISTINCT h.* FROM hints_docs h WHERE h.id IN ("
            " SELECT hints_id FROM user_hints WHERE user_id=?"
            " UNION SELECT th.hints_id FROM team_hints th JOIN team_members m ON m.team_id=th.team_id"
            " WHERE m.user_id=?) ORDER BY h.name", (user["id"], user["id"]))

    def compose_hints(self, user: dict) -> str:
        parts = [HINTS_HEADER]
        for h in self.assigned_hints(user):
            parts.append(f"\n# ---- {h['name']} ----\n{h['content'].rstrip()}\n")
        if (user.get("personal_hints") or "").strip():
            parts.append(f"\n# ---- personal ----\n{user['personal_hints'].rstrip()}\n")
        return "".join(parts)

    def native_hints_path(self, user: dict) -> Path:
        return self.config_dir(user) / ".goosehints"

    def read_native_hints(self, user: dict) -> str:
        try:
            return self.native_hints_path(user).read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def write_native_hints(self, user: dict, content: str) -> str:
        """Admin saves their own hints explicitly. Back up first. Returns the backup path."""
        p = self.native_hints_path(user)
        bdir = self.s.system_dir / "backups" / "native-hints"
        bdir.mkdir(parents=True, exist_ok=True)
        backup = ""
        if p.exists():
            backup = str(bdir / f".goosehints.{time.strftime('%Y%m%d_%H%M%S')}")
            shutil.copy2(p, backup)
        _atomic_write(p, content)
        return backup

    def write_hints(self, user: dict) -> None:
        """Rewrite only the composed .goosehints of an isolated profile (safe while Goose runs)."""
        if self.is_native(user):
            return
        self.ensure_layout(user)
        _atomic_write(self.config_dir(user) / ".goosehints", self.compose_hints(user))

    # ------------------------------------------------------------ provisioning
    def _manifest_path(self, user: dict) -> Path:
        return self.root_for(user) / ".goose-web" / "managed.json"

    def _load_manifest(self, user: dict) -> dict:
        try:
            return json.loads(self._manifest_path(user).read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def _native_admin(self) -> dict | None:
        return self.db.one("SELECT * FROM users WHERE profile_mode='native' AND role='admin' ORDER BY id LIMIT 1")

    def team_items(self, user: dict) -> list[dict]:
        return self.db.query(
            "SELECT i.* FROM team_items i JOIN team_members m ON m.team_id=i.team_id WHERE m.user_id=? "
            "ORDER BY i.team_id, i.kind, i.name", (user["id"],))

    def provision(self, user: dict) -> list[str]:
        """Apply teams, hints and policy to an isolated profile. Idempotent. Returns a change list."""
        if self.is_native(user):
            return []
        self.ensure_layout(user)
        changes: list[str] = []
        cfg_dir = self.config_dir(user)
        teams = self.db.user_teams(user["id"])
        pol = effective_policy(user, teams)
        items = self.team_items(user)
        old = self._load_manifest(user)
        new_manifest: dict[str, Any] = {"extensions": [], "providers": [], "secrets": [], "skills": [],
                                        "updatedAt": time.time()}

        cfg_path = cfg_dir / "config.yaml"
        first_time = not cfg_path.exists()
        cfg = _read_yaml(cfg_path)
        exts: dict = cfg.setdefault("extensions", {}) if isinstance(cfg.get("extensions"), dict) else {}
        cfg["extensions"] = exts
        secrets_path = cfg_dir / "secrets.yaml"
        secrets = _read_yaml(secrets_path)

        admin = self._native_admin()
        admin_cfg = _read_yaml(self.config_dir(admin) / "config.yaml") if admin else {}
        if first_time:
            for key in BASE_EXTENSIONS:
                src = (admin_cfg.get("extensions") or {}).get(key)
                if isinstance(src, dict) and src.get("type") in ("platform", "builtin"):
                    exts[key] = copy.deepcopy(src)
                    changes.append(f"extension {key} (base)")
            cfg.setdefault("GOOSE_MODE", "approve")
        # shell extensions follow allow_shell (explicitly disabled so Goose defaults never enable them)
        for key in SHELL_EXTENSIONS:
            src = exts.get(key) or (admin_cfg.get("extensions") or {}).get(key)
            if not pol.get("allow_shell"):
                if isinstance(exts.get(key), dict) and exts[key].get("enabled"):
                    exts[key]["enabled"] = False
                    changes.append(f"extension {key} disabled (allow_shell off)")
                elif key == "developer" and key not in exts:
                    exts[key] = {"enabled": False, "type": "platform", "name": "developer",
                                 "description": "Shell and file editing (disabled by policy)",
                                 "display_name": "Developer", "bundled": True}
            elif key == "developer" and isinstance(src, dict) and first_time:
                exts[key] = {**copy.deepcopy(src), "enabled": True}

        def secrets_from(username: str | None, keys: list[str]) -> None:
            if not username or not keys:
                return
            su = self.db.user_by_name(username)
            if not su:
                return
            src_secrets = _read_yaml(self.config_dir(su) / "secrets.yaml")
            for k in keys:
                if k in src_secrets:
                    if secrets.get(k) != src_secrets[k]:
                        changes.append(f"secret {k}")
                    secrets[k] = src_secrets[k]
                    new_manifest["secrets"].append(k)

        default_provider = default_model = None
        for t in teams:
            tp = t.get("policy") or {}
            default_provider = default_provider or tp.get("default_provider")
            default_model = default_model or tp.get("default_model")

        for it in items:
            kind, name, payload = it["kind"], it["name"], it.get("payload") or {}
            if kind == "extension":
                entry = payload.get("entry")
                if not isinstance(entry, dict):
                    continue
                key = payload.get("key") or name
                is_shell = key.lower() in SHELL_EXTENSIONS or entry.get("type") == "stdio"
                e = copy.deepcopy(entry)
                if is_shell and not pol.get("allow_shell"):
                    e["enabled"] = False
                if exts.get(key) != e:
                    changes.append(f"extension {key}")
                exts[key] = e
                new_manifest["extensions"].append(key)
                secrets_from(payload.get("secretsFrom"), list(entry.get("env_keys") or []))
            elif kind == "provider":
                pj = payload.get("json")
                pid = payload.get("providerId") or name
                if isinstance(pj, dict):
                    target = cfg_dir / "custom_providers" / f"{safe_name(pid, 128)}.json"
                    text = json.dumps(pj, indent=2)
                    if not target.exists() or target.read_text(encoding="utf-8") != text:
                        _atomic_write(target, text)
                        changes.append(f"provider {pid}")
                    new_manifest["providers"].append(pid)
                keys = list(payload.get("secretKeys") or [])
                if isinstance(pj, dict) and pj.get("api_key_env"):
                    keys.append(pj["api_key_env"])
                secrets_from(payload.get("secretsFrom"), keys)
            elif kind == "skill":
                files = payload.get("files") or {}
                sdir = cfg_dir / "skills" / safe_name(name, 128)
                if sdir.exists() and not (sdir / MANAGED_MARK).exists():
                    continue  # the user owns a skill with that name; never overwrite it
                sdir.mkdir(parents=True, exist_ok=True)
                for rel, content in files.items():
                    rp = Path(rel)
                    if rp.is_absolute() or ".." in rp.parts:
                        continue
                    target = sdir / rp
                    if not target.exists() or target.read_text(encoding="utf-8", errors="replace") != content:
                        _atomic_write(target, content)
                        changes.append(f"skill {name}/{rel}")
                (sdir / MANAGED_MARK).write_text(f"team item {it['id']}\n", encoding="utf-8")
                new_manifest["skills"].append(name)

        # remove items that were provisioned before but are no longer assigned
        for key in set(old.get("extensions") or []) - set(new_manifest["extensions"]):
            if key in exts:
                exts.pop(key)
                changes.append(f"extension {key} removed")
        for pid in set(old.get("providers") or []) - set(new_manifest["providers"]):
            f = cfg_dir / "custom_providers" / f"{pid}.json"
            if f.exists():
                f.unlink()
                changes.append(f"provider {pid} removed")
        for k in set(old.get("secrets") or []) - set(new_manifest["secrets"]):
            if k in secrets:
                secrets.pop(k)
                changes.append(f"secret {k} removed")
        for sk in set(old.get("skills") or []) - set(new_manifest["skills"]):
            sdir = cfg_dir / "skills" / sk
            if (sdir / MANAGED_MARK).exists():
                shutil.rmtree(sdir, ignore_errors=True)
                changes.append(f"skill {sk} removed")

        # provider / model / mode defaults and allow-lists
        allowed_p = pol.get("allowed_providers") or []
        if default_provider and (first_time or not cfg.get("GOOSE_PROVIDER")):
            cfg["GOOSE_PROVIDER"] = default_provider
            if default_model:
                cfg["GOOSE_MODEL"] = default_model
            changes.append(f"default model {default_provider}/{default_model}")
        elif first_time and admin_cfg.get("GOOSE_PROVIDER") and \
                (not allowed_p or admin_cfg.get("GOOSE_PROVIDER") in allowed_p) and \
                admin_cfg.get("GOOSE_PROVIDER") in new_manifest["providers"]:
            cfg["GOOSE_PROVIDER"] = admin_cfg["GOOSE_PROVIDER"]
            cfg["GOOSE_MODEL"] = admin_cfg.get("GOOSE_MODEL")
        if allowed_p and cfg.get("GOOSE_PROVIDER") and cfg["GOOSE_PROVIDER"] not in allowed_p:
            cfg["GOOSE_PROVIDER"] = default_provider or allowed_p[0]
            cfg.pop("GOOSE_MODEL", None)
            if default_model:
                cfg["GOOSE_MODEL"] = default_model
            changes.append("provider reset to an allowed one")
        modes = pol.get("allowed_modes") or []
        if modes and cfg.get("GOOSE_MODE") not in modes:
            cfg["GOOSE_MODE"] = modes[0]
            changes.append(f"mode {modes[0]}")

        _write_yaml(cfg_path, cfg)
        if secrets or secrets_path.exists():
            _write_yaml(secrets_path, secrets)
        hints = self.compose_hints(user)
        hp = cfg_dir / ".goosehints"
        if not hp.exists() or hp.read_text(encoding="utf-8") != hints:
            _atomic_write(hp, hints)
            changes.append("goose hints")
        _atomic_write(self._manifest_path(user), json.dumps(new_manifest, indent=1))
        return changes

    def archive_profile(self, user: dict, purge: bool = False) -> str:
        if self.is_native(user):
            return ""
        r = self.root_for(user)
        if not r.exists():
            return ""
        if purge:
            shutil.rmtree(r, ignore_errors=True)
            return "purged"
        dest = self.root / "_deleted" / f"{r.name}-{time.strftime('%Y%m%d_%H%M%S')}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(r), str(dest))
        return str(dest)

    # ------------------------------------------------------------ team library
    def team_recipe_dir(self, team_id: int) -> Path:
        return self.library_dir / "teams" / str(team_id) / "recipes"

    def store_team_item_files(self, team_id: int, kind: str, name: str, payload: dict) -> None:
        if kind == "recipe":
            d = self.team_recipe_dir(team_id)
            d.mkdir(parents=True, exist_ok=True)
            _atomic_write(d / f"{safe_name(name, 128)}.yaml", payload.get("yaml") or "")

    def remove_team_item_files(self, team_id: int, kind: str, name: str) -> None:
        if kind == "recipe":
            f = self.team_recipe_dir(team_id) / f"{safe_name(name, 128)}.yaml"
            if f.exists():
                f.unlink()

    def _recipe_dirs(self, user: dict) -> list[Path]:
        dirs = [self.config_dir(user) / "recipes"]
        if self.is_native(user):
            for d in (os.environ.get("GOOSE_RECIPE_PATH") or "").split(os.pathsep):
                if d.strip():
                    dirs.append(Path(d.strip()))
            dirs.append(Path(os.path.expanduser("~")) / ".agents" / "recipes")
        return [d for d in dirs if d.is_dir()]

    def library(self, user: dict, kind: str) -> list[dict]:
        out: list[dict] = []
        cfg_dir = self.config_dir(user)
        if kind == "recipe":
            for d in self._recipe_dirs(user):
                for f in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")) + list(d.glob("*.json")))[:2000]:
                    try:
                        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                    except Exception:
                        continue
                    if not isinstance(data, dict) or "title" not in data and "recipe" not in data:
                        continue
                    r = data.get("recipe", data) if isinstance(data.get("recipe"), dict) else data
                    out.append({"kind": "recipe", "ref": str(f), "name": f.stem,
                                "description": r.get("description") or r.get("title") or "", "source": str(d)})
        elif kind == "skill":
            sk = cfg_dir / "skills"
            if sk.is_dir():
                for d in sorted(sk.iterdir()):
                    if (d / "SKILL.md").is_file():
                        desc = ""
                        m = re.search(r"^description:\s*(.+)$", (d / "SKILL.md").read_text(encoding="utf-8",
                                      errors="replace")[:4000], re.M)
                        if m:
                            desc = m.group(1).strip().strip("'\"")
                        out.append({"kind": "skill", "ref": d.name, "name": d.name, "description": desc,
                                    "source": str(sk)})
        elif kind == "extension":
            cfg = _read_yaml(cfg_dir / "config.yaml")
            for key, e in sorted((cfg.get("extensions") or {}).items()):
                if isinstance(e, dict):
                    out.append({"kind": "extension", "ref": key, "name": e.get("display_name") or key,
                                "description": e.get("description") or e.get("type") or "",
                                "source": "config.yaml", "enabled": bool(e.get("enabled"))})
        elif kind == "provider":
            cp = cfg_dir / "custom_providers"
            if cp.is_dir():
                for f in sorted(cp.glob("*.json")):
                    try:
                        j = json.loads(f.read_text(encoding="utf-8"))
                    except ValueError:
                        continue
                    out.append({"kind": "provider", "ref": f.stem, "name": j.get("display_name") or f.stem,
                                "description": j.get("base_url") or j.get("engine") or "", "source": str(cp)})
        return out

    def export_item(self, user: dict, kind: str, ref: str) -> tuple[str, dict]:
        """Build a team-item payload from a profile library item. Secrets are referenced, never copied."""
        listed = {i["ref"]: i for i in self.library(user, kind)}
        if ref not in listed:
            raise ValueError(f"{kind} not found in {user['username']}'s profile: {ref}")
        cfg_dir = self.config_dir(user)
        if kind == "recipe":
            p = Path(ref)
            return re.sub(r"[^A-Za-z0-9._-]", "-", p.stem)[:100], {"yaml": p.read_text(encoding="utf-8"),
                                                                   "origin": str(p)}
        if kind == "skill":
            d = cfg_dir / "skills" / ref
            files, total = {}, 0
            for f in d.rglob("*"):
                if f.is_file() and f.name != MANAGED_MARK:
                    total += f.stat().st_size
                    if total > MAX_SKILL_BYTES:
                        raise ValueError("skill too large to share (2 MB limit)")
                    try:
                        files[f.relative_to(d).as_posix()] = f.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        continue  # binary supporting files are not shared
            return ref, {"files": files}
        if kind == "extension":
            cfg = _read_yaml(cfg_dir / "config.yaml")
            entry = copy.deepcopy((cfg.get("extensions") or {})[ref])
            entry["enabled"] = True
            return ref, {"key": ref, "entry": entry, "secretsFrom": user["username"]}
        if kind == "provider":
            j = json.loads((cfg_dir / "custom_providers" / f"{ref}.json").read_text(encoding="utf-8"))
            return ref, {"providerId": ref, "json": j, "secretsFrom": user["username"],
                         "secretKeys": [j["api_key_env"]] if j.get("api_key_env") else []}
        raise ValueError("unknown kind")
