"""Profile layout, provisioning (teams -> profile files) and the cross-profile library.

Layout of an isolated profile (GOOSE_PATH_ROOT=<profiles_root>/<username>):
    config/  config.yaml, secrets.yaml, .goose-web-hints.md (composed hints), custom_providers/, recipes/, skills/
    data/    sessions/sessions.db, logs/        (written by Goose)
    state/                                       (written by Goose)
    workspace/                                   default folder for new chats
    .goose-web/managed.json                      content-free "provisioned" marker (Goose Web <= 1.11 kept the
                                                 manifest here; it now lives in <system_dir>/manifests/<user id>.json,
                                                 outside the user's reach - C-3)

Team shared folders: <profiles_root>/_teams/<team id> (or the team's share_folder), reachable by the members.
Isolated workers run with CONTEXT_FILE_NAMES=[".goose-web-hints.md"] (workers.py), so Goose loads only the
gateway-written hints file, never an AGENTS.md / .goosehints planted in a working folder (spec 009).

The admin's native profile (profile_mode = native) is NEVER provisioned. The gateway only reads it, except
for its goose hints: an admin saves them in the UI (the previous file is backed up first), or - managed native
hints, spec 011 - the gateway writes the native user's composed hints (personal + assigned + team documents) into
the native profile's own config/.goosehints, so Goose Desktop, the goose CLI and scheduled runs on that account load
the same hints as the web chats. Setting `native_hints_owner` = that user's id (one per native profile).
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
from .effort import DEFAULT_EFFORT
from .policy import (ANY, GUARDED_EXTENSIONS, allows, effective_policy, ext_key, extension_needs, guard_on,
                     is_command_extension, missing)
from .security import safe_name

MANAGED_MARK = ".goose-web-managed"
HINTS_HEADER = ("# Managed by Goose Web. Edit your personal hints in the web UI (Settings > Goose hints);\n"
                "# changes made directly in this file are overwritten.\n")
PRECEDENCE_NOTE = ("\n# How to use these hints: they are listed from lowest to highest precedence. Team hints come\n"
                   "# last and are final: if a personal hint conflicts with a team hint, follow the team hint.\n")
# The only hints file name Goose loads for isolated profiles (CONTEXT_FILE_NAMES, set by workers.py).
GW_HINTS_FILENAME = ".goose-web-hints.md"
# Header of a native profile's .goosehints when Goose Web manages it (spec 011).
NATIVE_HINTS_HEADER = ("# Managed by Goose Web (managed native hints). Goose Desktop, the goose CLI and scheduled runs on\n"
                       "# this Windows account load this file too. Edit the documents in Goose Web: Admin > Hints (team\n"
                       "# and assigned documents) or Settings > Goose hints (personal). Changes made directly in this\n"
                       "# file are overwritten; the previous versions are in <system_dir>/backups/native-hints.\n")
NATIVE_HINTS_SETTING = "native_hints_owner"
LEGACY_HINTS_FILENAME = ".goosehints"
# File names a non-admin may not upload or create: Goose's default context files and ours (lower case).
HINT_FILE_NAMES = frozenset({".goosehints", "agents.md", GW_HINTS_FILENAME.lower()})
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


def strip_always_allow(path: Path) -> bool:
    """Spec 018: drop the user 'always allow' tool permissions from a profile's permission.yaml (Goose never asks
    about those tools, even in Approve mode, so a guarded member's calls to them would bypass the guard). Goose reads
    the file at worker start; the caller's change list restarts the worker. Returns True if something was removed."""
    if not path.exists():
        return False
    data = _read_yaml(path)
    user = data.get("user") if isinstance(data.get("user"), dict) else None
    if not user or not user.get("always_allow"):
        return False
    user["always_allow"] = []
    _write_yaml(path, data)
    return True


def _same_path(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


def _safe_id(value: Any) -> str | None:
    """A manifest entry usable as one file / folder name (security.safe_name rules: no separators, '..', drive,
    ':' or reserved device name); None if it is not."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    try:
        return safe_name(value, 128)
    except ValueError:
        return None


_REPARSE = 0x400   # FILE_ATTRIBUTE_REPARSE_POINT (junctions, symlinks, mount points)


def _is_reparse(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if getattr(st, "st_file_attributes", 0) & _REPARSE:
        return True
    return os.path.islink(p)


def _real_norm(p: str | Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.realpath(str(p))))


def _inside_profile(p: Path, root: Path) -> bool:
    """`p` (existing or not) lies inside the profile `root`: lexically, after resolving links, and without any
    junction / symlink between the root and `p` (the root itself included)."""
    try:
        rel = Path(os.path.relpath(os.path.abspath(p), os.path.abspath(root)))
    except ValueError:   # another drive
        return False
    if rel.parts and rel.parts[0] == "..":
        return False
    cur = Path(os.path.abspath(root))
    if _is_reparse(cur):
        return False
    for part in rel.parts:
        cur = cur / part
        if _is_reparse(cur):
            return False
    rr, rp = _real_norm(root), _real_norm(p)
    return rp == rr or rp.startswith(rr.rstrip("\\/") + os.sep)


def _delete_target(folder: Path, name: Any, suffix: str, root: Path) -> Path | None:
    """The file / folder `<folder>/<name><suffix>` a provisioning delete may touch, or None: the name must be a safe
    id, the folder must lie inside the user's profile without links, and the target's resolved parent must be
    exactly that folder (C-3)."""
    sid = _safe_id(name)
    if sid is None:
        return None
    target = folder / f"{sid}{suffix}"
    if not _inside_profile(target, root) or _is_reparse(target):
        return None
    if _real_norm(target.parent) != _real_norm(folder) or os.path.dirname(_real_norm(target)) != _real_norm(folder):
        return None
    return target


LEGACY_MANIFEST_STUB = ('{"moved": "Goose Web keeps the provisioning manifest in <system_dir>/manifests; this file '
                        'only marks the profile as provisioned"}\n')
_GUARDED = {ext_key(n) for n in GUARDED_EXTENSIONS}
# Description of an extension entry Goose Web pinned off; Goose Web <= 1.11 wrote "... (disabled by policy)" too.
PINNED_SUFFIX = "(disabled by policy)"
PINNED_DESCRIPTION = "Turned off by Goose Web: your team does not give the permission it needs " + PINNED_SUFFIX


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

    # ------------------------------------------------------------ team shared folder
    def team_folder(self, team: dict) -> Path:
        """The team's shared folder: its share_folder (absolute) or <profiles_root>/_teams/<team id>."""
        sf = str((team.get("policy") or {}).get("share_folder") or "").strip()
        if sf and os.path.isabs(sf):
            return Path(sf)
        return self.root / "_teams" / str(int(team["id"]))

    def ensure_team_folder(self, team: dict) -> Path | None:
        p = self.team_folder(team)
        try:
            p.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
        return p

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

    def hint_sections(self, user: dict) -> dict:
        """The parts of a user's composed hints, lowest precedence first (spec 009)."""
        team = self.db.user_team(user["id"])
        pol = effective_policy(user, [team] if team else [])
        personal = (user.get("personal_hints") or "").strip()
        use_personal = bool(personal) and (user.get("role") == "admin" or bool(pol.get("hints_edit")))
        mine = self.db.query("SELECT h.* FROM hints_docs h JOIN user_hints uh ON uh.hints_id=h.id "
                             "WHERE uh.user_id=? ORDER BY h.name", (user["id"],))
        team_docs = self.db.query("SELECT h.* FROM hints_docs h JOIN team_hints th ON th.hints_id=h.id "
                                  "WHERE th.team_id=? ORDER BY h.name", (team["id"],)) if team else []
        team_ids = {d["id"] for d in team_docs}
        return {"team": team, "personal": personal if use_personal else "",
                "personalDropped": bool(personal) and not use_personal,
                "user": [h for h in mine if h["id"] not in team_ids],   # a doc on both lists appears once, as team
                "teamDocs": team_docs}

    def compose_hints(self, user: dict) -> str:
        """Header, precedence rule, personal hints (if the team allows them), documents an admin assigned to
        this user, then the team's documents LAST, so team hints are final (spec 009)."""
        s = self.hint_sections(user)
        parts = [NATIVE_HINTS_HEADER if self.is_native(user) else HINTS_HEADER, PRECEDENCE_NOTE]
        if s["personal"]:
            parts.append(f"\n# ---- personal hints (lowest precedence) ----\n{s['personal'].rstrip()}\n")
        for h in s["user"]:
            parts.append(f"\n# ---- {h['name']} (assigned to you) ----\n{h['content'].rstrip()}\n")
        if s["teamDocs"]:
            parts.append(f"\n# ==== Team: {s['team']['name']} (final: these take precedence) ====\n")
            for h in s["teamDocs"]:
                parts.append(f"\n# ---- {h['name']} ----\n{h['content'].rstrip()}\n")
        return "".join(parts)

    def hints_path(self, user: dict) -> Path:
        """The file Goose loads the composed hints from (isolated profiles)."""
        return self.config_dir(user) / GW_HINTS_FILENAME

    def native_hints_path(self, user: dict) -> Path:
        return self.config_dir(user) / ".goosehints"

    def read_native_hints(self, user: dict) -> str:
        try:
            return self.native_hints_path(user).read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def native_hints_managed(self, user: dict) -> bool:
        """Spec 011: Goose Web writes this native user's composed hints into the native .goosehints."""
        if not self.is_native(user):
            return False
        owner = self.db.get_setting(NATIVE_HINTS_SETTING)
        return owner is not None and str(owner) == str(user["id"])

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

    def _drop_legacy_hints(self, user: dict) -> bool:
        """Remove the config/.goosehints that Goose Web 1.4 wrote (only if it is ours: it starts with the header)."""
        p = self.config_dir(user) / LEGACY_HINTS_FILENAME
        try:
            if p.is_file() and p.read_text(encoding="utf-8", errors="replace").startswith(HINTS_HEADER[:40]):
                p.unlink()
                return True
        except OSError:
            pass
        return False

    def write_hints(self, user: dict) -> None:
        """Rewrite only the composed hints file of an isolated profile (safe while Goose runs). A native user's
        .goosehints is rewritten only when managed native hints are on for that user (and only if it changed)."""
        if self.is_native(user):
            if self.native_hints_managed(user):
                text = self.compose_hints(user)
                if self.read_native_hints(user) != text:
                    self.write_native_hints(user, text)
            return
        self.ensure_layout(user)
        _atomic_write(self.hints_path(user), self.compose_hints(user))
        self._drop_legacy_hints(user)

    # ------------------------------------------------------------ provisioning
    def manifest_path(self, user: dict) -> Path:
        """What the gateway provisioned for this user: <system_dir>/manifests/<user id>.json, outside every profile
        and container (security assessment 2026-11-09, C-3: the old <profile>/.goose-web/managed.json is writable
        by the user's sandboxed agent and drove the gateway's deletes)."""
        return self.s.system_dir / "manifests" / f"{int(user['id'])}.json"

    _manifest_path = manifest_path

    def legacy_manifest_path(self, user: dict) -> Path:
        return self.root_for(user) / ".goose-web" / "managed.json"

    def provisioned(self, user: dict) -> bool:
        """True once provision() ran for this user (context.upstream_for provisions on first use otherwise)."""
        return self.manifest_path(user).exists() or self.legacy_manifest_path(user).exists()

    def _load_manifest(self, user: dict) -> dict:
        """The gateway-owned manifest; else (first run after the upgrade) the legacy in-profile one, whose content
        is untrusted: only well-formed names are kept (every delete is checked again in provision())."""
        try:
            data = json.loads(self.manifest_path(user).read_text(encoding="utf-8"))
            trusted = True
        except (FileNotFoundError, ValueError, OSError):
            try:
                data = json.loads(self.legacy_manifest_path(user).read_text(encoding="utf-8"))
            except (FileNotFoundError, ValueError, OSError):
                return {}
            trusted = False
        if not isinstance(data, dict):
            return {}
        out: dict[str, Any] = {}
        for k in ("extensions", "providers", "secrets", "skills"):
            v = data.get(k)
            out[k] = [x for x in v if _safe_id(x) is not None] if isinstance(v, list) else []
        if trusted:
            for k in ("pinned", "parked"):
                if isinstance(data.get(k), dict):
                    out[k] = data[k]
        else:
            # guarded extension keys from an untrusted manifest are never removed (Goose would turn them on)
            out["extensions"] = [x for x in out["extensions"] if ext_key(x) not in _GUARDED]
        td = data.get("teamDefault")
        if isinstance(td, list) and len(td) == 2 and all(isinstance(x, (str, type(None))) for x in td):
            out["teamDefault"] = td
        return out

    def _write_manifest(self, user: dict, manifest: dict) -> None:
        _atomic_write(self.manifest_path(user), json.dumps(manifest, indent=1))
        legacy = self.legacy_manifest_path(user)
        # keep a content-free marker where Goose Web <= 1.11 (and context.upstream_for) looks for it
        try:
            if not legacy.is_file() or legacy.read_text(encoding="utf-8") != LEGACY_MANIFEST_STUB:
                if _inside_profile(legacy.parent, self.root_for(user)):
                    _atomic_write(legacy, LEGACY_MANIFEST_STUB)
        except OSError:
            pass

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
        root = self.root_for(user)
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
        if first_time and pol.get("allow_shell"):
            src = (admin_cfg.get("extensions") or {}).get("developer")
            if isinstance(src, dict):
                exts["developer"] = {**copy.deepcopy(src), "enabled": True}

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

        team = teams[0] if teams else None
        tp = (team or {}).get("policy") or {}
        default_provider = tp.get("default_provider") or None
        default_model = tp.get("default_model") or None
        if team is not None:
            self.ensure_team_folder(team)

        for it in items:
            kind, name, payload = it["kind"], it["name"], it.get("payload") or {}
            if kind == "extension":
                entry = payload.get("entry")
                if not isinstance(entry, dict):
                    continue
                key = payload.get("key") or name
                if ext_key(key) in _GUARDED:
                    continue   # shell-capable / extension-starting: follows the member's permissions (below)
                e = copy.deepcopy(entry)
                if is_command_extension(e) and not pol.get("allow_shell"):
                    # not even dormant: a disabled entry can be switched on (B-2). Removed below if it was there.
                    continue
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
                    if not _inside_profile(target, root) or _is_reparse(target):
                        continue   # a junction / link planted in the profile: never write through it (C-3)
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
                if not _inside_profile(sdir, root) or _is_reparse(sdir):
                    continue   # never write through a junction / link planted in the profile (C-3)
                if sdir.exists() and not (sdir / MANAGED_MARK).exists():
                    continue  # the user owns a skill with that name; never overwrite it
                sdir.mkdir(parents=True, exist_ok=True)
                for rel, content in files.items():
                    rp = Path(rel)
                    if rp.is_absolute() or ".." in rp.parts:
                        continue
                    target = sdir / rp
                    if not _inside_profile(target, root):
                        continue
                    if not target.exists() or target.read_text(encoding="utf-8", errors="replace") != content:
                        _atomic_write(target, content)
                        changes.append(f"skill {name}/{rel}")
                (sdir / MANAGED_MARK).write_text(f"team item {it['id']}\n", encoding="utf-8")
                new_manifest["skills"].append(name)

        # remove items that were provisioned before but are no longer assigned. Every name comes from the manifest:
        # only safe ids, and only files / folders whose resolved parent is the expected folder of THIS profile (C-3).
        for key in set(old.get("extensions") or []) - set(new_manifest["extensions"]):
            if key in exts and ext_key(key) not in _GUARDED:
                exts.pop(key)
                changes.append(f"extension {key} removed")
        for pid in set(old.get("providers") or []) - set(new_manifest["providers"]):
            f = _delete_target(cfg_dir / "custom_providers", pid, ".json", root)
            if f is not None and f.is_file():
                f.unlink()
                changes.append(f"provider {pid} removed")
        for k in set(old.get("secrets") or []) - set(new_manifest["secrets"]):
            if k in secrets:
                secrets.pop(k)
                changes.append(f"secret {k} removed")
        for sk in set(old.get("skills") or []) - set(new_manifest["skills"]):
            sdir = _delete_target(cfg_dir / "skills", sk, "", root)
            if sdir is not None and sdir.is_dir() and (sdir / MANAGED_MARK).is_file():
                shutil.rmtree(sdir, ignore_errors=True)
                changes.append(f"skill {sk} removed")

        self._apply_extension_permissions(pol, exts, admin_cfg, old, new_manifest, changes)

        # provider / model / mode defaults and allow-lists (spec 009: the team default model)
        allowed_p = [p for p in pol.get("allowed_providers") or [] if p != ANY]
        team_default = [default_provider, default_model] if default_provider else None
        default_ok = bool(team_default) and allows(pol, "allowed_providers", default_provider) and \
            (not default_model or allows(pol, "allowed_models", default_model))
        prev_default = old.get("teamDefault")
        current = [cfg.get("GOOSE_PROVIDER"), cfg.get("GOOSE_MODEL")]
        if team_default:
            new_manifest["teamDefault"] = team_default
        if default_ok and (first_time or not cfg.get("GOOSE_PROVIDER") or
                           (team_default != prev_default and (prev_default is None or current == prev_default))):
            if current != team_default:
                cfg["GOOSE_PROVIDER"] = default_provider
                if default_model:
                    cfg["GOOSE_MODEL"] = default_model
                else:
                    cfg.pop("GOOSE_MODEL", None)
                changes.append(f"default model {default_provider}/{default_model or '(provider default)'}")
        elif first_time and admin_cfg.get("GOOSE_PROVIDER") and \
                allows(pol, "allowed_providers", admin_cfg.get("GOOSE_PROVIDER")) and \
                admin_cfg.get("GOOSE_PROVIDER") in new_manifest["providers"]:
            cfg["GOOSE_PROVIDER"] = admin_cfg["GOOSE_PROVIDER"]
            cfg["GOOSE_MODEL"] = admin_cfg.get("GOOSE_MODEL")
        if cfg.get("GOOSE_PROVIDER") and not allows(pol, "allowed_providers", cfg["GOOSE_PROVIDER"]):
            cfg.pop("GOOSE_MODEL", None)
            if default_ok:
                cfg["GOOSE_PROVIDER"] = default_provider
                if default_model:
                    cfg["GOOSE_MODEL"] = default_model
            elif allowed_p:
                cfg["GOOSE_PROVIDER"] = allowed_p[0]
            else:
                cfg.pop("GOOSE_PROVIDER", None)
            changes.append("provider reset to an allowed one")
        if cfg.get("GOOSE_MODEL") and not allows(pol, "allowed_models", cfg["GOOSE_MODEL"]):
            if default_ok and default_model and cfg.get("GOOSE_PROVIDER") == default_provider:
                cfg["GOOSE_MODEL"] = default_model
            else:
                cfg.pop("GOOSE_MODEL", None)
            changes.append("model reset to an allowed one")
        modes = pol.get("allowed_modes") or []
        if modes and not allows(pol, "allowed_modes", cfg.get("GOOSE_MODE")):
            cfg["GOOSE_MODE"] = "approve" if allows(pol, "allowed_modes", "approve") else modes[0]
            changes.append(f"mode {cfg['GOOSE_MODE']}")
        # spec 021: the highest thinking effort by default (Goose clamps it per model: models without `max` get their
        # top level). A value the member saved (Settings > Preferences) is kept. No team policy restricts effort.
        if not str(cfg.get("GOOSE_THINKING_EFFORT") or "").strip():
            cfg["GOOSE_THINKING_EFFORT"] = DEFAULT_EFFORT
            changes.append(f"thinking effort {DEFAULT_EFFORT} (default)")
        if guard_on(pol) and strip_always_allow(cfg_dir / "permission.yaml"):
            changes.append("prompt guard: 'always allow' tool permissions removed")

        _write_yaml(cfg_path, cfg)
        if secrets or secrets_path.exists():
            _write_yaml(secrets_path, secrets)
        hints = self.compose_hints(user)
        hp = self.hints_path(user)
        if not hp.exists() or hp.read_text(encoding="utf-8") != hints:
            _atomic_write(hp, hints)
            changes.append("goose hints")
        if self._drop_legacy_hints(user):
            changes.append("old .goosehints removed (Goose Web now uses .goose-web-hints.md)")
        self._write_manifest(user, new_manifest)
        return changes

    @staticmethod
    def _apply_extension_permissions(pol: dict, exts: dict, admin_cfg: dict, old: dict, new_manifest: dict,
                                     changes: list[str]) -> None:
        """Shell-capable and extension-starting extensions follow the member's permissions, in both directions
        (security assessment 2026-11-09, B-2/B-3).

        Without the permission (policy.extension_needs: allow_shell; extensionmanager also extensions_edit) the key
        is PINNED as `enabled: false`. It is not removed: Goose 1.57 enables a bundled platform extension that is
        missing from config.yaml (measured: without a `developer` key the member's chats had `shell`, and every
        member had `scheduler`). extensionmanager is pinned off too, so the model cannot switch developer back on.
        With the permission again, what Goose Web pinned is restored (BASE_EXTENSIONS and developer on; others as
        in the admin's config, or Goose's default).
        Command extensions (stdio, inline_python) without allow_shell are PARKED in the gateway's manifest and taken
        out of config.yaml (a disabled entry can be switched on); they come back when allow_shell is on again."""
        admin_exts = admin_cfg.get("extensions") or {}
        # Deny by default: every other bundled extension the admin's Goose lists is written disabled when the member
        # has no entry for it, so a bundled extension Goose turns on by default (a new release may add one) is not
        # silently on for members. Team items and the member's own entries win (only missing keys are added).
        for key, src in admin_exts.items():
            if key not in exts and key not in BASE_EXTENSIONS and ext_key(key) not in _GUARDED and \
                    isinstance(src, dict) and src.get("bundled") and src.get("type") in ("platform", "builtin"):
                exts[key] = {**copy.deepcopy(src), "enabled": False}
        old_pinned = old.get("pinned") if isinstance(old.get("pinned"), dict) else {}
        parked = dict(old.get("parked") or {}) if isinstance(old.get("parked"), dict) else {}
        pinned: dict[str, bool] = {}
        for key in sorted(GUARDED_EXTENSIONS):
            cur = exts.get(key)
            ours = key in old_pinned or (isinstance(cur, dict) and str(cur.get("description") or "")
                                         .endswith(PINNED_SUFFIX))
            if missing(pol, extension_needs(key)):
                if isinstance(cur, dict):
                    if cur.get("enabled") is not False:
                        cur["enabled"] = False
                        ours = True
                        changes.append(f"extension {key} disabled (needs {' and '.join(extension_needs(key))})")
                else:
                    ours = True
                    src = admin_exts.get(key)
                    stub = copy.deepcopy(src) if isinstance(src, dict) and src.get("type") in ("platform", "builtin") \
                        else {"type": "platform", "name": key, "display_name": key.replace("_", " ").title(),
                              "bundled": True}
                    stub.update(enabled=False, description=PINNED_DESCRIPTION)
                    exts[key] = stub
                    changes.append(f"extension {key} pinned off (needs {' and '.join(extension_needs(key))})")
                if ours:
                    pinned[key] = True
                continue
            if not ours or not isinstance(cur, dict) or cur.get("enabled"):
                continue
            src = admin_exts.get(key)
            if key in BASE_EXTENSIONS or key == "developer":
                base = copy.deepcopy(src) if isinstance(src, dict) and src.get("type") in ("platform", "builtin") \
                    else {k: v for k, v in cur.items() if k != "description"}
                exts[key] = {**base, "enabled": True}
            elif isinstance(src, dict) and src.get("type") in ("platform", "builtin"):
                exts[key] = copy.deepcopy(src)
            else:
                exts.pop(key)   # Goose's own default for this bundled extension applies again
            changes.append(f"extension {key} restored (permission granted)")
        if not pol.get("allow_shell"):
            for key in [k for k, e in exts.items() if is_command_extension(e)]:
                parked[key] = exts.pop(key)
                changes.append(f"extension {key} parked (command extensions need allow_shell)")
        else:
            for key in list(parked):
                e = parked.pop(key)
                if key not in exts and isinstance(e, dict):
                    exts[key] = e
                    changes.append(f"extension {key} restored (allow_shell on)")
        new_manifest["pinned"] = pinned
        new_manifest["parked"] = parked

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
