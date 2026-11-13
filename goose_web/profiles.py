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
import itertools
import json
import logging
import os
import re
import shutil
import stat
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
# adversary.md (spec 026): Goose's adversary mode is on when <config dir>/adversary.md exists; Goose Web writes it.
HINT_FILE_NAMES = frozenset({".goosehints", "agents.md", GW_HINTS_FILENAME.lower(), "adversary.md"})
# Platform extensions every new profile starts with (copied from the admin profile when present there).
BASE_EXTENSIONS = ["todo", "skills", "apps", "chatrecall", "summarize", "extensionmanager", "analyze", "memory",
                   "summon", "tom"]
MAX_SKILL_BYTES = 2 * 1024 * 1024
MAX_SKILL_FILES = 500
# Bounds of the library (review of 1.21.0, L-3 / L-4). Whoever fills a folder in a profile decides how big it is, so
# every limit applies before the work it limits.
MAX_SKILL_ENTRIES = 5000      # files and folders looked at while reading one skill
MAX_SKILL_DEPTH = 12          # levels of folders inside a skill
MAX_SKILL_REL_PATH = 180      # characters of a file's path inside a skill (it must also fit in the members' profiles)
MAX_RECIPE_BYTES = 1024 * 1024   # a recipe or provider file larger than this is neither listed nor shared
LIBRARY_SCAN = 2000           # entries of one folder the picker looks at
LIBRARY_BYTES = 16 * 1024 * 1024   # recipe files one listing parses in total
# Spec 028. Where Goose looks for GLOBAL skills, recipes and agents: under the home folder of the operating-system
# account, which GOOSE_PATH_ROOT does not move (Goose 1.57.0 and 1.59.0: crates/goose/src/skills/mod.rs
# all_skill_dirs_with_config, agents/platform_extensions/summon.rs discover_filesystem_sources,
# recipe/local_recipes.rs local_recipe_dirs). Relative to that home folder. The home is the gateway's account, i.e.
# the administrator's: inside the sandbox a member's agent cannot read these folders, without it every agent loads
# them. Administrators offer skills and recipes from them per team (library items); agents are not offered.
HOME_SKILL_DIRS = ((".agents", "skills"), (".claude", "skills"), (".config", "agents", "skills"))
HOME_RECIPE_DIRS = ((".agents", "recipes"), (".goose", "recipes"))
HOME_AGENT_DIRS = ((".agents", "agents"), (".goose", "agents"), (".claude", "agents"))
# FIX team-skills-not-loadable-via-load: first line of a skill bridge (config/agents/<skill>.md) Goose Web wrote
SKILL_BRIDGE_MARK = "<!-- skill-bridge: managed by Goose Web"
log = logging.getLogger("goose_web")


def _split_skill(text: str) -> tuple[dict, str] | None:
    """(frontmatter dict, body) of a SKILL.md, or None if it has no YAML frontmatter mapping."""
    lines = text.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            try:
                meta = yaml.safe_load("\n".join(lines[1:i])) or {}
            except yaml.YAMLError:
                return None
            if not isinstance(meta, dict):
                return None
            return meta, "\n".join(lines[i + 1:]).strip("\n") + "\n"
    return None


def _read_yaml(p: Path) -> dict:
    try:
        with open(p, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}


def _atomic_write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, p)
    except BaseException:
        # a write that failed leaves nothing behind (third review of 1.21.0, N-3: a left-over temporary file kept
        # a new skill folder from being removed again, and the folder was then taken for the member's own)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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


def _linked(p: Path) -> bool:
    """True for something a library export must not read through (spec 028, D5): a junction, a symbolic link or a
    mount point, or a FILE with more than one hard link - its content may be a file somewhere else, which the gateway
    can read and whoever made the link may not. Something that cannot be examined counts as linked."""
    if _is_reparse(p):
        return True
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return not stat.S_ISDIR(st.st_mode) and getattr(st, "st_nlink", 1) > 1


def _scan(d: Path, limit: int | None = None) -> list[Path]:
    """At most `limit` (default LIBRARY_SCAN) entries of a folder, sorted by name. Bounded BEFORE the listing is
    complete and before the sorting (reviews of 1.21.0, L-4 and M-10)."""
    try:
        with os.scandir(d) as it:
            names = [e.name for e in itertools.islice(it, LIBRARY_SCAN if limit is None else max(0, limit))]
    except OSError:
        return []
    return [d / n for n in sorted(names)]


def _text(v: Any, limit: int = 500) -> str:
    """A value from a file someone else wrote, as text that can be sent: a str, cut to `limit`, with anything that
    cannot be encoded replaced (a lone surrogate makes the whole answer unserialisable: second review, M-8).
    Anything that is not a str is ''."""
    return v[:limit].encode("utf-8", "replace").decode("utf-8") if isinstance(v, str) else ""


def _sendable(name: str) -> bool:
    """A file, folder or key name that can be part of the picker's answer and of a reference sent back."""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return 0 < len(name) <= 200


def _small_tree(obj: Any, nodes: int = 20000, depth: int = 24, chars: int = 1024 * 1024) -> bool:
    """True when `obj`, written out as JSON, stays small and is plain data: at most `nodes` values and `chars`
    characters of text and keys, both counting every repetition; at most `depth` levels; only JSON types. YAML
    aliases share one object; JSON writes it out every time it is used, so a few hundred bytes of nested aliases
    become gigabytes (second review, M-1), and so does one long text used twenty thousand times (third review,
    N-1). The count stops at the budget: it never walks more than it allows."""
    todo = [(obj, 0)]
    seen = text = 0
    while todo:
        o, d = todo.pop()
        seen += 1
        if seen > nodes or d > depth:
            return False
        if isinstance(o, dict):
            if len(o) > nodes or not all(isinstance(k, str) for k in o):
                return False
            text += sum(len(k) for k in o)
            todo.extend((v, d + 1) for v in o.values())
        elif isinstance(o, list):
            if len(o) > nodes:
                return False
            todo.extend((v, d + 1) for v in o)
        elif isinstance(o, str):
            text += len(o)
        elif not (o is None or isinstance(o, (bool, int, float))):
            return False
        if text > chars:
            return False
    return True


def _names(v: Any) -> list[str]:
    """The names in a list a file or a stored item supplies (an extension's env_keys, a provider's secret keys):
    only non-empty text. Anything else - not a list, a number, a nested list - is no name; it must not be able to
    fail the provisioning of a whole team (third review, N-2)."""
    return [k for k in v if isinstance(k, str) and k] if isinstance(v, list) else []


def _read_head(p: Path, size: int = 16384) -> str:
    """The first bytes of a file as text; never the whole of a file of unknown size."""
    with open(p, "rb") as fh:
        return fh.read(size).decode("utf-8", "replace")


def account_home() -> Path:
    """The home folder of the account the gateway runs as. Goose finds its global skill, recipe and agent folders
    there (HOME_*_DIRS). Asked from Windows, as Goose does (it does not go by USERPROFILE: measured, spec 028), so
    that the picker and `check` look where Goose looks. One function, so that the tests never read the developer's
    real home folder."""
    from . import winsec
    return Path(winsec.profile_folder() or os.path.expanduser("~"))


def home_library_summary() -> dict:
    """What Goose finds in the home folder of the gateway's account: the NAMES of global skills, recipes and agents
    (spec 028; for `goose-web check`). A member's agent loads them whenever it is not confined by the sandbox.
    Goose follows links, so the names are counted through links too (review of 1.21.0, L-7: a linked folder used to
    be reported as "none"). `linked` = the folders that are reached through a link; the library picker does not
    offer what is in them."""
    h = account_home()
    out: dict[str, Any] = {"home": str(h), "skills": set(), "recipes": set(), "agents": set(), "linked": []}
    for key, rels, want in (("skills", HOME_SKILL_DIRS, lambda x: (x / "SKILL.md").is_file()),
                            ("recipes", HOME_RECIPE_DIRS, lambda x: x.suffix.lower() in (".yaml", ".yml", ".json")),
                            ("agents", HOME_AGENT_DIRS, lambda x: x.suffix.lower() == ".md")):
        for rel in rels:
            d = h.joinpath(*rel)
            try:
                if not d.is_dir():   # follows a link, as Goose does
                    continue
                if not _inside_profile(d, h):
                    out["linked"].append(str(d))
                out[key].update(x.name if key == "skills" else x.stem for x in _scan(d) if want(x))
            except OSError:
                continue
    for key in ("skills", "recipes", "agents"):
        out[key] = sorted(out[key])
    return out


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
    SET_ASIDE_KEEP = 5   # unreadable config.yaml / secrets.yaml files kept per member and file name (the newest)

    def __init__(self, settings: Settings, db: Database):
        self.s = settings
        self.db = db
        self.root = settings.profiles_root
        self.library_dir = settings.system_dir / "library"
        # spec 026: the classification endpoint's URL while the gateway holds its port (set by the app); None =
        # Goose-native detection uses patterns only
        self.security_endpoint: Any = None

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
            if isinstance(data.get("adversary"), str):   # spec 026: hash of the adversary.md the gateway wrote
                out["adversary"] = data["adversary"]
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

    def relay_mapping(self, user: dict) -> dict[str, str]:
        """Spec 014 relays the user's sandboxed worker runs now (target -> forwarder address), from the record
        workers._start_relays keeps; {} for a user without relays."""
        from . import relay as rl
        from . import sandbox as sb
        return rl.state_mapping(self.s.system_dir / "sandbox", sb.container_name(str(self.root), user["username"]))

    def _read_profile_yaml(self, user: dict, p: Path) -> dict:
        """config.yaml / secrets.yaml of an isolated profile. A file that is not readable YAML or not a mapping (an
        interrupted write, or something the member's agent did) used to make every start of that member's agent
        fail until an administrator repaired the file by hand (review 2026-11-12, B-9). It is now moved to
        <system_dir>/backups/profiles/<user>/, the event is audited, and provisioning rebuilds the file from the
        team's policy. Second review 2026-11-12: every way the YAML parser can fail counts (a bad date is a
        ValueError, deep nesting a RecursionError: R-10); two files set aside in the same second no longer overwrite
        each other, and only the newest SET_ASIDE_KEEP per file name are kept, because the member decides how often
        and how large (R-9). Something that is not a file (a folder or a link named config.yaml) is not moved: the
        start fails, as before."""
        try:
            data = _read_yaml(p)
            if isinstance(data, dict):
                return data
            problem = "not a mapping"
        except (yaml.YAMLError, ValueError, RecursionError) as e:   # ValueError includes UnicodeDecodeError
            problem = e.__class__.__name__
        dst_dir = self.s.system_dir / "backups" / "profiles" / safe_name(user["username"])
        dst_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        dst, n = dst_dir / f"{p.name}.{stamp}.unreadable", 1
        while dst.exists():
            n += 1
            dst = dst_dir / f"{p.name}.{stamp}-{n}.unreadable"
        # The member's agent owns the file's attributes and times (third review, T-7 / T-8): a read-only file could
        # not be moved across volumes or pruned later, and a back-dated one would be pruned at once.
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        shutil.move(str(p), str(dst))   # also across volumes (system_dir may be on another disk)
        try:
            os.utime(dst)               # set aside NOW, whatever date the file carried
        except OSError:
            pass
        others = []
        try:
            found = list(dst_dir.glob(f"{p.name}.*.unreadable"))
        except OSError:   # the folder cannot be listed: nothing is pruned this time, the set-aside itself is done
            found = []
        for f in found:
            try:
                if f != dst and f.is_file() and not f.is_symlink():
                    others.append((f.stat().st_mtime, f))
            except OSError:
                continue
        for _, f in sorted(others, key=lambda t: t[0], reverse=True)[max(0, self.SET_ASIDE_KEEP - 1):]:
            try:   # one file that cannot be deleted must not end the pruning of the others
                os.chmod(f, stat.S_IWRITE | stat.S_IREAD)
                f.unlink()
            except OSError as e:
                log.warning("profile %s: an old set-aside file could not be removed (%s: %s)", user.get("username"),
                            f.name, e.__class__.__name__)
        log.warning("profile %s: %s was not readable (%s); moved to %s and rebuilt", user.get("username"), p.name,
                    problem, dst)
        self.db.audit("profile.file.set_aside", user=user, target=str(user.get("username") or ""),
                      detail={"file": p.name, "problem": problem, "movedTo": str(dst)}, ok=False)
        return {}

    def security_plan(self, user: dict, relays: dict[str, str] | None = None) -> dict:
        """Spec 026: what this profile gets of Goose's own security settings (goosesec.profile_plan). A sandboxed
        AppContainer member reaches the classification endpoint at its relay forwarder's address (`relays`)."""
        from . import goosesec
        from . import relay as rl
        cfg = goosesec.load(self.db)
        endpoint = self.security_endpoint() if callable(self.security_endpoint) else None
        if endpoint and relays:
            endpoint = rl.rewrite_text(endpoint, relays)
        token = goosesec.token_for(self.db, user["id"]) if endpoint else None
        return goosesec.profile_plan(cfg, native=self.is_native(user), token=token, endpoint=endpoint)

    def _apply_security(self, user: dict, cfg: dict, secrets: dict, cfg_dir: Path, root: Path, old: dict,
                        new_manifest: dict, changes: list[str], relays: dict[str, str]) -> None:
        """Spec 026: Goose's prompt injection detection keys, the classifier token (the profile's secret store) and
        config/adversary.md, written from the administrators' settings and removed again when they are off."""
        from . import goosesec
        plan = self.security_plan(user, relays)
        for k, v in plan["config"].items():
            if cfg.get(k) != v or type(cfg.get(k)) is not type(v):
                cfg[k] = v
                changes.append(f"goose security: {k}")
        for k in plan["remove"]:
            if k in cfg:
                cfg.pop(k)
                changes.append(f"goose security: {k} removed")
        cfg.pop(goosesec.CLS_TOKEN, None)   # Goose reads the token from the secret store only; never in config.yaml
        if plan["secret"]:
            if secrets.get(goosesec.CLS_TOKEN) != plan["secret"]:
                secrets[goosesec.CLS_TOKEN] = plan["secret"]
                changes.append("goose security: classifier token")
        elif goosesec.CLS_TOKEN in secrets:
            secrets.pop(goosesec.CLS_TOKEN)
            changes.append("goose security: classifier token removed")
        # a member's agent must not carry Goose's other security switches in its own config.yaml either (the
        # undocumented command classifier, anything new): only what the plan sets stays
        for k in [k for k in cfg if isinstance(k, str) and k.upper().startswith(goosesec.MANAGED_KEY_PREFIX)
                  and k not in plan["config"]]:
            cfg.pop(k)
            changes.append(f"goose security: {k} removed (not set by Goose Web)")
        adv = cfg_dir / goosesec.ADVERSARY_FILE
        if not _inside_profile(adv, root) or _is_reparse(adv) or (adv.exists() and not adv.is_file()):
            # a junction, a link or a folder where adversary.md belongs: never written through (C-3)
            if plan["adversary"] is None and not old.get("adversary"):
                return   # adversary mode is not on for this profile and the gateway never wrote a file here
            # Security review 2026-11-12, E-5: this is how a member's agent would stop the reviewer's rules from
            # being written. The control cannot be established, so the agent does not start (provisioning fails
            # closed, like every other provisioning failure) and administrators find the reason in the audit log.
            self.db.audit("goosesec.profile", user=user, target=str(user.get("username") or ""),
                          detail={"problem": "adversary.md is a link or a folder, not a file"}, ok=False)
            raise RuntimeError("adversary.md in this profile's config folder is a link or a folder; an administrator "
                               "must remove it (adversary mode is on for members)")
        if plan["adversary"] is not None:
            want = plan["adversary"]
            if not adv.is_file() or goosesec.file_hash(adv) != goosesec.text_hash(want):
                _atomic_write(adv, want)
                changes.append("goose security: adversary.md")
            new_manifest["adversary"] = goosesec.text_hash(want)
        elif old.get("adversary") and adv.is_file():
            # the gateway wrote one for this profile before: off means gone, whatever was done to the file since
            adv.unlink()
            changes.append("goose security: adversary.md removed")

    def provision(self, user: dict) -> list[str]:
        """Apply teams, hints and policy to an isolated profile. Idempotent. Returns a change list.
        A sandboxed user's provider and extension URLs are written with the worker's relay mapping applied (FIX
        closeout-2026-11-11 F1): the team item has the real URL (127.0.0.1:<port>), the profile the forwarder's
        (127.64.x.y:<port>). Writing the real one would cut the member off until the worker restarts, and every
        save would report the provider as changed."""
        if self.is_native(user):
            return []
        self.ensure_layout(user)
        from . import relay as rl
        relays = self.relay_mapping(user)

        def relayed(obj: Any) -> Any:
            return json.loads(rl.rewrite_text(json.dumps(obj), relays)) if relays else obj
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
        cfg = self._read_profile_yaml(user, cfg_path)
        first_time = not cfg_path.exists()   # also after an unreadable file was set aside: rebuilt like a new profile
        exts: dict = cfg.setdefault("extensions", {}) if isinstance(cfg.get("extensions"), dict) else {}
        cfg["extensions"] = exts
        secrets_path = cfg_dir / "secrets.yaml"
        secrets = self._read_profile_yaml(user, secrets_path)

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
            sp = self.config_dir(su) / "secrets.yaml"
            if not self._profile_file_ok(su, sp):
                # A member's secrets.yaml that is a link could be someone else's: nothing is copied from it (review
                # of 1.21.0, L-1). A file that is simply not there is the ordinary case and says nothing.
                if os.path.lexists(sp):
                    log.warning("profile %s: secrets.yaml of the source profile %s is a link or not a file; no secret "
                                "was copied from it", user.get("username"), su.get("username"))
                return
            try:
                src_secrets = _read_yaml(sp)
            except Exception:
                src_secrets = None
            if not isinstance(src_secrets, dict):
                # The source cannot be read right now (in use, not valid YAML). That is no reason to take away the
                # keys this profile already has: the cleanup below removes every key that is not confirmed here
                # (second review of 1.21.0, M-4).
                log.warning("profile %s: secrets.yaml of the source profile %s could not be read; keys copied "
                            "earlier are kept", user.get("username"), su.get("username"))
                for k in keys:
                    if k in (old.get("secrets") or []) and k in secrets:
                        new_manifest["secrets"].append(k)
                return
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
                e = relayed(copy.deepcopy(entry))
                if is_command_extension(e) and not pol.get("allow_shell"):
                    # not even dormant: a disabled entry can be switched on (B-2). Removed below if it was there.
                    continue
                if exts.get(key) != e:
                    changes.append(f"extension {key}")
                exts[key] = e
                new_manifest["extensions"].append(key)
                secrets_from(payload.get("secretsFrom"), _names(entry.get("env_keys")))
            elif kind == "provider":
                pj = payload.get("json")
                pid = payload.get("providerId") or name
                if isinstance(pj, dict):
                    target = cfg_dir / "custom_providers" / f"{safe_name(pid, 128)}.json"
                    if not _inside_profile(target, root) or _is_reparse(target):
                        continue   # a junction / link planted in the profile: never write through it (C-3)
                    text = rl.rewrite_text(json.dumps(pj, indent=2), relays)
                    if not target.exists() or target.read_text(encoding="utf-8") != text:
                        _atomic_write(target, text)
                        changes.append(f"provider {pid}")
                    new_manifest["providers"].append(pid)
                keys = _names(payload.get("secretKeys"))
                if isinstance(pj, dict):
                    keys += _names([pj.get("api_key_env")])
                secrets_from(payload.get("secretsFrom"), keys)
            elif kind == "skill":
                files = payload.get("files") or {}
                sdir = cfg_dir / "skills" / safe_name(name, 128)
                if not _inside_profile(sdir, root) or _is_reparse(sdir):
                    continue   # never write through a junction / link planted in the profile (C-3)
                mark = sdir / MANAGED_MARK
                if sdir.exists() and not (mark.is_file() and not _linked(mark)):
                    # the user owns a skill with that name; never overwrite it. A mark that is a link is not Goose
                    # Web's mark either: it used to be written through (review of 1.21.0, L-9).
                    continue
                # A part that cannot be written here (a path too long under this profile, a file in use) must not
                # fail the provisioning: that would stop this member's agent from starting until someone removed
                # the item (review of 1.21.0, L-3). It is logged, not reported as a change: a change marks the
                # member's agent for a restart, which cannot help (second review, M-3). And a skill that was
                # delivered before stays on record, or the cleanup below would delete it while it is still
                # assigned (M-2).
                was_ours, existed, began = name in (old.get("skills") or []), sdir.exists(), False
                failed: list[str] = []
                try:
                    sdir.mkdir(parents=True, exist_ok=True)
                    want = f"team item {it['id']}\n"
                    # the mark first: a folder Goose Web begins to fill is its own from the first moment
                    if not mark.is_file() or mark.read_text(encoding="utf-8", errors="replace") != want:
                        _atomic_write(mark, want)
                    began = True
                except OSError as e:
                    failed.append(f"the folder or its mark ({e.__class__.__name__})")
                    if not existed:
                        try:
                            sdir.rmdir()   # empty: nothing was written; tried again at the next start
                        except OSError:
                            pass
                if began:
                    for rel, content in files.items():
                        rp = Path(rel)
                        if rp.is_absolute() or ".." in rp.parts or not isinstance(content, str):
                            continue
                        target = sdir / rp
                        if not _inside_profile(target, root):
                            continue
                        try:
                            if not target.exists() or target.read_text(encoding="utf-8", errors="replace") != content:
                                _atomic_write(target, content)
                                changes.append(f"skill {name}/{rel}")
                        except OSError as e:
                            failed.append(f"{rel} ({e.__class__.__name__})")
                if failed:
                    log.warning("profile %s: team skill %s: %d part(s) could not be written; tried again at the next "
                                "start: %s", user.get("username"), name, len(failed), "; ".join(failed[:5]))
                if began or was_ours:
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
                try:
                    f.unlink()
                    changes.append(f"provider {pid} removed")
                except OSError as e:   # in use: tried again at the next start, never a failed start (N-6)
                    log.warning("profile %s: provider %s could not be removed (%s); tried again at the next start",
                                user.get("username"), pid, e.__class__.__name__)
                    new_manifest["providers"].append(pid)
        for k in set(old.get("secrets") or []) - set(new_manifest["secrets"]):
            if k in secrets:
                secrets.pop(k)
                changes.append(f"secret {k} removed")
        for sk in set(old.get("skills") or []) - set(new_manifest["skills"]):
            sdir = _delete_target(cfg_dir / "skills", sk, "", root)
            if sdir is not None and sdir.is_dir() and (sdir / MANAGED_MARK).is_file() \
                    and not _linked(sdir / MANAGED_MARK):
                shutil.rmtree(sdir, ignore_errors=True)
                if not sdir.exists():
                    changes.append(f"skill {sk} removed")
                    continue
                # A file in it is in use: what is left stays Goose Web's (the mark is put back if it went with the
                # rest) and on record, so the withdrawal is finished at a later start instead of leaving a folder
                # that nothing ever removes (third review, N-5).
                try:
                    if not (sdir / MANAGED_MARK).is_file():
                        _atomic_write(sdir / MANAGED_MARK, "team item withdrawn\n")
                except OSError:
                    pass
                log.warning("profile %s: skill %s could not be removed completely; tried again at the next start",
                            user.get("username"), sk)
                new_manifest["skills"].append(sk)

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
        # Spec 026. A failure here fails the provisioning, like any other step (the worker then does not start): a
        # security setting that could be skipped by making this step raise would not be one (review E-5).
        self._apply_security(user, cfg, secrets, cfg_dir, root, old, new_manifest, changes, relays)

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
        try:
            bridged = self.sync_skill_bridges(user)
            if bridged:
                log.info("profile %s: skill bridges %s", user.get("username"), "; ".join(bridged)[:300])
        except Exception:
            # a convenience file must never block a worker start (provisioning failure fails closed in pre_start)
            log.exception("profile %s: skill bridge sync failed", user.get("username"))
        return changes

    def sync_skill_bridges(self, user: dict) -> list[str]:
        """FIX team-skills-not-loadable-via-load: make every skill of an isolated profile loadable with Summon's
        load(source=<skill>) too. Goose 1.57 Summon resolves only recipes and agents (it reads agents from
        Paths::config_dir()/agents = <profile>/config/agents), and in Code Mode load_skill is reachable only inside
        execute_javascript, so a chat's first load("<skill>") failed. For each config/skills/<dir>/SKILL.md this
        writes config/agents/<name>.md with the same text and SKILL_BRIDGE_MARK; bridges whose skill is gone are
        removed. Files without the mark belong to the user and are never written or deleted. Never reads or writes
        through a junction / link (C-3). Not part of the provisioning change list: Summon re-reads sources on every
        call, so a new bridge needs no worker restart. Returns what changed."""
        if self.is_native(user):
            return []
        root = self.root_for(user)
        cfg_dir = self.config_dir(user)
        skills, agents = cfg_dir / "skills", cfg_dir / "agents"
        if not _inside_profile(agents, root) or _is_reparse(agents):
            return []
        want: dict[str, str] = {}
        if skills.is_dir() and _inside_profile(skills, root) and not _is_reparse(skills):
            for d in sorted(skills.iterdir())[:500]:
                sk = d / "SKILL.md"
                if _is_reparse(d) or not d.is_dir() or _is_reparse(sk) or not sk.is_file():
                    continue
                if not _inside_profile(sk, root):
                    continue
                st = os.lstat(sk)
                if st.st_size > MAX_SKILL_BYTES or getattr(st, "st_nlink", 1) > 1:
                    continue   # a hard link could point at a file outside the profile
                parsed = _split_skill(sk.read_text(encoding="utf-8", errors="replace"))
                if parsed is None:
                    continue
                meta, body = parsed
                sid = _safe_id(str(meta.get("name") or d.name).strip())
                if sid is None or f"{sid}.md".lower() in (k.lower() for k in want):
                    continue
                desc = str(meta.get("description") or f"Skill {sid}")
                head = yaml.safe_dump({"name": sid, "description": desc}, sort_keys=False, allow_unicode=True,
                                      width=10_000)
                want[f"{sid}.md"] = (f"---\n{head}---\n{SKILL_BRIDGE_MARK} from config/skills/{d.name}/SKILL.md; "
                                     f"same text as load_skill(\"{sid}\"). Edit the skill, not this file. -->\n\n{body}")
        changes: list[str] = []
        if agents.is_dir():
            wanted = {k.lower() for k in want}
            for f in sorted(agents.glob("*.md"))[:2000]:
                if f.name.lower() in wanted or _is_reparse(f) or not f.is_file():
                    continue
                if SKILL_BRIDGE_MARK in f.read_text(encoding="utf-8", errors="replace")[:4096]:
                    f.unlink()
                    changes.append(f"bridge {f.stem} removed")
        for fname, text in want.items():
            t = agents / fname
            if _is_reparse(t) or (t.exists() and not t.is_file()):
                continue
            if t.exists():
                cur = t.read_text(encoding="utf-8", errors="replace")
                if SKILL_BRIDGE_MARK not in cur[:4096] or cur == text:
                    continue   # the user's own agent file, or already current
            _atomic_write(t, text)
            changes.append(f"bridge {fname[:-3]}")
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

    @staticmethod
    def _library_dir_ok(d: Path, root: Path | None) -> bool:
        """A folder the library may read items from: a real folder that is not a link, with no link between `root`
        and it (`root` included). `root` None = a folder that is the administrator's own arrangement (the native
        profile's config folders, GOOSE_RECIPE_PATH): only the folder itself is examined."""
        if _is_reparse(d) or not d.is_dir():
            return False
        return root is None or _inside_profile(d, root)

    def _profile_file_ok(self, user: dict, p: Path) -> bool:
        """config.yaml, secrets.yaml or a provider file of `user` may be read for a team item. In a member's profile
        only a regular file that is not a link, with no link between the profile root and it: the member's agent can
        write there, and the gateway must not read someone else's file on its behalf (review of 1.21.0, L-1). The
        native profile is the administrator's own; Goose itself reads it through whatever links it has."""
        if self.is_native(user):
            return p.is_file()
        return p.is_file() and not _linked(p) and _inside_profile(p, self.root_for(user))

    def _recipe_dirs(self, user: dict) -> list[Path]:
        """Where this profile's recipes are. A member's profile: its own config/recipes. The native profile: also
        the administrator's GOOSE_RECIPE_PATH and Goose's home-folder recipe folders (HOME_RECIPE_DIRS)."""
        native = self.is_native(user)
        cands: list[tuple[Path, Path | None]] = [(self.config_dir(user) / "recipes", None if native else self.root_for(user))]
        if native:
            for d in (os.environ.get("GOOSE_RECIPE_PATH") or "").split(os.pathsep):
                if d.strip():
                    cands.append((Path(d.strip()), None))
            h = account_home()
            cands += [(h.joinpath(*rel), h) for rel in HOME_RECIPE_DIRS]
        seen: set[str] = set()
        out = []
        for d, root in cands:
            key = os.path.normcase(os.path.normpath(str(d)))
            if key not in seen and self._library_dir_ok(d, root):
                seen.add(key)
                out.append(d)
        return out

    def _skill_dirs(self, user: dict) -> list[tuple[Path, bool]]:
        """(folder, offered) for the folders this profile's Goose loads global skills from, in Goose's order of
        precedence. A member's profile: its own config/skills. The native profile: Goose's home-folder skill folders
        of the gateway's account as well (spec 028) - ~/.agents/skills first, then config/skills, then the others.
        `offered` False = Goose loads from it but the library does not read it (it is a link or lies behind one):
        its skills still take their names, so that a later folder's skill of the same name is not offered in their
        place (second review, M-5)."""
        if not self.is_native(user):
            cands: list[tuple[Path, Path | None]] = [(self.config_dir(user) / "skills", self.root_for(user))]
        else:
            h = account_home()
            first, *rest = HOME_SKILL_DIRS
            # the native config folder is the administrator's own arrangement: only the folder itself is examined
            # (M-6: with the profile root as the starting point a linked root emptied the picker without a word)
            cands = [(h.joinpath(*first), h), (self.config_dir(user) / "skills", None), *[(h.joinpath(*r), h) for r in rest]]
        out = []
        for d, root in cands:
            ok = self._library_dir_ok(d, root)
            if ok or (self.is_native(user) and d.is_dir()):
                out.append((d, ok))
        return out

    @staticmethod
    def _read_skill_files(d: Path) -> dict[str, str]:
        """The text files of one skill folder, for a team item. Nothing is read through a link (spec 028, D5): a
        linked folder is not entered, a linked or hard-linked file is skipped, and a file whose real location is
        outside the folder is skipped. Binary files are not shared. Raises ValueError when the skill cannot be
        shared: too large, too many files or folders, nested too deeply, a path too long, or no regular SKILL.md.
        Every limit applies before the work it limits: whoever fills the folder decides how big it is, so a folder
        is never listed further than the entries that are still allowed (second review, M-10)."""
        if _is_reparse(d) or not d.is_dir():
            raise ValueError("the skill folder is a link or not a folder; it is not shared")
        real = _real_norm(d).rstrip("\\/") + os.sep
        files: dict[str, str] = {}
        total = count = entries = 0
        skill_md = ""                       # the on-disk name of the top-level file that became SKILL.md
        todo: list[tuple[Path, int]] = [(d, 0)]
        while todo:
            cur, depth = todo.pop(0)
            names = [p.name for p in _scan(cur, MAX_SKILL_ENTRIES - entries + 1)]
            exact = depth == 0 and "SKILL.md" in names
            entries += len(names)
            if entries > MAX_SKILL_ENTRIES:
                raise ValueError(f"skill has too many files and folders to share ({MAX_SKILL_ENTRIES} at most)")
            for n in names:   # sorted by _scan: upper case first, so an exact SKILL.md comes before another case
                f = cur / n
                if _is_reparse(f):
                    continue                # never through a link, file or folder
                if f.is_dir():
                    if depth >= MAX_SKILL_DEPTH:
                        raise ValueError(f"skill folders are nested too deeply to share ({MAX_SKILL_DEPTH} levels at most)")
                    todo.append((f, depth + 1))
                    continue
                if n.lower() == MANAGED_MARK or _linked(f) or not f.is_file() or not _real_norm(f).startswith(real):
                    continue
                rel = f.relative_to(d).as_posix()
                if depth == 0 and n.lower() == "skill.md":
                    # Windows finds it under any case; members get the canonical name. In a case-sensitive folder
                    # the exact SKILL.md is the one whatever sorts before it, and two other variants are ambiguous
                    # (reviews M-7, N-4).
                    if exact and n != "SKILL.md":
                        continue
                    if skill_md:
                        raise ValueError(f"the skill has both {skill_md} and {n}; it is not shared")
                    skill_md, rel = n, "SKILL.md"
                if len(rel) > MAX_SKILL_REL_PATH:
                    raise ValueError(f"a file path inside the skill is too long to share ({MAX_SKILL_REL_PATH} "
                                     f"characters at most): {rel[:60]}...")
                count += 1
                if count > MAX_SKILL_FILES:
                    raise ValueError(f"skill has too many files to share ({MAX_SKILL_FILES} at most)")
                total += f.stat().st_size
                if total > MAX_SKILL_BYTES:
                    raise ValueError("skill too large to share (2 MB limit)")
                try:
                    files[rel] = f.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue  # binary supporting files are not shared
        if "SKILL.md" not in files:
            raise ValueError("SKILL.md is missing, is not text, or is a link; the skill is not shared")
        return files

    def library(self, user: dict, kind: str) -> list[dict]:
        """What the "Add from library" picker offers from `user`'s profile. Everything a member's profile holds is
        the member's to write, so every value is bounded and is sendable text before it leaves here (reviews of
        1.21.0: L-2, L-4, M-8, M-10): at most LIBRARY_SCAN entries of a folder are looked at, large files are
        skipped, one listing parses at most LIBRARY_BYTES, a name or description is text of bounded length."""
        out: list[dict] = []
        cfg_dir = self.config_dir(user)
        member = not self.is_native(user)
        if kind == "recipe":
            budget = LIBRARY_BYTES
            for d in self._recipe_dirs(user):
                for f in _scan(d):
                    if f.suffix.lower() not in (".yaml", ".yml", ".json") or not _sendable(f.name) \
                            or _linked(f) or not f.is_file():
                        continue   # never read through a link (spec 028, D5)
                    try:
                        size = f.stat().st_size
                        if size > MAX_RECIPE_BYTES or size > budget:
                            continue
                        budget -= size
                        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                    except Exception:
                        continue
                    if not isinstance(data, dict) or "title" not in data and "recipe" not in data:
                        continue
                    r = data.get("recipe", data) if isinstance(data.get("recipe"), dict) else data
                    out.append({"kind": "recipe", "ref": str(f), "name": f.stem,
                                "description": _text(r.get("description")) or _text(r.get("title")), "source": str(d)})
        elif kind == "skill":
            seen: set[str] = set()
            for sk, offered in self._skill_dirs(user):
                for d in _scan(sk):
                    md = d / "SKILL.md"
                    key = d.name.casefold()   # one folder on Windows whatever the case
                    if key in seen or not os.path.lexists(md):
                        continue
                    # The first folder that has a skill of this name is the one Goose loads: the name is taken from
                    # here on, also when this one is a link, or in a linked folder, and therefore not offered
                    # (reviews L-8, M-5).
                    seen.add(key)
                    if not offered or not _sendable(d.name) or _is_reparse(d) or not d.is_dir() \
                            or _linked(md) or not md.is_file():
                        continue
                    try:
                        head = _read_head(md)
                    except OSError:
                        continue
                    m = re.search(r"^description:\s*(.+)$", head, re.M)
                    out.append({"kind": "skill", "ref": d.name, "name": d.name,
                                "description": _text(m.group(1).strip().strip("'\"")) if m else "", "source": str(sk)})
        elif kind == "extension":
            cp = cfg_dir / "config.yaml"
            try:
                readable = self._profile_file_ok(user, cp) and not (member and cp.stat().st_size > MAX_RECIPE_BYTES)
                cfg = _read_yaml(cp) if readable else {}
            except Exception:
                cfg = {}
            exts = cfg.get("extensions") if isinstance(cfg, dict) else None
            keys = sorted(k for k in itertools.islice(exts if isinstance(exts, dict) else {}, LIBRARY_SCAN)
                          if isinstance(k, str) and _sendable(k))
            for key in keys:
                e = exts[key]
                if isinstance(e, dict):
                    out.append({"kind": "extension", "ref": key, "name": _text(e.get("display_name"), 200) or key,
                                "description": _text(e.get("description")) or _text(e.get("type")),
                                "source": "config.yaml", "enabled": bool(e.get("enabled"))})
        elif kind == "provider":
            cp = cfg_dir / "custom_providers"
            if self._library_dir_ok(cp, self.root_for(user)) if member else cp.is_dir():
                budget = LIBRARY_BYTES
                for f in _scan(cp):
                    if f.suffix.lower() != ".json" or not _sendable(f.name) or not self._profile_file_ok(user, f):
                        continue
                    try:
                        size = f.stat().st_size
                        if size > MAX_RECIPE_BYTES or size > budget:
                            continue
                        budget -= size
                        j = json.loads(f.read_text(encoding="utf-8"))
                    except (ValueError, OSError, RecursionError):
                        continue
                    if not isinstance(j, dict):
                        continue
                    out.append({"kind": "provider", "ref": f.stem, "name": _text(j.get("display_name"), 200) or f.stem,
                                "description": _text(j.get("base_url")) or _text(j.get("engine")), "source": str(cp)})
        return out

    def export_item(self, user: dict, kind: str, ref: str) -> tuple[str, dict]:
        """Build a team-item payload from a profile library item. Secrets are referenced, never copied. Only what
        the listing offers can be exported, and nothing is read through a link in a member's profile. The payload
        is plain data of bounded size: it is written out as JSON on the gateway's event loop and copied to every
        member of the team (second review, M-1)."""
        listed = {i["ref"]: i for i in self.library(user, kind)}
        if ref not in listed:
            raise ValueError(f"{kind} not found in {user['username']}'s profile: {ref}")
        cfg_dir = self.config_dir(user)
        if kind == "recipe":
            p = Path(ref)
            if _linked(p) or not p.is_file():   # listed a moment ago as a regular file; never read through a link
                raise ValueError("the recipe file is a link or not a file; it is not shared")
            if p.stat().st_size > MAX_RECIPE_BYTES:
                raise ValueError("recipe too large to share (1 MB limit)")
            return re.sub(r"[^A-Za-z0-9._-]", "-", p.stem)[:100], {"yaml": p.read_text(encoding="utf-8"),
                                                                   "origin": str(p)}
        if kind == "skill":
            # the folder the listing found it in: config/skills, or for the native profile one of Goose's
            # home-folder skill folders (spec 028)
            return ref, {"files": self._read_skill_files(Path(listed[ref]["source"]) / ref)}
        if kind == "extension":
            cp = cfg_dir / "config.yaml"
            if not self._profile_file_ok(user, cp):
                raise ValueError("config.yaml of that profile is a link or not a file; nothing is shared from it")
            entry = (_read_yaml(cp).get("extensions") or {})[ref]
            if not isinstance(entry, dict) or not _small_tree(entry):
                raise ValueError("the extension entry is too large, too deeply nested or not plain data; it is not "
                                 "shared")
            if entry.get("env_keys") is not None and _names(entry["env_keys"]) != entry["env_keys"]:
                raise ValueError("the extension's env_keys is not a list of names; it is not shared")
            entry = json.loads(json.dumps(entry))   # a plain copy: no shared parts, nothing but JSON types
            entry["enabled"] = True
            return ref, {"key": ref, "entry": entry, "secretsFrom": user["username"]}
        if kind == "provider":
            f = cfg_dir / "custom_providers" / f"{ref}.json"
            if not self._profile_file_ok(user, f):
                raise ValueError("the provider file is a link or not a file; it is not shared")
            if f.stat().st_size > MAX_RECIPE_BYTES:
                raise ValueError("provider file too large to share (1 MB limit)")
            j = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(j, dict) or not _small_tree(j):
                raise ValueError("the provider file is too deeply nested or not plain data; it is not shared")
            key = j.get("api_key_env")
            if key is not None and not isinstance(key, str):
                raise ValueError("the provider's api_key_env is not a name; it is not shared")
            return ref, {"providerId": ref, "json": j, "secretsFrom": user["username"], "secretKeys": _names([key])}
        raise ValueError("unknown kind")
