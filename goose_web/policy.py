"""Effective policy (the user's one team + user overrides) and the ACP method firewall.

Least privilege (spec 009): a missing or false switch is off, an empty allowed_modes / allowed_providers /
allowed_models list allows NOTHING, and the explicit value "*" (ANY) allows everything. A user without a team
can sign in but cannot chat. Admins are unrestricted. For everyone else, every ACP method a browser sends goes
through `check()`. Unknown methods are denied by default, so a new Goose release cannot open a hole by itself.
"""
from __future__ import annotations

import os
import sys
from typing import Any

BOOL_KEYS = ["recipes_edit", "skills_edit", "extensions_edit", "providers_edit", "schedules", "apps",
             "prompts_edit", "hints_edit", "tools_permissions", "config_edit", "allow_shell", "notify_webhook"]
LIST_KEYS = ["allowed_modes", "allowed_providers", "allowed_models", "allowed_roots"]
# Lists that gate chatting. "*" = any value; empty = none. allowed_roots has no "*" (folders are explicit).
CHAT_LISTS = ["allowed_modes", "allowed_providers", "allowed_models"]
ANY = "*"
# Extra keys a team policy may carry besides BOOL_KEYS / LIST_KEYS / max_concurrent_runs.
# guard: the team's prompt guard (spec 018, guard.clean_team_guard); missing = off.
TEAM_EXTRA_KEYS = ["default_provider", "default_model", "share_folder", "guard", "require_totp"]
# Approval modes in which Goose does not ask before every tool call: Auto never asks, Smart approve skips tools
# annotated (or judged) read-only. A guarded team cannot use them (spec 018): the guard sees tool calls only through
# Goose's permission requests.
UNGUARDED_MODES = ("auto", "smart_approve")
GUARDED_MODES = ["approve", "chat"]

# The base every team starts from (spec 009): everything off, nothing allowed.
DEFAULT_POLICY: dict[str, Any] = {**{k: False for k in BOOL_KEYS}, **{k: [] for k in LIST_KEYS},
                                  "max_concurrent_runs": 3}

# The defaults of Goose Web 1.4 and earlier (empty list = unrestricted). Used only to migrate old teams.
LEGACY_DEFAULT_POLICY: dict[str, Any] = {
    "recipes_edit": True, "skills_edit": True, "extensions_edit": False, "providers_edit": False,
    "schedules": True, "apps": True, "prompts_edit": False, "hints_edit": True, "tools_permissions": True,
    "config_edit": False, "allow_shell": False, "notify_webhook": False,
    "allowed_modes": [], "allowed_providers": [], "allowed_models": [], "allowed_roots": [],
    "max_concurrent_runs": 3,
}

ADMIN_POLICY: dict[str, Any] = {**{k: True for k in BOOL_KEYS}, **{k: [ANY] for k in CHAT_LISTS},
                                "allowed_roots": [], "max_concurrent_runs": 0, "chat_blocked": ""}

NO_TEAM_REASON = "You are not in a team yet, so you cannot chat. Ask your administrator to add you to a team."
_LIST_LABELS = {"allowed_providers": "providers", "allowed_models": "models", "allowed_modes": "approval modes"}

# Extensions that give the model a shell or arbitrary code execution, or that start other extensions / run recipes
# (a recipe's extensions and retry checks are commands). Measured on Goose 1.57 (security assessment 2026-11-09):
# summon's `delegate` runs any recipe it can find (a planted <cwd>/.goose/recipes/x.yaml with a stdio extension ran
# its command), and `scheduler` creates scheduled recipe runs. Goose ENABLES bundled platform extensions that are
# missing from config.yaml (developer, scheduler, ...), so profiles pin these as `enabled: false` (profiles.py).
SHELL_EXTENSIONS = {"developer", "computercontroller", "code_execution", "orchestrator", "summon", "scheduler"}
# extensionmanager turns any configured or bundled extension on from a tool call (developer included -> shell).
EXTENSION_MANAGER = "extensionmanager"
GUARDED_EXTENSIONS = SHELL_EXTENSIONS | {EXTENSION_MANAGER}
# Extension types whose config is a command line or code (recipes, ACP extension configs, session exports).
COMMAND_EXTENSION_TYPES = {"stdio", "inline_python"}
# Keys a non-admin may send in session/new `_meta` (static/js/views/home.js); everything else is dropped.
MEMBER_NEW_META_KEYS = {"recipeId", "recipeDeeplink", "enabledExtensions"}


def ext_key(name: Any) -> str:
    """Normalised extension name: 'Extension Manager', 'extension_manager' and 'extensionmanager' are the same."""
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


_GUARDED_KEYS = {ext_key(n): n for n in GUARDED_EXTENSIONS}


def extension_needs(name: Any) -> list[str]:
    """The permissions a non-admin needs to turn the named extension on (beyond extensions_edit for adding it)."""
    k = ext_key(name)
    if k == ext_key(EXTENSION_MANAGER):
        return ["extensions_edit", "allow_shell"]
    if k in _GUARDED_KEYS:
        return ["allow_shell"]
    return []


def missing(policy: dict, perms: list[str]) -> list[str]:
    return [p for p in perms if not policy.get(p)]


def is_command_extension(ext: Any) -> bool:
    """True for an extension config that is a command line or code (stdio, inline_python, MCP server command)."""
    if not isinstance(ext, dict):
        return False
    t = str(ext.get("type") or "").lower()
    if t in COMMAND_EXTENSION_TYPES:
        return True
    server = ext.get("server") if isinstance(ext.get("server"), dict) else {}
    return bool(ext.get("cmd") or ext.get("command") or ext.get("code") or server.get("command"))

P = "_goose/unstable/"

ALWAYS = {
    "session/new", "session/load", "session/prompt", "session/cancel", "session/list", "session/fork",
    "session/close", "session/delete", "session/resume", "session/set_mode", "session/set_config_option",
    P + "session/info", P + "session/rename", P + "session/archive", P + "session/unarchive",
    P + "session/export", P + "session/import", P + "session/conversation/truncate", P + "session/project/update",
    P + "session/working-dir/update", P + "session/steer", P + "session/extensions/list", P + "tools/list",
    P + "resources/read", P + "apps/list", P + "apps/export", P + "recipes/list", P + "recipes/encode",
    P + "recipes/decode", P + "recipes/scan", P + "recipes/parse", P + "recipes/to-yaml", P + "schedules/list",
    P + "schedules/sessions/list", P + "schedules/running-job/inspect", P + "sources/list", P + "sources/export",
    P + "agent-mentions/list", P + "slash-commands/list", P + "config/extensions/list", P + "providers/list",
    P + "providers/supported-models/list", P + "providers/config/status", P + "providers/readiness/check",
    P + "providers/canonical-model-info", P + "defaults/read", P + "preferences/read", P + "preferences/save",
    P + "config/prompts/list", P + "config/prompts/get", P + "dictation/config", P + "dictation/transcribe",
    P + "dictation/models/list", P + "dictation/models/download/progress", P + "local-inference/models/list",
    P + "local-inference/models/download/progress", P + "diagnostics/get", P + "session/live-voice/availability",
    P + "session/live-voice/start", P + "session/live-voice/stop",
}

BY_PERMISSION = {
    "recipes_edit": {P + "recipes/save", P + "recipes/delete", P + "recipes/slash-command"},
    "schedules": {P + "schedules/create", P + "schedules/delete", P + "schedules/pause", P + "schedules/unpause",
                  P + "schedules/update", P + "schedules/run-now", P + "schedules/running-job/kill",
                  P + "recipes/schedule"},
    "extensions_edit": {P + "session/extensions/add", P + "session/extensions/remove", P + "config/extensions/add",
                        P + "config/extensions/remove", P + "config/extensions/set-enabled"},
    "providers_edit": {P + "providers/custom/create", P + "providers/custom/read", P + "providers/custom/update",
                       P + "providers/custom/delete", P + "providers/inventory/refresh", P + "providers/config/read",
                       P + "providers/config/save", P + "providers/config/delete",
                       P + "providers/config/authenticate", P + "providers/secrets/list",
                       P + "providers/secrets/delete", P + "providers/catalog/list",
                       P + "providers/setup/catalog/list", P + "providers/catalog/template", P + "defaults/save",
                       P + "defaults/clear", P + "onboarding/import/scan", P + "onboarding/import/apply",
                       P + "dictation/models/download", P + "dictation/models/cancel", P + "dictation/models/delete",
                       P + "local-inference/models/download", P + "local-inference/models/download/cancel",
                       P + "local-inference/models/delete", P + "local-inference/models/evict",
                       P + "local-inference/models/settings/read", P + "local-inference/models/settings/update",
                       P + "local-inference/huggingface/search", P + "local-inference/huggingface/repo/variants",
                       P + "local-inference/chat-templates/builtin/list"},
    "apps": {P + "apps/import", P + "apps/delete", P + "tools/call"},
    "prompts_edit": {P + "config/prompts/save", P + "config/prompts/reset", P + "session/system-prompt/set"},
    "tools_permissions": {P + "tools/permissions/set"},
    "config_edit": {P + "config/read", P + "config/upsert", P + "config/remove", P + "config/read-all"},
}
SOURCE_METHODS = {P + "sources/create", P + "sources/update", P + "sources/delete", P + "sources/import"}
SOURCE_PERMISSION = {"skill": "skills_edit", "builtinSkill": "skills_edit", "agent": "skills_edit",
                     "project": "skills_edit", "recipe": "recipes_edit", "subrecipe": "recipes_edit"}
# config keys a non-config_edit user may read
READABLE_CONFIG_KEYS = {"GOOSE_PROVIDER", "GOOSE_MODEL", "GOOSE_MODE", "GOOSE_THINKING_EFFORT", "GOOSE_MAX_TURNS"}
# config keys Goose Web sets itself (spec 009: the hints file name); never writable by a non-admin
MANAGED_CONFIG_KEYS = {"CONTEXT_FILE_NAMES"}
# spec 026: Goose's own security settings (prompt injection detection: SECURITY_PROMPT_*, the undocumented
# SECURITY_COMMAND_CLASSIFIER_* and the *_OVERRIDE switches) are set by Goose Web for every profile; a member
# cannot change or remove them through Goose's configuration API
MANAGED_CONFIG_PREFIXES = ("SECURITY_",)
# config/upsert values checked against the team's lists
CONFIG_LIST_KEYS = {"GOOSE_PROVIDER": "allowed_providers", "GOOSE_MODEL": "allowed_models",
                    "GOOSE_MODE": "allowed_modes"}


class Denied(Exception):
    pass


def allows(policy: dict, key: str, value: Any) -> bool:
    """True if the list `key` contains "*" (any) or `value`. Empty or missing = nothing allowed."""
    lst = policy.get(key) or []
    return ANY in lst or value in lst


def chat_block(policy: dict) -> str:
    """Why this (non-admin) policy cannot chat, or "" if it can."""
    if policy.get("no_team"):
        return NO_TEAM_REASON
    for k in ("allowed_providers", "allowed_models", "allowed_modes"):
        if not policy.get(k):
            return f"Your team allows no {_LIST_LABELS[k]}, so you cannot chat. Ask your administrator."
    return ""


def effective_policy(user: dict, teams: list[dict]) -> dict:
    """The policy of a user. Admins: ADMIN_POLICY. Everyone else: their ONE team over the least-privilege base
    (spec 009; a second team, which the database no longer allows, is ignored), then the user's overrides."""
    if user.get("role") == "admin":
        return dict(ADMIN_POLICY)
    pol: dict[str, Any] = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_POLICY.items()}
    team = teams[0] if teams else None
    if team is None:
        pol["no_team"] = True
        pol["team"] = None
    else:
        tp = team.get("policy") or {}
        for k in BOOL_KEYS:
            if k in tp:
                pol[k] = bool(tp[k])
        for k in LIST_KEYS:
            if isinstance(tp.get(k), list):
                pol[k] = [str(x) for x in tp[k] if str(x).strip()]
        if tp.get("max_concurrent_runs") is not None:
            pol["max_concurrent_runs"] = int(tp.get("max_concurrent_runs") or 0)
        for k in ("default_provider", "default_model"):
            if tp.get(k):
                pol[k] = str(tp[k])
        pol["team"] = {"id": team.get("id"), "name": team.get("name")}
        from .guard import clean_team_guard
        pol["guard"] = clean_team_guard(tp.get("guard"))
    for k, v in (user.get("policy_overrides") or {}).items():
        if k in DEFAULT_POLICY:
            pol[k] = v
    if (pol.get("guard") or {}).get("enabled"):
        pol["allowed_modes"] = guarded_modes(pol.get("allowed_modes") or [])
    pol["chat_blocked"] = chat_block(pol)
    return pol


def guarded_modes(modes: list[str]) -> list[str]:
    """allowed_modes of a guarded team (spec 018): without Auto and Smart approve. "*" becomes Approve + Chat only;
    a list that only had tool-running modes the guard cannot see gets Approve instead."""
    if ANY in modes:
        return list(GUARDED_MODES)
    out = [m for m in modes if m not in UNGUARDED_MODES]
    if len(out) < len(modes) and "approve" not in out:
        out.insert(0, "approve")
    return out


def guard_on(policy: dict) -> bool:
    return bool((policy.get("guard") or {}).get("enabled"))


def check_session_choice(policy: dict, load_result: dict | None) -> None:
    """Refuse a prompt when the chat's CURRENT provider, model or mode is not allowed (for example an old chat
    after the team narrowed its lists). Values come from session/new, session/load and set_config_option."""
    if not isinstance(load_result, dict):
        return
    names = {"allowed_providers": "provider", "allowed_models": "model", "allowed_modes": "approval mode"}
    for o in load_result.get("configOptions") or []:
        if not isinstance(o, dict):
            continue
        cur = o.get("currentValue")
        key = {"provider": "allowed_providers", "model": "allowed_models", "mode": "allowed_modes"}.get(o.get("id"))
        if key and cur and not allows(policy, key, cur):
            raise Denied(f"this chat uses the {names[key]} '{cur}', which your team does not allow. "
                         f"Pick an allowed {names[key]} for this chat first.")
    modes = load_result.get("modes")
    if isinstance(modes, dict) and modes.get("currentModeId") and \
            not allows(policy, "allowed_modes", modes["currentModeId"]):
        raise Denied(f"this chat uses the approval mode '{modes['currentModeId']}', which your team does not "
                     "allow. Pick an allowed mode for this chat first.")


def team_warnings(policy: dict, *, hints: int, members: int, provider_items: set | None = None) -> list[dict]:
    """What the admin should know about a team's experience (Experience page). level: err | warn | info.
    `provider_items`: the ids of the providers this team has as library items (None = not looked at)."""
    p = {**DEFAULT_POLICY, **(policy or {})}
    out: list[dict] = []
    # Allowing a provider, or making it the team's default, does not put it into the members' profiles. A custom
    # provider is defined in ONE profile - its address, its models, its key. Found in use, 2026-11-13: a team with
    # a default provider whose members could not reach a model, and nothing said why.
    if provider_items is not None:
        default = p.get("default_provider")
        named = [x for x in (p.get("allowed_providers") or []) if x != ANY]
        for prov in dict.fromkeys(([default] if default else []) + named):
            if str(prov).startswith("custom_") and prov not in provider_items:
                out.append({"level": "err" if prov == default else "warn", "text": (
                    f"Members do not have the provider '{prov}'" + (" (the team's default)" if prov == default else "")
                    + ": it is defined in one profile only. Add it to this team under Library items (Provider) - "
                    "that copies its definition and its key to every member. Until then members cannot reach a "
                    "model with it.")})
    for k in ("allowed_providers", "allowed_models", "allowed_modes"):
        if not p.get(k):
            out.append({"level": "err", "text": f"No {_LIST_LABELS[k]} allowed: members can't chat."})
    dp, dm = p.get("default_provider"), p.get("default_model")
    if dp and p.get("allowed_providers") and not allows(p, "allowed_providers", dp):
        out.append({"level": "warn", "text": f"The default provider '{dp}' is not in the allowed providers."})
    if dm and p.get("allowed_models") and not allows(p, "allowed_models", dm):
        out.append({"level": "warn", "text": f"The default model '{dm}' is not in the allowed models."})
    if dp and not dm:
        # found in use, 2026-11-13: Goose answers a new chat with "Configuration value not found: GOOSE_MODEL"
        out.append({"level": "err", "text": "A default provider without a default model: a new member's profile has "
                                            "no model, and Goose cannot start a chat without one. Choose a default "
                                            "model."})
    if not dp and p.get("allowed_providers"):
        out.append({"level": "info", "text": "No default model: members keep their profile's model if it is "
                                             "allowed, otherwise the first allowed provider."})
    if p.get("allow_shell"):
        out.append({"level": "warn", "text": "Shell is on: members' agents can run commands as the gateway's "
                                             "Windows account and read other profiles (known risk)."})
    if p.get("config_edit"):
        out.append({"level": "warn", "text": "Raw config editing is on: members can change their Goose settings."})
    if p.get("providers_edit"):
        out.append({"level": "warn", "text": "Members can add providers and API keys of their own."})
    if not hints:
        out.append({"level": "info", "text": "No team hints assigned: members get no team instructions."})
    if p.get("hints_edit"):
        out.append({"level": "info", "text": "Members may add personal hints (team hints take precedence)."})
    if p.get("require_totp"):
        out.append({"level": "info", "text": "Two-factor sign-in is required: a member who has not set it up can do "
                                             "nothing but set it up."})
    if not members:
        out.append({"level": "info", "text": "No members yet."})
    from .guard import clean_team_guard
    g = clean_team_guard(p.get("guard"))
    if g["enabled"]:
        modes = p.get("allowed_modes") or []
        if ANY in modes or any(m in modes for m in UNGUARDED_MODES):
            out.append({"level": "info", "text": "Prompt guard on: Auto and Smart approve are not available to "
                                                 "members (the guard sees tool calls only when Goose asks first)"
                                                 + ("; guarded auto approves calls that pass." if g["auto_approve"]
                                                    else ".")})
        if g["threshold"] is not None:
            out.append({"level": "info", "text": f"Prompt guard: this team's classifier threshold is {g['threshold']} "
                                                 "(instead of the global guard.threshold)."})
        if not g["rulesets"] and not g["check_input"]:
            out.append({"level": "warn", "text": "Prompt guard on, but with no rule sets and no input check it only "
                                                 "classifies tool-call arguments."})
        if p.get("allow_shell"):
            out.append({"level": "warn", "text": "Prompt guard with shell on: sub-agents and recipe checks started "
                                                 "through the shell extensions run tools the guard does not see."})
        if p.get("schedules"):
            out.append({"level": "warn", "text": "Prompt guard: scheduled runs have nobody to ask, so their tool "
                                                 "calls are not guarded. Turn off schedules for this team if that "
                                                 "matters."})
    return out


def _norm(p: str) -> str:
    p = os.path.normpath(os.path.abspath(os.path.expanduser(p)))
    return p.lower() if sys.platform == "win32" else p


def _real(p: str) -> str | None:
    """The path with every symlink / junction that exists resolved (None if it cannot be resolved)."""
    try:
        p = os.path.normpath(os.path.realpath(os.path.expanduser(p)))
    except (OSError, ValueError, RuntimeError):
        return None
    return p.lower() if sys.platform == "win32" else p


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("\\/") + os.sep)


# Goose (1.50-1.57: plugins/discovery.rs, acp/server.rs initial_session_extensions) treats every folder under
# <cwd>/.agents/plugins of a new chat as an enabled plugin and starts its MCP servers (.mcp.json or the plugin
# manifest: any command line) during session/new. No Goose setting turns this off (NEW-36).
AGENTS_DIR = ".agents"


def is_agents_name(name: Any) -> bool:
    """True for a path component Windows opens as the `.agents` folder: any case, trailing dots/spaces, or an NTFS
    stream suffix (creating `.agents::$INDEX_ALLOCATION` creates the folder `.agents`)."""
    return str(name or "").split(":", 1)[0].strip().rstrip(". ").lower() == AGENTS_DIR


def has_agents_component(path: str) -> bool:
    """True if `path` has a `.agents` component, as written or resolved (realpath expands 8.3 short names such as
    AGENTS~1 and links of the parts that exist). Fails closed when the path cannot be resolved."""
    cands = [str(path or "")]
    try:
        cands.append(os.path.realpath(cands[0]))
    except (OSError, ValueError, RuntimeError):
        return True
    for c in cands:
        rest = os.path.splitdrive(c)[1]
        if any(is_agents_name(part) for part in rest.replace("/", "\\").split("\\")):
            return True
    return False


def project_plugins(cwd: Any) -> list[str]:
    """The plugin folders Goose would load from <cwd>/.agents/plugins at session/new (sub-folders, links followed;
    Goose ignores files there). A plugins folder that exists but cannot be listed counts as one (fail closed)."""
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        return []
    base = os.path.expanduser(cwd)
    cands = [base]
    try:   # SD-5: as written, as Win32 normalises it, and with links resolved - whichever Goose ends up opening
        cands += [os.path.abspath(base), os.path.realpath(base)]
    except (OSError, ValueError, RuntimeError):
        return ["(unreadable)"]
    out: set[str] = set()
    for c in dict.fromkeys(cands):
        d = os.path.join(c, AGENTS_DIR, "plugins")
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_dir():
                            out.add(e.name)
                    except OSError:
                        out.add(e.name)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            out.add("(unreadable)")
    return sorted(out)


def canonical_dir(p: Any) -> Any:
    """SD-5: an existing folder in the form Win32 opens it (GetFullPathName: `..`, `.`, separators, and the trailing
    dots/spaces Windows drops), so the gateway's checks and Goose see the same string. Links are NOT resolved here
    (a team folder may sit behind a junction); project_plugins also looks at the resolved path. Anything that is
    not an existing absolute folder is left unchanged (the path checks refuse what they must)."""
    if not isinstance(p, str) or not p or "\x00" in p:
        return p
    try:
        q = os.path.expanduser(p)
        if os.path.isabs(q) and os.path.isdir(q):
            return os.path.abspath(q)
    except (OSError, ValueError, RuntimeError):
        pass
    return p


def canonical_dirs(params: dict) -> None:
    """Rewrite cwd and additionalDirectories of a session call to canonical folders in place."""
    if "cwd" in params:
        params["cwd"] = canonical_dir(params.get("cwd"))
    if isinstance(params.get("additionalDirectories"), list):
        params["additionalDirectories"] = [canonical_dir(d) for d in params["additionalDirectories"]]


def path_allowed(path: str, roots: list[str]) -> bool:
    """True if `path` lies inside one of `roots`.

    Two checks must both pass (GW-19): the lexical one (normpath/abspath, so `..` cannot climb out) and the
    resolved one (os.path.realpath on the candidate and on every root, so a symlink or junction inside an
    allowed root that points elsewhere cannot be used to escape).
    """
    if not path or "\x00" in path:
        return False
    if not os.path.isabs(os.path.expanduser(path)):
        return False
    roots = [r for r in roots if r and "\x00" not in r]
    np, rp = _norm(path), _real(path)
    if rp is None:
        return False
    lexical = any(_within(np, _norm(r)) for r in roots)
    if not lexical:
        return False
    for r in roots:
        rr = _real(r)
        if rr is not None and _within(rp, rr):
            return True
    return False


def _plain_path(p: str) -> str:
    """Drop the \\\\?\\ / \\\\?\\UNC\\ prefixes, normalise, lower-case on Windows."""
    s = str(p or "").strip()
    if s[:8].upper() == "\\\\?\\UNC\\":
        s = "\\\\" + s[8:]
    elif s[:4] in ("\\\\?\\", "//?/"):
        s = s[4:]
    s = os.path.normpath(s)
    return s.lower() if sys.platform == "win32" else s


def _is_drive_or_share_root(p: str) -> bool:
    drive, rest = os.path.splitdrive(p)
    return rest.strip("\\/") == ""


def _same_or_inside(path: str, root: str) -> bool:
    return bool(root) and _within(path, root)


def folder_grant_problem(path: str, *, profiles_root: str, system_dir: str = "",
                         native_roots: list[str] | None = None, users_root: str = "",
                         own_home: str = "") -> str:
    """Why `path` must not be a team's extra folder (allowed_roots) or shared folder (share_folder); "" = fine.

    C-11 (security assessment 2026-11-09): members get these folders as chat roots and, with the sandbox, their
    container gets recursive Modify on them. Refused: relative paths, device paths and alternate data streams,
    drive and share roots, the profiles root, any folder inside it except the team folders (_teams) and any parent
    of it, system_dir (inside or a parent of it), the native Goose roots (inside or a parent: %APPDATA%\\Block\\goose
    and every native profile), %SystemRoot%, Program Files, ProgramData, the users folder (C:\\Users), any user's
    profile folder itself, and anything inside another user's profile or inside AppData. Both the given path and
    the path with junctions / symlinks resolved are checked."""
    raw = str(path or "").strip()
    if not raw or "\x00" in raw:
        return "the folder is empty"
    if raw[:4] in ("\\\\.\\", "//./"):
        return "device paths are not allowed"
    probe = raw[8:] if raw[:8].upper() == "\\\\?\\UNC\\" else raw[4:] if raw[:4] in ("\\\\?\\", "//?/") else raw
    drive, rest = os.path.splitdrive(probe)
    if ":" in rest:
        return "the folder name contains ':' (alternate data stream)"
    if not os.path.isabs(probe):
        return "the folder must be an absolute path"
    env = os.environ
    home_drive = env.get("SystemDrive", "C:")
    users = _plain_path(users_root or os.path.dirname(os.path.expanduser("~")) or home_drive + "\\Users")
    own = _plain_path(own_home or os.path.expanduser("~"))
    natives = [r for r in (native_roots or []) if r]
    if env.get("APPDATA"):
        natives.append(os.path.join(env["APPDATA"], "Block", "goose"))
    system_dirs = [env.get("SystemRoot") or env.get("windir") or home_drive + "\\Windows"]
    program = [env.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData")
               if env.get(k)] or [home_drive + "\\Program Files", home_drive + "\\Program Files (x86)",
                                  home_drive + "\\ProgramData"]
    profiles = _plain_path(profiles_root) if profiles_root else ""
    teams = os.path.join(profiles, "_teams") if profiles else ""
    cands = [_plain_path(probe)]
    real = _real(probe)
    if real:
        cands.append(_plain_path(real))
    for p in dict.fromkeys(cands):
        if _is_drive_or_share_root(p):
            return "a drive or share root cannot be shared"
        if profiles and (_same_or_inside(profiles, p) or
                         _same_or_inside(p, profiles) and not (p != teams and _same_or_inside(p, teams))):
            return "the profiles root, a folder inside it (other than a team folder) or a parent of it " \
                   "cannot be shared"
        if system_dir and (_same_or_inside(p, _plain_path(system_dir)) or _same_or_inside(_plain_path(system_dir), p)):
            return "the Goose Web system folder (or a parent of it) cannot be shared"
        for n in natives:
            n = _plain_path(n)
            if _same_or_inside(p, n) or _same_or_inside(n, p):
                return "a native Goose profile (or a parent of it) cannot be shared"
        for s in system_dirs + program:
            if _same_or_inside(p, _plain_path(s)) or _same_or_inside(_plain_path(s), p):
                return "Windows and program folders cannot be shared"
        if users and (p == users or os.path.dirname(p) == users):
            return "the users folder or a user's profile folder cannot be shared"
        if users and _same_or_inside(p, users):
            if not _same_or_inside(p, own):
                return "folders inside another user's profile cannot be shared"
            if _same_or_inside(p, os.path.join(own, "appdata")):
                return "AppData cannot be shared"
    return ""


def check_team_folders(policy: dict, **where: Any) -> None:
    """Raise ValueError(reason) if the team policy's allowed_roots or share_folder is a dangerous folder
    (folder_grant_problem). For the API's team policy normaliser (api._clean_policy)."""
    for r in policy.get("allowed_roots") or []:
        if r == ANY:
            continue
        why = folder_grant_problem(str(r), **where)
        if why:
            raise ValueError(f"{r}: {why}")
    sf = str(policy.get("share_folder") or "").strip()
    if sf:
        why = folder_grant_problem(sf, **where)
        if why:
            raise ValueError(f"{sf}: {why}")


def user_roots(policy: dict, workspace: str) -> list[str]:
    """Own workspace, the team's shared folder, then the team's extra folders ("*" is never a folder)."""
    extra = [r for r in policy.get("allowed_roots") or [] if r and r != ANY]
    team = [policy["team_folder"]] if policy.get("team_folder") else []
    return [workspace, *team, *extra]


def _ext_name(ext: dict | None) -> str:
    if not isinstance(ext, dict):
        return ""
    if ext.get("type") == "mcp":
        server = ext.get("server") or {}
        return str(server.get("name") or "").lower()
    return str(ext.get("name") or "").lower()


TOOLS_CALL = P + "tools/call"


def check_tool_call_target(params: dict) -> None:
    """A direct tool call (MCP Apps bridge) may only call a tool of the extension it names.

    Prefixed tool names have the form `<extension>__<tool>`. If the prefix differs from `extensionName`, an
    app of one extension could reach the tools of another (for example a shell tool), so the call is refused
    for every user. Unprefixed names are resolved inside `extensionName` by Goose and need no check; without
    `extensionName` there is nothing to mismatch (the allow_shell check in `check` still examines the prefix).
    """
    ext = params.get("extensionName")
    if ext is None or ext == "":
        return
    for key in ("name", "toolName"):
        name = str(params.get(key) or "")
        if "__" in name and name.split("__", 1)[0].lower() != str(ext).lower():
            raise Denied(f"tool '{name[:200]}' does not belong to extension '{str(ext)[:200]}': a tool call may "
                         "only use tools of the extension it names")


def enabled_extension_map(listing: Any, only_enabled: bool = True) -> dict[str, dict]:
    """{ext_key(name): config entry} of the ENABLED (or all) extensions in a `config/extensions/list` result."""
    out: dict[str, dict] = {}
    items = listing.get("extensions") if isinstance(listing, dict) else None
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or only_enabled and not item.get("enabled"):
            continue
        e = item.get("extension") if isinstance(item.get("extension"), dict) else {}
        for n in (item.get("configKey"), e.get("name")):
            if n:
                out[ext_key(n)] = e
    return out


def _same_command(a: dict, b: dict | None) -> bool:
    if not isinstance(b, dict):
        return False
    keys = ("type", "cmd", "args", "code", "uri", "envs", "env_keys")
    return all((a.get(k) or None) == (b.get(k) or None) for k in keys)


def recipe_extension_names(recipe: Any) -> list[str]:
    exts = recipe.get("extensions") if isinstance(recipe, dict) else None
    return [str(e.get("name") or (e.get("server") or {}).get("name") or "?")[:100]
            for e in exts or [] if isinstance(e, dict)][:50]


def recipe_problems(recipe: Any, policy: dict, enabled: dict[str, dict] | None) -> list[str]:
    """Why a non-admin may not run `recipe` (empty = allowed). B-1 (security assessment 2026-11-09): Goose starts
    every entry of recipe.extensions when a session starts from a recipe (session/new `_meta.recipeId` /
    `recipeDeeplink`, schedules), a stdio entry being any command line, so a recipe may only bring:
    - extensions already enabled in the member's config (same type and command), or any non-command extension
      with extensions_edit;
    - command extensions (stdio, inline_python), shell-capable or extension-starting ones (GUARDED_EXTENSIONS)
      only with allow_shell (and extensions_edit when not already enabled);
    - sub_recipes (they run through summon) and retry checks / on_failure (shell commands) only with allow_shell;
    - a provider / model the team allows.
    `enabled` = enabled_extension_map(config/extensions/list); None = unknown: only the rules that do not depend on
    the member's config apply (the hub repeats the check with the real map)."""
    if not isinstance(recipe, dict):
        return ["could not be read"]
    out: list[str] = []
    exts = recipe.get("extensions")
    if exts is not None and not isinstance(exts, list):
        return ["has an unreadable extensions list"]
    for e in exts or []:
        if not isinstance(e, dict):
            out.append("has an unreadable extension entry")
            continue
        name = str(e.get("name") or (e.get("server") or {}).get("name") or "")
        key = ext_key(name)
        current = (enabled or {}).get(key)
        label = f"extension '{name[:80]}'"
        if is_command_extension(e):
            need = ["allow_shell"] + ([] if _same_command(e, current) else ["extensions_edit"])
            label = f"command extension '{name[:80]}'"
        elif extension_needs(name):
            need = extension_needs(name) + ([] if current is not None else ["extensions_edit"])
        elif str(e.get("type") or "").lower() in ("platform", "builtin") and current is not None:
            need = []
        elif current is not None and _same_command(e, current):
            need = []
        else:
            need = ["extensions_edit"] if enabled is not None else []
        lack = missing(policy, need)
        if lack:
            out.append(f"starts the {label}, which needs the {' and '.join(lack)} permission")
    if recipe.get("sub_recipes") and not policy.get("allow_shell"):
        out.append("runs sub-recipes (through summon), which needs the allow_shell permission")
    retry = recipe.get("retry")
    if isinstance(retry, dict) and (retry.get("checks") or retry.get("on_failure")) and not policy.get("allow_shell"):
        out.append("runs retry checks (shell commands), which needs the allow_shell permission")
    settings = recipe.get("settings") if isinstance(recipe.get("settings"), dict) else {}
    if settings.get("goose_provider") and not allows(policy, "allowed_providers", settings["goose_provider"]):
        out.append(f"uses the provider '{str(settings['goose_provider'])[:80]}', which your team does not allow")
    if settings.get("goose_model") and not allows(policy, "allowed_models", settings["goose_model"]):
        out.append(f"uses the model '{str(settings['goose_model'])[:80]}', which your team does not allow")
    return out


def check_recipe(recipe: Any, policy: dict, enabled: dict[str, dict] | None, *, what: str = "this recipe") -> None:
    probs = recipe_problems(recipe, policy, enabled)
    if probs:
        title = str((recipe or {}).get("title") or "") if isinstance(recipe, dict) else ""
        raise Denied(f"{what}{' ' + repr(title[:80]) if title else ''} {probs[0]}"
                     + (f" (and {len(probs) - 1} more problem(s))" if len(probs) > 1 else ""))


def enabled_extensions_names(value: Any) -> list[str]:
    """session/new `_meta.enabledExtensions`: a list of names / extension configs, or a {name: bool} map."""
    if isinstance(value, dict):
        return [str(k) for k, v in value.items() if v]
    if isinstance(value, list):
        out = []
        for v in value:
            if isinstance(v, dict):
                out.append(str(v.get("name") or v.get("configKey") or v.get("key") or ""))
            else:
                out.append(str(v))
        return out
    return [str(value)] if value else []


def check_enabled_extensions(value: Any, policy: dict, configured: dict[str, dict] | None = None) -> None:
    """Members choosing session extensions (session/new `_meta.enabledExtensions`): extensions_edit, plus
    allow_shell for shell-capable / extension-starting names and for command entries of the member's config."""
    if not policy.get("extensions_edit"):
        raise Denied("choosing session extensions needs the extensions_edit permission")
    if isinstance(value, list) and any(isinstance(v, dict) and is_command_extension(v) for v in value):
        if not policy.get("allow_shell"):
            raise Denied("command-running extensions need the allow_shell permission")
    for n in enabled_extensions_names(value):
        lack = missing(policy, extension_needs(n))
        entry = (configured or {}).get(ext_key(n))
        if not lack and entry is not None and is_command_extension(entry):
            lack = missing(policy, ["allow_shell"])
        if lack:
            raise Denied(f"the extension '{n[:80]}' needs the {' and '.join(lack)} permission")


IMPORT_DROP_FOR_MEMBERS = ("container",)


def sanitize_session_import(params: dict, policy: dict) -> dict | None:
    """A non-admin's session/import: Goose restores `extension_data.enabled_extensions*` of an imported session on
    session/load and starts every extension in it (a crafted stdio entry ran its command - measured on Goose 1.57).
    Keep only the harmless bundled entries of that state (platform / builtin, not GUARDED_EXTENSIONS; Goose does not
    fall back to the member's config for an imported session), drop a system-prompt override
    without prompts_edit, and return the imported recipe (if any) for check_recipe. The input must be a JSON object."""
    raw = params.get("input")
    if not isinstance(raw, str):
        raise Denied("session import needs the exported session JSON in 'input'")
    try:
        import json as _json
        data = _json.loads(raw)
    except ValueError:
        raise Denied("only JSON session exports can be imported")
    if not isinstance(data, dict):
        raise Denied("only JSON session exports can be imported")
    ed = data.get("extension_data")
    if isinstance(ed, dict):
        clean = {}
        for k, v in ed.items():
            if not str(k).lower().startswith("enabled_extensions"):
                clean[k] = v
                continue
            # keep the harmless bundled ones (todo, skills, memory, ...) so the chat still has its tools
            exts = v.get("extensions") if isinstance(v, dict) else None
            keep = [e for e in exts or [] if isinstance(e, dict)
                    and str(e.get("type") or "").lower() in ("platform", "builtin")
                    and not is_command_extension(e) and not extension_needs(e.get("name"))]
            clean[k] = {**v, "extensions": keep} if isinstance(v, dict) else {"extensions": keep}
        data["extension_data"] = clean
    elif ed is not None:
        data["extension_data"] = {}
    for k in IMPORT_DROP_FOR_MEMBERS:
        data.pop(k, None)
    if not policy.get("prompts_edit"):
        data.pop("system_prompt_override", None)
        data.pop("system_prompt_extras", None)
    params["input"] = _json.dumps(data)
    for k in [k for k in params if k not in ("input", "source")]:
        params.pop(k, None)
    return data.get("recipe") if isinstance(data.get("recipe"), dict) else None


def check(method: str, params: Any, *, is_admin: bool, policy: dict, roots: list[str]) -> None:
    """Raise Denied(reason) if the call is not allowed. May normalise params in place."""
    if not isinstance(method, str) or not method:
        raise Denied("invalid method")
    params = params if isinstance(params, dict) else {}
    if method == "session/new":
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
        meta.pop("hidden", None)
        if not is_admin:
            # B-1: only the keys the SPA sends; recipe keys are resolved and checked by the hub (Upstream).
            meta = {k: v for k, v in meta.items() if k in MEMBER_NEW_META_KEYS}
            if meta.get("enabledExtensions") is not None:
                check_enabled_extensions(meta["enabledExtensions"], policy)
            for k in ("recipeId", "recipeDeeplink"):
                if k in meta and not isinstance(meta[k], str):
                    raise Denied(f"{k} must be a string")
        meta["client"] = "goose-web"
        params["_meta"] = meta
    if method in ("session/load", "session/resume") and not is_admin and "_meta" in params:
        params.pop("_meta", None)   # the SPA sends none; nothing else reaches Goose from a non-admin (B-1)
    if method in ("session/new", "session/load", "session/fork", "session/resume"):
        # Goose persists per-session MCP servers given on ANY of these (prepare_session_for_activation), and a
        # stdio server is an arbitrary command: same rule for all four (1.7.0 security fix NEW-30; GW-32).
        if params.get("mcpServers") and not is_admin and not policy.get("allow_shell"):
            raise Denied("per-session MCP servers need the allow_shell permission")
    if method == "session/fork" and not is_admin:
        meta = params.get("_meta")
        if isinstance(meta, dict):   # only the cut point (Edit > Branch); nothing else reaches Goose from a non-admin
            params["_meta"] = {k: v for k, v in meta.items() if k == "conversationBefore"}
    if method == TOOLS_CALL:
        check_tool_call_target(params)  # every user, admins included (NEW-01)
    if method in ("session/new", "session/load", "session/fork", "session/resume"):
        canonical_dirs(params)   # SD-5: every check below and Goose itself see the same, canonical folder
    if is_admin:
        return
    if method in ("session/new", "session/fork", "session/prompt"):
        why = chat_block(policy)
        if why:
            raise Denied(why)
    if method in ("session/new", "session/load", "session/fork", "session/resume"):
        cwd = params.get("cwd")
        if cwd is not None and not path_allowed(str(cwd), roots):
            raise Denied(f"folder not allowed: {cwd}")
        for d in params.get("additionalDirectories") or []:
            if not path_allowed(str(d), roots):
                raise Denied(f"folder not allowed: {d}")
    if method == "session/new":
        # NEW-36: Goose would start the MCP servers (commands) of every plugin in <cwd>/.agents/plugins.
        # SD-2 (security review 2026-11-11): in a folder other members can write (the team folder, the team's extra
        # folders) a plugin may be someone else's program, which would run as THIS member - refused whatever the
        # member's permissions. Only the member's own workspace allows plugins, and only with allow_shell.
        found = project_plugins(params.get("cwd"))
        if found:
            names = ", ".join(n[:40] for n in found[:3]) + (", ..." if len(found) > 3 else "")
            own = bool(roots) and path_allowed(str(params.get("cwd") or ""), roots[:1])
            if not own:
                raise Denied(f"this shared folder has Goose plugins in .agents/plugins ({names}); plugins run "
                             "programs as the person who starts the chat, so chats cannot start here. Ask your "
                             "administrator to remove them, or start the chat in your own workspace")
            if not policy.get("allow_shell"):
                raise Denied(f"this folder has Goose plugins in .agents/plugins ({names}); plugins run programs, so "
                             "chats in this folder need the allow_shell permission")
    if method == P + "session/working-dir/update" and not path_allowed(str(params.get("workingDir") or ""), roots):
        raise Denied("folder not allowed")
    if method == "session/set_mode" and not allows(policy, "allowed_modes", params.get("modeId")):
        raise Denied(f"mode not allowed: {params.get('modeId')}")
    if method == "session/set_config_option":
        cid, val = params.get("configId"), params.get("value")
        key = {"provider": "allowed_providers", "model": "allowed_models", "mode": "allowed_modes"}.get(cid)
        if key and not allows(policy, key, val):
            raise Denied(f"{cid} not allowed: {val}")
    if method in (P + "config/upsert", P + "config/remove"):
        managed = str(params.get("key") or "").strip().upper()
        if managed in MANAGED_CONFIG_KEYS or managed.startswith(MANAGED_CONFIG_PREFIXES):
            raise Denied(f"{params.get('key')} is managed by Goose Web")
    if method == P + "session/import":
        sanitize_session_import(params, policy)   # the hub checks the imported recipe (if any)
    if method == P + "tools/permissions/set" and guard_on(policy):
        # spec 018: an "always allow" tool is never asked about again, so the guard would never see its calls
        for e in params.get("toolPermissions") or []:
            if isinstance(e, dict) and str(e.get("permission") or "").lower().replace("-", "_") == "always_allow":
                raise Denied("your team uses the prompt guard, so tools cannot be set to 'always allow'")
    if method in ALWAYS:
        return
    if method in SOURCE_METHODS:
        perm = SOURCE_PERMISSION.get(str(params.get("type") or "skill"), "skills_edit")
        if not policy.get(perm):
            raise Denied(f"needs the {perm} permission")
        target = params.get("target") or {}
        # SD-3: project skills / agents land in <projectDir>/.agents and are read by everyone who chats there, so a
        # member may only write them into their own workspace (never the shared team folder)
        if isinstance(target, dict) and target.get("scope") == "projectDir" and \
                not path_allowed(str(target.get("projectDir") or ""), roots[:1]):
            raise Denied("project skills and agents can only be saved in your own workspace")
        return
    if method == P + "config/read" and str(params.get("key")) in READABLE_CONFIG_KEYS and not params.get("isSecret"):
        return
    for perm, methods in BY_PERMISSION.items():
        if method in methods:
            if not policy.get(perm):
                raise Denied(f"needs the {perm} permission")
            if method in (P + "session/extensions/add", P + "config/extensions/add"):
                ext = params.get("extension") or {}
                name = _ext_name(ext)
                if (extension_needs(name) or is_command_extension(ext)) and not policy.get("allow_shell"):
                    raise Denied("command-running extensions need the allow_shell permission")
            if method == P + "config/extensions/set-enabled" and params.get("enabled"):
                lack = missing(policy, extension_needs(params.get("configKey") or params.get("name")))
                if lack:
                    raise Denied(f"this extension needs the {' and '.join(lack)} permission")
            if method == P + "config/extensions/remove":
                # Goose enables a bundled platform extension that is missing from config.yaml (developer, scheduler,
                # ...): removing the pinned `enabled: false` entry would turn it on (B-2).
                key = params.get("configKey") or params.get("name") or params.get("key")
                lack = missing(policy, extension_needs(key))
                if lack:
                    raise Denied(f"removing this extension would turn it on; it needs the {' and '.join(lack)} "
                                 "permission")
            if method == P + "tools/call":
                tool_ext = ext_key(params.get("extensionName"))
                name = str(params.get("name") or params.get("toolName") or "")
                tool_prefix = ext_key(name.split("__", 1)[0]) if "__" in name else ""
                if not tool_ext and not tool_prefix:
                    raise Denied("a direct tool call must name its extension (extensionName)")
                for k in {tool_ext, tool_prefix} - {""}:
                    lack = missing(policy, extension_needs(k))
                    if lack:   # B-3: extensionmanager enables developer; summon / scheduler run recipes
                        raise Denied(f"direct calls to the {_GUARDED_KEYS.get(k, k)} extension need the "
                                     f"{' and '.join(lack)} permission")
            if method in (P + "config/upsert", P + "config/remove") and \
                    str(params.get("key") or "").lower().split(".", 1)[0] == "extensions":
                lack = missing(policy, ["extensions_edit", "allow_shell"])
                if lack:   # the raw extensions map can hold stdio commands and re-enable developer
                    raise Denied(f"editing the raw extensions config needs the {' and '.join(lack)} permission")
            if method in (P + "schedules/create", P + "schedules/update") and "recipe" in params:
                # a scheduled recipe starts its extensions (a stdio entry ran its command on run-now - measured);
                # the hub repeats this check with the member's enabled extensions
                check_recipe(params.get("recipe"), policy, None, what="the scheduled recipe")
            if method == P + "config/upsert":
                key = CONFIG_LIST_KEYS.get(str(params.get("key")).upper())
                if key and params.get("value") is not None and not allows(policy, key, params.get("value")):
                    raise Denied(f"{params.get('key')} value not allowed by your team")
            if method == P + "defaults/save":
                if not allows(policy, "allowed_providers", params.get("providerId")):
                    raise Denied("provider not allowed")
                if params.get("modelId") and not allows(policy, "allowed_models", params.get("modelId")):
                    raise Denied("model not allowed")
            return
    raise Denied(f"method not available to your account: {method}")
