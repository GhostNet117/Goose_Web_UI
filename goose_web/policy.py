"""Effective policy (the user's one team + user overrides) and the ACP method firewall.

Least privilege (spec 009): a missing or false switch is off, an empty allowed_modes / allowed_providers /
allowed_models list allows NOTHING, and the explicit value "*" (ANY) allows everything. A user without a team
can sign in but cannot chat. Admins are unrestricted. For everyone else, every ACP method a browser sends goes
through `check()`. Unknown methods are denied by default, so a new Goose release cannot open a hole by itself.
"""
from __future__ import annotations

import os
import sys
from pathlib import PurePath
from typing import Any

BOOL_KEYS = ["recipes_edit", "skills_edit", "extensions_edit", "providers_edit", "schedules", "apps",
             "prompts_edit", "hints_edit", "tools_permissions", "config_edit", "allow_shell", "notify_webhook"]
LIST_KEYS = ["allowed_modes", "allowed_providers", "allowed_models", "allowed_roots"]
# Lists that gate chatting. "*" = any value; empty = none. allowed_roots has no "*" (folders are explicit).
CHAT_LISTS = ["allowed_modes", "allowed_providers", "allowed_models"]
ANY = "*"
# Extra keys a team policy may carry besides BOOL_KEYS / LIST_KEYS / max_concurrent_runs.
TEAM_EXTRA_KEYS = ["default_provider", "default_model", "share_folder"]

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

# Extensions that give the model a shell or arbitrary code execution.
SHELL_EXTENSIONS = {"developer", "computercontroller", "code_execution", "orchestrator"}

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
    for k, v in (user.get("policy_overrides") or {}).items():
        if k in DEFAULT_POLICY:
            pol[k] = v
    pol["chat_blocked"] = chat_block(pol)
    return pol


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


def team_warnings(policy: dict, *, hints: int, members: int) -> list[dict]:
    """What the admin should know about a team's experience (Experience page). level: err | warn | info."""
    p = {**DEFAULT_POLICY, **(policy or {})}
    out: list[dict] = []
    for k in ("allowed_providers", "allowed_models", "allowed_modes"):
        if not p.get(k):
            out.append({"level": "err", "text": f"No {_LIST_LABELS[k]} allowed: members can't chat."})
    dp, dm = p.get("default_provider"), p.get("default_model")
    if dp and p.get("allowed_providers") and not allows(p, "allowed_providers", dp):
        out.append({"level": "warn", "text": f"The default provider '{dp}' is not in the allowed providers."})
    if dm and p.get("allowed_models") and not allows(p, "allowed_models", dm):
        out.append({"level": "warn", "text": f"The default model '{dm}' is not in the allowed models."})
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
    if not members:
        out.append({"level": "info", "text": "No members yet."})
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


def check(method: str, params: Any, *, is_admin: bool, policy: dict, roots: list[str]) -> None:
    """Raise Denied(reason) if the call is not allowed. May normalise params in place."""
    if not isinstance(method, str) or not method:
        raise Denied("invalid method")
    params = params if isinstance(params, dict) else {}
    if method == "session/new":
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
        meta["client"] = "goose-web"
        meta.pop("hidden", None)
        params["_meta"] = meta
        if params.get("mcpServers") and not is_admin and not policy.get("allow_shell"):
            raise Denied("per-session MCP servers need the allow_shell permission")
        if not is_admin and meta.get("enabledExtensions") is not None and not policy.get("extensions_edit"):
            raise Denied("choosing session extensions needs the extensions_edit permission")
    if method == TOOLS_CALL:
        check_tool_call_target(params)  # every user, admins included (NEW-01)
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
    if method == P + "session/working-dir/update" and not path_allowed(str(params.get("workingDir") or ""), roots):
        raise Denied("folder not allowed")
    if method == "session/set_mode" and not allows(policy, "allowed_modes", params.get("modeId")):
        raise Denied(f"mode not allowed: {params.get('modeId')}")
    if method == "session/set_config_option":
        cid, val = params.get("configId"), params.get("value")
        key = {"provider": "allowed_providers", "model": "allowed_models", "mode": "allowed_modes"}.get(cid)
        if key and not allows(policy, key, val):
            raise Denied(f"{cid} not allowed: {val}")
    if method in (P + "config/upsert", P + "config/remove") and \
            str(params.get("key") or "").upper() in MANAGED_CONFIG_KEYS:
        raise Denied(f"{params.get('key')} is managed by Goose Web")
    if method in ALWAYS:
        return
    if method in SOURCE_METHODS:
        perm = SOURCE_PERMISSION.get(str(params.get("type") or "skill"), "skills_edit")
        if not policy.get(perm):
            raise Denied(f"needs the {perm} permission")
        target = params.get("target") or {}
        if isinstance(target, dict) and target.get("scope") == "projectDir" and \
                not path_allowed(str(target.get("projectDir") or ""), roots):
            raise Denied("project folder not allowed")
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
                stdio = ext.get("type") == "mcp" and "command" in (ext.get("server") or {})
                if (name in SHELL_EXTENSIONS or stdio) and not policy.get("allow_shell"):
                    raise Denied("command-running extensions need the allow_shell permission")
            if method == P + "config/extensions/set-enabled" and params.get("enabled") and \
                    str(params.get("configKey") or "").lower() in SHELL_EXTENSIONS and not policy.get("allow_shell"):
                raise Denied("shell extensions need the allow_shell permission")
            tool_ext = str(params.get("extensionName") or "").lower()
            tool_prefix = str(params.get("name") or params.get("toolName") or "").lower().split("__", 1)[0]
            if method == P + "tools/call" and (tool_ext in SHELL_EXTENSIONS or tool_prefix in SHELL_EXTENSIONS) \
                    and not policy.get("allow_shell"):
                raise Denied("direct shell tool calls need the allow_shell permission")
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
