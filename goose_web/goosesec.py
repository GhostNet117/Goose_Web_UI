"""Goose-native security (spec 026): prompt injection detection and adversary mode, configured where Goose reads them.

The prompt guard of spec 018 (guard.py) runs in the gateway and only sees chats that pass through it. Goose has two
security features of its own that run inside the agent in every front end (Goose Web, Goose Desktop, the goose CLI,
scheduled recipes): prompt injection detection (SECURITY_PROMPT_* settings, optionally with a self-hosted classifier)
and adversary mode (<config dir>/adversary.md). This module holds their settings and writes them for every profile:

  * isolated profiles (members): Profiles.provision applies profile_plan() to config.yaml, secrets.yaml and
    config/adversary.md before every worker start, and the worker gets the same values in its environment, which
    Goose ranks above its files, so neither a member nor an agent can weaken them;
  * the native profile (the administrator's Goose appdata, shared with Goose Desktop and the CLI): apply_native()
    sets the keys through Goose's own configuration API, so Goose decides the file format and where the secret is
    kept. adversary.md is a plain file by Goose's design; a file Goose Web did not write is never replaced.

What Goose really does with these settings (read in the source of 1.57.0 and 1.59.0 and measured with 1.57.0, spec
026 spike s1) differs from its public guides in ways that matter here:
  - the classifier token is read from the secret store or the environment; a token in config.yaml is ignored;
  - the classifier is sent the chat's recent USER MESSAGES, one request each, on every shell call - never the command;
  - only the tool named exactly "shell" is inspected; a finding becomes an approval request, also in Auto mode, except
    in a headless `goose run` in Auto mode, which allows the call and only logs it;
  - adversary mode is on when adversary.md exists; a BLOCK cannot be overridden and also stops headless runs; every
    reviewed call costs one more model call. It is therefore OFF until an administrator turns it on.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any

from .security import consteq

log = logging.getLogger("goose_web")

SETTING = "goose_security"            # the administrators' choice (absent = DEFAULTS)
KEY_SETTING = "goose_security_key"    # HMAC key of the classifier tokens; never leaves the database
STATE_SETTING = "goose_security_state"   # outcome of the last native apply

P = "_goose/unstable/"
ENABLED, THRESHOLD = "SECURITY_PROMPT_ENABLED", "SECURITY_PROMPT_THRESHOLD"
CLS_ENABLED, CLS_ENDPOINT = "SECURITY_PROMPT_CLASSIFIER_ENABLED", "SECURITY_PROMPT_CLASSIFIER_ENDPOINT"
CLS_TOKEN = "SECURITY_PROMPT_CLASSIFIER_TOKEN"   # a secret (Goose reads it with get_secret)
CONFIG_KEYS = (ENABLED, THRESHOLD, CLS_ENABLED, CLS_ENDPOINT)
# Goose configuration keys only administrators may change (policy.check). The whole family, so the undocumented
# SECURITY_COMMAND_CLASSIFIER_* and the *_OVERRIDE switches are covered too.
MANAGED_KEY_PREFIX = "SECURITY_"
ADVERSARY_FILE = "adversary.md"
DEFAULT_TOOLS = ["shell"]            # Goose's own default (adversary_inspector.rs DEFAULT_TOOLS)
MAX_RULES_CHARS = 8000
MAX_TOOLS = 32
TOOL_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,95}")
TOKEN_RE = re.compile(r"gwc1\.(\d{1,12})\.([0-9a-f]{64})")

DEFAULTS: dict[str, Any] = {
    "enabled": True,        # prompt injection detection (patterns)
    "threshold": 0.8,       # Goose's default; lower = stricter
    "classifier": True,     # Prompt Guard 2 through the gateway's classification endpoint
    "adversary": {"members": False, "native": False, "tools": list(DEFAULT_TOOLS), "rules": ""},
}


class SettingsError(ValueError):
    pass


# ---------------------------------------------------------------------------------------------------- settings
def _bool(v: Any, name: str) -> bool:
    if isinstance(v, bool):
        return v
    raise SettingsError(f"{name} must be true or false")


def clean_rules(v: Any) -> str:
    """Adversary rules as Goose will read them: plain text, LF line ends, no BOM (a BOM in front of the file breaks
    Goose's `tools:` line), no NUL. Empty = Goose's built-in rules."""
    if v is None:
        return ""
    if not isinstance(v, str):
        raise SettingsError("adversary.rules must be text")
    s = v.replace("\ufeff", "").replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in s:
        raise SettingsError("adversary.rules contains a NUL character")
    s = "\n".join(line.rstrip() for line in s.split("\n")).strip("\n")
    if len(s) > MAX_RULES_CHARS:
        raise SettingsError(f"adversary.rules is longer than {MAX_RULES_CHARS} characters")
    return s


def clean_tools(v: Any) -> list[str]:
    """Tool names the reviewer checks. Goose compares them exactly with the name the model calls (`shell`, or
    `<extension>__<tool>` for an extension's tool)."""
    if v is None:
        return list(DEFAULT_TOOLS)
    if isinstance(v, str):
        v = [x for x in re.split(r"[,\n]", v)]
    if not isinstance(v, list):
        raise SettingsError("adversary.tools must be a list of tool names")
    out: list[str] = []
    for x in v:
        name = str(x).strip()
        if not name:
            continue
        if not TOOL_RE.fullmatch(name):
            raise SettingsError(f"adversary.tools: {name[:40]!r} is not a tool name (letters, digits, _ . -)")
        if name not in out:
            out.append(name)
    if len(out) > MAX_TOOLS:
        raise SettingsError(f"adversary.tools lists more than {MAX_TOOLS} tools")
    return out or list(DEFAULT_TOOLS)


def clean(body: Any, base: dict | None = None) -> dict:
    """A validated settings object: `body` (any subset of the keys) over `base` (default: DEFAULTS)."""
    out = copy.deepcopy(base if base is not None else DEFAULTS)
    if not isinstance(body, dict):
        raise SettingsError("the settings must be an object")
    if "enabled" in body:
        out["enabled"] = _bool(body["enabled"], "enabled")
    if "classifier" in body:
        out["classifier"] = _bool(body["classifier"], "classifier")
    if "threshold" in body:
        t = body["threshold"]
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0.01 <= float(t) <= 1.0:
            raise SettingsError("threshold must be a number from 0.01 to 1.0 (lower = stricter)")
        out["threshold"] = round(float(t), 2)
    adv = body.get("adversary")
    if adv is not None:
        if not isinstance(adv, dict):
            raise SettingsError("adversary must be an object")
        a = out["adversary"]
        for k in ("members", "native"):
            if k in adv:
                a[k] = _bool(adv[k], f"adversary.{k}")
        if "tools" in adv:
            a["tools"] = clean_tools(adv["tools"])
        if "rules" in adv:
            a["rules"] = clean_rules(adv["rules"])
    return out


def load(db) -> dict:
    """The administrators' settings; a database that never stored a choice gets DEFAULTS (an upgrade applies them,
    an explicit choice is kept). A stored value that no longer validates falls back key by key."""
    stored = db.get_setting(SETTING)
    if not isinstance(stored, dict):
        return copy.deepcopy(DEFAULTS)
    try:
        return clean(stored)
    except SettingsError:
        out = copy.deepcopy(DEFAULTS)
        for k in ("enabled", "classifier", "threshold"):
            try:
                out = clean({k: stored[k]}, out)
            except (SettingsError, KeyError):
                pass
        adv = stored.get("adversary") if isinstance(stored.get("adversary"), dict) else {}
        for k in ("members", "native", "tools", "rules"):
            try:
                out = clean({"adversary": {k: adv[k]}}, out)
            except (SettingsError, KeyError):
                pass
        log.warning("goose security: the stored settings were not valid; the unreadable parts use the defaults")
        return out


def read_only(db_path) -> tuple[dict, dict | None, bool]:
    """(settings, native state, chosen) through a read-only connection: `goose-web check` and `security status` run
    next to a live gateway and must not open the database for writing."""
    import sqlite3
    rows: dict[str, Any] = {}
    try:
        con = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            for key, value in con.execute("SELECT key, value FROM settings WHERE key IN (?, ?)",
                                          (SETTING, STATE_SETTING)):
                try:
                    rows[key] = json.loads(value)
                except ValueError:
                    pass
        finally:
            con.close()
    except sqlite3.Error:
        pass   # no database yet, or no settings table: the defaults

    class _Rows:
        def get_setting(self, key, default=None):
            return rows.get(key, default)
    state = rows.get(STATE_SETTING)
    native = state.get("native") if isinstance(state, dict) else None
    return load(_Rows()), (native if isinstance(native, dict) else None), isinstance(rows.get(SETTING), dict)


def chosen(db) -> bool:
    """True when an administrator (or the installer) stored a choice; False = running on the defaults."""
    return isinstance(db.get_setting(SETTING), dict)


def save(db, cfg: dict) -> dict:
    cfg = clean(cfg)
    db.set_setting(SETTING, cfg)
    return cfg


def summary(cfg: dict) -> dict:
    """What an audit row may hold: switches and sizes, never the rules text."""
    a = cfg["adversary"]
    return {"enabled": cfg["enabled"], "threshold": cfg["threshold"], "classifier": cfg["classifier"],
            "adversaryMembers": a["members"], "adversaryNative": a["native"], "adversaryTools": list(a["tools"]),
            "adversaryRulesChars": len(a["rules"])}


# ---------------------------------------------------------------------------------------------------- tokens
def _key(db) -> bytes:
    k = db.get_setting(KEY_SETTING)
    if not (isinstance(k, str) and len(k) >= 40):
        # two processes may start at once (the gateway and a CLI command): whoever inserts first wins
        db.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)",
                   (KEY_SETTING, json.dumps(secrets.token_urlsafe(48))))
        k = db.get_setting(KEY_SETTING)
        if not (isinstance(k, str) and len(k) >= 40):   # an unusable stored value: replace it
            k = secrets.token_urlsafe(48)
            db.set_setting(KEY_SETTING, k)
    return k.encode("ascii", "replace")


def rotate_key(db) -> None:
    """Every classifier token stops working; profiles get new ones at their next provisioning / native apply."""
    db.set_setting(KEY_SETTING, secrets.token_urlsafe(48))


def token_for(db, user_id: int, key: bytes | None = None) -> str:
    """The profile's classifier token. It authorises classification requests and nothing else."""
    uid = int(user_id)
    mac = hmac.new(key or _key(db), f"classify:{uid}".encode(), hashlib.sha256).hexdigest()
    return f"gwc1.{uid}.{mac}"


def verify_token(db, token: str | None, key: bytes | None = None) -> int | None:
    """The user id a token belongs to, or None. Constant-time comparison; the caller checks the user still exists."""
    m = TOKEN_RE.fullmatch(token or "")
    if not m:
        # same work for a malformed token as for a wrong one
        consteq(token_for(db, 0, key), "gwc1.0." + "0" * 64)
        return None
    uid = int(m.group(1))
    return uid if consteq(token, token_for(db, uid, key)) else None


# ---------------------------------------------------------------------------------------------------- adversary.md
def adversary_text(cfg: dict) -> str:
    """The adversary.md Goose reads: a `tools:` line, the `---` separator, then the rules. Goose splits the file at
    the FIRST line that starts with `---`, so a `---` inside the rules is harmless. Empty rules = Goose's built-in
    rules. UTF-8 without BOM, LF."""
    a = cfg["adversary"]
    tools = ", ".join(a.get("tools") or DEFAULT_TOOLS)
    rules = a.get("rules") or ""
    return f"tools: {tools}\n---\n{rules}\n" if rules else f"tools: {tools}\n---\n"


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_hash(p: Path) -> str | None:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------------------------------- plan
def classifier_port(settings) -> int:
    """guard.classifier_port: the loopback port of the classification endpoint (0 = no endpoint)."""
    try:
        p = int(settings.get("guard", "classifier_port", 8711))
    except (TypeError, ValueError):
        return 0
    return p if 0 < p < 65536 else 0


def classifier_url(port: int) -> str:
    return f"http://127.0.0.1:{int(port)}/classify"


def profile_plan(cfg: dict, *, native: bool, token: str | None, endpoint: str | None) -> dict:
    """What one profile gets. `endpoint` None = the classification endpoint is not available (not listening, off):
    detection then runs on patterns only and no chat text is sent anywhere.

    -> {config: {key: value}, remove: [config keys], secret: token | None, adversary: text | None,
        env: {name: value}}. `env` is for isolated workers; Goose ranks the environment above config.yaml and the
    secret store."""
    config: dict[str, Any] = {}
    remove: list[str] = []
    env: dict[str, str] = {}
    secret = None
    if cfg["enabled"]:
        use_cls = bool(cfg["classifier"] and endpoint and token)
        config[ENABLED] = True
        config[THRESHOLD] = float(cfg["threshold"])
        config[CLS_ENABLED] = use_cls
        env[ENABLED] = "true"
        env[THRESHOLD] = repr(float(cfg["threshold"]))
        env[CLS_ENABLED] = "true" if use_cls else "false"
        if use_cls:
            config[CLS_ENDPOINT] = endpoint
            env[CLS_ENDPOINT] = str(endpoint)
            env[CLS_TOKEN] = str(token)
            secret = token
        else:
            remove.append(CLS_ENDPOINT)
    else:
        remove = list(CONFIG_KEYS)
    adv = adversary_text(cfg) if cfg["adversary"]["native" if native else "members"] else None
    return {"config": config, "remove": remove, "secret": secret, "adversary": adv, "env": env}


# ---------------------------------------------------------------------------------------------------- native profile
def _backup(system_dir: Path, src: Path) -> str:
    d = Path(system_dir) / "backups" / "native-security"
    d.mkdir(parents=True, exist_ok=True)
    dst = d / f"{ADVERSARY_FILE}.{time.strftime('%Y%m%d-%H%M%S')}"
    n = 1
    while dst.exists():
        n += 1
        dst = d / f"{ADVERSARY_FILE}.{time.strftime('%Y%m%d-%H%M%S')}-{n}"
    dst.write_bytes(src.read_bytes())
    return str(dst)


def apply_adversary_file(path: Path, want: str | None, ours: str | None, system_dir: Path, *,
                         adopt: bool = False) -> dict:
    """Write, replace or remove the native profile's adversary.md.

    `ours` is the hash of the file Goose Web wrote last. A file with another content was written by the
    administrator (or another tool): it is kept and reported, unless `adopt` says to take it over (it is backed up
    first). -> {state: on | off | foreign | error, hash, changed, backup?, error?}"""
    out: dict[str, Any] = {"changed": False, "hash": None}
    try:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return {**out, "state": "error", "error": f"{path.name} is not a regular file"}
        cur = file_hash(path) if path.exists() else None
        if path.exists() and cur is None:
            return {**out, "state": "error", "error": f"{path.name} exists but cannot be read; it was left alone"}
        mine = cur is not None and (cur == ours or (want is not None and cur == text_hash(want)))
        if want is None:
            if cur is None:
                return {**out, "state": "off"}
            if not mine:
                return {**out, "state": "foreign", "hash": None}
            out["backup"] = _backup(system_dir, path)
            path.unlink()
            return {**out, "state": "off", "changed": True}
        h = text_hash(want)
        if cur == h:
            return {**out, "state": "on", "hash": h}
        if cur is not None and not mine and not adopt:
            return {**out, "state": "foreign", "hash": None}
        if cur is not None:
            out["backup"] = _backup(system_dir, path)
        tmp = path.with_name(path.name + ".gw-tmp")
        tmp.write_text(want, encoding="utf-8", newline="\n")
        tmp.replace(path)
        return {**out, "state": "on", "hash": h, "changed": True}
    except OSError as e:
        return {**out, "state": "error", "error": f"{e.__class__.__name__}: {str(e)[:200]}"}


def _same(a: Any, b: Any) -> bool:
    return a == b and type(a) is type(b)


def _could_not_ask(e: BaseException) -> bool:
    """True when a Goose request failed because Goose could not be asked (the worker is down, a timeout, the method
    does not exist), as opposed to Goose answering that a key is not there. Only the second may count as "absent"."""
    if isinstance(e, (asyncio.TimeoutError, TimeoutError, ConnectionError, OSError)):
        return True
    code = getattr(e, "code", None)
    return not isinstance(code, int) or code in (-32000, -32601, -32600, -32700)


async def apply_native(*, db, settings, upstream, config_dir: Path, user: dict, endpoint: str | None,
                       goose_version: str = "", adopt: bool = False, timeout: float = 30.0) -> dict:
    """Apply the plan to a native profile through Goose's own configuration API and record the outcome.

    `upstream` is the profile's hub.Upstream (its request() starts the worker when needed). Nothing here raises:
    a failure is recorded and returned ({ok: False, error}), and Goose keeps running with what it had.

    OWNERSHIP (security review 2026-11-12, E-3). The native profile is the administrator's own Goose: they may have
    set these keys themselves. Goose Web therefore remembers what it wrote (`written`, the token's fingerprint) and
      - replaces or removes a value only when it is absent or still exactly what Goose Web wrote;
      - keeps any other value and reports the key as `foreign`, unless `adopt` says to take it over (the replaced
        values are saved to <system_dir>/backups/native-security first);
      - treats the classifier keys as one group: an endpoint someone else configured keeps its switch and its token;
      - when the feature is off, removes only its own values. An "off" that was never "on" touches nothing.
    Every write is read back. A request Goose could not be asked (worker down, timeout, unknown method) is a
    failure, never "the key is not there" (E-7)."""
    cfg = load(db)
    token = token_for(db, user["id"]) if endpoint else None
    plan = profile_plan(cfg, native=True, token=token, endpoint=endpoint)
    prev = db.get_setting(STATE_SETTING)
    pn = prev.get("native") if isinstance(prev, dict) and isinstance(prev.get("native"), dict) else {}
    ours: dict = dict(pn["written"]) if isinstance(pn.get("written"), dict) else {}
    our_token = bool(pn.get("tokenFp"))
    our_adv = pn.get("adversaryHash")
    state: dict[str, Any] = {"ok": True, "at": time.time(), "goose": goose_version, "user": user.get("username"),
                             "detection": bool(cfg["enabled"]), "classifier": bool(plan["secret"]),
                             "changed": [], "foreign": [], "error": "", "written": dict(ours),
                             "tokenFp": pn.get("tokenFp") or "", "adversary": pn.get("adversary") or "off",
                             "adversaryHash": our_adv}
    unknown = object()   # Goose answered that the key does not exist (some versions answer that with an error)
    replaced: dict[str, Any] = {}
    try:
        async def read(key: str, secret: bool = False) -> Any:
            try:
                r = await upstream.request(P + "config/read", {"key": key, "isSecret": secret}, timeout=timeout)
            except Exception as e:
                if _could_not_ask(e):
                    raise
                return unknown
            return r.get("value") if isinstance(r, dict) else None

        async def upsert(key: str, value: Any, secret: bool = False) -> None:
            await upstream.request(P + "config/upsert", {"key": key, "value": value, "isSecret": secret},
                                   timeout=timeout)

        async def remove(key: str, secret: bool = False) -> None:
            try:
                await upstream.request(P + "config/remove", {"key": key, "isSecret": secret}, timeout=timeout)
            except Exception as e:
                if _could_not_ask(e):
                    raise   # not removed and Goose could not say why: a failure, never "done"

        have = {k: await read(k) for k in CONFIG_KEYS}

        def present(k: str) -> bool:
            return have[k] is not None and have[k] is not unknown

        def is_ours(k: str) -> bool:
            return present(k) and k in ours and _same(have[k], ours[k])

        # someone else's classifier endpoint: its switch and its token stay as they are
        group_foreign = (present(CLS_ENDPOINT) and not is_ours(CLS_ENDPOINT) and not adopt
                         and not _same(have[CLS_ENDPOINT], plan["config"].get(CLS_ENDPOINT)))
        wrote: list[str] = []
        for key in CONFIG_KEYS:
            cur = have[key]
            if key in plan["config"]:
                want = plan["config"][key]
                if present(key) and _same(cur, want):
                    state["written"][key] = want
                    continue
                blocked = present(key) and not is_ours(key) and not adopt
                if key in (CLS_ENABLED, CLS_ENDPOINT) and group_foreign:
                    blocked = True
                if blocked:
                    state["foreign"].append(key)
                    state["written"].pop(key, None)
                    continue
                if present(key) and not is_ours(key):
                    replaced[key] = cur
                await upsert(key, want)
                state["written"][key] = want
                state["changed"].append(key)
                wrote.append(key)
            else:   # the plan wants the key gone: only Goose Web's own value is removed
                if is_ours(key):
                    await remove(key)
                    state["changed"].append(f"{key} removed")
                elif present(key):
                    state["foreign"].append(key)
                state["written"].pop(key, None)
        for key in wrote:   # read back
            back = await read(key)
            if back is unknown or not _same(back, state["written"][key]):
                raise RuntimeError(f"{key} did not read back as written")
        if plan["secret"] and not group_foreign:
            have_t = await read(CLS_TOKEN, True)
            # Goose masks a secret it returns, so the token is written at every apply (the same value changes nothing)
            await upsert(CLS_TOKEN, plan["secret"], True)
            fp = token_fingerprint(plan["secret"])
            if have_t is None or have_t is unknown or fp != state["tokenFp"]:
                state["changed"].append(f"{CLS_TOKEN} set")
            state["tokenFp"] = fp
        elif not plan["secret"] and our_token and not group_foreign:
            if await read(CLS_TOKEN, True) is not None:
                await remove(CLS_TOKEN, True)
                state["changed"].append(f"{CLS_TOKEN} removed")
            state["tokenFp"] = ""
        if replaced:
            d = Path(settings.system_dir) / "backups" / "native-security"
            d.mkdir(parents=True, exist_ok=True)
            bak = d / f"config-keys.{time.strftime('%Y%m%d-%H%M%S')}.json"
            bak.write_text(json.dumps(replaced, indent=1, default=str), encoding="utf-8")
            state["configBackup"] = str(bak)
    except Exception as e:   # the Goose worker did not start, the method changed, a timeout, a failed read-back
        state["ok"] = False
        state["error"] = f"{e.__class__.__name__}: {str(e)[:300]}"
        log.warning("goose security: the native profile of %s was not updated: %s", user.get("username"), state["error"])
    if state["ok"]:
        # adversary.md only after the settings went in: a failed apply changes nothing else
        adv = apply_adversary_file(Path(config_dir) / ADVERSARY_FILE, plan["adversary"], our_adv, settings.system_dir,
                                   adopt=adopt)
        state["adversary"] = adv["state"]
        state["adversaryHash"] = adv.get("hash") if adv["state"] == "on" else \
            (our_adv if adv["state"] in ("foreign", "error") else None)
        if adv.get("changed"):
            state["changed"].append("adversary.md " + ("written" if adv["state"] == "on" else "removed"))
        if adv.get("backup"):
            state["adversaryBackup"] = adv["backup"]
        if adv["state"] == "error":
            state["ok"] = False
            state["error"] = "adversary.md: " + adv.get("error", "")
    whole = prev if isinstance(prev, dict) else {}
    whole["native"] = state
    db.set_setting(STATE_SETTING, whole)
    return state


def native_state(db) -> dict | None:
    s = db.get_setting(STATE_SETTING)
    n = s.get("native") if isinstance(s, dict) else None
    return n if isinstance(n, dict) else None


def native_managed(settings) -> bool:
    """guard.native_profile (default true): may Goose Web change the administrator's own Goose profile at all?

    Found the hard way (2026-11-12): any real gateway whose administrator uses the default Goose folder applies
    these settings to it when it starts - also a gateway started by a test, on the developer's real Goose profile.
    tests/conftest.py therefore switches this off for the whole test session; only an explicit true counts as on
    when the value is not a boolean."""
    v = settings.get("guard", "native_profile", True)
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def token_fingerprint(token: str | None) -> str:
    """Enough of a hash to notice that the token changed; not enough to be the token."""
    return hashlib.sha256((token or "").encode()).hexdigest()[:16] if token else ""


def native_drift(config_dir: Path, plan: dict, state: dict | None) -> list[str]:
    """What apply_native would change, found WITHOUT starting Goose: config.yaml is only read. The secret store
    cannot be read from here, so the token is compared with what the last apply recorded. Values someone else set
    (not what Goose Web wrote) are not drift: apply_native keeps them. An empty list = nothing to do (the gateway
    then does not start the administrator's Goose worker for it)."""
    out: list[str] = []
    state = state or {}
    if not state.get("ok"):
        if not state:
            # never applied: an "off" that was never "on" has nothing to remove
            if not plan["config"] and plan["adversary"] is None:
                return []
            out.append("never applied")
        else:
            out.append("the last apply failed")
    try:
        import yaml
        cfg = yaml.safe_load((Path(config_dir) / "config.yaml").read_text(encoding="utf-8")) or {}
        if not isinstance(cfg, dict):
            cfg = {}
    except FileNotFoundError:
        cfg = {}
    except Exception:   # unreadable, or not YAML
        return out + ["config.yaml could not be read"]
    ours = state.get("written") if isinstance(state.get("written"), dict) else {}

    def is_ours(k: str) -> bool:
        return k in cfg and k in ours and _same(cfg[k], ours[k])
    group_foreign = (CLS_ENDPOINT in cfg and not is_ours(CLS_ENDPOINT)
                     and not _same(cfg[CLS_ENDPOINT], plan["config"].get(CLS_ENDPOINT)))
    for k in CONFIG_KEYS:
        if k in plan["config"]:
            if k in cfg and _same(cfg[k], plan["config"][k]):
                continue
            if (k in cfg and not is_ours(k)) or (group_foreign and k in (CLS_ENABLED, CLS_ENDPOINT)):
                continue   # someone else's value: kept
            out.append(k)
        elif is_ours(k):
            out.append(f"{k} present")
    if not group_foreign and token_fingerprint(plan["secret"]) != (state.get("tokenFp") or ""):
        out.append(CLS_TOKEN)
    adv = Path(config_dir) / ADVERSARY_FILE
    cur = file_hash(adv) if adv.is_file() else None
    theirs = state.get("adversaryHash")
    if plan["adversary"] is not None:
        if cur != text_hash(plan["adversary"]) and not (cur is not None and state.get("adversary") == "foreign"):
            out.append(ADVERSARY_FILE)
    elif cur is not None and theirs and cur == theirs:
        out.append(f"{ADVERSARY_FILE} present")
    return out


_native_lock: asyncio.Lock | None = None


async def sync_native(c, *, adopt: bool = False, force: bool = False) -> dict | None:
    """Bring the native administrator's profile in line with the settings (gateway start, a settings change, the
    admin's "Apply now"). `c` is the gateway's Ctx. Returns the recorded state, or None without a native profile.
    Never raises; a failure is recorded, audited and shown to administrators."""
    global _native_lock
    if _native_lock is None:
        _native_lock = asyncio.Lock()
    async with _native_lock:
        try:
            if not native_managed(c.settings):
                return None   # guard.native_profile: false - the administrator's own Goose profile is never changed
            admin = c.profiles._native_admin()
            if not admin or admin.get("disabled"):
                return None
            endpoint = c.classify.endpoint if c.classify is not None else None
            cfg = load(c.db)
            token = token_for(c.db, admin["id"]) if endpoint else None
            plan = profile_plan(cfg, native=True, token=token, endpoint=endpoint)
            config_dir = c.profiles.config_dir(admin)
            prev = native_state(c.db)
            drift = native_drift(config_dir, plan, prev)
            if not drift and not adopt and not force:
                return prev
            state = await apply_native(db=c.db, settings=c.settings, upstream=c.upstream_for(admin),
                                       config_dir=config_dir, user=admin, endpoint=endpoint,
                                       goose_version=c.goose_version, adopt=adopt)
            if state["changed"] or not state["ok"]:
                c.db.audit("goosesec.native", user=admin, target=admin["username"],
                           detail={"changed": state["changed"][:20], "foreign": state.get("foreign") or [],
                                   "adversary": state["adversary"],
                                   "error": state["error"][:300], "goose": state["goose"]}, ok=state["ok"])
            if state["changed"]:
                # Goose reads the classifier settings and adversary.md once per process (1.59; per chat in 1.57)
                w = c.workers.get(admin["username"].lower())
                if w is not None and w.state == "ready":
                    w.restart_pending = True
                log.info("goose security: native profile of %s updated (%s)", admin["username"],
                         "; ".join(state["changed"])[:300])
            if not state["ok"]:
                c.hub.broadcast_admins({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
                    "level": "warning", "kind": "goosesec",
                    "message": "Goose security settings could not be applied to the administrator's Goose profile "
                               f"({state['error'][:200]}). See Admin > Prompt guard."}})
            return state
        except Exception as e:
            log.exception("goose security: native sync")
            return {"ok": False, "error": f"{e.__class__.__name__}: {str(e)[:300]}", "changed": [], "at": time.time()}
