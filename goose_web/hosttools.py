"""Host tools (spec 035, 1.26.0): servers the gateway runs for sandboxed members, lent tool by tool.

A sandboxed member's agent cannot use an extension that needs something outside its sandbox - a credential the
administrator keeps in a password store, a service on the LAN, an index or a program on the host. A host tool is such
a server, run by the gateway OUTSIDE every member's sandbox under the gateway's own account (as the administrator's
own Goose runs it), and lent to the members of the teams that have it, with ONLY the tools the administrator lists:

  member's goose (MXC sandbox) --HTTP_PROXY--> member's egress proxy --> HostTools --stdio--> server (host process)

- Defined only in config.yaml (`host_tools.servers`): by whoever administers the machine, never from the web page.
  `from_extension: <key>` takes the command line and variables of the gateway administrator's own Goose extension.
- A member reaches host tool <name> at http://<name>.goose-web.invalid/mcp - a name that never resolves. The egress
  proxy never looks it up or forwards it: it hands the request to HostTools with the member its per-start credential
  belongs to (R1). No port of its own is opened.
- Every request is checked against the member's team at that moment (R2): the team has the item (kind `hosttool`),
  the account is enabled and not an administrator, the definition is valid.
- Deny by default (R3): `initialize` (answered from the gateway's own handshake with the server, tools capability
  only), `tools/list` filtered to the lent tools, `tools/call` of a lent tool (name and arguments only), `ping`,
  cancellations. Everything else is refused, `server/discover` with "method not found" (Goose 1.57 then uses
  `initialize` - measured 2026-11-20). Requests the server sends (sampling, roots, elicitation) get an error; its
  notifications are not passed on.
- One process per member and host tool (R4): a member's state is that member's; ids are remapped. Started at first
  use; stopped when unused for host_tools.idle_minutes, when the member loses it, and when the member's agent stops.
- A definition whose program, script, interpreter or path variable lies in a folder that broad groups (Everyone,
  Users, ...) can change - or below a folder they can rename or re-permission - is not started (R5): the gateway would
  run their code as its own account. Checked when definitions are read and again right before every start.
- Limits (R6): request body 1 MiB (60 s for all of it), one message from the server 8 MiB, time per call (`timeout`),
  calls per minute and at once, requests per minute, per member and host tool; counted across restarts of the server.
  Refusals are JSON-RPC errors with HTTP 200, never 401/403: Goose answers those with an OAuth sign-in attempt.
- Server I/O never blocks the gateway (review 2026-11-20, HT-1/HT-2): one writer thread per server with a bounded
  queue (a server that does not read for WRITE_DEADLINE is stopped), JSON parsed and answers encoded in the reader
  thread, and a stop kills the process before anything waits on its pipes.
- Every decision is in the activity log as `sandbox.hosttool` (member, host tool, tool, decision, duration) - never the
  arguments or the result; per member the first 30 of a minute one by one, the rest as one summary (HT-3).
"""
from __future__ import annotations

import asyncio
import collections
import itertools
import json
import logging
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("goose_web.hosttools")
IS_WINDOWS = sys.platform == "win32"

SUFFIX = "goose-web.invalid"
MCP_PATH = "/mcp"
NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?\Z")
TOOL_RE = re.compile(r"[A-Za-z0-9_.\-]{1,128}\Z")
ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
CLIENT_PROTOCOL = "2025-11-25"       # what the gateway asks a server for (what Goose 1.57 asks)
MAX_BODY = 1 << 20                   # a member's request body
MAX_LINE = 4 << 20                   # one message from a server; a larger one is dropped (R2-10)
BODY_DEADLINE = 60.0                 # for the whole request body
MAX_TRAILERS = 32
START_TIMEOUT = 60.0                 # one handshake request
START_DEADLINE = 120.0               # the whole start of a server (R2-11)
LOCK_WAIT = 150.0                    # waiting for another request's start of the same server
# Variables that steer an interpreter to other code: not passed on from the gateway's own environment (R2-2); a
# definition that sets one gets it checked like its program (program_problems)
_CODE_VARS = {"NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE",
              "PYTHONEXECUTABLE", "PYTHONINSPECT", "PERL5LIB", "PERL5OPT", "RUBYLIB", "RUBYOPT", "JAVA_TOOL_OPTIONS",
              "_JAVA_OPTIONS", "CLASSPATH", "UV_PYTHON", "VIRTUAL_ENV", "CONDA_PREFIX"}
_IDS = itertools.count(1)            # the server-side ids, unique in the gateway (R2-14)
WRITE_DEADLINE = 30.0                # a server that does not take a message for this long is stopped
WRITE_QUEUE = 64                     # messages waiting for one server; one more and the server is stopped
SESSIONS_PER_MEMBER = 32
REQUESTS_PER_MINUTE = 600            # every request of one member to one host tool
SWEEP_SECONDS = 60.0
SESSION_IDLE = 3600.0
# a lent tool with a parameter like these acts on what the caller names - on the HOST, for a host tool
RISKY_PARAM = re.compile(r"(?i)(path|file|dir|folder|url|uri|link|command|cmd|exec|script|shell|host|socket)")
METHOD_NOT_FOUND, INVALID_PARAMS, INVALID_REQUEST, REFUSED = -32601, -32602, -32600, -32001
_OWN = object()                      # a request of the gateway itself (handshake, tool list)


def host_name(host: str) -> str | None:
    """'wiki' for 'wiki.goose-web.invalid' (any case, trailing dot); '' for an invalid name under the suffix; None for
    any other host."""
    h = str(host or "").strip().rstrip(".").lower()
    if not h.endswith("." + SUFFIX):
        return None
    name = h[: -len(SUFFIX) - 1]
    return name if NAME_RE.match(name) else ""


def member_uri(name: str) -> str:
    return f"http://{name}.{SUFFIX}{MCP_PATH}"


# ------------------------------------------------------------------ definitions
@dataclass
class ServerDef:
    name: str
    command: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    tools: list[str] = field(default_factory=list)
    timeout: int = 300
    description: str = ""
    source: str = ""
    max_calls_per_minute: int = 60
    max_concurrent: int = 4
    problems: list[str] = field(default_factory=list)

    def describe(self) -> dict:
        return {"name": self.name, "description": self.description, "tools": list(self.tools), "timeout": self.timeout,
                "source": self.source, "program": self.command[0] if self.command else "",
                "arguments": len(self.command) - 1 if self.command else 0, "problems": list(self.problems),
                "uri": member_uri(self.name)}


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return n if lo <= n <= hi else default


def _reserved(name: str) -> bool:
    """A key profiles.py pins, restores or provisions itself (guarded and base extensions)."""
    from .policy import GUARDED_EXTENSIONS, ext_key
    from .profiles import BASE_EXTENSIONS
    return ext_key(name) in {ext_key(n) for n in [*GUARDED_EXTENSIONS, *BASE_EXTENSIONS, "developer", "scheduler"]}


_OWNERS_OK = {"S-1-5-18", "S-1-5-32-544",                     # SYSTEM, Administrators
               "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}   # TrustedInstaller
_ALLOW_TYPES = ("A", "OA", "XA", "ZA")        # conditional allow entries count as allow (second review R2-3)
# On a folder ABOVE the program: what lets someone swap the program's folder for one of their own - delete or rename
# a child, delete the folder itself, change its permissions or owner, full control. Creating a NEW sub-folder (which
# every account may do in the root of C:) is harmless there - except where Node looks for modules (below).
_ANCESTOR_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000
_ADD_SUBDIR = 0x4 | 0x40000000 | 0x10000000   # create a sub-folder: add subdirectory, generic write, generic all
_ME: list[str] = []


def _sddl(path: str) -> str:
    """The DACL of `path` as SDDL; OSError when it cannot be read (the callers then refuse: fail closed)."""
    from .__main__ import _path_sddl
    return _path_sddl(path)


def _broad(sddl: str, mask: int, *, this_object_only: bool) -> list[str]:
    from .__main__ import BROAD_PRINCIPALS, _sddl_mask
    dacl = sddl.split("D:", 1)[1].split("S:", 1)[0] if "D:" in sddl else ""
    out: list[str] = []
    for ace in re.findall(r"\(([^)]*)\)", dacl):
        parts = ace.split(";")
        if len(parts) < 6 or parts[0].upper() not in _ALLOW_TYPES:
            continue
        if this_object_only:
            flags = parts[1].upper()
            if "IO" in {flags[i:i + 2] for i in range(0, len(flags), 2)}:
                continue      # for the children only: they carry it themselves when they inherit (and are checked)
        who = BROAD_PRINCIPALS.get(parts[5].strip().upper())
        if who and _sddl_mask(parts[2].strip()) & mask and who not in out:
            out.append(who)
    return out


def writable_by_others(path: str) -> list[str]:
    """Broad groups (Everyone, Authenticated Users, Users, Interactive) that may write, delete or re-permission `path`
    or create files in it - for it or for its children (C-4's rule). OSError when it cannot be read."""
    if not IS_WINDOWS:
        import stat
        return ["others"] if os.stat(path).st_mode & stat.S_IWOTH else []
    from .__main__ import _WRITE_MASK
    return _broad(_sddl(path), _WRITE_MASK, this_object_only=False)


def ancestor_writers(path: str) -> list[str]:
    """Broad groups that may rename, delete or re-permission what is in the folder `path` (or the folder)."""
    return _broad(_sddl(path), _ANCESTOR_MASK, this_object_only=True) if IS_WINDOWS else []


def subfolder_creators(path: str) -> list[str]:
    """Broad groups that may create a new sub-folder in `path`."""
    return _broad(_sddl(path), _ADD_SUBDIR, this_object_only=True) if IS_WINDOWS else []


def foreign_owner(path: str) -> str:
    """'' when `path` belongs to SYSTEM, Administrators, TrustedInstaller or the gateway's own account; else who owns
    it - an owner may change the permissions at any time (second review R2-3). OSError when it cannot be read."""
    if not IS_WINDOWS:
        return ""
    from .winsec import current_user_sid, file_owner
    sid, name = file_owner(path)
    if not sid:
        raise OSError(f"the owner of {path} cannot be read")
    if not _ME:
        _ME.append(current_user_sid())
    return "" if sid in _OWNERS_OK or sid == _ME[0] else (name or sid)


def _program_paths(command: list[str], env: dict[str, str] | None = None) -> list[str]:
    """What the server's code comes from: the program, every argument that is an absolute path (also `--x=C:\\...`)
    and every absolute folder in a path-like variable of its environment (PYTHONPATH, NODE_PATH, PATH, ...)."""
    out = []
    for i, a in enumerate(command):
        a = str(a)
        for cand in (a, a.split("=", 1)[1] if "=" in a else ""):
            if cand and os.path.isabs(cand) and (i == 0 and cand == a or os.path.exists(cand)):
                out.append(cand)
    for v in (env or {}).values():
        for part in str(v).replace("{service_dir}", "").split(os.pathsep):
            if part and os.path.isabs(part) and os.path.exists(part):
                out.append(part)
    return list(dict.fromkeys(out))


def _above(path: str) -> list[str]:
    """Every folder above `path`, up to and including the root of its drive."""
    out, cur = [], path
    while True:
        parent = os.path.dirname(cur)
        if not parent or parent == cur:
            return out
        out.append(parent)
        cur = parent


def _is_node(command: list[str]) -> bool:
    return bool(command) and (os.path.basename(str(command[0])).lower() in ("node.exe", "node") or
                              any(str(a).lower().endswith((".js", ".mjs", ".cjs")) for a in command[1:]))


def program_problems(command: list[str], env: dict[str, str] | None = None) -> list[str]:
    """R5: why the gateway must not run this command as its own account ([] = nothing found). Permissions that
    cannot be read count as a reason (fail closed)."""
    if command and not os.path.exists(command[0]):
        return [f"the program {command[0]} does not exist"]
    try:
        return _program_problems(command, env)
    except OSError as e:
        return [f"permissions of the program's folders cannot be read ({str(e)[:160]})"]


def safe_path_entries(value: str, who: str = "") -> list[str]:
    """The PATH entries a host tool's server may search: existing absolute folders that no broad group can change, own
    or replace (second review R2-2: servers start programs and load DLLs by name). Missing, relative and unsafe
    entries are left out (missing ones could be created by others later); unsafe ones are logged."""
    out, dropped, cache = [], [], {}
    for entry in str(value or "").split(os.pathsep):
        e = entry.strip().strip('"')
        if not e or not os.path.isabs(e) or not os.path.isdir(e):
            continue
        try:
            bad = _folder_unsafe(e, cache)
        except OSError:
            bad = True
        (dropped if bad else out).append(e)
    if dropped:
        log.info("%s: PATH entries left out (other accounts can change or replace them): %s", who or "host tool",
                 "; ".join(dropped)[:600])
    return list(dict.fromkeys(out))


def _folder_unsafe(folder: str, cache: dict) -> bool:
    for f in dict.fromkeys([os.path.abspath(folder), os.path.realpath(folder)]):
        if writable_by_others(f) or foreign_owner(f):
            return True
        for anc in _above(f):
            if anc not in cache:
                cache[anc] = bool(ancestor_writers(anc) or foreign_owner(anc))
            if cache[anc]:
                return True
    return False


def _program_problems(command: list[str], env: dict[str, str] | None) -> list[str]:
    node = _is_node(command)
    seen: set[str] = set()
    above: set[str] = set()
    for path in _program_paths(command, env):
        for p in dict.fromkeys([os.path.abspath(path), os.path.realpath(path)]):      # as written and resolved
            if not os.path.exists(p):
                continue
            folder = p if os.path.isdir(p) else os.path.dirname(p)
            checks = [p, folder]
            if os.path.basename(p).lower().startswith("python") and not os.path.isdir(p):
                checks.append(os.path.dirname(folder))      # a Python reads pyvenv.cfg here too (R2-1)
            for t in checks:
                if not t or t in seen or not os.path.exists(t):
                    continue
                seen.add(t)
                who = writable_by_others(t)
                if who:
                    return [f"{t} can be changed by {', '.join(who)}: the gateway would run their code as its own "
                            "account - restrict that folder to administrators first"]
                owner = foreign_owner(t)
                if owner:
                    return [f"{t} belongs to {owner}, who may change its permissions at any time - let it belong to "
                            "administrators first"]
            for anc in _above(folder):
                if anc in above:
                    continue
                above.add(anc)
                who = ancestor_writers(anc)
                if who:
                    return [f"{anc} lets {', '.join(who)} rename or re-permission what is in it, so {folder} could be "
                            "replaced - restrict it to administrators first"]
                owner = foreign_owner(anc)
                if owner:
                    return [f"{anc} belongs to {owner}, who could replace {folder} - let it belong to administrators "
                            "first"]
                if node:              # Node looks for a module it does not find in every node_modules up to the root
                    nm = os.path.join(anc, "node_modules")
                    if os.path.isdir(nm):
                        who = writable_by_others(nm)
                        if who or foreign_owner(nm):
                            return [f"{nm} can be changed by {', '.join(who) or 'another account'}: a Node program "
                                    "below it could load their code"]
                    else:
                        who = subfolder_creators(anc)
                        if who:
                            return [f"Node looks for modules it does not find in {nm}, and {', '.join(who)} may "
                                    f"create that folder: create {nm} first, changeable by administrators only"]
    return []



def load_servers(settings: Any, admin_extensions: dict | None = None, *, acl: bool = True) -> dict[str, ServerDef]:
    """The host tools of config.yaml (`host_tools.servers`), each with the problems that keep it from being started
    or lent. `admin_extensions`: the gateway administrator's own Goose extensions (for `from_extension`)."""
    raw = settings.get("host_tools", "servers") or {}
    calls = _int(settings.get("host_tools", "max_calls_per_minute"), 60, 1, 10000)
    conc = _int(settings.get("host_tools", "max_concurrent"), 4, 1, 64)
    out: dict[str, ServerDef] = {}
    if not isinstance(raw, dict):
        log.error("host_tools.servers must be a mapping of names to definitions; no host tool is available")
        return out
    for name, d in raw.items():
        name = str(name)
        sd = ServerDef(name=name, max_calls_per_minute=calls, max_concurrent=conc)
        out[name] = sd
        p = sd.problems
        if not NAME_RE.match(name):
            p.append("the name must be 1-40 lower-case letters, digits or '-' (not at the start or end)")
        elif _reserved(name):
            p.append("the name of a Goose extension that Goose Web manages cannot be a host tool's name")
        if not isinstance(d, dict):
            p.append("the definition is not a mapping")
            continue
        tools = d.get("tools")
        if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and TOOL_RE.match(t) for t in tools):
            p.append("`tools` must list the tools members may use (names; the list is required and not empty)")
        else:
            sd.tools = list(dict.fromkeys(tools))
        entry: dict = {}
        if d.get("from_extension") and d.get("command"):
            p.append("give either `from_extension` or `command`, not both")
        elif d.get("from_extension"):
            key = str(d["from_extension"])
            entry = (admin_extensions or {}).get(key) if isinstance(admin_extensions, dict) else None
            sd.source = f"from_extension: {key}"
            if not isinstance(entry, dict):
                p.append(f"the administrator's Goose has no extension '{key}'")
                entry = {}
            elif str(entry.get("type") or "") != "stdio" or not entry.get("cmd"):
                p.append(f"the administrator's extension '{key}' is not a command (stdio) extension")
            else:
                args = entry.get("args") if isinstance(entry.get("args"), list) else []
                sd.command = [str(entry["cmd"]), *[str(a) for a in args]]
                envs = entry.get("envs") if isinstance(entry.get("envs"), dict) else {}
                sd.env.update({str(k): str(v) for k, v in envs.items()})
        elif d.get("command"):
            cmd = d["command"]
            sd.source = "command"
            if not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) for a in cmd):
                p.append("`command` must be a list: the program, then its arguments")
            else:
                sd.command = list(cmd)
        else:
            p.append("give `from_extension` (one of your own Goose extensions) or `command`")
        if sd.command and not os.path.isabs(sd.command[0]):
            p.append("the program must be given with its full path")
        env = d.get("env") or {}
        if not isinstance(env, dict) or not all(isinstance(k, str) and ENV_RE.match(k) and isinstance(v, (str, int))
                                                for k, v in env.items()):
            p.append("`env` must map variable names to text")
        else:
            sd.env.update({k: str(v) for k, v in env.items()})
        sd.timeout = _int(d.get("timeout", entry.get("timeout")), 300, 1, 3600)
        sd.description = str(d.get("description") or entry.get("description") or f"Host tool {name}")[:300]
        sd.max_calls_per_minute = _int(d.get("max_calls_per_minute"), calls, 1, 10000)
        sd.max_concurrent = _int(d.get("max_concurrent"), conc, 1, 64)
        if acl and sd.command and not p:
            p.extend(program_problems(sd.command, sd.env))
    return out


def admin_extensions_from_db(settings: Any) -> dict:
    """The gateway administrator's own Goose extensions, read through the database (for the command line)."""
    try:
        from .db import Database
        from .profiles import Profiles, _read_yaml
        dbp = settings.system_dir / "goose-web.db"
        if not dbp.exists():
            return {}
        db = Database(dbp)
        try:
            pr = Profiles(settings, db)
            admin = pr._native_admin()
            cfg = _read_yaml(pr.config_dir(admin) / "config.yaml") if admin else {}
            return (cfg.get("extensions") or {}) if isinstance(cfg, dict) else {}
        finally:
            db.close()
    except Exception:
        return {}


def check_lines(settings: Any) -> list[tuple[str, bool]]:
    """(text, good) per host tool for `goose-web check` and `sandbox status`."""
    if not settings.get("host_tools", "servers"):
        return []
    out = []
    for name, sd in sorted(load_servers(settings, admin_extensions_from_db(settings)).items()):
        if sd.problems:
            out.append((f"{name} is not available: {'; '.join(sd.problems)}", False))
        else:
            out.append((f"{name}: {len(sd.tools)} tool(s) lent ({sd.source}): {', '.join(sd.tools)[:200]} - runs "
                        "as this gateway's account outside the sandbox", True))
    return out


def member_entry(sd: ServerDef) -> dict:
    """The extension entry a member's profile gets for a host tool: an HTTP extension, nothing else."""
    return {"type": "streamable_http", "name": sd.name, "description": sd.description, "uri": member_uri(sd.name),
            "timeout": sd.timeout, "enabled": True, "bundled": False, "envs": {}, "env_keys": [], "headers": {},
            "available_tools": sorted(sd.tools)}


def risky_params(tool: dict) -> list[str]:
    schema = tool.get("inputSchema") if isinstance(tool, dict) else None
    props = schema.get("properties") if isinstance(schema, dict) else None
    return sorted(k for k in (props or {}) if isinstance(k, str) and RISKY_PARAM.search(k))


def _encode(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _err(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _resolve(fut: asyncio.Future, value: Any) -> None:
    if not fut.done():
        fut.set_result(value)


def _resume(proc: subprocess.Popen) -> None:
    """Resume a process created suspended (Windows)."""
    import ctypes
    from ctypes import wintypes
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    rc = ntdll.NtResumeProcess(int(proc._handle))  # type: ignore[attr-defined]
    if rc != 0:
        raise RuntimeError(f"the server could not be resumed (NTSTATUS 0x{rc & 0xFFFFFFFF:08X})")


# ------------------------------------------------------------------ one server process
class HostProcess:
    """One host tool's server for one member: a process of the gateway's account, outside the sandbox. Its pipes are
    served by two threads of its own; nothing on the event loop ever waits on them."""

    def __init__(self, sd: ServerDef, member: str, service_dir: Path, log_dir: Path, jobs: list):
        self.sd, self.member, self.service_dir, self.log_dir, self.jobs = sd, member, service_dir, log_dir, jobs
        self.proc: subprocess.Popen | None = None
        self.job: Any = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.init: dict = {}
        self.tools: list[dict] = []
        self.seq = 0
        self.started = 0.0
        self.last_used = time.monotonic()
        self.dead = False
        self.crashed = False            # ended by itself, not stopped by the gateway
        self.writing_since = 0.0        # when the write now in progress began (0 = none)
        self._lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._stopped = False
        self._expect: dict[str, tuple[asyncio.Future, Any]] = {}    # the server's id -> (future, member's id | _OWN)
        self._wq: queue.Queue = queue.Queue(maxsize=WRITE_QUEUE)
        self._refreshing: asyncio.Task | None = None

    # ---------------------------------------------------------- lifecycle
    def env(self) -> dict[str, str]:
        """The gateway's environment without Goose Web's own variables, secret-looking names and variables that steer
        an interpreter; PATH without folders other accounts can change (R2-2: servers start programs by name)."""
        from .winsec import secret_looking
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GOOSE_") and not secret_looking(k)
               and k.upper() not in _CODE_VARS}
        for k in [k for k in env if k.upper() == "PATH"]:
            env[k] = os.pathsep.join(safe_path_entries(env[k], f"host tool {self.sd.name}"))
        tmp = str(self.service_dir / "tmp")
        env.update({"TEMP": tmp, "TMP": tmp,
                    # CreateProcess and cmd do not look for programs in the working folder first (HT-7)
                    "NoDefaultCurrentDirectoryInExePath": "1"})
        for k, v in self.sd.env.items():
            env[k] = v.replace("{service_dir}", str(self.service_dir))
        return env

    def _spawn(self) -> None:
        """In a thread: the R5 check at the moment of the start (HT-6), folders, log, the process, its threads."""
        from .security import safe_name
        from .workers import _Job, open_append_log, rotate_log
        problems = program_problems(self.sd.command, self.sd.env)
        if problems:
            raise RuntimeError(problems[0])
        (self.service_dir / "tmp").mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        logp = self.log_dir / f"host-tool-{self.sd.name}-{safe_name(self.member.lower(), 64)}.log"
        rotate_log(logp)
        logf = open_append_log(logp)
        try:
            logf.write(f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start host tool {self.sd.name} for "
                       f"{self.member}\n".encode("utf-8", "replace"))
            # suspended until it is in its jobs: nothing it starts can be outside them (second review R2-6)
            self.proc = subprocess.Popen(self.sd.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=logf,
                                         cwd=str(self.service_dir), env=self.env(),
                                         creationflags=(0x08000000 | 0x00000200 | 0x00000004) if IS_WINDOWS else 0,
                                         start_new_session=not IS_WINDOWS)
        finally:
            logf.close()
        if IS_WINDOWS:
            try:
                for j in self.jobs:    # the gateway's kill-on-close job: the server dies with the gateway
                    if not j.add(self.proc):
                        raise RuntimeError("the server could not be put in the gateway's kill-on-close job")
                self.job = _Job()
                if not self.job.add(self.proc):
                    raise RuntimeError("the server could not be put in a kill-on-close job of its own")
                _resume(self.proc)
            except BaseException:
                try:
                    self.proc.kill()
                except Exception:
                    pass
                raise
        else:
            self.job = _Job()
        self.started = time.monotonic()
        pid = self.proc.pid
        threading.Thread(target=self._reader, name=f"hosttool-r-{self.sd.name}-{pid}", daemon=True).start()
        threading.Thread(target=self._writer, name=f"hosttool-w-{self.sd.name}-{pid}", daemon=True).start()

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        await asyncio.to_thread(self._spawn)
        r = await self.request("initialize", {"protocolVersion": CLIENT_PROTOCOL, "capabilities": {},
                                              "clientInfo": {"name": "goose-web-host-tools", "version": "1"}},
                               START_TIMEOUT)
        if "result" not in r or not isinstance(r["result"], dict):
            raise RuntimeError(f"the server refused initialize: {str(r.get('error'))[:300]}")
        self.init = r["result"]
        self._enqueue(_encode({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        await self.refresh_tools()

    async def refresh_tools(self) -> None:
        tools, cursor = [], None
        for _ in range(20):
            r = await self.request("tools/list", {"cursor": cursor} if cursor else {}, START_TIMEOUT)
            res = r.get("result") if isinstance(r.get("result"), dict) else {}
            tools += [t for t in res.get("tools") or [] if isinstance(t, dict) and isinstance(t.get("name"), str)]
            cursor = res.get("nextCursor")
            if not cursor:
                break
        self.tools = tools
        missing = sorted(set(self.sd.tools) - {t["name"] for t in tools})
        if missing:
            log.warning("host tool %s: lent tool(s) %s are not offered by the server", self.sd.name, missing)

    def alive(self) -> bool:
        return not self.dead and self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        """Ends the server at once. Kills first - a write blocked on its pipe then fails - and never waits on a pipe
        (HT-1). Runs once, whoever calls it (R2-4); the reader thread asks the event loop to call it."""
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
        self.dead = True
        self._fail_all("the host tool stopped")
        j, self.job = self.job, None
        if j is not None:
            for step in (j.terminate, j.close):
                try:
                    step()
                except Exception:
                    pass
        p = self.proc
        if p is not None and p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
        try:
            self._wq.put_nowait(None)    # the writer thread ends and closes the pipe itself
        except queue.Full:
            pass                         # it ends on the broken pipe

    def _fail_all(self, why: str) -> None:
        with self._lock:
            pend = list(self._expect.values())
            self._expect.clear()
        for fut, cid in pend:
            value = {"error": {"code": REFUSED, "message": why}} if cid is _OWN else (_encode(_err(cid, REFUSED, why)),
                                                                                      "error")
            if fut.get_loop() is _running_loop():
                _resolve(fut, value)
            else:
                self._post(_resolve, fut, value)

    # ---------------------------------------------------------- threads
    def _post(self, fn, *args) -> None:
        loop = self.loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:            # the loop is closed: the gateway is stopping
            pass

    def _writer(self) -> None:
        p = self.proc
        clean = False
        try:
            while True:
                data = self._wq.get()
                if data is None or p is None:
                    clean = True
                    break
                self.writing_since = time.monotonic()
                p.stdin.write(data)
                p.stdin.flush()
                self.writing_since = 0.0
        except (OSError, ValueError):
            pass
        finally:
            self.writing_since = 0.0
            try:
                p.stdin.close()
            except Exception:
                pass
            if not clean and not self.dead:     # R2-5: nobody writes to this server any more - it is finished
                self._post(self._on_exit)

    def _reader(self) -> None:
        p = self.proc
        try:
            while p is not None:
                line = p.stdout.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:           # dropped (its caller gets a time-out); the rest of it skipped
                    while line and not line.endswith(b"\n"):
                        line = p.stdout.readline(MAX_LINE + 1)
                    log.warning("host tool %s: a message larger than %d bytes was dropped", self.sd.name, MAX_LINE)
                    continue
                s = line.strip()
                if not s.startswith(b"{"):
                    continue
                try:
                    m = json.loads(s)
                    if isinstance(m, dict):
                        self._dispatch(m)
                except Exception:          # nesting too deep, an odd message: that message only (R2-10)
                    continue
        except (OSError, ValueError):
            pass
        finally:
            self._post(self._on_exit)

    def _dispatch(self, m: dict) -> None:
        """In the reader thread: answers are matched (and, for a member's call, encoded here, not on the loop)."""
        if "method" not in m:
            with self._lock:
                entry = self._expect.pop(str(m.get("id")), None)
            if entry is None:
                return
            fut, cid = entry
            if cid is _OWN:
                value: Any = m
            elif "result" in m:
                res = m["result"]
                value = (_encode({"jsonrpc": "2.0", "id": cid, "result": res}),
                         "error result" if isinstance(res, dict) and res.get("isError") else "")
            else:
                e = m.get("error") if isinstance(m.get("error"), dict) else {}
                code = e.get("code") if isinstance(e.get("code"), int) else -32603
                value = (_encode(_err(cid, code, str(e.get("message") or "error")[:2000])), "error")
            self._post(_resolve, fut, value)
            return
        method = str(m.get("method") or "")
        if "id" in m:                                   # the server asks something: never passed on (R3)
            res = {"jsonrpc": "2.0", "id": m["id"]}
            if method == "ping":
                res["result"] = {}
            else:
                res["error"] = {"code": METHOD_NOT_FOUND, "message": "not available through Goose Web host tools"}
            try:
                self._enqueue(_encode(res))
            except ConnectionError:
                pass
        elif method == "notifications/tools/list_changed":
            self._post(self._schedule_refresh)

    def _on_exit(self) -> None:
        if not self.dead:
            self.crashed = True
            log.warning("host tool %s for %s: the server ended", self.sd.name, self.member)
        self.dead = True
        self._fail_all("the host tool's server ended")

    def _schedule_refresh(self) -> None:
        if not self.dead and (self._refreshing is None or self._refreshing.done()):
            self._refreshing = asyncio.ensure_future(self._refresh_quietly())

    async def _refresh_quietly(self) -> None:
        try:
            await self.refresh_tools()
        except Exception as e:
            log.info("host tool %s: refreshing its tools failed: %s", self.sd.name, e.__class__.__name__)

    # ---------------------------------------------------------- messages
    def _enqueue(self, data: bytes) -> None:
        if self.dead:
            raise ConnectionError(f"host tool {self.sd.name}: the server has ended")
        try:
            self._wq.put_nowait(data + b"\n")
        except queue.Full:
            log.warning("host tool %s for %s: the server takes no messages; stopped", self.sd.name, self.member)
            self.dead = True
            if _running_loop() is self.loop:
                self.stop()
            else:                         # from the reader thread: the event loop stops it (R2-4)
                self._post(self.stop)
            raise ConnectionError(f"host tool {self.sd.name}: the server takes no messages") from None

    def next_id(self) -> str:
        self.seq += 1
        return f"gw-{next(_IDS)}"         # unique in the gateway: a stale id never names a newer request (R2-14)

    async def _exchange(self, rid: str, msg: dict, cid: Any, timeout: float) -> Any:
        fut = asyncio.get_running_loop().create_future()
        with self._lock:
            self._expect[rid] = (fut, cid)
        try:
            self._enqueue(_encode(msg))
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            try:
                self._enqueue(_encode({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                       "params": {"requestId": rid, "reason": "timed out"}}))
            except ConnectionError:
                pass
            raise
        finally:
            with self._lock:
                self._expect.pop(rid, None)

    async def request(self, method: str, params: dict, timeout: float) -> dict:
        rid = self.next_id()
        return await self._exchange(rid, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, _OWN,
                                    timeout)

    async def call(self, rid: str, params: dict, timeout: float, cid: Any) -> tuple[bytes, str]:
        """A member's tools/call under the server id `rid`: (the answer for the member, encoded, with the member's id
        `cid`; "" | "error result" | "error")."""
        return await self._exchange(rid, {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params}, cid,
                                    timeout)

    def cancel(self, rid: str) -> None:
        with self._lock:
            waiting = rid in self._expect
        if waiting:
            try:
                self._enqueue(_encode({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                       "params": {"requestId": rid}}))
            except ConnectionError:
                pass


# ------------------------------------------------------------------ the broker
@dataclass
class Session:
    sid: str
    member: str
    name: str
    last_used: float = field(default_factory=time.monotonic)
    inflight: dict = field(default_factory=dict)        # the member's request id (json) -> the server's id


class _TooLarge(Exception):
    pass


class HostTools:
    """The gateway's host tools: definitions, member sessions and server processes. One per gateway."""

    def __init__(self, settings: Any, db: Any, profiles: Any = None, jobs: list | None = None,
                 audit: Any = None):
        self.s, self.db, self.profiles = settings, db, profiles
        self.jobs = [j for j in (jobs or []) if j is not None]
        self._audit = audit or _activity_audit
        self.servers: dict[str, ServerDef] = {}
        self.procs: dict[tuple[str, str], HostProcess] = {}
        self.sessions: dict[str, Session] = {}
        self.known_tools: dict[str, list[dict]] = {}        # name -> the server's whole tool list (admin page)
        self.failures: dict[tuple[str, str], list[float]] = {}
        self.calls: dict[tuple[str, str], collections.deque] = {}       # HT-4: kept across restarts of the server
        self.requests: dict[tuple[str, str], collections.deque] = {}
        self.inflight: dict[tuple[str, str], int] = {}
        self.gen: dict[str, int] = {}                       # HT-10: a member's agent stopped -> +1
        self._limiters: dict[str, Any] = {}
        self._start_locks: dict[tuple[str, str], asyncio.Lock] = {}
        self.loop: asyncio.AbstractEventLoop | None = None
        self._sweeper: asyncio.Task | None = None
        self.loaded_at = 0.0
        self.reload()

    # ---------------------------------------------------------- definitions
    def admin_extensions(self) -> dict:
        p = self.profiles
        if p is None:
            return {}
        try:
            from .profiles import _read_yaml
            admin = p._native_admin()
            cfg = _read_yaml(p.config_dir(admin) / "config.yaml") if admin else {}
            return cfg.get("extensions") or {} if isinstance(cfg, dict) else {}
        except Exception:
            return {}

    def reload(self) -> None:
        try:
            servers = load_servers(self.s, self.admin_extensions())
        except Exception:
            log.exception("host tools: definitions could not be read")
            servers = {}
        old = {n: list(sd.problems) for n, sd in self.servers.items()}
        self.servers = servers
        self.loaded_at = time.monotonic()
        for sd in servers.values():
            if sd.problems and old.get(sd.name) != sd.problems:
                log.error("host tool %s is not available: %s", sd.name, "; ".join(sd.problems))

    def describe(self) -> list[dict]:
        out = []
        for name, sd in sorted(self.servers.items()):
            d = sd.describe()
            known = self.known_tools.get(name)
            if known is not None:
                d["serverTools"] = [{"name": t["name"], "lent": t["name"] in sd.tools, "risky": risky_params(t),
                                     "description": str(t.get("description") or "")[:300]} for t in known]
            d["running"] = sorted(m for (n, m), hp in self.procs.items() if n == name and hp.alive())
            out.append(d)
        return out

    # ---------------------------------------------------------- authorisation
    def allowed(self, member: str, name: str) -> tuple[ServerDef | None, str]:
        """(definition, "") when `member` may use host tool `name` now, else (None, why)."""
        sd = self.servers.get(name)
        if sd is None:
            return None, f"there is no host tool '{name}' on this gateway"
        if sd.problems:
            return None, f"the host tool '{name}' is not available (an administrator can see why in goose-web check)"
        u = self.db.user_by_name(member) if self.db is not None else None
        if not u or u.get("disabled"):
            return None, "this account is disabled"
        if u.get("role") == "admin":
            return None, "host tools are for sandboxed members"
        try:
            items = self.profiles.team_items(u) if self.profiles is not None else []
        except Exception:
            items = []
        if not any(i.get("kind") == "hosttool" and i.get("name") == name for i in items):
            return None, f"your team does not have the host tool '{name}'"
        return sd, ""

    # ---------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        if self._sweeper is None:
            self._sweeper = asyncio.create_task(self._sweep_loop())

    async def close(self) -> None:
        if self._sweeper is not None:
            self._sweeper.cancel()
            self._sweeper = None
        for key in list(self.procs):
            self._stop(key, "gateway stopping")
        self.sessions.clear()

    def _stop(self, key: tuple[str, str], why: str) -> None:
        hp = self.procs.pop(key, None)
        if hp is not None:
            log.info("host tool %s for %s stopped (%s)", key[0], key[1], why)
            hp.stop()

    def member_stopped(self, member: str) -> None:
        """The member's agent stopped (its proxy credential was revoked): its host-tool processes and sessions end,
        and a start that is under way is not kept (HT-10). May be called from any thread."""
        m = member.lower()

        def run() -> None:
            self.gen[m] = self.gen.get(m, 0) + 1
            for key in [k for k in self.procs if k[1] == m]:
                self._stop(key, "the member's agent stopped")
            for sid in [s for s, ss in self.sessions.items() if ss.member == m]:
                self.sessions.pop(sid, None)
        loop = self.loop
        if loop is None or loop.is_closed():
            return
        try:
            if _running_loop() is loop:       # on the gateway's event loop already
                run()
            else:                             # WorkerManager._kill runs in a thread
                loop.call_soon_threadsafe(run)
        except RuntimeError:
            pass

    async def sweep(self) -> None:
        """Stop processes that are unused, withdrawn, dead or stuck on a write; forget old sessions and counters;
        re-read the definitions (the administrator's extension may have changed)."""
        idle = max(1.0, float(self.s.get("host_tools", "idle_minutes") or 10)) * 60
        now = time.monotonic()
        if now - self.loaded_at > SWEEP_SECONDS:
            await asyncio.to_thread(self.reload)
        for key, hp in list(self.procs.items()):
            name, member = key
            if not hp.alive():
                if hp.crashed:                  # counts toward the start back-off, also when the sweep finds it
                    self.failures.setdefault(key, []).append(now)
                self._stop(key, "ended")
            elif hp.writing_since and now - hp.writing_since > WRITE_DEADLINE:
                self._stop(key, f"it took no message for {int(WRITE_DEADLINE)} s")
            elif self.inflight.get(key, 0) == 0 and now - hp.last_used > idle:
                self._stop(key, "unused")
            elif self.allowed(member, name)[0] is None:
                self._stop(key, "no longer lent to this member")
        for sid, ss in list(self.sessions.items()):
            if now - ss.last_used > max(idle, SESSION_IDLE):
                self.sessions.pop(sid, None)
        for d in (self.calls, self.requests):
            for key, q in list(d.items()):
                while q and now - q[0] > 60:
                    q.popleft()
                if not q and key not in self.procs:
                    del d[key]

    async def _sweep_loop(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_SECONDS)
            try:
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("host tools: sweep")

    async def process(self, sd: ServerDef, member: str, gen: int | None = None) -> HostProcess:
        """The member's running server for `sd`, started if needed. `gen`: the member's stop generation when the
        request arrived (R2-8) - a start for a request older than the member's last stop is not kept."""
        m = member.lower()
        key = (sd.name, m)
        if gen is None:
            gen = self.gen.get(m, 0)
        hp = self.procs.get(key)
        if hp is not None and hp.alive():
            return hp
        lock = self._start_locks.setdefault(key, asyncio.Lock())
        try:
            await asyncio.wait_for(lock.acquire(), LOCK_WAIT)          # R2-11
        except asyncio.TimeoutError:
            raise RuntimeError("the host tool is still starting; try again in a moment") from None
        try:
            hp = self.procs.get(key)
            if hp is not None and hp.alive():
                return hp
            now = time.monotonic()
            fails = [t for t in self.failures.get(key, []) if now - t < 120]
            if hp is not None:
                if hp.crashed:                  # HT-4: a server that ended by itself counts like a failed start
                    fails.append(now)
                self._stop(key, "ended")
            self.failures[key] = fails
            if len(fails) >= 3:
                raise RuntimeError("the host tool failed three times in two minutes; try again later (an "
                                   f"administrator finds its log as host-tool-{sd.name}-<member>.log)")
            if self.gen.get(m, 0) != gen:
                raise RuntimeError("the member's agent stopped")
            from .security import safe_name
            hp = HostProcess(sd, member, self.s.system_dir / "host-tools" / sd.name / safe_name(m, 64),
                             self.s.system_dir / "logs", self.jobs)
            try:
                await asyncio.wait_for(hp.start(), START_DEADLINE)
            except Exception as e:
                hp.stop()
                self.failures[key] = fails + [time.monotonic()]
                log.error("host tool %s for %s did not start: %s", sd.name, member, e)
                raise RuntimeError(f"the host tool did not start ({e.__class__.__name__}: {str(e)[:200]})") from e
            except BaseException:               # cancelled (gateway stopping): nothing is left running (R2-7)
                hp.stop()
                raise
            if self.gen.get(m, 0) != gen:       # HT-10: the member's agent stopped while this one started
                hp.stop()
                raise RuntimeError("the member's agent stopped")
            self.procs[key] = hp
            self.known_tools[sd.name] = [t for t in hp.tools if TOOL_RE.match(str(t.get("name")))][:500]
            log.info("host tool %s for %s started (pid %s, %d tools, %d lent)", sd.name, member, hp.proc.pid,
                     len(hp.tools), len([t for t in hp.tools if t["name"] in sd.tools]))
            return hp
        finally:
            lock.release()

    # ---------------------------------------------------------- HTTP (from the member's egress proxy)
    async def handle(self, member: str, name: str, method: str, target: str, headers: dict, reader, writer) -> None:
        """One HTTP request of `member` (authenticated by the egress proxy) to http://<name>.goose-web.invalid/..."""
        gen = self.gen.get(member.lower(), 0)     # before anything slow: a stop after this point wins (R2-8)
        path = urlsplit(target).path or "/"
        if path.rstrip("/") != MCP_PATH:
            await _respond(writer, 404, {"error": "not_found", "message": f"host tools answer at {MCP_PATH}"},
                           reader=reader)
            return
        if method == "GET":
            await _respond(writer, 405, None, {"Allow": "POST, DELETE"}, reader=reader)
            return
        if method == "DELETE":
            ss = self.sessions.get(_header(headers, b"mcp-session-id"))
            if ss is not None and ss.member == member.lower() and ss.name == name:
                self.sessions.pop(ss.sid, None)
                await _respond(writer, 200, None, reader=reader)
            else:
                await _respond(writer, 404, None, reader=reader)
            return
        if method != "POST":
            await _respond(writer, 405, None, {"Allow": "POST, DELETE"}, reader=reader)
            return
        try:
            body = await asyncio.wait_for(_read_body(reader, headers), BODY_DEADLINE)
        except _TooLarge:
            await _respond(writer, 413, _err(None, INVALID_REQUEST, "request too large"), reader=reader)
            return
        except (ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError,
                ConnectionError):
            await _respond(writer, 400, _err(None, INVALID_REQUEST, "unreadable request body"), reader=reader)
            return
        try:
            msg = json.loads(body or b"null")
        except ValueError:
            await _respond(writer, 400, _err(None, -32700, "not JSON"))
            return
        if not isinstance(msg, dict):
            await _respond(writer, 400, _err(None, INVALID_REQUEST, "one JSON-RPC message per request (no batches)"))
            return
        status, payload, extra = await self.message(member, name, msg, _header(headers, b"mcp-session-id"), gen)
        await _respond(writer, status, payload, extra)

    def _over(self, d: dict, key: tuple[str, str], limit: int, now: float) -> bool:
        q = d.setdefault(key, collections.deque())
        while q and now - q[0] > 60:
            q.popleft()
        return len(q) >= limit

    async def message(self, member: str, name: str, msg: dict, sid: str,
                      gen: int | None = None) -> tuple[int, Any, dict]:
        """(HTTP status, JSON-RPC answer (dict or encoded) or None, extra headers) for one message of a member."""
        method = msg.get("method")
        has_id = "id" in msg and msg.get("id") is not None
        rid = msg.get("id")
        m = member.lower()
        key = (name, m)
        if gen is None:
            gen = self.gen.get(m, 0)
        if not isinstance(method, str):
            return 202, None, {}                                   # a response or nonsense: nothing to do
        if name not in self.servers:      # R2-9: no counters, sessions or database lookups for names nobody defined
            if has_id:
                self._record(member, name, method, "refused", "no such host tool")
                return 200, _err(rid, REFUSED, f"there is no host tool '{name}' on this gateway"), {}
            return 202, None, {}
        now = time.monotonic()
        if self._over(self.requests, key, REQUESTS_PER_MINUTE, now):     # HT-3: every request counts
            self._record(member, name, method, "refused", "too many requests")
            return (200, _err(rid, REFUSED, f"too many requests to {name} in the last minute"), {}) if has_id \
                else (202, None, {})
        self.requests[key].append(now)
        if not has_id:                                             # notifications
            if method == "notifications/cancelled":
                ss = self.sessions.get(sid)
                if ss is not None and ss.member == m and ss.name == name and self.allowed(member, name)[0]:
                    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                    srv = ss.inflight.get(json.dumps(params.get("requestId")))
                    hp = self.procs.get(key)
                    if srv and hp is not None:
                        hp.cancel(srv)
            return 202, None, {}
        if method == "server/discover":
            return 200, _err(rid, METHOD_NOT_FOUND, "Method not found: server/discover"), {}
        sd, why = self.allowed(member, name)
        if sd is None:
            self._record(member, name, method, "refused", why)
            return 200, _err(rid, REFUSED, why), {}
        if method == "initialize":
            try:
                hp = await self.process(sd, member, gen)
            except RuntimeError as e:
                self._record(member, name, method, "failed", str(e))
                return 200, _err(rid, REFUSED, str(e)), {}
            ss = self._new_session(member, name)
            res = {"protocolVersion": hp.init.get("protocolVersion") or CLIENT_PROTOCOL,
                   "capabilities": {"tools": {}},
                   "serverInfo": hp.init.get("serverInfo") if isinstance(hp.init.get("serverInfo"), dict)
                   else {"name": name, "version": "?"}}
            if isinstance(hp.init.get("instructions"), str):
                res["instructions"] = hp.init["instructions"][:8000]
            self._record(member, name, "initialize", "allowed")
            return 200, {"jsonrpc": "2.0", "id": rid, "result": res}, {"Mcp-Session-Id": ss.sid}
        ss = self.sessions.get(sid)
        if ss is None or ss.member != m or ss.name != name:
            return 404, _err(rid, REFUSED, "Session not found"), {}
        ss.last_used = now
        if method == "ping":
            return 200, {"jsonrpc": "2.0", "id": rid, "result": {}}, {}
        if method == "tools/list":
            try:
                hp = await self.process(sd, member, gen)
            except RuntimeError as e:
                return 200, _err(rid, REFUSED, str(e)), {}
            return 200, {"jsonrpc": "2.0", "id": rid,
                         "result": {"tools": [t for t in hp.tools if t["name"] in sd.tools]}}, {}
        if method == "tools/call":
            return 200, await self._call(sd, member, ss, rid, msg.get("params"), gen), {}
        self._record(member, name, method, "refused", "not available")
        return 200, _err(rid, METHOD_NOT_FOUND, f"{method} is not available through Goose Web host tools"), {}

    async def _call(self, sd: ServerDef, member: str, ss: Session, rid: Any, params: Any, gen: int | None = None) -> Any:
        params = params if isinstance(params, dict) else {}
        tool = params.get("name")
        label = str(tool)[:128] if isinstance(tool, str) else "?"
        if not isinstance(tool, str) or tool not in sd.tools:
            self._record(member, sd.name, label, "refused", "not lent")
            return _err(rid, INVALID_PARAMS, f"the tool '{label}' is not lent to members (host tool {sd.name})")
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return _err(rid, INVALID_PARAMS, "arguments must be an object")
        key = (sd.name, member.lower())
        now = time.monotonic()
        if self._over(self.calls, key, sd.max_calls_per_minute, now):
            self._record(member, sd.name, tool, "refused", "rate limit")
            return _err(rid, REFUSED, f"too many calls to {sd.name} in the last minute; wait a moment")
        if self.inflight.get(key, 0) >= sd.max_concurrent:
            self._record(member, sd.name, tool, "refused", "busy")
            return _err(rid, REFUSED, f"{sd.name} is already running {self.inflight[key]} calls for you; wait for "
                                      "them")
        try:
            hp = await self.process(sd, member, gen)
        except RuntimeError as e:
            self._record(member, sd.name, tool, "failed", str(e))
            return _err(rid, REFUSED, str(e))
        self.calls[key].append(now)
        self.inflight[key] = self.inflight.get(key, 0) + 1
        hp.last_used = now
        srv = hp.next_id()
        ikey = json.dumps(rid)
        ss.inflight[ikey] = srv
        t0 = time.monotonic()
        try:
            # HT-5: name and arguments only - nothing of the member's _meta (and no progress token) reaches the server
            answer, kind = await hp.call(srv, {"name": tool, "arguments": args}, sd.timeout, rid)
        except asyncio.TimeoutError:
            self._record(member, sd.name, tool, "failed", "timed out", t0)
            return _err(rid, REFUSED, f"{sd.name}: {tool} did not answer within {sd.timeout} s")
        except ConnectionError:
            self._record(member, sd.name, tool, "failed", "server not available", t0)
            return _err(rid, REFUSED, f"{sd.name}: the server is not available")
        finally:
            self.inflight[key] = max(0, self.inflight.get(key, 1) - 1)
            hp.last_used = time.monotonic()
            ss.inflight.pop(ikey, None)
        self._record(member, sd.name, tool, "allowed", kind, t0)
        return answer

    def _new_session(self, member: str, name: str) -> Session:
        m = member.lower()
        mine = sorted((s for s in self.sessions.values() if s.member == m), key=lambda s: s.last_used)
        for s in mine[: max(0, len(mine) - SESSIONS_PER_MEMBER + 1)]:
            self.sessions.pop(s.sid, None)
        ss = Session(sid=secrets.token_urlsafe(24), member=m, name=name)
        self.sessions[ss.sid] = ss
        return ss

    def _limiter(self, member: str):
        lim = self._limiters.get(member.lower())
        if lim is None:
            from .egress import _AuditLimiter

            def summary(total: int, items: list[dict], who: str = member) -> None:
                try:
                    self._audit(who, "(summary)", {"decision": "summary", "count": total, "items": items[:20]})
                except Exception:
                    pass
            lim = self._limiters[member.lower()] = _AuditLimiter(summary)
        return lim

    def _record(self, member: str, name: str, what: str, decision: str, reason: str = "", t0: float = 0.0) -> None:
        from .activity import clean_text
        target = clean_text(f"{name}:{what}", 200)
        try:
            if not self._limiter(member).allow(target, decision):
                return
        except Exception:
            pass
        detail: dict[str, Any] = {"decision": decision}
        if reason:
            detail["reason"] = clean_text(reason, 200)
        if t0:
            detail["ms"] = int((time.monotonic() - t0) * 1000)
        try:
            self._audit(member, target, detail)
        except Exception:
            pass


def _running_loop():
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _activity_audit(member: str, target: str, detail: dict) -> None:
    from . import activity
    activity.record("sandbox.hosttool", username=member, target=target, detail=detail,
                    ok=detail.get("decision") in ("allowed", "summary"))


def _header(headers: dict, name: bytes) -> str:
    v = headers.get(name, b"") if isinstance(headers, dict) else b""
    return v.decode("latin-1", "replace").strip() if isinstance(v, bytes) else str(v or "").strip()


async def _read_body(reader, headers: dict) -> bytes:
    te = headers.get(b"transfer-encoding", b"").strip().lower()
    cl = headers.get(b"content-length")
    if te and cl is not None:
        raise ValueError("both Transfer-Encoding and Content-Length")
    if te:
        if te != b"chunked":
            raise ValueError("unsupported transfer encoding")
        out = bytearray()
        while True:
            line = await reader.readline()
            size = int(line.split(b";", 1)[0].strip() or b"x", 16)
            if size < 0:
                raise ValueError("bad chunk")
            if size == 0:
                for _ in range(MAX_TRAILERS):
                    if (await reader.readline()) in (b"\r\n", b"\n", b""):
                        return bytes(out)
                raise ValueError("too many trailer lines")
            if len(out) + size > MAX_BODY:
                raise _TooLarge()
            out += await reader.readexactly(size)
            await reader.readexactly(2)
    n = int(cl.strip()) if cl is not None and cl.strip() else 0
    if n < 0:
        raise ValueError("bad Content-Length")
    if n > MAX_BODY:
        raise _TooLarge()
    return await reader.readexactly(n) if n else b""


async def _respond(writer, status: int, payload: Any, headers: dict | None = None, reader=None) -> None:
    """Answer and close. With `reader` (an answer before the body was read): a lingering close, as the egress proxy's
    own answers do - closing a socket with unread input makes Windows reset it, and the client would lose the answer."""
    reasons = {200: "OK", 202: "Accepted", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
               413: "Payload Too Large"}
    body = b"" if payload is None else payload if isinstance(payload, bytes) else _encode(payload)
    lines = [f"HTTP/1.1 {status} {reasons.get(status, 'Error')}", "Cache-Control: no-store"]
    if payload is not None:
        lines.append("Content-Type: application/json")
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    lines += [f"Content-Length: {len(body)}", "Connection: close"]
    try:
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        await asyncio.wait_for(writer.drain(), 30)
        if reader is not None:
            if writer.can_write_eof():
                writer.write_eof()
            end, got = time.monotonic() + 1.0, 0
            while got < 256 * 1024 and time.monotonic() < end:
                chunk = await asyncio.wait_for(reader.read(65536), max(0.05, end - time.monotonic()))
                if not chunk:
                    break
                got += len(chunk)
    except (ConnectionError, OSError, asyncio.TimeoutError, RuntimeError, ValueError):
        pass
