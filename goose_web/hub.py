"""The hub: one persistent ACP connection per profile, shared by every browser tab of that profile.

Goose cancels a run when its ACP connection drops. The hub therefore owns the upstream connection, and
browsers only attach to it and detach from it. Closing the tab never stops an agent (the "herd" model).

Responsibilities:
* id rewriting between many browser sockets and one upstream socket
* routing session notifications to the sockets watching that session
* per-session transcript buffers, so a reload or a second device can replay a live session without
  disturbing it
* agent->client requests (permissions, elicitations, recipe parameters): broadcast to every tab, first
  answer wins, replayed to tabs that connect later
* herd state per session: working / needs_you / done / idle / error
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import websockets

from . import __version__
from . import guard as guardmod
from . import policy as pol
from .workers import Worker, WorkerManager

log = logging.getLogger("goose_web.hub")

SESSION_BUFFER_BYTES = 12 * 1024 * 1024
TOTAL_BUFFER_BYTES = 256 * 1024 * 1024
AGENT_REQUESTS = {"session/request_permission", "elicitation/create", "_goose/unstable/session/recipe/request-params"}
SESSION_NOTIFICATIONS = {"session/update", "_goose/unstable/session/update"}
RPC_FORBIDDEN = -32003
SESSION_INFO = "_goose/unstable/session/info"
WATCH_INTERVAL = 2.0          # seconds between stat() calls on the profile's sessions.db (+ -wal)
WATCH_FALLBACK_INTERVAL = 15.0  # no sessions.db found: fingerprint-check watched sessions this often
WATCH_MAX_CHECKS = 40         # idle buffered sessions re-checked per change
# Methods that never change the stored session (no fingerprint refresh needed afterwards).
_READ_ONLY_SESSION_METHODS = {"session/load", "session/list", SESSION_INFO, "session/prompt", "session/cancel"}
TRUNCATE = "_goose/unstable/session/conversation/truncate"
SYSTEM_PROMPT_SET = "_goose/unstable/session/system-prompt/set"
MIN_GOOSE = (1, 50)        # oldest Goose version goose-web is tested with (every release 1.50.0 - 1.57.0)
# First Goose version with each feature Goose Web adapts to, measured against every release binary 1.50.0-1.57.0
# (`goose acp` probes; ADMINISTRATION 11.7). Everything else Goose Web uses behaves the same in all of them.
FEATURE_SINCE = {
    "toolCallScoped": (1, 51),           # tools/call honours extensionName (1.50 resolves the name across the chat)
    "toolshim": (1, 51),                 # custom provider "toolshim" field
    "liveVoice": (1, 52),                # _goose/unstable/session/live-voice/*
    "importWithoutSource": (1, 54),      # session/import without "source" (1.50-1.53 require it)
    "persistentSystemPrompt": (1, 55),   # session/system-prompt/set survives a worker restart
    "compactTokenLimit": (1, 55),        # GOOSE_AUTO_COMPACT_TOKEN_LIMIT and the 225k default cap
}
MODERN_GOOSE = max(FEATURE_SINCE.values())   # every feature above


def parse_version(v: Any) -> tuple[int, ...]:
    """'1.57.0', 'v1.50.1' or 'goose 1.50.1' -> (1, 57, 0); no version -> ()."""
    m = re.search(r"\d+(?:\.\d+)*", str(v or ""))
    out = []
    for part in (m.group(0) if m else "").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        out.append(int(digits))
    return tuple(out)


def goose_caps(init_result: dict | None) -> dict:
    """Feature flags of the connected Goose, from initialize.agentInfo.version (FEATURE_SINCE). Unknown version =
    assume the current feature set."""
    ver = ((init_result or {}).get("agentInfo") or {}).get("version") or ""
    v = parse_version(ver)
    caps = {k: (not v or v >= since) for k, since in FEATURE_SINCE.items()}
    caps.update(version=ver, supported=not v or v >= MIN_GOOSE, importNeedsSource=not caps["importWithoutSource"])
    return caps


# Everyday chat activity recorded per user (spec 015, Hub.audit_activity).
STEER = "_goose/unstable/session/steer"
CHAT_ACTIVITY = {"session/new": "chat.new", "session/load": "chat.open", "session/prompt": "chat.prompt",
                 "session/cancel": "chat.cancel", "session/fork": "chat.fork", "session/set_mode": "chat.mode",
                 STEER: "chat.steer"}
# Composer queue kept by the gateway per chat (spec 019): survives a refresh, another device and a restart.
QUEUE_MAX_ITEMS = 20
QUEUE_ITEM_BYTES = 9 * 1024 * 1024   # an inline image is at most 8 MB (composer.js)
QUEUE_MAX_SESSIONS = 200             # chats with a non-empty queue per profile
MARK_STATUSES = ("working", "needs_you", "done", "error")   # herd states kept in the database (spec 019)
MARK_MAX_AGE = 30 * 86400
QUEUE_RESTORED = "Kept across a Goose Web restart. Send it when you are ready."
# Why a steer Goose accepted was never read by the agent (bug steer-lost-on-slow-turn). Goose injects a steer only
# at the agent's next step (after the model's reply or a tool call) and drops what is still waiting when the run ends.
STEER_RETURNED = {
    "cancelled": "You stopped the run before the agent's next step, so it never read this steer.",
    "ended": "The run ended before the agent's next step, so it never read this steer.",
    "error": "The run failed before the agent's next step, so it never read this steer.",
}

EXT_ADD = "_goose/unstable/session/extensions/add"
EXT_REMOVE = "_goose/unstable/session/extensions/remove"
# Recipes the gateway resolves and checks before Goose runs them (B-1, security assessment 2026-11-09).
P_CFG_EXT_LIST = "_goose/unstable/config/extensions/list"
P_RECIPE_DECODE = "_goose/unstable/recipes/decode"
P_RECIPE_LIST = "_goose/unstable/recipes/list"
P_RECIPE_SCHEDULE = "_goose/unstable/recipes/schedule"
P_SCHEDULE_CREATE = "_goose/unstable/schedules/create"
P_SCHEDULE_UPDATE = "_goose/unstable/schedules/update"
P_SESSION_IMPORT = "_goose/unstable/session/import"
RECIPE_METHODS = {"session/new", P_RECIPE_SCHEDULE, P_SCHEDULE_CREATE, P_SCHEDULE_UPDATE, P_SESSION_IMPORT}
# Tool calls the model makes that start extensions or agents, audited when the hub forwards them (B-4).
AGENT_TOOL_AUDIT = {"manage_extensions": "agent.extension", "delegate": "agent.delegate",
                    "manage_schedule": "agent.schedule"}


def agent_tool_event(update: dict) -> tuple[str, dict] | None:
    """(audit action, detail) for a `tool_call` session update whose tool starts extensions, sub-agents or
    schedules (extensionmanager__manage_extensions, summon's delegate, scheduler__manage_schedule); else None."""
    if not isinstance(update, dict):
        return None
    goose = ((update.get("_meta") or {}).get("goose") or {}) if isinstance(update.get("_meta"), dict) else {}
    tc = goose.get("toolCall") if isinstance(goose.get("toolCall"), dict) else {}
    # the title is "<tool> · <argument preview>" or "<extension>: <tool words>": only the head names the tool
    cands = [str(tc.get("toolName") or ""), str(update.get("title") or "").split("\u00b7", 1)[0][:120]]
    action = None
    for c in cands:
        short = c.split("__", 1)[-1].split(" ", 1)[0].split(":", 1)[0].strip().lower()
        flat = "".join(ch for ch in c.lower() if ch.isalnum())
        for tool, act in AGENT_TOOL_AUDIT.items():
            if short == tool or tool.replace("_", "") in flat:
                action = act
                break
        if action:
            break
    if action is None:
        return None
    args = update.get("rawInput") if isinstance(update.get("rawInput"), dict) else {}
    detail: dict = {"tool": (cands[0] or cands[1])[:200]}
    if tc.get("extensionName"):
        detail["extension"] = str(tc["extensionName"])[:100]
    if action == "agent.extension":
        detail.update(action=str(args.get("action") or "")[:20], extensionName=str(args.get("extension_name") or "")[:100])
    elif action == "agent.delegate":
        detail.update(source=str(args.get("source") or "")[:200],
                      extensions=[str(x)[:100] for x in args.get("extensions") or []][:30]
                      if isinstance(args.get("extensions"), list) else None)
    else:
        detail.update({k: str(args.get(k))[:200] for k in ("action", "recipe_path", "recipe", "job_id") if k in args})
    return action, detail


def _ext_norm(name: Any) -> str:
    return "".join(ch for ch in str(name or "").lower() if ch.isalnum())


def _ext_names(ext: Any) -> list[str]:
    """Every name Goose may report an extension config under (builtin: name; MCP: server name / config key)."""
    if not isinstance(ext, dict):
        return []
    cands = [ext.get("name"), ext.get("key"), ext.get("configKey")]
    if isinstance(ext.get("server"), dict):
        cands.append(ext["server"].get("name"))
    return [str(c) for c in cands if c]


def apply_extension_change(load_result: dict | None, method: str, params: dict, msg: dict) -> bool:
    """Keep the cached start-up `_meta.extensionResults` in step with a later add/remove in the same chat.

    The cached load result is replayed to every tab that reconnects (7.3). Without this, an extension that failed
    at start and was started later with Retry showed as failed again after every reload. Returns True if changed."""
    meta = (load_result or {}).get("_meta")
    if not isinstance(meta, dict) or not isinstance(meta.get("extensionResults"), list):
        return False
    ok = "error" not in msg
    if method == EXT_REMOVE:
        raw = [str(params.get("extensionKey") or "")] if ok else []
    else:
        raw = _ext_names(params.get("extension"))
    keys = {_ext_norm(n) for n in raw} - {""}
    if not keys:
        return False
    results = list(meta["extensionResults"])
    hit = next((i for i, r in enumerate(results) if isinstance(r, dict) and _ext_norm(r.get("name")) in keys), None)
    if method == EXT_REMOVE:
        if hit is None:
            return False
        results.pop(hit)
    else:
        name = results[hit].get("name") if hit is not None else raw[0]
        if ok:
            entry = {"name": name, "success": True}
        else:
            entry = {"name": name, "success": False,
                     "error": str((msg.get("error") or {}).get("message") or "failed to start")}
        if hit is None:
            results.append(entry)
        else:
            results[hit] = entry
    load_result["_meta"] = {**meta, "extensionResults": results}
    return True


INIT_PARAMS = {
    "protocolVersion": 1,
    "clientCapabilities": {
        "elicitation": {"form": {}},
        "_meta": {"goose": {
            "mcpHostCapabilities": {"extensions": {"io.modelcontextprotocol/ui": {
                "mimeTypes": ["text/html;profile=mcp-app"]}}},
            "customNotifications": True,
            "recipeParameterRequests": True,
        }},
    },
    "clientInfo": {"name": "goose-web", "version": __version__},
}


def same_content(a: tuple | None, b: tuple | None) -> bool:
    """Fingerprints (messageCount, updatedAt, title): the transcript is unchanged if the message count is.
    Falls back to updatedAt when Goose does not report a count. Titles are metadata, not content."""
    if a is None or b is None:
        return False
    if a[0] is not None and b[0] is not None:
        return a[0] == b[0]
    return a[1] == b[1]


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.data = code, message, data

    def to_json(self) -> dict:
        e = {"code": self.code, "message": self.message}
        if self.data is not None:
            e["data"] = self.data
        return e


@dataclass
class SessionState:
    sid: str
    title: str = ""
    cwd: str = ""
    status: str = "idle"
    since: float = field(default_factory=time.time)
    run_id: str | None = None
    last_text: str = ""
    usage: dict = field(default_factory=dict)
    buffer: deque = field(default_factory=deque)
    buffer_bytes: int = 0
    truncated: bool = False
    loaded: bool = False
    load_result: dict | None = None
    loading_client: Any = None
    prompts: int = 0
    last_touch: float = field(default_factory=time.time)
    error: str = ""
    # (messageCount, updatedAt) from Goose when the buffer was known to match the session store. Another
    # process (Goose Desktop, the CLI, a schedule) writing the same session changes it -> the buffer is stale.
    fp: tuple | None = None
    fp_pending: bool = False
    sys_prompts: dict = field(default_factory=dict)   # (mode, key) -> override; re-sent after a load on Goose < 1.55
    # Steers sent to the active run that the agent has not read yet: {id, messageId, runId, blocks, by, at, state}
    # with state "sending" (no answer from Goose yet) or "pending" (accepted, waiting for the agent's next step).
    steers: list = field(default_factory=list)
    cancel_requested: bool = False   # a session/cancel passed since the last prompt (why undelivered steers came back)
    steer_seen: deque = field(default_factory=lambda: deque(maxlen=50))   # steer message ids already in the stream
    # The composer queue (spec 019): [{id, blocks, by, at, held?, steer?, note?}]. A tab sends the first item that is
    # not held when the run ends; returned steers come back held (the user decides). Persisted per profile.
    queue: list = field(default_factory=list)

    def running(self) -> bool:
        return self.prompts > 0 or bool(self.run_id) or self.status in ("working", "needs_you")


class Client:
    """One browser socket (or API client)."""

    def __init__(self, send: Callable[[str], Any], user: dict, policy: dict, roots: list[str], ip: str = ""):
        self._send = send
        self.user = user
        self.policy = policy
        self.roots = roots
        self.ip = ip
        self.is_admin = user.get("role") == "admin"
        self.watch: set[str] = set()
        self.herd_all = False
        self.closed = False
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=20000)
        self.task: asyncio.Task | None = None

    def start(self) -> None:
        self.task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        try:
            while True:
                msg = await self.queue.get()
                await self._send(msg)
        except Exception:
            self.closed = True

    def send(self, obj: dict | str) -> None:
        if self.closed:
            return
        try:
            self.queue.put_nowait(obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":")))
        except asyncio.QueueFull:  # a stuck tab must not stall the agent; drop it
            self.closed = True
            if self.task:
                self.task.cancel()

    def close(self) -> None:
        self.closed = True
        if self.task:
            self.task.cancel()


class Upstream:
    def __init__(self, hub: "Hub", key: str, username: str):
        self.hub = hub
        self.key = key
        self.username = username
        self.clients: set[Client] = set()
        self.ws = None
        self.state = "down"
        self.init_result: dict | None = None
        self._next = 0
        self.pending: dict[int, tuple] = {}
        self.asks: dict[str, dict] = {}
        self.sessions: dict[str, SessionState] = {}
        self._connect_lock = asyncio.Lock()
        self._reader: asyncio.Task | None = None
        self._herd_dirty: set[str] = set()
        self._watcher: asyncio.Task | None = None
        self._bg: set[asyncio.Task] = set()
        # spec 018: toolCallId -> (toolName, extensionName) from tool_call notifications, for permission requests
        # (which carry only a title); bounded, filled only while some prompt guard is in use
        self.tool_meta: OrderedDict[str, tuple[str, str]] = OrderedDict()

    # ------------------------------------------------------------ connection
    @property
    def worker(self) -> Worker:
        return self.hub.workers.workers[self.key]

    async def ensure(self) -> None:
        if self.state == "ready" and self.ws is not None:
            return
        async with self._connect_lock:
            if self.state == "ready" and self.ws is not None:
                return
            self.state = "starting"
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/upstream", "params": {"state": "starting"}})
            try:
                w = await self.hub.workers.ensure(self.key)
                if w.transport == "stdio":
                    # Sandboxed worker (spec 012): one ACP connection per process, over its stdin/stdout.
                    if w.channel is None or w.channel.claimed:
                        await self.hub.workers.stop(self.key, "(new connection)")
                        w = await self.hub.workers.ensure(self.key)
                    w.channel.claimed = True
                    self.ws = w.channel
                else:
                    self.ws = await websockets.connect(w.url, additional_headers={"X-Secret-Key": w.secret},
                                                       max_size=64 * 1024 * 1024, ping_interval=20, ping_timeout=60,
                                                       open_timeout=20, compression=None)
                self._reader = asyncio.create_task(self._read_loop(self.ws))
                self.state = "ready"
                self.init_result = await self.request("initialize", INIT_PARAMS, timeout=60)
            except Exception as e:
                self.state = "down"
                err = str(e) or e.__class__.__name__
                self.broadcast({"jsonrpc": "2.0", "method": "_gw/upstream", "params": {"state": "down", "error": err}})
                if self.ws is not None:
                    await self.ws.close()
                    self.ws = None
                raise RpcError(-32000, f"Goose is not available: {err}") from e
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/upstream", "params": {"state": "ready"}})
            if self._watcher is None or self._watcher.done():
                self._watcher = asyncio.create_task(self._watch_loop())

    async def reset(self, reason: str) -> None:
        """Called when the worker restarts: drop the old connection, fail everything in flight."""
        ws, self.ws = self.ws, None
        self.state = "down"
        if self._reader:
            self._reader.cancel()
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        self._fail_all(reason)

    def _fail_all(self, reason: str) -> None:
        pending, self.pending = self.pending, {}
        for up_id, entry in pending.items():
            client, cid, fut = entry[0], entry[1], entry[2]
            if fut is not None and not fut.done():
                fut.set_exception(RpcError(-32000, reason))
            elif client is not None:
                client.send({"jsonrpc": "2.0", "id": cid, "error": {"code": -32000, "message": reason}})
        for aid, ask in list(self.asks.items()):
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/ask_resolved",
                            "params": {"id": ask["msg"]["id"], "sessionId": ask["sessionId"], "by": "worker-restart"}})
        self.asks.clear()
        for s in self.sessions.values():
            if s.steers:
                # "sending" steers just failed above (the tab queues them itself); accepted ones come back here
                s.steers = [e for e in s.steers if e["state"] == "pending"]
                self._return_steers(s, "error")
            if s.running():
                self._set_status(s, "error", error=reason)
            s.prompts, s.run_id, s.loaded, s.load_result = 0, None, False, None
            s.buffer.clear()
            s.buffer_bytes = 0
        self.broadcast({"jsonrpc": "2.0", "method": "_gw/upstream", "params": {"state": "down", "error": reason}})

    async def _read_loop(self, ws) -> None:
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                try:
                    self._dispatch(msg, raw if isinstance(raw, str) else raw.decode("utf-8", "replace"))
                except Exception:
                    log.exception("dispatch error for %s", self.key)
        except websockets.ConnectionClosed:
            pass
        except asyncio.CancelledError:
            return
        except Exception:
            log.exception("upstream reader %s", self.key)
        if self.ws is ws:
            self.ws = None
            self.state = "down"
            self._fail_all("the Goose worker connection closed")

    async def _send(self, obj: dict) -> None:
        if self.ws is None:
            raise RpcError(-32000, "Goose is not connected")
        await self.ws.send(json.dumps(obj, separators=(",", ":")))

    # ------------------------------------------------------------ requests
    def _new_id(self) -> int:
        self._next += 1
        return self._next

    async def request(self, method: str, params: dict | None = None, timeout: float | None = 120) -> Any:
        """Gateway-internal request."""
        if method != "initialize":
            await self.ensure()
        up_id = self._new_id()
        fut = asyncio.get_running_loop().create_future()
        self.pending[up_id] = (None, None, fut, method, params or {})
        try:
            await self._send({"jsonrpc": "2.0", "id": up_id, "method": method, "params": params or {}})
            return await asyncio.wait_for(fut, timeout) if timeout else await fut
        finally:
            self.pending.pop(up_id, None)

    def sess(self, sid: str) -> SessionState:
        s = self.sessions.get(sid)
        if s is None:
            s = self.sessions[sid] = SessionState(sid=sid)
        s.last_touch = time.time()
        return s

    async def from_client(self, client: Client, msg: dict) -> None:
        """A frame from a browser socket."""
        method = msg.get("method")
        mid = msg.get("id")
        if method is None:
            if mid is not None:
                await self._answer_ask(client, msg)
            return
        if method.startswith("_gw/"):
            await self.hub.gw_method(self, client, msg)
            return
        params = msg.get("params")
        if params is None:
            params = {}
        try:
            pol.check(method, params, is_admin=client.is_admin, policy=client.policy, roots=client.roots)
            if method in RECIPE_METHODS:
                await self._guard_recipes(client, method, params)
            if method in CHAT_ACTIVITY:
                self.hub.audit_activity(client, self, method, params)
            if method == "initialize":
                await self.ensure()
                return self._reply(client, mid, self.init_result)
            if method == "_goose/unstable/recipes/delete" and not client.is_admin:
                await self._guard_recipe_delete(params)
            if method == TRUNCATE:
                # Goose deletes every message with created >= truncateFrom and does not check for an active run.
                s0 = self.sessions.get(str(params.get("sessionId") or ""))
                if s0 is not None and (s0.running() or s0.prompts):
                    raise RpcError(-32002, "this chat is running: stop it before editing a message")
                if type(params.get("truncateFrom")) is not int or params["truncateFrom"] <= 0:   # bool is an int
                    raise RpcError(-32602, "truncateFrom must be a positive unix time in seconds")
            if method in (pol.TOOLS_CALL, "_goose/unstable/session/import") \
                    or method.startswith("_goose/unstable/session/live-voice/"):
                await self.ensure()   # the checks below depend on the worker's Goose version
            if method == pol.TOOLS_CALL and params.get("extensionName"):
                await self._check_tool_owner(params)
            if method.startswith("_goose/unstable/session/live-voice/") and not self.caps()["liveVoice"]:
                raise RpcError(-32601, f"live voice needs Goose 1.52 or later (this worker runs Goose "
                                       f"{self.caps()['version'] or '?'})")
            if method == "_goose/unstable/session/import" and self.caps()["importNeedsSource"] and "source" not in params:
                params["source"] = "json"
            if method == "session/prompt":
                self._check_concurrency(client, params)
                if not client.is_admin:
                    s0 = self.sessions.get(str(params.get("sessionId") or ""))
                    pol.check_session_choice(client.policy, s0.load_result if s0 else None)
                if self.hub.guard is not None and await self._guard_prompt(client, mid, params):
                    return
            elif method == STEER and self.hub.guard is not None:
                # a steer becomes a user message of the run: the same prompt guard applies (it was not checked < 1.15)
                if await self._guard_prompt(client, mid, params, steer=True):
                    return
            await self.ensure()
            if method == "session/load":
                sid = str(params.get("sessionId") or "")
                s = self.sess(sid)
                # Live in this worker: replay from the buffer (never reload a running session upstream).
                if s.loaded and s.running():
                    self._replay(client, s, mid)
                    return
                # Idle: the buffer is only good while nobody else (Goose Desktop, the CLI, a schedule) has
                # written the session since. Compare the stored fingerprint with Goose's current one.
                if s.loaded and s.load_result is not None and not s.truncated and s.fp is not None \
                        and not s.fp_pending:
                    fp = await self._fingerprint(sid)
                    if fp is not None and same_content(fp, s.fp) and not s.running():
                        self._replay(client, s, mid)
                        return
                self.hub.total_buffer -= s.buffer_bytes
                s.buffer.clear()
                s.buffer_bytes, s.truncated, s.fp = 0, False, None
                s.loading_client = client
                s.cwd = str(params.get("cwd") or s.cwd)
        except pol.Denied as e:
            self.hub.audit_denied(client, method, str(e))
            if mid is not None:
                client.send({"jsonrpc": "2.0", "id": mid, "error": {"code": RPC_FORBIDDEN, "message": f"forbidden: {e}"}})
            return
        except RpcError as e:
            if mid is not None:
                client.send({"jsonrpc": "2.0", "id": mid, "error": e.to_json()})
            return
        if method == "session/cancel":
            s0 = self.sessions.get(str(params.get("sessionId") or ""))
            if s0 is not None:
                s0.cancel_requested = True
        elif method == STEER and mid is not None and isinstance(params.get("prompt"), list):
            # Goose answers at once ("accepted"), but the agent reads a steer only at its next step. Track it until
            # its user message appears in the stream (delivered) or the run ends (returned to the user's queue).
            s0 = self.sess(str(params.get("sessionId") or ""))
            s0.steers.append({"id": "s" + os.urandom(6).hex(), "messageId": None,
                              "runId": str(params.get("expectedRunId") or ""), "blocks": params["prompt"],
                              "by": client.user.get("username"), "at": time.time(), "state": "sending"})
        if method == "session/prompt":
            s = self.sess(str(params.get("sessionId") or ""))
            s.prompts += 1
            s.cancel_requested = False
            s.loaded = True
            client.watch.add(s.sid)
            s.last_text = ""
            self._set_status(s, "working")
            # Goose does not echo live prompts back, so record them for other tabs and for later replays.
            # Stamp them with this machine's clock (Goose stamps the stored message a moment later with the same
            # clock), so a tab can later edit the prompt: conversation/truncate cuts at created >= truncateFrom.
            created = int(time.time())
            client.send({"jsonrpc": "2.0", "method": "_gw/prompt_created",
                         "params": {"sessionId": s.sid, "created": created}})
            for block in params.get("prompt") or []:
                echo = json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": s.sid, "update": {"sessionUpdate": "user_message_chunk", "content": block,
                                                   "_meta": {"gw": {"synthetic": True,
                                                                    "by": client.user.get("username")},
                                                             "goose": {"created": created}}}}},
                                  separators=(",", ":"))
                self._buffer(s, echo)
                for c in list(self.clients):
                    if c is not client and s.sid in c.watch:
                        c.send(echo)
        self.hub.audit_call(client, self, method, params)
        if mid is None:  # notification (e.g. session/cancel)
            await self._send({"jsonrpc": "2.0", "method": method, "params": params})
            return
        up_id = self._new_id()
        self.pending[up_id] = (client, mid, None, method, params)
        try:
            await self._send({"jsonrpc": "2.0", "id": up_id, "method": method, "params": params})
        except RpcError as e:
            self.pending.pop(up_id, None)
            if method == STEER:   # never reached Goose: the tab queues it instead
                s0 = self.sessions.get(str(params.get("sessionId") or ""))
                if s0 is not None:
                    s0.steers = [x for x in s0.steers if x["blocks"] is not params.get("prompt")]
            client.send({"jsonrpc": "2.0", "id": mid, "error": e.to_json()})

    def _reply(self, client: Client, mid: Any, result: Any) -> None:
        if mid is not None:
            client.send({"jsonrpc": "2.0", "id": mid, "result": result})

    def caps(self) -> dict:
        return goose_caps(self.init_result)

    async def _check_tool_owner(self, params: dict) -> None:
        """Run a direct tool call only if the tool belongs to the extension it names. Goose 1.57 enforces this
        itself; Goose 1.50 ignores extensionName and resolves the name across all of the session's tools."""
        ext, name = str(params.get("extensionName") or ""), str(params.get("name") or "")
        res = await self.request("_goose/unstable/tools/list",
                                 {"sessionId": str(params.get("sessionId") or ""), "extensionName": ext}, timeout=30)
        names = {str(t.get("name") or "") for t in (res or {}).get("tools") or [] if isinstance(t, dict)}
        short = name.split("__", 1)[1] if "__" in name and name.split("__", 1)[0].lower() == ext.lower() else name
        if not ({name, short, f"{ext}__{short}"} & names):
            raise pol.Denied(f"tool '{name[:200]}' does not belong to extension '{ext[:200]}'")

    async def _resend_sys_prompt(self, s: SessionState) -> None:
        """Goose < 1.55 does not persist a session's system-prompt overrides: apply them again after a load."""
        for p in list(s.sys_prompts.values()):
            try:
                await self.request(SYSTEM_PROMPT_SET, dict(p, sessionId=s.sid), timeout=30)
            except Exception as e:  # the chat still works, only without the override
                log.warning("re-applying the system prompt of %s failed: %s", s.sid, e)

    def _check_concurrency(self, client: Client, params: dict) -> None:
        limit = int(client.policy.get("max_concurrent_runs") or 0)
        if client.is_admin or not limit:
            return
        sid = str(params.get("sessionId") or "")
        running = sum(1 for s in self.sessions.values() if s.running() and s.sid != sid)
        if running >= limit:
            raise pol.Denied(f"you already have {running} agents running (limit {limit})")

    # ------------------------------------------------------------ prompt guard (spec 018)
    async def _guard_prompt(self, client: Client, mid: Any, params: dict, steer: bool = False) -> bool:
        """Check a prompt against the typing user's guard. True = refused (the reply is sent here); False = go on.
        Administrators: an Auto chat bypasses; a Smart approve chat is refused while the admin guard is on (its
        read-only skip would hide tool calls from the guard)."""
        ctx = self.hub.guard_ctx(client.user.get("username") or "")
        if ctx is None:
            return False
        sid = str(params.get("sessionId") or "")
        s0 = self.sessions.get(sid)
        mode = guardmod.session_mode(s0.load_result if s0 else None)
        if ctx.kind == "admin":
            if mode == "auto":
                return False
            if mode == "smart_approve":
                raise pol.Denied("the prompt guard for administrators is on: use Approve (guarded) or Auto (not "
                                 "guarded) for this chat; Smart approve would skip tools the guard must see")
        d = await self.hub.guard.check_prompt(ctx, params)
        if not d.blocked:
            return False
        self.hub.audit_guard(self, sid, ctx, d, mode=mode, actor=client)
        if ctx.on_block == "silent" and not steer:   # a steer has no stop reason: it is always refused openly
            self._reply(client, mid, {"stopReason": "refusal"})
        elif mid is not None:
            why = f"rule {d.rule} ({d.ruleset})" if d.rule else "prompt-injection classifier"
            client.send({"jsonrpc": "2.0", "id": mid, "error": {
                "code": RPC_FORBIDDEN, "message": f"forbidden: the prompt guard blocked this message ({why}). "
                                                  f"{d.message}".strip()}})
        return True

    def _remember_tool(self, u: dict) -> None:
        tid = str(u.get("toolCallId") or "")
        goose = ((u.get("_meta") or {}).get("goose") or {}) if isinstance(u.get("_meta"), dict) else {}
        tc = goose.get("toolCall") if isinstance(goose.get("toolCall"), dict) else {}
        if tid and tc.get("toolName"):
            self.tool_meta[tid] = (str(tc["toolName"]), str(tc.get("extensionName") or ""))
            self.tool_meta.move_to_end(tid)
            while len(self.tool_meta) > 1000:
                self.tool_meta.popitem(last=False)

    async def _guarded_permission(self, msg: dict, raw: str, ctx: Any) -> None:
        """A tool-permission request of a guarded profile: block (the gateway answers reject_once), auto-allow
        (guarded auto: allow_once) or show the card without 'always allow'. Fails open to the normal card."""
        params = msg.get("params") or {}
        sid = str(params.get("sessionId") or "")
        tc = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        tool, ext = guardmod.tool_identity(tc, self.tool_meta.get(str(tc.get("toolCallId") or "")))
        try:
            d = await self.hub.guard.check_tool(ctx, tool, ext, tc.get("rawInput"))
        except Exception:
            log.exception("prompt guard tool check")
            d = guardmod.Decision(False, "tool", classifier="unavailable")
        answer = None
        if d.blocked:
            answer = "reject_once"
        elif ctx.auto_approve and ctx.kind == "team":
            answer = "allow_once"
        if answer:
            try:
                await self._send({"jsonrpc": "2.0", "id": msg["id"],
                                  "result": {"outcome": {"outcome": "selected", "optionId": answer}}})
            except RpcError:
                return
            if d.blocked:
                s = self.sessions.get(sid)
                self.hub.audit_guard(self, sid, ctx, d, tool=tool, ext=ext,
                                     mode=guardmod.session_mode(s.load_result if s else None))
                if ctx.on_block == "notify":
                    note = {"jsonrpc": "2.0", "method": "_gw/notice", "params": {
                        "level": "warning", "sessionId": sid, "kind": "guard",
                        "message": f"The prompt guard blocked a call to {tool[:120]}"
                                   + (f" (rule {d.rule})" if d.rule else " (prompt-injection classifier)")
                                   + (f": {d.message}" if d.message else ".")}}
                    for c in list(self.clients):
                        if sid in c.watch or not sid:
                            c.send(note)
            return
        opts = params.get("options")
        if isinstance(opts, list):
            keep = [o for o in opts if not (isinstance(o, dict) and
                                            (o.get("kind") == "allow_always" or o.get("optionId") == "allow_always"))]
            msg = {**msg, "params": {**params, "options": keep}}
            raw = json.dumps(msg, separators=(",", ":"))
        self._register_ask(msg, raw, guarded=True)

    def _register_ask(self, msg: dict, raw: str, guarded: bool = False) -> None:
        method = msg.get("method")
        params = msg.get("params") or {}
        sid = params.get("sessionId") or ""
        self.asks[json.dumps(msg["id"])] = {"msg": msg, "sessionId": sid, "ts": time.time(), "guarded": guarded}
        if sid:
            s = self.sess(sid)
            tc = params.get("toolCall") or {}
            s.last_text = (f"Needs approval: {tc.get('title')}" if method == "session/request_permission"
                           else str(params.get("message") or "Needs your input"))[:300]
            self._set_status(s, "needs_you")
        self.broadcast(raw)
        self.hub.notify_event(self, sid, "needs_you")

    # ------------------------------------------------------------ recipes (B-1)
    async def _guard_recipes(self, client: Client, method: str, params: dict) -> None:
        """Resolve every recipe a call would run and check it before Goose sees the call (security assessment
        2026-11-09, B-1): Goose starts recipe.extensions (a stdio entry is any command line) on session/new with
        `_meta.recipeId` / `recipeDeeplink`, on a scheduled run, and keeps an imported session's recipe. Members:
        pol.check_recipe against their enabled extensions, sub-recipes recursively; anything that cannot be
        resolved is refused (fail closed). Admins: never refused, but every recipe use is audited (B-4)."""
        found = await self._resolve_recipes(client, method, params)
        choose = method == "session/new" and not client.is_admin and \
            (params.get("_meta") or {}).get("enabledExtensions") is not None
        if not found and not choose:
            return
        enabled = configured = None
        if not client.is_admin:
            try:
                listing = await self.request(P_CFG_EXT_LIST, {}, timeout=30)
            except Exception as e:
                raise pol.Denied(f"your extensions could not be read to check the recipe ({e})")
            enabled = pol.enabled_extension_map(listing)
            configured = pol.enabled_extension_map(listing, only_enabled=False)
        for recipe, via, base in found:
            names = pol.recipe_extension_names(recipe)
            if client.is_admin:
                self.hub.audit_recipe(client, self, method, recipe, via, names, True)
                continue
            try:
                if recipe is None:
                    raise pol.Denied("the recipe could not be found or read, so it cannot be checked")
                pol.check_recipe(recipe, client.policy, enabled or {})
                await asyncio.to_thread(self._check_sub_recipes, recipe, client.policy, enabled or {}, base, 0, [0])
            except pol.Denied:
                self.hub.audit_recipe(client, self, method, recipe, via, names, False)
                raise
            self.hub.audit_recipe(client, self, method, recipe, via, names, True)
        if choose:
            pol.check_enabled_extensions(params["_meta"]["enabledExtensions"], client.policy, configured)

    async def _resolve_recipes(self, client: Client, method: str, params: dict) -> list[tuple]:
        """[(recipe dict or None if unresolvable, via, base folder for relative sub-recipe paths)]."""
        out: list[tuple] = []
        cwd = str(params.get("cwd") or "")
        if method == "session/new":
            meta = params.get("_meta") or {}
            if meta.get("recipeDeeplink"):
                try:
                    res = await self.request(P_RECIPE_DECODE, {"deeplink": str(meta["recipeDeeplink"])}, timeout=30)
                    recipe = (res or {}).get("recipe")
                except Exception:
                    recipe = None
                out.append((recipe if isinstance(recipe, dict) else None, "deeplink", cwd))
            if meta.get("recipeId"):
                out.append(await self._recipe_by_id(str(meta["recipeId"])))
        elif method in (P_SCHEDULE_CREATE, P_SCHEDULE_UPDATE) and "recipe" in params:
            recipe = params.get("recipe")
            out.append((recipe if isinstance(recipe, dict) else None, "schedule", ""))
        elif method == P_RECIPE_SCHEDULE and params.get("cron_schedule"):
            out.append(await self._recipe_by_id(str(params.get("id") or "")))
        elif method == P_SESSION_IMPORT:
            try:
                data = json.loads(str(params.get("input") or ""))
            except ValueError:
                data = None
            recipe = data.get("recipe") if isinstance(data, dict) else None
            if isinstance(recipe, dict):
                out.append((recipe, "import", ""))
        return out

    async def _recipe_by_id(self, rid: str) -> tuple:
        try:
            res = await self.request(P_RECIPE_LIST, {}, timeout=60)
        except Exception:
            return (None, "recipeId", "")
        for r in (res or {}).get("recipes") or []:
            if isinstance(r, dict) and str(r.get("id")) == rid and isinstance(r.get("recipe"), dict):
                fp = str(r.get("file_path") or "")
                fp = fp[4:] if fp.startswith("\\\\?\\") else fp
                return (r["recipe"], "recipeId", os.path.dirname(fp))
        return (None, "recipeId", "")

    def _check_sub_recipes(self, recipe: dict, policy: dict, enabled: dict, base: str, depth: int,
                           count: list) -> None:
        """Every sub-recipe file must be readable and pass check_recipe too (members; fail closed)."""
        for sr in recipe.get("sub_recipes") or []:
            count[0] += 1
            if depth >= 5 or count[0] > 50:
                raise pol.Denied("the recipe nests too many sub-recipes to check")
            path = str((sr or {}).get("path") or "") if isinstance(sr, dict) else ""
            if not path or "\x00" in path:
                raise pol.Denied("a sub-recipe of this recipe has no readable path")
            p = path if os.path.isabs(path) else os.path.join(base or "", path)
            try:
                import yaml
                data = yaml.safe_load(Path(p).read_text(encoding="utf-8"))
            except Exception:
                raise pol.Denied(f"the sub-recipe '{path[:120]}' cannot be read, so it cannot be checked")
            if isinstance(data, dict) and isinstance(data.get("recipe"), dict) and "title" not in data:
                data = data["recipe"]
            pol.check_recipe(data, policy, enabled, what="the sub-recipe")
            self._check_sub_recipes(data, policy, enabled, os.path.dirname(p), depth + 1, count)

    async def _guard_recipe_delete(self, params: dict) -> None:
        res = await self.request("_goose/unstable/recipes/list", {})
        root = self.hub.profile_root_for(self.username)
        for r in (res or {}).get("recipes") or []:
            if r.get("id") == params.get("id"):
                if not pol.path_allowed(str(r.get("file_path") or ""), [root]):
                    raise pol.Denied("team recipes are managed by your administrator")
                return

    # ------------------------------------------------------------ external changes
    async def _fingerprint(self, sid: str) -> tuple | None:
        """(messageCount, updatedAt) as Goose has them stored now; None if unknown."""
        try:
            res = await self.request(SESSION_INFO, {"sessionId": sid}, timeout=10)
        except Exception:
            return None
        info = (res or {}).get("session") or {}
        meta = info.get("_meta") or {}
        if not info:
            return None
        return (meta.get("messageCount"), info.get("updatedAt"), info.get("title"))

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self._bg.add(t)
        t.add_done_callback(self._bg.discard)

    def _refresh_fp_soon(self, s: SessionState) -> None:
        """The buffer now matches Goose: remember Goose's fingerprint (async, one cheap DB read)."""
        s.fp_pending = True

        async def run():
            try:
                s.fp = await self._fingerprint(s.sid)
            finally:
                s.fp_pending = False
        self._spawn(run())

    def _invalidate(self, s: SessionState) -> None:
        self.hub.total_buffer -= s.buffer_bytes
        s.buffer.clear()
        s.buffer_bytes, s.truncated = 0, False
        s.loaded, s.load_result, s.fp = False, None, None

    def _db_paths(self) -> list[Path]:
        from .config import default_native_goose_root
        try:
            root = Path(self.worker.path_root or default_native_goose_root())
        except Exception:
            return []
        d = root / "data" / "sessions"
        return [d / "sessions.db", d / "sessions.db-wal"]

    @staticmethod
    def _db_sig(paths: list[Path]) -> tuple | None:
        sig = []
        for p in paths:
            try:
                st = os.stat(p)
                sig.append((st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append(None)
        return tuple(sig) if sig and sig[0] is not None else None

    async def _watch_loop(self) -> None:
        """Notice sessions written by another process (stat() only; Goose's files are never opened)."""
        paths = self._db_paths()
        last = self._db_sig(paths)
        last_fallback = time.monotonic()
        while True:
            try:
                await asyncio.sleep(WATCH_INTERVAL)
                if self.state != "ready" or not self.clients:
                    last = self._db_sig(paths)
                    continue
                sig = self._db_sig(paths)
                if sig is None:
                    if time.monotonic() - last_fallback < WATCH_FALLBACK_INTERVAL:
                        continue
                    last_fallback = time.monotonic()
                    watched = {sid for c in self.clients for sid in c.watch}
                    await self.check_external(only=watched, announce_list=False)
                    continue
                if sig == last:
                    continue
                last = sig
                await self.check_external()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("session watcher %s", self.key)

    async def check_external(self, only: set[str] | None = None, announce_list: bool = True) -> list[str]:
        """Re-check idle buffered sessions against Goose; drop stale buffers and tell the browsers."""
        if announce_list:
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/sessions_changed", "params": {}})
        cands = [s for s in self.sessions.values()
                 if s.loaded and s.fp is not None and not s.fp_pending and not s.running()
                 and (only is None or s.sid in only)]
        cands.sort(key=lambda s: -s.last_touch)
        cands = cands[:WATCH_MAX_CHECKS]
        if not cands:
            return []
        fps = await asyncio.gather(*[self._fingerprint(s.sid) for s in cands])
        changed = []
        for s, fp in zip(cands, fps):
            if fp is None or s.running() or s.fp_pending or s.loading_client is not None:
                continue
            if fp[2] and fp[2] != s.title:   # renamed (auto-naming, or elsewhere): metadata only
                s.title = fp[2]
                self._herd_changed(s)
            if same_content(fp, s.fp):
                continue
            old = s.fp
            self._invalidate(s)
            changed.append(s.sid)
            log.info("session %s changed outside this worker (%s -> %s)", s.sid, old, fp)
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/session_changed",
                            "params": {"sessionId": s.sid, "messageCount": fp[0], "updatedAt": fp[1],
                                       "title": fp[2]}})
        return changed

    def _replay(self, client: Client, s: SessionState, mid: Any) -> None:
        for raw in list(s.buffer):
            client.send(raw)
        result = dict(s.load_result or {})
        meta = dict(result.get("_meta") or {})
        meta["gw"] = {"replayed": True, "running": s.running(), "truncated": s.truncated}
        result["_meta"] = meta
        self._reply(client, mid, result)
        client.watch.add(s.sid)

    async def _answer_ask(self, client: Client, msg: dict) -> None:
        key = json.dumps(msg.get("id"))
        ask = self.asks.pop(key, None)
        if ask is None:
            client.send({"jsonrpc": "2.0", "method": "_gw/ask_resolved",
                         "params": {"id": msg.get("id"), "sessionId": None, "by": "already-answered"}})
            return
        out = {"jsonrpc": "2.0", "id": ask["msg"]["id"]}
        if "error" in msg:
            out["error"] = msg["error"]
        else:
            out["result"] = msg.get("result")
            res = out["result"] if isinstance(out["result"], dict) else {}
            oc = res.get("outcome") if isinstance(res.get("outcome"), dict) else {}
            if ask.get("guarded") and oc.get("optionId") == "allow_always":
                # spec 018: a guarded profile never persists "always allow" (Goose would stop asking)
                out["result"] = {**res, "outcome": {**oc, "optionId": "allow_once"}}
                msg = {**msg, "result": out["result"]}
        await self._send(out)
        self.hub.audit_ask(client, self, ask, msg)
        self.broadcast({"jsonrpc": "2.0", "method": "_gw/ask_resolved",
                        "params": {"id": ask["msg"]["id"], "sessionId": ask["sessionId"],
                                   "by": client.user.get("username")}})
        s = self.sessions.get(ask["sessionId"] or "")
        if s and s.status == "needs_you" and not any(a["sessionId"] == s.sid for a in self.asks.values()):
            # Asks can also arrive outside a run (e.g. recipe parameters during session/new).
            if s.last_text.startswith("Needs"):
                s.last_text = ""
            self._set_status(s, "working" if (s.prompts > 0 or s.run_id) else "idle")

    # ------------------------------------------------------------ upstream -> clients
    def _dispatch(self, msg: dict, raw: str) -> None:
        if "method" not in msg and "id" in msg:
            entry = self.pending.pop(msg["id"], None) if isinstance(msg["id"], int) else None
            if entry is None:
                return
            client, cid, fut, method, params = entry
            self._post_response(method, params, msg, client)
            if fut is not None:
                if not fut.done():
                    if "error" in msg:
                        e = msg["error"] or {}
                        fut.set_exception(RpcError(e.get("code", -32000), e.get("message", "error"), e.get("data")))
                    else:
                        fut.set_result(msg.get("result"))
            elif client is not None:
                out = {"jsonrpc": "2.0", "id": cid}
                if "error" in msg:
                    out["error"] = msg["error"]
                else:
                    out["result"] = msg.get("result")
                client.send(out)
            return
        method = msg.get("method")
        params = msg.get("params") or {}
        if method in AGENT_REQUESTS and "id" in msg:
            if method == "session/request_permission" and self.hub.guard is not None:
                ctx = self.hub.guard_ctx(self.username)   # the profile owner's guard; None = unguarded
                if ctx is not None:
                    self._spawn(self._guarded_permission(msg, raw, ctx))
                    return
            self._register_ask(msg, raw)
            return
        if method in SESSION_NOTIFICATIONS:
            sid = str(params.get("sessionId") or "")
            s = self.sess(sid)
            replaying = s.loading_client is not None
            self._herd_from_update(s, method, params.get("update") or {}, replaying)
            if s.loaded or replaying:
                self._buffer(s, raw)
            if replaying:
                s.loading_client.send(raw)
            else:
                for c in list(self.clients):
                    if sid in c.watch:
                        c.send(raw)
            return
        # other notifications (device-code, etc.)
        self.broadcast(raw)

    def _buffer(self, s: SessionState, raw: str) -> None:
        n = len(raw)
        s.buffer.append(raw)
        s.buffer_bytes += n
        self.hub.total_buffer += n
        while s.buffer_bytes > SESSION_BUFFER_BYTES and len(s.buffer) > 1:
            old = s.buffer.popleft()
            s.buffer_bytes -= len(old)
            self.hub.total_buffer -= len(old)
            s.truncated = True
        if self.hub.total_buffer > TOTAL_BUFFER_BYTES:
            self.hub.evict_buffers()

    def _post_response(self, method: str, params: dict, msg: dict, client: Client | None) -> None:
        result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        ok = "error" not in msg
        # Our own change to a buffered session (rename, mode, truncate, ...): re-baseline its fingerprint so
        # the watcher does not mistake it for an outside write.
        sid0 = str(params.get("sessionId") or "") if isinstance(params, dict) else ""
        if ok and sid0 and method not in _READ_ONLY_SESSION_METHODS and method not in ("session/new",):
            s0 = self.sessions.get(sid0)
            if s0 is not None and s0.loaded and method not in ("session/delete", "session/close"):
                self._refresh_fp_soon(s0)
        if method == "session/new" and ok:
            sid = str(result.get("sessionId") or "")
            if sid:
                s = self.sess(sid)
                s.loaded, s.load_result, s.cwd = True, result, str(params.get("cwd") or "")
                s.title = s.title or "New chat"
                if client is not None:
                    client.watch.add(sid)
                self._herd_changed(s)
                self._refresh_fp_soon(s)
        elif method == SYSTEM_PROMPT_SET and ok:
            s = self.sess(sid0)
            # Goose < 1.55 keeps overrides only in the in-memory agent: remember them (one per mode and key, as
            # Goose does; empty text clears) to re-send after a load.
            slot = (str(params.get("mode") or "append"), str(params.get("key") or ""))
            if str(params.get("text") or "").strip():
                s.sys_prompts[slot] = {k: v for k, v in params.items() if k != "sessionId"}
            else:
                s.sys_prompts.pop(slot, None)
        elif method == "session/load":
            s = self.sess(str(params.get("sessionId") or ""))
            s.loading_client = None
            if ok:
                s.loaded, s.load_result = True, result
                if client is not None:
                    client.watch.add(s.sid)
                self._refresh_fp_soon(s)
                if s.sys_prompts and not self.caps()["persistentSystemPrompt"]:
                    self._spawn(self._resend_sys_prompt(s))
        elif method == "session/prompt":
            s = self.sess(str(params.get("sessionId") or ""))
            s.prompts = max(0, s.prompts - 1)
            if s.prompts == 0:
                self._refresh_fp_soon(s)
                if s.steers:
                    stop0 = result.get("stopReason") if ok else None
                    self._return_steers(s, "error" if not ok else "cancelled"
                                        if stop0 == "cancelled" or s.cancel_requested else "ended")
                if ok:
                    stop = result.get("stopReason") or "end_turn"
                    s.run_id = None
                    if stop == "cancelled":
                        self._set_status(s, "idle")
                    else:
                        self._set_status(s, "done")
                        self.hub.notify_event(self, s.sid, "done")
                else:
                    err = (msg.get("error") or {}).get("message") or "error"
                    s.run_id = None
                    self._set_status(s, "error", error=err)
                    self.hub.notify_event(self, s.sid, "error")
        elif method == STEER:
            s = self.sessions.get(sid0)
            e = next((x for x in s.steers if x["blocks"] is params.get("prompt")), None) if s else None
            if e is not None:
                if not ok or not result.get("messageId"):
                    s.steers.remove(e)   # refused (no active run, wrong run id): the tab queues it instead
                else:
                    e["messageId"], e["state"] = str(result["messageId"]), "pending"
                    e["runId"] = str(result.get("runId") or e["runId"])
                    if e["messageId"] in s.steer_seen:      # the agent already read it
                        s.steers.remove(e)
                        self._steer_update(s, e, "delivered")
                    else:
                        self._steer_update(s, e, "pending", skip=client)
                        if not s.run_id and s.prompts == 0:   # the run ended while Goose was answering
                            self._return_steers(s, "cancelled" if s.cancel_requested else "ended")
        elif method == "session/set_mode" and ok:
            s = self.sessions.get(str(params.get("sessionId") or ""))
            if s and s.load_result and isinstance(s.load_result.get("modes"), dict):
                s.load_result["modes"] = {**s.load_result["modes"], "currentModeId": params.get("modeId")}
            if s and s.load_result and isinstance(s.load_result.get("configOptions"), list):
                # keep the "mode" config option in step (the prompt policy check reads both)
                s.load_result["configOptions"] = [
                    {**o, "currentValue": params.get("modeId")} if isinstance(o, dict) and o.get("id") == "mode" else o
                    for o in s.load_result["configOptions"]]
        elif method == "session/set_config_option" and ok:
            s = self.sessions.get(str(params.get("sessionId") or ""))
            if s and s.load_result is not None and result.get("configOptions") is not None:
                s.load_result["configOptions"] = result["configOptions"]
            if s and s.load_result and params.get("configId") == "mode" and \
                    isinstance(s.load_result.get("modes"), dict):
                s.load_result["modes"] = {**s.load_result["modes"], "currentModeId": params.get("value")}
        elif method == TRUNCATE and ok:
            # Edit + rerun: the buffered transcript now shows messages Goose has deleted. Drop it so the next load
            # comes from Goose, and tell the other tabs showing this chat to reload (the editing tab reloads itself).
            s = self.sessions.get(sid0)
            if s is not None:
                self._invalidate(s)
                note = {"jsonrpc": "2.0", "method": "_gw/session_changed",
                        "params": {"sessionId": sid0, "reason": "truncated"}}
                for c in list(self.clients):
                    if c is not client:
                        c.send(note)
        elif method in (EXT_ADD, EXT_REMOVE):
            # Retry / add / remove in the extension panel: the cached load result is what reconnecting tabs are
            # replayed, so its start-up extension status must follow (bug 2026-11-08, stale "failed").
            s = self.sessions.get(sid0)
            if s is not None and s.load_result is not None:
                apply_extension_change(s.load_result, method, params, msg)
        elif method in ("session/delete", "session/close") and ok:
            s = self.sessions.pop(str(params.get("sessionId") or ""), None)
            if method == "session/delete":
                self.hub.save_chat_state(self.key, sid0, None, None)   # its queue and herd mark go too
            if s:
                self.hub.total_buffer -= s.buffer_bytes
                self.broadcast_herd(s, removed=True)
                if s.queue:
                    self.broadcast({"jsonrpc": "2.0", "method": "_gw/queue_update",
                                    "params": {"sessionId": s.sid, "items": []}})
        elif method == "_goose/unstable/session/rename" and ok:
            s = self.sess(str(params.get("sessionId") or ""))
            s.title = str(params.get("title") or s.title)
            self._herd_changed(s)
        elif method.startswith("_goose/unstable/schedules/") and ok:
            self.hub.schedules_changed(self.username)

    # ------------------------------------------------------------ herd
    def _herd_from_update(self, s: SessionState, method: str, u: dict, replaying: bool) -> None:
        kind = u.get("sessionUpdate")
        if kind == "tool_call" and self.hub.guard is not None and self.hub.guard_active():
            self._remember_tool(u)
        if method == "_goose/unstable/session/update":
            # SessionUsageUpdate / MessageUsageUpdate / StatusMessageUpdate
            if "contextLimit" in u:
                s.usage = {"used": u.get("used"), "contextLimit": u.get("contextLimit"),
                           "cost": u.get("accumulatedCost")}
                self._herd_dirty.add(s.sid)
            elif isinstance(u.get("status"), dict) and not replaying:
                s.last_text = str(u["status"].get("message") or "")[:300]
                self._herd_dirty.add(s.sid)
            return
        if kind == "config_option_update" and isinstance(u.get("configOptions"), list) and s.load_result is not None:
            s.load_result["configOptions"] = u["configOptions"]   # the prompt policy check reads these (spec 009)
            return
        if kind == "current_mode_update" and s.load_result is not None and u.get("currentModeId"):
            if isinstance(s.load_result.get("modes"), dict):
                s.load_result["modes"] = {**s.load_result["modes"], "currentModeId": u["currentModeId"]}
            if isinstance(s.load_result.get("configOptions"), list):
                s.load_result["configOptions"] = [
                    {**o, "currentValue": u["currentModeId"]} if isinstance(o, dict) and o.get("id") == "mode" else o
                    for o in s.load_result["configOptions"]]
            return
        if kind == "user_message_chunk" and not replaying:
            mid = u.get("messageId") or (((u.get("_meta") or {}).get("goose") or {}).get("messageId"))
            if isinstance(mid, str) and mid.startswith("steer_"):
                if mid not in s.steer_seen:
                    s.steer_seen.append(mid)
                e = next((x for x in s.steers if x["messageId"] == mid), None)
                if e is not None:   # the agent read the steer: it is in the conversation now
                    s.steers.remove(e)
                    self._steer_update(s, e, "delivered")
            return
        if kind == "session_info_update":
            if u.get("title"):
                s.title = str(u["title"])
            goose = ((u.get("_meta") or {}).get("goose") or {})
            if "activeRunId" in goose and not replaying:
                rid = goose.get("activeRunId")
                if rid:
                    s.run_id = rid
                    if s.status not in ("working", "needs_you"):
                        self._set_status(s, "working")
                else:
                    s.run_id = None
                    if s.steers:   # Goose dropped the steers the agent had not read (discard_pending_steers)
                        self._return_steers(s, "cancelled" if s.cancel_requested else "ended")
                    if s.status == "working" and s.prompts == 0:
                        self._set_status(s, "done")
                        self.hub.notify_event(self, s.sid, "done")
            self._herd_dirty.add(s.sid)
        elif kind == "agent_message_chunk" and not replaying:
            c = u.get("content") or {}
            if c.get("type") == "text":
                base = "" if s.last_text.startswith(("🔧", "Needs")) else s.last_text
                s.last_text = (base + (c.get("text") or ""))[-300:]
                self._herd_dirty.add(s.sid)
        elif kind == "tool_call" and not replaying:
            s.last_text = f"🔧 {u.get('title') or 'tool'}"[:300]
            self._herd_dirty.add(s.sid)
            ev = agent_tool_event(u)
            if ev:   # B-4: the model starting extensions / sub-agents / schedules leaves a trace
                self.hub.audit_agent(self, s.sid, ev[0], ev[1])
        elif kind == "usage_update":
            cost = u.get("cost") or {}
            s.usage = {"used": u.get("used"), "contextLimit": u.get("size"), "cost": cost.get("amount")}
            self._herd_dirty.add(s.sid)

    def _set_status(self, s: SessionState, status: str, error: str = "") -> None:
        changed = s.status != status or s.error != error
        if s.status != status:
            s.status, s.since = status, time.time()
        s.error = error
        if changed:   # spec 019: keep "working / needs you / done / error" across a gateway restart
            mark = {"status": status, "since": s.since, "title": s.title, "cwd": s.cwd,
                    "lastText": s.last_text, "error": error} if status in MARK_STATUSES else None
            self.hub.save_chat_state(self.key, s.sid, "mark", mark)
        self._herd_changed(s)

    # ------------------------------------------------------------ steers and the queue (bug steer-lost-on-slow-turn, spec 019)
    @staticmethod
    def _steer_view(s: SessionState, e: dict) -> dict:
        return {"sessionId": s.sid, "id": e["id"], "messageId": e["messageId"], "runId": e["runId"],
                "blocks": e["blocks"], "by": e["by"], "at": e["at"], "state": e["state"]}

    def _steer_update(self, s: SessionState, e: dict, state: str, skip: Client | None = None, **extra: Any) -> None:
        params = {**self._steer_view(s, e), "state": state, **extra}
        if state != "pending":
            params.pop("blocks", None)
        raw = json.dumps({"jsonrpc": "2.0", "method": "_gw/steer_update", "params": params}, separators=(",", ":"))
        for c in list(self.clients):
            if c is not skip:
                c.send(raw)

    def _return_steers(self, s: SessionState, reason: str) -> None:
        """The run ended with accepted steers the agent never read (Goose discards them silently): put them back at
        the front of the chat's queue, held, so the user can send, edit or drop them - and tell every tab."""
        back = [e for e in s.steers if e["state"] == "pending"]
        if not back:
            return
        s.steers = [e for e in s.steers if e["state"] != "pending"]
        note = STEER_RETURNED.get(reason, STEER_RETURNED["ended"])
        items = [{"id": e["id"], "blocks": e["blocks"], "by": e["by"], "at": e["at"], "held": True, "steer": True,
                  "note": note} for e in back]
        s.queue[0:0] = items
        log.info("session %s: %d steer(s) not delivered (%s), returned to the queue", s.sid, len(back), reason)
        for e in back:
            self._steer_update(s, e, "returned", reason=reason, note=note)
        self._queue_changed(s)

    def _queue_changed(self, s: SessionState) -> None:
        self.hub.save_chat_state(self.key, s.sid, "queue", s.queue or None)
        self.broadcast({"jsonrpc": "2.0", "method": "_gw/queue_update", "params": {"sessionId": s.sid, "items": s.queue}})

    def queue_op(self, client: Client, params: dict) -> dict:
        """_gw/queue: add / remove / take (a tab claims the item it is about to send; first claim wins) / list."""
        sid = str(params.get("sessionId") or "")
        op = params.get("op")
        if not sid or len(sid) > 200:
            raise RpcError(-32602, "sessionId is required")
        s = self.sessions.get(sid)
        if op == "list":
            return {"items": s.queue if s else []}
        if op == "add":
            blocks = params.get("blocks")
            if not isinstance(blocks, list) or not blocks or not all(isinstance(b, dict) for b in blocks):
                raise RpcError(-32602, "blocks must be a non-empty list of content blocks")
            if len(json.dumps(blocks)) > QUEUE_ITEM_BYTES:
                raise RpcError(-32602, "this message is too large to queue")
            s = self.sess(sid)
            if len(s.queue) >= QUEUE_MAX_ITEMS:
                raise RpcError(-32602, f"at most {QUEUE_MAX_ITEMS} messages can wait in a chat's queue")
            if not s.queue and sum(1 for x in self.sessions.values() if x.queue) >= QUEUE_MAX_SESSIONS:
                raise RpcError(-32602, "too many chats have queued messages")
            item = {"id": "q" + os.urandom(6).hex(), "blocks": blocks, "by": client.user.get("username"),
                    "at": time.time()}
            s.queue.append(item)
            self._queue_changed(s)
            return {"ok": True, "id": item["id"], "items": s.queue}
        if op in ("remove", "take"):
            qid = params.get("id")
            item = next((x for x in s.queue if x.get("id") == qid), None) if s else None
            if item is None or (op == "take" and item.get("held") and not params.get("manual")):
                # a held item (returned steer, kept across a restart) is only sent by the user's own click
                return {"ok": False, "items": s.queue if s else []}
            s.queue.remove(item)
            self._queue_changed(s)
            return {"ok": True, "item": item, "items": s.queue}
        raise RpcError(-32602, "op must be add, remove, take or list")

    def restore_state(self, rows: list[dict]) -> None:
        """Spec 019: the herd marks and queues this profile had before the gateway restarted."""
        now = time.time()
        for r in rows:
            sid, kind, data = r.get("session_id"), r.get("kind"), r.get("data")
            if not sid or not isinstance(data, (dict, list)):
                continue
            if kind == "queue" and isinstance(data, list):
                # the run these messages waited for ended with the old gateway: never send them by surprise
                self.sess(sid).queue = [x if x.get("held") else {**x, "held": True, "note": QUEUE_RESTORED}
                                        for x in data if isinstance(x, dict) and x.get("id")][:QUEUE_MAX_ITEMS * 2]
            elif kind == "mark" and isinstance(data, dict) and data.get("status") in MARK_STATUSES:
                if now - float(data.get("since") or 0) > MARK_MAX_AGE:
                    self.hub.save_chat_state(self.key, sid, "mark", None)
                    continue
                s = self.sess(sid)
                s.title, s.cwd = str(data.get("title") or ""), str(data.get("cwd") or "")
                s.last_text, s.since = str(data.get("lastText") or "")[:300], float(data.get("since") or now)
                s.status, s.error = data["status"], str(data.get("error") or "")
                if s.status in ("working", "needs_you"):   # its run ended with the old gateway and its workers
                    s.status, s.since = "error", now
                    s.error = "Interrupted: Goose Web restarted while this chat was running"
                    self.hub.save_chat_state(self.key, sid, "mark", {
                        "status": s.status, "since": s.since, "title": s.title, "cwd": s.cwd,
                        "lastText": s.last_text, "error": s.error})

    def snapshot(self) -> dict:
        """Spec 019: everything a tab needs to rebuild this user's live state (added to _gw/hello)."""
        return {"queues": {s.sid: s.queue for s in self.sessions.values() if s.queue},
                "steers": [self._steer_view(s, e) for s in self.sessions.values() for e in s.steers
                           if e["state"] == "pending"]}

    def _herd_changed(self, s: SessionState) -> None:
        self._herd_dirty.discard(s.sid)
        self.broadcast_herd(s)

    def agent(self, s: SessionState) -> dict:
        ask = next((a for a in self.asks.values() if a["sessionId"] == s.sid), None)
        a = {"profile": self.key, "username": self.username, "sessionId": s.sid, "title": s.title or s.sid,
             "cwd": s.cwd, "status": s.status, "since": s.since, "runId": s.run_id, "lastText": s.last_text,
             "usage": s.usage, "error": s.error}
        if ask:
            p = ask["msg"].get("params") or {}
            a["ask"] = {"id": ask["msg"]["id"], "kind": ask["msg"]["method"],
                        "title": (p.get("toolCall") or {}).get("title") or p.get("message") or ""}
        return a

    def herd(self) -> list[dict]:
        return [self.agent(s) for s in self.sessions.values() if s.status != "idle" or s.loaded and s.running()]

    def broadcast_herd(self, s: SessionState, removed: bool = False) -> None:
        a = self.agent(s)
        if removed:
            a["status"] = "removed"
        self.hub.herd_out(self, {"jsonrpc": "2.0", "method": "_gw/herd_update", "params": {"agent": a}})

    def flush_herd(self) -> None:
        dirty, self._herd_dirty = self._herd_dirty, set()
        for sid in dirty:
            s = self.sessions.get(sid)
            if s:
                self.broadcast_herd(s)

    def broadcast(self, obj: dict | str) -> None:
        raw = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"))
        for c in list(self.clients):
            c.send(raw)

    def activity(self) -> tuple[int, int]:
        return (len([c for c in self.clients if not c.closed]),
                sum(1 for s in self.sessions.values() if s.running()) + len(self.asks))


class Hub:
    def __init__(self, workers: WorkerManager):
        self.workers = workers
        self.upstreams: dict[str, Upstream] = {}
        self.total_buffer = 0
        self.herd_watchers: set[Client] = set()   # admin sockets with herd_all
        # callbacks wired by the app
        self.on_audit: Callable[..., None] | None = None
        self.on_event: Callable[..., None] | None = None
        self.on_schedules: Callable[[str], None] | None = None
        self.profile_root_for: Callable[[str], str] = lambda u: ""
        self.guard: Any = None          # guard.GuardService (spec 018), wired by the app; None = no prompt guard
        self.db: Any = None             # db.Database, wired by the app: chat_state rows (spec 019); None = memory only
        self._flusher: asyncio.Task | None = None
        workers.activity = self._activity
        workers.on_restart = self._on_restart

    def start(self) -> None:
        self._flusher = asyncio.create_task(self._flush_loop())

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            for up in list(self.upstreams.values()):
                try:
                    up.flush_herd()
                except Exception:
                    log.exception("herd flush")

    def _activity(self, key: str) -> tuple[int, int]:
        up = self.upstreams.get(key)
        return up.activity() if up else (0, 0)

    async def _on_restart(self, w: Worker) -> None:
        up = self.upstreams.get(w.key)
        if up:
            await up.reset("the Goose worker restarted")
            if up.clients:
                try:
                    await up.ensure()
                except RpcError:
                    pass

    # ------------------------------------------------------------ prompt guard (spec 018)
    def guard_ctx(self, username: str):
        return self.guard.context_for(username) if self.guard is not None else None

    def guard_active(self) -> bool:
        return self.guard is not None and self.guard.in_use()

    def guard_health_for(self, client: Client) -> dict | None:
        """Classifier health for administrators while some guard is on (banner), else None."""
        if self.guard is None or not client.is_admin or not self.guard.in_use():
            return None
        return self.guard.health()

    def broadcast_admins(self, obj: dict) -> None:
        raw = json.dumps(obj, separators=(",", ":"))
        seen: set[int] = set()
        for up in self.upstreams.values():
            for c in list(up.clients):
                if c.is_admin and id(c) not in seen:
                    seen.add(id(c))
                    c.send(raw)

    def audit_guard(self, up: "Upstream", sid: str, ctx: Any, d: Any, *, tool: str = "", ext: str = "",
                    mode: str = "", actor: Any = None) -> None:
        """guard.blocked: who, where, which rule or score - never the prompt or the arguments (R6)."""
        if not self.on_audit:
            return
        detail = {"profile": up.key, "sessionId": sid, "guard": ctx.kind, **d.audit_detail()}
        if ctx.team:
            detail["team"] = ctx.team
        if tool:
            detail["tool"] = tool[:200]
        if ext:
            detail["extension"] = ext[:100]
        if mode:
            detail["mode"] = mode
        if actor is None:
            owner = next((c for c in up.clients if _ukey(c.user) == up.key), None)
            actor = owner or _AgentActor({"id": None, "username": up.username})
        try:
            self.on_audit(actor, "guard.blocked", tool[:200] if tool else sid, detail, False)
        except Exception:
            log.exception("guard audit")

    def upstream(self, key: str, username: str) -> Upstream:
        up = self.upstreams.get(key)
        if up is None:
            up = self.upstreams[key] = Upstream(self, key, username)
            if self.db is not None:
                try:
                    up.restore_state(self.db.chat_state(key))
                except Exception:
                    log.exception("restoring the chat state of %s", key)
        return up

    def save_chat_state(self, profile: str, sid: str, kind: str | None, data: Any) -> None:
        """Persist (data) or delete (None) one chat_state row; kind None deletes every row of the chat."""
        if self.db is None or not sid:
            return
        try:
            if kind is None:
                self.db.delete_chat_state(profile, sid)
            else:
                self.db.set_chat_state(profile, sid, kind, data)
        except Exception:
            log.exception("saving the chat state of %s/%s", profile, sid)

    def attach(self, up: Upstream, client: Client) -> None:
        up.clients.add(client)

    def detach(self, up: Upstream, client: Client) -> None:
        up.clients.discard(client)
        self.herd_watchers.discard(client)
        for s in up.sessions.values():
            if s.loading_client is client:
                s.loading_client = None
        client.close()

    def herd_out(self, up: Upstream, msg: dict) -> None:
        raw = json.dumps(msg, separators=(",", ":"))
        for c in list(up.clients):
            c.send(raw)
        for c in list(self.herd_watchers):
            if c not in up.clients:
                c.send(raw)

    def all_herd(self) -> list[dict]:
        return [a for up in self.upstreams.values() for a in up.herd()]

    def evict_buffers(self) -> None:
        cands = sorted((s.last_touch, up, s) for up in self.upstreams.values() for s in up.sessions.values()
                       if not s.running() and s.buffer_bytes and not any(s.sid in c.watch for c in up.clients))
        for _, up, s in cands:
            if self.total_buffer <= TOTAL_BUFFER_BYTES * 0.7:
                break
            self.total_buffer -= s.buffer_bytes
            s.buffer.clear()
            s.buffer_bytes, s.loaded, s.load_result = 0, False, None

    async def gw_method(self, up: Upstream, client: Client, msg: dict) -> None:
        method, mid, params = msg["method"], msg.get("id"), msg.get("params") or {}
        result: Any
        if method == "_gw/hello":
            err = None
            try:
                await up.ensure()
            except RpcError as e:
                err = e.message
            result = {"user": {"username": client.user["username"], "role": client.user.get("role")},
                      "profile": up.key, "agent": up.init_result, "gooseCaps": up.caps(),
                      "asks": [a["msg"] for a in up.asks.values()], "herd": up.herd(),
                      "upstream": {"state": up.state, "error": err}, **up.snapshot()}
            gh = self.guard_health_for(client)
            if gh is not None:
                result["guard"] = gh
        elif method == "_gw/watch":
            client.watch = {str(x) for x in (params.get("sessionIds") or [])[:200]}
            result = {"ok": True}
        elif method == "_gw/herd":
            if params.get("all") and client.is_admin:
                client.herd_all = True
                self.herd_watchers.add(client)
                result = {"agents": self.all_herd()}
            else:
                client.herd_all = False
                self.herd_watchers.discard(client)
                result = {"agents": up.herd()}
        elif method == "_gw/seen":
            s = up.sessions.get(str(params.get("sessionId") or ""))
            if s and s.status in ("done", "error"):
                up._set_status(s, "idle")
            result = {"ok": True}
        elif method == "_gw/queue":
            try:
                result = up.queue_op(client, params)
            except RpcError as e:
                if mid is not None:
                    client.send({"jsonrpc": "2.0", "id": mid, "error": e.to_json()})
                return
        else:
            if mid is not None:
                client.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown gateway method"}})
            return
        if mid is not None:
            client.send({"jsonrpc": "2.0", "id": mid, "result": result})

    # ------------------------------------------------------------ hooks
    def audit_denied(self, client: Client, method: str, reason: str) -> None:
        if self.on_audit:
            self.on_audit(client, "acp.denied", method, {"reason": reason}, False)

    AUDITED_PREFIXES = ("_goose/unstable/config/", "_goose/unstable/providers/custom/", "_goose/unstable/providers/config/save",
                        "_goose/unstable/providers/config/delete", "_goose/unstable/providers/secrets/delete",
                        "_goose/unstable/recipes/save", "_goose/unstable/recipes/delete", "_goose/unstable/schedules/create",
                        "_goose/unstable/schedules/delete", "_goose/unstable/apps/import", "_goose/unstable/apps/delete",
                        "_goose/unstable/sources/create", "_goose/unstable/sources/update", "_goose/unstable/sources/delete",
                        "_goose/unstable/tools/permissions/set", "_goose/unstable/tools/call",
                        "_goose/unstable/session/extensions/add", "_goose/unstable/defaults/save", "session/delete",
                        TRUNCATE)
    QUIET = ("/list", "/read", "/get", "/status", "config/read-all")

    def audit_call(self, client: Client, up: Upstream, method: str, params: dict) -> None:
        if not self.on_audit:
            return
        if method.startswith(self.AUDITED_PREFIXES) and not method.endswith(self.QUIET) or up.key != _ukey(client.user):
            detail = {"profile": up.key}
            for k in ("sessionId", "key", "id", "name", "configKey", "scheduleId", "providerId", "extensionName"):
                if k in params:
                    detail[k] = params[k]
            args = params.get("arguments")
            if method == pol.TOOLS_CALL and isinstance(args, dict):   # B-4: which extension / recipe it starts
                picked = {k: str(args[k])[:200] for k in ("action", "extension_name", "source", "extensions")
                          if k in args}
                if picked:
                    detail["arguments"] = picked
            self.on_audit(client, "acp." + method.replace("_goose/unstable/", ""), method, detail, True)

    def audit_activity(self, client: Client, up: Upstream, method: str, params: dict) -> None:
        """Everyday chat activity (spec 015): who opened, started, prompted, stopped or forked which chat.
        Prompt text is never recorded - only its length and the number of attachments."""
        if not self.on_audit:
            return
        detail: dict = {"profile": up.key}
        if method in ("session/prompt", STEER):
            blocks = [b for b in (params.get("prompt") or []) if isinstance(b, dict)]
            detail["chars"] = sum(len(str(b.get("text") or "")) for b in blocks if b.get("type") in (None, "text"))
            detail["attachments"] = sum(1 for b in blocks if b.get("type") not in (None, "text"))
        elif method == "session/new":
            detail["cwd"] = str(params.get("cwd") or "")[:300]
        elif method == "session/set_mode":
            detail["mode"] = str(params.get("modeId") or "")
        try:
            self.on_audit(client, CHAT_ACTIVITY[method], str(params.get("sessionId") or ""), detail, True)
        except Exception:
            log.exception("activity record")

    def audit_recipe(self, client: Client, up: Upstream, method: str, recipe: Any, via: str, names: list[str],
                     ok: bool) -> None:
        """B-4: a recipe a session / schedule / import would run, with the extensions it declares."""
        if not self.on_audit:
            return
        r = recipe if isinstance(recipe, dict) else {}
        detail = {"profile": up.key, "via": via, "title": str(r.get("title") or "")[:200], "extensions": names,
                  "subRecipes": len(r.get("sub_recipes") or []) if isinstance(r.get("sub_recipes"), list) else 0,
                  "resolved": isinstance(recipe, dict)}
        try:
            self.on_audit(client, "agent.recipe", method, detail, ok)
        except Exception:
            log.exception("recipe audit")

    def audit_agent(self, up: Upstream, sid: str, action: str, detail: dict) -> None:
        """B-4: a tool call of the model that starts extensions / sub-agents / schedules (no browser sent it: the
        record is attributed to the profile owner's connected socket, or to the profile name)."""
        if not self.on_audit:
            return
        owner = next((c for c in up.clients if _ukey(c.user) == up.key), None)
        actor = owner or _AgentActor({"id": None, "username": up.username})
        try:
            self.on_audit(actor, action, sid, {"profile": up.key, "sessionId": sid, **detail}, True)
        except Exception:
            log.exception("agent audit")

    def audit_ask(self, client: Client, up: Upstream, ask: dict, answer: dict) -> None:
        if self.on_audit:
            res = answer.get("result") or {}
            choice = ((res.get("outcome") or {}).get("optionId") or res.get("action") or "")
            self.on_audit(client, "acp.answer", ask["msg"]["method"],
                          {"profile": up.key, "sessionId": ask["sessionId"], "choice": choice}, True)

    def notify_event(self, up: Upstream, sid: str, event: str) -> None:
        if self.on_event:
            watched = any(sid in c.watch for c in up.clients)
            s = up.sessions.get(sid)
            if s:
                self.on_event(up.username, event, up.agent(s), watched)

    def schedules_changed(self, username: str) -> None:
        if self.on_schedules:
            self.on_schedules(username)


def _ukey(user: dict) -> str:
    return str(user.get("username", "")).lower()


class _AgentActor:
    """Stands in for a browser socket in audit records the agent itself causes (Hub.audit_agent)."""

    def __init__(self, user: dict):
        self.user, self.ip, self.is_admin = user, "", False
