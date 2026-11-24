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
from . import effort as effortmod
from . import guard as guardmod
from . import policy as pol
from .unload import Unloader   # FIX idle-sessions-keep-mcp-servers: closes idle chats in Goose (unload.py)
from .workers import Worker, WorkerManager

log = logging.getLogger("goose_web.hub")

SESSION_BUFFER_BYTES = 12 * 1024 * 1024
TOTAL_BUFFER_BYTES = 256 * 1024 * 1024
# FIX chat-open-replay-overflow: a long run streams one frame per text chunk (tens of thousands). Consecutive chunks of
# one message are merged in the buffer (ChunkTail), which also keeps at most this many frames: beyond it the buffer is
# truncated like at SESSION_BUFFER_BYTES, so an idle chat is loaded from Goose again.
SESSION_BUFFER_FRAMES = 5000
COALESCED_UPDATES = ("agent_message_chunk", "agent_thought_chunk")
# A tab's send queue is bounded by bytes, not frames. Beyond CLIENT_QUEUE_BYTES its session frames are dropped and the
# tab is told to load those chats again (_gw/resync); only frames that must not be dropped (responses, agent requests,
# gateway notices) beyond CLIENT_QUEUE_HARD_BYTES end the socket (a tab that never reads).
CLIENT_QUEUE_BYTES = 64 * 1024 * 1024
CLIENT_QUEUE_HARD_BYTES = 2 * CLIENT_QUEUE_BYTES
REPLAY_BATCH_BYTES = 256 * 1024        # replayed frames go out as JSON arrays of at most this size
REPLAY_QUEUE_BYTES = 4 * 1024 * 1024   # a replay waits while the tab still has more than this to receive
SESSION_LOAD_TIMEOUT = 180             # default of goose.session_load_timeout_seconds (0 = no watchdog)
RESYNC = "_gw/resync"
WORKER_RESTARTING = "the Goose worker is restarting"
RESYNC_ERROR = {"code": -32000, "message": "this tab could not receive the chat as fast as it was sent: open it again",
                "data": {"resync": True}}
AGENT_REQUESTS = {"session/request_permission", "elicitation/create", "_goose/unstable/session/recipe/request-params"}
SESSION_NOTIFICATIONS = {"session/update", "_goose/unstable/session/update"}
RPC_FORBIDDEN = -32003
# FIX deploy-interrupts-running-turns (1.16.0): right before a restart the deploy asks the gateway to drain - new turns
# are refused for a short while (the tab puts the text back in the box), so none can start between the last
# "is anything running?" check and the restart.
RPC_DRAINING = -32010
DRAIN_REFUSED = {"session/prompt", "_goose/unstable/tools/call", "_goose/unstable/schedules/run-now"}
DRAIN_NOTICE = ("Goose Web restarts for an update in a moment (about a minute). New messages wait until it is back; "
                "running chats are not affected.")
DRAIN_REFUSAL = "Goose Web is restarting for an update: send this again in a minute."
P_SCHEDULES_LIST = "_goose/unstable/schedules/list"
# Spec 020: a chat another program (Goose Desktop, the CLI, a scheduled job) is running is read-only in Goose Web
RPC_ELSEWHERE = -32011
ELSEWHERE_REFUSAL = ("This chat is running elsewhere (Goose Desktop, the goose CLI or a scheduled job). Goose Web shows "
                     "it read-only and cannot stop, steer or message it; wait until it has finished.")
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
PROVIDERS_LIST = "_goose/unstable/providers/list"   # spec 021: answered with each provider's engine (gwEngine)
CHAT_ACTIVITY = {"session/new": "chat.new", "session/load": "chat.open", "session/prompt": "chat.prompt",
                 "session/cancel": "chat.cancel", "session/fork": "chat.fork", "session/set_mode": "chat.mode",
                 STEER: "chat.steer"}
# Composer queue kept by the gateway per chat (spec 019): survives a refresh, another device and a restart.
QUEUE_MAX_ITEMS = 20
QUEUE_ITEM_BYTES = 15 * 1024 * 1024   # a message's inline images are at most 10 MB of base64 (composer.js, spec 039)
# Security review 2026-11-11 (SC-2/SC-4): one member must not be able to fill the gateway's memory, disk or event loop
QUEUE_MAX_SESSIONS = 20              # chats with a non-empty queue per profile (was 200)
QUEUE_PROFILE_BYTES = 32 * 1024 * 1024   # all queued messages of a profile together
QUEUE_MAX_AGE = 7 * 86400            # queued messages older than this are dropped by the maintenance sweep (SC-7)
STEER_MAX_PENDING = 10               # steers waiting for the agent's next step, per chat
STATE_FLUSH_SECONDS = 0.5            # chat_state rows are written by a background flusher, in a thread
PREVIEW_CHARS = 300                  # queue rows sent to tabs carry this much text, never the whole message
QUEUE_DROPPED = "{n} older returned message(s) were dropped: the chat's queue is full."
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
P_CFG_EXT_ADD = "_goose/unstable/config/extensions/add"
# Text that reaches the model outside session/prompt, checked like a prompt for guarded users (SA-6)
GUARDED_TEXT_METHODS = {SYSTEM_PROMPT_SET, "_goose/unstable/config/prompts/save", "_goose/unstable/recipes/save",
                        "_goose/unstable/session/import"}
# SD-2: an administrator's session/new in a member-writable folder with Goose plugins must name the plugins it accepts
ALLOW_PLUGINS_META = "goose-web.allowPlugins"
BYPASS_ID = "guard-bypass"
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


def guard_message(d: Any, what: str, show_ids: bool) -> str:
    """A refusal by the prompt guard as the user sees it. SA-9: members never see rule ids or rule-set names (the
    audit has them); administrators do. Built-in decisions (too long, timeout, burst, self-protection) explain
    themselves."""
    if d.builtin:
        why = ""
    elif d.rule:
        why = f"rule {d.rule} ({d.ruleset})" if show_ids else ""
    else:
        why = "prompt-injection classifier"
    return (f"forbidden: the prompt guard blocked this {what}" + (f" ({why})" if why else "") + ". "
            + (d.message or "")).strip()


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


def chunk_key(msg: Any) -> tuple | None:
    """(sessionId, update kind, messageId) of a text chunk that may be merged with the chunk before it, else None.
    Only agent message / thought text chunks: the browser appends consecutive ones of one message to one item."""
    if not isinstance(msg, dict) or msg.get("method") != "session/update":
        return None
    p = msg.get("params")
    u = p.get("update") if isinstance(p, dict) else None
    if not isinstance(u, dict) or u.get("sessionUpdate") not in COALESCED_UPDATES:
        return None
    c = u.get("content")
    if not isinstance(c, dict) or c.get("type") != "text" or not isinstance(c.get("text"), str):
        return None
    meta = u.get("_meta")
    goose = meta.get("goose") if isinstance(meta, dict) else None
    mid = u.get("messageId") or (goose.get("messageId") if isinstance(goose, dict) else None)
    return (str(p.get("sessionId") or ""), u["sessionUpdate"], None if mid is None else str(mid))


class ChunkTail:
    """The last buffered frame while later chunks of the same message may still extend it (FIX
    chat-open-replay-overflow). Kept unserialized - the message and its text pieces - so a merge costs only the new
    piece (re-serializing on every merge would be quadratic); serialized when a replay reads it (cached) and for good
    when the next frame does not belong to it."""
    __slots__ = ("key", "msg", "content", "pieces", "size", "_raw")

    def __init__(self, msg: dict, key: tuple, raw: str):
        params = dict(msg["params"])
        update = dict(params["update"])
        self.content = dict(update["content"])   # own copies along the path: the text is replaced when rendering
        update["content"] = self.content
        params["update"] = update
        self.msg = {**msg, "params": params}
        self.key = key
        self.pieces = [self.content["text"]]
        self.size = len(raw)
        self._raw: str | None = raw

    def add(self, text: str) -> int:
        self.pieces.append(text)
        self._raw = None
        self.size += len(text)
        return len(text)

    def render(self) -> str:
        if self._raw is None:
            text = "".join(self.pieces)
            self.pieces = [text]
            self.content["text"] = text
            self._raw = json.dumps(self.msg, separators=(",", ":"), ensure_ascii=False)
        return self._raw


def replay_batches(frames: list[str], limit: int | None = None):
    """Serialized frames as JSON arrays of at most `limit` characters (a larger frame goes alone, unwrapped)."""
    limit = limit or REPLAY_BATCH_BYTES
    out: list[str] = []
    size = 2
    for f in frames:
        if out and size + len(f) + 1 > limit:
            yield out[0] if len(out) == 1 else "[" + ",".join(out) + "]"
            out, size = [], 2
        out.append(f)
        size += len(f) + 1
    if out:
        yield out[0] if len(out) == 1 else "[" + ",".join(out) + "]"


@dataclass(eq=False)
class LoadWaiter:
    """A tab opening a chat (FIX chat-open-replay-overflow). It is sent what the hub has of the chat so far (the
    catch-up, in batches at the pace the tab reads), then the frames that arrived meanwhile (held), and the answer."""
    client: Any
    sid: str
    mid: Any
    gen: int                       # client.dropped[sid] when it asked: a different value later = frames were dropped
    final: dict | None = None      # the answer once known (a replay knows it at once, a load when Goose answers)
    final_at: int = 0              # held frames that go before the answer
    task: asyncio.Task | None = None   # the catch-up while it runs
    load: Any = None               # the UpstreamLoad it waits for; None = a replay from the buffer


@dataclass(eq=False)
class UpstreamLoad:
    """The one session/load of a chat sent to Goose (its pending entry has no client); every tab that opens the chat
    meanwhile waits for it."""
    up_id: int
    started: float = field(default_factory=time.time)
    waiters: list = field(default_factory=list)
    timer: Any = None              # the watchdog (goose.session_load_timeout_seconds)


SESSION_STATES_MAX = 2000       # session states kept per worker before idle ones are dropped (B-7)


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
    loading: Any = None            # UpstreamLoad in flight (one per chat, FIX chat-open-replay-overflow)
    abandoned: int | None = None   # upstream id of a load the watchdog gave up on, until Goose's late answer
    prompts: int = 0
    last_touch: float = field(default_factory=time.time)
    wrote_at: float = 0.0   # spec 020: when Goose Web last changed this session (prompt, turn end, edit) - not a load
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


def blocks_size(blocks: Any) -> int:
    try:
        return len(json.dumps(blocks, separators=(",", ":")))
    except (TypeError, ValueError):
        return QUEUE_ITEM_BYTES + 1


def blocks_preview(blocks: Any) -> tuple[str, int]:
    """(the first PREVIEW_CHARS of the text, number of non-text blocks) of a queued message."""
    text, other = [], 0
    for b in blocks if isinstance(blocks, list) else []:
        if not isinstance(b, dict):
            continue
        if b.get("type") in (None, "text"):
            text.append(str(b.get("text") or ""))
        else:
            other += 1
    return " ".join(text)[:PREVIEW_CHARS], other


def queue_item(blocks: list, by: str, *, iid: str | None = None, at: float | None = None, **extra: Any) -> dict:
    preview, att = blocks_preview(blocks)
    item = {"id": iid or "q" + os.urandom(6).hex(), "blocks": blocks, "by": by, "at": at or time.time(),
            "preview": preview, "attachments": att, "bytes": blocks_size(blocks)}
    item.update(extra)
    return item


def item_view(x: dict) -> dict:
    """What tabs see of a queued message (SC-2): everything but its content; the content comes with `take`."""
    v = {k: x[k] for k in ("id", "by", "at", "held", "steer", "note") if k in x}
    if "preview" not in x:
        x["preview"], x["attachments"] = blocks_preview(x.get("blocks"))
    v.update(preview=x.get("preview", ""), attachments=x.get("attachments", 0), bytes=x.get("bytes", 0))
    return v


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
        self.elsewhere = False   # spec 020: an administrator's tab that asked for the "running elsewhere" list
        self.closed = False
        self.reason = ""         # why the gateway ended this socket: queue-full | kick (app.py: ws.disconnect detail)
        self.key = ""            # profile key of the upstream it is attached to (log lines)
        # FIX chat-open-replay-overflow: the send queue is bounded by bytes. Entries are (text, sid): sid = a session
        # notification the gateway may drop (the tab is then told to load that chat again), None = kept.
        self._q: deque[tuple[str, str | None]] = deque()
        self.qbytes = 0          # queued, all entries
        self.kept_bytes = 0      # queued, kept entries
        self.hold_bytes = 0      # held (below)
        self._wake = asyncio.Event()
        self._room = asyncio.Event()
        self.holds: dict[str, list] = {}       # sid -> live frames held back while this tab is sent that chat
        self.replays: dict[str, Any] = {}      # sid -> the LoadWaiter of a session/load of this tab
        self.stale: set[str] = set()           # chats whose frames were dropped: no more until the tab loads them
        self.dropped: dict[str, int] = {}      # sid -> how often frames of that chat were dropped
        self.task: asyncio.Task | None = None
        # SC-3, wired by the app: close the socket itself (the read loop is waiting on it), and re-check that the
        # session / API token this socket signed in with is still valid
        self.kick: Callable[[], Any] | None = None
        self.still_valid: Callable[[], bool] | None = None

    def start(self) -> None:
        self.task = asyncio.create_task(self._pump())

    async def _pump(self) -> None:
        try:
            while True:
                if not self._q:
                    self._wake.clear()
                    await self._wake.wait()
                    continue
                raw, sid = self._q.popleft()
                self.qbytes -= len(raw)
                if sid is None:
                    self.kept_bytes -= len(raw)
                if self.qbytes <= REPLAY_QUEUE_BYTES:
                    self._room.set()
                await self._send(raw)
        except Exception:
            self.closed = True
            self._room.set()

    def send(self, obj: dict | str) -> None:
        """A frame the tab must get: a response, an agent request, a gateway notice."""
        if self.closed:
            return
        self._put(obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":")), None)

    def push(self, sid: str, raw: str) -> None:
        """A notification of the chat `sid`: held while that chat is being sent to this tab, dropped while it is stale."""
        if self.closed or sid in self.stale:
            return
        held = self.holds.get(sid)
        if held is None:
            self._put(raw, sid)
            return
        held.append((raw, sid))
        self.hold_bytes += len(raw)
        if self.qbytes + self.hold_bytes > CLIENT_QUEUE_BYTES:
            self._overflow()

    def put_frames(self, sid: str, raw: str) -> None:
        """Replayed frames of `sid` (one JSON array): queued now, never held."""
        if not self.closed and sid not in self.stale:
            self._put(raw, sid)

    def unhold(self, sid: str) -> list:
        held = self.holds.pop(sid, None) or []
        self.hold_bytes -= sum(len(r) for r, _ in held)
        return held

    def put_held(self, entries: list) -> None:
        for raw, sid in entries:
            if self.closed:
                return
            if sid is None or sid not in self.stale:
                self._put(raw, sid)

    def _put(self, raw: str, sid: str | None) -> None:
        self._q.append((raw, sid))
        self.qbytes += len(raw)
        if sid is None:
            self.kept_bytes += len(raw)
        self._wake.set()
        if self.qbytes + self.hold_bytes > CLIENT_QUEUE_BYTES:
            self._overflow()

    def _overflow(self) -> None:
        """More than CLIENT_QUEUE_BYTES waits for this tab (it reads slower than its chats stream, or not at all). Its
        session frames are dropped - never responses or agent requests - and it is told to load those chats again;
        until it does, their frames are not queued. A replay of such a chat answers -32000 {resync: true}."""
        if self.qbytes - self.kept_bytes + self.hold_bytes > 0:
            lost: dict[str, list[int]] = {}
            kept: deque[tuple[str, str | None]] = deque()
            for raw, sid in self._q:
                if sid is None:
                    kept.append((raw, sid))
                else:
                    x = lost.setdefault(sid, [0, 0])
                    x[0] += 1
                    x[1] += len(raw)
            for sid, held in self.holds.items():
                if held:
                    x = lost.setdefault(sid, [0, 0])
                    x[0] += len(held)
                    x[1] += sum(len(r) for r, _ in held)
                    held.clear()
            self._q, self.qbytes, self.hold_bytes = kept, self.kept_bytes, 0
            for sid, (frames, nbytes) in lost.items():
                self.stale.add(sid)
                self.dropped[sid] = self.dropped.get(sid, 0) + 1
                log.warning("tab queue overflow (profile %s, user %s, session %s): dropped %d frame(s), %d bytes; the "
                            "tab is told to load the chat again", self.key, self.user.get("username"), sid, frames,
                            nbytes)
                raw = json.dumps({"jsonrpc": "2.0", "method": RESYNC, "params": {"sessionId": sid}},
                                 separators=(",", ":"))
                self._q.append((raw, None))
                self.qbytes += len(raw)
                self.kept_bytes += len(raw)
            self._room.set()   # a replay waiting for this tab stops now (it answers {resync: true})
        if self.kept_bytes > CLIENT_QUEUE_HARD_BYTES:
            log.warning("tab queue full (profile %s, user %s): %d bytes of responses and requests unread; closing the "
                        "socket", self.key, self.user.get("username"), self.kept_bytes)
            self.disconnect("queue full", kind="queue-full")

    async def wait_room(self) -> None:
        """Until the tab has at most REPLAY_QUEUE_BYTES left to receive (or the socket is gone)."""
        while self.qbytes > REPLAY_QUEUE_BYTES and not self.closed:
            self._room.clear()
            await self._room.wait()

    def close(self, reason: str = "") -> None:
        if reason and not self.reason:
            self.reason = reason
        self.closed = True
        self._room.set()
        if self.task:
            self.task.cancel()

    def disconnect(self, reason: str = "", kind: str = "kick") -> None:
        """SC-3: end this socket now (user deleted / disabled / signed out elsewhere): nothing it sends is handled.
        Also a tab that never reads (kind queue-full)."""
        if self.closed and self.kick is None:
            return
        self.close(kind)
        kick, self.kick = self.kick, None
        if kick is not None:
            try:
                kick()
            except Exception:
                log.exception("closing a socket (%s)", reason)


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
        # SA-1: toolCallIds Goose asked permission for (the gateway saw the request) - a guarded tool call that runs
        # without one bypassed the guard; and the ones already reported
        self.asked: OrderedDict[str, None] = OrderedDict()
        self.bypassed: OrderedDict[str, None] = OrderedDict()
        self.closed = False   # SC-3: the user was deleted; this object must not write state any more
        self.starting = 0     # prompts / tool calls between "not draining" and Goose (guard checks, worker start-up)
        # FIX idle-sessions-keep-mcp-servers: which chats Goose holds an agent (and its MCP servers) for; closes idle ones
        self.unloader = Unloader(self)

    # ------------------------------------------------------------ connection
    @property
    def worker(self) -> Worker:
        return self.hub.workers.workers[self.key]

    def _channel_gone(self) -> bool:
        """A stdio worker whose process has exited while its connection still looks ready (RC5 of
        chat-open-replay-overflow): nothing sent to it is ever answered."""
        proc = getattr(self.ws, "proc", None)
        try:
            return proc is not None and proc.poll() is not None
        except Exception:
            return False

    async def ensure(self) -> None:
        if self.state == "ready" and self.ws is not None:
            if not self._channel_gone():
                return
            log.warning("the Goose worker of %s has exited but its connection looked ready: reconnecting", self.key)
            await self.reset(WORKER_RESTARTING)
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
            self.unloader.start()   # FIX idle-sessions-keep-mcp-servers: its loop (ends when this Upstream is closed)

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
        # tabs opening a chat: from Goose (the load's pending entry has no client) or from the buffer cleared below
        err = {"code": -32000, "message": reason}
        for s in self.sessions.values():
            ld, s.loading, s.abandoned = s.loading, None, None
            if ld is not None:
                if ld.timer is not None:
                    ld.timer.cancel()
                for w in list(ld.waiters):
                    self._fail_waiter(w, err)
        for c in list(self.clients):
            for w in list(c.replays.values()):
                self._fail_waiter(w, err)
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
            # B-1 (review 2026-11-12): the bytes leave the gateway-wide total too. They used to stay counted after
            # every worker stop, until the phantom total made evict_buffers run on every streamed chunk.
            self.hub.total_buffer = max(0, self.hub.total_buffer - s.buffer_bytes)
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
        ws = self.ws
        if ws is None:
            raise RpcError(-32000, "Goose is not connected")
        try:
            await ws.send(json.dumps(obj, separators=(",", ":")))
        except (OSError, websockets.ConnectionClosed) as e:   # OSError: also a stdio channel's ConnectionError
            # RC5: the caller answers the tab and drops the pending entry, as for any RpcError
            log.warning("sending to the Goose worker of %s failed: %s", self.key, e.__class__.__name__)
            raise RpcError(-32000, WORKER_RESTARTING) from e

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
            if len(self.sessions) >= SESSION_STATES_MAX:
                self._prune_sessions()
            s = self.sessions[sid] = SessionState(sid=sid)
        s.last_touch = time.time()
        return s

    def _prune_sessions(self) -> None:
        """Review 2026-11-12, B-7: one state per session id a client names, never dropped - a member's script could
        grow the gateway's memory without bound. Beyond SESSION_STATES_MAX the states nobody needs go, oldest
        first: not running, nothing queued or being steered or loaded, no open request, no tab showing them. Such a
        chat is simply loaded from Goose again when somebody opens it."""
        watched = {x for c in self.clients for x in c.watch}
        asked = {a["sessionId"] for a in self.asks.values()}
        # a request about a session that Goose has not answered yet holds on to that session's state
        asked |= {str(e[4].get("sessionId") or "") for e in self.pending.values()
                  if len(e) > 4 and isinstance(e[4], dict)}
        idle = sorted((s for s in self.sessions.values()
                       if not s.running() and not s.queue and not s.steers and s.loading is None
                       and s.abandoned is None and s.sid not in watched and s.sid not in asked),
                      key=lambda s: s.last_touch)
        for s in idle[:max(1, len(self.sessions) - SESSION_STATES_MAX * 9 // 10)]:
            self.unloader.before_forget(s)   # FIX idle-sessions-keep-mcp-servers: Goose closes a chat it holds first
            if self.sessions.pop(s.sid, None) is not None:
                # what it had buffered leaves the gateway-wide count with it (as when a chat is closed)
                self.hub.total_buffer = max(0, self.hub.total_buffer - s.buffer_bytes)

    async def from_client(self, client: Client, msg: dict) -> None:
        """A frame from a browser socket. While the gateway drains before a restart, new turns are refused; a turn
        that passed this point is counted (`starting`) until Goose has it, so the deploy's last check sees it."""
        if msg.get("method") not in DRAIN_REFUSED:
            return await self._from_client(client, msg)
        if self.hub.draining is not None and not client.closed and not self.closed:
            if msg.get("id") is not None:
                client.send({"jsonrpc": "2.0", "id": msg["id"],
                             "error": {"code": RPC_DRAINING, "message": DRAIN_REFUSAL}})
            return
        self.starting += 1
        try:
            await self._from_client(client, msg)
        finally:
            self.starting -= 1

    def busy(self) -> list[dict]:
        """What runs in this profile's worker right now, as the gateway knows it (the deploy's idle check)."""
        out: list[dict] = []
        base = {"profile": self.key, "username": self.username}
        listed: set[str] = set()
        asked = {a["sessionId"] for a in self.asks.values()}
        for s in self.sessions.values():
            if s.running():
                listed.add(s.sid)
                out.append({**base, "sessionId": s.sid, "title": s.title, "status": s.status, "since": s.since,
                            "kind": "permission" if s.sid in asked or s.status == "needs_you" else "turn",
                            "detail": f"{s.prompts} prompt(s) waiting for Goose" if s.prompts else ""})
        for a in self.asks.values():
            if a["sessionId"] not in listed:
                listed.add(a["sessionId"])
                out.append({**base, "sessionId": a["sessionId"], "title": "", "status": "needs_you", "since": None,
                            "kind": "permission", "detail": str(a["msg"].get("method") or "")})
        for entry in list(self.pending.values()):
            if entry[3] == pol.TOOLS_CALL:
                p = entry[4] if isinstance(entry[4], dict) else {}
                out.append({**base, "sessionId": str(p.get("sessionId") or ""), "title": "", "status": "working",
                            "since": None, "kind": "tool", "detail": f"tool call {str(p.get('name') or '')[:80]}"})
        if self.starting:
            out.append({**base, "sessionId": "", "title": "", "status": "working", "since": time.time(),
                        "kind": "starting", "detail": f"{self.starting} new prompt(s) being checked"})
        return out

    async def running_jobs(self) -> list[dict]:
        """Jobs of Goose's scheduler running inside this worker (they never pass through the gateway)."""
        base = {"profile": self.key, "username": self.username, "kind": "schedule"}
        try:
            r = await asyncio.wait_for(self.request(P_SCHEDULES_LIST, {}, timeout=None), 8.0)
        except RpcError as e:
            if e.code == -32601:   # this Goose has no schedules API: nothing to ask
                return []
            return [{**base, "sessionId": "", "title": "", "status": "unknown", "since": None,
                     "detail": f"could not list the scheduler's jobs: {e.message}"}]
        except (asyncio.TimeoutError, OSError) as e:
            return [{**base, "sessionId": "", "title": "", "status": "unknown", "since": None,
                     "detail": f"could not list the scheduler's jobs: {e.__class__.__name__}"}]
        out = []
        jobs = r.get("jobs") if isinstance(r, dict) else None
        for j in jobs if isinstance(jobs, list) else []:
            if isinstance(j, dict) and j.get("currentlyRunning"):
                since = None
                try:
                    from datetime import datetime
                    since = datetime.fromisoformat(str(j.get("jobStartTime")).replace("Z", "+00:00")).timestamp()
                except (TypeError, ValueError):
                    pass
                out.append({**base, "sessionId": str(j.get("currentSessionId") or ""),
                            "title": f"scheduled job {str(j.get('id') or '')[:80]}", "status": "working",
                            "since": since, "detail": ""})
        return out

    async def _from_client(self, client: Client, msg: dict) -> None:
        if client.closed or self.closed:   # SC-3: a socket of a deleted / disabled / signed-out user
            return
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
        load: UpstreamLoad | None = None
        try:
            pol.check(method, params, is_admin=client.is_admin, policy=client.policy, roots=client.roots)
            if method == "session/new" and client.is_admin:
                self._confirm_plugins(client, params)   # SD-2
            if method in RECIPE_METHODS:
                await self._guard_recipes(client, method, params)
            if method in CHAT_ACTIVITY and method not in ("session/prompt", STEER):
                self.hub.audit_activity(client, self, method, params)
            if self.hub.guard is not None:
                if method in GUARDED_TEXT_METHODS and await self._guard_texts(client, mid, method, params):
                    return   # SA-6
                if method == pol.TOOLS_CALL:
                    await self._guard_direct_tool(client, params)   # SA-7
                if method in (EXT_ADD, P_CFG_EXT_ADD) and not client.is_admin:
                    self._check_trusted_collision(params)   # SA-8
            if method == "initialize":
                await self.ensure()
                return self._reply(client, mid, self.init_result)
            if method == "_goose/unstable/recipes/delete" and not client.is_admin:
                await self._guard_recipe_delete(params)
            if method in ("session/prompt", TRUNCATE) and \
                    self.hub.elsewhere_running(self.key, str(params.get("sessionId") or "")):
                raise RpcError(RPC_ELSEWHERE, ELSEWHERE_REFUSAL)   # spec 020: two writers would corrupt the chat
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
            elif method == STEER:
                self._check_steer_limits(params)   # SC-4
                # a steer becomes a user message of the run: the same prompt guard applies (it was not checked < 1.15)
                if self.hub.guard is not None and await self._guard_prompt(client, mid, params, steer=True):
                    return
            if method in ("session/prompt", STEER):
                self.hub.audit_activity(client, self, method, params)   # SA-10: only what passed the guard
            await self.ensure()
            # FIX idle-sessions-keep-mcp-servers (unload.py): wait while the gateway closes this chat; a chat it unloaded
            # is loaded again (silently) before a method that needs its agent
            await self.unloader.before_forward(method, params)
            if method == "session/load":
                load = await self._open_chat(client, mid, params)
                if load is None:
                    return   # answered from the buffer, or waiting for the load of this chat already in flight
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
            s.wrote_at = time.time()
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
                    if c is not client and (s.sid in c.watch or s.sid in c.holds):
                        c.push(s.sid, echo)
        self.hub.audit_call(client, self, method, params)
        if mid is None:  # notification (e.g. session/cancel)
            try:
                await self._send({"jsonrpc": "2.0", "method": method, "params": params})
            except RpcError:
                pass   # nobody to answer; the worker's restart is announced to every tab
            return
        if load is not None:
            await self._send_load(load, params)
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
        """Check a prompt against the typing user's guard AND, when someone else types into this profile (an
        administrator viewing it), the profile owner's guard (SC-1: text entering a member's agent always passes the
        member's guard). True = refused (the reply is sent here); False = go on.
        Administrators: an Auto chat bypasses their own guard; a Smart approve chat is refused while it is on (its
        read-only skip would hide tool calls from the guard)."""
        typer = str(client.user.get("username") or "")
        ctxs = []
        c1 = self.hub.guard_ctx(typer)
        if c1 is not None:
            ctxs.append(c1)
        if typer.lower() != self.key:
            c2 = self.hub.guard_ctx(self.username)
            if c2 is not None:
                ctxs.append(c2)
        if not ctxs:
            return False
        sid = str(params.get("sessionId") or "")
        s0 = self.sessions.get(sid)
        mode = guardmod.session_mode(s0.load_result if s0 else None)
        g = self.hub.guard
        for ctx in ctxs:
            if ctx.kind == "admin":
                if mode == "auto":
                    continue
                if mode == "smart_approve":
                    raise pol.Denied("the prompt guard for administrators is on: use Approve (guarded) or Auto (not "
                                     "guarded) for this chat; Smart approve would skip tools the guard must see")
            own = ctx.username.lower() == typer.lower()
            d = (g.burst_decision(ctx.username, "prompt") if own else None) or await g.check_prompt(ctx, params)
            if not d.blocked:
                continue
            self.hub.audit_guard(self, sid, ctx, d, mode=mode, actor=client)
            if own and d.rule != guardmod.BURST_ID:
                g.note_block(ctx.username)
            if ctx.on_block == "silent" and not steer and not d.builtin:   # a steer has no stop reason: refused openly
                self._reply(client, mid, {"stopReason": "refusal"})
            elif mid is not None:
                client.send({"jsonrpc": "2.0", "id": mid, "error": {
                    "code": RPC_FORBIDDEN, "message": guard_message(d, "message", client.is_admin)}})
            return True
        return False

    async def _guard_texts(self, client: Client, mid: Any, method: str, params: dict) -> bool:
        """SA-6: a system prompt, saved prompt, recipe or imported conversation of a guarded user is checked like a
        prompt (rules for prompts + the classifier). True = refused."""
        texts: list[str] = []
        if method == P_SESSION_IMPORT:
            try:
                data = json.loads(params.get("input") or "")
            except (TypeError, ValueError):
                data = None
            if isinstance(data, dict):
                texts = guardmod.argument_texts({k: data.get(k) for k in (
                    "conversation", "messages", "system_prompt_override", "system_prompt_extras", "recipe")}, ["*"])
        else:
            texts = guardmod.argument_texts({k: v for k, v in params.items() if k != "sessionId"}, ["*"])
        text = "\n".join(t for t in texts if t and t.strip())
        if not text:
            return False
        return await self._guard_prompt(client, mid, {"sessionId": params.get("sessionId") or "",
                                                      "prompt": [{"type": "text", "text": text}]}, steer=True)

    async def _guard_direct_tool(self, client: Client, params: dict) -> None:
        """SA-7: a direct tools/call (MCP Apps) of a guarded profile runs the tool check of the caller's and the
        profile owner's guard; blocked or too long to inspect = refused."""
        typer = str(client.user.get("username") or "")
        ctxs = [c for c in (self.hub.guard_ctx(typer),
                            self.hub.guard_ctx(self.username) if typer.lower() != self.key else None) if c is not None]
        if not ctxs:
            return
        sid = str(params.get("sessionId") or "")
        s0 = self.sessions.get(sid)
        mode = guardmod.session_mode(s0.load_result if s0 else None)
        ext = str(params.get("extensionName") or "")
        name = str(params.get("name") or params.get("toolName") or "")
        tool = name if "__" in name or not ext else f"{ext}__{name}"
        for ctx in ctxs:
            if ctx.kind == "admin" and mode == "auto":
                continue
            d = await self.hub.guard.check_tool(ctx, tool, ext, params.get("arguments"), sid=sid)
            if d.blocked or d.classifier == "not_inspected":
                if not d.blocked:
                    d = guardmod.Decision(True, "tool", guardmod.TOO_LONG_ID, "prompt guard", None,
                                          "The arguments are too long for the prompt guard to check.",
                                          classifier="not_inspected")
                self.hub.audit_guard(self, sid, ctx, d, tool=tool, ext=ext, mode=mode, actor=client)
                raise pol.Denied(guard_message(d, "tool call", client.is_admin).removeprefix("forbidden: "))

    def _check_trusted_collision(self, params: dict) -> None:
        """SA-8: a member cannot add an extension whose name is one of the team guard's trusted extensions (its calls
        would skip the rules and the classifier)."""
        ctx = self.hub.guard_ctx(self.username)
        if ctx is None or not ctx.trusted:
            return
        ext = params.get("extension") if isinstance(params.get("extension"), dict) else {}
        cfg = params.get("config") if isinstance(params.get("config"), dict) else {}
        names = [pol._ext_name(ext), pol._ext_name(cfg), params.get("name"), params.get("configKey"), params.get("key")]
        if any(n and guardmod.ext_key(n) in ctx.trusted for n in names):
            raise pol.Denied("this name belongs to an extension your team's prompt guard trusts; choose another name")

    def _check_steer_limits(self, params: dict) -> None:
        """SC-4: a steer is tracked until the agent reads it and comes back to the queue if it never does, so it obeys
        the queue's limits."""
        blocks = params.get("prompt")
        if isinstance(blocks, list) and blocks_size(blocks) > QUEUE_ITEM_BYTES:
            raise RpcError(-32602, "this message is too large to steer; send it after the run instead")
        s0 = self.sessions.get(str(params.get("sessionId") or ""))
        if s0 is not None and len(s0.steers) >= STEER_MAX_PENDING:
            raise RpcError(-32602, f"at most {STEER_MAX_PENDING} steers can wait for the agent's next step")

    def _confirm_plugins(self, client: Client, params: dict) -> None:
        """SD-2: Goose starts every plugin in <cwd>/.agents/plugins at session/new, unsandboxed for administrators. In
        a folder members can write (their profiles, team folders) an administrator must accept the exact list of
        plugins first (the SPA asks and resends with _meta['goose-web.allowPlugins'] = the names)."""
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        allow = meta.pop(ALLOW_PLUGINS_META, None)
        cwd = params.get("cwd")
        if not isinstance(cwd, str) or not cwd or not self.hub.member_writable(cwd):
            return
        found = pol.project_plugins(cwd)
        if not found:
            return
        if not (isinstance(allow, list) and sorted(str(x) for x in allow) == sorted(found)):
            raise RpcError(RPC_FORBIDDEN, "this folder can be written by members and has Goose plugins in "
                                          f".agents/plugins ({', '.join(n[:40] for n in found[:10])}); plugins run "
                                          "programs on this computer as you. Confirm them to start the chat.",
                           {"plugins": found, "confirm": ALLOW_PLUGINS_META, "cwd": cwd})
        if self.hub.on_audit:
            self.hub.on_audit(client, "chat.plugins_allowed", cwd[:300], {"plugins": found[:50]}, True)

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
        g = self.hub.guard
        try:
            d = g.burst_decision(ctx.username, "tool") or await g.check_tool(ctx, tool, ext, tc.get("rawInput"), sid=sid)
        except Exception:
            # the rules fail closed inside check_tool; this is an unexpected bug: block rather than allow
            log.exception("prompt guard tool check")
            d = guardmod.Decision(True, "tool", guardmod.ERROR_ID, "prompt guard", None,
                                  "The prompt guard could not check this call, so it was blocked.",
                                  classifier="unavailable")
        answer = None
        if d.blocked:
            answer = "reject_once"
            if d.rule != guardmod.BURST_ID:
                g.note_block(ctx.username)
        elif d.classifier == "not_inspected":
            # SA-4: too long for the classifier - never auto-allowed; the user decides on the card
            s = self.sessions.get(sid)
            self.hub.audit_guard(self, sid, ctx, d, tool=tool, ext=ext, action="guard.not_inspected",
                                 mode=guardmod.session_mode(s.load_result if s else None))
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
                if ctx.on_block == "notify" or d.builtin:
                    for c in list(self.clients):
                        if sid in c.watch or not sid:
                            why = ("" if d.builtin else f" (rule {d.rule})" if d.rule and (c.is_admin or ctx.kind == "admin")
                                   else "" if d.rule else " (prompt-injection classifier)")
                            c.send({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
                                "level": "warning", "sessionId": sid, "kind": "guard",
                                "message": f"The prompt guard blocked a call to {tool[:120]}{why}"
                                           + (f": {d.message}" if d.message else ".")}})
            return
        opts = params.get("options")
        if isinstance(opts, list):
            keep = [o for o in opts if not (isinstance(o, dict) and
                                            (o.get("kind") == "allow_always" or o.get("optionId") == "allow_always"))]
            msg = {**msg, "params": {**params, "options": keep}}
            raw = json.dumps(msg, separators=(",", ":"))
        self._register_ask(msg, raw, guarded=True)

    def _check_bypass(self, s: SessionState, u: dict) -> None:
        """SA-1: in a guarded profile Goose must ask before every tool runs (Approve mode; Goose 1.57
        permission_inspector). A tool call that starts or finishes without a permission request the gateway saw was
        never checked: an "always allow" entry (written into permission.yaml by the agent itself, or left from
        before), a provider that runs tools itself, or a Goose that did not ask. Cancel the run, audit guard.bypass,
        tell the chat and the administrators; the app re-provisions an isolated profile and restarts its worker."""
        tid = str(u.get("toolCallId") or "")
        if not tid or tid in self.asked or tid in self.bypassed:
            return
        ctx = self.hub.guard_ctx(self.username)
        if ctx is None:
            return
        mode = guardmod.session_mode(s.load_result)
        if ctx.kind == "admin" and mode == "auto":   # administrators' Auto chats are unguarded by design
            return
        self.bypassed[tid] = None
        while len(self.bypassed) > 1000:
            self.bypassed.popitem(last=False)
        tool, ext = guardmod.tool_identity(u, self.tool_meta.get(tid))
        log.warning("prompt guard bypass in %s/%s: %s ran without a permission request (mode %s)", self.key, s.sid,
                    tool, mode or "?")
        s.cancel_requested = True

        async def cancel():
            try:
                await self._send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": s.sid}})
            except Exception:
                pass
        self._spawn(cancel())
        d = guardmod.Decision(True, "tool", BYPASS_ID, "prompt guard", None,
                              "Goose ran this tool without asking first, so the guard could not check it.")
        self.hub.audit_guard(self, s.sid, ctx, d, tool=tool, ext=ext, mode=mode, action="guard.bypass")
        text = (f"The prompt guard stopped this chat: {tool[:120]} ran without the permission request the guard "
                "checks (an 'Always allow' setting or a provider that runs tools itself). The run was cancelled and "
                "an administrator was told.")
        note = {"jsonrpc": "2.0", "method": "_gw/notice", "params": {"level": "error", "sessionId": s.sid,
                                                                       "kind": "guard", "message": text}}
        for c in list(self.clients):
            if s.sid in c.watch:
                c.send(note)
        self.hub.broadcast_admins({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
            "level": "error", "kind": "guard",
            "message": f"Prompt guard bypass in the profile {self.username}: {tool[:120]} ran without a permission "
                       "request; the run was cancelled (activity log: guard.bypass)."}})
        if self.hub.on_guard_bypass is not None:
            try:
                self.hub.on_guard_bypass(self.key, self.username)
            except Exception:
                log.exception("guard bypass handler")

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
                # her profile, her allowed folders, and the folders of the recipes her teams gave her (Goose reads
                # those through GOOSE_RECIPE_PATH; they are outside the profile)
                mine = [self.hub.profile_root_for(self.username), *(client.roots or []),
                        *self.hub.recipe_dirs_for(self.username)]
                await asyncio.to_thread(self._check_sub_recipes, recipe, client.policy, enabled or {}, base, 0, [0],
                                        mine)
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
                           count: list, roots: list[str] | None = None) -> None:
        """Every sub-recipe file must be readable and pass check_recipe too (members; fail closed).

        The file is read by the gateway, with the gateway's rights, at a path the member names (review 2026-11-12,
        B-8). So only what the member may read anyway is read: a regular file of at most 1 MB inside the member's
        own folders (`roots`: the profile and the allowed folders; links resolved) - never a network or device
        path, never another member's file, whose title and extensions the refusal would otherwise quote."""
        from . import security
        for sr in recipe.get("sub_recipes") or []:
            count[0] += 1
            if depth >= 5 or count[0] > 50:
                raise pol.Denied("the recipe nests too many sub-recipes to check")
            path = str((sr or {}).get("path") or "") if isinstance(sr, dict) else ""
            if not path or "\x00" in path:
                raise pol.Denied("a sub-recipe of this recipe has no readable path")
            p = path if os.path.isabs(path) else os.path.join(base or "", path)
            if security.is_unc_path(p) or not pol.path_allowed(p, [r for r in (roots or []) if r]):
                raise pol.Denied(f"the sub-recipe '{path[:120]}' is not in one of your folders, so it cannot be "
                                 "checked")
            try:
                import stat
                import yaml
                with open(p, "rb") as fh:           # one open: what is judged is what is read
                    st = os.fstat(fh.fileno())
                    if not stat.S_ISREG(st.st_mode) or st.st_size > 1_048_576:
                        raise OSError("not a regular file of at most 1 MB")
                    # S-5: the path was judged before it was opened. Where the open really ended (a link put in
                    # between) is asked of the open file; elsewhere than in the member's folders = not read.
                    final = security.final_path(fh.fileno())
                    if final is not None and not pol.path_allowed(final, [r for r in (roots or []) if r]):
                        raise OSError("the file that was opened is not in one of the member's folders")
                    blob = fh.read(1_048_577)
                if len(blob) > 1_048_576:
                    raise OSError("more than 1 MB")
                data = yaml.safe_load(blob.decode("utf-8"))
            except Exception:
                raise pol.Denied(f"the sub-recipe '{path[:120]}' cannot be read, so it cannot be checked")
            if isinstance(data, dict) and isinstance(data.get("recipe"), dict) and "title" not in data:
                data = data["recipe"]
            pol.check_recipe(data, policy, enabled, what="the sub-recipe")
            self._check_sub_recipes(data, policy, enabled, os.path.dirname(p), depth + 1, count, roots)

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

    def _with_engines(self, result: Any) -> Any:
        """spec 021: tell the front end each provider's engine (custom_providers/*.json of this worker's profile), so
        it can say when Goose sends no thinking effort for a model. Never fails the reply."""
        from .config import default_native_goose_root
        try:
            root = Path(self.worker.path_root or default_native_goose_root())
            return effortmod.annotate_providers(result, effortmod.provider_engines(root / "config"))
        except Exception:
            log.debug("providers/list engine annotation skipped", exc_info=True)
            return result

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
            if fp is None or s.running() or s.fp_pending or s.loading is not None or s.abandoned is not None:
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

    # ------------------------------------------------------------ opening a chat (FIX chat-open-replay-overflow)
    def _load_timeout(self) -> float:
        s = getattr(self.hub.workers, "s", None)
        v = s.get("goose", "session_load_timeout_seconds", SESSION_LOAD_TIMEOUT) if s is not None else None
        try:
            return max(0.0, float(SESSION_LOAD_TIMEOUT if v is None else v))
        except (TypeError, ValueError):
            return float(SESSION_LOAD_TIMEOUT)

    async def _open_chat(self, client: Client, mid: Any, params: dict) -> UpstreamLoad | None:
        """session/load. A chat live in this worker, or idle and unchanged elsewhere, is replayed from the buffer; a
        load of it already in flight gets this tab as one more waiter (one upstream load per chat); otherwise a new
        upstream load is set up and returned for the caller to send."""
        sid = str(params.get("sessionId") or "")
        s = self.sess(sid)
        if mid is None:
            return None   # a load nobody waits for
        client.stale.discard(sid)   # the tab loads it again: its frames flow again
        self._drop_waiter(client, sid, "superseded by a newer load of this chat")
        # Idle: the buffer is only good while nobody else (Goose Desktop, the CLI, a schedule) has written the session
        # since. Compare the stored fingerprint with Goose's current one.
        if s.loading is None and s.abandoned is None and not s.running() and s.loaded and \
                s.load_result is not None and not s.truncated and s.fp is not None and not s.fp_pending:
            fp = await self._fingerprint(sid)
            if client.closed:
                return None
            if fp is not None and same_content(fp, s.fp) and s.loading is None and s.abandoned is None and \
                    not s.running() and s.loaded and s.load_result is not None and not s.truncated:
                self._replay(client, s, mid)
                return None
        if s.abandoned is not None:
            raise RpcError(-32000, f"Goose has not answered an earlier load of this chat (it did not answer within "
                                   f"{self._load_timeout():g} s): try again later")
        if s.loading is not None:
            self._open_waiter(s, client, mid, self._frames(s), load=s.loading)
            return None
        # Live in this worker: replay from the buffer (never reload a running session upstream).
        if s.loaded and s.running():
            self._replay(client, s, mid)
            return None
        self.hub.total_buffer -= s.buffer_bytes
        s.buffer.clear()
        s.buffer_bytes, s.truncated, s.fp = 0, False, None
        s.cwd = str(params.get("cwd") or s.cwd)
        ld = s.loading = UpstreamLoad(self._new_id())
        self._open_waiter(s, client, mid, [], load=ld)
        return ld

    @staticmethod
    def _frames(s: SessionState) -> list[str]:
        return [x.render() if isinstance(x, ChunkTail) else x for x in s.buffer]

    def _replay(self, client: Client, s: SessionState, mid: Any) -> None:
        """Send a chat from the hub buffer: its frames in batches at the tab's pace, then the load result as it was when
        the frames were taken. Frames arriving meanwhile are held and follow the result."""
        result = dict(s.load_result or {})
        meta = dict(result.get("_meta") or {})
        meta["gw"] = {"replayed": True, "running": s.running(), "truncated": s.truncated}
        result["_meta"] = meta
        client.watch.add(s.sid)
        self._open_waiter(s, client, mid, self._frames(s), final={"jsonrpc": "2.0", "id": mid, "result": result})

    def _open_waiter(self, s: SessionState, client: Client, mid: Any, frames: list[str], final: dict | None = None,
                     load: UpstreamLoad | None = None) -> LoadWaiter:
        w = LoadWaiter(client, s.sid, mid, client.dropped.get(s.sid, 0), final=final, load=load)
        client.replays[s.sid] = w
        if load is not None:
            load.waiters.append(w)
        if frames:
            client.holds[s.sid] = []   # taken together with the snapshot: nothing is lost or sent twice
            w.task = asyncio.create_task(self._catch_up(w, frames))
        elif final is not None:
            self._waiter_done(w)
        return w

    @staticmethod
    def _dropped(w: LoadWaiter) -> bool:
        return w.client.dropped.get(w.sid, 0) != w.gen

    async def _catch_up(self, w: LoadWaiter, frames: list[str]) -> None:
        c = w.client
        for batch in replay_batches(frames):
            await c.wait_room()
            if c.closed or self._dropped(w):
                break
            c.put_frames(w.sid, batch)
        # no await from here on: the held frames, the answer and later frames keep their order
        w.task = None
        held = c.unhold(w.sid)
        if c.closed:
            return
        if self._dropped(w):
            self._fail_waiter(w, RESYNC_ERROR)
            return
        if w.final is None:   # Goose has not answered yet: from now on this tab gets the load's frames as they come
            c.put_held(held)
            return
        c.put_held(held[:w.final_at])
        self._waiter_done(w)
        c.put_held(held[w.final_at:])

    def _waiter_done(self, w: LoadWaiter) -> None:
        c = w.client
        if c.replays.get(w.sid) is w:
            del c.replays[w.sid]
        if w.load is not None and w in w.load.waiters:
            w.load.waiters.remove(w)
        out = w.final
        if out is None or c.closed:
            return
        if "result" in out:
            if self._dropped(w):
                out = {"jsonrpc": "2.0", "id": w.mid, "error": RESYNC_ERROR}
            else:
                c.watch.add(w.sid)
        c.send(out)

    def _fail_waiter(self, w: LoadWaiter, err: dict) -> None:
        c = w.client
        if w.task is not None:
            w.task.cancel()
            w.task = None
            c.unhold(w.sid)
        if c.replays.get(w.sid) is w:
            del c.replays[w.sid]
        if w.load is not None and w in w.load.waiters:
            w.load.waiters.remove(w)
        if not c.closed:
            c.send({"jsonrpc": "2.0", "id": w.mid, "error": err})

    def _drop_waiter(self, client: Client, sid: str, why: str) -> None:
        w = client.replays.get(sid)
        if w is not None:
            self._fail_waiter(w, {"code": -32000, "message": why})

    def forget_client(self, client: Client) -> None:
        """The socket is gone: its loads stop waiting (an upstream load goes on and fills the buffer)."""
        for w in list(client.replays.values()):
            if w.task is not None:
                w.task.cancel()
                w.task = None
            if w.load is not None and w in w.load.waiters:
                w.load.waiters.remove(w)
        client.replays.clear()
        client.holds.clear()
        client.hold_bytes = 0

    async def _send_load(self, ld: UpstreamLoad, params: dict) -> None:
        """Send the chat's one upstream session/load (internal pending entry: the waiters are answered from it)."""
        sid = str(params.get("sessionId") or "")
        self.pending[ld.up_id] = (None, None, None, "session/load", params)
        t = self._load_timeout()
        if t > 0:
            ld.timer = asyncio.get_running_loop().call_later(t, self._load_watchdog, sid, ld)
        try:
            await self._send({"jsonrpc": "2.0", "id": ld.up_id, "method": "session/load", "params": params})
        except RpcError as e:
            self.pending.pop(ld.up_id, None)
            s = self.sessions.get(sid)
            if s is not None and s.loading is ld:
                s.loading = None
                if ld.timer is not None:
                    ld.timer.cancel()
                for w in list(ld.waiters):
                    self._fail_waiter(w, e.to_json())

    def _load_answered(self, up_id: int, params: dict, msg: dict) -> None:
        sid = str(params.get("sessionId") or "")
        s = self.sessions.get(sid)
        if s is None:
            return
        if s.abandoned == up_id:
            # the watchdog gave up on this load and its frames were dropped: the buffer does not hold the chat
            s.abandoned = None
            log.info("Goose answered the abandoned load of %s (profile %s) late", sid, self.key)
            return
        ld = s.loading
        if ld is None or ld.up_id != up_id:
            return
        s.loading = None
        if ld.timer is not None:
            ld.timer.cancel()
        self._post_response("session/load", params, msg, None)
        if "error" in msg and not s.running():
            self._invalidate(s)   # what Goose sent before the error is not the chat
        for w in list(ld.waiters):
            w.final = {"jsonrpc": "2.0", "id": w.mid, **({"error": msg["error"]} if "error" in msg
                                                         else {"result": msg.get("result")})}
            if w.task is not None:   # still catching up: the answer goes after the frames held so far
                w.final_at = len(w.client.holds.get(sid) or ())
            else:
                self._waiter_done(w)

    def _load_watchdog(self, sid: str, ld: UpstreamLoad) -> None:
        """Goose did not answer a session/load in goose.session_load_timeout_seconds: every waiting tab is answered,
        and Goose's late frames for it are dropped until its late answer arrives (a new load is refused meanwhile)."""
        s = self.sessions.get(sid)
        if s is None or s.loading is not ld:
            return
        t = self._load_timeout()
        s.loading = None
        s.abandoned = ld.up_id   # its pending entry stays: Goose's late answer ends this (_load_answered)
        log.warning("Goose did not answer session/load of %s within %g s (profile %s, %d tab(s) waiting)", sid, t,
                    self.key, len(ld.waiters))
        err = {"code": -32000, "message": f"Goose did not answer within {t:g} s"}
        for w in list(ld.waiters):
            self._fail_waiter(w, err)
        if not s.running():
            self._invalidate(s)

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
            if method == "session/load" and client is None and fut is None:
                self._load_answered(msg["id"], params, msg)   # the chat's one upstream load: answer its waiters
                return
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
                    if method == PROVIDERS_LIST:
                        out["result"] = self._with_engines(out["result"])
                client.send(out)
            return
        method = msg.get("method")
        params = msg.get("params") or {}
        if method in AGENT_REQUESTS and "id" in msg:
            if method == "session/request_permission" and self.hub.guard_active():
                tid = str(((params.get("toolCall") or {}) if isinstance(params.get("toolCall"), dict) else {})
                          .get("toolCallId") or "")
                if tid:   # SA-1: Goose asked about this call (the bypass detector below looks for calls it did not)
                    self.asked[tid] = None
                    while len(self.asked) > 5000:
                        self.asked.popitem(last=False)
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
            ld = s.loading
            if ld is None and s.abandoned is not None:
                return   # the late history of a load the watchdog gave up on: neither buffered nor sent
            replaying = ld is not None
            u0 = params.get("update") if isinstance(params.get("update"), dict) else {}
            self._herd_from_update(s, method, u0, replaying)
            if not replaying and u0.get("sessionUpdate") in ("tool_call", "tool_call_update") \
                    and u0.get("status") in ("in_progress", "completed") and self.hub.guard_active():
                self._check_bypass(s, u0)
            if s.loaded or replaying:
                self._buffer(s, raw, msg)
            if replaying:   # Goose's history goes only to the tabs waiting for this load
                for w in list(ld.waiters):
                    w.client.push(sid, raw)
            else:
                for c in list(self.clients):
                    if sid in c.watch or sid in c.holds:
                        c.push(sid, raw)
            return
        # other notifications (device-code, etc.)
        self.broadcast(raw)

    def _buffer(self, s: SessionState, raw: str, msg: dict | None = None) -> None:
        """Append one frame (msg: its parsed form). A text chunk of the same message as the chunk before it is merged
        into that one (FIX chat-open-replay-overflow: about one frame per message, as in Goose's own replay)."""
        key = chunk_key(msg) if msg is not None else None
        last = s.buffer[-1] if s.buffer else None
        if isinstance(last, ChunkTail):
            if key is not None and key == last.key:
                n = last.add(msg["params"]["update"]["content"]["text"])
                s.buffer_bytes += n
                self.hub.total_buffer += n
                self._trim(s)
                return
            text = s.buffer[-1] = last.render()   # the message's text is complete: serialize it once
            s.buffer_bytes += len(text) - last.size
            self.hub.total_buffer += len(text) - last.size
        n = len(raw)
        s.buffer.append(ChunkTail(msg, key, raw) if key is not None else raw)
        s.buffer_bytes += n
        self.hub.total_buffer += n
        self._trim(s)

    def _trim(self, s: SessionState) -> None:
        while (s.buffer_bytes > SESSION_BUFFER_BYTES or len(s.buffer) > SESSION_BUFFER_FRAMES) and len(s.buffer) > 1:
            old = s.buffer.popleft()
            n = old.size if isinstance(old, ChunkTail) else len(old)
            s.buffer_bytes -= n
            self.hub.total_buffer -= n
            s.truncated = True
        if self.hub.total_buffer > TOTAL_BUFFER_BYTES:
            self.hub.evict_buffers()

    def _post_response(self, method: str, params: dict, msg: dict, client: Client | None) -> None:
        if self.unloader.on_response(method, params, msg):
            return   # FIX idle-sessions-keep-mcp-servers: the unloader's own close (_gw/unload) - never the close branch
        result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        ok = "error" not in msg
        # Our own change to a buffered session (rename, mode, truncate, ...): re-baseline its fingerprint so
        # the watcher does not mistake it for an outside write.
        sid0 = str(params.get("sessionId") or "") if isinstance(params, dict) else ""
        if sid0 and method in ("session/prompt", STEER, TRUNCATE):
            sw = self.sessions.get(sid0)
            if sw is not None:   # spec 020: these messages were Goose Web's, not another program's (only methods
                sw.wrote_at = time.time()   # that write messages: opening a chat lists extensions etc.)
        if ok and sid0 and method not in _READ_ONLY_SESSION_METHODS and method not in ("session/new",):
            s0 = self.sessions.get(sid0)
            if s0 is not None and s0.loaded and method not in ("session/delete", "session/close"):
                self._refresh_fp_soon(s0)
        if method == "session/new" and ok:
            sid = str(result.get("sessionId") or "")
            if sid:
                s = self.sess(sid)
                s.loaded, s.load_result, s.cwd = True, result, str(params.get("cwd") or "")
                s.wrote_at = time.time()
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
                    # S-8: a prompt for a session Goose never loaded here (any id a script makes up) must not keep
                    # its state alive by being "watched" for as long as the socket lives
                    if client is not None and s.load_result is None:
                        client.watch.discard(s.sid)
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
                self._save(sid0, None, None)   # its queue and herd mark go too
            if s:
                self.hub.total_buffer -= s.buffer_bytes
                self.broadcast_herd(s, removed=True)
                if s.queue:
                    self.broadcast({"jsonrpc": "2.0", "method": "_gw/queue_update",
                                    "params": {"sessionId": s.sid, "items": []}})
        elif method == "session/list" and ok and isinstance(params, dict) and not params.get("cursor") \
                and not params.get("cwd") and not params.get("_meta") and not result.get("nextCursor") \
                and isinstance(result.get("sessions"), list):
            # SC-7: the complete list of this profile's chats - queue rows / marks of chats deleted elsewhere go
            self.hub.prune_chat_state(self.key, {str(x.get("sessionId")) for x in result["sessions"]
                                                 if isinstance(x, dict)})
        elif method == "_goose/unstable/session/rename" and ok:
            s = self.sess(str(params.get("sessionId") or ""))
            s.title = str(params.get("title") or s.title)
            self._herd_changed(s)
        elif method.startswith("_goose/unstable/schedules/") and ok and method != P_SCHEDULES_LIST:
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
            self._save(s.sid, "mark", mark)
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
        the front of the chat's queue, held, so the user can send, edit or drop them - and tell every tab. The
        queue's limits apply (SC-4): the newest steers that fit are kept, a notice says how many were dropped."""
        back = [e for e in s.steers if e["state"] == "pending"]
        if not back:
            return
        s.steers = [e for e in s.steers if e["state"] != "pending"]
        note = STEER_RETURNED.get(reason, STEER_RETURNED["ended"])
        items = [queue_item(e["blocks"], e["by"], iid=e["id"], at=e["at"], held=True, steer=True, note=note)
                 for e in back]
        room = max(0, QUEUE_MAX_ITEMS - len(s.queue))
        budget = QUEUE_PROFILE_BYTES - self.queued_bytes()
        keep: list[dict] = []
        for it in reversed(items):   # newest first
            if len(keep) < room and it["bytes"] <= QUEUE_ITEM_BYTES and it["bytes"] <= budget:
                keep.insert(0, it)
                budget -= it["bytes"]
        dropped = len(items) - len(keep)
        if not s.queue and keep and sum(1 for x in self.sessions.values() if x.queue) >= QUEUE_MAX_SESSIONS:
            dropped, keep = len(items), []
        s.queue[0:0] = keep
        log.info("session %s: %d steer(s) not delivered (%s), %d returned to the queue", s.sid, len(back), reason,
                 len(keep))
        kept = {it["id"] for it in keep}
        for e in back:
            self._steer_update(s, e, "returned" if e["id"] in kept else "dropped", reason=reason, note=note)
        if dropped:
            self.broadcast({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
                "level": "warning", "sessionId": s.sid, "kind": "queue", "message": QUEUE_DROPPED.format(n=dropped)}})
        self._queue_changed(s)

    def _save(self, sid: str, kind: str | None, data: Any) -> None:
        if not self.closed:   # SC-3: a deleted user's Upstream never writes again
            self.hub.save_chat_state(self.key, sid, kind, data)

    def queued_bytes(self) -> int:
        return sum(int(x.get("bytes") or 0) for s in self.sessions.values() for x in s.queue)

    def _queue_changed(self, s: SessionState) -> None:
        self._save(s.sid, "queue", list(s.queue) or None)
        # SC-2: tabs get the rows (id, author, time, preview, size), never the whole messages
        self.broadcast({"jsonrpc": "2.0", "method": "_gw/queue_update",
                        "params": {"sessionId": s.sid, "items": [item_view(x) for x in s.queue]}})

    def queue_op(self, client: Client, params: dict) -> dict:
        """_gw/queue: add / remove / take (a tab claims the item it is about to send; first claim wins) / list.
        SC-1/SC-6: only the profile owner's tab may take an item automatically, and only an item that user queued;
        anything else needs a click (manual). SC-8: takes and removes by someone else are audited."""
        if self.closed or client.closed:
            raise RpcError(-32000, "this account was signed out")
        sid = str(params.get("sessionId") or "")
        op = params.get("op")
        if not sid or len(sid) > 200:
            raise RpcError(-32602, "sessionId is required")
        s = self.sessions.get(sid)
        me = _ukey(client.user)
        if op == "list":
            return {"items": [item_view(x) for x in s.queue] if s else []}
        if op == "add":
            blocks = params.get("blocks")
            if not isinstance(blocks, list) or not blocks or not all(isinstance(b, dict) for b in blocks):
                raise RpcError(-32602, "blocks must be a non-empty list of content blocks")
            size = blocks_size(blocks)
            if size > QUEUE_ITEM_BYTES:
                raise RpcError(-32602, "this message is too large to queue")
            if s is None:   # SC-9: only chats this profile has open; nothing is created before the checks
                raise RpcError(-32602, "this chat is not open in Goose Web; open it first")
            if len(s.queue) >= QUEUE_MAX_ITEMS:
                raise RpcError(-32602, f"at most {QUEUE_MAX_ITEMS} messages can wait in a chat's queue")
            if not s.queue and sum(1 for x in self.sessions.values() if x.queue) >= QUEUE_MAX_SESSIONS:
                raise RpcError(-32602, f"at most {QUEUE_MAX_SESSIONS} chats can have queued messages")
            if self.queued_bytes() + size > QUEUE_PROFILE_BYTES:
                raise RpcError(-32602, f"the queued messages of this profile are limited to "
                                       f"{QUEUE_PROFILE_BYTES // (1024 * 1024)} MB together; send or remove some first")
            item = queue_item(blocks, str(client.user.get("username") or ""))
            s.queue.append(item)
            self._queue_changed(s)
            return {"ok": True, "id": item["id"], "items": [item_view(x) for x in s.queue]}
        if op in ("remove", "take"):
            qid = params.get("id")
            item = next((x for x in s.queue if x.get("id") == qid), None) if s else None
            manual = bool(params.get("manual"))
            refused = item is None or (op == "take" and not manual and (
                item.get("held") or me != self.key or str(item.get("by") or "").lower() != me))
            if refused:
                # a held item (returned steer, kept across a restart), someone else's item, or a tab that is not the
                # owner's is only sent by a click
                return {"ok": False, "items": [item_view(x) for x in s.queue] if s else []}
            s.queue.remove(item)
            self._queue_changed(s)
            if me != self.key or str(item.get("by") or "").lower() != me:
                if self.hub.on_audit:
                    self.hub.on_audit(client, f"queue.{op}", sid, {"profile": self.key, "item": item.get("id"),
                                                                   "queuedBy": item.get("by"), "manual": manual}, True)
            return {"ok": True, "item": item, "items": [item_view(x) for x in s.queue]}
        raise RpcError(-32602, "op must be add, remove, take or list")

    def restore_state(self, rows: list[dict]) -> None:
        """Spec 019: the herd marks and queues this profile had before the gateway restarted (within the queue's
        limits: SC-4)."""
        now = time.time()
        budget = QUEUE_PROFILE_BYTES
        chats = 0
        for r in rows:
            sid, kind, data = r.get("session_id"), r.get("kind"), r.get("data")
            if not sid or not isinstance(data, (dict, list)):
                continue
            if kind == "queue" and isinstance(data, list):
                if chats >= QUEUE_MAX_SESSIONS:
                    continue
                items = []
                for x in data:
                    if not isinstance(x, dict) or not x.get("id") or not isinstance(x.get("blocks"), list):
                        continue
                    if len(items) >= QUEUE_MAX_ITEMS:
                        break
                    size = blocks_size(x["blocks"])
                    if size > QUEUE_ITEM_BYTES or size > budget:
                        continue
                    budget -= size
                    # the run these messages waited for ended with the old gateway: never send them by surprise
                    extra = {k: x[k] for k in ("steer",) if k in x}
                    items.append(queue_item(x["blocks"], str(x.get("by") or ""), iid=str(x["id"]),
                                            at=float(x.get("at") or now), held=True,
                                            note=x.get("note") if x.get("held") else QUEUE_RESTORED, **extra))
                if items:
                    self.sess(sid).queue = items
                    chats += 1
            elif kind == "mark" and isinstance(data, dict) and data.get("status") in MARK_STATUSES:
                if now - float(data.get("since") or 0) > MARK_MAX_AGE:
                    self._save(sid, "mark", None)
                    continue
                s = self.sess(sid)
                s.title, s.cwd = str(data.get("title") or ""), str(data.get("cwd") or "")
                s.last_text, s.since = str(data.get("lastText") or "")[:300], float(data.get("since") or now)
                s.status, s.error = data["status"], str(data.get("error") or "")
                s.wrote_at = s.since   # spec 020: the chat's last writes were Goose Web's own (not "elsewhere")
                if s.status in ("working", "needs_you"):   # its run ended with the old gateway and its workers
                    s.status, s.since = "error", now
                    s.wrote_at = now
                    s.error = "Interrupted: Goose Web restarted while this chat was running"
                    self._save(sid, "mark", {
                        "status": s.status, "since": s.since, "title": s.title, "cwd": s.cwd,
                        "lastText": s.last_text, "error": s.error})

    def snapshot(self) -> dict:
        """Spec 019: everything a tab needs to rebuild this user's live state (added to _gw/hello). Queue rows only
        (SC-2: a reconnect no longer downloads every queued message)."""
        steers = []
        for s in self.sessions.values():
            for e in s.steers:
                if e["state"] != "pending":
                    continue
                v = self._steer_view(s, e)
                if blocks_size(e["blocks"]) > 64 * 1024:   # a large steer is shown by its first words only
                    pv, att = blocks_preview(e["blocks"])
                    v["blocks"] = [{"type": "text", "text": pv + " ..." + (f" (+{att} attachment(s))" if att else "")}]
                steers.append(v)
        return {"queues": {s.sid: [item_view(x) for x in s.queue] for s in self.sessions.values() if s.queue},
                "steers": steers}

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
                sum(1 for s in self.sessions.values() if s.running()) + len(self.asks) + self.starting)


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
        self.recipe_dirs_for: Callable[[str], list[str]] = lambda u: []     # a member's team recipe folders
        self.guard: Any = None          # guard.GuardService (spec 018), wired by the app; None = no prompt guard
        self.db: Any = None             # db.Database, wired by the app: chat_state rows (spec 019); None = memory only
        # wired by the app: is a folder writable by members (SD-2), and what to do after a guard bypass (SA-1)
        self.member_writable: Callable[[str], bool] = lambda path: False
        self.on_guard_bypass: Callable[[str, str], None] | None = None
        # {since, until, reason} while a deploy drains the gateway before a restart (control.py); None = normal
        self.draining: dict | None = None
        self.elsewhere: dict[str, Any] = {}   # spec 020: profile key -> elsewhere.ElsewhereWatcher (native profiles)
        self.started = time.time()
        self._elsewhere_task: asyncio.Task | None = None
        self._flusher: asyncio.Task | None = None
        self._state_task: asyncio.Task | None = None
        # SC-2: chat_state writes wait here (latest value per row) and are written by a background task in a thread
        self._dirty: dict[tuple, Any] = {}
        self._dirty_event: asyncio.Event | None = None
        self._state_lock = __import__("threading").Lock()
        workers.activity = self._activity
        workers.on_restart = self._on_restart

    def start(self) -> None:
        self._flusher = asyncio.create_task(self._flush_loop())
        self._dirty_event = asyncio.Event()
        self._state_task = asyncio.create_task(self._state_loop())
        self._elsewhere_task = asyncio.create_task(self._elsewhere_loop())

    # ------------------------------------------------------------ running elsewhere (spec 020)
    def elsewhere_knobs(self) -> dict:
        from .elsewhere import DEFAULTS
        s = getattr(self.workers, "s", None)
        k = dict(DEFAULTS)
        if s is not None:
            for name in DEFAULTS:
                v = s.get("elsewhere", name)
                if v is not None:
                    k[name] = v
        return k

    def is_native(self, up: "Upstream") -> bool:
        w = getattr(self.workers, "workers", {}).get(up.key)
        return bool(w is not None and getattr(w, "native", False))

    def _elsewhere_watcher(self, up: "Upstream"):
        from .elsewhere import DONE_ROW, ElsewhereWatcher
        wt = self.elsewhere.get(up.key)
        if wt is None or wt.up is not up:
            state = None
            if self.db is not None:   # the Done markers survive a refresh, other devices and a restart
                try:
                    state = next((r["data"] for r in self.db.chat_state(up.key)
                                  if r["session_id"] == DONE_ROW and r["kind"] == "done"), None)
                except Exception:
                    log.exception("running elsewhere: reading the Done markers of %s", up.key)
            wt = self.elsewhere[up.key] = ElsewhereWatcher(
                up, self.elsewhere_knobs(), state,
                save=lambda st, key=up.key: self.save_chat_state(key, DONE_ROW, "done", st))
        return wt

    def elsewhere_push(self, up: "Upstream") -> None:
        wt = self.elsewhere.get(up.key)
        if wt is None:
            return
        raw = json.dumps({"jsonrpc": "2.0", "method": "_gw/elsewhere",
                          "params": {"items": wt.items, "done": wt.done(), "at": wt.ticked}}, separators=(",", ":"))
        for c in self._elsewhere_subs(up):
            c.send(raw)

    @staticmethod
    def _elsewhere_subs(up: "Upstream") -> list[Client]:
        return [c for c in up.clients if c.elsewhere and c.is_admin and not c.closed]

    async def elsewhere_tick(self, up: "Upstream") -> None:
        wt = self._elsewhere_watcher(up)
        wt.knobs = self.elsewhere_knobs()
        if await wt.tick():
            self.elsewhere_push(up)

    async def _elsewhere_loop(self) -> None:
        """Only native profiles, only while an administrator's tab asked for the list (no clients = no reads)."""
        while True:
            try:
                await asyncio.sleep(max(5.0, float(self.elsewhere_knobs()["poll_seconds"])))
                if not self.elsewhere_knobs()["enabled"]:
                    continue
                for up in list(self.upstreams.values()):
                    if not up.closed and self._elsewhere_subs(up) and self.is_native(up):
                        await self.elsewhere_tick(up)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("running elsewhere")

    def elsewhere_running(self, key: str, sid: str) -> bool:
        wt = self.elsewhere.get(key)
        return bool(sid) and wt is not None and sid in wt.running_ids()

    async def _flush_loop(self) -> None:
        n = 0
        while True:
            await asyncio.sleep(1.0)
            n += 1
            for up in list(self.upstreams.values()):
                try:
                    up.flush_herd()
                except Exception:
                    log.exception("herd flush")
            if n % 30 == 0:
                self.revalidate_clients()

    def revalidate_clients(self) -> None:
        """SC-3 backstop: every 30 s each socket checks that its session / API token is still valid (revoked,
        expired, user disabled or deleted = the socket is closed)."""
        for up in list(self.upstreams.values()):
            for c in list(up.clients):
                if c.still_valid is None or c.closed:
                    continue
                try:
                    ok = c.still_valid()
                except Exception:
                    # fail closed (reviews of 2026-11-12, R-6 / T-9): while the check itself fails (the database
                    # cannot be read), a disabled user's or a revoked session's socket must not stay open. The
                    # browser reconnects, and the new socket is authenticated from scratch.
                    log.exception("socket re-validation")
                    ok = False
                if not ok:
                    log.info("closing a socket of %s: its sign-in is no longer valid", c.user.get("username"))
                    c.disconnect("sign-in no longer valid")

    # ------------------------------------------------------------ chat_state persistence (spec 019, SC-2)
    async def _state_loop(self) -> None:
        while True:
            await self._dirty_event.wait()
            await asyncio.sleep(STATE_FLUSH_SECONDS)   # coalesce a burst of changes into one write per row
            self._dirty_event.clear()
            try:
                await asyncio.to_thread(self.flush_state_now)
            except Exception:
                log.exception("saving chat state")

    def flush_state_now(self) -> None:
        """Write every pending chat_state change (also called at shutdown and by tests)."""
        with self._state_lock:
            batch, self._dirty = self._dirty, {}
        if not batch or self.db is None:
            return
        # deletes of whole chats first, then rows: a row written after the chat's delete wins
        for key, data in batch.items():
            if key[2] is None:
                try:
                    self.db.delete_chat_state(key[0], key[1])
                except Exception:
                    log.exception("deleting the chat state of %s/%s", key[0], key[1])
        for key, data in batch.items():
            if key[2] is not None:
                try:
                    self.db.set_chat_state(key[0], key[1], key[2], data)
                except Exception:
                    log.exception("saving the chat state of %s/%s", key[0], key[1])

    def forget_profile(self, profile: str) -> None:
        with self._state_lock:
            self._dirty = {k: v for k, v in self._dirty.items() if k[0] != profile}

    def prune_chat_state(self, profile: str, keep: set[str]) -> None:
        """SC-7: rows of chats Goose no longer lists (deleted in Goose Desktop / the CLI) go, after a grace period."""
        if self.db is None:
            return
        up = self.upstreams.get(profile)
        busy = {s.sid for s in up.sessions.values() if s.running()} if up else set()

        def run():
            cutoff = time.time() - 600
            for r in self.db.query("SELECT session_id, MAX(updated_at) AS t FROM chat_state WHERE profile=? "
                                   "GROUP BY session_id", (profile,)):
                if r["session_id"] not in keep and r["session_id"] not in busy and (r["t"] or 0) < cutoff \
                        and not str(r["session_id"]).startswith("~"):   # "~elsewhere" (spec 020) is no chat
                    self.db.delete_chat_state(profile, r["session_id"])
        try:
            asyncio.get_running_loop().run_in_executor(None, run)
        except RuntimeError:
            run()

    def expire_queues(self, max_age: float) -> int:
        """SC-7: queued messages older than max_age leave memory too (the sweep removes their rows)."""
        cutoff = time.time() - max_age
        n = 0
        for up in list(self.upstreams.values()):
            for s in up.sessions.values():
                old = [x for x in s.queue if float(x.get("at") or 0) < cutoff]
                if old:
                    s.queue = [x for x in s.queue if x not in old]
                    n += len(old)
                    up._queue_changed(s)
        return n

    def disconnect_user(self, username: str, *, profile: bool = False, reason: str = "") -> int:
        """SC-3: close every socket of `username` (and with profile=True every socket attached to that profile, e.g.
        an administrator viewing it). On deletion the caller also drops the profile's Upstream (closed, no writes)."""
        key = str(username or "").lower()
        n = 0
        for up in list(self.upstreams.values()):
            for c in list(up.clients):
                if _ukey(c.user) == key or (profile and up.key == key):
                    c.disconnect(reason)
                    up.clients.discard(c)
                    self.herd_watchers.discard(c)
                    n += 1
        for c in list(self.herd_watchers):
            if _ukey(c.user) == key:
                c.disconnect(reason)
                self.herd_watchers.discard(c)
        return n

    def drop_profile(self, username: str) -> None:
        """SC-3: the user is deleted: its Upstream stops writing and is forgotten (a new account with the same name
        starts clean); pending writes are discarded."""
        key = str(username or "").lower()
        self.disconnect_user(key, profile=True, reason="user deleted")
        up = self.upstreams.pop(key, None)
        if up is not None:
            up.closed = True
            for s in up.sessions.values():
                s.queue, s.steers = [], []
                self.total_buffer = max(0, self.total_buffer - s.buffer_bytes)   # B-1
                s.buffer.clear()
                s.buffer_bytes = 0
        self.forget_profile(key)

    def _activity(self, key: str) -> tuple[int, int]:
        up = self.upstreams.get(key)
        return up.activity() if up else (0, 0)

    # ------------------------------------------------------------ deploy: busy check and drain (control.py)
    async def busy_report(self) -> list[dict]:
        """Every turn running in any worker: prompts in flight (long tool calls and sub-agents included), pending
        permission requests and questions, direct tool calls, prompts being checked, and scheduler jobs running
        inside a worker the gateway started."""
        out = [b for up in list(self.upstreams.values()) for b in up.busy()]
        sched = []
        for up in list(self.upstreams.values()):
            w = self.workers.get(up.key) if hasattr(self.workers, "get") else None
            if w is not None and getattr(w, "scheduler", False) and getattr(w, "state", "") == "ready" \
                    and not up.closed:
                sched.append(up.running_jobs())
        for jobs in await asyncio.gather(*sched):
            out += jobs
        return out

    def broadcast_all(self, obj: dict) -> None:
        raw = json.dumps(obj, separators=(",", ":"))
        seen: set[int] = set()
        for up in list(self.upstreams.values()):
            for c in list(up.clients):
                if id(c) not in seen:
                    seen.add(id(c))
                    c.send(raw)

    def set_draining(self, seconds: float, reason: str = "") -> None:
        now = time.time()
        first = self.draining is None
        self.draining = {"since": now if first else self.draining["since"], "until": now + seconds,
                         "reason": reason}
        if first:
            log.info("draining for %d s before a restart%s: new prompts are refused", seconds,
                     f" ({reason})" if reason else "")
            self.broadcast_all({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
                "level": "warning", "kind": "restart", "message": DRAIN_NOTICE}})

    def end_draining(self, why: str) -> None:
        if self.draining is None:
            return
        self.draining = None
        log.info("drain ended (%s): prompts are accepted again", why)
        self.broadcast_all({"jsonrpc": "2.0", "method": "_gw/notice", "params": {
            "level": "info", "kind": "restart", "message": "The update was postponed: you can send messages again."}})

    def expire_drain(self) -> None:
        if self.draining is not None and time.time() >= self.draining["until"]:
            self.end_draining("expired")

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

    def broadcast_user(self, uid: Any, obj: dict) -> None:
        """Every open socket signed in as this user (all tabs and browsers, whichever profile they look at)."""
        raw = json.dumps(obj, separators=(",", ":"))
        seen: set[int] = set()
        for up in list(self.upstreams.values()):
            for c in list(up.clients):
                if id(c) not in seen and (c.user or {}).get("id") == uid:
                    seen.add(id(c))
                    c.send(raw)

    def audit_guard(self, up: "Upstream", sid: str, ctx: Any, d: Any, *, tool: str = "", ext: str = "",
                    mode: str = "", actor: Any = None, action: str = "guard.blocked") -> None:
        """guard.blocked (or guard.bypass / guard.not_inspected): who, where, which rule or score - never the prompt
        or the arguments (R6). The author of the guarded user is recorded when someone else typed (SC-1)."""
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
            if _ukey(getattr(actor, "user", {}) or {}) not in ("", ctx.username.lower()):
                detail["guardedUser"] = ctx.username
            self.on_audit(actor, action, tool[:200] if tool else sid, detail, action == "guard.not_inspected")
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
        """Persist (data) or delete (None) one chat_state row; kind None deletes every row of the chat. Written by
        the background task (SC-2: never a synchronous SQLite write of a whole queue on the event loop); without a
        running hub (CLI, tests that did not start it) at once."""
        if self.db is None or not sid:
            return
        up = self.upstreams.get(profile)
        if up is not None and up.closed:
            return
        with self._state_lock:
            if kind is None:
                for k in [k for k in self._dirty if k[0] == profile and k[1] == sid]:
                    del self._dirty[k]
            self._dirty[(profile, sid, kind)] = data
        if self._dirty_event is not None:
            self._dirty_event.set()
        else:
            self.flush_state_now()

    def attach(self, up: Upstream, client: Client) -> None:
        client.key = up.key
        up.clients.add(client)

    def detach(self, up: Upstream, client: Client) -> None:
        up.clients.discard(client)
        self.herd_watchers.discard(client)
        up.forget_client(client)
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
        # key=: two sessions touched at the same instant must not make sorted() compare Upstream objects (TypeError,
        # which lost the chunk being buffered - B-1)
        cands = sorted(((s.last_touch, up, s) for up in self.upstreams.values() for s in up.sessions.values()
                        if not s.running() and s.buffer_bytes and s.loading is None
                        and not any(s.sid in c.watch for c in up.clients)),
                       key=lambda t: t[0])
        for _, up, s in cands:
            if self.total_buffer <= TOTAL_BUFFER_BYTES * 0.7:
                break
            self.total_buffer -= s.buffer_bytes
            s.buffer.clear()
            s.buffer_bytes, s.loaded, s.load_result = 0, False, None

    async def gw_method(self, up: Upstream, client: Client, msg: dict) -> None:
        method, mid, params = msg["method"], msg.get("id"), msg.get("params") or {}
        result: Any
        if client.closed or up.closed:   # SC-3
            return
        if method == "_gw/hello":
            err = None
            try:
                await up.ensure()
            except RpcError as e:
                err = e.message
            result = {"user": {"username": client.user["username"], "role": client.user.get("role")},
                      "profile": up.key, "agent": up.init_result, "gooseCaps": up.caps(),
                      "asks": [a["msg"] for a in up.asks.values()], "herd": up.herd(),
                      "upstream": {"state": up.state, "error": err}, "draining": self.draining is not None,
                      **up.snapshot()}
            gh = self.guard_health_for(client)
            if gh is not None:
                result["guard"] = gh
        elif method == "_gw/watch":
            client.watch = {str(x) for x in (params.get("sessionIds") or [])[:200]}
            if "current" in params:   # FIX idle-sessions-keep-mcp-servers: the chat this tab shows is never unloaded
                client.current = str(params.get("current") or "")[:200]
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
        elif method == "_gw/elsewhere":
            # spec 020: administrators of the native profile only; members never see the native profile
            if not client.is_admin or not self.is_native(up) or not self.elsewhere_knobs()["enabled"]:
                client.elsewhere = False
                result = {"enabled": False, "items": [], "done": []}
            else:
                client.elsewhere = True
                wt = self._elsewhere_watcher(up)
                if time.time() - wt.ticked > 2:
                    await self.elsewhere_tick(up)
                result = {"enabled": True, "items": wt.items, "done": wt.done(), "at": wt.ticked,
                          "pollSeconds": self.elsewhere_knobs()["poll_seconds"]}
        elif method == "_gw/elsewhere_clear":
            # spec 020: Done entries of sessions finished elsewhere - one group ({key}) or all ("mark all read")
            wt = self.elsewhere.get(up.key)
            if not client.is_admin or not self.is_native(up) or wt is None:
                result = {"ok": False}
            else:
                key = params.get("key")
                if wt.clear(str(key) if key else None):
                    self.elsewhere_push(up)
                result = {"ok": True}
        elif method == "_gw/seen":
            client.current = str(params.get("sessionId") or "")[:200]   # FIX idle-sessions-keep-mcp-servers
            s = up.sessions.get(str(params.get("sessionId") or ""))
            if s and s.status in ("done", "error"):
                up._set_status(s, "idle")
            wt = self.elsewhere.get(up.key)   # spec 020: opening a chat in Goose Web clears its "done elsewhere"
            if wt is not None and client.is_admin and wt.ack(str(params.get("sessionId") or "")):
                self.elsewhere_push(up)
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
