"""Idle-chat unloader (FIX idle-sessions-keep-mcp-servers).

Goose 1.57 keeps one agent - with a full set of the profile's stdio MCP servers - for every chat that was created,
opened, forked or prompted on an ACP connection, until the chat is closed (`session/close`), deleted or archived, or
the connection ends. It has no idle time-out of its own. Goose Web keeps one connection per worker for the worker's
whole life, and a worker that owns schedules or always has a tab open never stops, so every chat ever opened there
kept its servers running.

One Unloader per Upstream (hub.py):

- it remembers which chats Goose holds an agent for on the current connection (`held`): the answers to session/new,
  session/load, session/fork and the per-session methods that make Goose create one (NEEDS_AGENT);
- every TICK_SECONDS it closes the chats idle longer than goose.session_unload_minutes and, while the worker holds
  more than goose.max_loaded_sessions, the least recently used idle ones at once. Only when the worker's initialize
  result advertises sessionCapabilities.close (off for that worker after a "method not found"), and never a chat
  that is running, has a prompt, a question or a request in flight, queued messages or steers, is being loaded, or
  is the current chat of a connected tab;
- the close is an internal request whose pending entry carries the pseudo-method UNLOAD_METHOD, so the hub's own
  close/delete branch (which forgets the chat, its queue and its herd mark) never runs for it. Afterwards the
  gateway's buffer of the chat goes; its queue, title, herd status and marks stay; tabs hear
  `_gw/session_changed {reason: "unloaded"}` and load the chat again (from Goose) when they show it next;
- a method that needs the agent of a chat the gateway unloaded first loads the chat again, silently (the replay
  goes into the gateway's buffer, to no tab), then goes to Goose. A per-chat lock keeps a load or a prompt from
  racing a close.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import OrderedDict
from typing import Any

log = logging.getLogger("goose_web.unload")

UNLOAD_METHOD = "_gw/unload"     # name of the unloader's own session/close in Upstream.pending (never sent as such)
CLOSE = "session/close"
TICK_SECONDS = 60.0
LRU_MIN_IDLE_SECONDS = 120.0     # max_loaded_sessions never unloads a chat used less than this long ago
CLOSE_TIMEOUT = 30.0
LOAD_TIMEOUT = 120.0             # a silent load waits at least this long (or the hub's load watchdog + 5 s)
LOAD_POLL_SECONDS = 0.05
DEFAULT_MINUTES = 30
DEFAULT_MAX_LOADED = 12
UNLOADED_MAX = 5000              # unloaded chat ids remembered per connection
METHOD_NOT_FOUND = -32601
# Goose's answer that the chat does not exist, or the request was malformed: no agent was created for it
NO_AGENT_ERRORS = (-32002, -32602, METHOD_NOT_FOUND)
_G = "_goose/unstable/"
# Per-session methods for which Goose 1.57 creates the chat's agent when it has none (get_session_agent). Goose
# refuses them for a chat closed on this connection until it is loaded again: the gateway loads it first.
NEEDS_AGENT = frozenset({
    "session/prompt", "session/set_mode", "session/set_model", "session/set_config_option",
    _G + "session/steer", _G + "session/working-dir/update", _G + "session/extensions/add",
    _G + "session/extensions/remove", _G + "session/extensions/list", _G + "session/system-prompt/set",
    _G + "tools/list", _G + "tools/call"})
NEEDS_AGENT_PREFIXES = (_G + "session/live-voice/",)
RELEASES = frozenset({CLOSE, "session/delete", _G + "session/archive"})


def needs_agent(method: str) -> bool:
    return method in NEEDS_AGENT or method.startswith(NEEDS_AGENT_PREFIXES)


def close_supported(init_result: Any) -> bool:
    """True when Goose's initialize result advertises session/close (agentCapabilities.sessionCapabilities.close;
    Goose 1.57 does, older versions do not)."""
    if not isinstance(init_result, dict):
        return False
    for caps in (init_result.get("agentCapabilities"), init_result):
        sc = caps.get("sessionCapabilities") if isinstance(caps, dict) else None
        if isinstance(sc, dict) and sc.get("close") not in (None, False):
            return True
    return False


class Unloader:
    def __init__(self, up: Any):
        self.up = up
        self.held: dict[str, float] = {}       # chats Goose holds an agent for on this connection -> last answer
        self.unloaded: OrderedDict[str, float] = OrderedDict()   # chats this connection closed, not loaded since
        self.locks: dict[str, asyncio.Lock] = {}
        self._users: dict[str, int] = {}
        self.off = ""          # why unloading is off for this worker's Goose ("method not found")
        self.count = 0         # chats unloaded since the gateway started
        self._why: dict[str, str] = {}
        self._conn: Any = None
        self._task: asyncio.Task | None = None
        self._wake: asyncio.Event | None = None

    # ------------------------------------------------------------ settings and state
    def knobs(self) -> tuple[int, int]:
        """(goose.session_unload_minutes, goose.max_loaded_sessions)."""
        s = getattr(self.up.hub.workers, "s", None)
        if s is None:
            return DEFAULT_MINUTES, DEFAULT_MAX_LOADED
        from .config import session_unload
        minutes, most, _ = session_unload(s)
        return minutes, most

    def supported(self) -> bool:
        return not self.off and close_supported(self.up.init_result)

    def active(self) -> bool:
        return self.knobs()[0] > 0 and self.supported()

    def _sync(self) -> None:
        """A new connection (worker restart, reconnect) holds no agent yet and has closed no chat."""
        ws = self.up.ws
        if ws is not self._conn:
            self._conn = ws
            self.held.clear()
            self.unloaded.clear()
            self.off = ""

    def loaded_count(self) -> int:
        self._sync()
        return len(self.held) if self.up.ws is not None else 0

    def describe(self) -> dict:
        minutes, most = self.knobs()
        off = self.off
        if not off and self.up.init_result is not None and not close_supported(self.up.init_result):
            off = "this Goose does not offer session/close"
        return {"loadedSessions": self.loaded_count(), "unloadedSessions": self.count, "unloading": self.active(),
                "unloadOff": off, "unloadMinutes": minutes, "maxLoadedSessions": most}

    def last_use(self, sid: str) -> float:
        s = self.up.sessions.get(sid)
        return max(self.held.get(sid, 0.0), s.last_touch if s is not None else 0.0)

    def _hold(self, sid: str) -> None:
        self.held[sid] = time.time()
        most = self.knobs()[1]
        if most and len(self.held) > most and self._wake is not None:
            self._wake.set()   # more chats loaded than allowed: unload the least recently used idle ones now

    @contextlib.asynccontextmanager
    async def _locked(self, sid: str):
        lk = self.locks.get(sid)
        if lk is None:
            lk = self.locks[sid] = asyncio.Lock()
        self._users[sid] = self._users.get(sid, 0) + 1
        try:
            async with lk:
                yield
        finally:
            n = self._users.get(sid, 1) - 1
            if n > 0:
                self._users[sid] = n
            else:
                self._users.pop(sid, None)
                self.locks.pop(sid, None)

    def busy_sids(self) -> set[str]:
        """Chats with a question, a request in flight, or shown as the current chat of a connected tab."""
        up = self.up
        out = {str(a.get("sessionId") or "") for a in list(up.asks.values())}
        for e in list(up.pending.values()):
            if len(e) > 4 and isinstance(e[4], dict) and e[3] != UNLOAD_METHOD:
                out.add(str(e[4].get("sessionId") or ""))
        for c in list(up.clients):
            cur = getattr(c, "current", None)   # set by _gw/watch and _gw/seen (hub.gw_method)
            if cur and not c.closed:
                out.add(str(cur))
        out.discard("")
        return out

    def candidate(self, sid: str, now: float, min_idle: float, busy: set[str] | None = None) -> bool:
        """Goose holds this chat's agent, nothing uses it, and it was last used at least min_idle seconds ago."""
        up = self.up
        if sid not in self.held or sid in (self.busy_sids() if busy is None else busy):
            return False
        s = up.sessions.get(sid)
        if s is not None and (s.running() or s.prompts or s.queue or s.steers or s.loading is not None
                              or s.abandoned is not None):
            return False   # (loading/abandoned: the chat's one upstream load, FIX chat-open-replay-overflow)
        try:
            if up.hub.elsewhere_running(up.key, sid):   # spec 020: another program runs it (read-only here)
                return False
        except Exception:
            pass
        return now - self.last_use(sid) >= min_idle

    # ------------------------------------------------------------ hooks called by hub.py
    def on_response(self, method: str, params: Any, msg: dict) -> bool:
        """Upstream._post_response calls this first, for every answer from Goose. True = it answered the unloader's
        own close: the bookkeeping is done here, and the hub's close branch must not run."""
        self._sync()
        p = params if isinstance(params, dict) else {}
        sid = str(p.get("sessionId") or "")
        ok = "error" not in msg
        if method == UNLOAD_METHOD:
            if ok and sid:
                self._mark_unloaded(sid, self._why.get(sid, "idle"))
            return True
        err = msg.get("error") if isinstance(msg.get("error"), dict) else {}
        if method in ("session/new", "session/fork"):
            res = msg.get("result") if isinstance(msg.get("result"), dict) else {}
            if ok and res.get("sessionId"):
                self._hold(str(res["sessionId"]))
        elif method == "session/load":
            if ok and sid:
                self.unloaded.pop(sid, None)
                self._hold(sid)
        elif method in RELEASES:
            if ok and sid:
                self.held.pop(sid, None)
                self.unloaded.pop(sid, None)
        elif sid and needs_agent(method) and sid in self.up.sessions and err.get("code") not in NO_AGENT_ERRORS:
            self._hold(sid)   # Goose created the agent if it had none (a failed turn included)
        return False

    async def before_forward(self, method: str, params: Any) -> None:
        """Upstream._from_client calls this right before a request about one chat goes to Goose: wait while the
        gateway closes that chat, and load a chat the gateway unloaded again before a method that needs its agent."""
        if method != "session/load" and not needs_agent(method):
            return
        sid = str((params if isinstance(params, dict) else {}).get("sessionId") or "")
        if not sid:
            return
        self._sync()
        if sid not in self.unloaded and sid not in self.locks:
            return
        async with self._locked(sid):
            if method != "session/load" and sid in self.unloaded and self.up.ws is not None:
                await self._silent_load(sid, method)

    async def chat_folder(self, sid: str) -> str:
        """The chat's working folder: the gateway's record, else what Goose stored (session/info, read-only)."""
        from .hub import SESSION_INFO, RpcError
        s = self.up.sess(sid)
        if s.cwd:
            return s.cwd
        try:
            info = await self.up.request(SESSION_INFO, {"sessionId": sid}, timeout=30)
        except asyncio.TimeoutError:
            raise RpcError(-32000, "Goose did not say where this chat works in time; try once more") from None
        cwd = str((((info or {}).get("session") or {}) if isinstance(info, dict) else {}).get("cwd") or "")
        s.cwd = s.cwd or cwd
        return s.cwd or cwd

    async def ensure_loaded(self, sid: str, method: str) -> None:
        """M-1 (assessment 2026-11-24): a member's prompt is checked against the chat's CURRENT provider, model and
        mode (policy.check_session_choice), which the gateway knows only from a load. A chat it unloaded - or never
        loaded on this connection - is loaded first (the same silent load), so the check always has the values."""
        s = self.up.sessions.get(sid)
        if not sid or (s is not None and s.load_result is not None) or self.up.ws is None:
            return
        self._sync()
        async with self._locked(sid):
            s = self.up.sessions.get(sid)
            if s is not None and s.load_result is not None:
                return
            if s is not None and s.running():
                return   # a running chat is never loaded again upstream; the caller refuses (no load result)
            await self._silent_load(sid, method)

    def before_forget(self, s: Any) -> None:
        """Upstream._prune_sessions is about to forget this chat's state: Goose closes the chat first."""
        if s.sid in self.held and self.active():
            self.up._spawn(self._close_locked(s.sid, "its state was dropped"))

    # ------------------------------------------------------------ loop
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._wake = asyncio.Event()
            self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        t, self._task = self._task, None
        if t is not None:
            t.cancel()

    async def _loop(self) -> None:
        while not self.up.closed:
            try:
                try:
                    await asyncio.wait_for(self._wake.wait(), TICK_SECONDS)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()
                await self.tick()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("chat unloader %s", self.up.key)

    async def tick(self) -> list[str]:
        """Unload what is due now; returns the chats closed."""
        up = self.up
        self._sync()
        if up.closed or up.state != "ready" or up.ws is None or up.starting or not self.active():
            return []
        minutes, most = self.knobs()
        now = time.time()
        busy = self.busy_sids()
        cands = sorted((self.last_use(sid), sid) for sid in list(self.held) if self.candidate(sid, now, 0.0, busy))
        due = [(sid, f"idle for {minutes} min", minutes * 60.0) for t, sid in cands if now - t >= minutes * 60]
        excess = len(self.held) - most if most > 0 else 0
        if excess > len(due):
            chosen = {d[0] for d in due}
            lru = [sid for t, sid in cands if now - t >= LRU_MIN_IDLE_SECONDS and sid not in chosen]
            due += [(sid, f"more than {most} chats loaded", LRU_MIN_IDLE_SECONDS) for sid in lru[:excess - len(due)]]
        done = []
        for sid, why, floor in due:
            if self.off or up.closed or up.ws is None:
                break
            if await self.unload(sid, why, floor):
                done.append(sid)
        return done

    # ------------------------------------------------------------ close and load
    async def unload(self, sid: str, why: str = "idle", min_idle: float = 0.0) -> bool:
        lk = self.locks.get(sid)
        if lk is not None and lk.locked():
            return False   # a close or a load of this chat is in flight
        async with self._locked(sid):
            if not self.supported() or not self.candidate(sid, time.time(), min_idle):
                return False
            return await self._close(sid, why)

    async def _close_locked(self, sid: str, why: str) -> bool:
        async with self._locked(sid):
            return await self._close(sid, why)

    async def _close(self, sid: str, why: str) -> bool:
        from .hub import RpcError
        up = self.up
        conn = up.ws
        up_id = up._new_id()
        fut = asyncio.get_running_loop().create_future()
        params = {"sessionId": sid}
        self._why[sid] = why
        up.pending[up_id] = (None, None, fut, UNLOAD_METHOD, params)
        try:
            await up._send({"jsonrpc": "2.0", "id": up_id, "method": CLOSE, "params": params})
            await asyncio.wait_for(fut, CLOSE_TIMEOUT)
            return True      # on_response did the bookkeeping when the answer came
        except RpcError as e:
            if up.ws is None or up.ws is not conn:
                return False   # the connection ended: Goose holds nothing for it any more
            if e.code == METHOD_NOT_FOUND:
                self.off = "Goose answered session/close with 'method not found'"
                log.warning("chat unloading is off for %s: %s", up.key, self.off)
                return False
            # Goose does not have it (or will not say): count it closed, so it is loaded before it is used again
            log.warning("unloading chat %s of %s: Goose answered %s %s", sid, up.key, e.code, e.message)
            self._mark_unloaded(sid, why)
            return False
        except asyncio.TimeoutError:
            log.warning("unloading chat %s of %s: no answer to session/close in %g s", sid, up.key, CLOSE_TIMEOUT)
            if up.ws is conn:
                self._mark_unloaded(sid, why + ", no answer")
            return False
        except Exception as e:   # the socket failed while sending: the connection is ending
            log.warning("unloading chat %s of %s: %s", sid, up.key, e.__class__.__name__)
            return False
        finally:
            up.pending.pop(up_id, None)
            self._why.pop(sid, None)

    def _mark_unloaded(self, sid: str, why: str) -> None:
        up = self.up
        self.held.pop(sid, None)
        self.unloaded[sid] = time.time()
        self.unloaded.move_to_end(sid)
        while len(self.unloaded) > UNLOADED_MAX:
            self.unloaded.popitem(last=False)
        self.count += 1
        s = up.sessions.get(sid)
        log.info("unloaded chat %s of %s (%s): Goose ended its agent and extensions", sid, up.key, why)
        if s is None:
            return
        up._invalidate(s)   # the buffer goes (the next load comes from Goose); queue, title, herd status, marks stay
        up.broadcast({"jsonrpc": "2.0", "method": "_gw/session_changed",
                      "params": {"sessionId": sid, "reason": "unloaded"}})

    async def _silent_load(self, sid: str, method: str) -> None:
        """Load a chat the gateway unloaded before `method` needs its agent. It is the chat's one upstream load
        (hub.UpstreamLoad, FIX chat-open-replay-overflow) with no tab waiting: Goose's history fills only the hub
        buffer, so a tab that opens the chat later gets it replayed, and a tab that opens it meanwhile joins the same
        load. A load already in flight (a tab's) is waited for instead of sending a second one."""
        from .hub import RpcError, UpstreamLoad
        up = self.up
        s = up.sess(sid)
        if s.abandoned is not None:
            raise RpcError(-32000, "Goose has not answered an earlier load of this chat: try again later")
        ld = s.loading
        if ld is None:
            cwd = await self.chat_folder(sid)
            ld = s.loading
            if ld is None:   # nobody started a load while Goose was asked for the folder
                up.hub.total_buffer -= s.buffer_bytes
                s.buffer.clear()
                s.buffer_bytes, s.truncated, s.fp = 0, False, None
                ld = s.loading = UpstreamLoad(up._new_id())
                await up._send_load(ld, {"sessionId": sid, "cwd": s.cwd or cwd, "mcpServers": []})
        deadline = time.monotonic() + max(LOAD_TIMEOUT, up._load_timeout() + 5.0)
        while s.loading is ld and time.monotonic() < deadline and not up.closed:
            await asyncio.sleep(LOAD_POLL_SECONDS)
        # Answered: on_response moved the chat from `unloaded` to `held`. Anything else (an error, the watchdog, the
        # connection ending, no answer at all) leaves Goose without the chat's agent.
        if sid in self.unloaded or sid not in self.held:
            raise RpcError(-32000, "Goose did not load this chat again; try once more")
        log.info("loaded the unloaded chat %s of %s again for %s", sid, up.key, method)
