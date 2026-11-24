"""Read-only copy of a chat (FIX chat-open-readonly-fallback): when Goose cannot load a chat (session/load fails, takes
too long, or the connection keeps dropping while the chat opens), the person can still read the conversation.

Source: the profile's Goose session database (<root>/data/sessions/sessions.db), the file Goose itself writes. Goose
Web only READS it, the same way elsewhere.py does: a read-only connection (`mode=ro`, `PRAGMA query_only`), a short
busy timeout, a few indexed queries, closed at once - never a write, never a long lock, never created when missing.

What a page holds: the session's name, folder and times, and the messages the person would see in the chat (a
message whose metadata says `userVisible: false` is left out), oldest first, paged by message id (`after`, `limit`).
Every content block is reduced to what a reader needs:
* text, and thinking (marked as thinking; redacted thinking as a placeholder);
* a tool call as its tool name and shortened arguments, a tool result as shortened text (TOOL_TEXT_MAX);
* an image as a placeholder - never its bytes;
* anything else (notices Goose stores in the conversation) as a short notice.
One message's text is capped (TEXT_MAX, all its blocks together), and so is the page (PAGE_BYTES of JSON, READ_MAX of
stored content read): a page that reaches a cap ends early with `more` and `next`, the id to continue after.

Who may read what is decided by the caller (api.session_transcript): the same rules as opening the chat.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .elsewhere import _epoch

SID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")    # Goose's ids look like 20261124_38
DEFAULT_LIMIT = 200                  # messages per page
MAX_LIMIT = 1000
TEXT_MAX = 200 * 1024                # characters of one message's text, all its blocks together
TOOL_TEXT_MAX = 2000                 # characters of a tool call's arguments or of a tool result
MAX_BLOCKS = 500                     # content blocks shown per message
PAGE_BYTES = 4 * 1024 * 1024         # the page's messages as JSON (UTF-8)
RAW_MAX = 16 * 1024 * 1024           # a stored message larger than this is not read at all (a placeholder instead)
READ_MAX = 64 * 1024 * 1024          # stored message content read for one page
BUSY_TIMEOUT = 2.0                   # seconds to wait while Goose holds a write lock

_SESSION_COLS = ("name", "description", "working_dir", "created_at", "updated_at", "session_type", "archived_at",
                 "parent_session_id")
# Goose's MessageMetadata: userVisible is true unless it says false (a missing or unreadable value counts as shown).
_VISIBLE = ("COALESCE(CASE WHEN json_valid(metadata_json) THEN json_extract(metadata_json, '$.userVisible') END, 1) "
            "NOT IN (0, 'false')")


class Unavailable(Exception):
    """The database exists but cannot be read now (locked, damaged, another schema)."""


def valid_sid(sid: Any) -> bool:
    return isinstance(sid, str) and bool(SID_RE.fullmatch(sid))


def db_path(root: str | Path) -> Path:
    """The Goose session database of a profile root (profiles.Profiles.root_for)."""
    return Path(root) / "data" / "sessions" / "sessions.db"


def connect(db: Path) -> sqlite3.Connection:
    """A read-only connection: `mode=ro` (sqlite refuses every write and never creates the file) and
    `PRAGMA query_only` on top. FileNotFoundError when there is no database."""
    if not db.is_file():
        raise FileNotFoundError(str(db))
    con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT)
    try:
        con.execute("PRAGMA query_only=1")
    except BaseException:
        con.close()
        raise
    return con


def _s(v: Any) -> str:
    return v if isinstance(v, str) else "" if v is None else str(v)


def _err_text(e: Any) -> str:
    if isinstance(e, dict):
        return _s(e.get("message")) or json.dumps(e, ensure_ascii=False, default=str)
    return _s(e)


def _clip(text: str, n: int) -> tuple[str, bool]:
    return (text, False) if len(text) <= n else (text[:n], True)


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def _session(con: sqlite3.Connection, sid: str) -> dict | None:
    cols = [c for c in _SESSION_COLS if c in _columns(con, "sessions")]
    row = con.execute(f"SELECT id{''.join(', ' + c for c in cols)} FROM sessions WHERE id=?", (sid,)).fetchone()
    if row is None:
        return None
    r = dict(zip(["id", *cols], row))
    return {"id": sid, "name": _s(r.get("name") or r.get("description"))[:500],
            "workingDir": _s(r.get("working_dir"))[:4096], "created": _epoch(r.get("created_at")),
            "updated": _epoch(r.get("updated_at")), "type": _s(r.get("session_type"))[:40],
            "archived": bool(r.get("archived_at")), "parent": _s(r.get("parent_session_id"))[:128]}


def _tool_call(tc: Any) -> tuple[str, str, bool]:
    """(tool name, arguments as text, failed) of a Goose tool call ({status, value: {name, arguments}} or
    {status: error, error})."""
    if not isinstance(tc, dict):
        return "", "", False
    if tc.get("status") == "error" or ("error" in tc and "value" not in tc):
        return "", _err_text(tc.get("error")), True
    v = tc.get("value") if isinstance(tc.get("value"), dict) else tc
    args = v.get("arguments")
    if args is None:
        text = ""
    elif isinstance(args, str):
        text = args
    else:
        try:
            text = json.dumps(args, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = _s(args)
    return _s(v.get("name"))[:200], text, False


def _content_text(items: Any) -> str:
    """The text of MCP content items (a tool result): text as it is, other kinds as short placeholders."""
    parts: list[str] = []
    size = 0
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        t = it.get("type")
        if t == "text":
            p = _s(it.get("text"))
        elif t in ("image", "audio"):
            p = f"[{t}]"
        elif t == "resource":
            r = it.get("resource") if isinstance(it.get("resource"), dict) else {}
            p = _s(r.get("text")) if isinstance(r.get("text"), str) else f"[resource {_s(r.get('uri'))[:200]}]"
        elif t in ("resource_link", "resourceLink"):
            p = f"[link {_s(it.get('name') or it.get('uri'))[:200]}]"
        else:
            p = f"[{_s(t)[:40]}]"
        parts.append(p)
        size += len(p) + 1
        if size > TOOL_TEXT_MAX:
            break
    return "\n".join(parts)


def _tool_result(tr: Any) -> tuple[str, bool]:
    """(text, failed) of a Goose tool result ({status, value: CallToolResult | [content]} or {status: error})."""
    if not isinstance(tr, dict):
        return "", False
    if tr.get("status") == "error" or ("error" in tr and "value" not in tr):
        return _err_text(tr.get("error")), True
    v = tr.get("value")
    if isinstance(v, dict):
        return _content_text(v.get("content")), bool(v.get("isError"))
    return _content_text(v), False


def _block(b: dict, tools: dict[str, str]) -> dict | None:
    """One content block as the reader sees it ({type, text?, ...}); None = nothing to show."""
    t = b.get("type")
    if t == "text":
        return {"type": "text", "text": _s(b.get("text"))}
    if t in ("thinking", "reasoning"):
        return {"type": "thinking", "text": _s(b.get("thinking") if t == "thinking" else b.get("text"))}
    if t == "redactedThinking":
        return {"type": "thinking", "text": "", "redacted": True}
    if t == "image":
        return {"type": "image", "mimeType": _s(b.get("mimeType"))[:100]}
    if t in ("toolRequest", "frontendToolRequest"):
        name, args, failed = _tool_call(b.get("toolCall"))
        tid = _s(b.get("id"))[:200]
        if tid and name:
            tools[tid] = name
        text, cut = _clip(args, TOOL_TEXT_MAX)
        return {"type": "toolRequest", "id": tid, "tool": name, "text": text, "error": failed, "truncated": cut}
    if t == "toolResponse":
        text, failed = _tool_result(b.get("toolResult"))
        tid = _s(b.get("id"))[:200]
        text, cut = _clip(text, TOOL_TEXT_MAX)
        return {"type": "toolResponse", "id": tid, "tool": tools.get(tid, ""), "text": text, "error": failed,
                "truncated": cut}
    if t == "toolConfirmationRequest":
        return {"type": "notice", "kind": t, "text": f"Permission asked to run {_s(b.get('toolName'))[:200]}".strip()}
    # systemNotification, actionRequired, conversationCompacted, ... and kinds a newer Goose adds
    text = next((_s(b.get(k)) for k in ("msg", "text", "message") if isinstance(b.get(k), str)), "")
    return {"type": "notice", "kind": _s(t)[:40], "text": _clip(text, TOOL_TEXT_MAX)[0]}


def message_view(mid: int, role: Any, created: Any, raw_len: int | None, raw: str | None,
                 tools: dict[str, str] | None = None) -> dict:
    """One stored message (a messages row) as the reader sees it. `tools`: tool call id -> tool name of the calls
    seen so far on this page (a tool result names its tool)."""
    tools = {} if tools is None else tools
    out: dict[str, Any] = {"id": mid, "role": _s(role)[:20], "created": created if isinstance(created, int) else None,
                           "blocks": []}
    if raw is None:
        mb = max(1, (raw_len or 0) // (1024 * 1024))
        out["blocks"].append({"type": "notice", "kind": "too-large",
                              "text": f"This message is too large to show in the read-only copy (about {mb} MB)."})
        out["truncated"] = True
        return out
    try:
        content = json.loads(raw)
    except ValueError:
        content = None
    if not isinstance(content, list):
        out["blocks"].append({"type": "notice", "kind": "unreadable", "text": "This message could not be read."})
        return out
    budget = TEXT_MAX
    for b in content[:MAX_BLOCKS]:
        if not isinstance(b, dict):
            continue
        v = _block(b, tools)
        if v is None:
            continue
        text = v.get("text") or ""
        if budget <= 0 and (text or v["type"] in ("text", "thinking")):
            out["truncated"] = True
            break
        if len(text) > budget:
            v["text"], v["truncated"] = text[:budget], True
            out["truncated"] = True
        budget -= len(v.get("text") or "")
        out["blocks"].append(v)
    if len(content) > MAX_BLOCKS:
        out["truncated"] = True
    return out


def session_info(db: Path, sid: str) -> dict | None:
    """The session's name, folder and times, or None when the profile has no such session (or no database).
    Raises Unavailable when the database cannot be read now."""
    try:
        con = connect(db)
    except FileNotFoundError:
        return None
    except sqlite3.Error as e:
        raise Unavailable(str(e)) from e
    try:
        return _session(con, sid)
    except sqlite3.Error as e:
        raise Unavailable(str(e)) from e
    finally:
        con.close()


def read(db: Path, sid: str, after: int = 0, limit: int = DEFAULT_LIMIT) -> dict | None:
    """The session and one page of its user-visible messages with an id above `after`, oldest first; None when the
    profile has no such session. Raises Unavailable when the database cannot be read now."""
    after = max(0, int(after or 0))
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    try:
        con = connect(db)
    except FileNotFoundError:
        return None
    except sqlite3.Error as e:
        raise Unavailable(str(e)) from e
    try:
        info = _session(con, sid)
        if info is None:
            return None
        visible = _VISIBLE if "metadata_json" in _columns(con, "messages") else "1"
        total = con.execute(f"SELECT COUNT(*) FROM messages WHERE session_id=? AND {visible}", (sid,)).fetchone()[0]
        cur = con.execute(
            "SELECT id, role, created_timestamp, length(content_json), "
            f"CASE WHEN length(content_json) <= {RAW_MAX} THEN content_json END "
            f"FROM messages WHERE session_id=? AND id>? AND {visible} ORDER BY id LIMIT ?", (sid, after, limit + 1))
        messages: list[dict] = []
        tools: dict[str, str] = {}
        size = raw_read = 0
        more, last = False, after
        for mid, role, created, raw_len, raw in cur:     # one row at a time: a page never holds more than it needs
            if len(messages) >= limit or (messages and raw_read >= READ_MAX):
                more = True
                break
            m = message_view(mid, role, created, raw_len, raw, tools)
            n = len(json.dumps(m, ensure_ascii=False).encode("utf-8"))
            if messages and size + n > PAGE_BYTES:
                more = True
                break
            messages.append(m)
            size += n
            raw_read += len(raw) if raw is not None else 0
            last = mid
        return {"session": info, "messages": messages, "total": total, "after": after, "next": last, "more": more,
                "limit": limit}
    except sqlite3.Error as e:
        raise Unavailable(str(e)) from e
    finally:
        con.close()
