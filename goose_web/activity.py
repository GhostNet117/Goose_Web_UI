"""User activity log (spec 015): one JSON line per event in <system_dir>/logs/activity.jsonl.

Every audit event (sign-in/out, admin and security actions, audited agent calls) is mirrored here, plus everyday
activity that is not worth a database row per se but answers "who did what, when, from where": opening, creating,
prompting, cancelling and forking chats, and browser connections. Each line carries the time (UTC, ISO 8601), the
user, the client address (the real one behind a trusted proxy), the action, its target and a small detail object.
Prompt text is never logged - only its length and the number of attachments.

The file rotates by size (logs.activity_file_mb x logs.activity_files); the log janitor (logjanitor.py) keeps all
logs together under the disk budget (logs.max_disk_percent of the volume).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any

log = logging.getLogger("goose_web.activity")
log.propagate = False            # never mixed into gateway.log
FILE_NAME = "activity.jsonl"
_state = {"enabled": False}


def setup(logdir: Path, max_mb: float = 20, files: int = 10, enabled: bool = True) -> None:
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    _state["enabled"] = bool(enabled)
    if not enabled:
        return
    logdir.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(logdir / FILE_NAME, maxBytes=int(max(1, max_mb) * 1024 * 1024),
                                             backupCount=max(1, int(files)), encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h)
    log.setLevel(logging.INFO)


def enabled() -> bool:
    return _state["enabled"]


_CONTROL = {c: f"\\x{c:02x}" for c in (*range(0x20), 0x7f, *range(0x80, 0xa0))}
_CONTROL.update({0x2028: "\\u2028", 0x2029: "\\u2029"})


def clean_text(value: Any, limit: int = 300) -> str:
    """A string from outside the gateway (a member's request, a container's output, a file name) made safe for
    gateway.log, the activity log and the audit: control characters (CR, LF, TAB, ESC, C1, the Unicode line
    separators) shown escaped (\\x0a), so one value is always one line; at most `limit` characters (security review
    2026-11-12, MX-5)."""
    s = str(value if value is not None else "")
    if len(s) > limit * 4:
        s = s[:limit * 4]
    s = s.translate(_CONTROL)
    return s if len(s) <= limit else s[:max(0, limit - 3)] + "..."


def record(action: str, *, user: dict | None = None, username: str = "", ip: str = "", target: str = "",
           detail: dict | None = None, ok: bool = True) -> None:
    if not _state["enabled"]:
        return
    entry: dict[str, Any] = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
                             "user": (user or {}).get("username") or username or "", "ip": ip or "",
                             "action": action, "target": str(target or "")[:500], "ok": bool(ok)}
    if user and user.get("id") is not None:
        entry["uid"] = user["id"]
    if detail:
        entry["detail"] = detail
    try:
        log.info(json.dumps(entry, default=str, ensure_ascii=False)[:20000])
    except Exception:  # logging must never break a request
        pass


def close() -> None:
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    _state["enabled"] = False
