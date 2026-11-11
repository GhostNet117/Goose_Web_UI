"""Prompt-guard rule matching in a child process (security review 2026-11-11, SA-2 / SD-1).

Python's `re` backtracks, and it holds the GIL while it does: a slow pattern on long text stops the whole asyncio
event loop (every user's chats, sign-ins and health checks), and running it in a thread would not help. The gateway
therefore matches its rules in up to `CHILDREN` small child processes and only waits on their pipes:

* each check has a hard deadline; a child that overruns is killed (and replaced on the next check) and the caller
  gets RuleTimeout, which the guard treats as a match (fail closed);
* the child runs `python -E -s -c "from goose_web.rulematch import serve; serve()"` and imports nothing but the
  standard library and this module;
* protocol: one JSON object per line. Request {"items": [[kind, [patterns...], texts_index], ...],
  "texts": [[str, ...], ...]} -> {"hit": index of the first matching item, or -1} or {"error": "..."}.

The matching functions (`pipeline_commands`, `words_pattern`, `match_items`) are also used in-process by the unit
tests and by guard.evaluate_* (which tests call directly); the gateway itself always goes through RuleRunner.
"""
from __future__ import annotations

import asyncio
import json
import os
import queue
import re
import subprocess  # nosec B404 - runs this module's own matcher with the gateway's Python, fixed arguments
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

CHILDREN = 2                 # concurrent matcher processes
ACQUIRE_FACTOR = 1.0         # how long a check may wait for a free matcher, as a multiple of its deadline
_CACHE_MAX = 4000            # compiled patterns kept per child
_CMD_HEAD = re.compile(r"\s*([A-Za-z_][\w-]*)")


# ---------------------------------------------------------------------------------------------- matching (pure)
def pipeline_commands(text: str) -> list[str]:
    """SPL-aware: the command at the start of every pipeline segment (split on `|` and at subsearch `[`, outside
    double quotes; backslash escapes inside quotes), lower case. Single quotes are NOT quotes here: in SPL they only
    quote field names inside eval/where expressions, and the base search treats them as ordinary characters, so a
    `'` must not hide a following `| outputlookup` (security review 2026-11-11, SA-5)."""
    cmds: list[str] = []
    seg: list[str] = []
    quote = False
    esc = False

    def close():
        m = _CMD_HEAD.match("".join(seg))
        if m:
            cmds.append(m.group(1).lower())
        seg.clear()
    for ch in text:
        if quote:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                quote = False
            continue
        if ch == '"':
            quote = True
            seg.append(" ")
            continue
        if ch in "|[":
            close()
            continue
        seg.append(ch)
    close()
    return cmds


def words_pattern(phrase: str) -> str:
    """The regex of a `words` rule entry: the words in order, any whitespace between them, not inside a word."""
    return r"(?<!\w)" + r"\s+".join(re.escape(w) for w in str(phrase).split()) + r"(?!\w)"


def _compiled(kind: str, p: str, cache: dict) -> re.Pattern:
    key = (kind, p)
    rx = cache.get(key)
    if rx is None:
        if len(cache) > _CACHE_MAX:
            cache.clear()
        rx = cache[key] = re.compile(words_pattern(p) if kind == "words" else p, re.IGNORECASE)
    return rx


def match_items(items: list, texts: list, cache: dict | None = None) -> int:
    """Index of the first item whose patterns match one of its texts, else -1."""
    cache = {} if cache is None else cache
    for i, item in enumerate(items):
        kind, patterns, ti = item[0], item[1], int(item[2])
        tl = texts[ti] if 0 <= ti < len(texts) else []
        if kind == "pipeline":
            words = {str(p).lower() for p in patterns}
            for t in tl:
                if t and words.intersection(pipeline_commands(t)):
                    return i
            continue
        rxs = [_compiled(kind, str(p), cache) for p in patterns]
        for t in tl:
            if not t:
                continue
            for rx in rxs:
                if rx.search(t):
                    return i
    return -1


# ---------------------------------------------------------------------------------------------- child process
def serve() -> None:
    """The child: answer one request per line until stdin closes (the gateway stopped or killed it)."""
    inp, out = sys.stdin.buffer, sys.stdout.buffer
    cache: dict = {}
    while True:
        line = inp.readline()
        if not line:
            return
        try:
            req = json.loads(line)
            res: dict[str, Any] = {"hit": match_items(req.get("items") or [], req.get("texts") or [], cache)}
        except Exception as e:  # a bad request must not kill the matcher
            res = {"error": f"{e.__class__.__name__}: {e}"[:300]}
        out.write((json.dumps(res) + "\n").encode("ascii"))
        out.flush()


class RuleTimeout(Exception):
    """The rules did not finish within the deadline (or no matcher was free in time)."""


class RuleRunnerError(Exception):
    """The matcher could not be started or answered with an error."""


_CHILD_CODE = "from goose_web.rulematch import serve; serve()"


class _Child:
    def __init__(self) -> None:
        flags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
        # sys.executable is the gateway's own interpreter; the arguments are fixed (no user input).
        self.proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-E", "-s", "-c", _CHILD_CODE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=str(Path(__file__).resolve().parent.parent), creationflags=flags)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, name="guard-rules-reader", daemon=True).start()

    def _read(self) -> None:
        try:
            for line in self.proc.stdout:
                self.lines.put(line)
        except (OSError, ValueError):
            pass
        self.lines.put(None)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass
        for f in (self.proc.stdin, self.proc.stdout):
            try:
                f.close()
            except (OSError, ValueError):
                pass


class RuleRunner:
    """A small pool of matcher processes. `match()` is awaited by the guard; the event loop only waits."""

    def __init__(self, children: int = CHILDREN):
        self.size = max(1, int(children))
        self._idle: list[_Child] = []
        self._count = 0
        self._cond = threading.Condition()
        self._pool = ThreadPoolExecutor(max_workers=self.size * 8, thread_name_prefix="guard-rules")
        self.spawned = 0
        self.killed = 0

    def _acquire(self, timeout: float) -> _Child:
        end = time.monotonic() + timeout
        with self._cond:
            while True:
                while self._idle:
                    ch = self._idle.pop()
                    if ch.alive():
                        return ch
                    self._count -= 1
                if self._count < self.size:
                    self._count += 1
                    break
                left = end - time.monotonic()
                if left <= 0:
                    raise RuleTimeout("every rule matcher is busy")
                self._cond.wait(left)
        try:
            ch = _Child()
            self.spawned += 1
            return ch
        except Exception as e:
            with self._cond:
                self._count -= 1
                self._cond.notify()
            raise RuleRunnerError(f"cannot start the rule matcher: {e}") from e

    def _release(self, ch: _Child, ok: bool) -> None:
        with self._cond:
            if ok and ch.alive():
                self._idle.append(ch)
            else:
                ch.kill()
                self.killed += 1
                self._count -= 1
            self._cond.notify()

    def call(self, items: list, texts: list, timeout: float) -> int:
        """Blocking (run in a thread): the index of the first matching item, -1 for none."""
        payload = (json.dumps({"items": items, "texts": texts}, ensure_ascii=True, separators=(",", ":"))
                   + "\n").encode("ascii")
        ch = self._acquire(max(0.05, timeout * ACQUIRE_FACTOR))
        ok = False
        try:
            t0 = time.monotonic()
            try:
                ch.proc.stdin.write(payload)
                ch.proc.stdin.flush()
            except (OSError, ValueError) as e:
                raise RuleRunnerError(f"the rule matcher stopped: {e}") from e
            try:
                line = ch.lines.get(timeout=max(0.01, timeout - (time.monotonic() - t0)))
            except queue.Empty:
                raise RuleTimeout(f"the rules took longer than {timeout * 1000:.0f} ms") from None
            if line is None:
                raise RuleRunnerError("the rule matcher stopped")
            res = json.loads(line)
            if "error" in res:
                ok = True   # the child is fine; the request was bad
                raise RuleRunnerError(str(res["error"]))
            ok = True
            return int(res.get("hit", -1))
        finally:
            self._release(ch, ok)

    async def match(self, items: list, texts: list, timeout: float) -> int:
        if not items:
            return -1
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._pool, self.call, items, texts, timeout)

    def shutdown(self) -> None:
        with self._cond:
            idle, self._idle = self._idle, []
            self._count -= len(idle)
        for ch in idle:
            ch.kill()


_RUNNER: RuleRunner | None = None
_RUNNER_LOCK = threading.Lock()


def runner() -> RuleRunner:
    """The process-wide matcher pool (created on first use)."""
    global _RUNNER
    with _RUNNER_LOCK:
        if _RUNNER is None:
            _RUNNER = RuleRunner()
        return _RUNNER


def shutdown() -> None:
    global _RUNNER
    with _RUNNER_LOCK:
        r, _RUNNER = _RUNNER, None
    if r is not None:
        r.shutdown()
