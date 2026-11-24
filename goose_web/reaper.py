"""Orphan reaper (FIX idle-sessions-keep-mcp-servers), Windows only.

When Goose 1.57 lets a stdio MCP server go (a chat closed or unloaded, an extension removed), it kills only the
server's DIRECT child process. A launcher such as uvx, npx or a virtual environment's python.exe starts the real
server as its own child, and that grandchild survives: it keeps running in the worker's job object, with no parent,
until the worker stops.

Every TICK_SECONDS the reaper lists the processes in each running worker's job object (QueryInformationJobObject,
JobObjectBasicProcessIdList; nested jobs included) and

- classifies MCP server trees: a direct child of the worker's goose.exe whose command line matches one of the
  profile's configured stdio extensions (config.yaml `extensions` entries of type stdio: cmd + args) is the root of a
  tree, and every process descending from it (parent links checked against creation times) belongs to that tree.
  Processes are keyed by (pid, creation time), so a reused pid is another process;
- ends a classified process only when its tree's root has ended AND its own ancestor chain no longer reaches the
  worker's goose.exe, once that has lasted longer than goose.orphan_grace_seconds. Each one is audited
  (worker.orphan_ended) with its command line, secrets masked.

It never touches the worker itself, the gateway, anything outside the worker's job, anything it never classified (a
program a developer-shell command left running in the background, say), or a pid that now belongs to another process
(stdio_guard._terminate checks the creation time through the handle that ends it). Off Windows it does nothing.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("goose_web.reaper")
IS_WINDOWS = os.name == "nt"
TICK_SECONDS = 60.0
MAX_CHAIN = 64                    # ancestors followed at most
MAX_TERMINATE_TRIES = 3
_PROGRAM_SUFFIXES = (".exe", ".cmd", ".bat", ".com")


# ------------------------------------------------------------------ command lines
def split_cmdline(line: str) -> list[str]:
    """A Windows command line split into its arguments (the Microsoft C runtime rules)."""
    out: list[str] = []
    cur: list[str] = []
    have = quoted = False
    i, n = 0, len(line or "")
    while i < n:
        ch = line[i]
        if ch == "\\":
            j = i
            while j < n and line[j] == "\\":
                j += 1
            if j < n and line[j] == '"':
                cur.append("\\" * ((j - i) // 2))
                if (j - i) % 2:
                    cur.append('"')
                    j += 1
                i, have = j, True
                continue
            cur.append(line[i:j])
            i, have = j, True
            continue
        if ch == '"':
            if quoted and i + 1 < n and line[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            quoted, have, i = not quoted, True, i + 1
            continue
        if ch in " \t" and not quoted:
            if have:
                out.append("".join(cur))
                cur, have = [], False
            i += 1
            continue
        cur.append(ch)
        have, i = True, i + 1
    if have:
        out.append("".join(cur))
    return out


def _words(items: Any) -> list[str]:
    return [w for it in items for w in str(it).split()]


def _program(word: str) -> str:
    base = re.split(r"[\\/]", word.strip().strip('"'))[-1].lower()
    for suffix in _PROGRAM_SUFFIXES:
        if base.endswith(suffix):
            return base[:-len(suffix)]
    return base


def _arg(word: str) -> str:
    return word.replace("\\", "/").casefold()


def _in_order(needle: list[str], hay: list[str]) -> bool:
    it = iter(hay)
    return all(any(x == y for y in it) for x in needle)


def match_extension(line: str, exts: list[tuple[str, str, list[str]]]) -> str | None:
    """The name of the configured stdio extension this command line runs, or None: the extension's program appears
    in it (folder and .exe/.cmd/.bat ignored; also inside a `cmd /c "..."` wrapper), followed in order by its args."""
    words = _words(split_cmdline(line or ""))
    progs, args = [_program(w) for w in words], [_arg(w) for w in words]
    for name, cmd, ext_args in exts:
        want = _program(str(cmd))
        if not want:
            continue
        need = [_arg(a) for a in _words(ext_args)]
        if any(p == want and _in_order(need, args[i + 1:]) for i, p in enumerate(progs)):
            return name
    return None


_SECRET_WORD = r"[\w.-]*(?:key|token|secret|passw(?:or)?d|pwd|auth|credential)[\w.-]*"
_SECRET_FLAG = re.compile(r"(?i)(--?" + _SECRET_WORD + r")(=|\s+)(\"[^\"]*\"|\S+)")
_SECRET_SET = re.compile(r"(?i)(?<![\w-])(" + _SECRET_WORD + r")=(\"[^\"]*\"|\S+)")
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
_OPAQUE = re.compile(r"(?<![\w\\/.:@-])[A-Za-z0-9_+=-]{32,}(?![\w\\/.:@-])")


def mask_cmdline(line: str, limit: int = 600) -> str:
    """A command line for the audit: values of key/token/secret/password options, credentials in URLs and long
    opaque strings become ***."""
    s = _URL_CREDENTIALS.sub(r"\1***@", line or "")
    s = _SECRET_FLAG.sub(lambda m: m.group(1) + m.group(2) + "***", s)
    s = _SECRET_SET.sub(lambda m: m.group(1) + "=***", s)
    s = _OPAQUE.sub("***", s)
    return s[:limit]


# ------------------------------------------------------------------ Windows calls
class WinProcs:
    """The Windows calls the reaper makes (tests replace this object)."""

    def __init__(self):
        from . import stdio_guard as sg
        self.sg = sg

    def job_pids(self, handle: Any) -> list[int]:
        """Processes in a job object and the jobs nested in it (JobObjectBasicProcessIdList)."""
        w = self.sg._win()
        c, wt, k32 = w["ctypes"], w["wt"], w["k32"]
        query = k32.QueryInformationJobObject
        query.argtypes = [wt.HANDLE, c.c_int, c.c_void_p, wt.DWORD, c.c_void_p]
        query.restype = wt.BOOL
        n = 1024
        for _ in range(4):
            class IdList(c.Structure):
                _fields_ = [("assigned", wt.DWORD), ("listed", wt.DWORD), ("ids", c.c_size_t * n)]
            buf = IdList()
            if query(wt.HANDLE(int(handle)), 3, c.byref(buf), c.sizeof(buf), None):
                return [int(buf.ids[i]) for i in range(min(buf.listed, n))]
            if c.get_last_error() != 234:            # ERROR_MORE_DATA: a larger list, else give up
                return []
            n = max(n * 4, int(buf.assigned) + 64)
        return []

    def snapshot(self) -> list[tuple[int, int, str]]:
        """[(pid, parent pid, image name)] of every process now."""
        w = self.sg._win()
        c, k32 = w["ctypes"], w["k32"]
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)
        if not snap or snap == w["wt"].HANDLE(-1).value:
            return []
        rows = []
        try:
            e = w["Entry"]()
            e.dwSize = c.sizeof(e)
            ok = k32.Process32FirstW(snap, c.byref(e))
            while ok:
                rows.append((int(e.pid), int(e.ppid), str(e.exe)))
                ok = k32.Process32NextW(snap, c.byref(e))
        finally:
            k32.CloseHandle(snap)
        return rows

    def created(self, pid: int) -> int | None:
        return self.sg._created_pid(pid)

    def cmdline(self, pid: int) -> str | None:
        """The process's command line (NtQueryInformationProcess, ProcessCommandLineInformation), or None."""
        w = self.sg._win()
        c, wt, k32 = w["ctypes"], w["wt"], w["k32"]
        nt = w["ntdll"].NtQueryInformationProcess
        nt.argtypes = [wt.HANDLE, c.c_int, c.c_void_p, wt.ULONG, c.POINTER(wt.ULONG)]
        nt.restype = c.c_long
        h = k32.OpenProcess(0x1000, False, int(pid))        # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            size = wt.ULONG(0)
            nt(h, 60, None, 0, c.byref(size))
            if not 0 < size.value <= 1 << 20:
                return None
            buf = c.create_string_buffer(size.value)
            if nt(h, 60, buf, size.value, c.byref(size)) != 0:
                return None

            class Text(c.Structure):    # UNICODE_STRING
                _fields_ = [("Length", c.c_ushort), ("MaximumLength", c.c_ushort), ("Buffer", c.c_void_p)]
            us = Text.from_buffer(buf)
            return c.wstring_at(us.Buffer, us.Length // 2) if us.Buffer and us.Length else ""
        finally:
            k32.CloseHandle(h)

    def terminate(self, pid: int, born: int) -> bool:
        return self.sg._terminate(pid, born)


# ------------------------------------------------------------------ the reaper
class OrphanReaper:
    def __init__(self, settings: Any, workers: Any, audit: Callable[[str, dict], None] | None = None,
                 procs: Any = None):
        self.s = settings
        self.workers = workers
        self.audit = audit           # (username of the worker's profile, detail) -> an audit row
        self.procs = procs
        self.trees: dict[str, dict[tuple[int, int], dict]] = {}   # worker key -> {(pid, born): entry}
        self.unmatched: dict[str, set[tuple[int, int]]] = {}      # goose children whose command line matched nothing
        self.ended = 0
        self._cfg: dict[str, tuple] = {}
        self._task: asyncio.Task | None = None

    def knobs(self) -> tuple[bool, int]:
        from .config import orphan_reaper
        on, grace, _ = orphan_reaper(self.s)
        return on, grace

    def start(self) -> None:
        if IS_WINDOWS and self._task is None:
            self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        t, self._task = self._task, None
        if t is not None:
            t.cancel()

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(TICK_SECONDS)
                await self.run_once()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("orphan reaper")

    def targets(self) -> list[dict]:
        """The running workers with a job object (read on the event loop; the sweep runs in a thread)."""
        from .config import default_native_goose_root
        out = []
        for w in list(getattr(self.workers, "workers", {}).values()):
            job = getattr(w, "job", None)
            handle = getattr(job, "handle", None) if job is not None else None
            if getattr(w, "state", "") != "ready" or not handle:
                continue
            root = Path(w.path_root or default_native_goose_root())
            out.append({"key": w.key, "username": w.username, "handle": handle,
                        "config": root / "config" / "config.yaml"})
        return out

    async def run_once(self) -> list[dict]:
        on, grace = self.knobs()
        if not IS_WINDOWS or not on:
            self.trees.clear()
            self.unmatched.clear()
            return []
        image = os.path.basename(str(self.s.goose_binary or "goose.exe")).lower() or "goose.exe"
        image = image if image.endswith(".exe") else image + ".exe"
        ended = await asyncio.to_thread(self.sweep, self.targets(), time.time(), grace, image)
        for e in ended:
            if self.audit is not None:
                try:
                    self.audit(e.pop("username"), e)
                except Exception:
                    log.exception("orphan reaper audit")
        return ended

    def sweep(self, targets: list[dict], now: float, grace: float, image: str = "goose.exe") -> list[dict]:
        if not IS_WINDOWS and self.procs is None:
            return []
        procs = self.procs or WinProcs()
        keys = {t["key"] for t in targets}
        for k in [k for k in self.trees if k not in keys]:
            self.trees.pop(k, None)
            self.unmatched.pop(k, None)
        out = []
        for t in targets:
            try:
                out += self.sweep_worker(procs, t, now, grace, image)
            except Exception:
                log.exception("orphan reaper: worker %s", t.get("key"))
        return out

    def _extensions(self, key: str, path: Path) -> list[tuple[str, str, list[str]]]:
        """(name, cmd, args) of the profile's stdio extensions (config.yaml; read again only when it changed)."""
        try:
            st = os.stat(path)
        except OSError:
            return []
        sig = (str(path), st.st_mtime_ns, st.st_size)
        cached = self._cfg.get(key)
        if cached is not None and cached[0] == sig:
            return cached[1]
        exts: list[tuple[str, str, list[str]]] = []
        try:
            import yaml
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            entries = data.get("extensions") if isinstance(data, dict) else None
            for k, e in (entries.items() if isinstance(entries, dict) else ()):
                if isinstance(e, dict) and e.get("type") == "stdio" and e.get("cmd"):
                    args = e.get("args") if isinstance(e.get("args"), list) else []
                    exts.append((str(e.get("name") or k), str(e["cmd"]), [str(a) for a in args]))
        except Exception as e:
            log.debug("orphan reaper: reading %s: %s", path, e)
        self._cfg[key] = (sig, exts)
        return exts

    def sweep_worker(self, procs: Any, t: dict, now: float, grace: float, image: str) -> list[dict]:
        key = t["key"]
        members = set(procs.job_pids(t["handle"]))
        if not members:
            return []
        rows = procs.snapshot()
        parent = {pid: ppid for pid, ppid, _ in rows}
        exe = {pid: str(name).lower() for pid, _, name in rows}
        known_born: dict[int, int | None] = {}

        def born(pid: Any) -> int | None:
            if pid not in known_born:
                known_born[pid] = procs.created(pid) if pid in parent else None
            return known_born[pid]

        # the worker's goose: a goose.exe in the job whose parent is not a goose.exe in the job
        gooses = {}
        for p in members:
            pp = parent.get(p)
            if exe.get(p) == image and not (pp in members and exe.get(pp) == image) and born(p) is not None:
                gooses[p] = born(p)
        trees = self.trees.setdefault(key, {})
        unmatched = self.unmatched.setdefault(key, set())
        alive = {(p, born(p)) for p in members if born(p) is not None}
        for k in [k for k in trees if k not in alive]:
            del trees[k]     # ended, left the job, or the pid now belongs to another process
        unmatched &= alive
        # new tree roots: direct children of the worker's goose that run a configured stdio extension
        exts = self._extensions(key, t["config"])
        for p in sorted(members):
            pp, b = parent.get(p), born(p)
            if pp not in gooses or b is None or b < gooses[pp] or (p, b) in trees or (p, b) in unmatched:
                continue
            line = procs.cmdline(p)
            name = match_extension(line or "", exts) if exts else None
            if name is None:
                unmatched.add((p, b))
                continue
            trees[(p, b)] = {"root": (p, b), "ext": name, "cmd": mask_cmdline(line or ""), "detached": None}
        # their descendants (each created after its parent)
        grew = True
        while grew:
            grew = False
            for p in sorted(members):
                b = born(p)
                if b is None or (p, b) in trees or (p, b) in unmatched:
                    continue
                pp = parent.get(p)
                pb = born(pp) if pp is not None and pp != p else None
                e = trees.get((pp, pb)) if pb is not None and pb <= b else None
                if e is not None:
                    trees[(p, b)] = {"root": e["root"], "ext": e["ext"], "cmd": None, "detached": None}
                    grew = True
        # end what has been cut off from goose for longer than the grace period
        ended = []
        for k, e in list(trees.items()):
            pid, b = k
            if e["root"] in alive or self._reaches_goose(pid, b, parent, born, gooses):
                e["detached"] = None
                continue
            if e["detached"] is None:
                e["detached"] = now
                continue
            if now - e["detached"] < grace:
                continue
            line = e["cmd"] if e["cmd"] is not None else mask_cmdline(procs.cmdline(pid) or "")
            if procs.terminate(pid, b):
                del trees[k]
                self.ended += 1
                detail = {"profile": key, "pid": pid, "extension": e["ext"], "commandLine": line,
                          "detachedSeconds": int(now - e["detached"])}
                log.warning("orphan reaper: ended process %s of worker %s (extension %s, cut off from goose for "
                            "%d s): %s", pid, key, e["ext"], detail["detachedSeconds"], line)
                ended.append({"username": t.get("username") or key, **detail})
            else:
                e["tries"] = e.get("tries", 0) + 1
                if e["tries"] >= MAX_TERMINATE_TRIES:
                    log.warning("orphan reaper: could not end process %s of worker %s; leaving it", pid, key)
                    del trees[k]
                    unmatched.add(k)   # never classified again while it lives
        return ended

    @staticmethod
    def _reaches_goose(pid: int, b: int, parent: dict, born: Callable[[Any], int | None], gooses: dict) -> bool:
        """Does the process's chain of (living, older) parents lead to the worker's goose?"""
        cur, cb = pid, b
        for _ in range(MAX_CHAIN):
            pp = parent.get(cur)
            if pp is None or pp == cur:
                return False
            if pp in gooses:
                return gooses[pp] <= cb
            pb = born(pp)
            if pb is None or pb > cb:
                return False   # the parent ended, or its pid now belongs to a newer process
            cur, cb = pp, pb
        return False
