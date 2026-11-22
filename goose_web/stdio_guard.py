"""stdio_guard.py - Goose Web's start-up guard for a member's stdio MCP extension (since 1.26.1).

Goose 1.57 starts a stdio extension by sending `server/discover` and waiting 10 seconds. A server that needs longer
(uv installing it on first use, a slow Python start in a sandbox) then also gets the legacy `initialize` on the same
connection, and a server that speaks the 2026-07-28 protocol answers the late `discover` and rejects `initialize`
(error -32022). Goose never completes the extension's start, and a chat that waits for it never opens.

This guard sits between Goose and the server:

- it answers `server/discover` itself, at once, with "method not found": Goose takes the legacy `initialize` path,
  which has no 10-second window, and the server never sees `discover`, so the race cannot happen;
- everything else passes through unchanged, in both directions;
- the server gets --limit seconds to answer `initialize` (0 = no limit). If it does not, its whole process tree is
  ended, Goose gets an error naming the extension and the limit, and the guard exits; Goose reports the extension as
  failed and the chat opens without it;
- the server's process tree ends with the guard (1.26.2, FIX stdio-guard-orphans): the server is started suspended
  and put into a kill-on-close Windows job before it runs, so nothing it starts is created outside the job (a
  launcher such as uvx starts its child within milliseconds) and ending the job ends the whole tree; if the job
  cannot be used, the server's descendants are found by process snapshot and ended; `taskkill /T` last;
- the server has its own stderr pipe, which the guard forwards line by line: whatever survives, Goose's stderr is
  closed when the guard ends (Goose reads an extension's stderr to the end before it reports the failure).

Goose Web writes this file into each isolated member's profile (.goose-web/stdio_guard.py) and starts a team's stdio
extensions through it on the members' Python:

    python -I stdio_guard.py [--limit 120] [--name NAME] -- COMMAND [ARGS...]

Standard library only. It reads and writes no file; its own messages go to stderr (Goose's extension log).
"""
import json
import os
import subprocess
import sys
import threading

DISCOVER = "server/discover"
METHOD_NOT_FOUND = -32601
START_FAILED = -32000
PREFIX = "[goose-web start-up guard]"
CREATE_SUSPENDED = 0x00000004


def parse_args(argv):
    """(limit seconds, name, command). Unknown options before `--` are ignored."""
    limit, name, i = 120.0, "extension", 0
    while i < len(argv) and argv[i] != "--":
        if argv[i] == "--limit" and i + 1 < len(argv):
            try:
                limit = float(argv[i + 1])
            except ValueError:
                pass
            i += 2
            continue
        if argv[i] == "--name" and i + 1 < len(argv):
            name = argv[i + 1]
            i += 2
            continue
        i += 1
    return max(0.0, limit), name, list(argv[i + 1:])


# ------------------------------------------------------------------------------------------------ Windows helpers
_W = {}


def _win():
    """kernel32/ntdll and the structures, loaded once (Windows only)."""
    if _W:
        return _W
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class Basic(ctypes.Structure):
        _fields_ = [("a", ctypes.c_longlong), ("b", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                    ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", wintypes.DWORD),
                    ("f", ctypes.c_size_t), ("g", wintypes.DWORD), ("h", wintypes.DWORD)]

    class Ext(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("Io", IO), ("a", ctypes.c_size_t), ("b", ctypes.c_size_t),
                    ("c", ctypes.c_size_t), ("d", ctypes.c_size_t)]

    class Entry(ctypes.Structure):     # PROCESSENTRY32W
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("pid", wintypes.DWORD),
                    ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                    ("ppid", wintypes.DWORD), ("prio", ctypes.c_long), ("flags", wintypes.DWORD),
                    ("exe", ctypes.c_wchar * 260)]

    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _W.update(ctypes=ctypes, wt=wintypes, k32=k32, ntdll=ctypes.WinDLL("ntdll"), Ext=Ext, Entry=Entry)
    return _W


def _created(handle):
    """Creation time (FILETIME as an int) of the process behind an open handle, or None."""
    w = _win()
    c = w["ctypes"]
    t = [c.c_ulonglong() for _ in range(4)]
    if not w["k32"].GetProcessTimes(w["wt"].HANDLE(int(handle)), *[c.byref(x) for x in t]):
        return None
    return t[0].value


def _created_pid(pid):
    w = _win()
    h = w["k32"].OpenProcess(0x1000, False, int(pid))         # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return None
    try:
        return _created(h)
    finally:
        w["k32"].CloseHandle(h)


def _snapshot():
    """[(pid, parent pid)] of every process now, or [] when the snapshot fails."""
    w = _win()
    c, k32 = w["ctypes"], w["k32"]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)                 # TH32CS_SNAPPROCESS
    if not snap or snap == w["wt"].HANDLE(-1).value:
        return []
    rows = []
    try:
        e = w["Entry"]()
        e.dwSize = c.sizeof(e)
        ok = k32.Process32FirstW(snap, c.byref(e))
        while ok:
            rows.append((int(e.pid), int(e.ppid)))
            ok = k32.Process32NextW(snap, c.byref(e))
    finally:
        k32.CloseHandle(snap)
    return rows


def descendants(roots):
    """{pid: creation time} of the descendants of `roots` ({pid: creation time}), found by parent links in a process
    snapshot. A child counts only if it was created after its parent, and a process id that is now alive as another
    process (or cannot be examined) is not followed. Only roots can be processes that have ended (the server's own
    process, or descendants remembered while they were alive); the guard uses this only when the server could not be
    put into its job."""
    rows = _snapshot()
    alive = {pid for pid, _ in rows}
    kids = {}
    for pid, ppid in rows:
        if pid != ppid:
            kids.setdefault(ppid, []).append(pid)
    found, stack = {}, list(roots.items())
    while stack:
        pid, born = stack.pop()
        if pid in alive and (born is None or _created_pid(pid) != born):
            continue                     # the id now belongs to another process (or cannot be examined): not ours
        for k in kids.get(pid, ()):
            if k in found or k in roots:
                continue
            kb = _created_pid(k)
            if kb is None or (born is not None and kb < born):
                continue
            found[k] = kb
            stack.append((k, kb))
    return found


def _terminate(pid, born):
    """End one process if it is still the one created at `born` (checked through the handle that ends it)."""
    w = _win()
    h = w["k32"].OpenProcess(0x1001, False, int(pid))         # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    try:
        if born is not None and _created(h) != born:
            return False
        return bool(w["k32"].TerminateProcess(h, 1))
    finally:
        w["k32"].CloseHandle(h)


def _resume(proc):
    """Resume a process created suspended (NtResumeProcess on its handle)."""
    w = _win()
    return w["ntdll"].NtResumeProcess(w["wt"].HANDLE(int(proc._handle))) == 0


class Job:
    """Windows job object with KILL_ON_JOB_CLOSE: the server's whole tree ends with the guard (best effort)."""

    def __init__(self):
        self.h = None
        if os.name != "nt":
            return
        try:
            w = _win()
            k32, c = w["k32"], w["ctypes"]
            h = k32.CreateJobObjectW(None, None)
            info = w["Ext"]()
            info.Basic.LimitFlags = 0x2000                  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if h and k32.SetInformationJobObject(w["wt"].HANDLE(h), 9, c.byref(info), c.sizeof(info)):
                self.h = h
            elif h:
                k32.CloseHandle(w["wt"].HANDLE(h))
        except Exception:
            self.h = None

    def add(self, proc):
        if not self.h:
            return False
        try:
            w = _win()
            return bool(w["k32"].AssignProcessToJobObject(w["wt"].HANDLE(self.h), w["wt"].HANDLE(int(proc._handle))))
        except Exception:
            return False

    def end(self):
        if self.h:
            try:
                w = _win()
                w["k32"].TerminateJobObject(w["wt"].HANDLE(self.h), 1)
            except Exception:
                pass


def _parse(line):
    try:
        m = json.loads(line)
    except ValueError:
        return None
    return m if isinstance(m, dict) else None


class Guard:
    def __init__(self, cmd, limit, name, stdin, stdout, stderr):
        self.cmd, self.limit, self.name = cmd, limit, name
        self.inp, self.out, self.err = stdin, stdout, stderr
        self.wlock = threading.Lock()
        self.elock = threading.Lock()
        self.state = threading.Lock()
        self.init_id = None
        self.init_seen = False
        self.started = False        # the server answered initialize
        self.gave_up = False
        self.done = threading.Event()
        self.timed_out = threading.Event()   # time_up has ended the server and answered Goose
        self.proc = None
        self.job = None
        self.in_job = False
        self.root = {}              # {pid: creation time} of the server's direct process
        self.known = {}             # its descendants, remembered once it has started
        self.err_thread = None

    def log(self, msg):
        with self.elock:
            try:
                self.err.write(f"{PREFIX} {self.name}: {msg}\n".encode("utf-8", "replace"))
                self.err.flush()
            except (OSError, ValueError):
                pass

    def write(self, data):
        with self.wlock:
            try:
                self.out.write(data)
                self.out.flush()
            except (OSError, ValueError):
                self.done.set()

    def reply_error(self, mid, code, msg):
        self.write((json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}) + "\n")
                   .encode("utf-8"))

    def remember_tree(self):
        if os.name == "nt" and self.root:
            try:
                self.known.update(descendants(dict(self.root)))
            except Exception:
                pass

    def end_tree(self):
        """Every descendant of the server's direct process (and of those remembered), for up to three rounds."""
        if os.name != "nt" or not self.root:
            return
        roots = {**self.root, **self.known}
        for _ in range(3):
            try:
                found = descendants(roots)
            except Exception:
                return
            found.update({p: b for p, b in self.known.items() if p not in self.root})
            alive = [(p, b) for p, b in found.items() if _terminate(p, b)]
            if not alive:
                return
            roots.update(found)
            self.known = {}

    def end_server(self):
        p = self.proc
        if p is None:
            return
        if self.in_job:
            # the server joined the job before it ran and the job allows no breakaway: ending the job ends every
            # process of its tree, also those whose parent has already ended
            self.job.end()
        else:
            self.end_tree()          # no job: the tree by process snapshot
        if p.poll() is None and os.name == "nt":
            try:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True, timeout=15)
            except Exception:
                pass
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass

    def drain_err(self, seconds):
        t = self.err_thread
        if t is not None:
            t.join(seconds)

    def time_up(self, mid):
        with self.state:
            if self.started or self.done.is_set():
                return
            self.gave_up = True
        msg = (f"the extension '{self.name}' did not start within {self.limit:g} s; Goose Web's start-up guard "
               "stopped its server")
        try:
            self.end_server()
            self.drain_err(2.0)      # what the server wrote before it ended comes first in Goose's message
            self.log(msg)
            self.reply_error(mid, START_FAILED, msg)
        finally:
            self.timed_out.set()
            self.done.set()

    def from_goose(self):
        try:
            for line in iter(self.inp.readline, b""):
                with self.state:
                    if self.gave_up:
                        break
                    handshake = not self.started
                if handshake:
                    m = _parse(line)
                    if m is not None and m.get("method") == DISCOVER and "id" in m:
                        # answered here: the server never sees discover, Goose falls back to initialize at once
                        self.reply_error(m["id"], METHOD_NOT_FOUND,
                                         "Method not found: server/discover (Goose Web start-up guard: use initialize)")
                        continue
                    if m is not None and m.get("method") == "initialize" and "id" in m and not self.init_seen:
                        self.init_id, self.init_seen = m["id"], True
                        if self.limit > 0:
                            t = threading.Timer(self.limit, self.time_up, args=(m["id"],))
                            t.daemon = True
                            t.start()
                try:
                    self.proc.stdin.write(line)
                    self.proc.stdin.flush()
                except (OSError, ValueError):
                    break
        finally:
            # Goose closed the guard's input (or the server's input broke): give the server a moment, then end it
            try:
                self.proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.end_server()
            self.done.set()

    def from_server(self):
        for line in iter(self.proc.stdout.readline, b""):
            with self.state:
                if self.gave_up:
                    break
                if not self.started and self.init_seen:
                    m = _parse(line)
                    if m is not None and "method" not in m and m.get("id") == self.init_id:
                        self.started = True
                        threading.Thread(target=self.remember_tree, daemon=True).start()
            self.write(line)
        self.done.set()

    def from_server_err(self):
        try:
            for line in iter(lambda: self.proc.stderr.readline(65536), b""):     # bounded: a line without end
                with self.elock:
                    try:
                        self.err.write(line)
                        self.err.flush()
                    except (OSError, ValueError):
                        pass
        except (OSError, ValueError):
            pass

    def run(self):
        if not self.cmd:
            self.log("no server command after --")
            return 2
        nt = os.name == "nt"
        self.job = Job() if nt else None
        try:
            # buffered pipes: readline on an unbuffered pipe reads byte by byte (large tool results); its own stderr
            # pipe (forwarded below), so no process of the server ever holds Goose's
            self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, creationflags=CREATE_SUSPENDED if nt else 0)
        except OSError as e:
            self.log(f"cannot start {self.cmd[0]}: {e}")
            return 1
        if nt:
            # suspended until it is in the job: nothing it starts can be created outside the job
            self.in_job = self.job.add(self.proc)
            if not self.in_job:
                self.log("the server could not be put into a job object; its processes are ended by process "
                         "snapshot instead")
            try:
                self.root = {self.proc.pid: _created(self.proc._handle)}
            except Exception:
                self.root = {self.proc.pid: None}
            try:
                resumed = _resume(self.proc)
            except Exception:
                resumed = False
            if not resumed:
                self.log(f"cannot resume {self.cmd[0]}")
                self.end_server()
                return 1
        self.err_thread = threading.Thread(target=self.from_server_err, daemon=True)
        self.err_thread.start()
        threading.Thread(target=self.from_server, daemon=True).start()
        threading.Thread(target=self.from_goose, daemon=True).start()
        self.done.wait()
        if self.gave_up:
            # the server's end (EOF) can wake us before time_up has told Goose why: let it finish first
            self.timed_out.wait(30)
            return 1
        try:
            rc = self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.end_server()
            rc = 1
        self.drain_err(2.0)
        return rc


def _exit_code(rc):
    """os._exit takes a signed 32-bit int: a Windows crash status such as 0xC0000005 is passed on as its negative
    form; anything else that is not a usable int becomes 1."""
    if not isinstance(rc, int) or isinstance(rc, bool):
        return 1
    if 2 ** 31 <= rc < 2 ** 32:
        return rc - 2 ** 32
    return rc if -2 ** 31 <= rc < 2 ** 31 else 1


def main(argv=None):
    limit, name, cmd = parse_args(sys.argv[1:] if argv is None else argv)
    g = Guard(cmd, limit, name, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)
    return g.run()


if __name__ == "__main__":
    rc = main()
    try:
        sys.stdout.buffer.flush()
        sys.stderr.flush()
    finally:
        # not sys.exit: a reader thread may still block on stdin, and the interpreter's shutdown would then wait
        # for (or abort on) that stream's lock
        os._exit(_exit_code(rc))
