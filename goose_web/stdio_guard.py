"""stdio_guard.py - Goose Web's start-up guard for a member's stdio MCP extension (since 1.26.1).

Goose 1.57 starts a stdio extension by sending `server/discover` and waiting 10 seconds. A server that needs longer
(uv installing it on first use, a slow Python start in a sandbox) then also gets the legacy `initialize` on the same
connection, and a server that speaks the 2026-07-28 protocol answers the late `discover` and rejects `initialize`
(error -32022). Goose never completes the extension's start, and a chat that waits for it never opens.

This guard sits between Goose and the server:

- it answers `server/discover` itself, at once, with "method not found": Goose takes the legacy `initialize` path,
  which has no 10-second window, and the server never sees `discover`, so the race cannot happen;
- everything else passes through unchanged, in both directions;
- the server gets --limit seconds to answer `initialize` (0 = no limit). If it does not, Goose gets an error naming
  the extension and the limit, the server's process tree is ended and the guard exits; Goose reports the extension
  as failed and the chat opens without it;
- the server's process tree ends with the guard (a Windows job object, else `taskkill /T`).

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


class Job:
    """Windows job object with KILL_ON_JOB_CLOSE: the server's whole tree ends with the guard (best effort)."""

    def __init__(self):
        self.h = None
        if os.name != "nt":
            return
        try:
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

            k32.CreateJobObjectW.restype = wintypes.HANDLE
            h = k32.CreateJobObjectW(None, None)
            info = Ext()
            info.Basic.LimitFlags = 0x2000                  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if h and k32.SetInformationJobObject(wintypes.HANDLE(h), 9, ctypes.byref(info), ctypes.sizeof(info)):
                self.h, self.k32, self.wt = h, k32, wintypes
        except Exception:
            self.h = None

    def add(self, proc):
        if not self.h:
            return False
        try:
            return bool(self.k32.AssignProcessToJobObject(self.wt.HANDLE(self.h), self.wt.HANDLE(int(proc._handle))))
        except Exception:
            return False

    def end(self):
        if self.h:
            try:
                self.k32.TerminateJobObject(self.wt.HANDLE(self.h), 1)
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
        self.state = threading.Lock()
        self.init_id = None
        self.init_seen = False
        self.started = False        # the server answered initialize
        self.gave_up = False
        self.done = threading.Event()
        self.proc = None
        self.job = None
        self.in_job = False

    def log(self, msg):
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

    def end_server(self):
        p = self.proc
        if p is None:
            return
        if self.in_job:
            self.job.end()
        if p.poll() is None:
            try:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True, timeout=15)
                else:
                    p.kill()
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def time_up(self, mid):
        with self.state:
            if self.started or self.done.is_set():
                return
            self.gave_up = True
        msg = (f"the extension '{self.name}' did not start within {self.limit:g} s; Goose Web's start-up guard "
               "stopped its server")
        self.log(msg)
        self.reply_error(mid, START_FAILED, msg)
        self.end_server()
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
            self.write(line)
        self.done.set()

    def run(self):
        if not self.cmd:
            self.log("no server command after --")
            return 2
        try:
            # buffered pipes: readline on an unbuffered pipe reads byte by byte (large tool results)
            self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        except OSError as e:
            self.log(f"cannot start {self.cmd[0]}: {e}")
            return 1
        self.job = Job()
        self.in_job = self.job.add(self.proc)
        threading.Thread(target=self.from_server, daemon=True).start()
        threading.Thread(target=self.from_goose, daemon=True).start()
        self.done.wait()
        if self.gave_up:
            return 1
        try:
            return self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.end_server()
            return 1


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
        os._exit(rc if isinstance(rc, int) else 1)
