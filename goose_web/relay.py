"""Brokered access from sandboxed workers to allow-listed local services (spec 014, Windows).

A sandboxed worker (sandbox.py) cannot reach 127.0.0.1 of the machine, so a model proxy or another local service
that listens on loopback is out of reach. `sandbox.relays` lists the targets ("127.0.0.1:4000") sandboxed workers
may use. For each sandboxed user and target:

  goose (container) --TCP--> forwarder (same container, 127.64.x.y:<port>) --named pipe--> gateway --TCP--> target

- The forwarder runs inside the user's own AppContainer and listens on a loopback address of its own
  (127.64.x.y, derived from the user id), so every user can use the same port as the real service.
- The named pipe is created by the gateway with a DACL that admits only that user's container SID (and the gateway's
  own account), and a low mandatory label so the (low-integrity) container can write to it. Another user's
  container cannot open it.
- Its name is random per worker start (new_pipe_name) and the gateway creates it with FILE_FLAG_FIRST_PIPE_INSTANCE,
  so the relay fails closed if any other process holds the name already. The forwarder gets the name and the
  gateway's process id on its command line and, before it sends a byte, checks that the pipe's server process is
  the gateway (GetNamedPipeServerProcessId): a pipe instance made by any other process is refused.
- The gateway connects each pipe connection to the target over TCP and copies bytes both ways (overlapped I/O, so
  a streaming response and a request can flow at the same time).
- The user's Goose configuration (config/config.yaml and config/custom_providers/*.json in their profile) is
  rewritten so URLs that point at the target point at the user's forwarder address instead; the rewrite is undone
  when the user stops being sandboxed.

Only the listed targets are reachable; everything else on loopback stays closed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
from pathlib import Path

log = logging.getLogger("goose_web.relay")
IS_WINDOWS = sys.platform == "win32"


def parse_target(t: str) -> tuple[str, int]:
    host, _, port = str(t).strip().rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"relay target must be host:port, got {t!r}")
    return host.strip("[]"), int(port)


_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOST = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*\Z")


def target_problem(t) -> str:
    """'' when `t` is a relay target Goose Web can serve ("127.0.0.1:4000", "localhost:4000", "name:port"), else
    why not (AC-6). An IPv6 address is refused: the URL rewrite and the per-user forward address are IPv4."""
    if not isinstance(t, str):
        return "not a text"
    try:
        host, port = parse_target(t)
    except ValueError:
        return "not host:port"
    if not 1 <= port <= 65535:
        return "the port is not between 1 and 65535"
    if not _HOST.match(host):
        return "the host must be an IPv4 address or a name (IPv6 is not supported)"
    return ""


FORWARD_BLOCKS = 32     # services on one port that a user can be given a forward address for


def forward_ip(user_id: int, block: int = 0) -> str:
    """A loopback address of the user's own: 127.<64 + block>.<hi>.<lo> with lo in 1..254 (the whole 127/8 is
    loopback on Windows). Unique for the first 65,024 user ids. `block` > 0 gives the same user a further address,
    for a second relayed service on a port already in use (V-12)."""
    n = int(user_id) % (256 * 254)
    return f"127.{64 + int(block)}.{n // 254}.{n % 254 + 1}"


PIPE_PREFIX = "\\\\.\\pipe\\goose-web-relay."


def new_pipe_name() -> str:
    """A fresh, unguessable pipe name for one relay of one worker start (128 random bits). A predictable name
    would let any local process create the pipe first and sit between the container and the gateway."""
    return PIPE_PREFIX + secrets.token_hex(16)


def relay_specs(container: str, user_id: int, targets: list[str]) -> list[dict]:
    """{target, listen} per allow-listed service. The pipe name is chosen per worker start (new_pipe_name), not
    here: the spec must stay the same between calls (a changed spec marks the worker for a restart)."""
    out, seen, per_port = [], set(), {}
    for t in targets:
        host, port = parse_target(t)
        target = f"{host}:{port}"
        if target.lower() in seen:            # listed twice: one relay
            continue
        seen.add(target.lower())
        # Two services on one port (10.0.0.5:8080 and 127.0.0.1:8080, or a relay on the classification endpoint's
        # port) cannot share a forward address: the second forwarder could not bind, and that stopped every relay
        # of every member (V-12). Each gets an address of its own, in the order of the list.
        block = per_port.get(port, 0)
        per_port[port] = block + 1
        if block >= FORWARD_BLOCKS:
            log.error("relay %s: more than %d relayed services on port %d; this one is left out", target,
                      FORWARD_BLOCKS, port)
            continue
        out.append({"target": target, "listen": f"{forward_ip(user_id, block)}:{port}"})
    return out


# ------------------------------------------------------------------ provider URL rewrite
def _url_variants(hostport: str) -> list[str]:
    host, port = parse_target(hostport)
    names = {host}
    if host in ("127.0.0.1", "localhost"):
        names |= {"127.0.0.1", "localhost"}
    return [f"{h}:{port}" for h in sorted(names)]


def rewrite_text(text: str, mapping: dict[str, str]) -> str:
    """'//<target host>:<port>' -> '//<forward ip>:<port>' in one text (mapping target -> listen). The port must
    end there (AC-5): a target on port 80 does not rewrite a URL on port 8080. An entry that is not host:port is
    skipped."""
    for target, listen in (mapping or {}).items():
        try:
            variants = _url_variants(str(target))
        except ValueError:
            continue
        for v in variants:
            text = re.sub("//" + re.escape(v) + r"(?![0-9])", lambda m, to=str(listen): "//" + to, text)
    return text


def state_mapping(state_dir: str | Path, name: str) -> dict[str, str]:
    """The relays the worker of container `name` runs now (<state_dir>/<name>.relays.json, written by
    workers._start_relays): target -> listen. {} when the user has none (not sandboxed, or no relays)."""
    try:
        m = json.loads((Path(state_dir) / f"{name}.relays.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(m, dict):
        return {}
    out = {}
    for t, lst in m.items():
        try:
            parse_target(t), parse_target(lst)
        except ValueError:
            continue
        out[str(t)] = str(lst)
    return out


MAX_REWRITE_FILES = 500           # entries of the custom providers folder that are looked at
MAX_REWRITE_BYTES = 1024 * 1024   # a larger file is not a Goose configuration file; it is left alone


def _config_files(profile_root: str) -> tuple[list[Path], list[Path]]:
    """(files, links): config.yaml and the custom provider files of a profile that the gateway may rewrite (AC-5),
    and what it must not touch because it is a link. The member can write in these folders and the gateway writes
    with its own rights, so: regular files only, none that is a link or has a second name, nothing below a folder
    that is a link, and a bounded number of entries."""
    from itertools import islice
    from .profiles import _is_reparse, _linked
    cfg = Path(profile_root) / "config"
    if _is_reparse(cfg):
        return [], [cfg]
    if not cfg.is_dir():
        return [], []
    files, links = [cfg / "config.yaml"], []
    cp = cfg / "custom_providers"
    if _is_reparse(cp):
        links.append(cp)
    elif cp.is_dir():
        try:
            with os.scandir(cp) as it:
                files += sorted(Path(e.path) for e in islice(it, MAX_REWRITE_FILES) if e.name.lower().endswith(".json"))
        except OSError:
            pass
    ok = []
    for f in files:
        if _is_reparse(f) or (f.is_file() and _linked(f)):
            links.append(f)
        elif f.is_file():
            ok.append(f)
    return ok, links


def _rewrite(profile_root: str, mapping: dict[str, str]) -> tuple[list[str], list[str]]:
    """(changed files, files left as they are although they may need the change: a link, or a write that failed).
    Every file that is left out is logged."""
    from .sandbox import write_atomic
    changed, left, failures = [], [], 0
    files, links = _config_files(profile_root)
    for f in links:
        log.warning("relay: %s is a link or has a second name; its URLs are not rewritten", f)
        left.append(str(f))
    for f in files:
        if failures >= 3:       # a folder that refuses writes: not 500 more attempts in this start (W-4)
            left.append(str(f))
            continue
        try:
            with open(f, "rb") as fh:
                raw = fh.read(MAX_REWRITE_BYTES + 1)       # bounded: the member can put any file here (V-3)
            if len(raw) > MAX_REWRITE_BYTES:
                log.warning("relay: %s is larger than %d bytes; its URLs are not rewritten", f, MAX_REWRITE_BYTES)
                continue
            text = raw.decode("utf-8")
        except OSError:
            continue
        except ValueError:
            log.warning("relay: %s is not UTF-8 text; its URLs are not rewritten", f)
            continue
        new = rewrite_text(text, mapping)
        if new != text:
            try:
                write_atomic(f, new)
            except OSError as e:
                log.warning("relay: %s was not rewritten: %s", f, e)
                left.append(str(f))
                failures += 1
                continue
            changed.append(str(f))
    return changed, left


def rewrite_profile_urls(profile_root: str, mapping: dict[str, str]) -> list[str]:
    """Replace '<target host>:<port>' by '<forward ip>:<port>' in the profile's config.yaml and custom provider
    JSON files (mapping target -> listen). Returns the changed files. Idempotent."""
    return _rewrite(profile_root, mapping)[0]


def restore_profile_urls(profile_root: str, mapping: dict[str, str]) -> list[str]:
    return rewrite_profile_urls(profile_root, {listen: target for target, listen in mapping.items()}) \
        if mapping else []


def _pending_file(state_dir: str | Path, name: str) -> Path:
    # not "<name>.relays.json": state_mapping must not take a restore that is still owed for a running relay
    return Path(state_dir) / f"{name}.relays.undo.json"


def _pairs(d) -> dict[str, str]:
    return {t: lst for t, lst in (d.items() if isinstance(d, dict) else []) if isinstance(t, str) and isinstance(lst, str)}


def _read_owed(g: Path) -> dict[str, str]:
    try:
        return _pairs(json.loads(g.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def _write_owed(g: Path, before: dict, now: dict) -> None:
    from .sandbox import write_atomic
    try:
        if not now:
            g.unlink(missing_ok=True)
        elif now != before:
            g.parent.mkdir(parents=True, exist_ok=True)
            write_atomic(g, json.dumps(now))
    except OSError as e:      # the record of a debt must not be what stops the relays (W-9)
        log.warning("relay: %s could not be written: %s", g, e)


def restore_pending(state_dir: str | Path, name: str, profile_root: str | None, extra: dict | None = None,
                    active: dict | None = None) -> list[str]:
    """Point the profile's URLs back at the real services for `extra` (target -> listen) and for whatever an
    earlier restore could not finish. A restore is not finished while a file could not be written (in use) or is a
    link the gateway does not touch; what is owed is kept in <state_dir>/<name>.relays.undo.json and tried again at
    the worker's next start (V-4). Returns the restored files.

    `active` (target -> listen): the relays this start is about to run.
    - What is owed for one of them is not undone now. It stays on file until that relay's record is written
      (forget_owed): if the relay does not start after all, the debt is still known (W-2).
    - A forward address that now belongs to ANOTHER target is never undone from the file: `//<listen>` in the
      profile means the new service by now, and undoing it at every start made two URLs swap, or pointed one at a
      closed address for good (W-1). Such an entry is applied once, when it arrives in `extra` at the changeover -
      before the new rewrite - and is not kept."""
    g = _pending_file(state_dir, name)
    owed, extra, act = _read_owed(g), _pairs(extra or {}), _pairs(active or {})
    if not profile_root:
        g.unlink(missing_ok=True)
        return []
    busy = set(act.values())
    keep = {t: lst for t, lst in owed.items() if act.get(t) == lst}
    todo = {t: lst for t, lst in owed.items() if act.get(t) != lst and lst not in busy}
    todo.update({t: lst for t, lst in extra.items() if act.get(t) != lst})
    changed, left = _rewrite(profile_root, {lst: t for t, lst in todo.items()}) if todo else ([], [])
    if left:
        keep.update({t: lst for t, lst in todo.items() if lst not in busy})
        log.warning("relay %s: %d file(s) still point at a relay forwarder; tried again at the next start: %s",
                    name, len(left), left[:5])
    _write_owed(g, owed, keep)
    return changed


def forget_owed(state_dir: str | Path, name: str, live: dict) -> None:
    """The relays in `live` are on record now (<name>.relays.json): a restore owed for one of them is covered by
    that record and leaves the undo file."""
    g = _pending_file(state_dir, name)
    owed = _read_owed(g)
    if owed:
        _write_owed(g, owed, {t: lst for t, lst in owed.items() if _pairs(live).get(t) != lst})


def undo_relays(state_dir: str, name: str, profile_root: str | None) -> list[str]:
    """The user is no longer sandboxed in an AppContainer: point their provider URLs back at the real services and
    forget the record (<state_dir>/<container>.relays.json, written by workers.py). Returns the restored files.
    What cannot be restored now stays owed (restore_pending)."""
    f = Path(state_dir) / f"{name}.relays.json"
    try:
        old = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    changed = restore_pending(state_dir, name, profile_root, old if isinstance(old, dict) else {})
    f.unlink(missing_ok=True)
    return changed


# ------------------------------------------------------------------ forwarder (runs INSIDE the container)
FORWARDER_SRC = r'''# Goose Web relay forwarder (generated; runs inside this user's sandbox). TCP <listen> -> named pipe <pipe>.
# argv: <listen host:port> <pipe name> <gateway process id>. Every pipe connection must be served by the gateway.
import ctypes, socket, sys, threading, _winapi, _overlapped
from ctypes import wintypes
LISTEN, PIPE, GATEWAY_PID = sys.argv[1], sys.argv[2], int(sys.argv[3])
host, port = LISTEN.rsplit(":", 1)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
_k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL

def server_pid(h):
    pid = wintypes.ULONG(0)
    if not _k32.GetNamedPipeServerProcessId(h, ctypes.byref(pid)):
        return -1
    return pid.value

def pump_pipe_to_sock(h, s):
    try:
        while True:
            ov = _overlapped.Overlapped()
            ov.ReadFile(h, 65536)
            data = ov.getresult(True)
            if not data:
                break
            s.sendall(data)
    except OSError as e:
        if getattr(e, 'winerror', 0) not in (109, 232, 233):   # the gateway closed the pipe: the answer is complete
            sys.stderr.write('relay pipe to socket: %r\n' % (e,)); sys.stderr.flush()
    finally:
        try: s.shutdown(socket.SHUT_WR)
        except OSError: pass

def handle(s):
    try:
        # read + write data (0x2), not GENERIC_WRITE: the pipe withholds the right to create instances of it
        h = _winapi.CreateFile(PIPE, _winapi.GENERIC_READ | 0x0002, 0, _winapi.NULL,
                               _winapi.OPEN_EXISTING, _winapi.FILE_FLAG_OVERLAPPED, _winapi.NULL)
    except OSError:
        s.close(); return
    pid = server_pid(h)
    if pid != GATEWAY_PID:   # someone else's pipe instance: never send it a byte
        sys.stderr.write('relay: pipe server is process %d, not the gateway (%d); connection refused\n'
                         % (pid, GATEWAY_PID)); sys.stderr.flush()
        try: _winapi.CloseHandle(h)
        except OSError: pass
        s.close(); return
    t = threading.Thread(target=pump_pipe_to_sock, args=(h, s), daemon=True); t.start()
    try:
        while True:
            data = s.recv(65536)
            if not data:
                break
            ov = _overlapped.Overlapped()
            ov.WriteFile(h, data)
            ov.getresult(True)
    except OSError as e:
        sys.stderr.write('relay socket to pipe: %r\n' % (e,)); sys.stderr.flush()
    t.join(timeout=600)
    try: _winapi.CloseHandle(h)
    except OSError: pass
    s.close()

srv = socket.socket(); srv.bind((host, int(port))); srv.listen(64)
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
'''


# ------------------------------------------------------------------ pipe server (runs in the gateway)
if IS_WINDOWS:  # pragma: no cover - exercised by the Windows tests
    import _overlapped
    import _winapi
    import ctypes
    from ctypes import wintypes

    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]

    class _SA(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
    PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

    class PipeRelayServer:
        """Accepts connections on `pipe` from the container `sid` only and connects each to `target`.

        The first pipe instance is created in the constructor with FILE_FLAG_FIRST_PIPE_INSTANCE: if any process
        already owns the name, OSError is raised (fail closed). From then on at least one instance stays open
        until stop() (the next one is created before a connected one is handed on), so the name never becomes
        free for another process to take."""

        def __init__(self, pipe: str, sid: str, target: str, max_connections: int = 64):
            self.pipe, self.sid, self.target = pipe, sid, parse_target(target)
            self._stop = False
            # AC-3: every connection costs the gateway two threads and a socket, and the gateway serves everyone
            self.max_connections = max(1, int(max_connections))
            self._slots = threading.BoundedSemaphore(self.max_connections)
            self.refused = 0
            # The container: read, and write data (0x12008b = FILE_GENERIC_READ | FILE_WRITE_DATA). Not GENERIC_WRITE,
            # which includes the right to create further instances of this pipe (V-9): with one of its own the
            # agent could sit in front of the gateway's and keep stop() from ending the serving thread.
            sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;0x12008b;;;{sid})S:(ML;;NW;;;LW)"
            self._sd = ctypes.c_void_p()
            if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(self._sd), None):
                raise OSError(f"pipe security descriptor failed ({ctypes.get_last_error()})")
            self._sa = _SA(ctypes.sizeof(_SA), self._sd, False)
            try:
                self._pending = self._new_instance(first=True)
            except OSError as e:
                self._free_sd()
                raise OSError(f"relay pipe {pipe} exists already or cannot be created ({e}); relay not started") from e
            self._thread = threading.Thread(target=self._serve, name=f"relay {target}", daemon=True)

        def start(self) -> "PipeRelayServer":
            self._thread.start()
            return self

        def _new_instance(self, first: bool = False) -> int:
            return _winapi.CreateNamedPipe(
                self.pipe, _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
                | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0),
                0 | 0 | _winapi.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,   # PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                _winapi.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, ctypes.addressof(self._sa))

        def _serve(self) -> None:
            h = self._pending
            while not self._stop:
                try:
                    ov = _overlapped.Overlapped()
                    if not ov.ConnectNamedPipe(h):   # True = a client is already connected; False = wait for one
                        ov.getresult(True)
                    connected = True
                except OSError:
                    connected = False
                if self._stop:
                    break
                try:   # the next instance BEFORE this one is handed on or closed: the name stays ours
                    nxt = self._new_instance()
                except OSError as e:
                    log.warning("relay %s: cannot create pipe: %s", self.pipe, e)
                    break
                if connected and self._slots.acquire(blocking=False):
                    try:
                        threading.Thread(target=self._handle, args=(h,), daemon=True).start()
                    except RuntimeError:          # no thread to be had: give the slot and the instance back
                        self._slots.release()
                        _winapi.CloseHandle(h)
                elif connected:                   # over the limit: closed at once, the client sees an empty answer
                    self.refused += 1
                    if self.refused in (1, 100) or self.refused % 1000 == 0:
                        log.warning("relay %s -> %s:%s: more than %d connections at once; %d refused so far",
                                    self.pipe, *self.target, self.max_connections, self.refused)
                    _winapi.CloseHandle(h)
                else:
                    _winapi.CloseHandle(h)
                h = self._pending = nxt
            self._pending = None
            try:
                _winapi.CloseHandle(h)
            except OSError:
                pass
            self._free_sd()

        def _free_sd(self) -> None:
            sd, self._sd = self._sd, None     # the kernel copied it into every instance; no instance is made after
            if sd:
                _k32.LocalFree(sd)

        def _handle(self, h: int) -> None:
            try:
                self._relay(h)
            finally:
                self._slots.release()

        def _relay(self, h: int) -> None:
            try:
                s = socket.create_connection(self.target, timeout=30)
                s.settimeout(None)
            except Exception as e:      # not only OSError: a name that cannot be encoded raises UnicodeError (V-8)
                log.info("relay %s -> %s:%s refused: %s", self.pipe, *self.target, e)
                _winapi.CloseHandle(h)
                return

            def sock_to_pipe():
                try:
                    while True:
                        data = s.recv(65536)
                        if not data:
                            break
                        ov = _overlapped.Overlapped()
                        ov.WriteFile(h, data)
                        ov.getresult(True)
                except OSError as e:
                    log.info("relay %s: target -> pipe ended: %r", self.pipe, e)
                finally:
                    try:
                        _winapi.CloseHandle(h)   # ends the forwarder's read: the response is complete
                    except OSError:
                        pass
            t = threading.Thread(target=sock_to_pipe, daemon=True)
            t.start()
            try:
                while True:
                    ov = _overlapped.Overlapped()
                    ov.ReadFile(h, 65536)
                    data = ov.getresult(True)
                    if not data:
                        break
                    s.sendall(data)
            except OSError as e:
                log.info("relay %s: pipe -> target ended: %r", self.pipe, e)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            t.join(timeout=600)
            s.close()

        def stop(self) -> None:
            self._stop = True
            if not self._thread.is_alive():   # never started: only the first instance to close
                h, self._pending = self._pending, None
                if h:
                    try:
                        _winapi.CloseHandle(h)
                    except OSError:
                        pass
                self._free_sd()
                return
            try:   # unblock the pending ConnectNamedPipe
                hc = _winapi.CreateFile(self.pipe, _winapi.GENERIC_READ, 0, _winapi.NULL, _winapi.OPEN_EXISTING, 0,
                                        _winapi.NULL)
                _winapi.CloseHandle(hc)
            except OSError:
                pass
else:
    class PipeRelayServer:  # pragma: no cover
        def __init__(self, *a, **k):
            raise OSError("relays need Windows")


def write_forwarder(profile_root: str) -> str:
    """The forwarder script in the member's profile (it runs inside the member's container, which reads nothing
    else of the gateway's). The member can write there: the folder must not be a link, and the file is replaced as
    a whole, never written through a link (AC-5)."""
    from .profiles import _is_reparse
    from .sandbox import write_atomic
    d = Path(profile_root) / ".goose-web"
    if _is_reparse(d):
        raise OSError(f"{d} is a link; the relay forwarder is not written through it")
    d.mkdir(parents=True, exist_ok=True)
    p = d / "relay_forwarder.py"
    want = FORWARDER_SRC.encode("utf-8")
    try:    # the size first, and never more than that is read: the member can put any file here (V-3)
        same = not _is_reparse(p) and p.stat().st_size == len(want)
        if same:
            with open(p, "rb") as fh:
                same = fh.read(len(want) + 1) == want
    except OSError:
        same = False
    if not same:
        write_atomic(p, FORWARDER_SRC)
    return str(p)


def python_for_container() -> tuple[str, str]:
    """The real python.exe (not a venv launcher) and its folder, which the container must be allowed to read."""
    base = sys.base_prefix
    return os.path.join(base, "python.exe"), base
