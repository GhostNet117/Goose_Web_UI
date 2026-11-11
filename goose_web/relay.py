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


def forward_ip(user_id: int) -> str:
    """A loopback address of the user's own: 127.64.<hi>.<lo> with lo in 1..254 (the whole 127/8 is loopback on
    Windows). Unique for the first 65,024 user ids."""
    n = int(user_id) % (256 * 254)
    return f"127.64.{n // 254}.{n % 254 + 1}"


PIPE_PREFIX = "\\\\.\\pipe\\goose-web-relay."


def new_pipe_name() -> str:
    """A fresh, unguessable pipe name for one relay of one worker start (128 random bits). A predictable name
    would let any local process create the pipe first and sit between the container and the gateway."""
    return PIPE_PREFIX + secrets.token_hex(16)


def relay_specs(container: str, user_id: int, targets: list[str]) -> list[dict]:
    """{target, listen} per allow-listed service. The pipe name is chosen per worker start (new_pipe_name), not
    here: the spec must stay the same between calls (a changed spec marks the worker for a restart)."""
    ip = forward_ip(user_id)
    out = []
    for t in targets:
        host, port = parse_target(t)
        out.append({"target": f"{host}:{port}", "listen": f"{ip}:{port}"})
    return out


# ------------------------------------------------------------------ provider URL rewrite
def _url_variants(hostport: str) -> list[str]:
    host, port = parse_target(hostport)
    names = {host}
    if host in ("127.0.0.1", "localhost"):
        names |= {"127.0.0.1", "localhost"}
    return [f"{h}:{port}" for h in sorted(names)]


def rewrite_text(text: str, mapping: dict[str, str]) -> str:
    """'//<target host>:<port>' -> '//<forward ip>:<port>' in one text (mapping target -> listen)."""
    for target, listen in (mapping or {}).items():
        for v in _url_variants(target):
            text = text.replace(f"//{v}", f"//{listen}")
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


def rewrite_profile_urls(profile_root: str, mapping: dict[str, str]) -> list[str]:
    """Replace '<target host>:<port>' by '<forward ip>:<port>' in the profile's config.yaml and custom provider
    JSON files (mapping target -> listen). Returns the changed files. Idempotent."""
    cfg = Path(profile_root) / "config"
    files = [cfg / "config.yaml", *sorted((cfg / "custom_providers").glob("*.json"))]
    changed = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        new = rewrite_text(text, mapping)
        if new != text:
            f.write_text(new, encoding="utf-8")
            changed.append(str(f))
    return changed


def restore_profile_urls(profile_root: str, mapping: dict[str, str]) -> list[str]:
    return rewrite_profile_urls(profile_root, {listen: target for target, listen in mapping.items()}) \
        if mapping else []


def undo_relays(state_dir: str, name: str, profile_root: str | None) -> list[str]:
    """The user is no longer sandboxed: point their provider URLs back at the real services and forget the
    record (<state_dir>/<container>.relays.json, written by workers.py). Returns the restored files."""
    f = Path(state_dir) / f"{name}.relays.json"
    try:
        old = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    changed = restore_profile_urls(profile_root, old) if profile_root and isinstance(old, dict) else []
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
        sys.stderr.write('relay pipe to socket: %r\n' % (e,)); sys.stderr.flush()
    finally:
        try: s.shutdown(socket.SHUT_WR)
        except OSError: pass

def handle(s):
    try:
        h = _winapi.CreateFile(PIPE, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
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

        def __init__(self, pipe: str, sid: str, target: str):
            self.pipe, self.sid, self.target = pipe, sid, parse_target(target)
            self._stop = False
            sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;{sid})S:(ML;;NW;;;LW)"
            self._sd = ctypes.c_void_p()
            if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(self._sd), None):
                raise OSError(f"pipe security descriptor failed ({ctypes.get_last_error()})")
            self._sa = _SA(ctypes.sizeof(_SA), self._sd, False)
            try:
                self._pending = self._new_instance(first=True)
            except OSError as e:
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
                if connected:
                    threading.Thread(target=self._handle, args=(h,), daemon=True).start()
                else:
                    _winapi.CloseHandle(h)
                h = self._pending = nxt
            self._pending = None
            try:
                _winapi.CloseHandle(h)
            except OSError:
                pass

        def _handle(self, h: int) -> None:
            try:
                s = socket.create_connection(self.target, timeout=30)
                s.settimeout(None)
            except OSError as e:
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
    p = Path(profile_root) / ".goose-web" / "relay_forwarder.py"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists() or p.read_text(encoding="utf-8") != FORWARDER_SRC:
        p.write_text(FORWARDER_SRC, encoding="utf-8")
    return str(p)


def python_for_container() -> tuple[str, str]:
    """The real python.exe (not a venv launcher) and its folder, which the container must be allowed to read."""
    base = sys.base_prefix
    return os.path.join(base, "python.exe"), base
