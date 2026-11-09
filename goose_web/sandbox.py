"""Per-user Windows AppContainer sandbox for isolated workers (spec 012).

All goose-web workers run as ONE operating-system account. With `sandbox.enabled`, every isolated non-admin user's
worker (`goose acp` and everything it starts: shells, MCP servers, scripts) runs inside that user's own Windows
AppContainer. The kernel then allows file access only where an ACL grants the container's SID: the user's profile
folder (incl. the workspace), the team folder and the team's extra folders (Modify), and the program folders in
`sandbox.read_dirs` plus the goose CLI folder (Read & execute). The gateway's data, other users' profiles, the
native Goose profile and the rest of the account's files stay out of reach.

The gateway talks to the worker over the worker's stdin/stdout (anonymous pipes inherited only by that process):
no TCP port, no loopback exemption, no administrator rights. Loopback (127.0.0.1) stays closed for the container, so
local services such as a browser's remote-debugging port or a local model proxy are not reachable from it. Network
capabilities: `internetClient` (default) and optionally `privateNetworkClientServer` (LAN).

Windows only. On other systems `sandbox.enabled` makes isolated non-admin workers refuse to start (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("goose_web.sandbox")
IS_WINDOWS = sys.platform == "win32"

CAP_INTERNET = "S-1-15-3-1"          # internetClient
CAP_PRIVATE_NETWORK = "S-1-15-3-3"   # privateNetworkClientServer
NETWORK_CAPS = {"none": [], "internet": [CAP_INTERNET], "internet+lan": [CAP_INTERNET, CAP_PRIVATE_NETWORK]}
RIGHTS = {"modify": "(OI)(CI)M", "read": "(OI)(CI)RX"}


class SandboxError(RuntimeError):
    pass


def _root_hash(profiles_root: str) -> str:
    return hashlib.sha256(os.path.normcase(os.path.abspath(profiles_root)).encode()).hexdigest()[:8]


def container_name(profiles_root: str, username: str) -> str:
    """Deterministic AppContainer name (max 64 chars): same name -> same SID across restarts and upgrades. The hash
    of the profiles root keeps two gateways on one account apart.

    GooseWeb.<root hash>.<readable prefix>.<hash of the exact user name>: the readable part drops characters an
    AppContainer name cannot hold and is shortened, so it alone is not unique (jo.ann / joann); the 10-hex hash of
    the full (case-folded: user names are unique case-insensitively) name keeps every user in a container of
    their own. At most 9 + 8 + 1 + 32 + 1 + 10 = 61 characters."""
    exact = str(username).lower()
    tag = hashlib.sha256(exact.encode("utf-8")).hexdigest()[:10]
    user = "".join(ch for ch in exact if (ch.isascii() and ch.isalnum()) or ch in "-_")[:32] or "user"
    return f"GooseWeb.{_root_hash(profiles_root)}.{user}.{tag}"


def legacy_container_name(profiles_root: str, username: str) -> str:
    """The container name Goose Web 1.11.0 and earlier used (dots dropped, 40 characters): two users could share
    it. Only used to find and remove those containers (migrate_legacy)."""
    user = "".join(ch for ch in username.lower() if ch.isalnum() or ch in "-_")[:40] or "user"
    return f"GooseWeb.{_root_hash(profiles_root)}.{user}"


def desired_grants(profile_root: str, roots: list[str], read_dirs: list[str], goose_binary: str) -> dict[str, str]:
    """{path: 'modify'|'read'} the container needs. Modify wins over read for the same path."""
    out: dict[str, str] = {}
    for d in [os.path.dirname(os.path.abspath(goose_binary)) if goose_binary and os.path.isabs(goose_binary) else "",
              *read_dirs]:
        if d:
            out[os.path.normpath(d)] = "read"
    for d in [profile_root, *roots]:
        if d:
            out[os.path.normpath(d)] = "modify"
    return out


def diff_grants(old: dict[str, str], new: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """(to_apply, to_revoke): grants that are new or changed, and paths no longer granted (or changed)."""
    norm = os.path.normcase
    old_n = {norm(k): (k, v) for k, v in old.items()}
    new_n = {norm(k): (k, v) for k, v in new.items()}
    apply = {k: v for nk, (k, v) in new_n.items() if old_n.get(nk, (None, None))[1] != v}
    revoke = [k for nk, (k, v) in old_n.items() if nk not in new_n or new_n[nk][1] != v]
    return apply, revoke


# ------------------------------------------------------------------ Windows implementation
if IS_WINDOWS:  # pragma: no cover - exercised by the Windows end-to-end test
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _uenv = ctypes.WinDLL("userenv", use_last_error=True)

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class _SecurityCapabilities(ctypes.Structure):
        _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.POINTER(_SidAndAttributes)),
                    ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]

    class _StartupInfoW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class _StartupInfoExW(ctypes.Structure):
        _fields_ = [("StartupInfo", _StartupInfoW), ("lpAttributeList", ctypes.c_void_p)]

    class _ProcessInformation(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    _uenv.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                                 ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _uenv.CreateAppContainerProfile.restype = ctypes.c_long
    _uenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _uenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    _uenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
    _uenv.DeleteAppContainerProfile.restype = ctypes.c_long
    _adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    _adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    _adv.FreeSid.argtypes = [ctypes.c_void_p]
    _k32.LocalFree.argtypes = [ctypes.c_void_p]
    _k32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                       ctypes.POINTER(ctypes.c_size_t)]
    _k32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                               ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    _k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    _k32.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                                ctypes.POINTER(_SecurityAttributes), wintypes.DWORD]
    _k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    _k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                    ctypes.POINTER(_StartupInfoExW), ctypes.POINTER(_ProcessInformation)]
    _k32.ResumeThread.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _k32.WaitForSingleObject.restype = wintypes.DWORD
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

    _PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
    _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    _HR_ALREADY_EXISTS = ctypes.c_long(0x800700B7).value

    def _sid_to_str(psid) -> str:
        s = wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(psid, ctypes.byref(s)):
            raise SandboxError(f"ConvertSidToStringSid failed ({ctypes.get_last_error()})")
        try:
            return s.value
        finally:
            _k32.LocalFree(s)

    def _str_to_sid(text: str):
        p = ctypes.c_void_p()
        if not _adv.ConvertStringSidToSidW(text, ctypes.byref(p)):
            raise SandboxError(f"ConvertStringSidToSid({text}) failed ({ctypes.get_last_error()})")
        return p   # LocalFree

    def ensure_container(name: str) -> str:
        """Create the AppContainer profile (no admin needed) or derive the SID of the existing one."""
        psid = ctypes.c_void_p()
        hr = _uenv.CreateAppContainerProfile(name, name, "Goose Web worker sandbox", None, 0, ctypes.byref(psid))
        if hr == _HR_ALREADY_EXISTS:
            hr = _uenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(psid))
        if hr != 0:
            raise SandboxError(f"AppContainer profile {name}: HRESULT 0x{hr & 0xFFFFFFFF:08X}")
        try:
            return _sid_to_str(psid)
        finally:
            _adv.FreeSid(psid)

    def delete_container(name: str) -> bool:
        return _uenv.DeleteAppContainerProfile(name) == 0

    class ContainedProcess:
        """subprocess.Popen-like handle for a process started inside an AppContainer."""

        def __init__(self, hproc: int, pid: int, stdin, stdout):
            self._handle = hproc
            self.pid = pid
            self.stdin = stdin
            self.stdout = stdout
            self.returncode: int | None = None

        def poll(self) -> int | None:
            if self.returncode is None:
                code = wintypes.DWORD()
                if _k32.GetExitCodeProcess(self._handle, ctypes.byref(code)) and code.value != 259:  # STILL_ACTIVE
                    self.returncode = code.value
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
            if _k32.WaitForSingleObject(self._handle, ms) != 0:
                raise subprocess.TimeoutExpired("goose acp", timeout)
            return self.poll()  # type: ignore[return-value]

        def kill(self) -> None:
            if self.poll() is None:
                _k32.TerminateProcess(self._handle, 1)

        terminate = kill

    def _pipe() -> tuple[int, int]:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
        r, w = wintypes.HANDLE(), wintypes.HANDLE()
        if not _k32.CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(sa), 1 << 20):
            raise SandboxError(f"CreatePipe failed ({ctypes.get_last_error()})")
        return r.value, w.value

    def spawn(args: list[str] | str, env: dict, cwd: str, sid: str, capabilities: list[str], stderr_file,
              job=None) -> ContainedProcess:
        """Start args inside the AppContainer `sid` with the given capability SIDs. stdin/stdout are pipes to the
        caller; stderr goes to stderr_file. Only these three handles are inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
        Started suspended, put in `job` (kill-on-close), then resumed, so no child can escape the job. `job` may be
        a list: the process joins each in order (gateway job first, then the worker's own job, which so becomes a
        job nested in the gateway's)."""
        in_r, in_w = _pipe()
        out_r, out_w = _pipe()
        _k32.SetHandleInformation(in_w, 1, 0)      # parent ends: not inheritable
        _k32.SetHandleInformation(out_r, 1, 0)
        err_h = msvcrt.get_osfhandle(stderr_file.fileno())
        os.set_handle_inheritable(err_h, True)
        cap_sids = [_str_to_sid(c) for c in capabilities]
        app_sid = _str_to_sid(sid)
        attrs = (_SidAndAttributes * max(1, len(cap_sids)))(*[_SidAndAttributes(s.value, 0x4) for s in cap_sids])
        sc = _SecurityCapabilities(app_sid.value, attrs if cap_sids else None, len(cap_sids), 0)
        handles = (wintypes.HANDLE * 3)(in_r, out_w, err_h)
        size = ctypes.c_size_t()
        _k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not _k32.InitializeProcThreadAttributeList(buf, 2, 0, ctypes.byref(size)):
            raise SandboxError(f"InitializeProcThreadAttributeList failed ({ctypes.get_last_error()})")
        pi = _ProcessInformation()
        try:
            if not _k32.UpdateProcThreadAttribute(buf, 0, _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                  ctypes.byref(sc), ctypes.sizeof(sc), None, None):
                raise SandboxError(f"security capabilities attribute failed ({ctypes.get_last_error()})")
            if not _k32.UpdateProcThreadAttribute(buf, 0, _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                  handles, ctypes.sizeof(handles), None, None):
                raise SandboxError(f"handle list attribute failed ({ctypes.get_last_error()})")
            si = _StartupInfoExW()
            si.StartupInfo.cb = ctypes.sizeof(_StartupInfoExW)
            si.StartupInfo.dwFlags = 0x100           # STARTF_USESTDHANDLES
            si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = in_r, out_w, err_h
            si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)
            block = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
            envbuf = ctypes.create_unicode_buffer(block, len(block))
            cmd = ctypes.create_unicode_buffer(args if isinstance(args, str) else subprocess.list2cmdline(args))
            # EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW
            flags = 0x00080000 | 0x00000400 | 0x00000004 | 0x08000000
            if not _k32.CreateProcessW(None, cmd, None, None, True, flags, envbuf, cwd, ctypes.byref(si),
                                       ctypes.byref(pi)):
                raise SandboxError(f"CreateProcess in AppContainer failed ({ctypes.get_last_error()})")
        finally:
            _k32.DeleteProcThreadAttributeList(buf)
            for s in [app_sid, *cap_sids]:
                _k32.LocalFree(s)
            _k32.CloseHandle(in_r)
            _k32.CloseHandle(out_w)
            os.set_handle_inheritable(err_h, False)
        for j in (job if isinstance(job, (list, tuple)) else [job]):
            if j is not None and getattr(j, "handle", None):
                if not _k32.AssignProcessToJobObject(j.handle, pi.hProcess):
                    log.warning("could not put the sandboxed worker in the job object (%s)", ctypes.get_last_error())
        _k32.ResumeThread(pi.hThread)
        _k32.CloseHandle(pi.hThread)
        stdin = os.fdopen(msvcrt.open_osfhandle(in_w, os.O_WRONLY | os.O_BINARY), "wb", buffering=0)
        stdout = os.fdopen(msvcrt.open_osfhandle(out_r, os.O_RDONLY | os.O_BINARY), "rb", buffering=0)
        return ContainedProcess(pi.hProcess, pi.dwProcessId, stdin, stdout)

    def _icacls(args: list[str]) -> None:
        r = subprocess.run(["icacls", *args], capture_output=True, text=True, timeout=600,  # nosec B603 B607
                           stdin=subprocess.DEVNULL, creationflags=0x08000000)
        if r.returncode != 0:
            raise SandboxError(f"icacls {' '.join(args[:2])} failed: {(r.stdout + r.stderr).strip()[:300]}")

    def grant(path: str, sid: str, right: str) -> None:
        _icacls([path, "/grant", f"*{sid}:{RIGHTS[right]}", "/Q", "/C"])

    def revoke(path: str, sid: str) -> None:
        if os.path.exists(path):
            _icacls([path, "/remove:g", f"*{sid}", "/Q", "/C"])
else:
    def ensure_container(name: str) -> str:
        raise SandboxError("the sandbox needs Windows (AppContainer)")

    def delete_container(name: str) -> bool:
        return False

    def spawn(*a, **k):
        raise SandboxError("the sandbox needs Windows (AppContainer)")

    def grant(path: str, sid: str, right: str) -> None:
        raise SandboxError("the sandbox needs Windows (AppContainer)")

    def revoke(path: str, sid: str) -> None:
        raise SandboxError("the sandbox needs Windows (AppContainer)")


def _state_path(state_dir: str, name: str) -> Path:
    # Kept in the gateway's system folder, outside every container's reach (a worker cannot edit its own record).
    return Path(state_dir) / f"{name}.json"


def load_state(state_dir: str, name: str) -> dict:
    try:
        return json.loads(_state_path(state_dir, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(state_dir: str, name: str, state: dict) -> None:
    sp = _state_path(state_dir, name)
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(json.dumps(state, indent=1), encoding="utf-8")


def prepare(name: str, state_dir: str, grants: dict[str, str]) -> dict:
    """Ensure the container exists and the folder grants match `grants` (only changes are applied; folders that
    do not exist yet are skipped and retried at the next start). Returns the saved state
    {name, sid, grants, pending, updatedAt} (<system_dir>/sandbox/<name>.json).

    `pending` keeps grants that were applied earlier on a folder that is missing right now (renamed away, a
    disconnected drive): its ACE cannot be checked or revoked, so the record is kept until the folder is back and
    the grant is either confirmed (still wanted) or revoked (no longer wanted). Dropping it would leave an ACE
    nobody tracks."""
    sid = ensure_container(name)
    old = load_state(state_dir, name)
    same = old.get("sid") == sid
    recorded = {**(old.get("pending", {}) if same else {}), **(old.get("grants", {}) if same else {})}
    have = {p: r for p, r in recorded.items() if os.path.isdir(p)}
    missing = {p: r for p, r in recorded.items() if not os.path.isdir(p)}
    present = {p: r for p, r in grants.items() if os.path.isdir(p)}
    apply, revoke_list = diff_grants(have, present)
    for p in revoke_list:
        try:
            revoke(p, sid)
        except SandboxError as e:
            log.warning("sandbox %s: %s", name, e)
    for p, right in apply.items():
        grant(p, sid, right)
    state = {"name": name, "sid": sid, "grants": present, "pending": missing, "updatedAt": time.time()}
    _save_state(state_dir, name, state)
    if apply or revoke_list:
        log.info("sandbox %s: granted %s, revoked %s", name, sorted(apply), sorted(revoke_list))
    if missing:
        log.info("sandbox %s: %d earlier grant(s) on missing folders kept for a later revoke: %s", name,
                 len(missing), sorted(missing))
    return state


def remove(state_dir: str, name: str) -> dict:
    """Revoke every recorded grant and delete the container profile (user deleted, made admin, or sandbox off).
    Grants on folders that are missing now stay recorded (a record with only `pending` grants), so a later
    remove (`goose-web sandbox remove --all`) or a new container of the same name revokes them when they are back."""
    st = load_state(state_dir, name)
    if not st.get("sid"):
        return {}
    left: dict[str, str] = {}
    for p, r in {**st.get("pending", {}), **st.get("grants", {})}.items():
        if not os.path.isdir(p):
            left[p] = r
            continue
        try:
            revoke(p, st["sid"])
        except SandboxError as e:
            log.warning("sandbox remove: %s", e)
            left[p] = r
    delete_container(name)
    if left:
        _save_state(state_dir, name, {"name": name, "sid": st["sid"], "grants": {}, "pending": left,
                                      "removed": True, "updatedAt": time.time()})
        log.warning("sandbox %s removed; %d grant(s) on missing folders stay recorded for a later revoke: %s",
                    name, len(left), sorted(left))
    else:
        try:
            _state_path(state_dir, name).unlink()
        except OSError:
            pass
    return st


def migrate_legacy(state_dir: str, profiles_root: str, username: str) -> dict:
    """Before a user's worker starts in its (1.12+) container: if a container recorded under the 1.11.0 name
    (legacy_container_name, which two users could share) exists, revoke its grants and delete it, and keep its
    relay record (relay.py) under the new name. Returns the removed state ({} if there was none)."""
    old = legacy_container_name(profiles_root, username)
    new = container_name(profiles_root, username)
    if old == new:
        return {}
    rel_old, rel_new = Path(state_dir) / f"{old}.relays.json", Path(state_dir) / f"{new}.relays.json"
    try:
        if rel_old.exists() and not rel_new.exists():
            os.replace(rel_old, rel_new)
    except OSError as e:
        log.warning("sandbox: could not move %s: %s", rel_old, e)
    if not load_state(state_dir, old):
        return {}
    st = remove(state_dir, old)
    log.info("sandbox: removed the 1.11 container %s of %s (replaced by %s)", old, username, new)
    return st


def all_states(state_dir: str) -> list[dict]:
    out = []
    for f in sorted(Path(state_dir).glob("GooseWeb.*.json")) if Path(state_dir).is_dir() else []:
        if f.name.endswith(".relays.json"):     # relay records (relay.py), not container states
            continue
        try:
            st = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(st, dict) and st.get("sid"):
            out.append(st)
    return out


class StdioChannel:
    """The worker connection over the process's stdin/stdout (newline-delimited JSON-RPC, as `goose acp` speaks).
    Same surface the hub uses on a websocket: `await send(text)`, `async for text in channel`, `await close()`."""

    def __init__(self, proc: Any, loop):
        self.proc = proc
        self.loop = loop
        self.claimed = False
        self._q: Any = None
        self._wlock = threading.Lock()
        import asyncio
        self._q = asyncio.Queue()
        threading.Thread(target=self._reader, name=f"stdio-{getattr(proc, 'pid', '?')}", daemon=True).start()

    def _reader(self) -> None:
        try:
            for line in iter(self.proc.stdout.readline, b""):
                text = line.decode("utf-8", "replace").strip()
                if text.startswith("{"):
                    self.loop.call_soon_threadsafe(self._q.put_nowait, text)
        except (OSError, ValueError):
            pass
        finally:
            try:
                self.loop.call_soon_threadsafe(self._q.put_nowait, None)
            except RuntimeError:
                pass

    def _write(self, data: bytes) -> None:
        with self._wlock:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    async def send(self, text: str) -> None:
        import asyncio
        try:
            await asyncio.to_thread(self._write, text.encode("utf-8") + b"\n")
        except (OSError, ValueError) as e:
            raise ConnectionError(f"worker stdin closed: {e}") from e

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        while True:
            item = await self._q.get()
            if item is None:
                return
            yield item

    async def close(self) -> None:
        pass   # the process (and so the pipes) is owned by the WorkerManager
