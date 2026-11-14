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
import re
import secrets
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
NEED = {"modify": 0x1301BF, "read": 0x1200A9}      # the access masks icacls writes for M and RX
ALL_APP_PACKAGES = "S-1-15-2-1"                     # "ALL APPLICATION PACKAGES": every application container
ALL_RESTRICTED_APP_PACKAGES = "S-1-15-2-2"          # ... and the less privileged ones too; an entry for it also lets
#                                                     an ordinary container in (measured, build 26100)
_CONTAINER_SID = re.compile(r"^S-1-15-2(-\d+){7}$")  # one container's own SID - never one of the two above


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

        def __del__(self):
            h, self._handle = getattr(self, "_handle", None), None
            if h:
                _k32.CloseHandle(h)

    def _pipe() -> tuple[int, int]:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
        r, w = wintypes.HANDLE(), wintypes.HANDLE()
        if not _k32.CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(sa), 1 << 20):
            raise SandboxError(f"CreatePipe failed ({ctypes.get_last_error()})")
        return r.value, w.value

    def spawn(args: list[str] | str, env: dict, cwd: str, sid: str, capabilities: list[str], stderr_file,
              job=None, desktop: str = "", admit_first: bool = True) -> ContainedProcess:
        """Start args inside the AppContainer `sid` with the given capability SIDs. stdin/stdout are pipes to the
        caller; stderr goes to stderr_file. Only these three handles are inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).
        Started suspended, put in `job` (kill-on-close), then resumed, so no child can escape the job. `job` may be
        a list: the process joins each in order (gateway job first, then the worker's own job, which so becomes a
        job nested in the gateway's).

        The process connects to the window station and desktop this process is on (`desktop`: to that desktop of
        the window station instead - the self-test and the tests use it). A program that cannot open them ends
        before its first instruction with 0xC0000142, so the container is let in first where nothing lets it in
        (admit; `admit_first=False` leaves the access lists alone)."""
        if admit_first:
            try:
                for what in admit(sid, desktop):
                    log.info("sandbox: container %s is now named on the %s this gateway runs on", sid, what)
            except Exception as e:      # never the reason a start fails: a process that is not let in says so itself
                if sid not in _ADMIT_WARNED:        # once per container, not at every start
                    _ADMIT_WARNED.add(sid)
                    log.warning("sandbox: %s. Its processes may end with 0xC0000142",
                                e if isinstance(e, SandboxError) else f"{type(e).__name__}: {e}")
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
            # Without a name the process goes where THIS process was started (the name in its start-up block), not
            # where it is now. Where somebody is signed in that is left to Windows, as always; a gateway nobody is
            # signed in to names the window station and desktop it is on - the ones admit() looked at.
            ws_name = _object_name(_u32.GetProcessWindowStation())
            on = desktop or ("" if ws_name.lower() == "winsta0"
                             else _object_name(_u32.GetThreadDesktop(_k32.GetCurrentThreadId())))
            if on and ws_name:
                si.StartupInfo.lpDesktop = ws_name + "\\" + on
            si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)
            block = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
            envbuf = ctypes.create_unicode_buffer(block, len(block))
            cmd = ctypes.create_unicode_buffer(args if isinstance(args, str) else subprocess.list2cmdline(args))
            # EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW
            flags = 0x00080000 | 0x00000400 | 0x00000004 | 0x08000000
            if not _k32.CreateProcessW(None, cmd, None, None, True, flags, envbuf, cwd, ctypes.byref(si),
                                       ctypes.byref(pi)):
                raise SandboxError(f"CreateProcess in AppContainer failed ({ctypes.get_last_error()})")
        except BaseException:
            _k32.CloseHandle(in_w)      # the caller's ends: nobody will ever read or write them
            _k32.CloseHandle(out_r)
            raise
        finally:
            _k32.DeleteProcThreadAttributeList(buf)
            for s in [app_sid, *cap_sids]:
                _k32.LocalFree(s)
            _k32.CloseHandle(in_r)
            _k32.CloseHandle(out_w)
            os.set_handle_inheritable(err_h, False)
        # Every job the caller names must hold the process before it runs one instruction (AC-4; MX-9 for MXC): a
        # process outside the kill-on-close jobs would outlive the gateway and be missed when its worker is stopped.
        for j in (job if isinstance(job, (list, tuple)) else [job]):
            if j is None:
                continue
            h = getattr(j, "handle", None)
            if not h or not _k32.AssignProcessToJobObject(h, pi.hProcess):
                err = ctypes.get_last_error() if h else 0
                _k32.TerminateProcess(pi.hProcess, 1)
                for x in (pi.hThread, pi.hProcess, in_w, out_r):
                    _k32.CloseHandle(x)
                raise SandboxError("the sandboxed process could not be put in its kill-on-close job "
                                   f"({err or 'the job does not exist'}); it was ended before it ran")
        _k32.ResumeThread(pi.hThread)
        _k32.CloseHandle(pi.hThread)
        stdin = os.fdopen(msvcrt.open_osfhandle(in_w, os.O_WRONLY | os.O_BINARY), "wb", buffering=0)
        stdout = os.fdopen(msvcrt.open_osfhandle(out_r, os.O_RDONLY | os.O_BINARY), "rb", buffering=0)
        return ContainedProcess(pi.hProcess, pi.dwProcessId, stdin, stdout)

    _FAILED = re.compile(r"Failed processing (\d+) file")

    def _icacls(args: list[str]) -> int:
        """Run icacls; SandboxError when it exits with an error. Returns the number of files icacls says it could
        not process (0 when it says nothing we can read: the sentence is English, other Windows languages word it
        differently). With /C that number is the only sign of a failure - the exit code stays 0 - so it is never
        what a grant or revoke is judged by (the folder's access list is read for that); it is what tells an
        administrator that files BELOW a granted folder were left out."""
        # by full path (review 2026-11-12, C-5): a bare name is looked up in the current directory before System32
        icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
        try:
            r = subprocess.run([icacls, *args], capture_output=True, text=True, timeout=600,  # nosec B603
                               stdin=subprocess.DEVNULL, creationflags=0x08000000)
        except (OSError, subprocess.SubprocessError) as e:
            raise SandboxError(f"icacls {' '.join(args[:2])} did not finish: {e.__class__.__name__}") from e
        if r.returncode != 0:
            raise SandboxError(f"icacls {' '.join(args[:2])} failed: {(r.stdout + r.stderr).strip()[:300]}")
        m = _FAILED.search(r.stdout or "")
        return int(m.group(1)) if m else 0

    _adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                           ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    _adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    _k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD, ctypes.c_void_p]
    _k32.CreateFileW.restype = ctypes.c_void_p

    def _aces(path: str) -> list[tuple[int, int, int, str]] | None:
        """(type, flags, mask, sid) of the allow (0) and deny (1) entries of a folder's access list, in order; None
        when the list cannot be read. Read from the folder itself, not from what a program reported about it."""
        pdacl, psd = ctypes.c_void_p(), ctypes.c_void_p()
        if _adv.GetNamedSecurityInfoW(path, 1, 4, None, None, ctypes.byref(pdacl), None, ctypes.byref(psd)) != 0:
            return None
        try:
            if not pdacl:
                return []
            info = (wintypes.DWORD * 3)()
            if not _adv.GetAclInformation(pdacl, info, ctypes.sizeof(info), 2):      # AclSizeInformation
                return None
            out = []
            for i in range(info[0]):
                pace = ctypes.c_void_p()
                if not _adv.GetAce(pdacl, i, ctypes.byref(pace)) or not pace.value:
                    continue
                kind = ctypes.c_ubyte.from_address(pace.value).value
                if kind not in (0, 1):        # other entry types (object, audit, ...) have another layout
                    continue
                try:
                    sid = _sid_to_str(ctypes.c_void_p(pace.value + 8))
                except SandboxError:
                    continue
                out.append((kind, ctypes.c_ubyte.from_address(pace.value + 1).value,
                            ctypes.c_uint32.from_address(pace.value + 4).value, sid))
            return out
        finally:
            _k32.LocalFree(psd)

    def _specific(mask: int) -> int:
        for generic, rights in ((0x10000000, 0x1F01FF), (0x80000000, 0x120089), (0x40000000, 0x120116),
                                (0x20000000, 0x1200A0)):
            if mask & generic:
                mask |= rights
        return mask & 0x1FFFFF

    def access_of(path: str, sids: list[str]) -> tuple[int, int] | None:
        """(rights on the folder itself, rights its files and subfolders inherit) that the access list gives to any
        of `sids`. None when the list cannot be read or a deny entry names one of them (then nothing is assumed)."""
        aces = _aces(path)
        if aces is None:
            return None
        here = below = 0
        for kind, flags, mask, sid in aces:
            if sid not in sids:
                continue
            if kind == 1:
                return None
            if not flags & 0x8:                    # not inherit-only: applies to the folder
                here |= _specific(mask)
            if flags & 0x1 and flags & 0x2 and not flags & 0x4:    # object + container inherit, not "this level only"
                below |= _specific(mask)
        return here, below

    def own_mask(path: str, sid: str) -> int | None:
        """The rights of the allow entries `sid` has ON this folder itself (not inherited from a folder above); 0
        when it has none, None when the access list cannot be read."""
        aces = _aces(path)
        if aces is None:
            return None
        m = 0
        for kind, flags, mask, s in aces:
            if s == sid and kind == 0 and not flags & 0x10:
                m |= _specific(mask)
        return m

    def exceeds(path: str, sid: str, right: str) -> bool:
        """True when the container's own entry on the folder carries more than `right` (modify where read is
        wanted, full control where modify is). A list that cannot be read counts as "more"."""
        m = own_mask(path, sid)
        return m is None or bool(m & ~NEED[right] & 0x1FFFFF)

    def allowed(path: str, sids: list[str], right: str) -> bool:
        """True when the folder's access list gives one of `sids` the rights of `right`, on it and below it."""
        a = access_of(path, sids)
        return a is not None and a[0] & NEED[right] == NEED[right] and a[1] & NEED[right] == NEED[right]

    def can_change_permissions(path: str) -> bool:
        """May this process change the access list of `path`? Asked of Windows by opening it for exactly that."""
        h = _k32.CreateFileW(path, 0x00040000, 7, None, 3, 0x02000000, None)     # WRITE_DAC, backup semantics
        if h in (None, 0, ctypes.c_void_p(-1).value):
            return False
        _k32.CloseHandle(h)
        return True

    _u32 = ctypes.WinDLL("user32", use_last_error=True)
    _u32.GetProcessWindowStation.restype = wintypes.HANDLE
    _u32.GetThreadDesktop.restype = wintypes.HANDLE
    _u32.GetThreadDesktop.argtypes = [wintypes.DWORD]
    _u32.OpenWindowStationW.restype = wintypes.HANDLE
    _u32.OpenWindowStationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
    _u32.OpenDesktopW.restype = wintypes.HANDLE
    _u32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _u32.CloseWindowStation.argtypes = [wintypes.HANDLE]
    _u32.CloseDesktop.argtypes = [wintypes.HANDLE]
    _u32.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
    _adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    _adv.GetSecurityInfo.restype = wintypes.DWORD
    _adv.SetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p]
    _adv.SetSecurityInfo.restype = wintypes.DWORD
    _k32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetCurrentThreadId.restype = wintypes.DWORD

    class _Trustee(ctypes.Structure):
        _fields_ = [("pMultipleTrustee", ctypes.c_void_p), ("MultipleTrusteeOperation", ctypes.c_int),
                    ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int), ("ptstrName", ctypes.c_void_p)]

    class _ExplicitAccess(ctypes.Structure):
        _fields_ = [("grfAccessPermissions", wintypes.DWORD), ("grfAccessMode", ctypes.c_int),
                    ("grfInheritance", wintypes.DWORD), ("Trustee", _Trustee)]

    _adv.SetEntriesInAclW.argtypes = [wintypes.ULONG, ctypes.POINTER(_ExplicitAccess), ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_void_p)]
    _adv.SetEntriesInAclW.restype = wintypes.DWORD
    _adv.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                  ctypes.POINTER(wintypes.DWORD)]
    # A program that loads user32 (COM does; goose and Python's ctypes do) connects to a window station and a
    # desktop while it loads. Measured in a container on build 26100 (tests/test_appcontainer.py, the desktop
    # tests): unless the desktop gives the container - by its own SID or through an application-packages group -
    # both "read objects" and "write objects", user32 does not initialise: a program that links it ends with
    # 0xC0000142 before its first instruction (goose), and `import ctypes` says "DLL initialization routine
    # failed". A console program that does not load user32 (cmd.exe) still runs.
    #   - The desktop of a signed-in user gives application packages that and more (0x000F00FF).
    #   - A desktop on the window station of a logon nobody is signed in to ("Service-0x0-...$": a gateway started
    #     at boot under a service account) gives them, by default, read / list / switch (0x00020141): not enough.
    # So a container is given, on the desktop this gateway runs on: read and write objects, list, create windows
    # and menus - not the rights to hook or journal input, to switch desktops, or to change or delete the desktop
    # (which the interactive desktop gives application packages). On the window station: what Windows gives
    # application packages on every window station seen (0x00020327), when the container is not named there at all.
    WINSTA_FOR_CONTAINER = 0x00020327
    DESKTOP_NEED = 0x00000081           # DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS
    DESKTOP_FOR_CONTAINER = 0x000200C7  # + ENUMERATE, CREATEWINDOW, CREATEMENU, READ_CONTROL
    # SYSTEM, NETWORK SERVICE, LOCAL SERVICE: Windows' own services sit on these; their access lists are left alone
    _SHARED_STATIONS = ("service-0x0-3e7$", "service-0x0-3e4$", "service-0x0-3e5$")
    _ADMIT_LOCK = threading.Lock()
    _ADMIT_WARNED: set[str] = set()
    _ADMITTED: set[tuple[str, str, str]] = set()        # (container SID, what, name): the entries THIS process added

    def _object_name(h) -> str:
        buf, n = ctypes.create_unicode_buffer(256), wintypes.DWORD()
        return buf.value if _u32.GetUserObjectInformationW(h, 2, buf, ctypes.sizeof(buf), ctypes.byref(n)) else ""

    def _lets_in(h, sids, need: int = 0) -> bool | None:
        """Whether the allow entries of a window station or desktop that apply to the object itself give `sids`,
        together, all of `need` (need 0: anything at all). None when the list cannot be read. An object without an
        access list lets everybody in."""
        pdacl, psd = ctypes.c_void_p(), ctypes.c_void_p()
        if _adv.GetSecurityInfo(h, 7, 4, None, None, ctypes.byref(pdacl), None, ctypes.byref(psd)) != 0:   # SE_WINDOW_OBJECT
            return None
        try:
            if not pdacl:
                return True
            info, have = (wintypes.DWORD * 3)(), 0
            if not _adv.GetAclInformation(pdacl, info, ctypes.sizeof(info), 2):
                return None
            for i in range(info[0]):
                pace = ctypes.c_void_p()
                if not _adv.GetAce(pdacl, i, ctypes.byref(pace)) or not pace.value:
                    return None
                kind = ctypes.c_ubyte.from_address(pace.value).value
                flags = ctypes.c_ubyte.from_address(pace.value + 1).value
                mask = wintypes.DWORD.from_address(pace.value + 4).value
                if kind != 0 or flags & 0x08 or not mask:       # allow entries, and not the "inherit only" ones
                    continue
                try:
                    if _sid_to_str(ctypes.c_void_p(pace.value + 8)) in sids:
                        have |= mask
                except SandboxError:
                    pass
            return (have & need) == need if need else bool(have)
        finally:
            _k32.LocalFree(psd)

    def session_info() -> dict:
        """Where this process runs, as far as an application container is concerned: the session, the window
        station and desktop, and whether those let application packages in as they are (the window station names
        them; the desktop gives them DESKTOP_NEED). A boot task or a service runs in session 0 on a window station
        of its logon, not on the interactive "WinSta0"."""
        sess = wintypes.DWORD()
        _k32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))
        ws, dt = _u32.GetProcessWindowStation(), _u32.GetThreadDesktop(_k32.GetCurrentThreadId())
        name = _object_name(ws)
        return {"session": sess.value, "windowStation": name, "desktop": _object_name(dt),
                "interactive": name.lower() == "winsta0", "build": sys.getwindowsversion().build,
                "windowStationLetsContainersIn": _lets_in(ws, [ALL_APP_PACKAGES, ALL_RESTRICTED_APP_PACKAGES]),
                "desktopLetsContainersIn": _lets_in(dt, [ALL_APP_PACKAGES, ALL_RESTRICTED_APP_PACKAGES],
                                                    DESKTOP_NEED)}

    def _set_entry(h, sid: str, mask: int, mode: int, what: str) -> bool:
        """Add (mode 1, GRANT_ACCESS) or take off (mode 4, REVOKE_ACCESS) the entry of `sid` on a window station or
        desktop handle that was opened for changing its access list. False when the object has no access list:
        everybody is let in then, and a list with one entry would shut everybody else out."""
        pdacl, psd, new, psid = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p(), None
        rc = _adv.GetSecurityInfo(h, 7, 4, None, None, ctypes.byref(pdacl), None, ctypes.byref(psd))
        if rc:
            raise SandboxError(f"the access list of the {what} cannot be read ({rc})")
        try:
            if not pdacl:
                return False
            psid = _str_to_sid(sid)
            ea = _ExplicitAccess(mask, mode, 0, _Trustee(None, 0, 0, 0, psid.value))       # TRUSTEE_IS_SID
            rc = _adv.SetEntriesInAclW(1, ctypes.byref(ea), pdacl, ctypes.byref(new))
            if rc or not new.value:     # no list at all would be written as "everybody is let in"
                raise SandboxError(f"the access list of the {what} cannot be built ({rc})")
            # a list marked "protected" (takes nothing from above) stays so: only the one entry differs afterwards
            control, rev = wintypes.WORD(), wintypes.DWORD()
            _adv.GetSecurityDescriptorControl(psd, ctypes.byref(control), ctypes.byref(rev))
            rc = _adv.SetSecurityInfo(h, 7, 4 | (0x80000000 if control.value & 0x1000 else 0), None, None, new, None)
            if rc:
                raise SandboxError(f"the access list of the {what} cannot be changed ({rc})")
            return True
        finally:
            if psid:
                _k32.LocalFree(psid)
            _k32.LocalFree(psd)
            if new:
                _k32.LocalFree(new)

    def _own_objects(desktop: str):
        """(what, name, the handle this process holds or None, open(access), close, what a container needs there,
        what it is given) for the window station this process is on and for its desktop (or the desktop `desktop`
        of that window station)."""
        hws, hdt = _u32.GetProcessWindowStation(), _u32.GetThreadDesktop(_k32.GetCurrentThreadId())
        ws_name = _object_name(hws)
        dt_name = desktop or _object_name(hdt) or "Default"
        return (("window station", ws_name, hws, lambda a: _u32.OpenWindowStationW(ws_name, False, a),
                 _u32.CloseWindowStation, 0, WINSTA_FOR_CONTAINER),
                ("desktop", dt_name, None if desktop else hdt, lambda a: _u32.OpenDesktopW(dt_name, 0, False, a),
                 _u32.CloseDesktop, DESKTOP_NEED, DESKTOP_FOR_CONTAINER))

    def admit(sid: str, desktop: str = "", dry: bool = False) -> list[str]:
        """Make sure the container can use the window station and the desktop its processes connect to: those of
        this process (`desktop`: that desktop of its window station). Where the window station names neither the
        container nor ALL APPLICATION PACKAGES, or the desktop does not give them what user32 needs (DESKTOP_NEED),
        the container gets an entry of its own (WINSTA_FOR_CONTAINER, DESKTOP_FOR_CONTAINER). Returns what was
        added - nothing where somebody is signed in: Windows lets application packages in there itself. `dry`: only
        say what would be added. SandboxError when an entry is needed and this account may not add it, and for a
        SID that is not one container's own. Nothing here outlives the logon of this process: its window station
        and desktops end with it."""
        if not _CONTAINER_SID.fullmatch(sid or ""):
            raise SandboxError(f"not the SID of one application container: {sid!r}")
        who = [sid, ALL_APP_PACKAGES, ALL_RESTRICTED_APP_PACKAGES]
        station = _object_name(_u32.GetProcessWindowStation())
        added: list[str] = []
        with _ADMIT_LOCK:       # read, add, write: two members starting at once must not lose each other's entry
            for what, name, own, opener, closer, need, give in _own_objects(desktop):
                state = _lets_in(own, who, need) if own else None
                if state is None:                   # the handle this process holds may not read the list
                    h = opener(0x00020000)          # READ_CONTROL
                    if h:
                        try:
                            state = _lets_in(h, who, need)
                        finally:
                            closer(h)
                if state:
                    continue
                if dry:
                    added.append(f"{what} {name}")
                    continue
                if station.lower() in _SHARED_STATIONS:
                    raise SandboxError(f"the {what} {name!r} does not let the container in, and this gateway runs on "
                                       f"{station!r}, the window station of a Windows service account that Windows' "
                                       "own services share: its access lists are not changed. Run the gateway under "
                                       "an account of its own")
                h = opener(0x00060000)              # READ_CONTROL | WRITE_DAC
                if not h:
                    raise SandboxError(f"the {what} {name!r} this gateway runs on does not let the container in, "
                                       f"and this account may not change its access list "
                                       f"({ctypes.get_last_error()})")
                try:
                    state = _lets_in(h, who, need)
                    if state is None:
                        raise SandboxError(f"the access list of the {what} {name!r} cannot be read")
                    if not state and _set_entry(h, sid, give, 1, what):
                        _ADMITTED.add((sid, what, name))
                        added.append(f"{what} {name}")
                finally:
                    closer(h)
        return added

    def dismiss(sid: str, desktop: str = "") -> list[str]:
        """Take off again the entries that admit() added for this container IN THIS PROCESS (its container is
        deleted). Nothing else is ever taken off a window station or desktop: not an entry somebody else made, and
        not an entry of any other SID - the SID comes from a record on disk, and a record that named ALL APPLICATION
        PACKAGES would otherwise shut every application container of this logon out. Never raises: what cannot be
        taken off ends with the logon of this process."""
        gone: list[str] = []
        if not _CONTAINER_SID.fullmatch(sid or ""):
            return gone
        try:
            with _ADMIT_LOCK:
                for what, name, _own, opener, closer, _need, _give in _own_objects(desktop):
                    if (sid, what, name) not in _ADMITTED:
                        continue
                    try:                    # one that cannot be taken off does not keep the other on
                        h = opener(0x00060000)
                        if not h:
                            continue
                        try:
                            if _set_entry(h, sid, 0, 4, what):
                                gone.append(f"{what} {name}")
                            _ADMITTED.discard((sid, what, name))
                        finally:
                            closer(h)
                    except Exception as e:
                        log.debug("sandbox: the entry of %s is left on the %s %s: %s", sid, what, name, e)
        except Exception as e:
            log.debug("sandbox: entries of %s left on the window station: %s", sid, e)
        return gone

    def grant(path: str, sid: str, right: str) -> None:
        # :r - the container's entry is REPLACED. Without it icacls adds to an entry that is still there (a revoke
        # that failed), and a folder taken down from modify to read kept modify while the record said read (W-5).
        skipped = _icacls([path, "/grant:r", f"*{sid}:{RIGHTS[right]}", "/Q", "/C"])
        # /C ("continue") lets one locked file below not fail the folder - but with it icacls exits 0 even when it
        # could not change the folder at all, and Goose Web recorded a grant that was never made (found in use,
        # 2026-11-13). The entry must be on the folder.
        if not allowed(path, [sid], right):
            raise SandboxError(f"the permissions of {path} could not be changed: the container's entry is not there")
        if exceeds(path, sid, right):       # an older, wider entry that /grant:r could not replace (X-2)
            raise SandboxError(f"the permissions of {path} could not be changed: the container's entry there is "
                               f"wider than {right}")
        if skipped:
            log.warning("sandbox: %s is granted, but icacls could not change %d file(s) or folder(s) below it; the "
                        "member's agent cannot use those", path, skipped)

    def sweep(path: str, sid: str, keep=(), seconds: float = 20.0, max_entries: int = 200000) -> tuple[list[str], bool]:
        """After the container's entry was taken off `path`: is it off everything below as well? A subfolder whose
        inheritance was switched off keeps a copy of the entry as its own, and one that cannot be changed keeps the
        inherited one - both stayed, with nothing on record (review Z-1). An entry of its own found below is taken
        off; what cannot be cleaned is returned. Folders in `keep` (still wanted) and what is below them are not
        touched. Bounded walk; links are not followed. Returns (what still names the container - at most 20,
        whether everything was looked at)."""
        norm = os.path.normcase
        keepers = [norm(os.path.normpath(k)) for k in keep]
        top = _aces(path)
        # the folder itself still gets the entry from a granted folder above: below it, inherited entries are right
        inherits = top is not None and any(k == 0 and s == sid and f & 0x10 for k, f, m, s in top)
        left: list[str] = []
        seen, end, stack = 0, time.monotonic() + seconds, [path]
        while stack:
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    seen += 1
                    if seen > max_entries or time.monotonic() > end:
                        return left, False
                    try:
                        if e.is_symlink() or getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
                            continue
                        n = norm(e.path)
                        if any(n == k or n.startswith(k + os.sep) for k in keepers):
                            continue
                        aces = _aces(e.path)
                        if aces is not None:
                            own = any(k == 0 and s == sid and not f & 0x10 for k, f, m, s in aces)
                            stale = not inherits and any(k == 0 and s == sid and f & 0x10 for k, f, m, s in aces)
                            if own:
                                try:
                                    _icacls([e.path, "/remove:g", f"*{sid}", "/Q", "/C"])
                                except SandboxError:
                                    pass
                                again = _aces(e.path)
                                own = again is None or any(k == 0 and s == sid and not f & 0x10 for k, f, m, s in again)
                            if (own or stale) and len(left) < 20:
                                left.append(e.path)
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                    except OSError:
                        continue
        return left, True

    def revoke(path: str, sid: str) -> None:
        if os.path.exists(path):
            _icacls([path, "/remove:g", f"*{sid}", "/Q", "/C"])
            aces = _aces(path)      # an entry of its own must be gone; one inherited from a folder above is that folder's
            if aces is None or any(k == 0 and s == sid and not f & 0x10 for k, f, m, s in aces):
                raise SandboxError(f"the container's entry on {path} could not be removed")
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

    def access_of(path: str, sids: list[str]) -> tuple[int, int] | None:
        return None

    def allowed(path: str, sids: list[str], right: str) -> bool:
        return False

    def own_mask(path: str, sid: str) -> int | None:
        return None

    def exceeds(path: str, sid: str, right: str) -> bool:
        return True

    def sweep(path: str, sid: str, keep=(), seconds: float = 20.0, max_entries: int = 200000) -> tuple[list[str], bool]:
        return [], True

    def can_change_permissions(path: str) -> bool:
        return False

    def session_info() -> dict:
        return {}

    def admit(sid: str, desktop: str = "", dry: bool = False) -> list[str]:
        raise SandboxError("the sandbox needs Windows (AppContainer)")

    def dismiss(sid: str, desktop: str = "") -> list[str]:
        return []


# ------------------------------------------------------------------ does a container process start here at all?
INIT_FAILED = 0xC0000142        # STATUS_DLL_INIT_FAILED: what a process that cannot use its desktop ends with


def _selftest_run(sid: str, python: str, desktop: str = "") -> list[dict]:
    """The steps of the self-test, started as the access lists are (spawn does not touch them here)."""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    cwd = os.path.join(sysroot, "System32")
    env = {k: os.environ[k] for k in ("SystemRoot", "windir", "SystemDrive", "LOCALAPPDATA") if os.environ.get(k)}
    env["PATH"] = cwd
    steps = [("a console program (cmd.exe)", [os.path.join(cwd, "cmd.exe"), "/d", "/c", "echo ok"])]
    if python:
        steps.append(("a program that uses its desktop, COM and sockets (the gateway's Python)",
                      [python, "-I", "-c", "import ctypes, socket; ctypes.WinDLL('user32').GetDesktopWindow(); "
                                           "socket.socket().close(); print('ok')"]))
    out = []
    for what, args in steps:
        import tempfile
        with tempfile.TemporaryFile() as errf:
            try:
                p = spawn(args, env, cwd, sid, [], errf, desktop=desktop, admit_first=False)
                p.stdin.close()
                box: list[bytes] = []
                t = threading.Thread(target=lambda: box.append(p.stdout.read()), daemon=True)
                t.start()
                t.join(60)
                if t.is_alive():
                    p.kill()
                code = p.wait(10) & 0xFFFFFFFF
                errf.seek(0)
                err = errf.read().decode("utf-8", "replace").strip().splitlines()
                text = (box[0] if box else b"").decode("utf-8", "replace").strip()
                out.append({"what": what, "ok": code == 0 and text == "ok", "exit": f"0x{code:08X}",
                            "detail": (err[-1] if err else "")[:200]})
            except Exception as e:
                out.append({"what": what, "ok": False, "exit": "", "detail": f"{type(e).__name__}: {str(e)[:200]}"})
    return out


def selftest(python: str = "", desktop: str = "") -> dict:
    """Start a console program and - when `python` is given - a program that uses its desktop, COM and sockets in a
    throwaway AppContainer, from THIS process: in the session and on the window station it runs in (`desktop`: on
    that desktop of the window station; for tests). A member's agent needs exactly that to work, and only the
    gateway can measure it for the gateway.

    The case this is for: a gateway started at boot under an account nobody signs in with. Its window station is
    not the interactive one, and on some Windows versions it does not let application containers in; their
    processes then end with 0xC0000142 before the first instruction (reported from Windows Server 2022). Where the
    container is not let in, the steps run first as things are (`stepsBefore`), then the container is named on the
    window station and desktop (admit - what spawn does for every member) and they run again (`steps`). Where it
    is let in already, nothing is changed and they run once.

    Returns {ok, steps, stepsBefore?, missing, admitted, remedy, reason, at, session, windowStation, desktop,
    interactive, build, ...}. When containers cannot read the folder of `python`, the throwaway container is given
    it for the test and it is taken off again."""
    if not IS_WINDOWS:
        return {"ok": False, "reason": "the AppContainer backend needs Windows", "steps": []}
    info = session_info()
    name = f"GooseWeb.selftest.{os.getpid()}"
    res: dict = {**info, "ok": False, "steps": [], "missing": [], "admitted": [], "remedy": "", "reason": "",
                 "at": time.time()}
    granted, sid = "", ""
    try:
        sid = ensure_container(name)
        # the folder itself, not a link to it: a grant on a directory link changes the link (uv keeps its Pythons
        # behind one), and the program then ends with 0xC0000135
        pyfolder = os.path.realpath(os.path.dirname(python)) if python else ""
        if not python:
            res["reason"] = "the desktop and COM were not tried: no Python was given. "
        elif not allowed(pyfolder, [ALL_APP_PACKAGES], "read"):
            granted = pyfolder      # before the grant: one that fails half-way is taken off as well
            try:
                grant(pyfolder, sid, "read")
            except SandboxError:
                python = ""         # cannot be made readable here: only the console program is tried
                res["reason"] = "the desktop and COM were not tried: containers cannot read the gateway's Python folder. "
        res["missing"] = admit(sid, desktop, dry=True)
        if res["missing"]:
            res["stepsBefore"] = _selftest_run(sid, python, desktop)
            try:
                res["admitted"] = admit(sid, desktop)
            except SandboxError as e:
                res["remedy"] = str(e)[:300]
        res["steps"] = _selftest_run(sid, python, desktop)
        # A console program alone proves nothing: cmd.exe starts exactly where a member's agent ends with
        # 0xC0000142. Without the program that uses its desktop there is no "ok".
        res["ok"] = bool(python) and all(s["ok"] for s in res["steps"])
        before = [s for s in res.get("stepsBefore", []) if not s["ok"]]
        if res["ok"] and res["admitted"]:
            where = " and ".join(res["admitted"])
            res["remedy"] = ((f"only once its container is named on the {where}: without that, {before[0]['what']} "
                              f"ended with {before[0]['exit'] or before[0]['detail']}. ") if before else
                             (f"the {where} did not name application containers; the container was named there "
                              "(the processes started without that too). ")
                             ) + "Goose Web names every member's container there when it starts their agent"
        elif res["ok"] and res["missing"] and res["remedy"]:
            res["remedy"] = "although " + res["remedy"]
        if not res["ok"]:
            bad = next((s for s in res["steps"] if not s["ok"]), None)
            res["reason"] += ((f"a process in an application container does not start in this session: {bad['what']} "
                               f"ended with {bad['exit'] or bad['detail']}.") if bad else
                              "A console program started, which says nothing about a member's agent.")
            res["reason"] += (f" The gateway runs in session {info.get('session')} on window station "
                              f"{info.get('windowStation')!r}"
                              + ("" if info.get("interactive") else " (nobody is signed in there)") + ".")
            if res["admitted"]:
                res["remedy"] = ("naming the container on the " + " and ".join(res["admitted"]) + " did not help"
                                 + ("" if before else " (it started before that)"))
    except Exception as e:
        res["reason"] = f"the self-test could not run: {type(e).__name__}: {str(e)[:200]}"
    finally:        # each on its own: one that fails does not keep the others from being cleared away
        for what, undo in (("entries on the window station and desktop", lambda: sid and dismiss(sid, desktop)),
                           ("grant on the Python folder",
                            lambda: granted and sid and own_mask(granted, sid) and revoke(granted, sid)),
                           ("throwaway container", lambda: delete_container(name))):
            try:
                undo()
            except Exception as e:
                log.warning("sandbox self-test: the %s could not be cleared away: %s", what, e)
    return res


def selftest_text(res: dict) -> tuple[bool, str]:
    """(ok, one line) for `check`, `sandbox status` and the log."""
    where = (f"session {res.get('session')}, window station {res.get('windowStation')!r}"
             + ("" if res.get("interactive") else ", nobody signed in"))
    if res.get("ok"):
        return True, (f"a process in an application container starts here ({where})"
                      + (f"; {res['remedy']}" if res.get("remedy") else ""))
    return False, ((res.get("reason") or "failed") + (f" {res['remedy']}." if res.get("remedy") else "")
                   + " Members' agents cannot run in an AppContainer started by this gateway; see ADMINISTRATION "
                     "11.6 (a gateway nobody is signed in to)")


def _state_path(state_dir: str, name: str) -> Path:
    # Kept in the gateway's system folder, outside every container's reach (a worker cannot edit its own record).
    return Path(state_dir) / f"{name}.json"


def load_state(state_dir: str, name: str) -> dict:
    try:
        return json.loads(_state_path(state_dir, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_atomic(path: Path | str, text: str) -> None:
    """The whole file or nothing (AC-5, AC-7): written to a new file beside the target and moved over it, bytes as
    given (no newline translation). A target name that is a link is replaced by a file of its own, never written
    through. The temporary file has a random name and is created exclusively, so it is new, whatever sits in the
    folder. A target that is open elsewhere without delete sharing (a reader of ours) refuses the move for a
    moment: tried again for 150 ms. On failure the temporary file is removed and the target is as it was."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
        for attempt in range(6):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.03)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _save_state(state_dir: str, name: str, state: dict) -> None:
    sp = _state_path(state_dir, name)
    sp.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(sp, json.dumps(state, indent=1))


def _account() -> tuple[str, str]:
    """(name, "*<sid>" or the name) of the account this process runs as. icacls takes the SID form in cmd and in
    PowerShell alike; a name ending in $ (a managed service account) breaks a PowerShell command line (X-7)."""
    name = os.environ.get("USERNAME", "the gateway's account")
    try:
        from . import winsec
        name = str(winsec.current_user() or name)
        sid = str(winsec.current_user_sid() or "")
        return name, (f"*{sid}" if sid.startswith("S-1-") else name)
    except Exception:
        return name, name


def grant_help(path: str, right: str) -> str:
    """What to do about a folder a member's container needs and the gateway cannot give it."""
    who, ident = _account()
    if right == "read":
        return (f"{path}: members' containers cannot read it and the gateway's account ({who}) may not change its "
                "permissions (it has no WRITE_DAC there). Let application containers read it, as an administrator or "
                "the folder's owner: "
                f'icacls "{path}" /grant "*{ALL_APP_PACKAGES}:(OI)(CI)RX"')
    return (f"{path}: the gateway's account ({who}) may not change its permissions (it has no WRITE_DAC there), so a "
            "member's container cannot be given access. Make that account the folder's owner or give it full control "
            "(or at least the right to change permissions), as an administrator or "
            f'its owner: icacls "{path}" /grant "{ident}:(OI)(CI)F"')


def folder_problems(read_folders: list[str], profiles_root: str) -> list[dict]:
    """For `check`, `sandbox status` and the start of the gateway, when the AppContainer backend may be used: program
    folders every member's container must read (goose, sandbox.read_dirs, the gateway's base Python for relays) that
    give application containers no access while this account may not change their permissions, and the profiles
    root when this account may not change permissions in its own data folder. [{path, why}]; judged for THIS
    account. A team's extra folders are judged when a member's agent starts."""
    out = []
    for d in dict.fromkeys(os.path.normpath(x) for x in read_folders if x):
        if os.path.isdir(d) and not allowed(d, [ALL_APP_PACKAGES], "read") and not can_change_permissions(d):
            out.append({"path": d, "why": grant_help(d, "read")})
    if profiles_root and os.path.isdir(profiles_root) and not can_change_permissions(profiles_root):
        out.append({"path": profiles_root, "why": grant_help(profiles_root, "modify")})
    return out


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock(name: str) -> threading.Lock:
    """One at a time per container: a worker start, an administrator's change and a removal all rewrite the same
    folders and the same record (X-1 d)."""
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(str(name).lower(), threading.Lock())


def _drop(d: dict, path: str) -> None:
    for k in [k for k in d if os.path.normcase(k) == os.path.normcase(path)]:
        del d[k]


def prepare(name: str, state_dir: str, grants: dict[str, str], required: list[str] | tuple = ()) -> dict:
    """Ensure the container exists and the folder grants match `grants` (only changes are applied; folders that
    do not exist yet are skipped and retried at the next start). Returns the saved state
    {name, sid, grants, external, failed, pending, updatedAt} (<system_dir>/sandbox/<name>.json).

    `grants`: the folders on which the container has its entry, and from which Goose Web takes it off again when
    they are no longer wanted. Each is looked at on the folder itself, never taken from the record or from what
    icacls reported: an entry that is missing is made, one that is wider than wanted is replaced. An entry of the
    container that is already there counts as a grant whoever made it - a start that could not save its record, an
    earlier version, an administrator by hand: what is on record is taken off later, what is not would stay for
    good (review X-1).
    `external`: folders every application container may use anyway ("ALL APPLICATION PACKAGES", as under
    C:\\Program Files). Nothing is added there; an entry of the container's own that is still there is taken off.
    `failed` {folder: what to do}: folders that could not be given, because this account may not change their
    permissions. They are left out and tried again at every start. When one of them is in `required` (the member's
    profile, the goose folder) the call fails with that text - after the record is saved.
    `pending`: entries on a folder that is missing right now (renamed away, a disconnected drive) or that could not
    be taken off. Kept until the entry is confirmed (wanted again) or gone; dropping it would leave an entry
    nobody tracks."""
    with _lock(name):
        return _prepare(name, state_dir, grants, required)


def _record(state_dir: str, name: str) -> dict:
    """The container's record, for changing it: {} only when there is none. A record that cannot be read or is not
    a record stops the change: the entries it listed would otherwise be forgotten while they stay on the folders
    (review Z-5)."""
    p = _state_path(state_dir, name)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise SandboxError(f"the sandbox record {p} cannot be read ({e.__class__.__name__}); nothing was changed") from e
    try:
        st = json.loads(raw)
    except ValueError as e:
        raise SandboxError(f"the sandbox record {p} is damaged; nothing was changed. It lists the folders that carry "
                           "this container's entries: repair it, or look at those folders and delete the file") from e
    if not isinstance(st, dict) or any(not isinstance(st.get(k, {}), dict) for k in ("grants", "pending", "external", "failed")):
        raise SandboxError(f"the sandbox record {p} is not a record of this version; nothing was changed")
    return st


def _still_there(path: str, sid: str, fallback: str) -> str | None:
    """What the container's own entry on the folder is now: "modify", "read", None when it has none - read from the
    folder, so that the record never says less than is there (review Z-2). `fallback` when the list cannot be read
    (it may be there)."""
    m = own_mask(path, sid)
    if m is None:
        return fallback
    if not m:
        return None
    return "modify" if m & ~NEED["read"] & 0x1FFFFF else "read"


def _take_off(path: str, sid: str, keep=()) -> None:
    """The container's entry is off the folder and off everything below it, or SandboxError."""
    revoke(path, sid)
    left, complete = sweep(path, sid, keep)
    if left:
        raise SandboxError(f"the container's entry is still on {left[0]}"
                           + (f" and {len(left) - 1} more place(s)" if len(left) > 1 else "") + f" below {path}")
    if not complete:
        log.warning("sandbox: %s is too large to look through completely; single files or subfolders below it whose "
                    "permissions were set by hand may still name the container", path)


def _prepare(name: str, state_dir: str, grants: dict[str, str], required) -> dict:
    norm = os.path.normcase
    old = _record(state_dir, name)
    sid = ensure_container(name)
    same = old.get("sid") == sid
    recorded = {**(old.get("pending", {}) if same else {}), **(old.get("grants", {}) if same else {})}
    have = {p: r for p, r in recorded.items() if os.path.isdir(p)}
    missing = {p: r for p, r in recorded.items() if not os.path.isdir(p)}
    present = {p: r for p, r in grants.items() if os.path.isdir(p)}
    apply, revoke_list = diff_grants(have, present)
    for p in revoke_list:
        try:
            _take_off(p, sid, keep=present)
        except SandboxError as e:
            log.warning("sandbox %s: %s", name, e)
            # still on the folder (or below it): on record, with what is really there, until it is gone or replaced
            missing[p] = _still_there(p, sid, have[p]) or have[p]
    for p, r in present.items():        # after the revokes (Z-7): on record and wanted - on the folder, and no more?
        if p not in apply and (not allowed(p, [sid, ALL_APP_PACKAGES], r) or exceeds(p, sid, r)):
            apply[p] = r
    must = {norm(os.path.normpath(p)) for p in required}
    granted, external, failed, fatal = dict(present), {}, {}, ""
    for p, right in apply.items():
        if allowed(p, [ALL_APP_PACKAGES], right):
            own = _still_there(p, sid, recorded.get(p, right))
            if own:                     # no entry of the container's own is needed here: take it off
                try:
                    revoke(p, sid)
                    _drop(missing, p)
                except SandboxError as e:
                    log.warning("sandbox %s: %s", name, e)
                    _drop(missing, p)
                    missing[p] = own
            external[p] = granted.pop(p)
            continue
        if allowed(p, [sid], right) and not exceeds(p, sid, right):
            _drop(missing, p)           # the entry is there and is exactly what is wanted: a grant, on record
            continue
        try:
            grant(p, sid, right)
            _drop(missing, p)           # replaced: whatever was there before is gone
        except SandboxError as e:
            why = grant_help(p, right) if not can_change_permissions(p) else f"{p}: {e}"
            own = _still_there(p, sid, recorded.get(p, right))
            if own:                     # something of the container's is on it all the same: on record as it is
                _drop(missing, p)
                missing[p] = own
                if own == "modify" and right == "read":
                    why += " The container's modify entry could not be narrowed and is still on the folder."
            failed[p] = why
            granted.pop(p)
            log.error("sandbox %s: folder left out: %s", name, why)
            if norm(os.path.normpath(p)) in must and not fatal:
                fatal = why
    state = {"name": name, "sid": sid, "grants": granted, "external": external, "failed": failed,
             "pending": missing, "updatedAt": time.time()}
    _save_state(state_dir, name, state)     # before anything is raised: what was done is on record
    if apply or revoke_list:
        log.info("sandbox %s: granted %s, revoked %s", name, sorted(p for p in apply if p in granted),
                 sorted(p for p in revoke_list if p not in missing))
    if missing:
        log.info("sandbox %s: %d entr(y/ies) kept on record until they can be taken off: %s", name,
                 len(missing), sorted(missing))
    if fatal:
        raise SandboxError(fatal)
    return state


def shrink(name: str, state_dir: str, grants: dict[str, str]) -> dict:
    """Take the container's entry off every folder on record that is not in `grants` any more - now, without
    starting anything, granting anything or creating the container. For the moment an administrator takes a folder
    away (api._sync_grants): before, the entry stayed until that member's agent next started, for good when it
    never did, and a running agent kept the folder until it was restarted. What cannot be taken off stays on record
    (`pending`). Returns {revoked: [...], pending: {...}}; {} when the container has no record."""
    norm = os.path.normcase
    with _lock(name):
        st = _record(state_dir, name)
        sid = st.get("sid")
        if not sid:
            return {}
        wanted = {norm(p) for p in grants}
        keep, pending, gone = {}, {}, []
        for source, target in ((st.get("grants") or {}, keep), (st.get("pending") or {}, pending)):
            for p, r in source.items():
                if norm(p) in wanted or not os.path.isdir(p):
                    target[p] = r       # still wanted (a changed right is the next start's business), or not there now
                    continue
                try:
                    _take_off(p, sid, keep=grants)
                    gone.append(p)
                except SandboxError as e:
                    log.warning("sandbox %s: %s", name, e)
                    pending[p] = _still_there(p, sid, r) or r
        if gone or keep != (st.get("grants") or {}) or pending != (st.get("pending") or {}):
            _save_state(state_dir, name, {**st, "grants": keep, "pending": pending, "updatedAt": time.time()})
        if gone:
            log.info("sandbox %s: entries taken off at once (no longer permitted): %s", name, sorted(gone))
        return {"revoked": gone, "pending": pending}


def remove(state_dir: str, name: str) -> dict:
    """Revoke every recorded grant and delete the container profile (user deleted, made admin, or sandbox off).
    Grants on folders that are missing now stay recorded (a record with only `pending` grants), so a later
    remove (`goose-web sandbox remove --all`) or a new container of the same name revokes them when they are back."""
    with _lock(name):
        return _remove(state_dir, name)


def _remove(state_dir: str, name: str) -> dict:
    st = _record(state_dir, name)
    if not st.get("sid"):
        return {}
    left: dict[str, str] = {}
    for p, r in {**st.get("pending", {}), **st.get("grants", {})}.items():
        if not os.path.isdir(p):
            left[p] = r
            continue
        try:
            _take_off(p, st["sid"])
        except SandboxError as e:
            log.warning("sandbox remove: %s", e)
            left[p] = _still_there(p, st["sid"], r) or r
    delete_container(name)
    dismiss(st["sid"])      # what admit() gave it on this process's window station and desktop
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
