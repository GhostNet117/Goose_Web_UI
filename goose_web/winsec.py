"""Windows token helpers: keep the gateway (and every goose it starts) un-elevated.

Why: a scheduled-task or elevated launch of the service account gets the FULL admin token. Files that
Goose then creates (secrets.yaml, sessions.db, OAuth caches) become owned by BUILTIN\\Administrators and the
normal user loses access to them. The gateway therefore refuses to run elevated: at startup it re-launches
itself with a SAFER "Normal User" token at Medium integrity whose default owner is the user SID (the same
technique as `runas /trustlevel:0x20000`). Children inherit that token, so every goose serve worker writes
files owned by the user.

All functions are no-ops / safe defaults on non-Windows platforms.
"""
from __future__ import annotations

import os
import sys

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:  # pragma: no branch
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    TOKEN_QUERY = 0x0008
    TokenUser, TokenOwner, TokenElevation, TokenIntegrityLevel = 1, 4, 20, 25

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    advapi32.SaferCreateLevel.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi32.SaferComputeTokenFromLevel.argtypes = [ctypes.c_void_p, wintypes.HANDLE,
                                                    ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.c_void_p]
    advapi32.SaferCloseLevel.argtypes = [ctypes.c_void_p]
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    advapi32.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                              ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                                              wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                              ctypes.POINTER(PROCESS_INFORMATION)]
    advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.LookupAccountSidW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int)]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    # process priority (FIX gateway-below-normal-priority)
    kernel32.GetPriorityClass.argtypes = [wintypes.HANDLE]
    kernel32.GetPriorityClass.restype = wintypes.DWORD
    kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetPriorityClass.restype = wintypes.BOOL
    try:
        kernel32.GetProcessInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.GetProcessInformation.restype = wintypes.BOOL
        kernel32.SetProcessInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetProcessInformation.restype = wintypes.BOOL
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                    ctypes.POINTER(wintypes.ULONG)]
        ntdll.NtQueryInformationProcess.restype = ctypes.c_long
        ntdll.NtSetInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG]
        ntdll.NtSetInformationProcess.restype = ctypes.c_long
        _HAVE_PRIORITY_API = True
    except (AttributeError, OSError):  # pragma: no cover - a Windows without these calls: only the CPU class is handled
        ntdll = None
        _HAVE_PRIORITY_API = False

    def _check(ok, what):
        if not ok:
            raise OSError(ctypes.get_last_error(), f"{what} failed (WinError {ctypes.get_last_error()})")

    def _token_info(cls: int) -> ctypes.Array:
        tok = wintypes.HANDLE()
        _check(advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)),
               "OpenProcessToken")
        try:
            need = wintypes.DWORD()
            advapi32.GetTokenInformation(tok, cls, None, 0, ctypes.byref(need))
            buf = ctypes.create_string_buffer(max(need.value, 8))
            _check(advapi32.GetTokenInformation(tok, cls, buf, need.value or 8, ctypes.byref(need)),
                   "GetTokenInformation")
            return buf
        finally:
            kernel32.CloseHandle(tok)

    def _sid_str(psid) -> str:
        s = wintypes.LPWSTR()
        _check(advapi32.ConvertSidToStringSidW(psid, ctypes.byref(s)), "ConvertSidToStringSid")
        try:
            return s.value
        finally:
            kernel32.LocalFree(s)


def is_elevated() -> bool:
    """True when the current process holds an elevated (full admin) token."""
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        buf = _token_info(TokenElevation)
        return ctypes.c_uint32.from_buffer(buf).value != 0
    except OSError:
        return False


def integrity_level() -> str:
    """'low' | 'medium' | 'high' | 'system' | 'unknown' (POSIX: 'root' or 'user')."""
    if not IS_WINDOWS:
        return "root" if is_elevated() else "user"
    try:
        buf = _token_info(TokenIntegrityLevel)
        sa = SID_AND_ATTRIBUTES.from_buffer(buf)
        count = advapi32.GetSidSubAuthorityCount(sa.Sid)[0]
        rid = advapi32.GetSidSubAuthority(sa.Sid, count - 1)[0]
    except OSError:
        return "unknown"
    if rid >= 0x4000:
        return "system"
    if rid >= 0x3000:
        return "high"
    if rid >= 0x2000:
        return "medium"
    return "low"


def current_user_sid() -> str:
    if not IS_WINDOWS:
        return str(os.getuid()) if hasattr(os, "getuid") else ""
    buf = _token_info(TokenUser)
    return _sid_str(SID_AND_ATTRIBUTES.from_buffer(buf).Sid)


def current_user() -> str:
    if IS_WINDOWS:
        return os.environ.get("USERNAME", "")
    import getpass
    return getpass.getuser()


def file_owner(path: str) -> tuple[str, str]:
    """(owner_sid, 'DOMAIN\\name') of a file; ('', '') on failure or non-Windows."""
    if not IS_WINDOWS:
        try:
            import pwd
            st = os.stat(path)
            return str(st.st_uid), pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            return "", ""
    owner = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    rc = advapi32.GetNamedSecurityInfoW(path, 1, 0x1, ctypes.byref(owner), None, None, None, ctypes.byref(sd))
    if rc != 0:
        return "", ""
    try:
        sid = _sid_str(owner)
        name = ctypes.create_unicode_buffer(256)
        dom = ctypes.create_unicode_buffer(256)
        nl, dl, use = wintypes.DWORD(256), wintypes.DWORD(256), ctypes.c_int()
        if advapi32.LookupAccountSidW(None, owner, name, ctypes.byref(nl), dom, ctypes.byref(dl), ctypes.byref(use)):
            return sid, f"{dom.value}\\{name.value}" if dom.value else name.value
        return sid, sid
    finally:
        kernel32.LocalFree(sd)


def ownership_report(root: str, limit: int = 200, max_files: int = 20000) -> dict:
    """Scan a tree for files NOT owned by the current user (the Administrators/SYSTEM ownership bug)."""
    me = current_user_sid()
    bad, scanned = [], 0
    if not os.path.isdir(root):
        return {"root": root, "scanned": 0, "foreign": [], "exists": False}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "__pycache__"}]
        for n in [None, *filenames]:
            p = dirpath if n is None else os.path.join(dirpath, n)
            scanned += 1
            sid, name = file_owner(p)
            if sid and sid != me:
                bad.append({"path": p, "owner": name, "sid": sid})
                if len(bad) >= limit:
                    return {"root": root, "scanned": scanned, "foreign": bad, "truncated": True, "exists": True}
            if scanned >= max_files:
                return {"root": root, "scanned": scanned, "foreign": bad, "truncated": True, "exists": True}
    return {"root": root, "scanned": scanned, "foreign": bad, "truncated": False, "exists": True}


def run_unelevated(cmdline: str, cwd: str | None = None) -> int:
    """Run cmdline with a SAFER Normal-User, Medium-integrity, user-owned token; wait; return exit code.

    Raises OSError if the token cannot be built (callers must NOT fall back to running elevated).
    """
    if not IS_WINDOWS:
        raise OSError("run_unelevated is Windows-only")
    level = ctypes.c_void_p()
    _check(advapi32.SaferCreateLevel(2, 0x20000, 1, ctypes.byref(level), None), "SaferCreateLevel")
    tok = wintypes.HANDLE()
    try:
        _check(advapi32.SaferComputeTokenFromLevel(level, None, ctypes.byref(tok), 0, None),
               "SaferComputeTokenFromLevel")
    finally:
        advapi32.SaferCloseLevel(level)
    try:
        il = ctypes.c_void_p()
        _check(advapi32.ConvertStringSidToSidW("S-1-16-8192", ctypes.byref(il)), "ConvertStringSidToSid(IL)")
        try:
            sa = SID_AND_ATTRIBUTES(il, 0x20)
            _check(advapi32.SetTokenInformation(tok, TokenIntegrityLevel, ctypes.byref(sa),
                                                ctypes.sizeof(sa) + advapi32.GetLengthSid(il)),
                   "SetTokenInformation(IntegrityLevel)")
        finally:
            kernel32.LocalFree(il)
        us = ctypes.c_void_p()
        _check(advapi32.ConvertStringSidToSidW(current_user_sid(), ctypes.byref(us)), "ConvertStringSidToSid(user)")
        try:
            owner = ctypes.c_void_p(us.value)
            _check(advapi32.SetTokenInformation(tok, TokenOwner, ctypes.byref(owner), ctypes.sizeof(owner)),
                   "SetTokenInformation(Owner)")
        finally:
            kernel32.LocalFree(us)
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = 0x100  # STARTF_USESTDHANDLES
        si.hStdInput = kernel32.GetStdHandle(-10)
        si.hStdOutput = kernel32.GetStdHandle(-11)
        si.hStdError = kernel32.GetStdHandle(-12)
        pi = PROCESS_INFORMATION()
        buf = ctypes.create_unicode_buffer(cmdline)
        _check(advapi32.CreateProcessAsUserW(tok, None, buf, None, None, True, 0x400, None, cwd or os.getcwd(),
                                             ctypes.byref(si), ctypes.byref(pi)), "CreateProcessAsUser")
        kernel32.CloseHandle(pi.hThread)
        kernel32.WaitForSingleObject(pi.hProcess, 0xFFFFFFFF)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        kernel32.CloseHandle(pi.hProcess)
        return ctypes.c_int32(code.value).value
    finally:
        kernel32.CloseHandle(tok)


def ensure_unelevated(allow_elevated: bool = False) -> None:
    """Called first thing at startup. If elevated: re-exec self un-elevated and exit with its code."""
    if not is_elevated() or allow_elevated:
        return
    if not IS_WINDOWS:
        sys.stderr.write("goose-web refuses to run as root; run it as the Goose user "
                         "(or set server.allow_elevated).\n")
        raise SystemExit(3)
    if os.environ.get("GOOSE_WEB_UNELEVATED") == "1":
        sys.stderr.write("goose-web: still elevated after de-elevation; refusing to run.\n")
        raise SystemExit(3)
    os.environ["GOOSE_WEB_UNELEVATED"] = "1"
    import subprocess
    if getattr(sys, "frozen", False):
        cmd = subprocess.list2cmdline([sys.executable, *sys.argv[1:]])
    else:
        cmd = subprocess.list2cmdline([sys.executable, "-m", "goose_web", *sys.argv[1:]])
    sys.stderr.write("goose-web: elevated token detected - relaunching as a normal user (Medium integrity).\n")
    try:
        rc = run_unelevated(cmd)
    except OSError as e:
        sys.stderr.write(f"goose-web: could not de-elevate ({e}); refusing to run elevated.\n")
        raise SystemExit(3)
    raise SystemExit(rc)


# ------------------------------------------------------------------------------------------------ the profile folder
_PROFILE_FOLDER: str | None = None
_PROFILE_ASKED = False

if IS_WINDOWS:  # pragma: no branch
    class _GUID(ctypes.Structure):
        _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]


def profile_folder() -> str | None:
    """The home folder of this process's account as Windows knows it (FOLDERID_Profile), or None when it cannot be
    asked (other platforms, an error). Goose finds its global skill, recipe and agent folders under it and does not
    go by the USERPROFILE variable (spec 028: measured with the Goose binary), so Goose Web asks the same way.
    Asked once per process, whatever the answer."""
    global _PROFILE_FOLDER, _PROFILE_ASKED
    if _PROFILE_ASKED or not IS_WINDOWS:
        return _PROFILE_FOLDER
    _PROFILE_ASKED = True
    try:
        shell32, ole32 = ctypes.WinDLL("shell32"), ctypes.WinDLL("ole32")
        shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE,
                                                 ctypes.POINTER(ctypes.c_void_p)]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole32.CoTaskMemFree.restype = None
        fid = _GUID(0x5E6C858F, 0x0E22, 0x4760, (ctypes.c_ubyte * 8)(0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73))
        ptr = ctypes.c_void_p()
        try:
            if shell32.SHGetKnownFolderPath(ctypes.byref(fid), 0, None, ctypes.byref(ptr)) == 0 and ptr.value:
                _PROFILE_FOLDER = ctypes.wstring_at(ptr.value) or None
        finally:
            if ptr.value:
                ole32.CoTaskMemFree(ptr)   # freed whatever the result, as the API asks
    except Exception:  # pragma: no cover - the caller falls back to the environment
        _PROFILE_FOLDER = None
    return _PROFILE_FOLDER


# ------------------------------------------------------------------------------------------------ process priority
# FIX gateway-below-normal-priority (2026-11-12). Task Scheduler starts a task at task priority 7 unless the task
# says otherwise: CPU priority class BELOW_NORMAL, low I/O priority, low memory priority. A gateway started that way
# is starved by any ordinary process that keeps the cores busy (measured on 4 cores: healthz 2 ms -> 3.5-4.9 s, the
# classification endpoint gave no answer in 12 s, so Goose fell back to its patterns). The gateway therefore puts
# itself back to normal at start. A child process gets what its parent has when it is created, so the goose workers
# follow. Only what is BELOW normal is raised; nothing is ever lowered and nothing goes above normal.
_CPU_CLASSES = {0x40: "idle", 0x4000: "below_normal", 0x20: "normal", 0x8000: "above_normal", 0x80: "high",
                0x100: "realtime"}
_CPU_BELOW_NORMAL = (0x40, 0x4000)
_IO_LEVELS = {0: "very_low", 1: "low", 2: "normal", 3: "high"}
_MEMORY_LEVELS = {1: "very_low", 2: "low", 3: "medium", 4: "below_normal", 5: "normal"}
_CPU_NORMAL, _IO_NORMAL, _MEMORY_NORMAL = 0x20, 2, 5
_PROCESS_IO_PRIORITY = 33         # NtQueryInformationProcess / NtSetInformationProcess: ProcessIoPriority
_PROCESS_MEMORY_PRIORITY = 0      # GetProcessInformation / SetProcessInformation: ProcessMemoryPriority


def _priority_raw() -> dict:
    """{'cpu': priority class, 'io': level, 'memory': level}; None = could not be read."""
    out: dict = {"cpu": None, "io": None, "memory": None}
    if not IS_WINDOWS:
        return out
    h = kernel32.GetCurrentProcess()
    try:
        out["cpu"] = int(kernel32.GetPriorityClass(h)) or None
    except Exception:  # pragma: no cover
        pass
    if not _HAVE_PRIORITY_API:  # pragma: no cover
        return out
    try:
        v = wintypes.ULONG(0)
        if ntdll.NtQueryInformationProcess(h, _PROCESS_IO_PRIORITY, ctypes.byref(v), ctypes.sizeof(v), None) == 0:
            out["io"] = int(v.value)
    except Exception:  # pragma: no cover
        pass
    try:
        v = wintypes.ULONG(0)
        if kernel32.GetProcessInformation(h, _PROCESS_MEMORY_PRIORITY, ctypes.byref(v), ctypes.sizeof(v)):
            out["memory"] = int(v.value)
    except Exception:  # pragma: no cover
        pass
    return out


def _priority_names(raw: dict) -> dict:
    return {"cpu": _CPU_CLASSES.get(raw.get("cpu"), "unknown"), "io": _IO_LEVELS.get(raw.get("io"), "unknown"),
            "memory": _MEMORY_LEVELS.get(raw.get("memory"), "unknown")}


def process_priority() -> dict:
    """This process: {'cpu': 'below_normal' | 'normal' | ..., 'io': 'low' | 'normal' | ..., 'memory': 'low' |
    'normal' | ...}; 'unknown' = could not be read (always on other platforms)."""
    return _priority_names(_priority_raw())


def ensure_normal_priority() -> dict:
    """Raise what is below normal to normal: the CPU priority class, the I/O priority and the memory priority of
    this process. Never lowers anything, never goes above normal, never raises an exception.
    -> {'before': {...}, 'after': {...}, 'changed': ['cpu', 'io', 'memory'], 'errors': ['io: ...']}"""
    raw = _priority_raw()
    changed: list[str] = []
    errors: list[str] = []
    if IS_WINDOWS:
        h = kernel32.GetCurrentProcess()
        if raw["cpu"] in _CPU_BELOW_NORMAL:
            try:
                if kernel32.SetPriorityClass(h, _CPU_NORMAL):
                    changed.append("cpu")
                else:
                    errors.append(f"cpu: SetPriorityClass failed (WinError {ctypes.get_last_error()})")
            except Exception as e:  # pragma: no cover
                errors.append(f"cpu: {e.__class__.__name__}: {e}")
        if raw["io"] is not None and raw["io"] < _IO_NORMAL:
            try:
                v = wintypes.ULONG(_IO_NORMAL)
                st = ntdll.NtSetInformationProcess(h, _PROCESS_IO_PRIORITY, ctypes.byref(v), ctypes.sizeof(v))
                if st == 0:
                    changed.append("io")
                else:
                    errors.append(f"io: NtSetInformationProcess failed (status 0x{st & 0xFFFFFFFF:08X})")
            except Exception as e:  # pragma: no cover
                errors.append(f"io: {e.__class__.__name__}: {e}")
        if raw["memory"] is not None and raw["memory"] < _MEMORY_NORMAL:
            try:
                v = wintypes.ULONG(_MEMORY_NORMAL)
                if kernel32.SetProcessInformation(h, _PROCESS_MEMORY_PRIORITY, ctypes.byref(v), ctypes.sizeof(v)):
                    changed.append("memory")
                else:
                    errors.append(f"memory: SetProcessInformation failed (WinError {ctypes.get_last_error()})")
            except Exception as e:  # pragma: no cover
                errors.append(f"memory: {e.__class__.__name__}: {e}")
    return {"before": _priority_names(raw), "after": process_priority(), "changed": changed, "errors": errors}
