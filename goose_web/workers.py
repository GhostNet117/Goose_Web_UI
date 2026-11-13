"""One goose process per profile: `goose serve` on loopback (random port + secret), or - for sandboxed workers
(sandbox.py, spec 012) - `goose acp` inside the user's AppContainer, connected over its stdin/stdout.

A worker is started lazily on first use. It is stopped after `goose.idle_minutes` without browser
clients, active runs or a scheduler duty, and restarted with backoff if it crashes. Every worker inherits
the gateway's (non-elevated) token, so every file Goose writes is owned by the gateway user.

Scheduler ownership: isolated profiles always run their own scheduler. The admin's native profile is
shared with Goose Desktop, and two schedulers would fire every job twice. In `auto` mode the native worker
therefore runs the scheduler only while Goose Desktop is NOT running, and hands it over when Desktop starts
or stops.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from typing import Any
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .config import Settings

log = logging.getLogger("goose_web.workers")
IS_WINDOWS = os.name == "nt"

# Environment variables that would let the gateway's own configuration leak into an isolated profile.
_ISOLATION_STRIP_PREFIXES = ("GOOSE_",)
_ISOLATION_KEEP = {"GOOSE_DISABLE_KEYRING", "GOOSE_TELEMETRY_ENABLED"}
# The only variables a SANDBOXED worker gets from the gateway's environment (see WorkerManager._sandbox_env).
# LOCALAPPDATA stays the account's (a path, not a secret): inside an AppContainer Windows' GetTempPath ignores TEMP
# and returns %LOCALAPPDATA%\Packages\<container>\AC\Temp, the container's own folder; goose acp panics without it.
SANDBOX_ENV_ALLOW = ("SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "PATH", "OS",
                     "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
                     "PROCESSOR_REVISION", "LOCALAPPDATA")
# Same value as profiles.GW_HINTS_FILENAME (kept here so workers.py does not import profiles).
ISOLATED_HINTS_FILENAME = ".goose-web-hints.md"


# ------------------------------------------------------------------ Windows job object + process scan
class _Job:
    """Kill-on-close job object, so workers die with the gateway even if it crashes.

    The gateway has one for all workers; every worker also gets its own (nested in the gateway's: a process joins
    the gateway job first, then the worker job). Everything a worker starts - also detached processes whose parent
    has exited, which a process-tree kill misses - is in the worker's job, and terminate() ends all of it when the
    worker is stopped, killed or its user deleted."""

    def __init__(self):
        self.handle = None
        if not IS_WINDOWS:
            return
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        h = k32.CreateJobObjectW(None, None)
        if not h:
            return

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IOC(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IOC), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = EXT()
        info.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        if k32.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.handle = h
            self._k32 = k32
        else:
            k32.CloseHandle(h)

    def add(self, proc: subprocess.Popen) -> bool:
        if self.handle and IS_WINDOWS:
            import ctypes
            if self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)):  # type: ignore[attr-defined]
                return True
            log.warning("could not put process %s in a job object (%s)", proc.pid, ctypes.get_last_error())
        return False

    def terminate(self) -> None:
        """Kill every process in the job (and in jobs nested in it)."""
        if self.handle and IS_WINDOWS:
            self._k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        """Close the handle; kill-on-close ends whatever is still in the job."""
        h, self.handle = self.handle, None
        if h and IS_WINDOWS:
            self._k32.CloseHandle(h)


def desktop_running(cli_binary: str = "") -> bool:
    """True when the Goose Desktop (Electron) app runs for this user (not merely a goose CLI)."""
    if not IS_WINDOWS:
        return False
    cli_image = os.path.abspath(cli_binary).lower() if cli_binary else ""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == wintypes.HANDLE(-1).value:
        return False
    try:
        pe = PE()
        pe.dwSize = ctypes.sizeof(PE)
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() == "goose.exe":
                h = k32.OpenProcess(0x1000, False, pe.th32ProcessID)  # PROCESS_QUERY_LIMITED_INFORMATION
                if h:
                    buf = ctypes.create_unicode_buffer(1024)
                    n = wintypes.DWORD(1024)
                    if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                        image = buf.value.lower().replace("/", "\\")
                        # Electron app = Goose.exe that is NOT a CLI binary (bundled CLI lives in resources\bin;
                        # a standalone CLI is the configured binary or any goose.exe next to which no app.asar exists)
                        is_cli = image.endswith("\\resources\\bin\\goose.exe") or \
                            (cli_image and image == cli_image) or \
                            not os.path.exists(os.path.join(os.path.dirname(image), "resources", "app.asar"))
                        if not is_cli:
                            k32.CloseHandle(h)
                            return True
                    k32.CloseHandle(h)
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    return False


WORKER_LOG_MAX_BYTES = 10 * 1024 * 1024


def open_append_log(path: Path):
    """A log file for a child process's stdout/stderr whose writes always land at the end of the file.

    On Windows the handle gets FILE_APPEND_DATA without FILE_WRITE_DATA, so the log janitor can copy and empty a
    log that goose still writes to (copytruncate, logjanitor.py) without the next write leaving a gap; it is also
    shared for delete. Elsewhere O_APPEND does the same."""
    if not IS_WINDOWS:
        return open(path, "ab", buffering=0)
    import _winapi
    import msvcrt
    FILE_APPEND_DATA, SYNCHRONIZE, READ_ATTRS = 0x0004, 0x00100000, 0x0080
    SHARE_ALL, OPEN_ALWAYS = 0x1 | 0x2 | 0x4, 4
    h = _winapi.CreateFile(str(path), FILE_APPEND_DATA | SYNCHRONIZE | READ_ATTRS, SHARE_ALL, _winapi.NULL,
                           OPEN_ALWAYS, 0x80, _winapi.NULL)
    fd = msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_APPEND)
    return os.fdopen(fd, "ab", buffering=0)
WORKER_LOG_BACKUPS = 3


def rotate_log(path: Path, max_bytes: int = WORKER_LOG_MAX_BYTES, backups: int = WORKER_LOG_BACKUPS) -> bool:
    """Rotate `path` to .1 (and .1 -> .2 ... up to `backups` copies) when it is larger than `max_bytes`.

    Called before a worker starts (GW-23); goose writes its stdout/stderr straight into the file, so the
    gateway cannot use a RotatingFileHandler. Returns True if the file was rotated. Failures (for example a
    file still held open by a lingering process on Windows) are logged and the old file keeps growing.
    """
    try:
        if not path.is_file() or path.stat().st_size <= max_bytes:
            return False
        oldest = path.with_name(f"{path.name}.{backups}")
        if oldest.exists():
            oldest.unlink()
        for i in range(backups - 1, 0, -1):
            src = path.with_name(f"{path.name}.{i}")
            if src.exists():
                os.replace(src, path.with_name(f"{path.name}.{i + 1}"))
        os.replace(path, path.with_name(f"{path.name}.1"))
        return True
    except OSError as e:
        log.warning("could not rotate %s: %s", path, e)
        return False


def _log_tail_after(path: Path, marker: str, max_bytes: int = 32768) -> str:
    """What a process wrote into its worker log after `marker` (the start line), from the last `max_bytes`."""
    try:
        with open(path, "rb") as f:
            f.seek(max(0, path.stat().st_size - max_bytes))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return ""
    i = text.rfind(marker)
    return text[i + len(marker):] if i >= 0 else text[-4000:]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def schedule_count(path_root: str | None) -> int:
    """Jobs in <data>/schedule.json (read-only peek; 0 if absent)."""
    from .config import default_native_goose_root
    root = Path(path_root or default_native_goose_root())
    p = root / "data" / "schedule.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        jobs = data.get("jobs", data)
        return len(jobs) if isinstance(jobs, (list, dict)) else 0
    return 0


# ------------------------------------------------------------------ worker
@dataclass
class Worker:
    key: str
    username: str
    path_root: str | None            # None = Goose's default profile location
    native: bool
    recipe_dirs: list[str] = field(default_factory=list)
    proc: subprocess.Popen | None = None
    port: int = 0
    secret: str = ""
    state: str = "stopped"           # stopped | starting | ready | crashed
    started_at: float = 0
    last_used: float = field(default_factory=time.time)
    scheduler: bool = False
    restarts: int = 0
    last_error: str = ""
    restart_pending: bool = False
    sandbox: dict | None = None      # {name, profile_root, grants, caps} -> AppContainer + stdio transport
    sandbox_sid: str = ""
    channel: Any = None              # sandbox.StdioChannel of the running stdio worker
    relay_procs: list = field(default_factory=list)     # forwarders inside the container (relay.py)
    relay_servers: list = field(default_factory=list)   # gateway-side pipe servers
    job: Any = None                  # the worker's own kill-on-close job object (_Job), Windows
    backend: str = ""                # sandbox backend the running worker uses: mxc | appcontainer (spec 025)
    policy_file: str = ""            # MXC: the policy wxc-exec was started with (<system_dir>/sandbox/mxc)
    proxy_port: int = 0              # MXC: the member's egress proxy (egress.py)
    # Spec 026: Goose's own security settings (SECURITY_PROMPT_*) for an isolated worker, set by the app's pre_start
    # hook. Applied last: Goose ranks the environment above config.yaml and the secret store, so a member or an
    # agent editing the profile cannot switch the detection off. Never set for the native profile.
    security_env: dict = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def transport(self) -> str:
        return "stdio" if self.sandbox else "websocket"

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/acp"

    def describe(self) -> dict:
        return {"key": self.key, "username": self.username, "pid": self.proc.pid if self.proc else None,
                "port": self.port, "state": self.state, "startedAt": self.started_at, "scheduler": self.scheduler,
                "restarts": self.restarts, "lastError": self.last_error, "native": self.native,
                "pathRoot": self.path_root, "restartPending": self.restart_pending, "transport": self.transport,
                "sandboxed": bool(self.sandbox), "sandboxSid": self.sandbox_sid,
                "sandboxBackend": (self.backend or (self.sandbox or {}).get("backend") or "") if self.sandbox else "",
                "proxyPort": self.proxy_port if self.backend == "mxc" else 0}


class SandboxUnavailable(RuntimeError):
    """A sandboxed worker was not started (fail closed). str() is what the member sees; admin_reason is the detail
    for administrators (worker lastError in Admin > System, gateway.log)."""

    def __init__(self, member_message: str, admin_reason: str):
        super().__init__(member_message)
        self.admin_reason = admin_reason


class WorkerManager:
    def __init__(self, settings: Settings):
        self.s = settings
        self.workers: dict[str, Worker] = {}
        self.job = _Job()
        self.log_dir = settings.system_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._desktop = False
        self._desktop_checked = float("-inf")   # monotonic time of the last check
        self.on_restart = None       # async callback(worker) set by the hub
        self.activity = None         # callable(key) -> (clients, active_runs) set by the hub
        # callable(worker) set by the app: runs before EVERY start of a worker (security review 2026-11-11, SA-1:
        # re-provisions an isolated profile so nothing the agent wrote into its own config survives a restart)
        self.pre_start = None
        # callable(action, worker, detail) set by the app: sandbox fallbacks / refusals into the audit log (spec 025)
        self.on_sandbox_event = None
        from .egress import ProxyRegistry
        self.proxies = ProxyRegistry(settings)   # MXC members' egress proxies (spec 025 R6)
        self._links_checked: dict[str, tuple] = {}   # MX-3: read/write folder sets scanned for outside hard links
        # MXC policy files of a gateway that ended without stopping its workers (they died with its job object)
        for f in (settings.system_dir / "sandbox" / "mxc").glob("*.json") \
                if (settings.system_dir / "sandbox" / "mxc").is_dir() else []:
            try:
                f.unlink()
            except OSError:
                pass
        self._monitor_task: asyncio.Task | None = None

    # ---------------------------------------------------------- scheduler ownership
    def desktop_running(self, max_age: float = 20.0) -> bool:
        # max_age <= 0 always re-checks: on Windows before Python 3.13 the clock has ~15.6 ms resolution,
        # so two calls in the same tick would otherwise see an age of 0 and reuse the cached answer
        if max_age <= 0 or time.monotonic() - self._desktop_checked > max_age:
            try:
                self._desktop = desktop_running(self.s.goose_binary)
            except Exception:  # pragma: no cover
                # Fail SAFE: if detection breaks, assume Desktop is running so its scheduler is never doubled.
                log.exception("Goose Desktop detection failed; assuming it is running")
                self._desktop = True
            self._desktop_checked = time.monotonic()
        return self._desktop

    def wants_scheduler(self, w: Worker) -> tuple[bool, str]:
        if not w.native:
            return True, "this profile's own scheduler"
        mode = str(self.s.get("goose", "native_scheduler") or "auto").lower()
        if mode == "on":
            return True, "native_scheduler=on"
        if mode == "off":
            return False, "native_scheduler=off (schedules run in Goose Desktop or not at all)"
        if self.desktop_running():
            return False, "Goose Desktop is running on this profile and owns its scheduler"
        return True, "Goose Desktop is not running, so the gateway runs this profile's scheduler"

    # ---------------------------------------------------------- lifecycle
    def get(self, key: str) -> Worker | None:
        return self.workers.get(key)

    def register(self, key: str, username: str, path_root: str | None, native: bool,
                 recipe_dirs: list[str], sandbox: dict | None = None) -> Worker:
        w = self.workers.get(key)
        if w is None:
            w = Worker(key=key, username=username, path_root=path_root, native=native, recipe_dirs=recipe_dirs,
                       sandbox=sandbox)
            self.workers[key] = w
        else:
            if (w.path_root, w.recipe_dirs, w.sandbox) != (path_root, recipe_dirs, sandbox) and w.state == "ready":
                w.restart_pending = True
            w.path_root, w.native, w.recipe_dirs, w.sandbox = path_root, native, recipe_dirs, sandbox
        return w

    def _sandbox_env(self, w: Worker, backend: str | None = None) -> dict:
        """Environment of a sandboxed worker (C-2): built from an allow-list, never from the gateway's environment
        as a whole, which holds the gateway account's secrets (API keys in user variables and the like).

        Kept from the gateway: SANDBOX_ENV_ALLOW (system locations, processor facts, LOCALAPPDATA - see there) and
        the non-secret GOOSE_TELEMETRY_ENABLED switch. Set by the gateway: GOOSE_PATH_ROOT, GOOSE_DISABLE_KEYRING,
        GOOSE_RECIPE_PATH, CONTEXT_FILE_NAMES, and the home (USERPROFILE, HOME, APPDATA), temp and cache folders,
        all inside the user's profile.
        Then goose.extra_env (admin-controlled) on top."""
        env: dict[str, str] = {}
        for k in SANDBOX_ENV_ALLOW:
            v = os.environ.get(k)
            if v is not None:
                env[k] = v
        for k in _ISOLATION_KEEP - {"GOOSE_DISABLE_KEYRING"}:
            if os.environ.get(k) is not None:
                env[k] = os.environ[k]
        root = (w.sandbox or {})["profile_root"]
        env["GOOSE_DISABLE_KEYRING"] = "1"   # secrets stay in the profile's own secrets.yaml
        env["GOOSE_RECIPE_PATH"] = os.pathsep.join(w.recipe_dirs)
        env["GOOSE_PATH_ROOT"] = w.path_root or root
        for k, v in (self.s.get("goose", "extra_env") or {}).items():
            env[str(k)] = str(v)
        env["CONTEXT_FILE_NAMES"] = json.dumps([ISOLATED_HINTS_FILENAME])
        for k, v in (w.security_env or {}).items():   # spec 026: beats config.yaml, secrets.yaml and extra_env
            env[str(k)] = str(v)
        # `backend` = the backend of THIS start. w.backend still holds the previous start's backend until the new
        # worker is up, so a start that knows its backend passes it (second review 2026-11-12, R-2: an MXC start after
        # an AppContainer fallback was given the forwarder's address, which no MXC worker can reach).
        if (backend or w.backend) == "appcontainer":
            # An AppContainer (the configured backend or the fallback, decided at this start: review E-6) reaches
            # the classification endpoint at its relay forwarder's address, not at the gateway's.
            ep_key = "SECURITY_PROMPT_CLASSIFIER_ENDPOINT"
            ep = env.pop(ep_key, None)
            for r in (w.sandbox or {}).get("relays") or []:
                if ep and f"//{r.get('target')}/" in ep:
                    env[ep_key] = ep.replace(f"//{r['target']}/", f"//{r['listen']}/", 1)
                    break
        # The container cannot reach the account's home, TEMP or caches: keep them in the profile (granted Modify).
        for k, sub in (("TEMP", "tmp"), ("TMP", "tmp"), ("UV_CACHE_DIR", "cache/uv"), ("PIP_CACHE_DIR", "cache/pip"),
                       ("npm_config_cache", "cache/npm"), ("XDG_CACHE_HOME", "cache"),
                       ("APPDATA", "appdata/Roaming"), ("USERPROFILE", ""), ("HOME", "")):
            d = os.path.join(root, *[s for s in sub.split("/") if s])
            os.makedirs(d, exist_ok=True)
            env[k] = d
        return env

    def _env(self, w: Worker) -> dict:
        if w.sandbox:
            return self._sandbox_env(w)
        env = dict(os.environ)
        env.pop("GOOSE_WEB_UNELEVATED", None)
        if not w.native:
            for k in list(env):
                if k.startswith(_ISOLATION_STRIP_PREFIXES) and k not in _ISOLATION_KEEP:
                    env.pop(k)
            env["GOOSE_DISABLE_KEYRING"] = "1"   # secrets stay in the profile's own secrets.yaml
            # Only the team's recipe folders, not the administrator's own GOOSE_RECIPE_PATH. This does NOT keep Goose
            # away from the home-folder recipe, skill and agent folders (~/.agents/recipes and the like): Goose finds
            # those through the operating system's home folder whatever this variable says (profiles.HOME_*_DIRS).
            # Only the sandbox keeps a member's agent out of them; this worker has none (spec 028).
            env["GOOSE_RECIPE_PATH"] = os.pathsep.join(w.recipe_dirs)
        if w.path_root:
            env["GOOSE_PATH_ROOT"] = w.path_root
        else:
            env.pop("GOOSE_PATH_ROOT", None)
        for k, v in (self.s.get("goose", "extra_env") or {}).items():
            env[str(k)] = str(v)
        if not w.native:
            # Spec 009: Goose loads only the gateway-written hints file (config/.goose-web-hints.md), never an
            # AGENTS.md / .goosehints in a working folder. The env var beats config.yaml and extra_env.
            env["CONTEXT_FILE_NAMES"] = json.dumps([ISOLATED_HINTS_FILENAME])
            for k, v in (w.security_env or {}).items():   # spec 026: beats config.yaml, secrets.yaml and extra_env
                env[str(k)] = str(v)
        env["GOOSE_SERVER__SECRET_KEY"] = w.secret
        return env

    async def ensure(self, key: str) -> Worker:
        w = self.workers[key]
        w.last_used = time.time()
        if w.state == "ready" and w.proc and w.proc.poll() is None:
            return w
        async with w._lock:
            if w.state == "ready" and w.proc and w.proc.poll() is None:
                return w
            if self.pre_start is not None:
                try:
                    await asyncio.to_thread(self.pre_start, w)
                except Exception as e:
                    # never start a worker whose configuration could not be reset (fail closed)
                    w.state, w.last_error = "crashed", f"preparing the profile failed: {e.__class__.__name__}: {e}"
                    log.exception("worker %s: pre-start provisioning failed", w.key)
                    raise RuntimeError(w.last_error) from e
            await self._start(w)
        return w

    async def _start(self, w: Worker) -> None:
        if w.sandbox:
            return await self._start_sandboxed(w)
        w.backend = ""
        await self.proxies.drop(w.key)
        if w.path_root and not w.native and IS_WINDOWS:
            # Sandboxed before (sandbox switched off since)? Point relayed provider URLs back at the real services.
            from . import relay as rl
            from . import sandbox as sb
            try:
                for name in (sb.container_name(str(self.s.profiles_root), w.username),
                             sb.legacy_container_name(str(self.s.profiles_root), w.username)):
                    if rl.undo_relays(str(self.s.system_dir / "sandbox"), name, w.path_root):
                        log.info("worker %s: restored relayed URLs (no longer sandboxed)", w.key)
            except Exception as e:
                log.warning("worker %s: could not restore relayed URLs: %s", w.key, e)
        binary = self.s.goose_binary
        w.port = _free_port()
        w.secret = secrets.token_urlsafe(32)
        w.scheduler, _ = self.wants_scheduler(w)
        args = [binary, "serve", "--host", "127.0.0.1", "--port", str(w.port), "--platform", "desktop"]
        if w.scheduler:
            args.append("--enable-scheduler")
        rotate_log(self.log_dir / f"worker-{w.key}.log")
        logf = open_append_log(self.log_dir / f"worker-{w.key}.log")
        logf.write(f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start {' '.join(args[1:])} "
                   f"root={w.path_root or '(default)'}\n".encode())
        flags = 0
        if IS_WINDOWS:
            flags = 0x08000000 | 0x00000200  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        w.state = "starting"
        cwd = w.path_root or os.path.expanduser("~")
        if not os.path.isdir(cwd):
            cwd = os.path.expanduser("~")
        try:
            w.proc = subprocess.Popen(args, env=self._env(w), stdin=subprocess.DEVNULL, stdout=logf,
                                      stderr=subprocess.STDOUT, cwd=cwd, creationflags=flags,
                                      start_new_session=not IS_WINDOWS)
        except OSError as e:
            w.state, w.last_error = "crashed", f"cannot start goose: {e}"
            logf.close()
            raise RuntimeError(w.last_error) from e
        logf.close()
        self.job.add(w.proc)
        self._close_job(w)
        w.job = _Job()       # nested in the gateway's job (joined second): stop() ends everything goose started
        w.job.add(w.proc)
        deadline = time.time() + float(self.s.get("goose", "start_timeout_seconds") or 45)
        async with httpx.AsyncClient(timeout=1.5) as client:
            while time.time() < deadline:
                if w.proc.poll() is not None:
                    w.state = "crashed"
                    w.last_error = f"goose serve exited with code {w.proc.returncode} (see worker-{w.key}.log)"
                    raise RuntimeError(w.last_error)
                try:
                    r = await client.get(f"http://127.0.0.1:{w.port}/status")
                    if r.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.25)
            else:
                # in a thread (review 2026-11-12, B-4): taskkill and the wait take up to 25 s and used to run on the
                # event loop, freezing every user's chat when one worker's start timed out
                await asyncio.to_thread(self._kill, w)
                w.state, w.last_error = "crashed", "goose serve did not become ready in time"
                raise RuntimeError(w.last_error)
        w.state, w.started_at, w.restart_pending, w.last_error = "ready", time.time(), False, ""
        log.info("worker %s ready on port %s (pid %s, scheduler=%s)", w.key, w.port, w.proc.pid, w.scheduler)

    def _sandbox_event(self, action: str, w: Worker, detail: dict) -> None:
        if self.on_sandbox_event is not None:
            try:
                self.on_sandbox_event(action, w, detail)
            except Exception:
                log.exception("sandbox event %s", action)

    def _fail_closed(self, w: Worker, reason: str) -> None:
        """Spec 025 R3: the worker is not started; never run a member's agent unsandboxed."""
        from .activity import clean_text
        from .mxc import SANDBOX_UNAVAILABLE_MSG
        reason = clean_text(reason, 1200)      # MX-5: may carry container output or member file names
        if w.last_error != reason:
            self._sandbox_event("sandbox.unavailable", w, {"reason": reason[:300]})
        w.state, w.last_error, w.backend = "crashed", reason, ""
        log.error("worker %s: not started (fail closed): %s", w.key, reason)
        raise SandboxUnavailable(SANDBOX_UNAVAILABLE_MSG, reason)

    async def _start_sandboxed(self, w: Worker) -> None:
        """Spec 025: the member's sandbox backend - MXC (default) or the AppContainer of spec 012. MXC unavailable
        -> fail closed, or the AppContainer backend with `sandbox.fallback: appcontainer`."""
        from .config import sandbox_fallback
        spec = w.sandbox or {}
        problems = spec.get("config_problems") or []
        backend = spec.get("backend") or "appcontainer"
        if problems or backend not in ("mxc", "appcontainer"):
            self._fail_closed(w, "sandbox configuration: " + "; ".join(problems or [f"backend {backend!r}"]))
        if backend == "mxc":
            from . import mxc
            st = await asyncio.to_thread(mxc.availability, self.s)
            if st["available"]:
                return await self._start_mxc(w)
            if sandbox_fallback(self.s) != "appcontainer":
                self._fail_closed(w, f"sandbox unavailable (MXC): {st['reason']}")
            log.error("sandbox mxc: worker %s starts in the AppContainer backend instead (sandbox.fallback): %s",
                      w.key, st["reason"])
            self._sandbox_event("sandbox.fallback", w, {"from": "mxc", "to": "appcontainer",
                                                        "reason": st["reason"][:300]})
        await self.proxies.drop(w.key)
        await self._start_appcontainer(w)

    async def _start_appcontainer(self, w: Worker) -> None:
        """`goose acp` inside the user's AppContainer; the hub talks to it over stdin/stdout (spec 012)."""
        from . import sandbox as sb
        w.state = "starting"
        w.backend = "appcontainer"
        self._links_checked.pop(w.key, None)   # MX-3: the agent can make hard links here; rescan before MXC again
        w.scheduler, _ = self.wants_scheduler(w)
        spec = w.sandbox or {}
        try:
            if not sb.IS_WINDOWS:
                raise sb.SandboxError("sandbox.enabled is on, but the sandbox needs Windows; this worker is not "
                                      "started (fail closed). Turn sandbox.enabled off on this system.")
            state_dir = str(self.s.system_dir / "sandbox")
            # 1.11 named containers so that two users could share one (C-5): drop this user's old one first
            await asyncio.to_thread(sb.migrate_legacy, state_dir, str(self.s.profiles_root), w.username)
            state = await asyncio.to_thread(sb.prepare, spec["name"], state_dir, spec["grants"])
        except Exception as e:
            w.state, w.last_error = "crashed", f"sandbox: {e}"
            raise RuntimeError(w.last_error) from e
        w.sandbox_sid = state["sid"]
        args = [self.s.goose_binary, "acp"]
        if w.scheduler:
            args.append("--enable-scheduler")
        rotate_log(self.log_dir / f"worker-{w.key}.log")
        logf = open_append_log(self.log_dir / f"worker-{w.key}.log")
        logf.write(f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start {' '.join(args[1:])} (sandbox {spec['name']}, "
                   f"{state['sid']}) root={w.path_root}\n".encode())
        cwd = os.path.join(spec["profile_root"], "workspace")
        if not os.path.isdir(cwd):
            cwd = spec["profile_root"]
        self._close_job(w)
        w.job = _Job()       # the worker's own job (goose, its children, the relay forwarders), nested in self.job
        # Relays first, so goose reads the rewritten provider URLs when it starts.
        try:
            await asyncio.to_thread(self._start_relays, w, state["sid"])
        except Exception as e:   # the worker still runs; only the relayed services are unavailable
            self._stop_relays(w)
            log.warning("worker %s: relays not started: %s", w.key, e)
        try:
            w.proc = sb.spawn(args, self._env(w), cwd, state["sid"], spec.get("caps") or [], logf,
                              job=[self.job, w.job])
        except Exception as e:
            self._stop_relays(w)
            self._close_job(w)
            w.state, w.last_error = "crashed", f"cannot start goose in the sandbox: {e}"
            raise RuntimeError(w.last_error) from e
        finally:
            logf.close()
        w.channel = sb.StdioChannel(w.proc, asyncio.get_running_loop())
        await asyncio.sleep(0.3)
        if w.proc.poll() is not None:
            self._stop_relays(w)
            self._close_job(w)
            w.state = "crashed"
            w.last_error = f"goose acp exited with code {w.proc.returncode} (see worker-{w.key}.log)"
            raise RuntimeError(w.last_error)
        w.port, w.secret = 0, ""
        w.state, w.started_at, w.restart_pending, w.last_error = "ready", time.time(), False, ""
        log.info("worker %s ready in sandbox %s (pid %s, scheduler=%s)", w.key, spec["name"], w.proc.pid, w.scheduler)

    async def _start_mxc(self, w: Worker) -> None:
        """Spec 025: `goose acp` inside an MXC process container (wxc-exec + a policy built from the member's sandbox
        spec), over stdin/stdout like the AppContainer worker; network only through the member's egress proxy."""
        from . import mxc
        from . import relay as rl
        from . import sandbox as sb
        spec = w.sandbox or {}
        w.state = "starting"
        w.scheduler, _ = self.wants_scheduler(w)
        state_dir = self.s.system_dir / "sandbox"
        # R7: an MXC member reaches relayed services at their real address through the proxy: undo the AppContainer
        # backend's provider-URL rewrite (its grants and profile stay in place for a switch back)
        try:
            for name in (spec["name"], sb.legacy_container_name(str(self.s.profiles_root), w.username)):
                if await asyncio.to_thread(rl.undo_relays, str(state_dir), name, spec["profile_root"]):
                    log.info("worker %s: restored relayed URLs (MXC reaches them through the egress proxy)", w.key)
        except Exception as e:
            log.warning("worker %s: could not restore relayed URLs: %s", w.key, e)
        grants, refused = mxc.filter_grants(
            spec.get("mxc_grants") or {}, profile_root=spec["profile_root"], profiles_root=spec["profiles_root"],
            system_dir=spec["system_dir"], protected_write=spec.get("protected_write") or [],
            protected_any=spec.get("protected_any") or [])
        for p, why in refused:
            log.warning("sandbox mxc: %s: grant %s refused: %s", w.username, p, why)
        # MX-3: MXC grants are path-based - a file in a read/write folder hard-linked to a file outside them would
        # give the agent that file. Scanned once per set of read/write folders (again after any AppContainer run).
        rw = sorted(p for p, m in grants.items() if m == "modify")
        if self._links_checked.get(w.key) != tuple(rw):
            found, complete, seen = await asyncio.to_thread(mxc.hardlink_escapes, rw)
            if found:
                from .activity import clean_text
                sample = "; ".join(f"{clean_text(a, 200)} = {clean_text(b, 200)}" for a, b in found[:3])
                self._fail_closed(w, f"MXC sandbox not started: {len(found)}{'+' if len(found) >= 20 else ''} file(s) "
                                     "in the member's folders are hard links to files outside them, which the MXC "
                                     f"container could read and write ({sample}). Remove those links (fsutil hardlink "
                                     "list <file> shows every name of a file), then start again.")
            if complete:
                self._links_checked[w.key] = tuple(rw)
            else:
                log.warning("sandbox mxc: %s: hard-link scan of the member's folders stopped after %s entries / %.0f s;"
                            " starting anyway (scanned again at the next start)", w.username, seen,
                            mxc.HARDLINK_SCAN_SECONDS)
        network = spec.get("network") or "internet"
        targets = list(spec.get("relay_targets") or [])
        proxy_url = ""
        if network != "none" or targets:
            try:
                proxy = await self.proxies.ensure(w.key, w.username, network, targets)
            except Exception as e:
                self._fail_closed(w, f"sandbox unavailable (MXC): the egress proxy could not start: {e}")
            proxy_url, w.proxy_port = proxy.url(), proxy.port
        else:
            await self.proxies.drop(w.key)
            w.proxy_port = 0
        args = [self.s.goose_binary, "acp"]
        if w.scheduler:
            args.append("--enable-scheduler")
        cwd = os.path.join(spec["profile_root"], "workspace")
        if not os.path.isdir(cwd):
            cwd = spec["profile_root"]
        policy = mxc.build_policy(command=args, cwd=cwd, env=self._sandbox_env(w, "mxc"), grants=grants, proxy_url=proxy_url,
                                  system_drive=os.environ.get("SystemDrive", "C:"))
        pfile = state_dir / "mxc" / f"{spec['name']}.json"
        await asyncio.to_thread(mxc.write_policy, pfile, policy)
        logp = self.log_dir / f"worker-{w.key}.log"
        rotate_log(logp)
        logf = open_append_log(logp)
        marker = (f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start {' '.join(args[1:])} (sandbox mxc {spec['name']}, "
                  f"wxc-exec {mxc.MXC_PIN['version']}, network {network}, proxy "
                  f"{'127.0.0.1:' + str(w.proxy_port) if proxy_url else 'none'}, {len(policy['filesystem']['readwritePaths'])} "
                  f"read/write + {len(policy['filesystem']['readonlyPaths'])} read-only folders) root={w.path_root}\n")
        logf.write(marker.encode())
        self._close_job(w)
        w.job = _Job()       # the worker's own job (wxc-exec and the container's processes), nested in self.job
        try:
            w.proc = await asyncio.to_thread(mxc.launch, mxc.exe_path(self.s), pfile, logf, [self.job, w.job])
        except Exception as e:
            self._close_job(w)
            self._fail_closed(w, f"sandbox unavailable (MXC): {e}")
        finally:
            logf.close()
        w.channel = sb.StdioChannel(w.proc, asyncio.get_running_loop())
        w.backend, w.policy_file, w.sandbox_sid = "mxc", str(pfile), ""
        await asyncio.sleep(0.3)
        if w.proc.poll() is not None:
            reason = mxc.explain_exit(w.proc.returncode, _log_tail_after(logp, marker.strip()))
            self._close_job(w)
            w.proc, w.channel = None, None
            self._fail_closed(w, f"MXC sandbox did not start: {reason} (see worker-{w.key}.log)")
        w.port, w.secret = 0, ""
        w.state, w.started_at, w.restart_pending, w.last_error = "ready", time.time(), False, ""
        log.info("worker %s ready in MXC sandbox %s (pid %s, proxy %s, scheduler=%s)", w.key, spec["name"], w.proc.pid,
                 w.proxy_port or "none", w.scheduler)

    async def _back_to_mxc(self, w: Worker) -> bool:
        """A worker that started on the AppContainer fallback is marked for a restart (when no run is active) once
        MXC is available again. True when it was marked."""
        if not (w.state == "ready" and w.sandbox and w.sandbox.get("backend") == "mxc"
                and w.backend == "appcontainer" and not w.restart_pending):
            return False
        from . import mxc
        if not (await asyncio.to_thread(mxc.availability, self.s))["available"]:
            return False
        log.info("worker %s: MXC is available again; moves from the AppContainer fallback when idle", w.key)
        w.restart_pending = True
        return True

    def _start_relays(self, w: Worker, sid: str) -> None:
        """Spec 014: pipe server (gateway) + forwarder (inside the container) per allow-listed local service, and
        the user's provider URLs pointed at the forwarder. Targets removed from the config are restored."""
        from . import relay as rl
        from . import sandbox as sb
        spec = w.sandbox or {}
        root = spec["profile_root"]
        state_file = self.s.system_dir / "sandbox" / f"{spec['name']}.relays.json"
        try:
            old = json.loads(state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            old = {}
        new = {r["target"]: r["listen"] for r in spec.get("relays") or []}
        gone = {t: lst for t, lst in old.items() if new.get(t) != lst}
        if gone:
            rl.restore_profile_urls(root, gone)
        if not new:
            state_file.unlink(missing_ok=True)
            return
        py, _ = rl.python_for_container()
        fwd = rl.write_forwarder(root)
        logf = open_append_log(self.log_dir / f"worker-{w.key}.log")
        try:
            for r in spec["relays"]:
                # C-1: a new random name per start; the server owns it (first instance) or the relay fails closed,
                # and the forwarder accepts only a pipe served by this process (the gateway's pid is passed on).
                pipe = rl.new_pipe_name()
                w.relay_servers.append(rl.PipeRelayServer(pipe, sid, r["target"]).start())
                p = sb.spawn([py, "-I", fwd, r["listen"], pipe, str(os.getpid())], self._env(w), root, sid, [], logf,
                             job=[self.job, w.job])
                w.relay_procs.append(p)
                line = p.stdout.readline().decode("utf-8", "replace").strip()
                if line != "listening":
                    raise RuntimeError(f"forwarder for {r['target']} did not start (see worker-{w.key}.log)")
        finally:
            logf.close()
        changed = rl.rewrite_profile_urls(root, new)
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(new), encoding="utf-8")
        log.info("worker %s: relays %s (rewrote %d file(s))", w.key, new, len(changed))

    def _stop_relays(self, w: Worker) -> None:
        for p in w.relay_procs:
            try:
                p.kill()
            except Exception:
                pass
        for s in w.relay_servers:
            try:
                s.stop()
            except Exception:
                pass
        w.relay_procs, w.relay_servers = [], []

    @staticmethod
    def _close_job(w: Worker) -> None:
        """End every process in the worker's own job (C-7: also detached grandchildren) and drop the job."""
        j, w.job = w.job, None
        if j is not None:
            try:
                j.terminate()
            finally:
                j.close()

    def _kill(self, w: Worker) -> None:
        self.proxies.revoke(w.key)     # MX-10: the stopped container's proxy credential stops working now
        p = w.proc
        if w.backend == "mxc" and p and p.poll() is None:
            # spec 025: end of input first - goose acp exits cleanly (sessions flushed) and MXC removes the container
            try:
                p.stdin.close()
                p.wait(timeout=3)
            except Exception:
                pass
        if w.policy_file:
            try:
                Path(w.policy_file).unlink(missing_ok=True)
            except OSError:
                pass
            w.policy_file = ""
        self._stop_relays(w)
        self._close_job(w)
        p = w.proc
        if p and p.poll() is None:
            try:
                if IS_WINDOWS:
                    # goose serve's children (MCP servers) live in the same job/process tree. By full path, like
                    # icacls and powershell.exe (C-5; R-12): a bare name is looked up in the current directory first.
                    taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
                    subprocess.run([taskkill, "/PID", str(p.pid), "/T", "/F"], capture_output=True,
                                   creationflags=0x08000000, timeout=15)
                else:
                    # start_new_session=True made goose the leader of its own process group: stop MCP children too
                    import signal
                    try:
                        os.killpg(p.pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        p.terminate()
                p.wait(timeout=10)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        w.proc = None
        w.channel = None

    async def stop(self, key: str, reason: str = "") -> None:
        w = self.workers.get(key)
        if not w:
            return
        async with w._lock:
            await asyncio.to_thread(self._kill, w)
            w.state = "stopped"
        log.info("worker %s stopped %s", key, reason)

    async def restart(self, key: str) -> Worker:
        await self.stop(key, "(restart)")
        w = await self.ensure(key)
        if self.on_restart:
            await self.on_restart(w)
        return w

    async def shutdown(self) -> None:
        if self._monitor_task:
            self._monitor_task.cancel()
        for k in list(self.workers):
            await self.stop(k, "(shutdown)")
        await self.proxies.close_all()

    # ---------------------------------------------------------- monitor
    def start_monitor(self) -> None:
        self._monitor_task = asyncio.create_task(self._monitor())

    async def _monitor(self) -> None:
        backoff: dict[str, float] = {}
        while True:
            await asyncio.sleep(15)
            try:
                idle = float(self.s.get("goose", "idle_minutes") or 30) * 60
                for w in list(self.workers.values()):
                    clients, runs = self.activity(w.key) if self.activity else (0, 0)
                    if clients or runs:
                        w.last_used = time.time()
                    has_sched = schedule_count(w.path_root) > 0
                    want_sched, _ = self.wants_scheduler(w)
                    # crashed while it was needed -> restart with backoff
                    if w.state == "ready" and w.proc and w.proc.poll() is not None:
                        w.state = "crashed"
                        self.proxies.revoke(w.key)      # MX-10: nothing may use the dead container's credential
                        w.last_error = f"goose serve exited with code {w.proc.returncode}"
                        log.warning("worker %s crashed: %s", w.key, w.last_error)
                    if w.state == "crashed" and (clients or (has_sched and want_sched)):
                        if time.time() >= backoff.get(w.key, 0):
                            w.restarts += 1
                            backoff[w.key] = time.time() + min(300, 2 ** min(w.restarts, 8))
                            try:
                                await self.restart(w.key)
                            except Exception as e:
                                w.last_error = getattr(e, "admin_reason", "") or str(e)
                        continue
                    if w.state != "ready":
                        # a stopped profile that has schedules (and owns its scheduler) must be running
                        if has_sched and want_sched and w.state == "stopped":
                            try:
                                await self.ensure(w.key)
                                if self.on_restart:
                                    await self.on_restart(w)
                            except Exception as e:
                                w.last_error = getattr(e, "admin_reason", "") or str(e)
                        continue
                    # spec 025: started on the AppContainer fallback while MXC was unavailable -> back to MXC when
                    # it is available again (restarted below like any pending change: never during a run)
                    await self._back_to_mxc(w)
                    # scheduler hand-over (Desktop started/stopped) or pending config -> restart when quiet
                    if (w.scheduler != want_sched or w.restart_pending) and not runs:
                        log.info("worker %s restarting (scheduler %s -> %s, pending=%s)", w.key, w.scheduler,
                                 want_sched, w.restart_pending)
                        await self.restart(w.key)
                        continue
                    if not clients and not runs and not (has_sched and w.scheduler) and \
                            time.time() - w.last_used > idle:
                        await self.stop(w.key, "(idle)")
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - the monitor must never die
                log.exception("worker monitor error")


def goose_version(binary: str) -> str:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=20,
                             creationflags=0x08000000 if IS_WINDOWS else 0)
        return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else ""
    except Exception:
        return ""


if sys.platform == "win32":  # pragma: no cover
    pass
