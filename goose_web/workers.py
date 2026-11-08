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
# Same value as profiles.GW_HINTS_FILENAME (kept here so workers.py does not import profiles).
ISOLATED_HINTS_FILENAME = ".goose-web-hints.md"


# ------------------------------------------------------------------ Windows job object + process scan
class _Job:
    """Kill-on-close job object, so workers die with the gateway even if it crashes."""

    def __init__(self):
        self.handle = None
        if not IS_WINDOWS:
            return
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
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

    def add(self, proc: subprocess.Popen) -> None:
        if self.handle and IS_WINDOWS:
            from ctypes import wintypes
            self._k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self._k32.AssignProcessToJobObject(self.handle, int(proc._handle))  # type: ignore[attr-defined]


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
                "sandboxed": bool(self.sandbox), "sandboxSid": self.sandbox_sid}


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

    def _env(self, w: Worker) -> dict:
        env = dict(os.environ)
        env.pop("GOOSE_WEB_UNELEVATED", None)
        if not w.native:
            for k in list(env):
                if k.startswith(_ISOLATION_STRIP_PREFIXES) and k not in _ISOLATION_KEEP:
                    env.pop(k)
            env["GOOSE_DISABLE_KEYRING"] = "1"   # secrets stay in the profile's own secrets.yaml
            env["GOOSE_RECIPE_PATH"] = os.pathsep.join(w.recipe_dirs)
            # machine-wide ~/.agents/recipes would otherwise leak the admin's recipes
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
        if w.sandbox:
            # The container cannot reach the account's TEMP or caches: keep them in the profile (granted Modify).
            root = w.sandbox["profile_root"]
            for k, sub in (("TEMP", "tmp"), ("TMP", "tmp"), ("UV_CACHE_DIR", "cache/uv"), ("PIP_CACHE_DIR", "cache/pip"),
                           ("npm_config_cache", "cache/npm"), ("XDG_CACHE_HOME", "cache")):
                d = os.path.join(root, *sub.split("/"))
                os.makedirs(d, exist_ok=True)
                env[k] = d
        else:
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
            await self._start(w)
        return w

    async def _start(self, w: Worker) -> None:
        if w.sandbox:
            return await self._start_sandboxed(w)
        binary = self.s.goose_binary
        w.port = _free_port()
        w.secret = secrets.token_urlsafe(32)
        w.scheduler, _ = self.wants_scheduler(w)
        args = [binary, "serve", "--host", "127.0.0.1", "--port", str(w.port), "--platform", "desktop"]
        if w.scheduler:
            args.append("--enable-scheduler")
        rotate_log(self.log_dir / f"worker-{w.key}.log")
        logf = open(self.log_dir / f"worker-{w.key}.log", "ab", buffering=0)
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
                self._kill(w)
                w.state, w.last_error = "crashed", "goose serve did not become ready in time"
                raise RuntimeError(w.last_error)
        w.state, w.started_at, w.restart_pending, w.last_error = "ready", time.time(), False, ""
        log.info("worker %s ready on port %s (pid %s, scheduler=%s)", w.key, w.port, w.proc.pid, w.scheduler)

    async def _start_sandboxed(self, w: Worker) -> None:
        """`goose acp` inside the user's AppContainer; the hub talks to it over stdin/stdout (spec 012)."""
        from . import sandbox as sb
        w.state = "starting"
        w.scheduler, _ = self.wants_scheduler(w)
        spec = w.sandbox or {}
        try:
            if not sb.IS_WINDOWS:
                raise sb.SandboxError("sandbox.enabled is on, but the sandbox needs Windows; this worker is not "
                                      "started (fail closed). Turn sandbox.enabled off on this system.")
            state = await asyncio.to_thread(sb.prepare, spec["name"], str(self.s.system_dir / "sandbox"),
                                            spec["grants"])
        except Exception as e:
            w.state, w.last_error = "crashed", f"sandbox: {e}"
            raise RuntimeError(w.last_error) from e
        w.sandbox_sid = state["sid"]
        args = [self.s.goose_binary, "acp"]
        if w.scheduler:
            args.append("--enable-scheduler")
        rotate_log(self.log_dir / f"worker-{w.key}.log")
        logf = open(self.log_dir / f"worker-{w.key}.log", "ab", buffering=0)
        logf.write(f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start {' '.join(args[1:])} (sandbox {spec['name']}, "
                   f"{state['sid']}) root={w.path_root}\n".encode())
        cwd = os.path.join(spec["profile_root"], "workspace")
        if not os.path.isdir(cwd):
            cwd = spec["profile_root"]
        try:
            w.proc = sb.spawn(args, self._env(w), cwd, state["sid"], spec.get("caps") or [], logf, job=self.job)
        except Exception as e:
            w.state, w.last_error = "crashed", f"cannot start goose in the sandbox: {e}"
            raise RuntimeError(w.last_error) from e
        finally:
            logf.close()
        w.channel = sb.StdioChannel(w.proc, asyncio.get_running_loop())
        await asyncio.sleep(0.3)
        if w.proc.poll() is not None:
            w.state = "crashed"
            w.last_error = f"goose acp exited with code {w.proc.returncode} (see worker-{w.key}.log)"
            raise RuntimeError(w.last_error)
        w.port, w.secret = 0, ""
        w.state, w.started_at, w.restart_pending, w.last_error = "ready", time.time(), False, ""
        log.info("worker %s ready in sandbox %s (pid %s, scheduler=%s)", w.key, spec["name"], w.proc.pid, w.scheduler)

    def _kill(self, w: Worker) -> None:
        p = w.proc
        if p and p.poll() is None:
            try:
                if IS_WINDOWS:
                    # goose serve's children (MCP servers) live in the same job/process tree
                    subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True,
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
                        w.last_error = f"goose serve exited with code {w.proc.returncode}"
                        log.warning("worker %s crashed: %s", w.key, w.last_error)
                    if w.state == "crashed" and (clients or (has_sched and want_sched)):
                        if time.time() >= backoff.get(w.key, 0):
                            w.restarts += 1
                            backoff[w.key] = time.time() + min(300, 2 ** min(w.restarts, 8))
                            try:
                                await self.restart(w.key)
                            except Exception as e:
                                w.last_error = str(e)
                        continue
                    if w.state != "ready":
                        # a stopped profile that has schedules (and owns its scheduler) must be running
                        if has_sched and want_sched and w.state == "stopped":
                            try:
                                await self.ensure(w.key)
                                if self.on_restart:
                                    await self.on_restart(w)
                            except Exception as e:
                                w.last_error = str(e)
                        continue
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
