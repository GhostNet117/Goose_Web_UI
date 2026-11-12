"""Microsoft Execution Containers (MXC) sandbox backend (spec 025, Windows).

With `sandbox.backend: mxc` (the default) every isolated non-admin member's worker (`goose acp` and everything it
starts) runs inside an MXC process container, started by Microsoft's executor `wxc-exec.exe` from a JSON policy that
this module builds from the member's sandbox spec (context.Ctx.sandbox_spec):

- the member's profile, team folder and the team's extra folders: read/write; the program folders
  (`sandbox.read_dirs`) and the Goose folder: read and run; nothing else (the gateway's system folder, the database,
  the profiles root, other members' profiles, the native profile and the install folder are refused even when a
  setting names them);
- network: nothing, or - when the member may use the internet or relayed local services - only the member's own
  egress proxy in the gateway (egress.py), which decides every destination;
- UI: clipboard, input injection, desktop/system-settings control and IME locked (Win32k stays on: goose.exe and
  node.exe need it).

The executor is pinned (MXC_PIN): `wxc-exec.exe` 1.0.1 from the npm package @microsoft/mxc-sdk 1.0.1, installed by
`goose-web sandbox install-mxc` into `<install>/vendor/mxc/<version>/` after checking the package's npm sha512
integrity, the file's SHA-256 and its Authenticode signature (Microsoft Corporation). It is never committed to git.
Before every launch its SHA-256 is checked again through a handle that denies writes until the executor runs, so an
unverified binary is never executed. `wxc-exec --probe` and the Windows build tell whether this machine can run MXC.
When it cannot, members' workers do not start (fail closed) unless `sandbox.fallback: appcontainer` is set.

The request contract is pinned to "1.0.0" (telemetry off unless a run opts in; Goose Web never does).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("goose_web.mxc")
IS_WINDOWS = sys.platform == "win32"

CONTRACT = "1.0.0"
MXC_PIN: dict[str, Any] = {
    "package": "@microsoft/mxc-sdk",
    "version": "1.0.1",
    "url": "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.1.tgz",
    "integrity": "sha512-2cP925G5+lQyKzjBVha8uNtVd7XESgDBtgi1yCYYSo9M3xiFyZWtCO4SWPGTk509rdI6nqjyGcZxvEP3t6l8Hg==",
    "size": 38_256_855,
    "member": "package/bin/x64/wxc-exec.exe",
    "exe": "wxc-exec.exe",
    "exe_sha256": "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a",
    "exe_size": 12_152_632,
    "signer": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
}
DOWNLOAD_HOSTS = {"registry.npmjs.org"}
MIN_BUILD = (26100, 9278)          # Windows 11 24H2 process isolation (MXC docs, os-version-support)
PROBE_TIMEOUT = 30.0
SIGNATURE_TIMEOUT = 60.0
RECHECK_FAILED_SECONDS = 30.0      # an unavailable MXC is checked again at most this often
REQUIRED_PROBES = ("baseContainerApiPresent", "baseContainerSupportsEnumeratePaths",
                   "baseContainerSupportsIdentitylessLoopbackProxy", "baseContainerSupportsIngressHostLoopbackAllow")
REQUIRED_UI = ("canBlockClipboardRead", "canBlockClipboardWrite", "canBlockInputInjection")
PROXY_ENV = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
SANDBOX_UNAVAILABLE_MSG = ("The sandbox is unavailable, so your agent cannot start. Contact your administrator.")
INSTALL_HINT = ("If a proxy or firewall blocks the download, set HTTPS_PROXY for this command, or download "
                f"{MXC_PIN['url']} on another computer and run goose-web sandbox install-mxc --file <tgz> "
                "(docs/ADMINISTRATION.md, MXC sandbox).")


class MxcError(Exception):
    pass


# ------------------------------------------------------------------ locations
def install_root() -> Path:
    """The Goose Web install folder (the git clone that holds goose_web/)."""
    return Path(__file__).resolve().parent.parent


def mxc_dir(settings) -> Path:
    d = str(settings.get("sandbox", "mxc_dir") or "").strip()
    return Path(d) if d else install_root() / "vendor" / "mxc"


def protected_write_paths(settings) -> list[str]:
    """Folders a member's agent may never write: the code the gateway runs (package, venv, git metadata, scripts)
    and the MXC executor folder. A grant of a folder above one of them is refused too."""
    root = install_root()
    out = [root / "goose_web", root / ".git", root / "scripts", Path(sys.prefix), mxc_dir(settings)]
    return sorted({str(p) for p in out}, key=os.path.normcase)


def version_dir(settings) -> Path:
    return mxc_dir(settings) / MXC_PIN["version"]


def exe_path(settings) -> Path:
    return version_dir(settings) / MXC_PIN["exe"]


# ------------------------------------------------------------------ hashing / pinned handle
def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def npm_integrity(p: Path) -> str:
    h = hashlib.sha512()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha512-" + base64.b64encode(h.digest()).decode()


class PinnedFile:
    """The executor opened for reading with writes and deletes denied to everybody else (Windows share mode READ),
    so the file that was hashed is the file that is started: CreateProcess may still open it for execution, nobody
    may replace or change it until close(). Elsewhere a plain read handle."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if IS_WINDOWS:
            import _winapi
            import msvcrt
            h = _winapi.CreateFile(str(self.path), 0x80000000, 0x1, _winapi.NULL, 3, 0x80, _winapi.NULL)  # READ, SHARE_READ
            self.fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY)
        else:
            self.fd = os.open(str(self.path), os.O_RDONLY)

    def sha256(self) -> tuple[str, int]:
        h = hashlib.sha256()
        os.lseek(self.fd, 0, 0)
        n = 0
        while True:
            b = os.read(self.fd, 1 << 20)
            if not b:
                break
            n += len(b)
            h.update(b)
        return h.hexdigest(), n

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def verify_exe(path: Path, pinned: PinnedFile | None = None) -> str:
    """'' when `path` is the pinned executor (size + SHA-256), else the problem."""
    path = Path(path)
    if not path.is_file():
        return f"{path} is not installed (run: goose-web sandbox install-mxc)"
    own = pinned is None
    try:
        pf = pinned or PinnedFile(path)
    except OSError as e:
        return f"{path} cannot be opened for verification ({e})"
    try:
        digest, size = pf.sha256()
    finally:
        if own:
            pf.close()
    if size != MXC_PIN["exe_size"] or digest != MXC_PIN["exe_sha256"]:
        return (f"{path} does not match the pinned wxc-exec.exe {MXC_PIN['version']} (SHA-256 {digest[:16]}..., "
                f"{size:,} bytes; expected {MXC_PIN['exe_sha256'][:16]}..., {MXC_PIN['exe_size']:,} bytes); it is "
                "not run. Reinstall: goose-web sandbox install-mxc --force")
    return ""


def authenticode(path: Path, timeout: float = SIGNATURE_TIMEOUT) -> dict:
    """{'status', 'subject'} of the file's Authenticode signature (PowerShell Get-AuthenticodeSignature)."""
    if not IS_WINDOWS:
        return {"status": "NotSupported", "subject": ""}
    lit = str(path).replace("'", "''")
    ps = (f"$s = Get-AuthenticodeSignature -LiteralPath '{lit}'; "
          "[pscustomobject]@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject} | "
          "ConvertTo-Json -Compress")
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    try:  # fixed command; the path is quoted as a PowerShell literal
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, text=True,  # nosec B603
                           timeout=timeout, stdin=subprocess.DEVNULL, creationflags=0x08000000)
        data = json.loads((r.stdout or "").strip() or "{}")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return {"status": f"Error: {e.__class__.__name__}", "subject": ""}
    return {"status": str(data.get("status") or "Unknown"), "subject": str(data.get("subject") or "")}


def signature_problem(sig: dict) -> str:
    if sig.get("status") != "Valid":
        return f"the Authenticode signature of wxc-exec.exe is {sig.get('status')!r}, not Valid"
    if sig.get("subject") != MXC_PIN["signer"]:
        return f"wxc-exec.exe is signed by {sig.get('subject')!r}, not by {MXC_PIN['signer']!r}"
    return ""


# ------------------------------------------------------------------ install
def _same_or_parent(a: Path, b: Path) -> bool:
    try:
        ra, rb = os.path.normcase(os.path.realpath(a)), os.path.normcase(os.path.realpath(b))
    except (OSError, ValueError):
        return True
    return ra == rb or rb.startswith(ra.rstrip("\\/") + os.sep)


def target_problem(settings, d: Path) -> str:
    d = Path(d)
    if not d.is_absolute() or d.parent == d or len(d.parts) < 3:
        return f"{d} is not an MXC folder (a drive root or a relative path); set sandbox.mxc_dir to a folder of its own"
    for name, p in (("system folder", Path(settings.system_dir)), ("profiles root", Path(settings.profiles_root))):
        if _same_or_parent(d, p) or _same_or_parent(p, d):
            return f"{d} is the {name}, inside it or above it; set sandbox.mxc_dir to a folder of its own"
    if d.is_file() or d.is_symlink():
        return f"{d} is not a folder"
    return ""


def installed_info(settings) -> dict:
    try:
        return json.loads((version_dir(settings) / "install.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _extract_member(tgz: Path, dest: Path) -> None:
    """Copy only the pinned member's bytes out of the package (no name or path from the archive is used)."""
    with tarfile.open(tgz, "r:gz") as tf:
        try:
            info = tf.getmember(MXC_PIN["member"])
        except KeyError:
            raise MxcError(f"the package has no {MXC_PIN['member']}")
        if not info.isfile() or info.size != MXC_PIN["exe_size"]:
            raise MxcError(f"{MXC_PIN['member']} in the package is not the pinned file ({info.size:,} bytes)")
        src = tf.extractfile(info)
        if src is None:
            raise MxcError(f"{MXC_PIN['member']} cannot be read from the package")
        with src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1 << 20)


def _rmtree(p: Path) -> None:
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def install(settings, *, file: str | None = None, force: bool = False, if_missing: bool = False, log=print,
            signature=None) -> dict:
    """Install the pinned executor (download from the npm registry, or a local package .tgz). Verifies the package's
    npm integrity (sha512), the executable's size and SHA-256 and its Authenticode signer before anything is put in
    place; the swap is atomic (rename). Returns the install record. `signature` (tests) replaces authenticode()."""
    from . import guardmodel
    sign = signature or authenticode
    d = mxc_dir(settings)
    problem = target_problem(settings, d)
    if problem:
        raise MxcError(problem)
    final = version_dir(settings)
    exe = final / MXC_PIN["exe"]
    if not force and exe.is_file() and not verify_exe(exe):
        sig_problem = signature_problem(sign(exe))
        if not sig_problem:
            log(f"wxc-exec.exe {MXC_PIN['version']} is installed and verified ({exe}); nothing to do.")
            return installed_info(settings) or {"exe": str(exe)}
        if if_missing:
            log(f"The installed executor fails its signature check ({sig_problem}); installing it again.")
    d.mkdir(parents=True, exist_ok=True)
    stage = d / f".stage-{secrets.token_hex(6)}"     # os.mkdir: inherits the install folder's (restricted) ACL
    stage.mkdir()
    try:
        tgz = stage / "package.tgz"
        if file:
            src = Path(file)
            if not src.is_file():
                raise MxcError(f"{file} not found")
            if src.stat().st_size != MXC_PIN["size"]:
                raise MxcError(f"{file} has {src.stat().st_size:,} bytes; the pinned package has {MXC_PIN['size']:,}")
            shutil.copyfile(src, tgz)
        else:
            log(f"Downloading {MXC_PIN['package']} {MXC_PIN['version']} ({MXC_PIN['size'] / 1e6:.1f} MB) from "
                f"{MXC_PIN['url']}")
            try:
                guardmodel.download(MXC_PIN["url"], tgz, expected_size=MXC_PIN["size"], log=log, pinned=True,
                                    hosts=DOWNLOAD_HOSTS, agent="mxc install")
            except guardmodel.InstallError as e:
                raise MxcError(str(e).replace(guardmodel.BLOCKED_HINT, INSTALL_HINT)) from e
        got = npm_integrity(tgz)
        if got != MXC_PIN["integrity"]:
            raise MxcError(f"package integrity mismatch: expected {MXC_PIN['integrity']}, got {got}. Nothing was "
                           "installed.")
        new = stage / MXC_PIN["version"]
        new.mkdir()
        _extract_member(tgz, new / MXC_PIN["exe"])
        problem = verify_exe(new / MXC_PIN["exe"])
        if problem:
            raise MxcError(problem.replace(" Reinstall: goose-web sandbox install-mxc --force", " Nothing was installed."))
        sig = sign(new / MXC_PIN["exe"])
        problem = signature_problem(sig)
        if problem:
            raise MxcError(problem + ". Nothing was installed.")
        record = {"package": MXC_PIN["package"], "version": MXC_PIN["version"], "integrity": MXC_PIN["integrity"],
                  "sha256": MXC_PIN["exe_sha256"], "signer": sig["subject"], "contract": CONTRACT,
                  "source": file and "file" or MXC_PIN["url"], "installed": time.strftime("%Y-%m-%dT%H:%M:%S")}
        (new / "install.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
        tgz.unlink()
        old = d / f".old-{secrets.token_hex(6)}"
        had_old = final.exists()
        if had_old:
            os.replace(final, old)
        try:
            os.replace(new, final)
        except OSError:
            if had_old:
                os.replace(old, final)
            raise
        _rmtree(old)
        log(f"Installed wxc-exec.exe {MXC_PIN['version']} in {final} (SHA-256 {MXC_PIN['exe_sha256']}, signed by "
            f"{sig['subject']}).")
        AVAILABILITY.invalidate()
        return record
    finally:
        _rmtree(stage)


# ------------------------------------------------------------------ probe / build / availability
def windows_build() -> tuple[int, int]:
    """(build, UBR) of this Windows, (0, 0) elsewhere or when unknown."""
    if not IS_WINDOWS:
        return 0, 0
    build = sys.getwindowsversion().build
    ubr = 0
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as k:
            ubr = int(winreg.QueryValueEx(k, "UBR")[0])
    except OSError:
        pass
    return build, ubr


def build_problem(build: tuple[int, int]) -> str:
    if build == (0, 0):
        return "the Windows build is unknown"
    if build[0] < MIN_BUILD[0] or (build[0] == MIN_BUILD[0] and build[1] < MIN_BUILD[1]):
        return (f"Windows build {build[0]}.{build[1]} is older than {MIN_BUILD[0]}.{MIN_BUILD[1]}, the first with MXC "
                "process containers; install the Windows updates, or set sandbox.backend: appcontainer")
    return ""


def run_probe(exe: Path, timeout: float = PROBE_TIMEOUT) -> tuple[dict, str]:
    """(probe JSON, problem) from `wxc-exec --probe`."""
    try:
        r = subprocess.run([str(exe), "--probe"], capture_output=True, text=True, timeout=timeout,  # nosec B603
                           stdin=subprocess.DEVNULL, creationflags=0x08000000 if IS_WINDOWS else 0,
                           env=host_env())
    except subprocess.TimeoutExpired:
        return {}, f"wxc-exec --probe did not answer within {timeout:.0f} s"
    except OSError as e:
        return {}, f"wxc-exec --probe could not run ({e})"
    try:
        data = json.loads(r.stdout or "")
    except ValueError:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["no output"]
        return {}, f"wxc-exec --probe exited with {r.returncode}: {tail[0][:300]}"
    return (data if isinstance(data, dict) else {}), ""


def probe_problems(data: dict) -> list[str]:
    out = []
    if data.get("tier") != "base-container":
        out.append(f"probe tier is {data.get('tier')!r}, not 'base-container'")
    probes = data.get("probes") if isinstance(data.get("probes"), dict) else {}
    missing = [k for k in REQUIRED_PROBES if probes.get(k) is not True]
    ui = probes.get("uiCapabilities") if isinstance(probes.get("uiCapabilities"), dict) else {}
    missing += [f"uiCapabilities.{k}" for k in REQUIRED_UI if ui.get(k) is not True]
    if missing:
        out.append("this Windows lacks " + ", ".join(missing))
    return out


class Availability:
    """Can members' workers run in MXC here? Computed once (thread-safe: several members may start at once) and
    cached: a success for the gateway's life (the executor's hash is still checked before every launch), a failure
    for RECHECK_FAILED_SECONDS, so an `install-mxc` while the gateway runs is noticed without a restart."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state: dict | None = None
        self._at = 0.0
        self._key: tuple = ()
        self._sig_cache: dict[tuple, dict] = {}
        self._logged = ""

    def invalidate(self) -> None:
        with self._lock:
            self._state = None

    def mark_failed(self, reason: str) -> None:
        with self._lock:
            self._state = dict(self._state or {}, available=False, reason=reason)
            self._at = time.monotonic()
        self._log(self._state)

    def check(self, settings, refresh: bool = False) -> dict:
        from .config import sandbox_config_problems
        key = (os.path.normcase(str(exe_path(settings))), tuple(sandbox_config_problems(settings)))
        with self._lock:
            st = self._state
            if st is not None and not refresh and self._key == key and (
                    st["available"] or time.monotonic() - self._at < RECHECK_FAILED_SECONDS):
                return st
            st = self._compute(settings)
            self._state, self._at, self._key = st, time.monotonic(), key
        self._log(st)
        return st

    def _log(self, st: dict) -> None:
        key = f"{st['available']}|{st['reason']}"
        if key == self._logged:
            return
        self._logged = key
        if st["available"]:
            log.info("sandbox mxc: available (wxc-exec %s, %s, tier %s, Windows %s)", st["version"], st["exe"],
                     (st.get("probe") or {}).get("tier"), st.get("build"))
        else:
            log.error("sandbox mxc: UNAVAILABLE: %s", st["reason"])

    def _signature(self, exe: Path) -> dict:
        try:
            s = exe.stat()
            key = (os.path.normcase(str(exe)), s.st_size, s.st_mtime_ns, getattr(s, "st_ino", 0))
        except OSError:
            key = (str(exe),)
        if key not in self._sig_cache:
            self._sig_cache = {key: authenticode(exe)}
        return self._sig_cache[key]

    def _compute(self, settings) -> dict:
        exe = exe_path(settings)
        b = windows_build()
        st: dict[str, Any] = {"available": False, "reason": "", "exe": str(exe), "version": MXC_PIN["version"],
                              "contract": CONTRACT, "build": f"{b[0]}.{b[1]}", "probe": {}, "signature": {},
                              "checkedAt": time.time()}
        from .config import sandbox_config_problems
        problems = sandbox_config_problems(settings)
        if problems:
            st["reason"] = "; ".join(problems)
            return st
        if not IS_WINDOWS:
            st["reason"] = "MXC process containers need Windows"
            return st
        bp = build_problem(b)
        if bp:
            st["reason"] = bp
            return st
        vp = verify_exe(exe)
        if vp:
            st["reason"] = vp
            return st
        st["signature"] = sig = self._signature(exe)
        sp = signature_problem(sig)
        if sp:
            st["reason"] = sp + "; it is not run (goose-web sandbox install-mxc --force)"
            return st
        data, pp = run_probe(exe)
        st["probe"] = {"tier": data.get("tier"), "warnings": data.get("warnings") or [],
                       "probes": data.get("probes") or {}} if data else {}
        problems = [pp] if pp else probe_problems(data)
        if problems:
            st["reason"] = "; ".join(problems)
            return st
        st["available"] = True
        return st


AVAILABILITY = Availability()


def availability(settings, refresh: bool = False) -> dict:
    return AVAILABILITY.check(settings, refresh)


def summary(settings, refresh: bool = False) -> dict:
    """The sandbox state for `sandbox status`, `check` and Admin > System (spec 025 R1/R3)."""
    from .config import sandbox_backend, sandbox_config_problems, sandbox_fallback, sandbox_on
    on = sandbox_on(settings)
    backend = sandbox_backend(settings)
    out: dict[str, Any] = {
        "enabled": on, "backend": backend, "configuredBackend": str(settings.get("sandbox", "backend") or "mxc"),
        "fallback": sandbox_fallback(settings), "network": str(settings.get("sandbox", "network") or "internet"),
        "relays": [str(t) for t in (settings.get("sandbox", "relays") or [])], "problems": sandbox_config_problems(settings),
        "mxcDir": str(mxc_dir(settings)), "membersCanStart": True, "reason": ""}
    if backend == "mxc" or out["fallback"] == "appcontainer":
        st = availability(settings, refresh)
        out["mxc"] = {k: st.get(k) for k in ("available", "reason", "exe", "version", "contract", "build", "probe",
                                             "signature", "checkedAt")}
        out["mxc"]["installed"] = installed_info(settings)
    if out["problems"]:
        out["membersCanStart"], out["reason"] = False, "; ".join(out["problems"])
    elif on and backend == "mxc" and not out["mxc"]["available"]:
        if out["fallback"] == "appcontainer":
            out["reason"] = "MXC unavailable; members' agents start in the AppContainer fallback: " + out["mxc"]["reason"]
        else:
            out["membersCanStart"], out["reason"] = False, "MXC unavailable: " + out["mxc"]["reason"]
    return out


# ------------------------------------------------------------------ policy builder
def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _forms(p: str) -> set[str]:
    out = {_norm(os.path.abspath(p))}
    try:
        out.add(_norm(os.path.realpath(p)))
    except (OSError, ValueError):
        pass
    return out


def _under(a: str, b: str) -> bool:
    """a is b or inside b (both normalised)."""
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def resolved(p: str) -> str:
    """The long, link-resolved form MXC gets (junctions and 8.3 names resolved; \\\\?\\ prefixes removed)."""
    try:
        r = os.path.realpath(p)
    except (OSError, ValueError):
        r = os.path.abspath(p)
    if r.startswith("\\\\?\\UNC\\"):
        r = "\\\\" + r[8:]
    elif r.startswith("\\\\?\\"):
        r = r[4:]
    return os.path.normpath(r)


def grant_problem(path: str, mode: str, *, profile_root: str, profiles_root: str, system_dir: str,
                  protected_write: list[str] = (), protected_any: list[str] = ()) -> str:
    """'' when `path` may be granted with `mode` ('modify' | 'read') to the member whose profile is `profile_root`,
    else why not. Compared as written and after resolving links (junctions, symlinks, 8.3 names)."""
    if not path or not os.path.isabs(path):
        return "not an absolute path"
    drive, rest = os.path.splitdrive(os.path.normpath(path))
    if rest in ("", "\\", "/"):
        return "a drive or share root"
    forms = _forms(path)
    sysd = _forms(system_dir)
    if any(_under(f, s) or _under(s, f) for f in forms for s in sysd):
        return "the gateway's system folder (database, keys, logs) or a folder above it"
    roots = _forms(profiles_root)
    if any(_under(r, f) for f in forms for r in roots):
        return "the profiles root or a folder above it (every member's profile)"
    own = _forms(profile_root)
    teams = {_norm(os.path.join(r, "_teams")) for r in roots}
    for f in forms:
        if any(_under(f, r) for r in roots) and not any(_under(f, o) for o in own) and \
                not any(_under(f, t) for t in teams):
            return "inside another member's profile"
    for p in protected_any:
        if p and any(_under(f, q) or _under(q, f) for f in forms for q in _forms(p)):
            return "a protected folder (the native Goose profile) or a folder above it"
    if mode == "modify":
        for p in protected_write:
            if p and any(_under(f, q) or _under(q, f) for f in forms for q in _forms(p)):
                return "the Goose Web install or MXC folder (never writable for members) or a folder above it"
    return ""


def filter_grants(grants: dict[str, str], **ctx) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """(kept {resolved path: mode}, refused [(path, why)]). Modify wins over read for one (resolved) path."""
    kept: dict[str, str] = {}
    names: dict[str, str] = {}
    refused = []
    for path, mode in sorted(grants.items(), key=lambda kv: (kv[1] != "modify", _norm(kv[0]))):
        why = grant_problem(path, mode, **ctx)
        if why:
            refused.append((path, why))
            continue
        r = resolved(path)
        k = os.path.normcase(r)
        if k in names and kept[names[k]] == "modify":
            continue
        names[k] = r
        kept[r] = mode
    return kept, refused


def _drive_root(p: str) -> str:
    d = os.path.splitdrive(p)[0]
    return d.upper() + "\\" if len(d) == 2 and d[1] == ":" else ""


def build_policy(*, command: list[str], cwd: str, env: dict[str, str], grants: dict[str, str], proxy_url: str = "",
                 system_drive: str = "") -> dict:
    """The MXC request (contract 1.0.0) for one worker start. Pure and deterministic: same input, same JSON.
    `grants` must already be filtered (filter_grants). proxy_url '' = no network at all."""
    rw = sorted((p for p, m in grants.items() if m == "modify"), key=os.path.normcase)
    ro = sorted((p for p, m in grants.items() if m == "read"), key=os.path.normcase)
    drives = {_drive_root(p) for p in rw + ro + [cwd]} | {_drive_root(system_drive or "C:") or "C:\\"}
    envl = {k: str(v) for k, v in env.items() if k and "=" not in k and k.upper() not in PROXY_ENV}
    if not any(k.upper() == "LOCALAPPDATA" for k in envl):
        envl["LOCALAPPDATA"] = os.environ.get("LOCALAPPDATA") or cwd   # presence only; MXC sets the container's own
    if proxy_url:
        envl["NODE_USE_ENV_PROXY"] = "1"    # Node >= 24 honours HTTP(S)_PROXY with it (MXC sets those two)
    policy: dict[str, Any] = {
        "version": CONTRACT,
        "containment": "processcontainer",
        "process": {"commandLine": subprocess.list2cmdline(command), "cwd": cwd, "timeout": 0,
                    "inheritDefaultEnv": False,
                    "env": [f"{k}={v}" for k, v in sorted(envl.items(), key=lambda kv: kv[0].upper())]},
        "filesystem": {"readwritePaths": rw, "readonlyPaths": ro},
        "network": ({"egress": {"default": "deny"}, "ingress": {"default": "allow", "hostLoopback": "allow"}}
                    if proxy_url else
                    {"egress": {"default": "deny"}, "ingress": {"default": "deny", "hostLoopback": "deny"}}),
        "ui": {"disable": False, "clipboard": "none", "injection": False},
        "processContainer": {"filesystem": {"enumeratePaths": sorted(d for d in drives if d)},
                             "ui": {"desktopSystemControl": False, "systemSettings": "none", "ime": False}},
    }
    if proxy_url:
        policy["runtimeConfig"] = {"networkProxy": proxy_url}
    return policy


def write_policy(path: Path, policy: dict) -> None:
    """Atomic write (temp file + rename) into the gateway's system folder."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(json.dumps(policy, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def redacted(policy: dict) -> dict:
    """The policy without the proxy credential (for logs and status)."""
    p = json.loads(json.dumps(policy))
    url = (p.get("runtimeConfig") or {}).get("networkProxy")
    if url and "@" in url:
        p["runtimeConfig"]["networkProxy"] = "http://***@" + url.rsplit("@", 1)[1]
    return p


# ------------------------------------------------------------------ launch
HOST_ENV_KEYS = ("SystemRoot", "windir", "SystemDrive", "ComSpec", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE",
                 "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")


def host_env() -> dict:
    """The executor's own (host-side) environment: system locations only, never the gateway's secrets."""
    env = {k: os.environ[k] for k in HOST_ENV_KEYS if os.environ.get(k)}
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    env["PATH"] = os.pathsep.join([os.path.join(sysroot, "System32"), sysroot])
    return env


def launch(exe: Path, policy_file: Path, stderr_file, jobs: list) -> subprocess.Popen:
    """Start `wxc-exec <policy>` with stdin/stdout pipes. Verified first (SHA-256 through a write-denied handle kept
    open until the process runs); on Windows started suspended, put in every job of `jobs` (kill-on-close: the
    gateway's, then the worker's) and only then resumed, so nothing it starts can run outside the jobs."""
    with PinnedFile(exe) as pf:
        problem = verify_exe(exe, pinned=pf)
        if problem:
            AVAILABILITY.mark_failed(problem)
            raise MxcError(problem)
        flags = (0x08000000 | 0x00000004) if IS_WINDOWS else 0   # CREATE_NO_WINDOW | CREATE_SUSPENDED
        proc = subprocess.Popen([str(exe), str(policy_file)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # nosec B603
                                stderr=stderr_file, env=host_env(), creationflags=flags,
                                cwd=os.environ.get("SystemRoot") if IS_WINDOWS else None)
    if not IS_WINDOWS:
        return proc
    for j in jobs:
        if j is not None and not j.add(proc):
            log.warning("sandbox mxc: wxc-exec (pid %s) could not join a kill-on-close job", proc.pid)
    import ctypes
    from ctypes import wintypes
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    rc = ntdll.NtResumeProcess(int(proc._handle))  # type: ignore[attr-defined]
    if rc != 0:
        proc.kill()
        raise MxcError(f"wxc-exec could not be resumed (NTSTATUS 0x{rc & 0xFFFFFFFF:08X})")
    return proc


# ------------------------------------------------------------------ errors
NTSTATUS_TEXT = {
    0xC0000142: "a program in the container could not initialise (STATUS_DLL_INIT_FAILED: Win32k blocked or a DLL "
                "missing in the container's readable folders)",
    0xC0000022: "access denied while starting the container (STATUS_ACCESS_DENIED)",
    0xC0000135: "a DLL the program needs is not readable in the container (STATUS_DLL_NOT_FOUND)",
    0xC000013A: "the container was stopped (STATUS_CONTROL_C_EXIT)",
}


def explain_exit(code: int | None, stderr_text: str) -> str:
    """A readable reason for a wxc-exec that ended early, from its exit code and the stderr it wrote."""
    for line in reversed([x.strip() for x in (stderr_text or "").splitlines() if x.strip()]):
        if line.startswith("{") and '"error"' in line:
            try:
                err = json.loads(line)["error"]
                return f"MXC refused to start the sandbox ({err.get('code')}): {str(err.get('message'))[:400]}"
            except (ValueError, KeyError, TypeError):
                continue
    c = (code or 0) & 0xFFFFFFFF
    if c in NTSTATUS_TEXT:
        return NTSTATUS_TEXT[c]
    tail = [x.strip() for x in (stderr_text or "").splitlines() if x.strip()][-1:]
    return f"wxc-exec exited with code {code}" + (f": {tail[0][:300]}" if tail else "")
