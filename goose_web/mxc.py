"""Microsoft Execution Containers (MXC) sandbox backend (spec 025, Windows).

With `sandbox.backend: mxc` (the default) every isolated non-admin member's worker (`goose acp` and everything it
starts) runs inside an MXC process container, started by Microsoft's executor `wxc-exec.exe` from a JSON policy that
this module builds from the member's sandbox spec (context.Ctx.sandbox_spec):

- the member's profile, team folder and the team's extra folders: read/write; the program folders
  (`sandbox.read_dirs`) and the Goose folder: read and run; nothing else. Refused even when a setting names them
  (in any spelling: `\\\\?\\`, UNC, 8.3, trailing dots/spaces, junctions, case): the gateway's system folder (the
  database, keys, logs), the profiles root, other members' profiles and the native profile - for reading and
  writing; Goose Web's code folders (package, .git, scripts), its venv and base Python, the goose binary folder and
  the MXC folder - for writing (reading the install folder is allowed: program folders; spec 025 D3). Network (UNC)
  and device paths are never granted. A file in a read/write folder that is hard-linked to a file outside the
  read/write folders stops the start (MXC grants are path-based);
- network: nothing, or - when the member may use the internet or relayed local services - only the member's own
  egress proxy in the gateway (egress.py), which decides every destination;
- UI: clipboard, input injection, desktop/system-settings control and IME locked (Win32k stays on: goose.exe and
  node.exe need it).

The executor is pinned (MXC_PIN): `wxc-exec.exe` 1.0.1 from the npm package @microsoft/mxc-sdk 1.0.1, installed by
`goose-web sandbox install-mxc` into `<install>/vendor/mxc/<version>/` after checking the package's npm sha512
integrity, the file's SHA-256 and its Authenticode signature (Microsoft Corporation). It is never committed to git.
Before every launch - the worker's and `--probe` alike - every pinned file of the version folder (pinned_files) is
opened with writes and deletes denied, hashed through that handle and held until the executor runs; the folder must
hold nothing but the pinned files and install.json (a DLL next to wxc-exec.exe would be loaded by it), checked before
the start and again while the executor is still suspended; and the executor is created with the image-load
mitigations PreferSystem32Images + MicrosoftSignedOnly + NoRemoteImages, so a DLL planted in its folder is not loaded
in place of the System32 one (security review 2026-11-12, MX-8; the install folder's ACL is left as it is, SB-8).
`wxc-exec --probe` and the Windows build tell whether this machine can run MXC.
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
    # Further files installed next to wxc-exec.exe (name -> [sha256, size]). None today: a lone wxc-exec.exe is
    # enough (spec 025 converge), the package's mxc_ffi.dll / wslcsdk.dll are not installed. Anything added to the
    # install must be listed here, or the folder check refuses to run the executor.
    "extra_files": {},
}
INSTALL_RECORD = "install.json"    # written by install(); data, never loaded as code
# CreateProcess image-load mitigations for wxc-exec (MX-8): PreferSystem32Images | MicrosoftSignedOnly |
# NoRemoteImages (PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON)
EXEC_MITIGATIONS = (1 << 60) | (1 << 44) | (1 << 52)
HARDLINK_SCAN_SECONDS = 5.0        # MX-3: bounded scan of a member's read/write folders before an MXC start
HARDLINK_SCAN_ENTRIES = 200_000
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
    """Folders a member's agent may never write: the code the gateway runs (package, venv, git metadata, scripts),
    the Python it runs on (venv and base installation, MX-6), the goose binary's folder (admins' agents run it
    unsandboxed) and the MXC executor folder. A grant of a folder above one of them is refused too."""
    root = install_root()
    out = [root / "goose_web", root / ".git", root / "scripts", mxc_dir(settings)]
    for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix, os.path.dirname(sys.executable),
              os.path.dirname(getattr(sys, "_base_executable", "") or "")):
        if p and os.path.isabs(p):
            out.append(Path(p))
    try:
        goose = str(settings.goose_binary or "")
    except Exception:
        goose = ""
    if goose and os.path.isabs(goose):
        out.append(Path(os.path.dirname(goose)))
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


def verify_exe(path: Path, pinned: PinnedFile | None = None, expected: tuple[str, int] | None = None) -> str:
    """'' when `path` is the pinned executor (size + SHA-256; or `expected` for another pinned file), else the
    problem."""
    path = Path(path)
    want_sha, want_size = expected or (MXC_PIN["exe_sha256"], MXC_PIN["exe_size"])
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
    if size != want_size or digest != want_sha:
        return (f"{path} does not match the pinned {path.name} of wxc-exec {MXC_PIN['version']} (SHA-256 "
                f"{digest[:16]}..., {size:,} bytes; expected {want_sha[:16]}..., {want_size:,} bytes); it is "
                "not run. Reinstall: goose-web sandbox install-mxc --force")
    return ""


def pinned_files() -> dict[str, tuple[str, int]]:
    """Every file of the version folder the executor may load: name -> (SHA-256, size). wxc-exec.exe plus
    MXC_PIN['extra_files'] (none today)."""
    out = {MXC_PIN["exe"]: (MXC_PIN["exe_sha256"], MXC_PIN["exe_size"])}
    for name, (digest, size) in (MXC_PIN.get("extra_files") or {}).items():
        out[name] = (digest, size)
    return out


def folder_problem(vdir: Path) -> str:
    """'' when the version folder holds exactly the pinned files (+ install.json), else the problem (MX-8: Windows
    loads a DLL from the executable's own folder before System32 unless it is a KnownDLL)."""
    vdir = Path(vdir)
    allowed = {n.lower() for n in pinned_files()} | {INSTALL_RECORD}
    try:
        entries = list(os.scandir(vdir))
    except FileNotFoundError:
        return f"{vdir} is not installed (run: goose-web sandbox install-mxc)"
    except OSError as e:
        return f"{vdir} cannot be listed ({e})"
    extra = sorted(e.name for e in entries if e.name.lower() not in allowed or e.is_symlink()
                   or not e.is_file(follow_symlinks=False))
    if extra:
        from .activity import clean_text
        return (f"{vdir} holds files that are not part of the pinned executor ({clean_text(', '.join(extra[:5]), 300)}"
                f"{', ...' if len(extra) > 5 else ''}); wxc-exec.exe would load a DLL placed next to it, so it is not "
                "run. Remove them, or reinstall: goose-web sandbox install-mxc --force")
    names = {e.name.lower() for e in entries}
    missing = sorted(n for n in pinned_files() if n.lower() not in names)
    if missing:
        return f"{vdir / missing[0]} is not installed (run: goose-web sandbox install-mxc)"
    return ""


class PinnedSet:
    """Every pinned file of the version folder opened like PinnedFile (writes, deletes and renames denied) for as
    long as the set is open; problem() hashes each one through its handle."""

    def __init__(self, vdir: Path):
        self.vdir = Path(vdir)
        self.files: dict[str, PinnedFile] = {}
        try:
            for name in pinned_files():
                self.files[name] = PinnedFile(self.vdir / name)
        except BaseException:
            self.close()
            raise

    def problem(self) -> str:
        for name, pf in self.files.items():
            p = verify_exe(pf.path, pinned=pf, expected=pinned_files()[name])
            if p:
                return p
        return ""

    def close(self) -> None:
        for pf in self.files.values():
            pf.close()
        self.files = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def verify_install(vdir: Path) -> str:
    """'' when the version folder is exactly the pinned install (folder content + every pinned file's SHA-256)."""
    problem = folder_problem(vdir)
    if problem:
        return problem
    try:
        with PinnedSet(vdir) as ps:
            return ps.problem()
    except OSError as e:
        return f"{vdir} cannot be opened for verification ({e})"


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
    if not force and exe.is_file():
        folder = verify_install(final)
        sig_problem = folder or signature_problem(sign(exe))
        if not sig_problem:
            log(f"wxc-exec.exe {MXC_PIN['version']} is installed and verified ({exe}); nothing to do.")
            return installed_info(settings) or {"exe": str(exe)}
        if if_missing:
            log(f"The installed executor fails its check ({sig_problem}); installing it again.")
    d.mkdir(parents=True, exist_ok=True)
    # os.mkdir: the stage inherits the ACL of the MXC folder (by default that of the install folder; not changed
    # here - SB-8). The pin (pinned_files, folder_problem, PinnedSet) is the control, checked before every launch.
    stage = d / f".stage-{secrets.token_hex(6)}"
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
    """(probe JSON, problem) from `wxc-exec --probe`, started like a worker's executor (MX-8): every pinned file
    verified through write-denied handles held until it runs, the folder checked, the image-load mitigations on,
    in a kill-on-close job of its own."""
    from .activity import clean_text
    from .workers import _Job
    job = _Job() if IS_WINDOWS else None
    try:
        p = start_verified(Path(exe), ["--probe"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, jobs=[job] if IS_WINDOWS else [])
    except MxcError as e:
        if job is not None:
            job.close()
        return {}, str(e)
    except OSError as e:
        if job is not None:
            job.close()
        return {}, f"wxc-exec --probe could not run ({e})"
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return {}, f"wxc-exec --probe did not answer within {timeout:.0f} s"
    finally:
        if job is not None:
            job.close()
    out_s, err_s = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    try:
        data = json.loads(out_s or "")
    except ValueError:
        tail = (err_s or out_s or "").strip().splitlines()[-1:] or ["no output"]
        return {}, f"wxc-exec --probe exited with {p.returncode}: {clean_text(tail[0], 300)}"
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
        vp = verify_install(exe.parent)
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
    from .config import (sandbox_backend, sandbox_config_problems, sandbox_fallback, sandbox_on,
                         sandbox_relay_problems)
    on = sandbox_on(settings)
    relays = settings.get("sandbox", "relays") or []
    backend = sandbox_backend(settings)
    out: dict[str, Any] = {
        "enabled": on, "backend": backend, "configuredBackend": str(settings.get("sandbox", "backend") or "mxc"),
        "fallback": sandbox_fallback(settings), "network": str(settings.get("sandbox", "network") or "internet"),
        "relays": [str(t) for t in relays] if isinstance(relays, (list, tuple)) else [],     # V-7: any type
        "relayProblems": sandbox_relay_problems(settings), "problems": sandbox_config_problems(settings),
        "mxcDir": str(mxc_dir(settings)), "membersCanStart": True, "reason": "",
        "readDirProblems": [{"path": p, "why": w} for p, w in read_dir_problems(settings)]}
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


UNC_REFUSED = "a network (UNC) path; MXC grants only local folders (a share on this machine could be another name " \
              "for a protected folder)"


def canonical_path(p: str) -> tuple[str, str]:
    """(canonical absolute local path, '') or ('', why it cannot be granted). MX-6: \\\\?\\X:\\ prefixes removed,
    '/' -> '\\', trailing dots and spaces of every component removed (Windows ignores them), normalised; device
    paths (\\\\.\\, \\\\?\\GLOBALROOT, volume GUIDs), UNC paths (\\\\server\\share, \\\\?\\UNC\\...) and alternate
    data streams refused."""
    raw = str(p or "").strip()
    if not raw or "\x00" in raw:
        return "", "an empty path"
    s = raw.replace("/", "\\")
    if s.startswith("\\\\"):
        if s[2:4] == "?\\":
            rest = s[4:]
            if rest[:4].upper() == "UNC\\":
                return "", UNC_REFUSED
            if not (len(rest) >= 3 and rest[0].isalpha() and rest[1:3] == ":\\"):
                return "", "a device path"
            s = rest
        elif s[2:4] == ".\\":
            return "", "a device path"
        else:
            return "", UNC_REFUSED
    drive, tail = os.path.splitdrive(s)
    if not (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":") or not tail.startswith("\\"):
        return "", "not an absolute path"
    if ":" in tail:
        return "", "the path contains ':' (alternate data stream)"
    parts = [c if c in (".", "..") else c.rstrip(" .") for c in tail.split("\\")]
    return os.path.normpath(drive.upper() + "\\".join(parts)), ""


def _strip_prefix(r: str) -> str:
    if r.startswith("\\\\?\\UNC\\"):
        return "\\\\" + r[8:]
    if r.startswith("\\\\?\\"):
        return r[4:]
    return r


def _real(p: str) -> str:
    try:
        return os.path.normpath(_strip_prefix(os.path.realpath(p)))
    except (OSError, ValueError):
        return os.path.normpath(p)


def _forms(p: str) -> set[str]:
    """The canonical form of `p` and its link-resolved form (junctions, symlinks, 8.3 names), normalised; a path
    that cannot be canonicalised is compared as written (abspath)."""
    c, why = canonical_path(p)
    if why:
        return {_norm(os.path.abspath(p))}
    return {_norm(c), _norm(_real(c))}


def _under(a: str, b: str) -> bool:
    """a is b or inside b (both normalised)."""
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def resolved(p: str) -> str:
    """The canonical, long, link-resolved form MXC gets (the very form grant_problem checked)."""
    c, why = canonical_path(p)
    return _real(c if not why else p)


def grant_problem(path: str, mode: str, *, profile_root: str, profiles_root: str, system_dir: str,
                  protected_write: list[str] = (), protected_any: list[str] = ()) -> str:
    """'' when `path` may be granted with `mode` ('modify' | 'read') to the member whose profile is `profile_root`,
    else why not. Compared in canonical form (canonical_path: \\\\?\\, case, trailing dots/spaces, '/') and after
    resolving links (junctions, symlinks, 8.3 names); UNC and device paths are refused (MX-6)."""
    if not path:
        return "not an absolute path"
    canon, why = canonical_path(path)
    if why:
        return why
    real = _real(canon)
    if real.startswith("\\\\"):
        return "it resolves to a network (UNC) or device path"
    for c in (canon, real):
        drive, rest = os.path.splitdrive(c)
        if rest in ("", "\\", "/"):
            return "a drive or share root"
    forms = {_norm(canon), _norm(real)}
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


_READ_DIR_LOGGED: set[tuple[str, str]] = set()


def read_dir_problems(settings, native_roots: list[str] | None = None) -> list[tuple[str, str]]:
    """[(read_dir, why)] for `sandbox.read_dirs` entries no member may be granted, whatever the backend (MX-6): the
    gateway's system folder or above, the profiles root or above, anything inside it but the team folders, the native
    Goose profile, UNC and device paths - in any spelling. Each is logged once and left out of every member's
    sandbox (context.Ctx.sandbox_spec); `sandbox status` and `check` list them."""
    from .config import default_native_goose_root
    natives = [p for p in [default_native_goose_root(), *(native_roots or [])] if p]
    ctx = dict(profile_root=os.path.join(str(settings.profiles_root), "_teams"), profiles_root=str(settings.profiles_root),
               system_dir=str(settings.system_dir), protected_write=[], protected_any=natives)
    out = []
    for d in [str(x) for x in (settings.get("sandbox", "read_dirs") or []) if x]:
        why = grant_problem(d, "read", **ctx)
        if why:
            out.append((d, why))
            if (d, why) not in _READ_DIR_LOGGED:
                _READ_DIR_LOGGED.add((d, why))
                log.error("sandbox: sandbox.read_dirs entry %r is never granted to members: %s", d, why)
    return out


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


def _link_names(path: str) -> list[str]:
    """Every name of the file at `path` (all its hard links), as full paths (Windows: FindFirstFileNameW)."""
    if not IS_WINDOWS:
        return [path]
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.FindFirstFileNameW.restype = wintypes.HANDLE
    k32.FindFirstFileNameW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                       wintypes.LPWSTR]
    k32.FindNextFileNameW.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
    k32.FindClose.argtypes = [wintypes.HANDLE]
    drive = os.path.splitdrive(_strip_prefix(os.path.abspath(path)))[0]
    out: list[str] = []
    n = wintypes.DWORD(32768)
    buf = ctypes.create_unicode_buffer(32768)
    h = k32.FindFirstFileNameW(path, 0, ctypes.byref(n), buf)
    if not h or h == wintypes.HANDLE(-1).value:
        return [path]
    try:
        while True:
            out.append(drive + buf.value)
            n = wintypes.DWORD(32768)
            if not k32.FindNextFileNameW(h, ctypes.byref(n), buf):
                break
            if len(out) >= 64:
                break
    finally:
        k32.FindClose(h)
    return out


def hardlink_escapes(rw_paths: list[str], seconds: float = HARDLINK_SCAN_SECONDS,
                     max_entries: int = HARDLINK_SCAN_ENTRIES) -> tuple[list[tuple[str, str]], bool, int]:
    """MX-3: files in the read/write folders `rw_paths` that are hard-linked to a name outside all of them.
    MXC grants are path policy: such a link reads and writes a file outside every grant (links can only be made
    outside MXC - by an agent on the AppContainer backend/fallback, or on the host). Bounded walk (`seconds`,
    `max_entries`), reparse points (junctions, symlinks, mount points) not followed.
    Returns ([(file, outside name)] - at most 20, complete, entries seen)."""
    roots = [_norm(_real(p)) for p in rw_paths if p]
    found: list[tuple[str, str]] = []
    end = time.monotonic() + seconds
    seen = 0
    stack = list(rw_paths)
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
                    return found, False, seen
                try:
                    # FILE_ATTRIBUTE_REPARSE_POINT covers junctions, symlinks and mount points on every Python
                    # (DirEntry.is_junction() exists only from 3.12; Goose Web supports 3.11).
                    if e.is_symlink() or getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
                        continue
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                        continue
                    if not e.is_file(follow_symlinks=False) or os.lstat(e.path).st_nlink < 2:
                        continue
                    for other in _link_names(e.path):
                        if not any(_under(_norm(other), r) for r in roots):
                            found.append((e.path, other))
                            break
                    if len(found) >= 20:
                        return found, True, seen
                except OSError:
                    continue
    return found, True, seen


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
    """Start `wxc-exec <policy>` with stdin/stdout pipes (start_verified)."""
    return start_verified(Path(exe), [str(policy_file)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=stderr_file, jobs=jobs)


def start_verified(exe: Path, args: list[str], *, stdin, stdout, stderr, jobs: list) -> subprocess.Popen:
    """The one way the executor is started (worker launch and --probe). Every pinned file of its folder is opened
    with writes/deletes/renames denied and hashed through that handle, and the folder must hold nothing else
    (MX-8); the handles stay open until the process runs. On Windows it is created suspended with the image-load
    mitigations (EXEC_MITIGATIONS), put in every job of `jobs` (kill-on-close: the gateway's, then the worker's) -
    a job it cannot join kills it and fails the start (MX-9) -, the folder is checked once more, and only then it is
    resumed, so nothing it starts can run outside the jobs."""
    exe = Path(exe)
    vdir = exe.parent
    if exe.name.lower() != str(MXC_PIN["exe"]).lower():
        raise MxcError(f"{exe} is not the pinned executor {MXC_PIN['exe']}")
    problem = folder_problem(vdir)
    if problem:
        AVAILABILITY.mark_failed(problem)
        raise MxcError(problem)
    try:
        pins = PinnedSet(vdir)
    except OSError as e:
        problem = f"{exe} cannot be opened for verification ({e})"
        AVAILABILITY.mark_failed(problem)
        raise MxcError(problem) from e
    with pins:
        problem = pins.problem() or folder_problem(vdir)
        if problem:
            AVAILABILITY.mark_failed(problem)
            raise MxcError(problem)
        flags = (0x08000000 | 0x00000004) if IS_WINDOWS else 0   # CREATE_NO_WINDOW | CREATE_SUSPENDED
        popen = _HardenedPopen if IS_WINDOWS else subprocess.Popen
        proc = popen([str(exe), *args], stdin=stdin, stdout=stdout, stderr=stderr, env=host_env(),  # nosec B603
                     creationflags=flags, cwd=os.environ.get("SystemRoot") if IS_WINDOWS else None)
        if not IS_WINDOWS:
            return proc
        try:
            for j in jobs:
                if j is None or not j.add(proc):
                    raise MxcError("wxc-exec could not be put in a kill-on-close job; it is not started (a container "
                                   "outside the job could outlive the gateway)")
            problem = folder_problem(vdir)      # nothing appeared next to it while it was created (still suspended)
            if problem:
                AVAILABILITY.mark_failed(problem)
                raise MxcError(problem)
            _resume(proc)
        except BaseException:
            _kill_quietly(proc)
            raise
    return proc


def _resume(proc: subprocess.Popen) -> None:
    import ctypes
    from ctypes import wintypes
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    rc = ntdll.NtResumeProcess(int(proc._handle))  # type: ignore[attr-defined]
    if rc != 0:
        raise MxcError(f"wxc-exec could not be resumed (NTSTATUS 0x{rc & 0xFFFFFFFF:08X})")


def _kill_quietly(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:
        pass
    for s in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if s is not None:
                s.close()
        except Exception:
            pass


if IS_WINDOWS:
    class _HardenedPopen(subprocess.Popen):
        """subprocess.Popen whose CreateProcessW gets a PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (EXEC_MITIGATIONS)
        and an explicit handle list (only the child's standard handles are inherited). Everything else - pipes,
        wait(), kill(), communicate() - is Popen's own (MX-8)."""

        def _execute_child(self, args, executable, preexec_fn, close_fds, pass_fds, cwd, env, startupinfo,
                           creationflags, shell, p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite, *unused):
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class STARTUPINFOW(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                            ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                            ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                            ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

            class STARTUPINFOEXW(ctypes.Structure):
                _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

            k32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                              ctypes.POINTER(ctypes.c_size_t)]
            k32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t,
                                                      ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                                      ctypes.c_void_p]
            k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
            k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p,
                                           wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                           ctypes.c_void_p, ctypes.c_void_p]
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            app = os.fsdecode(executable) if executable is not None else (
                os.fsdecode(args[0]) if not isinstance(args, (str, bytes)) else None)
            cmd = args if isinstance(args, str) else subprocess.list2cmdline(args)
            handles = self._filter_handle_list([int(h) for h in (p2cread, c2pwrite, errwrite)
                                                if h is not None and int(h) != -1])
            attrs = ctypes.c_void_p()
            size = ctypes.c_size_t(0)
            buf = None
            try:
                k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
                buf = ctypes.create_string_buffer(size.value)
                if not k32.InitializeProcThreadAttributeList(buf, 2, 0, ctypes.byref(size)):
                    raise ctypes.WinError(ctypes.get_last_error())
                attrs = ctypes.cast(buf, ctypes.c_void_p)
                policy = ctypes.c_uint64(EXEC_MITIGATIONS)
                if not k32.UpdateProcThreadAttribute(attrs, 0, 0x00020007, ctypes.byref(policy),
                                                     ctypes.sizeof(policy), None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
                harr = (wintypes.HANDLE * max(1, len(handles)))(*handles)
                if handles and not k32.UpdateProcThreadAttribute(attrs, 0, 0x00020002, harr,
                                                                 ctypes.sizeof(wintypes.HANDLE) * len(handles),
                                                                 None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
                si = STARTUPINFOEXW()
                si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
                if -1 not in (p2cread, c2pwrite, errwrite):
                    si.StartupInfo.dwFlags = 0x100                       # STARTF_USESTDHANDLES
                    si.StartupInfo.hStdInput = int(p2cread)
                    si.StartupInfo.hStdOutput = int(c2pwrite)
                    si.StartupInfo.hStdError = int(errwrite)
                si.lpAttributeList = attrs
                block = None
                if env is not None:
                    text = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
                    block = (ctypes.c_wchar * len(text))(*text)
                cmdbuf = ctypes.create_unicode_buffer(cmd)
                pi = PROCESS_INFORMATION()
                flags = int(creationflags) | 0x00080000 | 0x00000400   # EXTENDED_STARTUPINFO_PRESENT | UNICODE_ENV
                cwd_s = os.fsdecode(cwd) if cwd is not None else None
                if not k32.CreateProcessW(app, cmdbuf, None, None, bool(handles), flags, block, cwd_s,
                                          ctypes.byref(si), ctypes.byref(pi)):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                if attrs.value:
                    k32.DeleteProcThreadAttributeList(attrs)
                self._close_pipe_fds(p2cread, p2cwrite, c2pread, c2pwrite, errread, errwrite)
            self._child_created = True
            self._handle = subprocess.Handle(pi.hProcess)
            self.pid = pi.dwProcessId
            k32.CloseHandle(pi.hThread)


def process_mitigations(proc: subprocess.Popen) -> dict:
    """The image-load / signature mitigations of a running process (Windows; for checks and tests)."""
    if not IS_WINDOWS:
        return {}
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetProcessMitigationPolicy.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    sig, img = wintypes.DWORD(), wintypes.DWORD()
    h = int(proc._handle)  # type: ignore[attr-defined]
    ok1 = k32.GetProcessMitigationPolicy(h, 8, ctypes.byref(sig), 4)      # ProcessSignaturePolicy
    ok2 = k32.GetProcessMitigationPolicy(h, 10, ctypes.byref(img), 4)     # ProcessImageLoadPolicy
    return {"microsoftSignedOnly": bool(ok1 and sig.value & 1), "noRemoteImages": bool(ok2 and img.value & 1),
            "preferSystem32Images": bool(ok2 and img.value & 4)}


# ------------------------------------------------------------------ errors
NTSTATUS_TEXT = {
    0xC0000142: "a program in the container could not initialise (STATUS_DLL_INIT_FAILED: Win32k blocked or a DLL "
                "missing in the container's readable folders)",
    0xC0000022: "access denied while starting the container (STATUS_ACCESS_DENIED)",
    0xC0000135: "a DLL the program needs is not readable in the container (STATUS_DLL_NOT_FOUND)",
    0xC000013A: "the container was stopped (STATUS_CONTROL_C_EXIT)",
}


def explain_exit(code: int | None, stderr_text: str) -> str:
    """A readable reason for a wxc-exec that ended early, from its exit code and the stderr it wrote. The stderr is
    written by the container side too, so it is shown as text only, one line, control characters escaped (MX-5;
    the admin UI escapes it as HTML as well)."""
    from .activity import clean_text
    for line in reversed([x.strip() for x in (stderr_text or "").splitlines() if x.strip()]):
        if line.startswith("{") and '"error"' in line:
            try:
                err = json.loads(line)["error"]
                return (f"MXC refused to start the sandbox ({clean_text(err.get('code'), 60)}): "
                        f"{clean_text(err.get('message'), 400)}")
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    c = (code or 0) & 0xFFFFFFFF
    if c in NTSTATUS_TEXT:
        return NTSTATUS_TEXT[c]
    tail = [x.strip() for x in (stderr_text or "").splitlines() if x.strip()][-1:]
    return f"wxc-exec exited with code {code}" + (f": {clean_text(tail[0], 300)}" if tail else "")
