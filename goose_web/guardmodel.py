"""Prompt Guard 2 22M model package: where it lives, where it comes from, and how it is installed (spec 018 R2).

The package is a zip built by scripts/export-prompt-guard.py from Meta's release of
meta-llama/Llama-Prompt-Guard-2-22M (pinned revision, every source file checked against Meta's SHA-256): model.onnx,
tokenizer.json, config.json, LICENSE (Llama 4 Community License), USE_POLICY.md, NOTICE, README.md ("Built with
Llama") and export.json (provenance and the SHA-256 of every file). It is installed into
<system_dir>/models/prompt-guard-2-22m/.

The package is published as an asset of a dedicated GitHub release of the Goose Web repository (tag MODEL_RELEASE,
independent of app versions, so the URL does not change) and pinned in MODEL_PIN (URL, SHA-256, size). It can be
overridden with guard.model_url / guard.model_sha256 in config.yaml. Nothing is installed without a trusted SHA-256:
the pin, the config value, or a hash the administrator types for a local file (`goose-web guard install-model --file
X.zip [--sha256 HEX]`; without --sha256 the pinned hash applies, so the published zip copied by hand works offline).
The download honours the standard proxy environment (HTTPS_PROXY / NO_PROXY), retries transient failures and is
cut off at the pinned size. The gateway never downloads anything at run time; only the install command (and the
installers that call it) does.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

MODEL_DIR_NAME = "prompt-guard-2-22m"
HF_REPO = "meta-llama/Llama-Prompt-Guard-2-22M"
HF_REVISION = "11614a155199674a0a95e6602d6ab0417b790ed0"
# The published package: an asset of the release MODEL_RELEASE of the Goose Web repository (see
# docs/ADMINISTRATION.md "Prompt guard"; published 2026-11-10, spec 018). guard.model_url / guard.model_sha256 in
# config.yaml override it (then the size is not known in advance). A new package = a new release tag + a new pin.
MODEL_RELEASE = "prompt-guard-2-22m-onnx-1"
MODEL_PIN: dict[str, Any] = {
    "url": "https://github.com/GhostNet117/Goose_Web_UI/releases/download/" + MODEL_RELEASE +
           "/Llama-Prompt-Guard-2-22M-onnx-int8emb-11614a15.zip",
    "sha256": "76d04f9014c82fbf28e51645272c974ca9273ad93512a36b9ef858e4e851eab3",
    "size": 116_747_849,
    "revision": HF_REVISION,
}
DOWNLOAD_ATTEMPTS = 3                     # network errors and HTTP 5xx/429 are retried
DOWNLOAD_RETRY_WAIT = (5.0, 15.0)         # seconds before the 2nd and 3rd attempt
_TRANSPORT = None                         # tests inject an httpx.MockTransport (no network in tests)
REQUIRED = ("model.onnx", "tokenizer.json", "config.json", "LICENSE", "NOTICE", "export.json")
MAX_ZIP_BYTES = 1024 * 1024 * 1024        # 1 GiB download/zip cap
MAX_MEMBER_BYTES = 900 * 1024 * 1024      # model.onnx fp32 is ~284 MB; the default (int8 embeddings) ~137 MB
ALLOWED_MEMBERS = set(REQUIRED) | {"USE_POLICY.md", "README.md", "MODEL_CARD.md"}


class InstallError(Exception):
    pass


def model_dir(settings) -> Path:
    d = str(settings.get("guard", "model_dir") or "").strip()
    return Path(d) if d else Path(settings.system_dir) / "models" / MODEL_DIR_NAME


def pin(settings) -> dict:
    """The package source: config.yaml guard.model_url (+ model_sha256) if set, else MODEL_PIN."""
    url = str(settings.get("guard", "model_url") or "").strip()
    sha = str(settings.get("guard", "model_sha256") or "").strip().lower()
    if url or sha:
        return {"url": url, "sha256": sha, "size": 0, "revision": "", "source": "config"}
    return {"url": MODEL_PIN["url"], "sha256": MODEL_PIN["sha256"], "size": int(MODEL_PIN.get("size") or 0),
            "revision": MODEL_PIN.get("revision") or "", "source": "pinned"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _hex(s: str) -> str:
    s = str(s or "").strip().lower()
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise InstallError("a SHA-256 is 64 hexadecimal characters")
    return s


def verify_dir(d: Path, *, deep: bool = False) -> str:
    """'' if the installed package is complete and (deep: every file matches export.json) intact, else the problem.
    The quick check compares sizes, the deep one hashes every file (CLI status, install)."""
    d = Path(d)
    missing = [f for f in REQUIRED if not (d / f).is_file()]
    if missing:
        return f"the model folder {d} lacks {', '.join(missing)}"
    try:
        meta = json.loads((d / "export.json").read_text(encoding="utf-8"))
        files = meta.get("files") or {}
    except (OSError, ValueError):
        return "export.json cannot be read"
    if "86m" in str(meta.get("model", "")).lower():
        return "this is the 86M model; Goose Web uses the 22M model only"
    for name, info in files.items():
        p = d / name
        if name == "export.json" or not isinstance(info, dict):
            continue
        if not p.is_file():
            return f"{name} is missing"
        if int(info.get("bytes", -1)) != p.stat().st_size:
            return f"{name} has the wrong size (damaged or changed)"
        if deep and str(info.get("sha256", "")).lower() != sha256_file(p):
            return f"{name} does not match its SHA-256 in export.json (damaged or changed)"
    if "model.onnx" not in files:
        return "export.json lists no model.onnx"
    return ""


def describe(settings) -> dict:
    d = model_dir(settings)
    info: dict[str, Any] = {"dir": str(d), "installed": (d / "model.onnx").is_file()}
    try:
        meta = json.loads((d / "export.json").read_text(encoding="utf-8"))
        info.update(model=meta.get("model"), revision=meta.get("revision"), quantization=meta.get("quantization"),
                    exported=meta.get("exported"), parameters=meta.get("parameters"),
                    package_sha256=meta.get("package_sha256"))
        cfg = json.loads((d / "config.json").read_text(encoding="utf-8"))
        info["proxy"] = bool(cfg.get("proxy"))
    except (OSError, ValueError):
        pass
    p = pin(settings)
    info["pin"] = {"url": p["url"], "sha256": p["sha256"], "size": p["size"], "revision": p["revision"],
                   "source": p["source"], "published": bool(p["url"] and p["sha256"])}
    return info


def _safe_extract(zpath: Path, dest: Path) -> None:
    with zipfile.ZipFile(zpath) as z:
        total = 0
        for zi in z.infolist():
            name = zi.filename
            if zi.is_dir():
                continue
            if "/" in name or "\\" in name or name.startswith(".") or ":" in name or name not in ALLOWED_MEMBERS:
                raise InstallError(f"unexpected file in the package: {name[:100]!r}")
            if zi.file_size > MAX_MEMBER_BYTES:
                raise InstallError(f"{name} is too large")
            total += zi.file_size
            if total > MAX_ZIP_BYTES:
                raise InstallError("the package is too large")
            with z.open(zi) as src, open(dest / name, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 20)


class _Retry(Exception):
    """A transient download failure (HTTP 5xx/429, a cut-off transfer): try again."""


BLOCKED_HINT = ("If a proxy or firewall blocks the download, set HTTPS_PROXY (for example "
                "http://proxy.example:8080) for this command, or download the zip on another computer and run "
                "goose-web guard install-model --file <zip> (docs/ADMINISTRATION.md, Prompt guard).")


def _mb(n: int) -> str:
    return f"{n / 1e6:.1f} MB"


def _download_once(url: str, dest: Path, *, expected_size: int, timeout: float, log) -> None:
    import httpx
    from . import __version__
    cap = expected_size or MAX_ZIP_BYTES
    n = 0
    # trust_env (the default) = HTTPS_PROXY / ALL_PROXY / NO_PROXY and the system CA settings apply.
    with httpx.Client(transport=_TRANSPORT, follow_redirects=True, trust_env=True,
                      timeout=httpx.Timeout(timeout, connect=30.0),
                      headers={"User-Agent": f"goose-web/{__version__} (prompt guard model install)"}) as client:
        with client.stream("GET", url) as r:          # GitHub release assets redirect to a CDN
            if r.url.scheme != "https":
                raise InstallError("the download was redirected to a non-https address; refused")
            if r.status_code == 429 or r.status_code >= 500:
                raise _Retry(f"HTTP {r.status_code}")
            if r.status_code != 200:
                raise InstallError(f"download failed: HTTP {r.status_code} from {url}")
            try:
                announced = int(r.headers.get("content-length") or 0)
            except ValueError:
                announced = 0
            if expected_size and announced and announced != expected_size:
                raise InstallError(f"the server offers {announced:,} bytes, the pinned package has {expected_size:,} "
                                   "bytes; nothing was installed")
            total = expected_size or announced
            step = max(total // 10, 1) if total else 20_000_000
            next_report = step
            with open(dest, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    n += len(chunk)
                    if n > cap:
                        raise InstallError("the download is larger than the pinned package; nothing was installed")
                    f.write(chunk)
                    if n >= next_report:
                        log(f"  {_mb(n)}" + (f" of {_mb(total)} ({100 * n // total}%)" if total else ""))
                        next_report += step
    if expected_size and n != expected_size:
        raise _Retry(f"the transfer stopped after {n:,} of {expected_size:,} bytes")


def download(url: str, dest: Path, *, expected_size: int = 0, timeout: float = 60, log=print,
             attempts: int = DOWNLOAD_ATTEMPTS) -> None:
    """HTTPS download with a size cap, retries and progress (installers / CLI only; never at gateway run time).
    `timeout` applies to each read (no data for that long = a failed attempt), not to the whole transfer."""
    import httpx
    if not url.lower().startswith("https://"):
        raise InstallError("the model URL must be https://")
    last = ""
    for attempt in range(1, max(1, attempts) + 1):
        try:
            _download_once(url, dest, expected_size=expected_size, timeout=timeout, log=log)
            return
        except _Retry as e:
            last = str(e)
        except httpx.TransportError as e:            # DNS, connect, TLS, proxy, timeouts, a dropped connection
            last = f"{e.__class__.__name__}: {e}" if str(e) else e.__class__.__name__
        if attempt < attempts:
            wait = DOWNLOAD_RETRY_WAIT[min(attempt - 1, len(DOWNLOAD_RETRY_WAIT) - 1)]
            log(f"Download attempt {attempt} of {attempts} failed ({last}); trying again in {wait:.0f} s.")
            time.sleep(wait)
    raise InstallError(f"the download failed after {attempts} attempt(s) ({last}). {BLOCKED_HINT}")


def _rmtree(p: Path) -> None:
    def onerr(func, path, _exc):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except OSError:
            pass
    if not p.exists():
        return
    import sys
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=onerr)
    else:   # Python 3.11
        shutil.rmtree(p, onerror=onerr)


def install(settings, *, file: str | None = None, sha256: str | None = None, force: bool = False,
            log=print) -> dict:
    """Install the model package (download from the pin, or a local zip) after verifying its SHA-256.
    Returns describe(). Raises InstallError with a message for the administrator."""
    d = model_dir(settings)
    p = pin(settings)
    if file:
        expected = _hex(sha256) if sha256 else p["sha256"]
        if not expected:
            raise InstallError("give the package's SHA-256 with --sha256 (guard.model_url is set without "
                               "guard.model_sha256 in config.yaml)")
    else:
        if not (p["url"] and p["sha256"]):
            raise InstallError(
                "no package source: guard.model_url and guard.model_sha256 in config.yaml must be set together "
                "(or remove both to use the published package), or install a local zip with --file. See "
                "docs/ADMINISTRATION.md, Prompt guard.")
        expected = _hex(p["sha256"])
    if not force and not verify_dir(d):
        try:
            meta = json.loads((d / "export.json").read_text(encoding="utf-8"))
            if meta.get("package_sha256") == expected:
                log(f"The Prompt Guard model is already installed in {d}.")
                return describe(settings)
        except (OSError, ValueError):
            pass
    d.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".pg-install-", dir=str(d.parent)))
    try:
        zpath = stage / "package.zip"
        if file:
            src = Path(file)
            if not src.is_file():
                raise InstallError(f"{file} not found")
            if src.stat().st_size > MAX_ZIP_BYTES:
                raise InstallError("the package is too large")
            shutil.copyfile(src, zpath)
        else:
            log("Downloading the Prompt Guard model package" + (f" ({_mb(p['size'])})" if p["size"] else "") +
                f" from {p['url']}")
            download(p["url"], zpath, expected_size=p["size"], log=log)
            log("Downloaded; checking its SHA-256.")
        got = sha256_file(zpath)
        if got != expected:
            raise InstallError(f"SHA-256 mismatch: expected {expected}, got {got}. Nothing was installed.")
        new = stage / "pkg"
        new.mkdir()
        _safe_extract(zpath, new)
        problem = verify_dir(new, deep=True)
        if problem:
            raise InstallError(f"the package is not valid: {problem}")
        meta_p = new / "export.json"
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        meta["package_sha256"] = expected
        meta["installed"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        meta_p.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        old = d.with_name(d.name + ".old")
        _rmtree(old)
        if d.exists():
            os.replace(d, old)
        os.replace(new, d)
        _rmtree(old)
        log(f"Installed the Prompt Guard model in {d} (package SHA-256 {expected}).")
        return describe(settings)
    finally:
        _rmtree(stage)


def remove(settings) -> bool:
    d = model_dir(settings)
    if not d.exists():
        return False
    _rmtree(d)
    return True
