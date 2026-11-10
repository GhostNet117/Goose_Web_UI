"""Prompt Guard 2 22M model package: where it lives, where it comes from, and how it is installed (spec 018 R2).

The package is a zip built by scripts/export-prompt-guard.py from the official, gated Hugging Face repository
meta-llama/Llama-Prompt-Guard-2-22M (pinned revision): model.onnx, tokenizer.json, config.json, LICENSE (Llama 4
Community License), USE_POLICY.md, NOTICE, README.md ("Built with Llama") and export.json (provenance and the SHA-256
of every file). It is installed into <system_dir>/models/prompt-guard-2-22m/.

The download source is pinned in MODEL_PIN (URL + SHA-256 of the zip) and can be overridden with guard.model_url /
guard.model_sha256 in config.yaml. Nothing is installed without a trusted SHA-256: the pin, the config value, or a
hash the administrator types for a local file (`goose-web guard install-model --file X.zip --sha256 HEX`).
The gateway never downloads anything at run time; only the install command (and the installers that call it) does.
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
# The published package (a release asset of the Goose Web repository, see docs/ADMINISTRATION.md "Prompt guard").
# Empty until the maintainer has exported and published it: the official weights are gated, so there is no
# anonymous, licence-compliant source to pin yet. guard.model_url / guard.model_sha256 in config.yaml override this.
MODEL_PIN: dict[str, str] = {"url": "", "sha256": ""}
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
    url = str(settings.get("guard", "model_url") or "").strip() or MODEL_PIN["url"]
    sha = str(settings.get("guard", "model_sha256") or "").strip().lower() or MODEL_PIN["sha256"]
    return {"url": url, "sha256": sha}


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
                    exported=meta.get("exported"), parameters=meta.get("parameters"))
        cfg = json.loads((d / "config.json").read_text(encoding="utf-8"))
        info["proxy"] = bool(cfg.get("proxy"))
    except (OSError, ValueError):
        pass
    p = pin(settings)
    info["pin"] = {"url": p["url"], "sha256": p["sha256"], "published": bool(p["url"] and p["sha256"])}
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


def download(url: str, dest: Path, *, timeout: float = 120) -> None:
    """HTTPS download with a size cap (installers / CLI only; never at gateway run time)."""
    import httpx
    if not url.lower().startswith("https://"):
        raise InstallError("the model URL must be https://")
    n = 0
    with httpx.stream("GET", url, follow_redirects=True, timeout=timeout) as r:   # GitHub assets redirect to a CDN
        if r.status_code != 200:
            raise InstallError(f"download failed: HTTP {r.status_code}")
        with open(dest, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                n += len(chunk)
                if n > MAX_ZIP_BYTES:
                    raise InstallError("the download is larger than expected")
                f.write(chunk)


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
            raise InstallError("give the package's SHA-256 with --sha256 (no published package is pinned yet)")
    else:
        if not (p["url"] and p["sha256"]):
            raise InstallError(
                "no published Prompt Guard package is pinned yet: the official weights are gated on Hugging Face "
                "(Llama 4 Community License). An administrator who accepted the licence can build the package with "
                "scripts/export-prompt-guard.py and install it with --file and --sha256, or set guard.model_url and "
                "guard.model_sha256 in config.yaml. See docs/ADMINISTRATION.md, Prompt guard.")
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
            log(f"Downloading the Prompt Guard model package from {p['url']}")
            download(p["url"], zpath)
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
