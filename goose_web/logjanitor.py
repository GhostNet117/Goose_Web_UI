"""Log budget (spec 015): keep every log Goose Web writes under logs.max_disk_percent of the disk volume.

Covered files:
- the gateway's own logs: <system_dir>/logs/** (gateway.log, activity.jsonl, worker-<user>.log and their
  rotated copies, relay logs);
- the Goose logs of the isolated profiles Goose Web created: <profiles_root>/<user>/state/logs/** and
  .../data/logs/** (Goose's own per-day logs);
- optionally (logs.include_native_goose_logs) the native profile's Goose logs, which Goose Desktop and the CLI
  also write - off by default because they are not Goose Web's files.

Sizes are the space a file really takes on disk (the smaller of its length and its allocated size:
GetCompressedFileSizeW on Windows, st_blocks on POSIX), so a sparse file that claims 500 GB but holds 64 KB
counts as 64 KB.

Every run (at start and then every logs.check_minutes): a worker log that alone grows beyond its share is copied
to <name>.1 and emptied in place ("copytruncate": goose keeps writing into the same open file). Then, if the total
is above the budget, files are deleted until the total is below 90 % of it, one at a time: always the oldest file
that is not in use of the OWNER that uses the most space right now. Owners: the gateway's logs, each profile
(its state/logs and data/logs together), the native profile. So a user's logs only ever displace that user's own
logs (or nothing): the gateway's and other users' files are deleted only when their owner is the largest. If the
largest owner has nothing left that may be deleted (all in use or written in the last 5 minutes), the run stops
with a warning instead of deleting anybody else's files.

Only files that really live inside a root are touched: directories that are junctions, symbolic links or other
reparse points are not entered, a root that is itself redirected somewhere else is skipped, and right before a
file is deleted or truncated its real path must still be inside the real path of the root it was found under.
Apart from those log files, the only thing pruned is the audit table in the database (logs.audit_days and
logs.audit_max_rows).
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
import time
from pathlib import Path

log = logging.getLogger("goose_web.logs")
ACTIVE_NAMES = {"gateway.log", "activity.jsonl"}
LOG_SUFFIXES = (".log", ".jsonl", ".txt", ".out", ".err")
RECENT_SECONDS = 300           # a file written in the last 5 minutes is treated as in use
GATEWAY = "gateway"            # owner of <system_dir>/logs
_REPARSE = 0x400               # FILE_ATTRIBUTE_REPARSE_POINT

if sys.platform == "win32":  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetCompressedFileSizeW.restype = wintypes.DWORD


def budget_bytes(settings) -> int:
    pct = float(settings.get("logs", "max_disk_percent") or 0.5)
    pct = min(max(pct, 0.01), 50.0)
    root = Path(settings.system_dir)
    root.mkdir(parents=True, exist_ok=True)
    return int(shutil.disk_usage(str(root)).total * pct / 100)


def _is_log(p: Path) -> bool:
    name = p.name.lower()
    if name.endswith(LOG_SUFFIXES):
        return True
    stem, _, num = name.rpartition(".")            # rotated copies: gateway.log.3, activity.jsonl.10
    return num.isdigit() and stem.endswith(LOG_SUFFIXES)


def is_link(path: str | Path) -> bool:
    """True for a symbolic link, a junction or any other reparse point (not followed by the janitor), and for a
    path that cannot be examined."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        return True
    isjunction = getattr(os.path, "isjunction", None)
    return bool(isjunction and isjunction(path))


def allocated_size(path: str | Path, st: os.stat_result | None = None) -> int:
    """Bytes the file really occupies: min(length, allocated size). Sparse (and compressed) files count with what
    is on disk, not with the length they claim."""
    st = st or os.stat(path)
    size = st.st_size
    if sys.platform == "win32":
        high = wintypes.DWORD(0)
        ctypes.set_last_error(0)
        low = _k32.GetCompressedFileSizeW(str(path), ctypes.byref(high))
        if low == 0xFFFFFFFF and ctypes.get_last_error():
            return size
        return min(size, (high.value << 32) | low)
    blocks = getattr(st, "st_blocks", None)
    return size if blocks is None else min(size, blocks * 512)


def _norm(p: str | Path) -> str:
    return os.path.normcase(os.path.realpath(str(p)))


def _inside(path: str | Path, real_root: str) -> bool:
    rp = _norm(path)
    return rp.startswith(real_root.rstrip("\\/") + os.sep) and not is_link(path)


def _root_specs(settings, native_root: str | None = None) -> list[tuple[Path, str, Path]]:
    """(root, owner, base) for every log folder; `root` is base/<relative part>."""
    sysd = Path(settings.system_dir)
    out = [(sysd / "logs", GATEWAY, sysd)]
    pr = Path(settings.profiles_root)
    try:
        for d in sorted(pr.iterdir()):
            if d.is_dir() and not d.name.startswith("_"):
                out += [(d / "state" / "logs", f"profile:{d.name}", pr), (d / "data" / "logs", f"profile:{d.name}", pr)]
    except OSError:
        pass
    if native_root and settings.get("logs", "include_native_goose_logs"):
        nr = Path(native_root)
        out += [(nr / "state" / "logs", "native", nr), (nr / "data" / "logs", "native", nr)]
    return out


def _valid_roots(settings, native_root: str | None = None) -> list[tuple[Path, str, str]]:
    """(root, owner, real root) of the log folders that exist and are not redirected: the real path of a root must
    be the real path of its base plus the same relative path (a profile's state\\logs, or state itself, made a
    junction to another folder is skipped)."""
    out = []
    for root, owner, base in _root_specs(settings, native_root):
        if not root.is_dir():
            continue
        try:
            rel = os.path.relpath(str(root), str(base))
        except ValueError:
            continue
        real = _norm(root)
        if real != os.path.normcase(os.path.join(_norm(base), rel)):
            log.warning("log budget: %s is redirected to %s; not scanned", root, os.path.realpath(str(root)))
            continue
        out.append((root, owner, real))
    return out


def roots(settings, native_root: str | None = None) -> list[Path]:
    return [r for r, _, _ in _valid_roots(settings, native_root)]


def scan(settings, native_root: str | None = None) -> list[dict]:
    files = []
    for r, owner, real in _valid_roots(settings, native_root):
        for dirpath, dirs, names in os.walk(r, followlinks=False):
            dirs[:] = [d for d in dirs if not is_link(os.path.join(dirpath, d))]   # never enter a junction/link
            for n in names:
                p = Path(dirpath) / n
                if not _is_log(p):
                    continue
                try:
                    st = os.lstat(p)
                    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
                        continue
                    size = allocated_size(p, st)
                except OSError:
                    continue
                files.append({"path": p, "size": size, "mtime": st.st_mtime, "owner": owner, "root": real})
    return files


def usage(settings, native_root: str | None = None) -> dict:
    files = scan(settings, native_root)
    return {"bytes": sum(f["size"] for f in files), "files": len(files), "budget": budget_bytes(settings),
            "percent": float(settings.get("logs", "max_disk_percent") or 0.5),
            "roots": [str(r) for r in roots(settings, native_root)]}


def _copytruncate(p: Path) -> bool:
    """Move the content of a log another process keeps open to <name>.1 and empty the original."""
    try:
        bak = p.with_name(p.name + ".1")
        if bak.exists():
            bak.unlink()
        shutil.copyfile(p, bak)
        with open(p, "r+b") as fh:
            fh.truncate(0)
        return True
    except OSError as e:
        log.warning("could not truncate %s: %s", p, e)
        return False


def enforce(settings, native_root: str | None = None, in_use: set[str] | None = None, now: float | None = None) -> dict:
    """Bring the logs under the budget (see the module docstring). Returns a report."""
    now = now or time.time()
    budget = budget_bytes(settings)
    files = scan(settings, native_root)
    total = sum(f["size"] for f in files)
    in_use = {os.path.normcase(str(p)) for p in (in_use or set())}
    report = {"before": total, "budget": budget, "deleted": 0, "freed": 0, "truncated": 0}
    # 1. A single active worker/relay log above its share of the budget: copytruncate it.
    share = max(budget // 10, 1024 * 1024)
    for f in files:
        p = f["path"]
        if f["size"] > share and os.path.normcase(str(p)) in in_use and p.name not in ACTIVE_NAMES \
                and _inside(p, f["root"]):
            if _copytruncate(p):
                report["truncated"] += 1
                f["size"] = 0
    total = sum(f["size"] for f in files)
    if total > budget:
        goal = int(budget * 0.9)
        owner_use: dict[str, int] = {}
        candidates: dict[str, list[dict]] = {}
        for f in files:
            owner_use[f["owner"]] = owner_use.get(f["owner"], 0) + f["size"]
            if p_free(f, in_use, now):
                candidates.setdefault(f["owner"], []).append(f)
        for lst in candidates.values():
            lst.sort(key=lambda f: f["mtime"], reverse=True)          # oldest last: pop() takes it
        while total > goal:
            # the owner using the most space right now; on a tie the gateway's own logs go last
            owner = max(owner_use, key=lambda o: (owner_use[o], o != GATEWAY))
            if not candidates.get(owner):
                log.warning("log budget: %s uses the most log space (%d MB) and has nothing that may be deleted "
                            "now; other owners' logs are left alone", owner, owner_use[owner] // 2**20)
                break
            f = candidates[owner].pop()
            if not _inside(f["path"], f["root"]):
                log.warning("log budget: %s is no longer inside %s; not deleted", f["path"], f["root"])
                continue
            try:
                f["path"].unlink()
            except OSError:
                continue            # still open (Windows) or already gone
            total -= f["size"]
            owner_use[owner] -= f["size"]
            report["deleted"] += 1
            report["freed"] += f["size"]
    report["after"] = total
    if report["deleted"] or report["truncated"]:
        log.info("log budget %d MB: deleted %d file(s) (%d MB), truncated %d; now %d MB", budget // 2**20,
                 report["deleted"], report["freed"] // 2**20, report["truncated"], total // 2**20)
    if total > budget:
        log.warning("logs use %d MB, above the budget of %d MB, and the rest is in use", total // 2**20, budget // 2**20)
    return report


def p_free(f: dict, in_use: set[str], now: float) -> bool:
    p: Path = f["path"]
    if p.name in ACTIVE_NAMES or os.path.normcase(str(p)) in in_use:
        return False
    return now - f["mtime"] > RECENT_SECONDS


def prune_audit(settings, db) -> int:
    days = float(settings.get("logs", "audit_days") or 365)
    max_rows = int(settings.get("logs", "audit_max_rows") or 500000)
    n = db.purge_audit(days)
    row = db.one("SELECT COUNT(*) AS n FROM audit")
    extra = int(row["n"] if row else 0) - max_rows
    if extra > 0:
        n += db.execute_count("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id LIMIT ?)", (extra,))
    return n
