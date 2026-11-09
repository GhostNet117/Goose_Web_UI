"""Log budget (spec 015): keep every log Goose Web writes under logs.max_disk_percent of the disk volume.

Covered files:
- the gateway's own logs: <system_dir>/logs/** (gateway.log, activity.jsonl, worker-<user>.log and their
  rotated copies, relay logs);
- the Goose logs of the isolated profiles Goose Web created: <profiles_root>/<user>/state/logs/** and
  .../data/logs/** (Goose's own per-day logs);
- optionally (logs.include_native_goose_logs) the native profile's Goose logs, which Goose Desktop and the CLI
  also write - off by default because they are not Goose Web's files.

Every run (at start and then every logs.check_minutes): if the total is above the budget, the oldest files that are
not in use are deleted until the total is below 90 % of it. A worker log that alone grows beyond its share is
copied to <name>.1 and emptied in place ("copytruncate": goose keeps writing into the same open file). The audit
table in the database is pruned to logs.audit_days and logs.audit_max_rows. Nothing else is ever deleted.
"""
from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

log = logging.getLogger("goose_web.logs")
ACTIVE_NAMES = {"gateway.log", "activity.jsonl"}
LOG_SUFFIXES = (".log", ".jsonl", ".txt", ".out", ".err")
RECENT_SECONDS = 300           # a file written in the last 5 minutes is treated as in use


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


def roots(settings, native_root: str | None = None) -> list[Path]:
    out = [Path(settings.system_dir) / "logs"]
    pr = Path(settings.profiles_root)
    try:
        for d in pr.iterdir():
            if d.is_dir() and not d.name.startswith("_"):
                out += [d / "state" / "logs", d / "data" / "logs"]
    except OSError:
        pass
    if native_root and settings.get("logs", "include_native_goose_logs"):
        out += [Path(native_root) / "state" / "logs", Path(native_root) / "data" / "logs"]
    return [r for r in out if r.is_dir()]


def scan(settings, native_root: str | None = None) -> list[dict]:
    files = []
    for r in roots(settings, native_root):
        for dirpath, _dirs, names in os.walk(r):
            for n in names:
                p = Path(dirpath) / n
                if not _is_log(p):
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                files.append({"path": p, "size": st.st_size, "mtime": st.st_mtime})
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
    """Delete the oldest unused logs until the total is under the budget. Returns a report."""
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
        if f["size"] > share and os.path.normcase(str(p)) in in_use and p.name not in ACTIVE_NAMES:
            if _copytruncate(p):
                report["truncated"] += 1
                f["size"] = 0
    total = sum(f["size"] for f in files)
    if total > budget:
        goal = int(budget * 0.9)
        candidates = sorted((f for f in files
                             if p_free(f, in_use, now)), key=lambda f: f["mtime"])
        for f in candidates:
            if total <= goal:
                break
            try:
                f["path"].unlink()
            except OSError:
                continue            # still open (Windows) or already gone
            total -= f["size"]
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
