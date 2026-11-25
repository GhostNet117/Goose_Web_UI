"""The Files page (spec 041): browse, download, preview, upload into, rename, move and delete files in the folders a
person may use - exactly the folders of spec 031 (Ctx.roots_for / write_roots_for); administrators get what the folder
picker gives them.

Routes (docs/API.md):

    GET  /api/files/locations                   the person's locations, `manage`, the recycle days
    GET  /api/files/list?path=&offset=&limit=&sort=&order=&q=&hidden=
    GET  /api/files/info?path=
    POST /api/files/hash      {path}            SHA-256 (in a thread; cached by path, size and modification time)
    GET  /api/files/download?path=              the file (Range for resuming), audited files.download
    GET  /api/files/preview?path=               text as JSON; PNG/JPEG/GIF/WebP as the image (never SVG); else 415
    POST /api/files/mkdir     {path, name}
    POST /api/files/rename    {path, name}
    POST /api/files/move      {paths, to}
    POST /api/files/delete    {paths}           into <location>\\.goose-web-recycle\\<id>\\<name>
    GET  /api/files/recycle?location=
    POST /api/files/restore   {id}
    GET  /api/files/activity?path=&limit=

Uploads use the chunked upload of spec 039 with `target: "folder"` (uploads.py).

Rules: the team switch `files` for everything and `files_manage` on top of it for rename / move / delete / restore
(administrators always have both); every path through api._check_path (read or write; the path as written and with
links resolved); new names cleaned like uploaded file names; for members no Goose hints file names and no `.agents`
(created, renamed, moved or deleted); nothing is ever replaced; a location's top folder (or a folder holding one) is
never renamed, moved or deleted; the recycle folder is hidden and reached by no route but restore (api._check_path
refuses it, listings leave it out). Every upload, download, preview and change is audited (files.*), which also
reaches activity.jsonl and so the SIEM (spec 017).
"""
from __future__ import annotations

import asyncio
import errno
import hashlib
import logging
import os
import re
import secrets
import shutil
import stat
import sys
import time
import weakref
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import FileResponse, Response
from starlette.routing import Route

from . import policy as pol
from .context import HTTPError, body_json
from .uploads import PARTIAL_PREFIX, _set_hidden, file_ident, is_link

log = logging.getLogger("goose_web")

RECYCLE_DIR = ".goose-web-recycle"     # in the top folder of a location; hidden; never listed or reachable
MOVE_PREFIX = ".goose-web-move-"       # a copy across volumes while it is being made (hidden by its dot)
RECYCLE_DAYS_DEFAULT = 30
RECYCLE_DAYS_MAX = 365
LIST_LIMIT_DEFAULT = 200
LIST_LIMIT_MAX = 500
SCAN_MAX = 20000                       # entries of one folder looked at (the answer says `truncated` beyond)
BATCH_MAX = 200                        # paths of one move / delete
HASH_PARALLEL = 2                      # SHA-256 computations of one person at the same time
HASH_BLOCK = 1024 * 1024
HEAD_BYTES = 4096                      # what the type is recognised from
PREVIEW_TEXT_BYTES = 256 * 1024
PREVIEW_IMAGE_MAX = 20 * 1024 * 1024
ACTIVITY_DEFAULT = 50
ACTIVITY_MAX = 200
RECYCLE_LIST_MAX = 1000
PURGE_PER_RUN = 500
HASH_KEEP_SECONDS = 365 * 86400        # cached hashes nobody computed again for a year are dropped
SANDBOX_CSP = "sandbox; default-src 'none'"
ID_RE = re.compile(r"^[0-9a-f]{20}$")
FILES_OFF = "Files is not enabled for your team. Ask your administrator."
MANAGE_OFF = "Your team may not rename, move or delete files. Ask your administrator."
NOT_FOUND = "Not found"
IMAGE_TYPES = {"PNG image": "image/png", "JPEG image": "image/jpeg", "GIF image": "image/gif",
               "WebP image": "image/webp"}

# The type of a file from its first bytes: (offset, bytes, type). No dependency; the common kinds of an incident
# (captures, logs, archives, executables, documents, images, Windows artefacts).
MAGIC: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x89PNG\r\n\x1a\n", "PNG image"),
    (0, b"\xff\xd8\xff", "JPEG image"),
    (0, b"GIF87a", "GIF image"),
    (0, b"GIF89a", "GIF image"),
    (0, b"%PDF-", "PDF document"),
    (0, b"PK\x03\x04", "ZIP archive"),
    (0, b"PK\x05\x06", "ZIP archive"),
    (0, b"PK\x07\x08", "ZIP archive"),
    (0, b"\xd4\xc3\xb2\xa1", "pcap capture"),
    (0, b"\xa1\xb2\xc3\xd4", "pcap capture"),
    (0, b"\x4d\x3c\xb2\xa1", "pcap capture"),
    (0, b"\xa1\xb2\x3c\x4d", "pcap capture"),
    (0, b"\x0a\x0d\x0d\x0a", "pcapng capture"),
    (0, b"MZ", "Windows executable"),
    (0, b"\x7fELF", "ELF executable"),
    (0, b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (0, b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (0, b"\x1f\x8b", "gzip archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"Rar!\x1a\x07", "RAR archive"),
    (0, b"BZh", "bzip2 archive"),
    (0, b"\xfd7zXZ\x00", "xz archive"),
    (0, b"\x28\xb5\x2f\xfd", "Zstandard archive"),
    (257, b"ustar", "tar archive"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (Office 97-2003, MSI)"),
    (0, b"SQLite format 3\x00", "SQLite database"),
    (0, b"ElfFile\x00", "Windows event log (EVTX)"),
    (0, b"regf", "Windows registry hive"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)"),
    (0, b"EVF\x09\x0d\x0a\xff\x00", "EnCase evidence file (E01)"),
    (0, b"{\\rtf", "RTF document"),
)
_RIFF = {b"WEBP": "WebP image", b"WAVE": "WAV audio", b"AVI ": "AVI video"}


def _api():
    from . import api   # api imports this module for its routes: resolved when a request comes
    return api


# ---------------------------------------------------------------------- settings
def recycle_days(settings) -> int:
    """files.recycle_days, 1..365 (anything that is not a number counts as 30)."""
    v = settings.get("files", "recycle_days")
    try:
        d = int(float(v))
    except OverflowError:       # infinity
        return RECYCLE_DAYS_MAX if float(v) > 0 else 1
    except (TypeError, ValueError):
        return RECYCLE_DAYS_DEFAULT
    return max(1, min(RECYCLE_DAYS_MAX, d))


def check_lines(settings) -> list[tuple[str, str]]:
    """`goose-web check`: how long deleted files wait in the recycle folder, and a configured value it did not take."""
    raw = settings.get("files", "recycle_days")
    days = recycle_days(settings)
    out = [("--", f"files: what is deleted on the Files page stays {days} days in the recycle folder of its location "
                  f"({RECYCLE_DIR}), then it is removed for good (files.recycle_days)")]
    try:
        if raw in (None, "") or float(raw) != float(raw):
            raise ValueError
        if not 1 <= float(raw) <= RECYCLE_DAYS_MAX:
            out.append(("!!", f"files.recycle_days: {raw} is outside 1..{RECYCLE_DAYS_MAX} - {days} is used"))
    except (TypeError, ValueError):
        out.append(("!!", f"files.recycle_days: {raw!r} is not a number of days - {days} is used"))
    return out


# ---------------------------------------------------------------------- permission
def gate(c, u: dict, manage: bool = False) -> dict:
    """The person's policy when they may use the Files page (`manage`: and rename / move / delete); 403 files_off
    otherwise."""
    p = c.policy_for(u)
    if not pol.files_allowed(u, p):
        raise HTTPError(403, "files_off", FILES_OFF)
    if manage and not pol.files_manage_allowed(u, p):
        raise HTTPError(403, "files_off", MANAGE_OFF)
    return p


# ---------------------------------------------------------------------- paths
def is_recycle_name(name: Any) -> bool:
    """A path component Windows opens as the recycle folder (any case, trailing dots/spaces, a stream suffix)."""
    return str(name or "").split(":", 1)[0].strip().rstrip(". ").lower() == RECYCLE_DIR


def has_recycle_component(path: Any) -> bool:
    """True if `path` has a recycle folder component, as written or resolved (8.3 names, links). Fails closed."""
    cands = [str(path or "")]
    try:
        cands.append(os.path.realpath(cands[0]))
    except (OSError, ValueError, RuntimeError):
        return True
    for cand in cands:
        rest = os.path.splitdrive(cand)[1]
        if any(is_recycle_name(part) for part in rest.replace("/", "\\").split("\\")):
            return True
    return False


def _norm(p: Any) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(str(p))))


def _key(p: Any) -> str:
    """How a path is stored in file_hashes."""
    return _norm(p)


def _within(path: Any, root: Any) -> bool:
    np_, nr = _norm(path), _norm(root)
    return np_ == nr or np_.startswith(nr.rstrip("\\/") + os.sep)


def _real(p: Any) -> str:
    try:
        return os.path.normcase(os.path.realpath(str(p)))
    except (OSError, ValueError, RuntimeError):
        return ""


def _arg_path(raw: Any) -> str:
    s = raw.strip() if isinstance(raw, str) else ""
    if not s or "\x00" in s or len(s) > 4096:
        raise HTTPError(400, "bad_request", "path (an absolute path) is required")
    if not os.path.isabs(s) and not (os.name == "nt" and s.startswith(("\\", "/"))):
        raise HTTPError(400, "bad_request", "path must be an absolute path")
    return os.path.abspath(s)


def _check(c, u: dict, path: str, write: bool = False) -> Path:
    """api._check_path, with the answer of the contract for a folder outside the person's folders (403 denied)."""
    try:
        return _api()._check_path(c, u, path, write=write)
    except HTTPError as e:
        if e.code == "path_forbidden":
            raise HTTPError(403, "denied", e.message)
        raise


def clean_name(raw: Any) -> str:
    """A new name (new folder, rename): cleaned like an uploaded file's name (api.safe_upload_name); 400 bad_name
    when nothing usable is left, for a path instead of a name, and for the recycle folder's name."""
    s = raw.strip() if isinstance(raw, str) else ""
    if not s or "/" in s or "\\" in s or "\x00" in s or s in (".", ".."):
        raise HTTPError(400, "bad_name", "Give a name without \\ or /")
    # ":" goes first: Windows would read "c:name" as a drive and "name:x" as a stream of "name"
    name = _api().safe_upload_name(s.replace(":", ""))
    if (name == "upload.bin" and s != "upload.bin") or is_recycle_name(name) or \
            name.lower().startswith((PARTIAL_PREFIX, MOVE_PREFIX)):
        raise HTTPError(400, "bad_name", "That name cannot be used")
    return name


def _drives() -> list[str]:
    if os.name == "nt":
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        return [f"{chr(65 + i)}:\\" for i in range(26) if mask >> i & 1]
    return ["/"]


def locations(c, u: dict, policy: dict) -> list[dict]:
    """The person's locations in roots_for order (members), or like the folder picker (administrators)."""
    ws = str(c.profiles.workspace(u))
    if u["role"] == "admin":
        native = c.profiles.is_native(u)
        out = [{"path": ws, "label": "Home" if native else "My workspace", "kind": "home" if native else "workspace",
                "access": "write"}]
        return out + [{"path": d, "label": d.rstrip("\\") or d, "kind": "drive", "access": "write"} for d in _drives()]
    c.profiles.ensure_layout(u)
    team_folder = policy.get("team_folder")
    team_name = str((policy.get("team") or {}).get("name") or "")
    ro = set(c.read_roots_for(u, policy))
    out = []
    for i, r in enumerate(c.roots_for(u, policy)):
        kind = "workspace" if i == 0 else "team" if r == team_folder else "extra"
        label = ("My workspace" if kind == "workspace" else f"{team_name} team folder" if kind == "team" else
                 os.path.basename(r.rstrip("\\/")) or r)
        out.append({"path": r, "label": label, "kind": kind, "access": "read" if r in ro else "write"})
    return out


def _tops(c, u: dict, policy: dict) -> list[str]:
    """The top folders that are never renamed, moved or deleted, and whose recycle folder takes what is deleted in
    them: the locations; for administrators also every team's folder and extra folders (what an administrator
    deletes there lands in the recycle folder the team sees)."""
    tops = [loc["path"] for loc in locations(c, u, policy)]
    if u["role"] == "admin":
        for t in c.db.query("SELECT id, name, policy FROM teams"):
            tp = t["policy"] if isinstance(t["policy"], dict) else {}
            tops.append(str(c.profiles.team_folder({**t, "policy": tp})))
            tops += [str(r) for r in tp.get("allowed_roots") or [] if isinstance(r, str) and os.path.isabs(r)]
    return tops


def _location_of(path: Any, tops: list[str]) -> str | None:
    """The deepest top folder `path` lies in."""
    best = None
    for t in tops:
        if _within(path, t) and (best is None or len(_norm(t)) > len(_norm(best))):
            best = t
    return best


def _is_top(path: Any, tops: list[str]) -> bool:
    n = _norm(path)
    if any(n == _norm(t) for t in tops):
        return True
    try:
        if is_link(os.lstat(path)):
            return False      # a link to a top folder is only a link: renaming or deleting it leaves the folder
    except (OSError, ValueError):
        return False
    r = _real(path)
    return bool(r) and any(r == _real(t) for t in tops)


def _protect(c, u: dict, src: Path, tops: list[str]) -> None:
    """What may not be renamed, moved or deleted: a location's top folder (or a folder holding one); for members a
    Goose hints file and anything in or named `.agents` (the administrator's)."""
    if _is_top(src, tops) or any(_within(t, src) for t in tops):
        raise HTTPError(403, "denied", "A location's top folder cannot be renamed, moved or deleted.")
    api = _api()
    api._refuse_hint_name(u, src.name)
    api._refuse_agents_dir(u, src)


# ---------------------------------------------------------------------- the type of a file
def detect_type(head: bytes, size: int | None = None) -> str:
    """The kind of file from its first bytes (a few KB): MAGIC, RIFF containers, text, else "data"."""
    if not head:
        return "empty" if not size else "data"
    for off, magic, kind in MAGIC:
        if head[off:off + len(magic)] == magic:
            return kind
    if head[:4] == b"RIFF" and head[8:12] in _RIFF:
        return _RIFF[head[8:12]]
    if head[4:8] == b"ftyp":
        return "MP4 / QuickTime video"
    return _text_kind(head) or "data"


def _text_kind(head: bytes) -> str | None:
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text (UTF-16)"
    if b"\x00" in head:
        return None
    body = head[3:] if head.startswith(b"\xef\xbb\xbf") else head
    controls = sum(1 for b in body if b < 32 and b not in (8, 9, 10, 12, 13, 27))
    return "text" if controls <= len(body) // 100 else None


def _read_head(p: Path, n: int = HEAD_BYTES) -> bytes:
    with open(p, "rb") as f:
        return f.read(n)


def _decode_text(data: bytes, kind: str) -> str:
    if kind == "text (UTF-16)":
        return data.decode("utf-16", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", "replace")


# ---------------------------------------------------------------------- what is known about a file
def _hash_file(path: str) -> tuple[str, int, float, bool]:
    """SHA-256 of a regular file: (hex, size, mtime, unchanged while read)."""
    with open(path, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise IsADirectoryError(path)
        h = hashlib.sha256()
        while chunk := f.read(HASH_BLOCK):
            h.update(chunk)
        st2 = os.fstat(f.fileno())
    return h.hexdigest(), st2.st_size, st2.st_mtime, (st.st_size, st.st_mtime) == (st2.st_size, st2.st_mtime)


def _same_mtime(a: Any, b: Any) -> bool:
    try:
        return abs(float(a) - float(b)) < 1e-6
    except (TypeError, ValueError):
        return False


def _known(c, items: list[dict]) -> None:
    """Adds uploadedBy / uploadedAt (uploaded through Goose Web, still the same file) and sha256 (from the upload or
    the cache, while the file is unchanged) to file entries {path, size, mtime}. Blocking: call in a thread."""
    files = [x for x in items if not x.get("dir")]
    if not files:
        return
    by_key = {_key(x["path"]): x for x in files}
    marks = ",".join("?" for _ in files)
    # the placeholders are "?" only; every value is a bound parameter
    rows = c.db.query(f"SELECT path, username, completed_at, sha256, size, file_id FROM uploads "  # nosec B608
                      f"WHERE state='done' AND path COLLATE NOCASE IN ({marks}) ORDER BY completed_at",
                      [x["path"] for x in files])
    for r in rows:
        x = by_key.get(_key(r["path"]))
        if x is None or int(r["size"] or 0) != int(x["size"]):
            continue
        try:
            st = os.lstat(x["path"])
        except OSError:
            continue
        if r["file_id"] and file_ident(st) != r["file_id"]:
            continue        # another file with that name now
        x["uploadedBy"], x["uploadedAt"] = r["username"], r["completed_at"]
        if r["sha256"] and float(x["mtime"]) <= float(r["completed_at"] or 0) + 2:
            x["sha256"] = r["sha256"]
        else:
            x.pop("sha256", None)
    rows = c.db.query(f"SELECT path, size, mtime, sha256 FROM file_hashes WHERE path IN "  # nosec B608
                      f"({','.join('?' for _ in by_key)})", list(by_key))
    for r in rows:
        x = by_key.get(r["path"])
        if x is not None and "sha256" not in x and int(r["size"]) == int(x["size"]) and _same_mtime(r["mtime"],
                                                                                                    x["mtime"]):
            x["sha256"] = r["sha256"]


def known_sha256(c, path: Any, st=None) -> str:
    """The SHA-256 of a file when it is known (an upload, the cache) and the file is unchanged; '' otherwise."""
    try:
        st = st or os.stat(path)
    except OSError:
        return ""
    item = {"path": str(path), "size": st.st_size, "mtime": st.st_mtime}
    _known(c, [item])
    return item.get("sha256") or ""


def _remember_hash(c, path: str, size: int, mtime: float, sha: str) -> None:
    c.db.execute("INSERT INTO file_hashes(path, size, mtime, sha256, at) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE "
                 "SET size=excluded.size, mtime=excluded.mtime, sha256=excluded.sha256, at=excluded.at",
                 (_key(path), int(size), float(mtime), sha, time.time()))


def _like_prefix(p: str) -> str:
    s = p.rstrip("\\/") + os.sep
    return s.replace("^", "^^").replace("%", "^%").replace("_", "^_") + "%"


def _repath(c, old: Any, new: Any) -> None:
    """Records follow an item that was renamed, moved, recycled or restored: uploads of the Files page (who uploaded
    it, its SHA-256) and cached hashes. Chat attachments do not follow: retention must not find them at the new
    place (an attachment moved out of Web_Uploads is kept)."""
    o, n = str(old), str(new)
    for r in c.db.query("SELECT id, path FROM uploads WHERE target='folder' AND state='done' AND "
                        "(path=? COLLATE NOCASE OR path LIKE ? ESCAPE '^')", (o, _like_prefix(o))):
        if _norm(r["path"]) == _norm(o):
            newp = n
        elif _within(r["path"], o):
            newp = os.path.join(n, os.path.relpath(r["path"], o))
        else:
            continue
        c.db.execute("UPDATE uploads SET path=?, dir=? WHERE id=?", (newp, os.path.dirname(newp), r["id"]))
    ko, kn = _key(o), _key(n)
    for r in c.db.query("SELECT path FROM file_hashes WHERE path=? OR path LIKE ? ESCAPE '^'", (ko, _like_prefix(ko))):
        if r["path"] == ko:
            newk = kn
        elif r["path"].startswith(ko.rstrip("\\/") + os.sep):
            newk = kn + r["path"][len(ko.rstrip("\\/")):]
        else:
            continue
        c.db.execute("UPDATE OR REPLACE file_hashes SET path=? WHERE path=?", (newk, r["path"]))


# ---------------------------------------------------------------------- moving things (never replacing)
def _rename_noreplace(src: Any, dst: Any) -> None:
    if os.name == "nt":
        os.rename(src, dst)        # MoveFileExW without MOVEFILE_REPLACE_EXISTING: never replaces anything
        return
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "File exists", str(dst))
    os.rename(src, dst)


def _cross_device(e: OSError) -> bool:
    return e.errno == errno.EXDEV or getattr(e, "winerror", 0) == 17      # ERROR_NOT_SAME_DEVICE


def _clear_readonly(func, path, _exc) -> None:
    if not os.path.islink(path):
        os.chmod(path, stat.S_IWRITE)
    func(path)


def _remove_tree(p: Any) -> None:
    """Delete a file, a link (never what it points to) or a folder tree (links inside it are removed, not
    followed)."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return
    if is_link(st) or not stat.S_ISDIR(st.st_mode):
        try:
            os.unlink(p)
        except PermissionError:
            if is_link(st):
                os.rmdir(p)        # a directory junction
            else:
                os.chmod(p, stat.S_IWRITE)
                os.unlink(p)
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=_clear_readonly)
    else:
        shutil.rmtree(p, onerror=_clear_readonly)


def _move_item(src: Path, dst: Path) -> None:
    """Move a file or folder to `dst`, which must not exist: a rename on the same volume; across volumes a copy under
    a hidden temporary name next to `dst`, renamed to `dst`, then the original is deleted. Blocking."""
    try:
        _rename_noreplace(src, dst)
        return
    except OSError as e:
        if not _cross_device(e):
            raise
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, "File exists", str(dst))
    tmp = dst.parent / f"{MOVE_PREFIX}{secrets.token_hex(8)}"
    try:
        st = os.lstat(src)
        if stat.S_ISDIR(st.st_mode) and not is_link(st):
            shutil.copytree(src, tmp, symlinks=True)
        else:
            shutil.copy2(src, tmp, follow_symlinks=False)
        _rename_noreplace(tmp, dst)
    except BaseException:
        try:
            _remove_tree(tmp)
        except OSError:
            log.warning("files: the temporary copy %s could not be removed", tmp)
        raise
    _remove_tree(src)


async def _move_checked(c, u: dict, src: Path, dst: Path, real_parent: str) -> None:
    """_move_item in a thread, then the item is looked at where it landed: its folder must still resolve to
    `real_parent` (resolved when it was checked) and be writable for the person. A folder swapped for a link
    meanwhile (by the person's agent, say) does not take the item elsewhere: it is moved back and refused."""
    try:
        await asyncio.to_thread(_move_item, src, dst)
    except OSError as e:
        raise _os_error(e)
    if _real(dst.parent) == real_parent and c.path_ok(u, str(dst.parent), write=True):
        return
    log.warning("files: %s changed while %s moved %s there; the item is put back", dst.parent, u["username"], src)
    try:
        await asyncio.to_thread(_move_item, dst, src)
    except OSError:
        log.error("files: %s could not be put back from %s", src, dst, exc_info=True)
    raise HTTPError(403, "denied", "The folder changed while the item was being moved; nothing was moved.")


def _measure(p: Path) -> tuple[int, bool]:
    """(bytes, is a folder) - a folder's files added up (at most SCAN_MAX entries looked at)."""
    st = os.lstat(p)
    if not stat.S_ISDIR(st.st_mode) or is_link(st):
        return st.st_size, False
    total = seen = 0
    for root, dirs, names in os.walk(p):
        for nm in names:
            seen += 1
            if seen > SCAN_MAX:
                return total, True
            try:
                total += os.lstat(os.path.join(root, nm)).st_size
            except OSError:
                continue
    return total, True


def _os_error(e: OSError, what: str = "") -> HTTPError:
    if isinstance(e, FileExistsError):
        return HTTPError(409, "exists", "Something with that name is already there; nothing was replaced.")
    if isinstance(e, FileNotFoundError):
        return HTTPError(404, "not_found", NOT_FOUND)
    if isinstance(e, PermissionError):
        return HTTPError(403, "denied", "Access denied by the file system (or the file is in use)" + what)
    return HTTPError(409, "failed", f"{e.__class__.__name__}: {e.strerror or e}"[:300])


# ---------------------------------------------------------------------- per-person live state
class _Live:
    def __init__(self) -> None:
        self.hashing: dict[int, int] = {}      # user id -> SHA-256 computations running


_LIVE: "weakref.WeakKeyDictionary[Any, _Live]" = weakref.WeakKeyDictionary()


def _live(db) -> _Live:
    st = _LIVE.get(db)
    if st is None:
        st = _LIVE[db] = _Live()
    return st


# ---------------------------------------------------------------------- handlers
def _begin(request: Request, manage: bool = False):
    api = _api()
    c = api.ctx(request)
    u = c.require(request).user
    return api, c, u, gate(c, u, manage)


def _int(raw: Any, default: int, lo: int, hi: int) -> int:
    if raw in (None, ""):
        return default
    try:
        v = int(raw)
    except (TypeError, ValueError):
        raise HTTPError(400, "bad_request", "A number was expected")
    return max(lo, min(hi, v))


async def locations_route(request: Request):
    api, c, u, policy = _begin(request)
    locs = await asyncio.to_thread(locations, c, u, policy)
    return api.ok({"locations": locs, "manage": pol.files_manage_allowed(u, policy),
                   "recycleDays": recycle_days(c.settings)})


def _scan(p: Path, hidden: bool, q: str) -> tuple[list[dict], bool]:
    out: list[dict] = []
    truncated = False
    with os.scandir(p) as it:
        for i, e in enumerate(it):
            if i >= SCAN_MAX:
                truncated = True
                break
            if is_recycle_name(e.name):
                continue
            try:
                st = e.stat()
                is_dir = e.is_dir()
            except OSError:
                continue
            hid = e.name.startswith(".") or bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_HIDDEN)
            if (hid and not hidden) or (q and q not in e.name.casefold()):
                continue
            out.append({"name": e.name, "path": e.path, "dir": is_dir, "size": 0 if is_dir else st.st_size,
                        "mtime": st.st_mtime, "hidden": hid})
    return out, truncated


async def list_route(request: Request):
    api, c, u, policy = _begin(request)
    qp = request.query_params
    p = _check(c, u, _arg_path(qp.get("path")))
    offset = _int(qp.get("offset"), 0, 0, 10 ** 9)
    limit = _int(qp.get("limit"), LIST_LIMIT_DEFAULT, 1, LIST_LIMIT_MAX)
    sort = qp.get("sort") or "name"
    order = qp.get("order") or "asc"
    if sort not in ("name", "size", "mtime") or order not in ("asc", "desc"):
        raise HTTPError(400, "bad_request", "sort is name, size or mtime; order is asc or desc")
    q = (qp.get("q") or "").strip().casefold()[:200]
    hidden = (qp.get("hidden") or "0") in ("1", "true")
    if not await asyncio.to_thread(p.is_dir):
        raise HTTPError(404, "not_found", "Folder not found")
    try:
        entries, truncated = await asyncio.to_thread(_scan, p, hidden, q)
    except PermissionError:
        raise HTTPError(403, "denied", "Access denied by the file system")
    except (FileNotFoundError, NotADirectoryError):
        raise HTTPError(404, "not_found", "Folder not found")

    def by(x):
        return x["name"].casefold() if sort == "name" else (x[sort], x["name"].casefold())
    dirs = sorted((x for x in entries if x["dir"]), key=by, reverse=order == "desc")
    files = sorted((x for x in entries if not x["dir"]), key=by, reverse=order == "desc")
    entries = dirs + files
    page = entries[offset:offset + limit]
    await asyncio.to_thread(_known, c, page)
    tops = [loc["path"] for loc in await asyncio.to_thread(locations, c, u, policy)]
    loc = _location_of(p, tops)
    at_top = loc is None or _norm(p) == _norm(loc) or p.parent == p
    parent = None if at_top or not c.path_ok(u, str(p.parent)) else str(p.parent)
    out = {"path": str(p), "parent": parent, "location": loc, "total": len(entries), "offset": offset,
           "access": "write" if c.path_ok(u, str(p), write=True) else "read", "entries": page}
    if truncated:
        out["truncated"] = True
    return api.ok(out)


async def info_route(request: Request):
    api, c, u, _ = _begin(request)
    p = _check(c, u, _arg_path(request.query_params.get("path")))
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", NOT_FOUND)
    is_dir = stat.S_ISDIR(st.st_mode)
    out = {"name": p.name or str(p), "path": str(p), "dir": is_dir, "size": 0 if is_dir else st.st_size,
           "mtime": st.st_mtime, "ctime": getattr(st, "st_birthtime", st.st_ctime),
           "access": "write" if c.path_ok(u, str(p), write=True) else "read", "type": "folder"}
    if not is_dir:
        try:
            out["type"] = detect_type(await asyncio.to_thread(_read_head, p), st.st_size)
        except OSError:
            out["type"] = "unreadable"
        item = {"path": str(p), "size": st.st_size, "mtime": st.st_mtime}
        await asyncio.to_thread(_known, c, [item])
        out.update({k: item[k] for k in ("sha256", "uploadedBy", "uploadedAt") if k in item})
    return api.ok(out)


async def hash_route(request: Request):
    api, c, u, _ = _begin(request)
    b = await body_json(request, 16 * 1024)
    p = _check(c, u, _arg_path(b.get("path")))
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", NOT_FOUND)
    if not stat.S_ISREG(st.st_mode):
        raise HTTPError(400, "bad_request", "Only a file has a SHA-256")
    known = await asyncio.to_thread(known_sha256, c, p, st)
    if known:
        return api.ok({"sha256": known, "cached": True})
    live = _live(c.db)
    if live.hashing.get(u["id"], 0) >= HASH_PARALLEL:
        raise HTTPError(429, "busy", f"{HASH_PARALLEL} SHA-256 computations of yours are running; try again when one "
                                     "has finished.")
    live.hashing[u["id"]] = live.hashing.get(u["id"], 0) + 1
    try:
        sha, size, mtime, stable = await asyncio.to_thread(_hash_file, str(p))
    except OSError as e:
        raise _os_error(e)
    finally:
        left = live.hashing.get(u["id"], 1) - 1
        if left > 0:
            live.hashing[u["id"]] = left
        else:
            live.hashing.pop(u["id"], None)
    if stable:
        _remember_hash(c, str(p), size, mtime, sha)
    return api.ok({"sha256": sha, "cached": False, **({} if stable else {"changing": True})})


async def audit_file(c, request: Request, u: dict, p: Path, action: str, route: str = "", **extra: Any) -> dict:
    """Audit a read of a file (download, preview, /api/fs/read): size and the SHA-256 when it is known."""
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", "File not found")
    detail: dict[str, Any] = {"size": st.st_size}
    sha = await asyncio.to_thread(known_sha256, c, p, st)
    if sha:
        detail["sha256"] = sha
    rng = request.headers.get("range")
    if rng:
        detail["range"] = rng[:100]
    if route:
        detail["route"] = route
    detail.update(extra)
    c.audit(request, action, u, target=str(p), detail=detail)
    return detail


async def download_route(request: Request):
    api, c, u, _ = _begin(request)
    p = _check(c, u, _arg_path(request.query_params.get("path")))
    if not await asyncio.to_thread(p.is_file):
        raise HTTPError(404, "not_found", "File not found")
    await audit_file(c, request, u, p, "files.download")
    # always a download, as /api/fs/download: octet-stream + attachment + sandbox CSP; Range is answered (resuming)
    return FileResponse(p, filename=p.name, media_type="application/octet-stream",
                        content_disposition_type="attachment",
                        headers={"Cache-Control": "no-store", "Content-Security-Policy": SANDBOX_CSP,
                                 "X-Content-Type-Options": "nosniff"})


def _read_upto(p: Path, n: int) -> bytes:
    with open(p, "rb") as f:
        return f.read(n)


async def preview_route(request: Request):
    api, c, u, _ = _begin(request)
    p = _check(c, u, _arg_path(request.query_params.get("path")))
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", "File not found")
    if not stat.S_ISREG(st.st_mode):
        raise HTTPError(404, "not_found", "File not found")
    try:
        kind = detect_type(await asyncio.to_thread(_read_head, p), st.st_size)
    except OSError as e:
        raise _os_error(e)
    mime = IMAGE_TYPES.get(kind)
    if mime:
        if st.st_size > PREVIEW_IMAGE_MAX:
            raise HTTPError(415, "no_preview", f"Images larger than {PREVIEW_IMAGE_MAX // 1048576} MB are not "
                                               "previewed; download it instead.")
        data = await asyncio.to_thread(_read_upto, p, PREVIEW_IMAGE_MAX + 1)
        # what is sent is looked at again: the file may have changed since its first bytes were read
        if len(data) > PREVIEW_IMAGE_MAX or IMAGE_TYPES.get(detect_type(data[:HEAD_BYTES], len(data))) != mime:
            raise HTTPError(415, "no_preview", "This file has no preview; download it instead.")
        await audit_file(c, request, u, p, "files.preview", kind="image")
        return Response(data, media_type=mime, headers={
            "Content-Disposition": "inline", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": SANDBOX_CSP, "Cache-Control": "no-store"})
    if kind.startswith("text") or kind == "empty":
        data = await asyncio.to_thread(_read_upto, p, PREVIEW_TEXT_BYTES)
        await audit_file(c, request, u, p, "files.preview", kind="text")
        return api.ok({"kind": "text", "type": kind, "content": _decode_text(data, kind),
                       "truncated": st.st_size > PREVIEW_TEXT_BYTES})
    raise HTTPError(415, "no_preview", f"There is no preview for this kind of file ({kind}); download it instead.")


async def mkdir_route(request: Request):
    api, c, u, _ = _begin(request)
    b = await body_json(request, 16 * 1024)
    parent = _check(c, u, _arg_path(b.get("path")), write=True)
    name = clean_name(b.get("name"))
    api._refuse_hint_name(u, name)
    target = parent / name
    api._refuse_agents_dir(u, target)
    _check(c, u, str(target), write=True)
    if not await asyncio.to_thread(parent.is_dir):
        raise HTTPError(404, "not_found", "Folder not found")
    try:
        await asyncio.to_thread(os.mkdir, target)
    except OSError as e:
        raise _os_error(e)
    if not c.path_ok(u, str(target), write=True):     # the folder was swapped for a link meanwhile
        await asyncio.to_thread(_remove_empty, target)
        raise HTTPError(403, "denied", "The folder changed while the new folder was made; try again.")
    c.audit(request, "files.mkdir", u, target=str(target))
    return api.ok({"path": str(target)})


def _remove_empty(p: Path) -> None:
    try:
        os.rmdir(p)
    except OSError:
        pass


async def rename_route(request: Request):
    api, c, u, policy = _begin(request, manage=True)
    b = await body_json(request, 16 * 1024)
    src = _check(c, u, _arg_path(b.get("path")), write=True)
    name = clean_name(b.get("name"))
    tops = await asyncio.to_thread(_tops, c, u, policy)
    _protect(c, u, src, tops)
    if not os.path.lexists(src):
        raise HTTPError(404, "not_found", NOT_FOUND)
    dst = src.parent / name
    api._refuse_hint_name(u, name)
    api._refuse_agents_dir(u, dst)
    _check(c, u, str(dst), write=True)
    if str(dst) == str(src):
        return api.ok({"path": str(src)})
    if os.path.lexists(dst) and os.path.normcase(str(dst)) != os.path.normcase(str(src)):
        raise HTTPError(409, "exists", f"'{name}' already exists in this folder; nothing was replaced.")
    real_parent = _real(src.parent)
    try:
        await asyncio.to_thread(_rename_noreplace, src, dst)
    except OSError as e:
        raise _os_error(e)
    if _real(dst.parent) != real_parent or not c.path_ok(u, str(dst.parent), write=True):
        await asyncio.to_thread(_rename_noreplace, dst, src)     # swapped for a link meanwhile: put back
        raise HTTPError(403, "denied", "The folder changed while the item was being renamed; nothing was renamed.")
    _repath(c, src, dst)
    c.audit(request, "files.rename", u, target=str(dst), detail={"from": str(src), "to": str(dst)})
    return api.ok({"path": str(dst)})


def _paths_arg(b: dict) -> list:
    paths = b.get("paths")
    if not isinstance(paths, list) or not paths or len(paths) > BATCH_MAX:
        raise HTTPError(400, "bad_request", f"paths must be a list of 1 to {BATCH_MAX} paths")
    return paths


def _failed(raw: Any, e: HTTPError) -> dict:
    return {"path": str(raw)[:4096], "error": e.code, "message": e.message}


async def move_route(request: Request):
    api, c, u, policy = _begin(request, manage=True)
    b = await body_json(request, 2 * 1024 * 1024)
    paths = _paths_arg(b)
    to = _check(c, u, _arg_path(b.get("to")), write=True)
    api._refuse_agents_dir(u, to)
    if not await asyncio.to_thread(to.is_dir):
        raise HTTPError(404, "not_found", "Folder not found")
    tops = await asyncio.to_thread(_tops, c, u, policy)
    real_to = _real(to)
    moved: list[dict] = []
    failed: list[dict] = []
    for raw in paths:
        try:
            src = _check(c, u, _arg_path(raw), write=True)
            _protect(c, u, src, tops)
            try:
                st = os.lstat(src)
            except OSError:
                raise HTTPError(404, "not_found", NOT_FOUND)
            dst = to / src.name
            api._refuse_agents_dir(u, dst)
            _check(c, u, str(dst), write=True)
            r_to, r_src = _real(to), _real(src)
            if stat.S_ISDIR(st.st_mode) and not is_link(st) and (_within(to, src) or (r_to and r_src and
                                                                                       _within(r_to, r_src))):
                raise HTTPError(400, "bad_request", "A folder cannot be moved into itself or one of its folders.")
            if os.path.lexists(dst):
                raise HTTPError(409, "exists", f"'{src.name}' already exists there; nothing was replaced.")
            await _move_checked(c, u, src, dst, real_to)
            _repath(c, src, dst)
            c.audit(request, "files.move", u, target=str(dst), detail={"from": str(src), "to": str(dst)})
            moved.append({"from": str(src), "to": str(dst)})
        except HTTPError as e:
            failed.append(_failed(raw, e))
    return api.ok({"moved": moved, "failed": failed})


def _recycle_slot(loc: Path, rid: str) -> Path:
    """<location>\\.goose-web-recycle\\<id>, made (the recycle folder hidden) and checked: a real folder, right in the
    location (never a link that leads elsewhere). Blocking."""
    rec = loc / RECYCLE_DIR
    try:
        os.mkdir(rec)
    except FileExistsError:
        pass
    st = os.lstat(rec)
    if is_link(st) or not stat.S_ISDIR(st.st_mode) or os.path.dirname(_real(rec)) != _real(loc):
        raise HTTPError(409, "denied", f"{RECYCLE_DIR} in this location is not a folder of Goose Web; ask your "
                                       "administrator.")
    _set_hidden(rec, True)
    slot = rec / rid
    os.mkdir(slot)
    return slot


async def delete_route(request: Request):
    api, c, u, policy = _begin(request, manage=True)
    b = await body_json(request, 2 * 1024 * 1024)
    paths = _paths_arg(b)
    tops = await asyncio.to_thread(_tops, c, u, policy)
    deleted: list[dict] = []
    failed: list[dict] = []
    for raw in paths:
        try:
            src = _check(c, u, _arg_path(raw), write=True)
            _protect(c, u, src, tops)
            if not os.path.lexists(src):
                raise HTTPError(404, "not_found", NOT_FOUND)
            loc = _location_of(src, tops)
            if loc is None:
                raise HTTPError(403, "denied", "This item is in none of your locations.")
            _check(c, u, loc, write=True)
            try:
                size, is_dir = await asyncio.to_thread(_measure, src)
                sha = "" if is_dir else await asyncio.to_thread(known_sha256, c, src)
                rid = secrets.token_hex(10)
                slot = await asyncio.to_thread(_recycle_slot, Path(loc), rid)
            except OSError as e:
                raise _os_error(e)
            dst = slot / src.name
            try:
                await _move_checked(c, u, src, dst, _real(slot))
            except HTTPError:
                await asyncio.to_thread(_remove_empty, slot)
                raise
            now = time.time()
            c.db.execute("INSERT INTO file_recycle(id, location, original_path, recycle_path, name, is_dir, size, "
                         "sha256, deleted_by, deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (rid, str(loc), str(src), str(dst), src.name, 1 if is_dir else 0, size, sha, u["username"],
                          now))
            _repath(c, src, dst)
            detail: dict[str, Any] = {"id": rid, "size": size, "dir": is_dir}
            if sha:
                detail["sha256"] = sha
            c.audit(request, "files.delete", u, target=str(src), detail=detail)
            deleted.append({"path": str(src), "id": rid})
        except HTTPError as e:
            failed.append(_failed(raw, e))
    return api.ok({"deleted": deleted, "failed": failed})


def _recycle_view(r: dict, days: int) -> dict:
    return {"id": r["id"], "name": r["name"], "originalPath": r["original_path"], "dir": bool(r["is_dir"]),
            "size": r["size"], "deletedBy": r["deleted_by"], "deletedAt": r["deleted_at"],
            "expiresAt": float(r["deleted_at"]) + days * 86400}


async def recycle_route(request: Request):
    api, c, u, _ = _begin(request)
    loc = _check(c, u, _arg_path(request.query_params.get("location")))
    days = recycle_days(c.settings)
    rows = c.db.query("SELECT * FROM file_recycle WHERE location=? COLLATE NOCASE ORDER BY deleted_at DESC LIMIT ?",
                      (str(loc), RECYCLE_LIST_MAX))
    items = [_recycle_view(r, days) for r in rows if _norm(r["location"]) == _norm(loc)
             and c.path_ok(u, os.path.dirname(r["original_path"]), write=True)]
    return api.ok({"items": items})


def _free_name(dst: Path, is_dir: bool) -> Path:
    if not os.path.lexists(dst):
        return dst
    stem, suf = (dst.name, "") if is_dir else (dst.stem, dst.suffix)
    for n in range(1, 1001):
        cand = dst.parent / (f"{stem} (restored){suf}" if n == 1 else f"{stem} (restored {n}){suf}")
        if not os.path.lexists(cand):
            return cand
    raise HTTPError(409, "exists", "Too many items with that name in this folder")


def _restore_source(r: dict) -> Path:
    """The recycled item, checked: where Goose Web put it (<location>\\.goose-web-recycle\\<id>\\<name>), the recycle
    folder and the item no links. Blocking."""
    loc = Path(r["location"])
    rec = loc / RECYCLE_DIR
    slot = rec / r["id"]
    src = Path(r["recycle_path"])
    if _norm(src.parent) != _norm(slot):
        raise HTTPError(409, "denied", "This recycle record does not match its folder")
    try:
        st_rec, st_slot, st = os.lstat(rec), os.lstat(slot), os.lstat(src)
    except FileNotFoundError:
        raise HTTPError(404, "not_found", "The item is no longer in the recycle folder")
    if any(is_link(s) for s in (st_rec, st_slot, st)) or os.path.dirname(_real(rec)) != _real(loc) \
            or os.path.dirname(_real(src)) != _real(slot):
        raise HTTPError(409, "denied", "The recycle folder was changed by something else; the item is not restored.")
    return src


async def restore_route(request: Request):
    api, c, u, _ = _begin(request, manage=True)
    b = await body_json(request, 16 * 1024)
    rid = b.get("id")
    if not isinstance(rid, str) or not ID_RE.match(rid):
        raise HTTPError(404, "not_found", NOT_FOUND)
    r = c.db.one("SELECT * FROM file_recycle WHERE id=?", (rid,))
    if r is None:
        raise HTTPError(404, "not_found", NOT_FOUND)
    orig = Path(r["original_path"])
    try:
        _check(c, u, str(r["location"]), write=True)
        parent = _check(c, u, str(orig.parent), write=True)
    except HTTPError as e:
        if e.code == "denied":
            raise HTTPError(404, "not_found", NOT_FOUND)    # an item of a folder this person cannot reach
        raise
    api._refuse_hint_name(u, orig.name)
    api._refuse_agents_dir(u, orig)
    src = await asyncio.to_thread(_restore_source, r)
    try:
        await asyncio.to_thread(parent.mkdir, parents=True, exist_ok=True)
    except OSError as e:
        raise _os_error(e)
    if not c.path_ok(u, str(parent), write=True):
        raise HTTPError(403, "denied", "The original folder changed; the item is not restored.")
    dst = await asyncio.to_thread(_free_name, orig, bool(r["is_dir"]))
    await _move_checked(c, u, src, dst, _real(parent))
    await asyncio.to_thread(_remove_empty, src.parent)
    c.db.execute("DELETE FROM file_recycle WHERE id=?", (rid,))
    _repath(c, src, dst)
    detail: dict[str, Any] = {"id": rid, "size": r["size"], "deletedBy": r["deleted_by"]}
    if str(dst) != str(orig):
        detail["originalPath"] = str(orig)
    c.audit(request, "files.restore", u, target=str(dst), detail=detail)
    return api.ok({"path": str(dst)})


async def activity_route(request: Request):
    api, c, u, _ = _begin(request)
    p = _check(c, u, _arg_path(request.query_params.get("path")))
    limit = _int(request.query_params.get("limit"), ACTIVITY_DEFAULT, 1, ACTIVITY_MAX)
    o = str(p)
    like = _like_prefix(o)
    rows = c.db.query(
        "SELECT ts, username, action, target, detail FROM audit WHERE action LIKE 'files.%' AND ("
        "target=? COLLATE NOCASE OR target LIKE ? ESCAPE '^' OR (action IN ('files.move', 'files.rename') AND "
        "json_valid(detail) AND (json_extract(detail, '$.from')=? COLLATE NOCASE OR "
        "json_extract(detail, '$.from') LIKE ? ESCAPE '^'))) ORDER BY id DESC LIMIT ?", (o, like, o, like, limit))
    items = []
    for r in rows:
        d = r["detail"] if isinstance(r["detail"], dict) else {}
        if _within(r["target"], o) or (isinstance(d.get("from"), str) and _within(d["from"], o)):
            items.append({"ts": r["ts"], "username": r["username"], "action": r["action"], "target": r["target"],
                          "detail": d})
    return api.ok({"items": items})


# ---------------------------------------------------------------------- maintenance
def _purge_item(r: dict) -> str | None:
    """Remove a recycled item for good. 'deleted', 'missing' (already gone, or the record does not match the folder
    Goose Web made: nothing is touched), or None (could not be deleted now: tried again later). Blocking."""
    loc = Path(r["location"])
    rec = loc / RECYCLE_DIR
    slot = rec / str(r["id"])
    if not ID_RE.match(str(r["id"])) or _norm(Path(r["recycle_path"]).parent) != _norm(slot):
        return "missing"
    try:
        st = os.lstat(rec)
        if is_link(st) or not stat.S_ISDIR(st.st_mode) or os.path.dirname(_real(rec)) != _real(loc):
            log.warning("files: %s is not the recycle folder Goose Web made; %s is not purged", rec, r["id"])
            return "missing"
        os.lstat(slot)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return None
    try:
        _remove_tree(slot)
    except OSError:
        log.warning("files: the recycled item %s could not be removed yet", slot, exc_info=True)
        return None
    return "deleted"


async def purge_recycle(c, now: float | None = None) -> int:
    """Maintenance loop: recycled items older than files.recycle_days are removed for good (audited files.purge, by
    the system); cached hashes nobody needed for a year are dropped. Returns how many items were purged."""
    now = time.time() if now is None else now
    days = recycle_days(c.settings)
    n = 0
    for r in c.db.query("SELECT * FROM file_recycle WHERE deleted_at<? ORDER BY deleted_at LIMIT ?",
                        (now - days * 86400, PURGE_PER_RUN)):
        try:
            how = await asyncio.to_thread(_purge_item, r)
        except Exception:
            log.exception("files: purging %s", r.get("recycle_path"))
            continue
        if how is None:
            continue
        c.db.execute("DELETE FROM file_recycle WHERE id=?", (r["id"],))
        detail: dict[str, Any] = {"id": r["id"], "name": r["name"], "size": r["size"], "days": days,
                                  "deletedBy": r["deleted_by"]}
        if how == "missing":
            detail["missing"] = True
        c.db.audit("files.purge", target=r["original_path"], detail=detail)
        n += 1
    c.db.execute("DELETE FROM file_hashes WHERE at<?", (now - HASH_KEEP_SECONDS,))
    if n:
        log.info("files: %d recycled item(s) older than %d days removed", n, days)
    return n


routes = [
    Route("/api/files/locations", locations_route),
    Route("/api/files/list", list_route),
    Route("/api/files/info", info_route),
    Route("/api/files/hash", hash_route, methods=["POST"]),
    Route("/api/files/download", download_route),
    Route("/api/files/preview", preview_route),
    Route("/api/files/mkdir", mkdir_route, methods=["POST"]),
    Route("/api/files/rename", rename_route, methods=["POST"]),
    Route("/api/files/move", move_route, methods=["POST"]),
    Route("/api/files/delete", delete_route, methods=["POST"]),
    Route("/api/files/recycle", recycle_route),
    Route("/api/files/restore", restore_route, methods=["POST"]),
    Route("/api/files/activity", activity_route),
]
