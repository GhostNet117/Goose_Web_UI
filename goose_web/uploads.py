"""Chunked, resumable uploads into <chat folder>\\Web_Uploads, and the upload limit (spec 039).

Protocol (docs/API.md):

    GET    /api/fs/uploads                the limits for the page
    POST   /api/fs/uploads                {dir, name, size, mime?, session?, profile?} -> {id, chunkBytes, received}
    PUT    /api/fs/uploads/{id}?offset=N  raw body, one piece (<= MAX_CHUNK_BYTES) -> {received, size, done, file?}
    GET    /api/fs/uploads/{id}           {received, size, state, done, file?} - where to continue after a failure
    DELETE /api/fs/uploads/{id}           cancel: the partial file is deleted
    POST   /api/fs/uploads/link           {session, ids?, from?, profile?} - the chat the files belong to (spec 040)

Every check of the single-request upload (`api.fs_upload`, spec 031) holds: sign-in, CSRF/Origin, write access to the
folder as it resolves (`<dir>\\Web_Uploads`, again before the partial file is made and before it gets its final
name), cleaned names, no Goose hints file names or `.agents` for members. New: the size is declared at the start and
must be within the limit; an upload belongs to the person who started it (32 random bytes; the database keeps their
SHA-256; another person's id is "not found"); bytes go straight to disk (at most WRITE_BYTES held per piece) into a
hidden partial file created exclusively in the same folder; a piece is all or nothing and must start exactly where
the last one ended; the server never takes more bytes than declared; the partial file is never followed when it was
replaced by a link or another file (its volume:file-index is stored and compared on the handle that was opened); at
the last byte it is renamed to a name that never replaces another file ("report (1).pdf"). Free disk space is checked
first. Idle partial files go after 24 hours (`cleanup`, maintenance loop).

Spec 041 (the Files page): `target: "folder"` puts the file in the folder `dir` itself instead of <dir>\\Web_Uploads -
the same write checks of the folder as written and as it resolves, refused with 403 files_off without the Files
switch; the upload belongs to no chat (never linked, never deleted by retention: `uploads.target` = 'folder'); its
SHA-256 is computed while the pieces arrive (the state is kept in memory between pieces and rebuilt from the partial
file once when it is missing, e.g. after a restart), stored in `uploads.sha256` and audited (`files.upload`). A chat
attachment (`target` missing or "chat") is handled exactly as before.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import stat
import time
import weakref
from pathlib import Path
from typing import Any

from starlette.requests import ClientDisconnect, Request
from starlette.routing import Route

from .context import HTTPError, body_json

log = logging.getLogger("goose_web")

MB = 1024 * 1024
LIMIT_MB_DEFAULT = 25                  # server.max_upload_mb when nothing is set
LIMIT_MB_MAX = 5120                    # 5 GB: the largest limit the administrator can set
CHUNK_BYTES = 16 * MB                  # what the page is asked to send per piece
MAX_CHUNK_BYTES = 32 * MB              # the most one piece may carry (app.BodyLimit caps the route at this too)
WRITE_BYTES = MB                       # bytes gathered in memory before they are written
MAX_OPEN_PER_USER = 20                 # unfinished uploads per person (the "20 files at once" rule)
MAX_PUTS_PER_USER = 4                  # pieces being received for one person at the same time
PARALLEL = 2                           # files the page sends at the same time
IDLE_SECONDS = 24 * 3600               # a partial file nobody added to for this long is deleted
PIECE_IDLE_SECONDS = 120               # a piece that brings no byte for this long ends (its slot is freed)
DISK_MARGIN = 1024 * MB                # free space that must remain on the drive after the upload (1 GB)
KEEP_ENDED_SECONDS = 30 * 86400        # rows of cancelled / abandoned / deleted uploads are dropped after this
PARTIAL_PREFIX = ".goose-web-upload-"
PARTIAL_SUFFIX = ".partial"
NOT_FOUND = "This upload does not exist or has ended."
ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,100}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
PIECE_ROUTE = re.compile(r"^/api/fs/uploads/[A-Za-z0-9_-]{20,100}$")   # app.BodyLimit: MAX_CHUNK_BYTES


def _api():
    from . import api   # api imports this module for its routes: resolved when a request comes
    return api


# ---------------------------------------------------------------------- the limit
def clamp_mb(value: Any) -> int:
    """1..LIMIT_MB_MAX; anything that is not a number counts as the default."""
    try:
        mb = int(float(value))
    except OverflowError:      # infinity
        return LIMIT_MB_MAX if float(value) > 0 else 1
    except (TypeError, ValueError):
        return LIMIT_MB_DEFAULT
    return max(1, min(LIMIT_MB_MAX, mb))


def config_mb(settings) -> int:
    """server.max_upload_mb from the configuration, clamped (a value above 5120 counts as 5120)."""
    return clamp_mb(settings.get("server", "max_upload_mb") or LIMIT_MB_DEFAULT)


def limit_mb(settings) -> int:
    """The limit for app.BodyLimit, which has no database: the administrator's setting as the app last loaded it
    (`load_admin_limit`, at start and at every save), else the configuration."""
    admin = getattr(settings, "admin_max_upload_mb", None)
    return clamp_mb(admin) if admin else config_mb(settings)


def load_admin_limit(settings, db) -> None:
    v = db.get_setting("max_upload_mb")
    settings.admin_max_upload_mb = clamp_mb(v) if v else None


def limit_bytes(c) -> int:
    """The limit in bytes for a request: Admin > Settings (stored) over server.max_upload_mb."""
    v = c.db.get_setting("max_upload_mb")
    return (clamp_mb(v) if v else config_mb(c.settings)) * MB


def single_request_mb(settings) -> int:
    """The single-request upload (api.fs_upload, multipart) keeps its old ceiling: the smaller of the limit and
    server.max_upload_mb. Starlette spools multipart files to the system's temp folder, which the disk check of the
    chunked upload does not cover; larger files go up in pieces (/api/fs/uploads)."""
    return min(limit_mb(settings), config_mb(settings))


def single_request_bytes(c) -> int:
    return min(limit_bytes(c), config_mb(c.settings) * MB)


def limit_text(mb: int) -> str:
    return f"{mb} MB" + (f" ({round(mb / 1024, 2):g} GB)" if mb >= 1024 else "")


def human(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def settings_view(c) -> dict:
    stored = c.db.get_setting("max_upload_mb")
    return {"maxUploadMb": clamp_mb(stored) if stored else config_mb(c.settings), "maxUploadMbMax": LIMIT_MB_MAX,
            "maxUploadMbConfig": config_mb(c.settings), "maxUploadMbStored": bool(stored)}


def clean_settings(b: dict) -> dict:
    """Admin > Settings: `maxUploadMb` 1..5120 (above is stored as 5120, below 1 as 1); null or "" = back to
    server.max_upload_mb. Raises 400 for anything else; writes nothing."""
    if "maxUploadMb" not in b:
        return {}
    v = b["maxUploadMb"]
    if v in (None, ""):
        return {"maxUploadMb": None}
    try:
        if isinstance(v, bool) or float(v) != float(v):
            raise ValueError
    except (TypeError, ValueError):
        raise HTTPError(400, "bad_request", "The largest file upload must be a number of megabytes")
    return {"maxUploadMb": clamp_mb(v)}


def store_settings(c, cleaned: dict) -> None:
    if "maxUploadMb" in cleaned:
        c.db.set_setting("max_upload_mb", cleaned["maxUploadMb"])
        load_admin_limit(c.settings, c.db)


def read_stored(settings, *keys: str) -> dict:
    """Admin settings from the database, opened read-only (`goose-web check` runs beside a running gateway)."""
    import json
    dbf = Path(settings.system_dir) / "goose-web.db"
    out: dict = {}
    if not dbf.is_file():
        return out
    try:
        con = sqlite3.connect(dbf.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            for k in keys:
                r = con.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()
                if r:
                    out[k] = json.loads(r[0])
        finally:
            con.close()
    except (sqlite3.Error, ValueError, TypeError):
        pass
    return out


def check_lines(settings) -> list[tuple[str, str]]:
    """`goose-web check`: the upload limit in force, and a configured value above 5120 (it counts as 5120)."""
    stored = read_stored(settings, "max_upload_mb").get("max_upload_mb")
    raw = settings.get("server", "max_upload_mb")
    eff = clamp_mb(stored) if stored else config_mb(settings)
    out = [("--", f"uploads: largest file {limit_text(eff)} ("
                  + ("Admin > Settings" if stored else "server.max_upload_mb") +
                  f"), sent in resumable pieces of {CHUNK_BYTES // MB} MB")]
    try:
        if raw not in (None, "") and float(raw) > LIMIT_MB_MAX:
            out.append(("!!", f"server.max_upload_mb: {raw} MB is configured, the limit is {LIMIT_MB_MAX} MB (5 GB) - "
                              f"{LIMIT_MB_MAX} is used"))
    except (TypeError, ValueError):
        out.append(("!!", f"server.max_upload_mb: {raw!r} is not a number of megabytes - {LIMIT_MB_DEFAULT} is used"))
    return out


# ---------------------------------------------------------------------- live state (per database)
class _Live:
    def __init__(self) -> None:
        self.busy: set[str] = set()          # uploads with a piece being received
        self.puts: dict[int, int] = {}       # user id -> pieces being received
        self.cancel: set[str] = set()        # cancelled while a piece was being received
        self.hashes: dict[str, tuple[int, Any]] = {}   # spec 041: folder upload -> (bytes hashed, SHA-256 state)


_LIVE: "weakref.WeakKeyDictionary[Any, _Live]" = weakref.WeakKeyDictionary()


def _live(db) -> _Live:
    st = _LIVE.get(db)
    if st is None:
        st = _LIVE[db] = _Live()
    return st


def _key(upload_id: str) -> str:
    return hashlib.sha256(str(upload_id).encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------- files (never follow a swapped file)
class _Swapped(Exception):
    """The partial file is not the file this upload created (replaced by a link or another file)."""


def file_ident(st) -> str:
    """volume:file-index of a stat result ('' when the file system gives no index)."""
    return f"{st.st_dev}:{st.st_ino}" if getattr(st, "st_ino", 0) else ""


def is_link(st) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _set_hidden(p: Path, hidden: bool) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetFileAttributesW.restype = ctypes.c_uint32
        k32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
        k32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        attrs = k32.GetFileAttributesW(str(p))
        if attrs == 0xFFFFFFFF:
            return
        new = (attrs | 0x2) if hidden else (attrs & ~0x2)
        if new != attrs:
            k32.SetFileAttributesW(str(p), new or 0x80)
    except Exception:   # cosmetic: a visible partial file is no problem
        log.debug("upload: hidden attribute not changed on %s", p, exc_info=True)


def _create_partial(d: Path) -> tuple[Path, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(5):
        p = d / f"{PARTIAL_PREFIX}{secrets.token_hex(12)}{PARTIAL_SUFFIX}"
        try:
            fd = os.open(p, flags, 0o600)
        except FileExistsError:
            continue
        try:
            ident = file_ident(os.fstat(fd))
        finally:
            os.close(fd)
        _set_hidden(p, True)
        return p, ident
    raise HTTPError(409, "name_taken", "Could not create the upload file")


def _same_place(p: Path, real_dir: str, ident: str) -> bool:
    """`p` is the file `ident`, as a plain file, in the folder that resolved to `real_dir` when the upload started."""
    try:
        st = os.lstat(p)
        rp = os.path.realpath(p)
    except (OSError, ValueError):
        return False
    if is_link(st) or not stat.S_ISREG(st.st_mode) or (ident and file_ident(st) != ident):
        return False
    return os.path.normcase(os.path.dirname(rp)) == os.path.normcase(real_dir)


def _open_partial(row: dict) -> int:
    st = os.lstat(row["partial"])      # FileNotFoundError: gone
    if is_link(st) or not stat.S_ISREG(st.st_mode):
        raise _Swapped()
    fd = os.open(row["partial"], os.O_WRONLY | getattr(os, "O_BINARY", 0))
    try:
        st2 = os.fstat(fd)
        if not stat.S_ISREG(st2.st_mode) or (row["file_id"] and file_ident(st2) != row["file_id"]):
            raise _Swapped()
    except BaseException:
        os.close(fd)
        raise
    return fd


def _discard(path: str, ident: str) -> bool:
    """Delete our own file at `path` (never a link, never another file); True when it is gone."""
    if not path:
        return True
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if is_link(st) or not stat.S_ISREG(st.st_mode) or (ident and file_ident(st) != ident):
        return False
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def _write_all(fd: int, data: bytes, h: Any = None) -> None:
    view = memoryview(data)
    try:
        while len(view):
            n = os.write(fd, view)
            view = view[n:]
    finally:
        view.release()
    if h is not None:      # spec 041: the SHA-256 of a folder upload, from the bytes as they were written
        h.update(data)


def _hash_partial(row: dict, upto: int) -> Any:
    """Spec 041: the SHA-256 state of the first `upto` bytes of the partial file - when the state kept in memory is
    missing (a restart) or behind. Only the file this upload created is read. Blocking."""
    h = hashlib.sha256()
    fd = os.open(row["partial"], os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (row["file_id"] and file_ident(st) != row["file_id"]):
            raise _Swapped()
        left = upto
        while left > 0:
            data = os.read(fd, min(4 * MB, left))
            if not data:
                raise _Swapped()    # shorter than what was counted
            h.update(data)
            left -= len(data)
    finally:
        os.close(fd)
    return h


def _hash_finished(target: Path, ident: str) -> tuple[str, int, int]:
    """Spec 041 / assessment F-5: (SHA-256, size, modification time in ns) of the finished file of a folder upload,
    read once - on Windows through a handle that lets nobody write while it reads. Only the file this upload created
    is read. Blocking."""
    if os.name == "nt":
        from . import files
        fd = files._hopen(target, files._GENERIC_READ, follow=False, share=0x1)   # FILE_SHARE_READ only
    else:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or is_link(st) or (ident and file_ident(st) != ident):
            raise _Swapped()
        h = hashlib.sha256()
        while data := os.read(fd, 4 * MB):
            h.update(data)
        st = os.fstat(fd)
    finally:
        os.close(fd)
    return h.hexdigest(), st.st_size, st.st_mtime_ns


def _rename_noreplace(src: Path, dst: Path) -> None:
    if os.name == "nt":
        os.rename(src, dst)        # MoveFileExW without MOVEFILE_REPLACE_EXISTING: never replaces a file
    else:
        os.link(src, dst)          # fails when dst exists
        os.unlink(src)


def _place(row: dict) -> Path:
    """Rename the finished partial file to its name in the folder; "name (1).ext" ... when the name is taken."""
    src = Path(row["partial"])
    st = os.lstat(src)
    if is_link(st) or not stat.S_ISREG(st.st_mode) or (row["file_id"] and file_ident(st) != row["file_id"]):
        raise _Swapped()
    d = Path(row["dir"])
    first = Path(row["name"])
    stem, suf = first.stem, first.suffix
    for n in range(0, 1001):
        target = d / (row["name"] if n == 0 else f"{stem} ({n}){suf}")
        if os.path.lexists(target):
            continue
        try:
            _rename_noreplace(src, target)
            return target
        except FileExistsError:
            continue
    raise HTTPError(409, "name_taken", "Too many files with that name in this folder")


# ---------------------------------------------------------------------- request helpers
def _own_row(c, u: dict, upload_id: str) -> dict:
    if not ID_RE.match(upload_id or ""):
        raise HTTPError(404, "not_found", NOT_FOUND)
    row = c.db.one("SELECT * FROM uploads WHERE id=?", (_key(upload_id),))
    if row is None or row["user_id"] != u["id"]:
        raise HTTPError(404, "not_found", NOT_FOUND)   # another person's upload: the same answer as none
    return row


def profile_for(c, u: dict, requested: Any) -> str:
    """The profile the files belong to: one's own; an administrator working in another profile (?profile=) names it."""
    own = str(u["username"]).lower()
    req = str(requested or "").strip().lower()
    if not req or req == own:
        return own
    if u.get("role") == "admin" and c.db.user_by_name(req):
        return req
    raise HTTPError(403, "forbidden", "Files can only be attached to chats of your own profile")


def session_arg(value: Any) -> str:
    s = str(value or "").strip()
    if s and not SESSION_RE.match(s):
        raise HTTPError(400, "bad_session", "session must be a chat id")
    return s


def _upload_dir(c, u: dict, raw_dir: str) -> Path:
    """<dir>\\Web_Uploads after the write checks of spec 031 (the folder as written and as it resolves)."""
    api = _api()
    base = os.path.abspath(raw_dir)
    try:
        api._check_path(c, u, base, write=True)
        # the folder that is written to, as it resolves: a link called Web_Uploads must not lead elsewhere
        d = api._check_path(c, u, os.path.join(base, api.UPLOAD_FOLDER), write=True)
    except HTTPError as e:
        if e.code == "read_only_folder":
            raise HTTPError(403, "read_only_folder", api.READ_ONLY_MESSAGE)
        raise
    if os.path.lexists(d) and not d.is_dir():
        raise HTTPError(409, "name_taken", f"{api.UPLOAD_FOLDER} exists in this folder and is not a folder")
    return d


def _folder_dir(c, u: dict, raw_dir: str) -> Path:
    """Spec 041 (`target: "folder"`): the folder itself, after the same write checks as Web_Uploads (the folder as
    written and as it resolves; a read-only folder is refused). It must exist: nothing is created on the way."""
    api = _api()
    try:
        d = api._check_path(c, u, os.path.abspath(raw_dir), write=True)
    except HTTPError as e:
        if e.code == "read_only_folder":
            raise HTTPError(403, "read_only_folder", api.READ_ONLY_MESSAGE)
        raise
    if not d.is_dir():
        raise HTTPError(404, "not_found", "Folder not found")
    return d


def _recheck(c, u: dict, d: Path) -> None:
    api = _api()
    try:
        api._check_path(c, u, str(d), write=True)
    except HTTPError as e:
        raise HTTPError(403, e.code, api.READ_ONLY_MESSAGE if e.code == "read_only_folder" else e.message)


def _check_disk(c, d: Path, size: int, now: float) -> None:
    probe = d
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return    # cannot tell: the write itself will fail if the disk is full
    drive = os.path.splitdrive(os.path.abspath(d))[0].lower()
    pending = sum(max(0, int(r["size"]) - int(r["received"])) for r in c.db.query(
        "SELECT dir, size, received FROM uploads WHERE state='open' AND updated_at>=?", (now - IDLE_SECONDS,))
        if os.path.splitdrive(str(r["dir"]))[0].lower() == drive)
    if free < size + pending + DISK_MARGIN:
        others = f", {human(pending)} for other uploads in progress" if pending else ""
        raise HTTPError(507, "disk_full", f"Not enough free disk space for this file: it needs {human(size)} plus "
                                          f"{human(DISK_MARGIN)} to spare{others}, and {human(free)} is free on the "
                                          "server's drive.", free=free)


def _file_view(row: dict) -> dict:
    p = Path(row["path"])
    return {"name": p.name, "path": str(p), "size": row["size"],
            "mime": row["mime"] or mimetypes.guess_type(p.name)[0] or "application/octet-stream"}


def link_upload(db, key: str, profile: str, session: str, now: float | None = None) -> int:
    return db.execute_count("INSERT OR IGNORE INTO upload_links(upload_id, profile, session_id, linked_at) "
                            "VALUES(?,?,?,?)", (key, profile, session, time.time() if now is None else now))


def _touch(c, profile: str, session: str) -> None:
    from . import retention
    try:
        retention.touch(c.db, profile, session, force=True)
    except Exception:
        log.exception("upload: recording the chat's last use")


def record_saved(c, u: dict, target: Path, size: int, mime: str, d: Path, profile: str = "",
                 session: str = "") -> str:
    """A file the single-request upload wrote (api.fs_upload): recorded like a finished chunked upload (spec 040),
    so retention knows it. Returns the id for the page."""
    upload_id = secrets.token_urlsafe(32)
    try:
        ident = file_ident(os.lstat(target))
        real = os.path.realpath(d)
    except OSError:
        ident, real = "", ""
    now = time.time()
    key = _key(upload_id)
    profile = profile or str(u["username"]).lower()
    c.db.execute("INSERT INTO uploads(id, user_id, username, profile, session_id, dir, real_dir, name, partial, path, "
                 "size, received, mime, state, file_id, created_at, updated_at, completed_at) "
                 "VALUES(?,?,?,?,?,?,?,?,'',?,?,?,?,'done',?,?,?,?)",
                 (key, u["id"], u["username"], profile, session, str(d), real, target.name, str(target), size, size,
                  mime or "", ident, now, now, now))
    if session:
        link_upload(c.db, key, profile, session, now)
    return upload_id


# ---------------------------------------------------------------------- handlers
async def _limits(c) -> dict:
    lim = limit_bytes(c)
    return {"maxBytes": lim, "maxMb": lim // MB, "chunkBytes": CHUNK_BYTES, "maxChunkBytes": MAX_CHUNK_BYTES,
            "parallel": PARALLEL, "maxFiles": MAX_OPEN_PER_USER}


async def collection(request: Request):
    api = _api()
    c = api.ctx(request)
    u = c.require(request).user
    if request.method == "GET":
        return api.ok(await _limits(c))
    return await _start(c, u, request)


async def _start(c, u: dict, request: Request):
    api = _api()
    b = await body_json(request, 16 * 1024)
    raw_dir = str(b.get("dir") or "").strip()
    if not raw_dir:
        raise HTTPError(400, "bad_request", "dir (the chat's folder) is required")
    size = b.get("size")
    try:
        if isinstance(size, bool) or not isinstance(size, (int, float)) or size != int(size) or size < 0:
            raise ValueError
    except (ValueError, OverflowError):     # NaN, Infinity
        raise HTTPError(400, "bad_request", "size must be the file's size in bytes")
    size = int(size)
    target = b.get("target") or "chat"
    if target not in ("chat", "folder"):
        raise HTTPError(400, "bad_request", 'target must be "chat" or "folder"')
    folder = target == "folder"
    if folder:
        from . import files
        files.gate(c, u)            # spec 041: the Files switch (403 files_off)
    lim = limit_bytes(c)
    if size > lim:
        raise HTTPError(413, "too_large", f"Uploads are limited to {limit_text(lim // MB)}", maxBytes=lim)
    name = api.safe_upload_name(b.get("name"))
    if folder:
        if files.is_recycle_name(name):
            raise HTTPError(400, "bad_name", "That name cannot be used")
        # a file of the Files page belongs to no chat: never linked, never deleted by retention (R9)
        profile, session = str(u["username"]).lower(), ""
    else:
        profile = profile_for(c, u, b.get("profile"))
        session = session_arg(b.get("session"))
    mime = "".join(ch for ch in str(b.get("mime") or "")[:200] if ch.isprintable())
    d = _folder_dir(c, u, raw_dir) if folder else _upload_dir(c, u, raw_dir)
    api._refuse_agents_dir(u, d)
    api._refuse_hint_name(u, name)
    api._refuse_agents_dir(u, d / name)
    now = time.time()
    n_open = c.db.one("SELECT COUNT(*) AS n FROM uploads WHERE user_id=? AND state='open' AND updated_at>=?",
                      (u["id"], now - IDLE_SECONDS))["n"]
    if n_open >= MAX_OPEN_PER_USER:
        raise HTTPError(429, "too_many_uploads", f"You have {n_open} unfinished uploads. Wait for them to finish or "
                                                 "cancel some.")
    _check_disk(c, d, size, now)
    if not folder:       # the folder of a folder upload exists (_folder_dir); nothing is made on the way
        try:
            await asyncio.to_thread(d.mkdir, parents=True, exist_ok=True)
        except PermissionError:
            raise HTTPError(403, "read_only_folder", api.READ_ONLY_MESSAGE)
    _recheck(c, u, d)    # R-5: looked at again right before the file is made
    real_dir = os.path.realpath(d)
    try:
        partial, ident = await asyncio.to_thread(_create_partial, d)
    except PermissionError:
        raise HTTPError(403, "read_only_folder", api.READ_ONLY_MESSAGE)
    if not _same_place(partial, real_dir, ident) or not c.path_ok(u, str(partial), write=True):
        # a junction swapped in between the check and the create: the file is not where it was meant to be
        await asyncio.to_thread(_discard, str(partial), ident)
        log.warning("upload: the folder %s changed while an upload of %s started; refused", d, u["username"])
        raise HTTPError(403, "path_forbidden", "The upload folder changed while the upload was starting. Try again.")
    upload_id = secrets.token_urlsafe(32)
    row = {"id": _key(upload_id), "user_id": u["id"], "username": u["username"], "profile": profile,
           "session_id": session, "dir": str(d), "real_dir": real_dir, "name": name, "partial": str(partial),
           "path": "", "size": size, "received": 0, "mime": mime, "state": "open", "file_id": ident,
           "created_at": now, "updated_at": now}
    if folder:
        row["target"] = "folder"
    cols = list(row)
    # column names are the fixed keys above; every value is a bound parameter (db.execute takes a sequence)
    c.db.execute(f"INSERT INTO uploads({', '.join(cols)}) VALUES({', '.join('?' for _ in cols)})",  # nosec B608
                 [row[k] for k in cols])
    out = {"id": upload_id, "chunkBytes": CHUNK_BYTES, "maxChunkBytes": MAX_CHUNK_BYTES, "received": 0, "size": size,
           "name": name, "done": False}
    if size == 0:
        out.update(done=True, file=await _finish(c, u, row, request))
    return api.ok(out)


async def one(request: Request):
    api = _api()
    c = api.ctx(request)
    u = c.require(request).user
    row = _own_row(c, u, request.path_params["uid"])
    if request.method == "GET":
        out = {"received": row["received"], "size": row["size"], "state": row["state"], "done": row["state"] == "done"}
        if row["state"] == "done":
            out["file"] = _file_view(row)
        return api.ok(out)
    if request.method == "DELETE":
        return api.ok(await _abort(c, row))
    return api.ok(await _put(c, u, row, request))


async def _abort(c, row: dict) -> dict:
    if row["state"] == "done":
        raise HTTPError(409, "upload_done", "This upload is complete; the file stays in " +
                        ("its folder." if row.get("target") == "folder" else "Web_Uploads."))
    if row["state"] != "open":
        return {"state": row["state"]}
    live = _live(c.db)
    c.db.execute("UPDATE uploads SET state='aborted', updated_at=? WHERE id=? AND state='open'", (time.time(), row["id"]))
    live.hashes.pop(row["id"], None)
    if row["id"] in live.busy:
        live.cancel.add(row["id"])     # the piece being received stops and deletes the file
    else:
        await asyncio.to_thread(_discard, row["partial"], row["file_id"])
    return {"state": "aborted"}


def _content_length(request: Request) -> int | None:
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    try:
        n = int(raw)
    except ValueError:
        raise HTTPError(400, "bad_request", "Invalid Content-Length")
    if n < 0:
        raise HTTPError(400, "bad_request", "Invalid Content-Length")
    return n


async def _put(c, u: dict, row: dict, request: Request) -> dict:
    if row["state"] != "open":
        raise HTTPError(409, "upload_ended", "This upload has ended" + (" (complete)" if row["state"] == "done" else ""),
                        received=row["received"], state=row["state"])
    try:
        offset = int(request.query_params.get("offset", ""))
    except ValueError:
        raise HTTPError(400, "bad_request", "offset must be a whole number")
    if offset != row["received"]:
        raise HTTPError(409, "offset_mismatch", f"The server has {row['received']} bytes of this file; continue from "
                                                "there.", received=row["received"])
    if row.get("target") == "folder":   # assessment F-9: the Files switch for every piece, not only at the start
        from . import files
        files.gate(c, u)
    declared = _content_length(request)
    if declared is not None and declared > MAX_CHUNK_BYTES:
        raise HTTPError(413, "too_large", f"One piece may carry at most {MAX_CHUNK_BYTES // MB} MB")
    if declared is not None and offset + declared > row["size"]:
        raise HTTPError(413, "too_large", "More bytes than the size given when the upload started")
    live = _live(c.db)
    key = row["id"]
    if key in live.busy:
        raise HTTPError(409, "upload_busy", "A piece of this file is still being received", received=row["received"])
    if live.puts.get(u["id"], 0) >= MAX_PUTS_PER_USER:
        raise HTTPError(429, "too_many_uploads", "Too many pieces at the same time; try again in a moment")
    live.busy.add(key)
    live.puts[u["id"]] = live.puts.get(u["id"], 0) + 1
    fd: int | None = None
    try:
        _recheck(c, u, Path(row["dir"]))
        try:
            fd = await asyncio.to_thread(_open_partial, row)
        except FileNotFoundError:
            _end(c, key, "aborted", "the partial file disappeared")
            raise HTTPError(410, "upload_lost", "The partial file is gone; start this upload again.")
        except (_Swapped, PermissionError, IsADirectoryError):
            _end(c, key, "aborted", "the partial file was replaced")
            log.warning("upload: the partial file of %s in %s was replaced; the upload is ended", u["username"],
                        row["dir"])
            raise HTTPError(409, "upload_lost", "The partial file was changed by something else; start this upload "
                                                "again.")
        have = os.fstat(fd).st_size
        if have < offset:
            os.close(fd)
            fd = None
            await asyncio.to_thread(_discard, row["partial"], row["file_id"])
            _end(c, key, "aborted", "the partial file was cut short")
            raise HTTPError(410, "upload_lost", "The partial file lost data; start this upload again.")
        if have > offset:      # a piece that ended half-way earlier (or a write by someone else): cut back
            os.ftruncate(fd, offset)
        os.lseek(fd, offset, os.SEEK_SET)
        h = await _hash_at(c, u, row, offset) if row.get("target") == "folder" else None
        try:
            n = await _receive(request, fd, offset, int(row["size"]), live, key, h)
        except ClientDisconnect:
            raise HTTPError(400, "disconnected", "The connection ended during the piece")
        received = offset + n
        await asyncio.to_thread(os.fsync, fd)
        now = time.time()
        c.db.execute("UPDATE uploads SET received=?, updated_at=? WHERE id=? AND state='open'", (received, now, key))
        if h is not None:      # spec 041: the hash moves on only with a piece that was kept whole
            live.hashes[key] = (received, h)
        if key in live.cancel:
            raise HTTPError(409, "upload_cancelled", "The upload was cancelled")
        if received < int(row["size"]):
            return {"received": received, "size": row["size"], "done": False}
        os.close(fd)
        fd = None
        file = await _finish(c, u, {**row, "received": received}, request)
        return {"received": received, "size": row["size"], "done": True, "file": file}
    finally:
        if fd is not None:
            os.close(fd)
        live.busy.discard(key)
        left = live.puts.get(u["id"], 1) - 1
        if left > 0:
            live.puts[u["id"]] = left
        else:
            live.puts.pop(u["id"], None)
        if key in live.cancel:
            live.cancel.discard(key)
            await asyncio.to_thread(_discard, row["partial"], row["file_id"])


async def _hash_at(c, u: dict, row: dict, offset: int) -> Any:
    """Spec 041: a copy of the SHA-256 state of a folder upload at `offset` (a failed piece leaves the kept state as
    it was); read from the partial file when there is none for that point (a restart)."""
    st = _live(c.db).hashes.get(row["id"])
    if st is not None and st[0] == offset:
        return st[1].copy()
    try:
        return await asyncio.to_thread(_hash_partial, row, offset)
    except (_Swapped, OSError):
        _end(c, row["id"], "aborted", "the partial file was replaced")
        log.warning("upload: the partial file of %s in %s was replaced; the upload is ended", u["username"], row["dir"])
        raise HTTPError(409, "upload_lost", "The partial file was changed by something else; start this upload again.")


async def _receive(request: Request, fd: int, offset: int, size: int, live: _Live, key: str, h: Any = None) -> int:
    """Write one piece to disk while it arrives: at most WRITE_BYTES are gathered before each write. All or
    nothing: whatever goes wrong, the file is cut back to where the piece started. `h`: a SHA-256 state the bytes
    are added to (spec 041; the caller keeps it only when the piece is kept)."""
    parts: list[bytes] = []
    held = 0
    n = 0
    stream = request.stream().__aiter__()
    try:
        while True:
            try:   # a connection that stalls must not hold the upload (and one of the person's 4 slots) forever
                piece = await asyncio.wait_for(stream.__anext__(), PIECE_IDLE_SECONDS)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                raise HTTPError(408, "timeout", f"No data for {PIECE_IDLE_SECONDS} seconds; send this piece again")
            if not piece:
                continue
            n += len(piece)
            if n > MAX_CHUNK_BYTES:
                raise HTTPError(413, "too_large", f"One piece may carry at most {MAX_CHUNK_BYTES // MB} MB")
            if offset + n > size:
                raise HTTPError(413, "too_large", "More bytes than the size given when the upload started")
            if key in live.cancel:
                raise HTTPError(409, "upload_cancelled", "The upload was cancelled")
            if len(piece) >= WRITE_BYTES:
                if parts:
                    data, parts, held = b"".join(parts), [], 0
                    await asyncio.to_thread(_write_all, fd, data, h)
                await asyncio.to_thread(_write_all, fd, piece, h)
                continue
            parts.append(piece)
            held += len(piece)
            if held >= WRITE_BYTES:
                data, parts, held = b"".join(parts), [], 0
                await asyncio.to_thread(_write_all, fd, data, h)
        if parts:
            await asyncio.to_thread(_write_all, fd, b"".join(parts), h)
    except BaseException:
        try:
            os.ftruncate(fd, offset)
        except OSError:
            pass
        raise
    finally:
        try:
            await stream.aclose()
        except Exception:
            pass
    return n


def _end(c, key: str, state: str, note: str) -> None:
    c.db.execute("UPDATE uploads SET state=?, note=?, updated_at=? WHERE id=? AND state='open'",
                 (state, note, time.time(), key))
    _live(c.db).hashes.pop(key, None)


async def _finish(c, u: dict, row: dict, request: Request) -> dict:
    """The last byte is in: the partial file gets its final name (never replacing a file), the upload is recorded
    and audited (name, size, folder - no content)."""
    d = Path(row["dir"])
    _recheck(c, u, d)
    folder = row.get("target") == "folder"
    if folder:     # F-9: ... and at the finish (switched off while the last piece arrived: it is not placed)
        from . import files
        files.gate(c, u)
    sha = ""
    if folder:     # spec 041: the SHA-256 of what arrived; the partial file is read once when the state is missing
        st = _live(c.db).hashes.pop(row["id"], None)
        if st is not None and st[0] == int(row["size"]):
            sha = st[1].hexdigest()
        else:
            try:
                sha = (await asyncio.to_thread(_hash_partial, row, int(row["size"]))).hexdigest()
            except (_Swapped, OSError):
                pass          # _place below finds out what happened to the file
    try:
        target = await asyncio.to_thread(_place, row)
    except FileNotFoundError:
        _end(c, row["id"], "aborted", "the partial file disappeared")
        raise HTTPError(410, "upload_lost", "The partial file is gone; start this upload again.")
    except _Swapped:
        _end(c, row["id"], "aborted", "the partial file was replaced")
        raise HTTPError(409, "upload_lost", "The partial file was changed by something else; start this upload again.")
    except PermissionError:
        raise HTTPError(403, "read_only_folder", _api().READ_ONLY_MESSAGE)
    if not _same_place(target, row["real_dir"], row["file_id"]) or not c.path_ok(u, str(target), write=True):
        # the folder was swapped for a link during the rename: the file is not kept where it landed
        await asyncio.to_thread(_discard, str(target), row["file_id"])
        _end(c, row["id"], "aborted", "the folder changed while the file was being finished")
        log.warning("upload: the folder %s changed while an upload of %s was finished; the file was removed", d,
                    u["username"])
        c.audit(request, "files.upload" if folder else "fs.upload", u, target=str(d),
                detail={"name": row["name"], "refused": "folder changed"}, ok=False)
        raise HTTPError(409, "upload_moved", "The upload folder changed while the file was being finished; the file "
                                             "was not kept. Try again.")
    mtime_ns = None
    if folder:     # assessment F-5: the finished file is read once - it must be exactly the bytes that arrived
        try:
            disk, disk_size, mtime_ns = await files.heavy(_hash_finished, target, row["file_id"], who=u["id"])
        except (_Swapped, OSError):
            disk, disk_size = "", -1
        if not sha or disk != sha or disk_size != int(row["size"]):
            await asyncio.to_thread(_discard, str(target), row["file_id"])
            _end(c, row["id"], "aborted", "the file changed on the server while it was uploaded")
            log.warning("upload: %s in %s (by %s) is not the file that was uploaded; it was not kept", target.name,
                        d, u["username"])
            c.audit(request, "files.upload", u, target=str(target),
                    detail={"name": target.name, "folder": str(d), "size": row["size"], "sha256Received": sha,
                            "sha256OnDisk": disk, "refused": "the file changed on the server while it was uploaded"},
                    ok=False)
            raise HTTPError(409, "upload_changed", "The file was changed on the server while it was being uploaded, "
                                                   "so it was not kept. Upload it again.")
    _set_hidden(target, False)
    now = time.time()
    mime = row["mime"] or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    n = c.db.execute_count("UPDATE uploads SET state='done', path=?, partial='', received=?, mime=?, completed_at=?, "
                           "updated_at=? WHERE id=? AND state='open'",
                           (str(target), row["size"], mime, now, now, row["id"]))
    if n == 0:     # cancelled while it was being renamed
        await asyncio.to_thread(_discard, str(target), row["file_id"])
        raise HTTPError(409, "upload_cancelled", "The upload was cancelled")
    if folder:     # spec 041: a file of the Files page - in no chat, audited with its SHA-256
        c.db.execute("UPDATE uploads SET sha256=?, mtime_ns=? WHERE id=?", (sha, mtime_ns, row["id"]))
        c.audit(request, "files.upload", u, target=str(target),
                detail={"name": target.name, "folder": str(d), "size": row["size"], "sha256": sha, "chunked": True})
        return {"name": target.name, "path": str(target), "size": row["size"], "mime": mime, "sha256": sha}
    if row.get("session_id"):
        link_upload(c.db, row["id"], row["profile"], row["session_id"], now)
        _touch(c, row["profile"], row["session_id"])
    detail = {"files": [target.name], "size": row["size"], "chunked": True}
    if row.get("session_id"):
        detail["sessionId"] = row["session_id"]
    if row.get("profile") and row["profile"] != str(u["username"]).lower():
        detail["profile"] = row["profile"]
    c.audit(request, "fs.upload", u, target=str(d), detail=detail)
    return {"name": target.name, "path": str(target), "size": row["size"], "mime": mime}


async def link(request: Request):
    """Spec 040: the chat the files belong to. `ids`: uploads of this person (made before the chat existed, on New
    chat); `from`: every file of another chat of the same profile (a fork shares the files of its chat)."""
    api = _api()
    c = api.ctx(request)
    u = c.require(request).user
    b = await body_json(request, 64 * 1024)
    profile = profile_for(c, u, b.get("profile"))
    session = session_arg(b.get("session"))
    if not session:
        raise HTTPError(400, "bad_session", "session (the chat's id) is required")
    ids = b.get("ids") or []
    if not isinstance(ids, list) or len(ids) > 100:
        raise HTTPError(400, "bad_request", "ids must be a list of at most 100 upload ids")
    now = time.time()
    n = 0
    for raw in ids:
        if not isinstance(raw, str) or not ID_RE.match(raw):
            continue
        row = c.db.one("SELECT id, user_id, profile, target FROM uploads WHERE id=?", (_key(raw),))
        if row is None or row["user_id"] != u["id"] or row["profile"] != profile or row["target"] == "folder":
            continue      # spec 041: a file of the Files page belongs to no chat (retention never deletes it)
        n += link_upload(c.db, row["id"], profile, session, now)
    src = session_arg(b.get("from"))
    if src and src != session:
        n += c.db.execute_count("INSERT OR IGNORE INTO upload_links(upload_id, profile, session_id, linked_at) "
                                "SELECT upload_id, profile, ?, ? FROM upload_links WHERE profile=? AND session_id=?",
                                (session, now, profile, src))
    if n:   # M-5 (assessment 2026-11-24): a use is recorded only for a chat files were really linked to
        _touch(c, profile, session)
    return api.ok({"linked": n})


# ---------------------------------------------------------------------- maintenance
def cleanup(c, now: float | None = None) -> int:
    """Partial files nobody added to for 24 hours are deleted (state abandoned); rows of uploads that ended long ago
    are dropped. Returns how many partial files were dealt with."""
    now = time.time() if now is None else now
    live = _live(c.db)
    n = 0
    for row in c.db.query("SELECT * FROM uploads WHERE state='open' AND updated_at<?", (now - IDLE_SECONDS,)):
        if row["id"] in live.busy:
            continue
        gone = _discard(row["partial"], row["file_id"])
        c.db.execute("UPDATE uploads SET state='abandoned', note=?, updated_at=? WHERE id=? AND state='open'",
                     ("" if gone else "the partial file was not ours any more and was left", now, row["id"]))
        live.hashes.pop(row["id"], None)
        n += 1
    c.db.execute("DELETE FROM uploads WHERE state IN ('aborted','abandoned','deleted','gone') AND updated_at<?",
                 (now - KEEP_ENDED_SECONDS,))
    c.db.execute("DELETE FROM upload_links WHERE upload_id NOT IN (SELECT id FROM uploads)")
    if n:
        log.info("uploads: %d partial file(s) idle for 24 hours removed", n)
    return n


routes = [
    Route("/api/fs/uploads", collection, methods=["GET", "POST"]),
    Route("/api/fs/uploads/link", link, methods=["POST"]),
    Route("/api/fs/uploads/{uid}", one, methods=["GET", "PUT", "DELETE"]),
]
