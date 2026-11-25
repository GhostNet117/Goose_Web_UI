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
    GET  /api/files/recycle?location=           the items, their total size, canEmpty
    POST /api/files/recycle/empty {location}    administrators: everything in that bin removed for good now
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
from dataclasses import dataclass
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
CHANGED = ("The item or one of its folders changed while it was being moved (a link put in its place?); nothing was "
           "moved.")
HAS_LINK = ("This folder holds a link (a junction or a symbolic link), so it is not copied to another drive; nothing "
            "was moved. Move it on the server.")
COPY_BLOCK = 1024 * 1024
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


class _Tops(list):
    """The top folders (as configured) with what each resolves to."""
    def __init__(self, paths: list[str]) -> None:
        super().__init__(dict.fromkeys(paths))
        self.real = {r for r in (_real(t) for t in self) if r}


def _tops(c, u: dict, policy: dict) -> _Tops:
    """The top folders that are never renamed, moved or deleted, and whose recycle folder takes what is deleted in
    them: the person's locations, every team's folder and extra folders (read and write) and every person's
    workspace - for members too (assessment F-3: another team's location may lie inside a folder this person may
    write; it is compared, never shown) - and the folders holding Goose Web's own data. What is deleted inside one of
    them lands in the deepest one's recycle folder (the one its team sees)."""
    tops = [loc["path"] for loc in locations(c, u, policy)]
    for t in c.db.query("SELECT id, name, policy FROM teams"):
        tp = t["policy"] if isinstance(t["policy"], dict) else {}
        try:
            tops.append(str(c.profiles.team_folder({**t, "policy": tp})))
        except Exception:
            pass
        tops += [str(r) for k in ("allowed_roots", "read_roots") for r in tp.get(k) or []
                 if isinstance(r, str) and os.path.isabs(r)]
    # every person's extra folders and workspace too: nobody moves or deletes one (or the profile folder or the
    # profiles root holding it) from the Files page, and what an administrator deletes in one lands in its own
    # recycle folder
    for m in c.db.users():
        ov = m.get("policy_overrides") if isinstance(m.get("policy_overrides"), dict) else {}
        tops += [str(r) for k in ("allowed_roots", "read_roots") for r in ov.get(k) or []
                 if isinstance(r, str) and os.path.isabs(r)]
        try:
            tops.append(str(c.profiles.workspace(m)))
        except Exception:
            continue
    # ... and no folder holding Goose Web's own data (the system folder itself is out of reach: path_ok)
    tops += [str(c.settings.system_dir), str(c.settings.profiles_root)]
    return _Tops(tops)


def _location_of(path: Any, tops: list[str]) -> str | None:
    """The deepest top folder `path` lies in."""
    best = None
    for t in tops:
        if _within(path, t) and (best is None or len(_norm(t)) > len(_norm(best))):
            best = t
    return best


def _is_top(path: Any, tops: list[str]) -> bool:
    """`path` is a top folder or holds one - as written, and (unless it is a link) as it resolves."""
    n = _norm(path)
    if any(n == _norm(t) or _within(t, path) for t in tops):
        return True
    try:
        if is_link(os.lstat(path)):
            return False      # a link to a top folder is only a link: renaming or deleting it leaves the folder
    except (OSError, ValueError):
        return False
    r = _real(path)
    reals = getattr(tops, "real", None)
    if reals is None:
        reals = {x for x in (_real(t) for t in tops) if x}
    return bool(r) and any(t == r or t.startswith(r.rstrip("\\/") + os.sep) for t in reals)


def _protect(c, u: dict, src: Path, tops: list[str]) -> None:
    """What may not be renamed, moved or deleted: a top folder (a location, any team's or person's folder) or a
    folder holding one; for members a Goose hints file and anything in or named `.agents` (the administrator's)."""
    if _is_top(src, tops):
        raise HTTPError(403, "denied", "A location's top folder cannot be renamed, moved or deleted.")
    api = _api()
    api._refuse_hint_name(u, src.name)
    if u["role"] != "admin":     # F-7: also by its long name (an 8.3 alias such as GOOSEH~1 names the same file)
        api._refuse_hint_name(u, _long_name(src))
    api._refuse_agents_dir(u, src)


def _long_name(p: Any) -> str:
    """The last component of `p` with an 8.3 short name expanded (a link is not followed)."""
    if os.name != "nt":
        return os.path.basename(str(p))
    import ctypes
    buf = ctypes.create_unicode_buffer(4096)
    n = ctypes.windll.kernel32.GetLongPathNameW(str(p), buf, 4096)
    return os.path.basename(buf.value if 0 < n < 4096 else str(p))


HOLDS_SCAN_MAX = 100000      # entries looked at for hints files / .agents in a folder a member renames, moves, deletes


def _holds_protected(p: Path) -> tuple[str, str] | None:
    """(refusal, path) when the folder `p` holds a Goose hints file (or .gooseignore) or a `.agents` folder, at any
    depth (links not entered); too many entries to look at counts as holding one (fails closed). Blocking."""
    try:
        st = os.lstat(p)
    except OSError:
        return None
    if not stat.S_ISDIR(st.st_mode) or is_link(st):
        return None
    names = _api().REFUSED_FILE_NAMES
    for i, (_, e, _st) in enumerate(_walk(str(p))):
        if i >= HOLDS_SCAN_MAX:
            return "hint_file_refused", str(p)
        n = e.name.split(":", 1)[0].strip().rstrip(". ").lower()
        if n in names:
            return "hint_file_refused", e.path
        if pol.is_agents_name(n):
            return "agents_folder_refused", e.path
    return None


async def _protect_tree(u: dict, src: Path) -> None:
    """F-7: a member does not rename, move or delete a folder holding a Goose hints file or a `.agents` folder (the
    administrator's) - that would take them away from the chats started there."""
    if u["role"] == "admin":
        return
    found = await asyncio.to_thread(_holds_protected, src)
    if found:
        code, where = found
        raise HTTPError(403, code, f"This folder holds Goose settings your administrator manages ({where}); it cannot "
                                   "be renamed, moved or deleted from the file browser. Ask your administrator.")


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
def _hash_file(path: str) -> tuple[str, int, float, int, bool]:
    """SHA-256 of a regular file: (hex, size, mtime, mtime in ns, unchanged while read)."""
    with open(path, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise IsADirectoryError(path)
        h = hashlib.sha256()
        while chunk := f.read(HASH_BLOCK):
            h.update(chunk)
        st2 = os.fstat(f.fileno())
    return (h.hexdigest(), st2.st_size, st2.st_mtime, st2.st_mtime_ns,
            (st.st_size, st.st_mtime_ns) == (st2.st_size, st2.st_mtime_ns))


HASH_KEYS = ("sha256", "sha256Source", "recordedAt")


def _known(c, items: list[dict]) -> None:
    """Adds uploadedBy / uploadedAt (uploaded through Goose Web, still the same file: its file index) and a stored
    SHA-256 with where it comes from - sha256Source "upload" (taken from the file when its upload finished) or
    "computed" (on request), recordedAt: when - to file entries {path, size, mtime, mtime_ns}. A stored SHA-256 is
    given only while the file's size and modification time (ns) are exactly what they were when it was taken
    (assessment F-5); a file changed in place with both kept shows it all the same, labelled with its source and time
    ("Compute again" reads the file). Blocking: call in a thread."""
    files = [x for x in items if not x.get("dir")]
    if not files:
        return
    for x in files:
        if x.get("mtime_ns") is None:
            try:
                x["mtime_ns"] = os.stat(x["path"]).st_mtime_ns
            except OSError:
                x["mtime_ns"] = -1
    by_key = {_key(x["path"]): x for x in files}
    marks = ",".join("?" for _ in files)
    # the placeholders are "?" only; every value is a bound parameter
    rows = c.db.query(f"SELECT path, username, completed_at, sha256, size, file_id, mtime_ns "  # nosec B608
                      f"FROM uploads WHERE state='done' AND path COLLATE NOCASE IN ({marks}) ORDER BY completed_at",
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
        for k in HASH_KEYS:
            x.pop(k, None)
        if r["sha256"] and r["mtime_ns"] is not None and int(r["mtime_ns"]) == int(x["mtime_ns"]):
            x.update(sha256=r["sha256"], sha256Source="upload", recordedAt=r["completed_at"])
    rows = c.db.query(f"SELECT path, size, mtime_ns, sha256, at FROM file_hashes WHERE path IN "  # nosec B608
                      f"({','.join('?' for _ in by_key)})", list(by_key))
    for r in rows:
        x = by_key.get(r["path"])
        if x is not None and "sha256" not in x and int(r["size"]) == int(x["size"]) and r["mtime_ns"] is not None \
                and int(r["mtime_ns"]) == int(x["mtime_ns"]):
            x.update(sha256=r["sha256"], sha256Source="computed", recordedAt=r["at"])


def known_hash(c, path: Any, st=None) -> dict:
    """{sha256, sha256Source, recordedAt} of a file when a SHA-256 of it is stored and the file is unchanged (size and
    modification time); {} otherwise."""
    try:
        st = st or os.stat(path)
    except OSError:
        return {}
    item = {"path": str(path), "size": st.st_size, "mtime": st.st_mtime, "mtime_ns": st.st_mtime_ns}
    _known(c, [item])
    return {k: item[k] for k in HASH_KEYS if k in item}


def known_sha256(c, path: Any, st=None) -> str:
    """The stored SHA-256 of an unchanged file (known_hash); '' otherwise."""
    return known_hash(c, path, st).get("sha256") or ""


def _remember_hash(c, path: str, size: int, mtime: float, mtime_ns: int, sha: str, at: float) -> None:
    c.db.execute("INSERT INTO file_hashes(path, size, mtime, mtime_ns, sha256, at) VALUES(?,?,?,?,?,?) "
                 "ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, mtime_ns=excluded.mtime_ns, "
                 "sha256=excluded.sha256, at=excluded.at",
                 (_key(path), int(size), float(mtime), int(mtime_ns), sha, at))


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


def _is_link_entry(st) -> bool:
    """A link no walk enters and no copy takes: a symbolic link, a junction or a mount point (a name-surrogate
    reparse point; a reparse point of unknown kind counts as one). Other reparse points - deduplicated or cloud
    files - are ordinary data."""
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        tag = getattr(st, "st_reparse_tag", 0)
        return not tag or bool(tag & 0x20000000)
    return False


def _walk(root: str):
    """(folder, entry, its lstat) for everything below the folder `root`; never enters a link. Blocking."""
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                yield d, e, st
                if stat.S_ISDIR(st.st_mode) and not _is_link_entry(st):
                    stack.append(e.path)


def _find_link(root: str) -> str | None:
    """The first link (symbolic link, junction, mount point) inside the folder `root`, or None (assessment F-1)."""
    for _, e, st in _walk(root):
        if _is_link_entry(st):
            return e.path
    return None


def _measure(p: Path) -> tuple[int, bool]:
    """(bytes, is a folder) - a folder's files added up (at most SCAN_MAX entries looked at; links are not
    entered)."""
    st = os.lstat(p)
    if not stat.S_ISDIR(st.st_mode) or is_link(st):
        return st.st_size, False
    total = seen = 0
    for _, _, est in _walk(str(p)):
        seen += 1
        if seen > SCAN_MAX:
            break
        if not stat.S_ISDIR(est.st_mode):
            total += est.st_size
    return total, True


# ---------------------------------------------------------------------- an item held while it moves (F-1, F-2)
class _Changed(Exception):
    """The item, the folder it is in or the folder it goes to is not what was checked (a link or another item put in
    its place)."""


class _HasLink(Exception):
    """A folder to be copied to another volume holds a link (junction, symbolic link, mount point)."""


@dataclass(frozen=True)
class _Pin:
    """What was checked: the item's identity (volume:file index; '' when the file system has none) and - resolved,
    normcase - the folder it is in and the folder it goes to."""
    ident: str
    parent: str
    dest: str


def _pin(c, u: dict, src: Path, dest_dir: Any, dest_real: str = "") -> _Pin:
    """Taken right after the checks of a rename / move / delete / restore: the item's identity and both folders as
    they resolve now, each resolved folder checked once more - a link swapped in before this point is refused here;
    one swapped in later is found by _move_item, which holds the item and both folders while it moves the item."""
    try:
        st = os.lstat(src)
    except OSError:
        raise HTTPError(404, "not_found", NOT_FOUND)
    parent, dest = _real(src.parent), dest_real or _real(dest_dir)
    if not (parent and dest and c.path_ok(u, parent, write=True) and c.path_ok(u, dest, write=True)):
        raise HTTPError(403, "denied", CHANGED)
    return _Pin(file_ident(st), parent, dest)


# Windows: the item and both folders are held open (CreateFileW) while the item moves. A handle with data or delete
# access that does not share delete keeps anyone from renaming or deleting that item; any open handle keeps the folders
# above it from being renamed (NTFS) - so no path the move uses can be swapped for a link while it runs.
_GENERIC_READ, _DELETE, _LIST_DIRECTORY = 0x80000000, 0x00010000, 0x00000001
_READ_ATTRIBUTES, _SYNCHRONIZE = 0x00000080, 0x00100000
_SHARE_READ_WRITE = 0x1 | 0x2       # never FILE_SHARE_DELETE
_WIN: Any = None


def _win():
    global _WIN
    if _WIN is None:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = wintypes.HANDLE
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                  wintypes.DWORD, wintypes.HANDLE]
        k.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        k.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        k.SetFileInformationByHandle.restype = wintypes.BOOL
        k.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        _WIN = (ctypes, msvcrt, wintypes, k)
    return _WIN


def _hopen(path: Any, access: int, follow: bool, share: int = _SHARE_READ_WRITE) -> int:
    """A handle on `path` as a file descriptor (os.close closes it). `follow`: what a link leads to; else the link
    itself. Shared for reading and writing (or `share`), never for deleting."""
    ctypes, msvcrt, wintypes, k = _win()
    flags = 0x02000000 | (0 if follow else 0x00200000)   # FILE_FLAG_BACKUP_SEMANTICS (folders), _OPEN_REPARSE_POINT
    h = k.CreateFileW(str(path), access | _READ_ATTRIBUTES | _SYNCHRONIZE, share, None, 3, flags, None)
    if h is None or h == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return msvcrt.open_osfhandle(h, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        k.CloseHandle(h)
        raise


def _hpath(fd: int) -> str:
    """Where the held item is now, as the file system resolves it (without the \\\\?\\ prefix)."""
    ctypes, msvcrt, wintypes, k = _win()
    h = msvcrt.get_osfhandle(fd)
    n = 520
    while True:
        buf = ctypes.create_unicode_buffer(n)
        r = k.GetFinalPathNameByHandleW(h, buf, n, 0)
        if not r:
            raise ctypes.WinError(ctypes.get_last_error())
        if r < n:
            break
        n = r + 1
    p = buf.value
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    return p[4:] if p.startswith("\\\\?\\") else p


def _hrename(fd: int, dst: str) -> None:
    """Rename the held item to `dst` (a full path) - FileRenameInfo, never replacing anything."""
    ctypes, msvcrt, wintypes, k = _win()
    n = len(dst)

    class _RenameInfo(ctypes.Structure):
        _fields_ = [("replace", wintypes.DWORD), ("root", wintypes.HANDLE), ("length", wintypes.DWORD),
                    ("name", wintypes.WCHAR * (n + 1))]
    info = _RenameInfo(0, None, n * 2, dst)
    if not k.SetFileInformationByHandle(msvcrt.get_osfhandle(fd), 3, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())


def _rename_item(fd: int, dst: str) -> None:
    """The move itself (on the same volume); fails with ERROR_NOT_SAME_DEVICE across volumes."""
    _hrename(fd, dst)


def _hdelete(fd: int) -> None:
    """Delete the held item (a read-only file too; a link itself, never what it leads to)."""
    ctypes, msvcrt, wintypes, k = _win()
    h = msvcrt.get_osfhandle(fd)
    for flags in (0x13, 0x11):     # FileDispositionInfoEx: DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
        v = wintypes.DWORD(flags)
        if k.SetFileInformationByHandle(h, 21, ctypes.byref(v), ctypes.sizeof(v)):
            return
    one = ctypes.c_ubyte(1)        # FileDispositionInfo (older Windows)
    if not k.SetFileInformationByHandle(h, 4, ctypes.byref(one), 1):
        raise ctypes.WinError(ctypes.get_last_error())


def _held(fd: int, pin: _Pin) -> str:
    """The held item's path, once it was found to be the item that was checked, in the folder that was checked."""
    path = _hpath(fd)
    if (pin.ident and file_ident(os.fstat(fd)) != pin.ident) or os.path.normcase(os.path.dirname(path)) != pin.parent:
        raise _Changed(path)
    return path


def _hold_dir(path: Any, want: str, access: int = _LIST_DIRECTORY) -> int:
    """A folder held open while things move into it - after it was found to resolve to `want` (normcase)."""
    fd = _hopen(path, access, follow=True)
    try:
        if os.path.normcase(_hpath(fd)) != want or not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise _Changed(str(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _landed(fd: int, dest: str) -> bool:
    return os.path.normcase(os.path.dirname(_hpath(fd))) == dest


def _move_item(src: Path, dst: Path, pin: _Pin) -> list[str]:
    """Move a file or folder to `dst`, which must not exist (nothing is ever replaced) - the item that was checked,
    from the folder that was checked into the folder that was checked: all three are held open meanwhile, and a swap
    of any of them (for a link or another item) raises _Changed with nothing moved (assessment F-2). On the same volume
    a rename; across volumes a copy under a hidden name next to `dst`, renamed to `dst`, then the original is deleted -
    a folder holding a link raises _HasLink before anything is copied (F-1). Returns what of the original could not be
    deleted (across volumes: the copy is in place all the same, F-10). Blocking."""
    if os.name != "nt":
        return _move_item_posix(src, dst, pin)
    fd = _hopen(src, _DELETE, follow=False)
    try:
        dfd = _hold_dir(dst.parent, pin.dest)
        try:
            origin = _held(fd, pin)
            target = os.path.join(_hpath(dfd), dst.name)
            try:
                _rename_item(fd, target)
            except OSError as e:
                if not _cross_device(e):
                    raise
            else:
                if not _landed(fd, pin.dest):      # cannot happen while the folder is held; never left elsewhere
                    _hrename(fd, origin)
                    raise _Changed(target)
                return []
            os.close(fd)            # across volumes: the item is read as well - held again, looked at again
            fd = -1
            fd = _hopen(origin, _DELETE | _GENERIC_READ, follow=False)
            origin = _held(fd, pin)
            return _copy_across(fd, origin, dfd, dst.name)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)


def _copy_across(fd: int, origin: str, dfd: int, name: str) -> list[str]:
    """The held item `origin` copied into the held folder `dfd` as `name` (through a hidden temporary name), then
    deleted. Blocking."""
    st = os.fstat(fd)
    if is_link(st):
        raise _HasLink(origin)          # a link (or another reparse point) itself is not copied to another volume
    is_dir = stat.S_ISDIR(st.st_mode)
    if is_dir:
        found = _find_link(origin)
        if found:
            raise _HasLink(found)
    dest_dir = _hpath(dfd)
    tmp = os.path.join(dest_dir, f"{MOVE_PREFIX}{secrets.token_hex(8)}")
    try:
        if is_dir:
            _copy_dir(origin, tmp, st)
        else:
            _copy_file(fd, st, tmp)
        tfd = _hopen(tmp, _DELETE, follow=False)
        try:
            if os.path.normcase(_hpath(tfd)) != os.path.normcase(tmp) or is_link(os.fstat(tfd)):
                raise _Changed(tmp)
            _hrename(tfd, os.path.join(dest_dir, name))
        finally:
            os.close(tfd)
    except BaseException:
        try:
            _remove_tree(tmp)
        except OSError:
            log.warning("files: the temporary copy %s could not be removed", tmp)
        raise
    left = _delete_entries(origin) if is_dir else []
    if not left:
        try:
            _hdelete(fd)
        except OSError:
            left.append(origin)
    return left


def _copy_file(sfd: int, st, dst: str) -> None:
    """The held file `sfd` copied to the new file `dst` (its times and read-only flag too). Blocking."""
    os.lseek(sfd, 0, os.SEEK_SET)
    out = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
    try:
        while chunk := os.read(sfd, COPY_BLOCK):
            view = memoryview(chunk)
            while len(view):
                view = view[os.write(out, view):]
    finally:
        os.close(out)
    os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))
    if not st.st_mode & stat.S_IWRITE:
        os.chmod(dst, stat.S_IREAD)


def _copy_dir(src: str, dst: str, st) -> None:
    """The held folder `src` copied into the new folder `dst`, entry by entry: each one opened, found to be right
    there (not a link leading elsewhere: _HasLink) and held while it is copied; `dst` is held while it fills."""
    os.mkdir(dst)
    dfd = _hopen(dst, _LIST_DIRECTORY, follow=False)
    try:
        if os.path.normcase(_hpath(dfd)) != os.path.normcase(dst) or is_link(os.fstat(dfd)):
            raise _Changed(dst)
        with os.scandir(src) as it:
            names = [e.name for e in it]
        for nm in names:
            sp = os.path.join(src, nm)
            try:
                cfd = _hopen(sp, _GENERIC_READ, follow=True)
            except OSError:
                if os.path.lexists(sp) and _is_link_entry(os.lstat(sp)):
                    raise _HasLink(sp)
                raise
            try:
                if os.path.normcase(_hpath(cfd)) != os.path.normcase(sp):
                    raise _HasLink(sp)
                cst = os.fstat(cfd)
                if stat.S_ISDIR(cst.st_mode):
                    _copy_dir(sp, os.path.join(dst, nm), cst)
                else:
                    _copy_file(cfd, cst, os.path.join(dst, nm))
            finally:
                os.close(cfd)
        os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))
    finally:
        os.close(dfd)


def _delete_entries(d: str) -> list[str]:
    """Everything in the held folder `d` deleted, entry by entry: each one opened without following a link, found to
    be right there and deleted through its handle (a link: the link itself). Returns what could not be deleted."""
    left: list[str] = []
    try:
        with os.scandir(d) as it:
            names = [e.name for e in it]
    except OSError:
        return [d]
    for nm in names:
        p = os.path.join(d, nm)
        try:
            cfd = _hopen(p, _DELETE, follow=False)
        except OSError:
            left.append(p)
            continue
        try:
            cst = os.fstat(cfd)
            if os.path.normcase(_hpath(cfd)) != os.path.normcase(p):
                left.append(p)
                continue
            sub = _delete_entries(p) if stat.S_ISDIR(cst.st_mode) and not is_link(cst) else []
            if sub:
                left += sub
                continue
            _hdelete(cfd)
        except OSError:
            left.append(p)
        finally:
            os.close(cfd)
    return left


def _move_item_posix(src: Path, dst: Path, pin: _Pin) -> list[str]:
    """_move_item where items cannot be held open by handle: looked at before and after, put back on a mismatch."""
    st = os.lstat(src)
    if (pin.ident and file_ident(st) != pin.ident) or _real(src.parent) != pin.parent or \
            _real(dst.parent) != pin.dest:
        raise _Changed(str(src))
    try:
        _rename_noreplace(src, dst)
    except OSError as e:
        if not _cross_device(e):
            raise
        if os.path.lexists(dst):
            raise FileExistsError(errno.EEXIST, "File exists", str(dst))
        is_dir = stat.S_ISDIR(st.st_mode) and not is_link(st)
        found = str(src) if is_link(st) else _find_link(str(src)) if is_dir else None
        if found:
            raise _HasLink(found)
        tmp = dst.parent / f"{MOVE_PREFIX}{secrets.token_hex(8)}"
        try:
            if is_dir:
                shutil.copytree(src, tmp, symlinks=True)
            else:
                shutil.copy2(src, tmp, follow_symlinks=False)
            _rename_noreplace(tmp, dst)
        except BaseException:
            _remove_tree(tmp)
            raise
        try:
            _remove_tree(src)
        except OSError:
            return [str(src)]
        return []
    if (pin.ident and file_ident(os.lstat(dst)) != pin.ident) or _real(dst.parent) != pin.dest:
        _rename_noreplace(dst, src)
        raise _Changed(str(dst))
    return []


async def _move_pinned(c, u: dict, src: Path, dst: Path, pin: _Pin) -> list[str]:
    """_move_item in a thread, its refusals as answers: 403 denied when the item or a folder changed meanwhile, 409
    has_link for a folder with a link that would be copied to another volume."""
    try:
        return await heavy(_move_item, src, dst, pin)
    except _HasLink as e:
        log.warning("files: %s holds a link (%s); %s's move to another volume was refused", src, e, u["username"])
        raise HTTPError(409, "has_link", HAS_LINK)
    except _Changed as e:
        log.warning("files: %s changed while %s moved it (%s); nothing was moved", src, u["username"], e)
        raise HTTPError(403, "denied", CHANGED)
    except OSError as e:
        raise _os_error(e)


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
        self.refused: dict[tuple, float] = {}  # (user id, route, refusal, path) -> when last audited (F-16)
        self.slots: dict[tuple, int] = {}      # (kind, user id) -> requests running (F-12)
        self.forced: dict[tuple, float] = {}   # (user id, path) -> when its SHA-256 was last read with `force` (F-12)


# Assessment F-12: what can take long - a SHA-256 of a large file, a move (a copy across volumes) - runs in a small
# pool of its own, never in asyncio's shared one (sign-in, listings and upload writes use that); one person runs at
# most a few such requests at a time.
HEAVY_THREADS = 4
CHANGES_PER_PERSON = 2         # move / delete requests of one person at the same time
PREVIEWS_PER_PERSON = 2        # previews (an image holds up to 20 MB) of one person at the same time
FORCE_PAUSE = 10.0             # seconds between two forced SHA-256 computations of one file by one person
_POOL: Any = None


def _pool():
    global _POOL
    if _POOL is None:
        from concurrent.futures import ThreadPoolExecutor
        _POOL = ThreadPoolExecutor(max_workers=HEAVY_THREADS, thread_name_prefix="goose-web-files")
    return _POOL


async def heavy(fn, *args: Any) -> Any:
    """`fn(*args)` in the Files pool (see HEAVY_THREADS)."""
    import functools
    return await asyncio.get_running_loop().run_in_executor(_pool(), functools.partial(fn, *args))


class _slot:
    """One of a person's few requests of a kind at a time (429 busy beyond)."""

    def __init__(self, c, u: dict, kind: str, limit: int, what: str) -> None:
        self.live, self.key, self.limit, self.what = _live(c.db), (kind, u["id"]), limit, what

    def __enter__(self):
        if self.live.slots.get(self.key, 0) >= self.limit:
            raise HTTPError(429, "busy", f"{self.limit} {self.what} of yours are running; try again when one has "
                                         "finished.")
        self.live.slots[self.key] = self.live.slots.get(self.key, 0) + 1
        return self

    def __exit__(self, *exc) -> None:
        left = self.live.slots.get(self.key, 1) - 1
        if left > 0:
            self.live.slots[self.key] = left
        else:
            self.live.slots.pop(self.key, None)


_LIVE: "weakref.WeakKeyDictionary[Any, _Live]" = weakref.WeakKeyDictionary()


def _live(db) -> _Live:
    st = _LIVE.get(db)
    if st is None:
        st = _LIVE[db] = _Live()
    return st


# ---------------------------------------------------------------------- refusals are audited (assessment F-16)
REFUSAL_QUIET = 60.0      # seconds: one files.refused row per person, route, refusal and path in this time


async def _body(request: Request, limit: int) -> dict:
    """body_json, kept on the request for the audit of a refusal."""
    b = await body_json(request, limit)
    request.state.files_body = b
    return b


def _refusal_target(request: Request) -> str:
    qp = request.query_params
    p: Any = qp.get("path") or qp.get("location")
    if not p:
        b = getattr(request.state, "files_body", None) or {}
        p = b.get("path") or b.get("to") or b.get("id")
        if not p and isinstance(b.get("paths"), list) and b["paths"]:
            p = b["paths"][0]
    return str(p or "")[:4096]


def _refused(c, request: Request, u: dict, target: str, e: HTTPError) -> None:
    """A refused attempt (403: denied, read_only_folder, files_off, a hints or Goose folder name ...) is audited as
    files.refused with ok=False - once a minute per person, route, refusal and path - so probing for other people's
    folders shows in the SIEM without flooding it."""
    if e.status != 403:
        return
    try:
        live, now = _live(c.db), time.monotonic()
        key = (u["id"], request.url.path, e.code, _norm(target) if target else "")
        if now - live.refused.get(key, -REFUSAL_QUIET) < REFUSAL_QUIET:
            return
        if len(live.refused) > 10000:
            live.refused.clear()
        live.refused[key] = now
        c.audit(request, "files.refused", u, target=target, detail={"route": request.url.path, "error": e.code},
                ok=False)
    except Exception:
        log.exception("files: a refusal of %s could not be audited", request.url.path)


def _limited(kind: str, limit: int, what: str):
    """A route one person runs at most `limit` times at once (F-12)."""
    def wrap(handler):
        async def endpoint(request: Request):
            c = _api().ctx(request)
            with _slot(c, c.require(request).user, kind, limit, what):
                return await handler(request)
        endpoint.__name__, endpoint.__doc__ = handler.__name__, handler.__doc__
        return endpoint
    return wrap


def _audited(handler):
    """A route whose 403 answers are audited (_refused)."""
    async def endpoint(request: Request):
        try:
            return await handler(request)
        except HTTPError as e:
            if e.status == 403:
                try:
                    api = _api()
                    c = api.ctx(request)
                    u = c.require(request).user
                except Exception:
                    raise e from None
                _refused(c, request, u, _refusal_target(request), e)
            raise
    endpoint.__name__, endpoint.__doc__ = handler.__name__, handler.__doc__
    return endpoint


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
                        "mtime": st.st_mtime, "mtime_ns": st.st_mtime_ns, "hidden": hid})
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
    for x in page:
        x.pop("mtime_ns", None)
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
        item = {"path": str(p), "size": st.st_size, "mtime": st.st_mtime, "mtime_ns": st.st_mtime_ns}
        await asyncio.to_thread(_known, c, [item])
        out.update({k: item[k] for k in (*HASH_KEYS, "uploadedBy", "uploadedAt") if k in item})
    return api.ok(out)


async def hash_route(request: Request):
    api, c, u, _ = _begin(request)
    b = await _body(request, 16 * 1024)
    p = _check(c, u, _arg_path(b.get("path")))
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", NOT_FOUND)
    if not stat.S_ISREG(st.st_mode):
        raise HTTPError(400, "bad_request", "Only a file has a SHA-256")
    # `force`: read the file again even when its SHA-256 is known (size and modification time can be kept by
    # whoever changes a file in place)
    force = b.get("force") is True
    known = {} if force else await asyncio.to_thread(known_hash, c, p, st)
    if known:
        return api.ok({**known, "cached": True})
    live = _live(c.db)
    if force:      # F-12: "Compute again" reads the whole file - not over and over
        fkey, now = (u["id"], _key(p)), time.monotonic()
        if now - live.forced.get(fkey, -FORCE_PAUSE) < FORCE_PAUSE:
            raise HTTPError(429, "busy", "The SHA-256 of this file was just computed; try again in a few seconds.")
        if len(live.forced) > 10000:
            live.forced.clear()
        live.forced[fkey] = now
    if live.hashing.get(u["id"], 0) >= HASH_PARALLEL:
        raise HTTPError(429, "busy", f"{HASH_PARALLEL} SHA-256 computations of yours are running; try again when one "
                                     "has finished.")
    live.hashing[u["id"]] = live.hashing.get(u["id"], 0) + 1
    try:
        sha, size, mtime, mtime_ns, stable = await heavy(_hash_file, str(p))
    except OSError as e:
        raise _os_error(e)
    finally:
        left = live.hashing.get(u["id"], 1) - 1
        if left > 0:
            live.hashing[u["id"]] = left
        else:
            live.hashing.pop(u["id"], None)
    now = time.time()
    if stable:
        _remember_hash(c, str(p), size, mtime, mtime_ns, sha, now)
    return api.ok({"sha256": sha, "cached": False, "sha256Source": "computed", "recordedAt": now,
                   **({} if stable else {"changing": True})})


async def audit_file(c, request: Request, u: dict, p: Path, action: str, route: str = "", sent: bytes | None = None,
                     **extra: Any) -> dict:
    """Audit a read of a file (preview, /api/fs/read): its size and, when `sent` (the bytes that were read and sent)
    is the whole file, the SHA-256 of exactly those bytes - never a stored one, which may be stale (assessment
    F-5); a part is recorded as such."""
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", "File not found")
    detail: dict[str, Any] = {"size": st.st_size}
    if sent is not None:
        if len(sent) == st.st_size:
            detail["sha256"] = await asyncio.to_thread(lambda: hashlib.sha256(sent).hexdigest())
        else:
            detail["sha256Omitted"] = f"only the first {len(sent)} bytes were sent"
    if route:
        detail["route"] = route
    detail.update(extra)
    c.audit(request, action, u, target=str(p), detail=detail)
    return detail


class _SentFile(FileResponse):
    """A FileResponse whose body is watched as it goes out (assessment F-5, F-16): the files.download audit row is
    written when the answer has ended, with the SHA-256 of exactly the bytes that were sent when they were the whole
    file; a part (Range) or a download that did not finish is recorded as such, without one. HEAD sends nothing and
    records nothing."""

    def __init__(self, path: Path, *, record, **kw: Any) -> None:
        super().__init__(path, **kw)
        self._record = record

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or str(scope.get("method") or "GET").upper() == "HEAD":
            await super().__call__(scope, receive, send)
            return
        # every byte passes through `watch` (no zero-copy path send by the server)
        ext = {k: v for k, v in (scope.get("extensions") or {}).items() if k != "http.response.pathsend"}
        scope = {**scope, "extensions": ext}
        h = hashlib.sha256()
        seen: dict[str, Any] = {"status": 0, "sent": 0, "done": False}
        batch: list[bytes] = []

        async def watch(msg) -> None:
            if msg["type"] == "http.response.start":
                seen["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                body = msg.get("body") or b""
                if seen["status"] == 200 and body:
                    batch.append(body)
                    if sum(map(len, batch)) >= HASH_BLOCK:
                        data = b"".join(batch)
                        batch.clear()
                        await asyncio.to_thread(h.update, data)     # off the event loop
            await send(msg)
            if msg["type"] == "http.response.body":
                seen["sent"] += len(msg.get("body") or b"")
                if not msg.get("more_body", False):
                    seen["done"] = True

        try:
            await super().__call__(scope, receive, watch)
        finally:
            sha = ""
            if seen["status"] == 200 and seen["done"]:
                h.update(b"".join(batch))
                sha = h.hexdigest()
            self._record(seen["status"], seen["sent"], seen["done"], sha)


def _download_record(c, request: Request, u: dict, p: Path, size: int, route: str):
    def record(status: int, sent: int, done: bool, sha: str) -> None:
        detail: dict[str, Any] = {"size": size}
        rng = request.headers.get("range")
        if rng:
            detail["range"] = rng[:100]
        if route:
            detail["route"] = route
        if status != 200:
            detail["status"] = status
        if sha:
            detail["sha256"] = sha          # of the bytes that were sent
            if sent != size:
                detail["sent"] = sent
        else:
            detail["sha256Omitted"] = ("the download did not finish" if not done else
                                       "a part of the file was sent (Range)" if status == 206 else
                                       "the file was not sent")
        if not done:
            detail.update(complete=False, sent=sent)
        try:
            c.audit(request, "files.download", u, target=str(p), detail=detail)
        except Exception:
            log.exception("files: the download of %s by %s could not be audited", p, u["username"])
    return record


async def download_response(c, request: Request, u: dict, p: Path, route: str = "") -> Response:
    """The file as a download (both download routes): octet-stream + attachment + sandbox CSP; Range is answered
    (resuming); audited files.download when it has been sent (_SentFile)."""
    try:
        st = await asyncio.to_thread(os.stat, p)
    except OSError:
        raise HTTPError(404, "not_found", "File not found")
    if not stat.S_ISREG(st.st_mode):
        raise HTTPError(404, "not_found", "File not found")
    return _SentFile(p, record=_download_record(c, request, u, p, st.st_size, route), filename=p.name,
                     media_type="application/octet-stream", content_disposition_type="attachment",
                     headers={"Cache-Control": "no-store", "Content-Security-Policy": SANDBOX_CSP,
                              "X-Content-Type-Options": "nosniff"})


async def download_route(request: Request):
    api, c, u, _ = _begin(request)
    p = _check(c, u, _arg_path(request.query_params.get("path")))
    return await download_response(c, request, u, p)


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
        await audit_file(c, request, u, p, "files.preview", sent=data, kind="image")
        return Response(data, media_type=mime, headers={
            "Content-Disposition": "inline", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": SANDBOX_CSP, "Cache-Control": "no-store"})
    if kind.startswith("text") or kind == "empty":
        data = await asyncio.to_thread(_read_upto, p, PREVIEW_TEXT_BYTES)
        await audit_file(c, request, u, p, "files.preview", sent=data, kind="text")
        return api.ok({"kind": "text", "type": kind, "content": _decode_text(data, kind),
                       "truncated": st.st_size > PREVIEW_TEXT_BYTES})
    raise HTTPError(415, "no_preview", f"There is no preview for this kind of file ({kind}); download it instead.")


async def mkdir_route(request: Request):
    api, c, u, _ = _begin(request)
    b = await _body(request, 16 * 1024)
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
    b = await _body(request, 16 * 1024)
    src = _check(c, u, _arg_path(b.get("path")), write=True)
    name = clean_name(b.get("name"))
    tops = await asyncio.to_thread(_tops, c, u, policy)
    _protect(c, u, src, tops)
    await _protect_tree(u, src)
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
    await _move_pinned(c, u, src, dst, _pin(c, u, src, src.parent))
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
    b = await _body(request, 2 * 1024 * 1024)
    paths = _paths_arg(b)
    to = _check(c, u, _arg_path(b.get("to")), write=True)
    api._refuse_agents_dir(u, to)
    if not await asyncio.to_thread(to.is_dir):
        raise HTTPError(404, "not_found", "Folder not found")
    tops = await asyncio.to_thread(_tops, c, u, policy)
    moved: list[dict] = []
    failed: list[dict] = []
    for raw in paths:
        try:
            src = _check(c, u, _arg_path(raw), write=True)
            _protect(c, u, src, tops)
            await _protect_tree(u, src)
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
            left = await _move_pinned(c, u, src, dst, _pin(c, u, src, to))
            _repath(c, src, dst)
            detail: dict[str, Any] = {"from": str(src), "to": str(dst)}
            item = {"from": str(src), "to": str(dst)}
            if left:      # F-10: across volumes the copy is in place; what of the original could not be deleted stays
                detail["sourceLeft"] = left[:50]
                item["warning"] = (f"Moved, but {len(left)} item(s) of the original could not be deleted (in use or "
                                   "access denied); they are still in the old place.")
            c.audit(request, "files.move", u, target=str(dst), detail=detail)
            moved.append(item)
        except HTTPError as e:
            failed.append(_failed(raw, e))
            _refused(c, request, u, str(raw)[:4096], e)
    return api.ok({"moved": moved, "failed": failed})


def _recycle_slot(loc: Path, rid: str) -> tuple[Path, str, str]:
    """<location>\\.goose-web-recycle\\<id>, made (the recycle folder hidden) and checked: a real folder, right in the
    location (never a link that leads elsewhere). Something else under that name - a file, a link, made by anyone's
    agent - is moved aside to `.goose-web-recycle.conflict-<id>` (a link itself, never what it leads to) instead of
    blocking every delete (assessment F-11). Returns the slot, where it resolves to and what was moved aside ('' for
    nothing). Blocking."""
    rec = loc / RECYCLE_DIR
    aside = ""

    def ours() -> bool:
        st = os.lstat(rec)
        return not is_link(st) and stat.S_ISDIR(st.st_mode) and os.path.dirname(_real(rec)) == _real(loc)
    try:
        os.mkdir(rec)
    except FileExistsError:
        pass
    if not ours():
        moved = loc / f"{RECYCLE_DIR}.conflict-{secrets.token_hex(4)}"
        os.rename(rec, moved)
        aside = str(moved)
        log.warning("files: %s was not the recycle folder of Goose Web; moved aside to %s", rec, moved)
        try:
            os.mkdir(rec)
        except FileExistsError:
            pass
        if not ours():
            raise HTTPError(409, "denied", f"{RECYCLE_DIR} in this location is not a folder of Goose Web; ask your "
                                           "administrator.")
    _set_hidden(rec, True)
    slot = rec / rid
    os.mkdir(slot)
    return slot, os.path.join(_real(rec), rid), aside


async def delete_route(request: Request):
    api, c, u, policy = _begin(request, manage=True)
    b = await _body(request, 2 * 1024 * 1024)
    paths = _paths_arg(b)
    tops = await asyncio.to_thread(_tops, c, u, policy)
    deleted: list[dict] = []
    failed: list[dict] = []
    for raw in paths:
        try:
            src = _check(c, u, _arg_path(raw), write=True)
            _protect(c, u, src, tops)
            await _protect_tree(u, src)
            if not os.path.lexists(src):
                raise HTTPError(404, "not_found", NOT_FOUND)
            loc = _location_of(src, tops)
            if loc is None:
                raise HTTPError(403, "denied", "This item is in none of your locations.")
            _check(c, u, loc, write=True)
            rid = secrets.token_hex(10)
            try:
                slot, slot_real, aside = await asyncio.to_thread(_recycle_slot, Path(loc), rid)
            except OSError as e:
                raise _os_error(e)
            if aside:
                c.audit(request, "files.recycle_conflict", u, target=str(Path(loc) / RECYCLE_DIR),
                        detail={"movedTo": aside})
            dst = slot / src.name
            try:
                await _move_pinned(c, u, src, dst, _pin(c, u, src, slot, slot_real))
            except HTTPError:
                await asyncio.to_thread(_remove_empty, slot)
                raise
            _repath(c, src, dst)
            # F-2: measured where it is now - the item that really moved, in its recycle slot
            try:
                size, is_dir = await asyncio.to_thread(_measure, dst)
            except OSError:
                size, is_dir = 0, False
            known = {} if is_dir else await asyncio.to_thread(known_hash, c, dst)
            sha = known.get("sha256", "")
            now = time.time()
            c.db.execute("INSERT INTO file_recycle(id, location, original_path, recycle_path, name, is_dir, size, "
                         "sha256, deleted_by, deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (rid, str(loc), str(src), str(dst), src.name, 1 if is_dir else 0, size, sha, u["username"],
                          now))
            detail: dict[str, Any] = {"id": rid, "size": size, "dir": is_dir}
            if sha:      # a stored SHA-256 of the unchanged file, with where it came from (F-5)
                detail.update(sha256=sha, sha256Source=known["sha256Source"])
            c.audit(request, "files.delete", u, target=str(src), detail=detail)
            deleted.append({"path": str(src), "id": rid})
        except HTTPError as e:
            failed.append(_failed(raw, e))
            _refused(c, request, u, str(raw)[:4096], e)
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
    # F-13: what the bin holds, and whether this person may empty it before its time (administrators)
    return api.ok({"items": items, "size": sum(int(x["size"] or 0) for x in items), "canEmpty": u["role"] == "admin"})


async def empty_route(request: Request):
    """F-13: an administrator removes everything in a location's recycle bin for good now (a full disk), each item
    audited files.purge with `early`."""
    api, c, u, _ = _begin(request, manage=True)
    if u["role"] != "admin":
        raise HTTPError(403, "denied", "Only an administrator can empty a recycle bin before its time.")
    b = await _body(request, 16 * 1024)
    loc = _check(c, u, _arg_path(b.get("location")), write=True)
    now = time.time()
    purged = failed = 0
    for r in c.db.query("SELECT * FROM file_recycle WHERE location=? COLLATE NOCASE ORDER BY deleted_at", (str(loc),)):
        if _norm(r["location"]) != _norm(loc):
            continue
        how = await _purge_one(c, r, now)
        if how is None:
            failed += 1
            continue
        detail: dict[str, Any] = {"id": r["id"], "name": r["name"], "size": r["size"], "deletedBy": r["deleted_by"],
                                  "early": True}
        if how == "missing":
            detail["missing"] = True
        c.audit(request, "files.purge", u, target=r["original_path"], detail=detail)
        purged += 1
    return api.ok({"purged": purged, "failed": failed})


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
    b = await _body(request, 16 * 1024)
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
    await _move_pinned(c, u, src, dst, _pin(c, u, src, parent))
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
        "SELECT ts, username, action, target, detail FROM audit WHERE action LIKE 'files.%' AND ok=1 AND ("
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


PURGE_RETRY_SECONDS = 3600      # F-13: an item that could not be removed waits an hour, then goes behind the others


async def _purge_one(c, r: dict, now: float) -> str | None:
    """_purge_item in a thread and its records: 'deleted' / 'missing' (the row and what followed the item end), or
    None (could not be removed now: counted, tried again later behind the others)."""
    try:
        how = await asyncio.to_thread(_purge_item, r)
    except Exception:
        log.exception("files: purging %s", r.get("recycle_path"))
        how = None
    if how is None:
        c.db.execute("UPDATE file_recycle SET tries=tries+1, last_try=? WHERE id=?", (now, r["id"]))
        return None
    c.db.execute("DELETE FROM file_recycle WHERE id=?", (r["id"],))
    # the records of what was in it end too (an upload row 'deleted' is dropped after 30 days, uploads.cleanup)
    rp = str(r["recycle_path"])
    c.db.execute("UPDATE uploads SET state='deleted', note='removed from the recycle folder', updated_at=? WHERE "
                 "target='folder' AND state='done' AND (path=? COLLATE NOCASE OR path LIKE ? ESCAPE '^')",
                 (now, rp, _like_prefix(rp)))
    c.db.execute("DELETE FROM file_hashes WHERE path=? OR path LIKE ? ESCAPE '^'", (_key(rp), _like_prefix(_key(rp))))
    return how


async def purge_recycle(c, now: float | None = None) -> int:
    """Maintenance loop: recycled items older than files.recycle_days are removed for good (audited files.purge, by
    the system); one that cannot be removed now waits PURGE_RETRY_SECONDS and then comes after the others, so a few
    stuck items never hold up the rest (F-13); cached hashes nobody needed for a year are dropped. Returns how many
    items were purged."""
    now = time.time() if now is None else now
    days = recycle_days(c.settings)
    n = 0
    for r in c.db.query("SELECT * FROM file_recycle WHERE deleted_at<? AND (last_try IS NULL OR last_try<?) "
                        "ORDER BY tries, deleted_at LIMIT ?", (now - days * 86400, now - PURGE_RETRY_SECONDS,
                                                              PURGE_PER_RUN)):
        how = await _purge_one(c, r, now)
        if how is None:
            continue
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
    Route("/api/files/locations", _audited(locations_route)),
    Route("/api/files/list", _audited(list_route)),
    Route("/api/files/info", _audited(info_route)),
    Route("/api/files/hash", _audited(hash_route), methods=["POST"]),
    Route("/api/files/download", _audited(download_route)),
    Route("/api/files/preview", _audited(_limited("preview", PREVIEWS_PER_PERSON, "previews")(preview_route))),
    Route("/api/files/mkdir", _audited(mkdir_route), methods=["POST"]),
    Route("/api/files/rename", _audited(rename_route), methods=["POST"]),
    Route("/api/files/move", _audited(_limited("change", CHANGES_PER_PERSON, "moves or deletes")(move_route)),
          methods=["POST"]),
    Route("/api/files/delete", _audited(_limited("change", CHANGES_PER_PERSON, "moves or deletes")(delete_route)),
          methods=["POST"]),
    Route("/api/files/recycle", _audited(recycle_route)),
    Route("/api/files/recycle/empty", _audited(empty_route), methods=["POST"]),
    Route("/api/files/restore", _audited(restore_route), methods=["POST"]),
    Route("/api/files/activity", _audited(activity_route)),
]
