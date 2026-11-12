"""Per-user UI preferences: merge saves with revisions (1.18.2).

A save never replaces the whole object. The stored prefs carry three server-owned keys (keys starting with "_" are
never written by a client):

* ``_rev``     - the revision of the user's prefs, +1 on every save that changed something;
* ``_keyRev``  - ``{key: revision of its last change}`` (deleted keys keep theirs);
* ``_hist``    - ``{key: [short hashes of the last superseded values]}``, never sent to clients.

Two save forms:

* ``PATCH`` (this front end): ``{"baseRev": n, "set": {key: value}, "unset": [key], "client": tab id}``. A key that
  changed on the server after ``baseRev`` is a conflict: nothing is applied and the caller answers 409; the client
  reloads the prefs, keeps the other side's value and re-applies only what it can rebase.
* ``PUT`` (front ends before 1.18.2, still open during a deploy): the body is the client's whole object. It is merged:
  keys it does not send are kept, nothing is deleted, and a value equal to one the server has since replaced (a stale
  echo of an old copy) is skipped.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
CLIENT = re.compile(r"[^A-Za-z0-9_-]")
MAX_KEYS = 100           # client keys stored per user
MAX_STORED = 256 * 1024  # bytes of the stored JSON, server keys included
HIST_KEEP = 6            # superseded values remembered per key (hashes only)
SERVER_KEYS = ("_rev", "_keyRev", "_hist")


class PrefsError(ValueError):
    """A save that cannot be applied: ``code`` is the API error code."""

    def __init__(self, code: str, message: str, keys: list[str] | None = None):
        super().__init__(message)
        self.code = code
        self.keys = keys or []


@dataclass
class Result:
    prefs: dict
    rev: int
    changed: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # stale echoes / invalid names from an old client


def digest(v: Any) -> str:
    """A short hash of a JSON value (key order does not matter); only hashes of superseded values are stored."""
    raw = json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def client_id(v: Any) -> str:
    return CLIENT.sub("", str(v or ""))[:40]


def public(prefs: dict | None) -> dict:
    """What GET /api/me/prefs and the `_gw/prefs` broadcast return: everything but the value history."""
    return {k: v for k, v in (prefs or {}).items() if k != "_hist"}


def rev_of(prefs: dict | None) -> int:
    try:
        return max(0, int((prefs or {}).get("_rev") or 0))
    except (TypeError, ValueError):
        return 0


def apply(stored: dict | None, sets: dict, unsets: list | tuple = (), *, base_rev: int | None,
          clean: dict[str, Callable[[Any], Any]] | None = None) -> Result:
    """Merge one save into ``stored`` (not modified) and return the new prefs.

    ``base_rev`` None = an old client's whole-object PUT (merge-only: no deletes, stale echoes skipped, invalid names
    skipped). Otherwise a PATCH: invalid names raise ``PrefsError("bad_key")``, keys changed after ``base_rev`` raise
    ``PrefsError("prefs_conflict")``."""
    legacy = base_rev is None
    cur = dict(stored or {})
    rev = rev_of(cur)
    key_rev = {str(k): v for k, v in (cur.get("_keyRev") or {}).items() if isinstance(v, int)}
    hist = {str(k): list(v) for k, v in (cur.get("_hist") or {}).items() if isinstance(v, list)}
    res = Result(prefs=cur, rev=rev)
    if not isinstance(sets, dict) or not isinstance(unsets, (list, tuple)):
        raise PrefsError("bad_request", "set must be an object and unset a list")
    sets = {str(k): v for k, v in sets.items()}
    unsets = [str(k) for k in unsets]
    bad = [k for k in [*sets, *unsets] if not KEY.match(k)]   # "_..." (server keys) never match
    if bad:
        if not legacy:
            raise PrefsError("bad_key", "Preference names must be letters, digits, '_', '.' or '-' (max 64)", bad)
        res.skipped += [k for k in bad if not k.startswith("_")]
        sets = {k: v for k, v in sets.items() if k not in bad}
    if not legacy:
        both = set(sets) & set(unsets)
        if both:
            raise PrefsError("bad_request", "A preference cannot be set and removed in one save", sorted(both))
        conflicts = sorted(k for k in [*sets, *unsets] if key_rev.get(k, 0) > base_rev)
        if conflicts:
            raise PrefsError("prefs_conflict", "These preferences were changed in another tab or browser: "
                             + ", ".join(conflicts), conflicts)
    clean = clean or {}
    new_rev = rev + 1

    def supersede(k: str) -> None:
        if k in cur:
            h = digest(cur[k])
            hist[k] = [h] + [x for x in hist.get(k, []) if x != h][:HIST_KEEP - 1]

    for k, v in sets.items():
        if k in clean:
            v = clean[k](v)
        if k in cur and cur[k] == v:
            continue                                   # unchanged
        if legacy and digest(v) in hist.get(k, []):
            res.skipped.append(k)                      # an old copy of a value the server has since replaced
            continue
        supersede(k)
        cur[k] = v
        key_rev[k] = new_rev
        res.changed.append(k)
    for k in unsets if not legacy else ():
        if k in cur:
            supersede(k)
            del cur[k]
            key_rev[k] = new_rev
            res.deleted.append(k)
    if not (res.changed or res.deleted):
        return res
    client_keys = [k for k in cur if not k.startswith("_")]
    if len(client_keys) > MAX_KEYS:
        raise PrefsError("too_many_prefs", f"At most {MAX_KEYS} preferences per user")
    # bookkeeping for keys that no longer exist and were not touched for a long time is dropped first
    for book in (key_rev, hist):
        extra = [k for k in book if k not in cur]
        while len(book) > 2 * MAX_KEYS and extra:
            book.pop(extra.pop(0), None)
    cur["_rev"] = new_rev
    cur["_keyRev"] = key_rev
    cur["_hist"] = hist
    if len(json.dumps(cur, separators=(",", ":"), default=str)) > MAX_STORED:
        raise PrefsError("prefs_too_large", "Preferences are too large")
    res.rev = new_rev
    return res


def set_server_key(stored: dict | None, key: str, value: Any) -> dict:
    """Write one server-owned key (for example ``_notify``) without touching the rest or the revision."""
    if not key.startswith("_") or key in SERVER_KEYS:
        raise ValueError(f"not a writable server key: {key}")
    cur = dict(stored or {})
    cur[key] = value
    return cur
