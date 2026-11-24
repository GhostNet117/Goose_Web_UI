"""Spec 038: a provider (and the models allowed with it) an administrator gives ONE person, outside their team.

A row of `user_items` is a copy of a provider of an administrator's own profile - its definition, the NAMES of its key
variables (never a key value), the administrator it came from - plus the models this person may use with it. It is
delivered by Profiles.provision together with the team's items (one per kind and name; the person's own row wins), so
only this person's profile receives the provider file and its key, and the manifest removes both when the row goes.
The policy adds it to the team's lists (policy.add_user_grants): the provider joins allowed_providers and each model
counts only with its own provider (`granted_models`). Like a team item taken from an administrator's profile, a row
follows that profile's later edits (refresh)."""
from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger("goose_web.useritems")

KINDS = ("provider",)          # what can be given to one person (the table has a kind column for later kinds)
ANY = "*"                      # every model of the provider (policy.ANY)
MAX_MODELS = 500
MAX_MODEL_ID = 200
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def clean_models(raw: Any) -> list[str]:
    """The models given with a provider: model ids, trimmed and unique; ["*"] = every model of that provider; empty =
    none beyond what the team allows. Raises ValueError for anything but a list of ids."""
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_MODELS:
        raise ValueError(f"models must be a list of at most {MAX_MODELS} model ids")
    out: list[str] = []
    for m in raw:
        if not isinstance(m, str) or len(m.strip()) > MAX_MODEL_ID:
            raise ValueError(f"models must be a list of model ids (text of at most {MAX_MODEL_ID} characters)")
        m = m.strip()
        if m and m not in out:
            out.append(m)
    return [ANY] if ANY in out else out


def grant_provider_id(payload: Any) -> str:
    """The id Goose knows the given provider by: `name` in its definition (custom_providers/<file>.json), else the
    file's name it was taken from (the payload's providerId)."""
    pj = payload.get("json") if isinstance(payload, dict) else None
    name = pj.get("name") if isinstance(pj, dict) else None
    if isinstance(name, str) and _PROVIDER_ID.match(name):
        return name
    return str(payload.get("providerId") or "") if isinstance(payload, dict) else ""


def rows(db, user_id: Any) -> list[dict]:
    """What was given to this person, of the kinds that can be given."""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return []
    marks = ",".join("?" for _ in KINDS)
    return db.query(f"SELECT * FROM user_items WHERE user_id=? AND kind IN ({marks}) ORDER BY kind, name",  # nosec B608
                    (uid, *KINDS))


def grants(db, user_id: Any) -> dict[str, list[str]]:
    """{provider id: [models]} of the providers given to this person (policy.effective_policy's `grants`)."""
    out: dict[str, list[str]] = {}
    for r in rows(db, user_id):
        p = r.get("payload") if isinstance(r.get("payload"), dict) else {}
        pid = grant_provider_id(p)
        if r.get("kind") != "provider" or not pid:
            continue
        have = out.setdefault(pid, [])
        for m in p.get("models") or []:
            if isinstance(m, str) and m and m not in have:
                have.append(m)
    return out


def merge(team_items: list[dict], own: list[dict]) -> list[dict]:
    """What a profile receives: the team's items and this person's, one per kind and name - the person's row wins (the
    same provider, given with this person's models). Withdrawing the person's row leaves the team's copy."""
    own = [r for r in own if r.get("kind") in KINDS]
    mine = {(r["kind"], r["name"]) for r in own}
    return [r for r in team_items if (r["kind"], r["name"]) not in mine] + own


def refresh(profiles, db) -> dict[int, list[str]]:
    """Each row follows the administrator's profile it was taken from, as Profiles.refresh_team_items does for a
    team: exported again and, when the definition or its key names changed, replaced - the models given stay. Returns
    {user id: ["provider <name>", ...]} for the people to provision. A source that is gone or cannot be exported now
    keeps the copy (taking a provider away is the administrator's explicit step); a source that is no longer an
    administrator's profile is not followed. The key itself is never part of the copy: provisioning reads it from the
    source profile every time."""
    from . import security
    out: dict[int, list[str]] = {}
    for it in db.query("SELECT * FROM user_items"):
        try:
            src = str(it.get("source") or "")
            who, _, ref = src.partition(":")
            if not who or not ref or it.get("kind") not in KINDS:
                continue
            u = db.user_by_name(who)
            if not u or u.get("role") != "admin" or u.get("disabled"):
                continue
            try:
                name, payload = profiles.export_item(u, it["kind"], ref)
                name = security.safe_name(name.replace(" ", "-"), 128)
            except (ValueError, OSError, KeyError) as e:   # not there (any more), not shareable now: the copy stays
                log.debug("user items: %s %s of user %s not refreshed from %s: %s", it["kind"], it["name"],
                          it["user_id"], who, e)
                continue
            held = it["payload"] if isinstance(it["payload"], dict) else json.loads(it["payload"] or "{}")
            new = {**json.loads(json.dumps(payload)), "models": held.get("models") if isinstance(held.get("models"), list)
                   else []}
            if name != it["name"] or held == new:
                continue
            db.execute("UPDATE user_items SET payload=? WHERE id=?", (json.dumps(new), it["id"]))
            out.setdefault(int(it["user_id"]), []).append(f"{it['kind']} {name}")
            log.info("user items: %s %s of user %s brought in line with %s's profile", it["kind"], name,
                     it["user_id"], who)
        except Exception:       # one row must not stop the others
            log.exception("user items: refreshing %s %s (user %s)", it.get("kind"), it.get("name"), it.get("user_id"))
    return out
