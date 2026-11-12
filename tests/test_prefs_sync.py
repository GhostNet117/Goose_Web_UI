"""1.18.2 (bug prefs-stale-tab-overwrite): a preferences save is merged, never a replacement.

A tab that loaded its prefs before another tab (or an administrator) changed them must not delete or revert the newer
keys: PATCH carries only the changed keys and the revision they are based on (a key changed since -> 409), an old front
end's whole-object PUT is merge-only (no deletes, stale echoes skipped), every save is audited with key NAMES only and
broadcast to the user's other tabs."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

import goose_web
from goose_web import hub as hubmod
from goose_web import prefsync
from test_sec_web import build, mk_user, sign_in

GROUPS = {"groups": [{"id": "lab", "name": "Lab", "members": [{"provider": "custom_a", "prefix": "A"},
                                                             {"provider": "custom_b", "prefix": "B"}]}],
          "modelNames": {"model-1": "Model One"}}


class Recorder:
    def __init__(self):
        self.sent = []

    def broadcast_user(self, uid, obj):
        self.sent.append((uid, obj))


@pytest.fixture
def gw(tmp_path):
    app, c = build(tmp_path)
    c.hub = Recorder()
    with TestClient(app) as client:
        yield client, c
    c.db.close()


def _client_keys(p: dict) -> dict:
    return {k: v for k, v in p.items() if not k.startswith("_")}


def _audits(c, uid):
    return [dict(r, detail=json.loads(r["detail"]) if isinstance(r["detail"], str) else r["detail"])
            for r in c.db.query("SELECT * FROM audit WHERE action='prefs.update' AND user_id=? ORDER BY id", (uid,))]


# ------------------------------------------------------------------ the merge rules (pure)
def test_patch_merges_and_counts_revisions():
    r = prefsync.apply({"theme": "dark", "_notify": {"webhook": None}}, {"density": "compact"}, [], base_rev=0)
    assert r.changed == ["density"] and r.rev == 1
    assert _client_keys(r.prefs) == {"theme": "dark", "density": "compact"}
    assert r.prefs["_notify"] == {"webhook": None} and r.prefs["_keyRev"] == {"density": 1}
    r2 = prefsync.apply(r.prefs, {"density": "compact"}, [], base_rev=1)     # unchanged value: nothing written
    assert not r2.changed and r2.rev == 1


def test_patch_conflict_only_for_keys_changed_after_the_base():
    p = prefsync.apply({}, {"theme": "dark", "providerGroups": GROUPS}, [], base_rev=0).prefs   # rev 1
    p = prefsync.apply(p, {"providerGroups": {"groups": []}}, [], base_rev=1).prefs              # rev 2
    ok = prefsync.apply(p, {"theme": "light"}, [], base_rev=1)        # an unrelated key from an older base: fine
    assert ok.changed == ["theme"] and ok.prefs["providerGroups"] == {"groups": []}
    with pytest.raises(prefsync.PrefsError) as e:
        prefsync.apply(p, {"providerGroups": GROUPS}, [], base_rev=1)
    assert e.value.code == "prefs_conflict" and e.value.keys == ["providerGroups"]
    with pytest.raises(prefsync.PrefsError):
        prefsync.apply(p, {}, ["providerGroups"], base_rev=1)         # a delete from an old base conflicts too


def test_explicit_delete_and_names():
    p = prefsync.apply({}, {"theme": "dark", "pinned": ["a"]}, [], base_rev=0).prefs
    r = prefsync.apply(p, {}, ["pinned", "missing"], base_rev=1)
    assert r.deleted == ["pinned"] and "pinned" not in r.prefs and r.prefs["_keyRev"]["pinned"] == 2
    for bad in ("_notify", "_rev", "", "a" * 65, "x y"):
        with pytest.raises(prefsync.PrefsError) as e:
            prefsync.apply(p, {bad: 1}, [], base_rev=1)
        assert e.value.code == "bad_key"
    with pytest.raises(prefsync.PrefsError):
        prefsync.apply(p, {"theme": "x"}, ["theme"], base_rev=1)


def test_legacy_put_never_deletes_and_skips_stale_echoes():
    old = {"theme": "dark", "newChat": {"provider": "custom_old", "model": ""}}
    p = prefsync.apply(old, {"newChat": {"provider": "custom_new", "model": "m"}, "providerGroups": GROUPS}, [],
                       base_rev=0).prefs
    # an old tab posts its whole load-time object plus one change (lastCwd): only lastCwd is new
    r = prefsync.apply(p, {**old, "lastCwd": "C:\\work", "_rev": 0, "_notify": {"webhook": "x"}}, [], base_rev=None)
    assert r.changed == ["lastCwd"] and r.skipped == ["newChat"]
    assert r.prefs["newChat"] == {"provider": "custom_new", "model": "m"} and r.prefs["providerGroups"] == GROUPS
    assert "_notify" not in r.prefs
    # a genuinely new value from an old tab is applied (last writer wins for that key)
    r2 = prefsync.apply(r.prefs, {"theme": "nord"}, [], base_rev=None)
    assert r2.changed == ["theme"]


def test_size_and_key_caps():
    with pytest.raises(prefsync.PrefsError) as e:
        prefsync.apply({}, {f"k{i}": 1 for i in range(prefsync.MAX_KEYS + 1)}, [], base_rev=0)
    assert e.value.code == "too_many_prefs"
    with pytest.raises(prefsync.PrefsError) as e:
        prefsync.apply({}, {"big": "x" * (prefsync.MAX_STORED + 1)}, [], base_rev=0)
    assert e.value.code == "prefs_too_large"


# ------------------------------------------------------------------ the API
def test_two_tab_race_keeps_the_newer_group(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    client.put("/api/me/prefs", headers=h, json={"theme": "dark", "newChat": {"provider": "custom_a", "model": ""}})
    tab_a = client.get("/api/me/prefs").json()                 # tab A loads (before the group exists)
    base_a = tab_a["_rev"]
    tab_b = client.get("/api/me/prefs").json()
    r = client.patch("/api/me/prefs", headers=h, json={"baseRev": tab_b["_rev"], "client": "tab-b",
                                                        "set": {"providerGroups": GROUPS}})
    assert r.status_code == 200 and r.json()["changed"] == ["providerGroups"]
    # tab A, still on its old copy, changes an unrelated setting and remembers a New chat choice
    r = client.patch("/api/me/prefs", headers=h, json={"baseRev": base_a, "client": "tab-a",
                                                        "set": {"density": "compact",
                                                                "newChat": {"provider": "custom_b", "model": "m2"}}})
    assert r.status_code == 200
    got = client.get("/api/me/prefs").json()
    assert got["providerGroups"] == GROUPS and got["density"] == "compact" and got["newChat"]["provider"] == "custom_b"
    assert r.json()["prefs"]["providerGroups"] == GROUPS          # the response carries the merged copy
    # tab A editing the groups from its old base is refused, nothing applied
    r = client.patch("/api/me/prefs", headers=h, json={"baseRev": base_a, "client": "tab-a",
                                                        "set": {"providerGroups": {"groups": []}, "theme": "nord"}})
    assert r.status_code == 409 and r.json()["conflicts"] == ["providerGroups"]
    got = client.get("/api/me/prefs").json()
    assert got["providerGroups"] == GROUPS and got["theme"] == "dark"
    assert "_hist" not in got                                    # value history stays on the server


def test_old_client_full_object_put_loses_nothing(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    old_copy = {"theme": "dark", "lastCwd": "C:\\a", "newChat": {"provider": "custom_old", "model": "", "effort": "",
                                                                   "mode": ""}}
    client.put("/api/me/prefs", headers=h, json=old_copy)
    base = client.get("/api/me/prefs").json()["_rev"]
    client.patch("/api/me/prefs", headers=h, json={"baseRev": base, "client": "tab-b", "set": {
        "providerGroups": GROUPS, "newChat": {"provider": "custom_a", "model": "model-1", "effort": "", "mode": ""}}})
    # the 1.18.1 front end still open: posts its whole load-time object with a new recent folder
    r = client.put("/api/me/prefs", headers=h, json={**old_copy, "lastCwd": "C:\\b", "recentFolders": ["C:\\b"]})
    assert r.status_code == 200
    got = client.get("/api/me/prefs").json()
    assert got["providerGroups"] == GROUPS                                      # not deleted
    assert got["newChat"]["provider"] == "custom_a"                             # stale echo skipped
    assert got["lastCwd"] == "C:\\b" and got["recentFolders"] == ["C:\\b"]     # its real change applied
    a = _audits(c, bob["id"])[-1]["detail"]
    assert a["mode"] == "legacy-put" and a["skipped"] == ["newChat"] and set(a["keys"]) == {"lastCwd", "recentFolders"}


def test_explicit_delete_via_patch(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    client.put("/api/me/prefs", headers=h, json={"theme": "dark", "providerGroups": GROUPS})
    base = client.get("/api/me/prefs").json()["_rev"]
    r = client.patch("/api/me/prefs", headers=h, json={"baseRev": base, "unset": ["providerGroups"], "client": "t"})
    assert r.status_code == 200 and r.json()["deleted"] == ["providerGroups"]
    got = client.get("/api/me/prefs").json()
    assert "providerGroups" not in got and got["theme"] == "dark"
    # an old tab that still has the deleted value cannot bring it back
    client.put("/api/me/prefs", headers=h, json={"theme": "dark", "providerGroups": GROUPS})
    assert "providerGroups" not in client.get("/api/me/prefs").json()


def test_patch_validation(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    assert client.patch("/api/me/prefs", headers=h, json={"set": {"theme": "x"}}).status_code == 400   # no baseRev
    assert client.patch("/api/me/prefs", headers=h, json={"baseRev": True, "set": {}}).status_code == 400
    assert client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "set": {"_notify": 1}}).status_code == 400
    assert client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "set": []}).status_code == 400
    assert client.patch("/api/me/prefs", json={"baseRev": 0, "set": {"theme": "x"}}).status_code == 403  # CSRF
    # cleaners apply to PATCH as well
    r = client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "set": {"providerVisibility": {"hidden": "all"}}})
    assert r.status_code == 200 and client.get("/api/me/prefs").json()["providerVisibility"] == {"hidden": []}


def test_audit_has_names_only_and_the_client(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "client": "tab-<x>1",
                                                   "set": {"lastCwd": "C:\\secret-folder-name", "theme": "dark"}})
    rows = _audits(c, bob["id"])
    assert len(rows) == 1 and rows[0]["ok"] == 1
    d = rows[0]["detail"]
    assert d == {"mode": "patch", "client": "tab-x1", "rev": 1, "keys": ["lastCwd", "theme"], "deleted": [],
                 "skipped": []}
    assert "secret-folder-name" not in json.dumps(rows[0], default=str)
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "client": "tab-y", "set": {"theme": "nord"}})
    bad = _audits(c, bob["id"])[-1]
    assert bad["ok"] == 0 and bad["detail"]["error"] == "prefs_conflict" and bad["detail"]["keys"] == ["theme"]
    # a save that changes nothing is not audited
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 1, "client": "tab-x1", "set": {"theme": "dark"}})
    assert len(_audits(c, bob["id"])) == 2


def test_save_is_broadcast_to_the_users_tabs(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "client": "tab-b", "set": {"providerGroups": GROUPS}})
    uid, msg = c.hub.sent[-1]
    assert uid == bob["id"] and msg["method"] == "_gw/prefs"
    p = msg["params"]
    assert p["rev"] == 1 and p["keys"] == ["providerGroups"] and p["client"] == "tab-b"
    assert p["prefs"]["providerGroups"] == GROUPS and "_hist" not in p["prefs"]
    n = len(c.hub.sent)
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 1, "set": {"providerGroups": GROUPS}})  # no change
    assert len(c.hub.sent) == n


def test_hub_broadcast_user_reaches_only_that_users_sockets():
    got = {"a1": [], "a2": [], "b": []}

    def sock(name, uid):
        return SimpleNamespace(user={"id": uid}, send=lambda raw, n=name: got[n].append(json.loads(raw)))

    a1, a2, b = sock("a1", 1), sock("a2", 1), sock("b", 2)
    fake = SimpleNamespace(upstreams={"alice": SimpleNamespace(clients=[a1, b]),
                                      "shared": SimpleNamespace(clients=[a1, a2])})
    hubmod.Hub.broadcast_user(fake, 1, {"method": "_gw/prefs", "params": {"rev": 3}})
    assert len(got["a1"]) == 1 and len(got["a2"]) == 1 and got["b"] == []    # once per socket, other users never


def test_front_end_sends_changed_keys_only_and_listens():
    js = Path(goose_web.__file__).parent / "static" / "js"
    prefs_js = (js / "prefs.js").read_text(encoding="utf-8")
    app_js = (js / "app.js").read_text(encoding="utf-8")
    assert "PATCH('/api/me/prefs', body" in prefs_js and "PUT(" not in prefs_js      # never the whole object
    assert "baseRev" in prefs_js and "export function removePref" in prefs_js
    assert "rpc.on('_gw/prefs', (p) => prefsChanged(p))" in app_js                      # live update from other tabs
    assert "refreshPrefs();" in app_js and "resetPrefsSync();" in app_js                # re-read on reconnect


def test_notify_save_keeps_prefs_and_revision(gw):
    client, c = gw
    bob = mk_user(c.db, "bob")
    h = sign_in(client, c, bob)
    client.patch("/api/me/prefs", headers=h, json={"baseRev": 0, "set": {"providerGroups": GROUPS}})
    assert client.put("/api/me/notify", headers=h, json={"webhook": None, "events": ["done"]}).status_code == 200
    stored = c.db.user_by_id(bob["id"])["prefs"]
    assert stored["providerGroups"] == GROUPS and stored["_rev"] == 1
    assert stored["_notify"] == {"webhook": None, "events": ["done"]}
