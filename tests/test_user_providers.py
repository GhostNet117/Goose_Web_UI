"""Spec 038: an administrator gives ONE person a provider of his own profile, and the models to use with it.

Team grants keep working as before (spec 033). A provider given to one person (table user_items):
- is ADDED to the person's lists, after the team and the person's overrides - never replacing them, a team "*" stays
  "*" - and its models count only with that provider (policy.granted_models), so a model given with one provider is
  not allowed with every other one;
- is delivered by Profiles.provision with the team's items (one per kind and name, the person's row wins): only that
  person's profile gets the provider file and its key, and both leave it when the grant is withdrawn;
- follows the administrator's later edits of the source provider (useritems.refresh, as refresh_team_items does);
- is managed through GET/POST /api/admin/users/{uid}/items and DELETE .../items/{iid} (administrators only, CSRF,
  audited), from the user dialog's "Providers for this user only"."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

import goose_web
from goose_web import policy as pol
from goose_web import useritems
from goose_web.auth import AuthService
from goose_web.context import Ctx

from test_profiles import make
from test_team_profiles import _Workers, client_for, sign_in, team

JS = Path(goose_web.__file__).parent / "static" / "js"
P = "_goose/unstable/"
TEAM = {"allowed_providers": ["openai"], "allowed_models": ["gpt-team"], "allowed_modes": ["*"]}


def _check(policy, method, params):
    pol.check(method, params, is_admin=False, policy=policy, roots=["/x"])


def _choice(provider, model):
    return {"configOptions": [{"id": "provider", "currentValue": provider}, {"id": "model", "currentValue": model}],
            "modes": {"currentModeId": "approve"}}


def _give(db, pr, admin, user, ref="p1", models=("m1",)):
    """What POST /api/admin/users/{uid}/items stores."""
    name, payload = pr.export_item(admin, "provider", ref)
    return db.execute("INSERT INTO user_items(user_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
                      (user["id"], "provider", name, json.dumps({**payload, "models": list(models)}),
                       f"{admin['username']}:{ref}"))


def _cfg(pr, user) -> Path:
    return pr.config_dir(user)


def _secrets(pr, user) -> dict:
    f = _cfg(pr, user) / "secrets.yaml"
    return (yaml.safe_load(f.read_text(encoding="utf-8")) or {}) if f.is_file() else {}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """The native administrator with provider p1 (key P1_KEY = s1) and p2 (key P2_KEY = s2); alice and bob in one team
    that allows the provider openai with the model gpt-team only."""
    s, db, pr, admin, alice, native = make(tmp_path, monkeypatch)
    (native / "config" / "custom_providers" / "p2.json").write_text(json.dumps(
        {"name": "p2", "engine": "openai", "api_key_env": "P2_KEY", "base_url": "http://y",
         "models": [{"name": "m2"}, {"name": "m3"}]}), encoding="utf-8")
    sec = yaml.safe_load((native / "config" / "secrets.yaml").read_text(encoding="utf-8"))
    (native / "config" / "secrets.yaml").write_text(yaml.safe_dump({**sec, "P2_KEY": "s2"}), encoding="utf-8")
    bob = db.user_by_id(db.create_user(username="bob", role="user"))
    tid = team(db, "Lab", TEAM)
    for u in (alice, bob):
        db.set_user_team(u["id"], tid)
    yield s, db, pr, admin, db.user_by_id(alice["id"]), db.user_by_id(bob["id"]), native, tid
    db.close()


# ------------------------------------------------------------------ policy: union, pairs
def test_a_grant_adds_to_the_team_lists_and_never_replaces_them():
    t = [{"id": 1, "name": "Lab", "policy": TEAM}]
    plain = pol.effective_policy({"role": "user"}, t)
    assert "granted_models" not in plain                                  # nothing given: as before
    e = pol.effective_policy({"role": "user"}, t, grants={"p1": ["m1"]})
    assert e["allowed_providers"] == ["openai", "p1"] and e["allowed_models"] == ["gpt-team"]
    assert e["granted_models"] == {"p1": ["m1"]} and e["chat_blocked"] == ""
    # a team "*" stays "*"; the models given still count with their provider only (the team's are for any)
    anyp = pol.effective_policy({"role": "user"}, [{"id": 1, "name": "A", "policy": {**TEAM, "allowed_providers": ["*"]}}],
                                grants={"p1": ["m1"]})
    assert anyp["allowed_providers"] == ["*"]
    # the person's overrides replace the team's value first, then the grant is added
    over = pol.effective_policy({"role": "user", "policy_overrides": {"allowed_providers": ["x"]}}, t,
                                grants={"p1": ["m1"]})
    assert over["allowed_providers"] == ["x", "p1"]
    # pairs: m1 only with p1; the team's model with any allowed provider, the given one included
    assert pol.model_allowed(e, "m1", "p1") and not pol.model_allowed(e, "m1", "openai")
    assert pol.model_allowed(e, "gpt-team", "p1") and pol.model_allowed(e, "gpt-team", "openai")
    assert pol.model_allowed(e, "m1") and not pol.model_allowed(e, "m9")  # a check without the provider: loose
    assert not pol.model_allowed(e, "m1", {"not": "hashable"}) and not pol.model_allowed(e, ["m1"], "p1")
    star = pol.effective_policy({"role": "user"}, t, grants={"p1": ["*"]})
    assert pol.model_allowed(star, "anything", "p1") and not pol.model_allowed(star, "anything", "openai")
    # a team that allows no models: the given ones are enough to chat; with none given, still blocked
    none = [{"id": 1, "name": "N", "policy": {**TEAM, "allowed_models": []}}]
    assert pol.effective_policy({"role": "user"}, none, grants={"p1": ["m1"]})["chat_blocked"] == ""
    assert "no models" in pol.effective_policy({"role": "user"}, none, grants={"p1": []})["chat_blocked"]
    # the team stays the base: no team = no chat; administrators are not restricted anyway
    lone = pol.effective_policy({"role": "user"}, [], grants={"p1": ["m1"]})
    assert lone["chat_blocked"] == pol.NO_TEAM_REASON and lone["allowed_providers"] == ["p1"]
    assert "granted_models" not in pol.effective_policy({"role": "admin"}, t, grants={"p1": ["m1"]})


def test_acp_the_grantee_may_use_the_provider_and_model_a_teammate_may_not():
    t = [{"id": 1, "name": "Lab", "policy": {**TEAM, "providers_edit": True}}]
    me = pol.effective_policy({"role": "user"}, t, grants={"p1": ["m1"]})
    mate = pol.effective_policy({"role": "user"}, t)
    _check(me, "session/set_config_option", {"configId": "provider", "value": "p1"})
    _check(me, "session/set_config_option", {"configId": "model", "value": "m1"})
    pol.check_session_choice(me, _choice("p1", "m1"))
    pol.check_session_choice(me, _choice("p1", "gpt-team"))
    pol.check_session_choice(me, _choice("openai", "gpt-team"))
    with pytest.raises(pol.Denied, match="model 'm1' with the provider 'openai'"):
        pol.check_session_choice(me, _choice("openai", "m1"))             # the pair holds at the prompt
    _check(me, P + "defaults/save", {"providerId": "p1", "modelId": "m1"})
    with pytest.raises(pol.Denied, match="model not allowed"):
        _check(me, P + "defaults/save", {"providerId": "openai", "modelId": "m1"})
    with pytest.raises(pol.Denied):
        _check(me, P + "defaults/save", {"providerId": {"x": 1}, "modelId": "m1"})
    assert pol.recipe_problems({"settings": {"goose_provider": "p1", "goose_model": "m1"}}, me, {}) == []
    assert pol.recipe_problems({"settings": {"goose_provider": "openai", "goose_model": "m1"}}, me, {})
    for method, params in (("session/set_config_option", {"configId": "provider", "value": "p1"}),
                           ("session/set_config_option", {"configId": "model", "value": "m1"}),
                           (P + "defaults/save", {"providerId": "p1", "modelId": "m1"})):
        with pytest.raises(pol.Denied):
            _check(mate, method, params)
    with pytest.raises(pol.Denied, match="provider 'p1'"):
        pol.check_session_choice(mate, _choice("p1", "m1"))
    assert pol.recipe_problems({"settings": {"goose_provider": "p1", "goose_model": "m1"}}, mate, {})


# ------------------------------------------------------------------ provisioning: the grantee only
def test_the_grantee_gets_the_file_and_the_key_a_teammate_gets_neither(setup):
    s, db, pr, admin, alice, bob, native, tid = setup
    _give(db, pr, admin, alice, "p1", ["m1"])
    changes = pr.provision(alice)
    assert "provider p1" in changes and (_cfg(pr, alice) / "custom_providers" / "p1.json").is_file()
    assert _secrets(pr, alice) == {"P1_KEY": "s1"}
    pr.provision(bob)
    assert not (_cfg(pr, bob) / "custom_providers" / "p1.json").exists() and "P1_KEY" not in _secrets(pr, bob)
    man = json.loads(pr.manifest_path(alice).read_text(encoding="utf-8"))
    assert man["providers"] == ["p1"] and set(man["secrets"]) == {"P1_KEY"}
    # the grant is in the policy both of them get from the gateway: alice's only
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=pr, workers=_Workers(), hub=None, version="t")
    pa, pb = c.policy_for(alice), c.policy_for(bob)
    assert pa["allowed_providers"] == ["openai", "p1"] and pa["granted_models"] == {"p1": ["m1"]}
    assert pb["allowed_providers"] == ["openai"] and "granted_models" not in pb
    before = c.rights_fingerprint(alice)
    # withdrawn: gone at the next provisioning, file and key; the open sockets see changed rights (closed, reconnect)
    db.execute("DELETE FROM user_items WHERE user_id=?", (alice["id"],))
    changes = pr.provision(alice)
    assert "provider p1 removed" in changes and "secret P1_KEY removed" in changes
    assert not (_cfg(pr, alice) / "custom_providers" / "p1.json").exists() and "P1_KEY" not in _secrets(pr, alice)
    assert c.rights_fingerprint(alice) != before
    # the profile default follows: a provider that is no longer allowed is reset
    _give(db, pr, admin, alice, "p1", ["m1"])
    cfgf = _cfg(pr, alice) / "config.yaml"
    pr.provision(alice)
    cfg = yaml.safe_load(cfgf.read_text(encoding="utf-8"))
    cfg.update({"GOOSE_PROVIDER": "p1", "GOOSE_MODEL": "m1"})
    cfgf.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    pr.provision(alice)
    assert yaml.safe_load(cfgf.read_text(encoding="utf-8"))["GOOSE_MODEL"] == "m1"     # the pair is allowed: kept
    db.execute("DELETE FROM user_items")
    assert "provider reset to an allowed one" in pr.provision(alice)
    assert yaml.safe_load(cfgf.read_text(encoding="utf-8")).get("GOOSE_PROVIDER") == "openai"


def test_a_provider_the_team_gives_too_stays_when_the_personal_grant_goes(setup):
    s, db, pr, admin, alice, bob, native, tid = setup
    name, payload = pr.export_item(admin, "provider", "p1")
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
               (tid, "provider", name, json.dumps(payload), "admin:p1"))
    _give(db, pr, admin, alice, "p1", ["m1"])
    rows = useritems.merge(pr.team_items(alice), useritems.rows(db, alice["id"]))
    assert [(r["kind"], r["name"], "models" in r["payload"]) for r in rows] == [("provider", "p1", True)]  # once, hers
    pr.provision(alice)
    pr.provision(bob)
    for u in (alice, bob):
        assert (_cfg(pr, u) / "custom_providers" / "p1.json").is_file() and _secrets(pr, u)["P1_KEY"] == "s1"
    db.execute("DELETE FROM user_items")
    changes = pr.provision(alice)
    assert not [x for x in changes if "p1" in x or "P1_KEY" in x]        # the team's copy: nothing to take away
    assert (_cfg(pr, alice) / "custom_providers" / "p1.json").is_file() and _secrets(pr, alice)["P1_KEY"] == "s1"


def test_the_grant_follows_the_administrators_edits(setup):
    s, db, pr, admin, alice, bob, native, tid = setup
    _give(db, pr, admin, alice, "p2", ["m2"])
    pr.provision(alice)
    assert useritems.refresh(pr, db) == {}                                 # nothing changed: nothing rewritten
    pf = native / "config" / "custom_providers" / "p2.json"
    pj = json.loads(pf.read_text(encoding="utf-8"))
    pj["base_url"] = "http://PROVIDER-V2"
    pf.write_text(json.dumps(pj), encoding="utf-8")
    assert useritems.refresh(pr, db) == {alice["id"]: ["provider p2"]}
    held = db.one("SELECT payload FROM user_items")["payload"]
    assert held["json"]["base_url"] == "http://PROVIDER-V2" and held["models"] == ["m2"]     # the models given stay
    pr.provision(alice)
    assert "PROVIDER-V2" in (_cfg(pr, alice) / "custom_providers" / "p2.json").read_text(encoding="utf-8")
    assert useritems.refresh(pr, db) == {}
    # the source is gone: the copy stays (taking it away is the administrator's step); a member's profile is never
    # followed (a row can only come from an administrator's, but a demoted one stops counting)
    pf.unlink()
    assert useritems.refresh(pr, db) == {} and db.one("SELECT payload FROM user_items")["payload"]["json"]
    pf.write_text(json.dumps({**pj, "base_url": "http://PROVIDER-V3"}), encoding="utf-8")
    db.update_user(admin["id"], role="user")
    assert useritems.refresh(pr, db) == {}
    db.update_user(admin["id"], role="admin")
    assert useritems.refresh(pr, db) == {alice["id"]: ["provider p2"]}


# ------------------------------------------------------------------ API
@pytest.fixture
def api(setup):
    s, db, pr, admin, alice, bob, native, tid = setup
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=pr, workers=_Workers(), hub=None, version="t")
    with client_for(c) as tc:
        yield tc, c, setup


def test_api_give_list_change_and_take_away(api):
    tc, c, (s, db, pr, admin, alice, bob, native, tid) = api
    h = sign_in(tc, c, admin)
    url = f"/api/admin/users/{alice['id']}/items"
    r = tc.post(url, json={"kind": "provider", "fromProfile": "admin", "ref": "p2", "models": ["m2", " m2 ", ""]}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "p2" and r.json()["providerId"] == "p2" and r.json()["models"] == ["m2"]
    assert "provider p2" in r.json()["changes"] and _secrets(pr, alice) == {"P2_KEY": "s2"}
    a = db.one("SELECT * FROM audit WHERE action='user.item.add'")
    assert a["target"] == "alice:provider:p2" and a["detail"] == {"source": "admin:p2", "models": ["m2"]}
    got = tc.get(url).json()
    assert [(i["name"], i["providerId"], i["models"], i["fromProfile"], i["sourceGone"]) for i in got["items"]] == \
        [("p2", "p2", ["m2"], "admin", False)]
    assert got["team"] == {"id": tid, "name": "Lab", "providers": [], "allowedProviders": ["openai"],
                           "allowedModels": ["gpt-team"]} and got["native"] is False
    # the same provider again replaces its models (one row); "*" = every model of it
    r = tc.post(url, json={"kind": "provider", "fromProfile": "admin", "ref": "p2", "models": ["m3", "*"]}, headers=h)
    assert r.status_code == 200 and r.json()["models"] == ["*"]
    assert [i["models"] for i in tc.get(url).json()["items"]] == [["*"]]
    # the member's own view: the provider and its models are offered to alice, not to bob
    assert c.policy_for(db.user_by_id(alice["id"]))["granted_models"] == {"p2": ["*"]}
    assert "granted_models" not in c.policy_for(bob)
    iid = tc.get(url).json()["items"][0]["id"]
    assert tc.delete(f"/api/admin/users/{bob['id']}/items/{iid}", headers=h).status_code == 404   # not bob's
    r = tc.delete(f"{url}/{iid}", headers=h)
    assert r.status_code == 200 and "provider p2 removed" in r.json()["changes"]
    assert "P2_KEY" not in _secrets(pr, alice) and tc.get(url).json()["items"] == []
    assert db.one("SELECT target FROM audit WHERE action='user.item.remove'")["target"] == "alice:provider:p2"
    assert tc.delete(f"{url}/{iid}", headers=h).status_code == 404
    # deleting the person deletes what was given to them
    tc.post(url, json={"kind": "provider", "fromProfile": "admin", "ref": "p2", "models": []}, headers=h)
    db.execute("DELETE FROM users WHERE id=?", (alice["id"],))
    assert db.one("SELECT COUNT(*) AS n FROM user_items")["n"] == 0


def test_api_refusals(api):
    tc, c, (s, db, pr, admin, alice, bob, native, tid) = api
    url = f"/api/admin/users/{alice['id']}/items"
    good = {"kind": "provider", "fromProfile": "admin", "ref": "p1", "models": ["m1"]}
    hb = sign_in(tc, c, bob)                                              # a member
    assert tc.get(url).status_code == 403 and tc.post(url, json=good, headers=hb).status_code == 403
    assert tc.delete(f"{url}/1", headers=hb).status_code == 403
    h = sign_in(tc, c, admin)
    assert tc.post(url, json=good).status_code == 403                    # no CSRF header
    assert tc.post(url, json=good, headers={**h, "origin": "http://evil.example"}).status_code == 403
    for body, code in (({**good, "kind": "skill"}, "bad_kind"), ({**good, "fromProfile": "bob"}, "bad_source"),
                       ({**good, "fromProfile": "nobody"}, "bad_source"), ({**good, "ref": "nope"}, "bad_ref"),
                       ({**good, "ref": "..\\..\\secrets"}, "bad_ref"), ({**good, "models": "m1"}, "bad_models"),
                       ({**good, "models": [1]}, "bad_models")):
        r = tc.post(url, json=body, headers=h)
        assert r.status_code == 400 and r.json()["error"] == code, (body, r.text)
    # a member's provider is never the source, even one an administrator could see
    (_cfg(pr, bob) / "custom_providers").mkdir(parents=True, exist_ok=True)
    (_cfg(pr, bob) / "custom_providers" / "own.json").write_text(json.dumps({"name": "own", "api_key_env": "BOB"}),
                                                                 encoding="utf-8")
    r = tc.post(url, json={**good, "fromProfile": "bob", "ref": "own"}, headers=h)
    assert r.status_code == 400 and r.json()["error"] == "bad_source"
    other = db.user_by_id(db.create_user(username="admin2", role="admin", disabled=1))
    r = tc.post(url, json={**good, "fromProfile": other["username"]}, headers=h)
    assert r.status_code == 400 and r.json()["error"] == "bad_source"    # a disabled administrator
    r = tc.post(f"/api/admin/users/{admin['id']}/items", json=good, headers=h)
    assert r.status_code == 400 and r.json()["error"] == "native"
    assert tc.post("/api/admin/users/999/items", json=good, headers=h).status_code == 404
    assert db.one("SELECT COUNT(*) AS n FROM user_items")["n"] == 0 and _secrets(pr, alice) == {}


def test_the_library_refresh_follows_given_providers(api):
    tc, c, (s, db, pr, admin, alice, bob, native, tid) = api
    h = sign_in(tc, c, admin)
    assert tc.post(f"/api/admin/users/{alice['id']}/items", headers=h,
                   json={"kind": "provider", "fromProfile": "admin", "ref": "p2", "models": ["m2"]}).status_code == 200
    pf = native / "config" / "custom_providers" / "p2.json"
    pf.write_text(json.dumps({**json.loads(pf.read_text(encoding="utf-8")), "base_url": "http://NEW"}), encoding="utf-8")
    r = tc.post("/api/admin/library/refresh", headers=h)
    assert r.status_code == 200 and r.json()["changed"] == {"user:alice": ["provider p2"]}
    assert "http://NEW" in (_cfg(pr, alice) / "custom_providers" / "p2.json").read_text(encoding="utf-8")
    assert db.one("SELECT target FROM audit WHERE action='user.item.refresh'")["target"] == "alice"


# ------------------------------------------------------------------ front end
def test_the_user_dialog_and_the_pickers_are_wired():
    admin = (JS / "views" / "admin.js").read_text(encoding="utf-8")
    fn = admin.split("function userProviders(u) {", 1)[1].split("\n}\n", 1)[0]
    assert "'/api/admin/users/' + encodeURIComponent(u.id) + '/items'" in fn
    assert "POST(url, { kind: 'provider', fromProfile: me, ref: p.ref, models })" in fn
    assert "DEL(url + '/' + encodeURIComponent(it.id))" in fn
    assert "GET('/api/admin/library' + qs({ profile: me, kind: 'provider' }))" in fn and "loadProviderCatalog()" in fn
    assert "'Any model of this provider'" in fn and "anyM ? ['*'] : [...sel]" in fn and "badge('also from the team')" in fn
    dialog = admin.split("const userDialog = (u) => {", 1)[1].split("const m = modal(", 2)[1].split("footer:", 1)[0]
    assert "h('summary', null, 'Providers for this user only')" in dialog and "userProviders(u)" in dialog
    assert "!isNew && u.profileMode !== 'native'" in dialog
    store = (JS / "store.js").read_text(encoding="utf-8")
    assert "export function allowedValue(listKey, value, provider) {" in store and ".granted_models" in store
    assert "allowedValue('allowed_models', m.id, e.providerId)" in (JS / "chatoptions.js").read_text(encoding="utf-8")
    chat = (JS / "views" / "chat.js").read_text(encoding="utf-8")
    assert "allowedValue('allowed_models', x.value, curP)" in chat and "allowedValue('allowed_models', m.id, p.id)" in chat
    assert "allowedValue(listKey, x.value, curP)" in chat


def _node():
    n = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    return n if Path(n).is_file() else None


def test_the_picker_rule_in_node():
    node = _node()
    if not node:
        pytest.skip("node not available")
    script = (f"const s = await import({json.dumps((JS / 'store.js').as_uri())});"
              "s.store.set('me', { isAdmin: false, policy: { allowed_providers: ['openai', 'p1', 'p2'], "
              "allowed_models: ['gpt-team'], granted_models: { p1: ['m1'], p2: ['*'] } } });"
              "const a = (k, v, p) => s.allowedValue(k, v, p);"
              "const out = [a('allowed_models', 'm1', 'p1'), a('allowed_models', 'm1', 'openai'), a('allowed_models', 'm1'),"
              " a('allowed_models', 'gpt-team', 'p1'), a('allowed_models', 'any', 'p2'), a('allowed_models', 'any', 'p1'),"
              " a('allowed_providers', 'p1', 'p1'), a('allowed_providers', 'p9')];"
              "s.store.set('me', { isAdmin: false, policy: { allowed_models: ['*'] } });"
              "out.push(a('allowed_models', 'x', 'p1'));"
              "s.store.set('me', { isAdmin: true, policy: {} });"
              "out.push(a('allowed_models', 'x', 'p1'));"
              "console.log(JSON.stringify(out));")
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == [True, False, False, True, True, False, True, False,
                                                             True, True]
