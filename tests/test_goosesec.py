"""Spec 026: Goose-native security - settings, tokens, adversary.md, the per-profile plan, provisioning, the worker
environment, the firewall, the native apply through Goose's configuration API, the admin API and the CLI."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from goose_web import goosesec as GS
from goose_web import policy as pol
from goose_web import workers as wk
from goose_web.__main__ import main as cli
from goose_web.profiles import HINT_FILE_NAMES

import test_team_profiles as _tp
from test_team_profiles import ANYCHAT, client_for, sign_in, team, user

env = _tp.env   # the shared fixture: (settings, db, profiles, ctx)
ENDPOINT = "http://127.0.0.1:8711/classify"
KEYS = ("SECURITY_PROMPT_ENABLED", "SECURITY_PROMPT_THRESHOLD", "SECURITY_PROMPT_CLASSIFIER_ENABLED",
        "SECURITY_PROMPT_CLASSIFIER_ENDPOINT")
TOKEN_KEY = "SECURITY_PROMPT_CLASSIFIER_TOKEN"


def member(db, name="alice"):
    u = user(db, name)
    tid = team(db, "T-" + name, ANYCHAT)
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, u["id"]))
    return u


def read(pr, u):
    d = pr.config_dir(u)
    cfg = yaml.safe_load((d / "config.yaml").read_text(encoding="utf-8")) or {}
    sp = d / "secrets.yaml"
    return cfg, (yaml.safe_load(sp.read_text(encoding="utf-8")) or {}) if sp.exists() else {}


# ------------------------------------------------------------------ settings
def test_settings_defaults_until_a_choice_is_stored(env):
    s, db, pr, c = env
    cfg = GS.load(db)
    assert cfg == GS.DEFAULTS and cfg is not GS.DEFAULTS and not GS.chosen(db)
    assert cfg["enabled"] and cfg["classifier"] and cfg["threshold"] == 0.8
    assert cfg["adversary"] == {"members": False, "native": False, "tools": ["shell"], "rules": ""}   # D4: off
    GS.save(db, GS.clean({"enabled": False}, cfg))
    assert GS.chosen(db) and GS.load(db)["enabled"] is False and GS.load(db)["threshold"] == 0.8


@pytest.mark.parametrize("body, match", [
    ({"threshold": 0}, "threshold"), ({"threshold": 1.5}, "threshold"), ({"threshold": "0.5"}, "threshold"),
    ({"threshold": True}, "threshold"), ({"enabled": "yes"}, "enabled"), ({"classifier": 1}, "classifier"),
    ({"adversary": []}, "adversary"), ({"adversary": {"members": "on"}}, "members"),
    ({"adversary": {"tools": ["rm -rf"]}}, "tool name"), ({"adversary": {"tools": ["a"] * 0 + [f"t{i}" for i in range(40)]}}, "more than"),
    ({"adversary": {"rules": "x" * 8001}}, "longer"), ({"adversary": {"rules": "a\x00b"}}, "NUL"),
    ({"adversary": {"rules": 5}}, "text"), ([], "object"),
])
def test_settings_validation(body, match):
    with pytest.raises(GS.SettingsError, match=match):
        GS.clean(body)


def test_settings_partial_update_and_cleaning():
    base = GS.clean({"threshold": 0.456, "adversary": {"tools": " shell , developer__shell\nshell ",
                                                       "rules": "\ufeffBLOCK x  \r\n\r\nALLOW y\r\n"}})
    assert base["threshold"] == 0.46
    assert base["adversary"]["tools"] == ["shell", "developer__shell"]            # exact names, no duplicates
    assert base["adversary"]["rules"] == "BLOCK x\n\nALLOW y"                      # no BOM, LF, no trailing blanks
    nxt = GS.clean({"adversary": {"native": True}}, base)
    assert nxt["adversary"]["native"] is True and nxt["adversary"]["rules"] == base["adversary"]["rules"]
    assert base["adversary"]["native"] is False                                    # the base is not changed
    assert GS.clean({"adversary": {"tools": []}})["adversary"]["tools"] == ["shell"]


def test_settings_unreadable_stored_value_falls_back_key_by_key(env):
    s, db, pr, c = env
    db.set_setting(GS.SETTING, {"enabled": False, "threshold": 99, "classifier": "x",
                                "adversary": {"members": True, "tools": ["bad name"], "rules": "keep me"}})
    cfg = GS.load(db)
    assert cfg["enabled"] is False and cfg["threshold"] == 0.8 and cfg["classifier"] is True
    assert cfg["adversary"]["members"] is True and cfg["adversary"]["tools"] == ["shell"]
    assert cfg["adversary"]["rules"] == "keep me"


def test_summary_never_holds_the_rules():
    cfg = GS.clean({"adversary": {"rules": "SECRET RULES TEXT", "members": True}})
    s = json.dumps(GS.summary(cfg))
    assert "SECRET" not in s and '"adversaryRulesChars": 17' in s and '"adversaryMembers": true' in s


# ------------------------------------------------------------------ tokens
def test_token_per_user_stable_and_verified(env):
    s, db, pr, c = env
    a, b = GS.token_for(db, 7), GS.token_for(db, 8)
    assert a == GS.token_for(db, 7) and a != b and GS.TOKEN_RE.fullmatch(a)
    assert GS.verify_token(db, a) == 7 and GS.verify_token(db, b) == 8
    for bad in (None, "", "x", a[:-1] + ("0" if a[-1] != "0" else "1"), a.replace("gwc1.7.", "gwc1.8."),
                "gwc1.7." + "0" * 64, "Bearer " + a, a.upper()):
        assert GS.verify_token(db, bad) is None
    stored = db.get_setting(GS.KEY_SETTING)
    assert isinstance(stored, str) and len(stored) >= 40 and stored not in a


def test_token_rotation_invalidates_every_token(env):
    s, db, pr, c = env
    a = GS.token_for(db, 7)
    GS.rotate_key(db)
    assert GS.verify_token(db, a) is None and GS.verify_token(db, GS.token_for(db, 7)) == 7


# ------------------------------------------------------------------ adversary.md
def test_adversary_text_is_what_goose_parses():
    t = GS.adversary_text(GS.clean({"adversary": {"tools": ["shell", "developer__shell"], "rules": "BLOCK a\n---\nALLOW b"}}))
    assert t == "tools: shell, developer__shell\n---\nBLOCK a\n---\nALLOW b\n"
    assert not t.startswith("\ufeff") and "\r" not in t
    head, rules = t.strip().split("\n---", 1)          # Goose: trimmed.split_once("\n---")
    assert head == "tools: shell, developer__shell" and rules.strip() == "BLOCK a\n---\nALLOW b"
    assert GS.adversary_text(GS.clean({})) == "tools: shell\n---\n"   # empty rules = Goose's built-in rules


# ------------------------------------------------------------------ plan
def test_plan_with_endpoint_without_endpoint_and_off():
    cfg = GS.clean({})
    p = GS.profile_plan(cfg, native=False, token="tok", endpoint=ENDPOINT)
    assert p["config"] == {KEYS[0]: True, KEYS[1]: 0.8, KEYS[2]: True, KEYS[3]: ENDPOINT}
    assert p["remove"] == [] and p["secret"] == "tok" and p["adversary"] is None
    assert p["env"] == {KEYS[0]: "true", KEYS[1]: "0.8", KEYS[2]: "true", KEYS[3]: ENDPOINT, TOKEN_KEY: "tok"}
    assert TOKEN_KEY not in p["config"]                      # Goose ignores a token in config.yaml
    p = GS.profile_plan(cfg, native=False, token=None, endpoint=None)      # the gateway does not hold the port
    assert p["config"] == {KEYS[0]: True, KEYS[1]: 0.8, KEYS[2]: False} and p["remove"] == [KEYS[3]]
    assert p["secret"] is None and TOKEN_KEY not in p["env"] and KEYS[3] not in p["env"]
    p = GS.profile_plan(GS.clean({"classifier": False}), native=False, token="tok", endpoint=ENDPOINT)
    assert p["config"][KEYS[2]] is False and p["secret"] is None
    p = GS.profile_plan(GS.clean({"enabled": False}), native=False, token="tok", endpoint=ENDPOINT)
    assert p["config"] == {} and p["remove"] == list(KEYS) and p["secret"] is None and p["env"] == {}


def test_plan_adversary_scope():
    cfg = GS.clean({"adversary": {"members": True, "rules": "BLOCK x"}})
    assert GS.profile_plan(cfg, native=False, token=None, endpoint=None)["adversary"] == "tools: shell\n---\nBLOCK x\n"
    assert GS.profile_plan(cfg, native=True, token=None, endpoint=None)["adversary"] is None
    cfg = GS.clean({"adversary": {"native": True}})
    assert GS.profile_plan(cfg, native=True, token=None, endpoint=None)["adversary"] == "tools: shell\n---\n"
    assert GS.profile_plan(cfg, native=False, token=None, endpoint=None)["adversary"] is None


# ------------------------------------------------------------------ provisioning
def test_provision_writes_keys_token_and_is_idempotent(env):
    s, db, pr, c = env
    alice = member(db)
    pr.security_endpoint = lambda: ENDPOINT
    changes = pr.provision(alice)
    cfg, sec = read(pr, alice)
    assert [cfg[k] for k in KEYS] == [True, 0.8, True, ENDPOINT]
    assert sec[TOKEN_KEY] == GS.token_for(db, alice["id"]) and TOKEN_KEY not in cfg
    assert any(ch.startswith("goose security") for ch in changes)
    assert not (pr.config_dir(alice) / "adversary.md").exists()          # adversary mode is off by default
    assert pr.provision(alice) == []                                     # nothing to do the second time
    cfg["SECURITY_PROMPT_ENABLED"] = False                               # the member (or an agent) edits the file
    cfg[TOKEN_KEY] = "planted"
    (pr.config_dir(alice) / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert "goose security: SECURITY_PROMPT_ENABLED" in pr.provision(alice)
    cfg, _ = read(pr, alice)
    assert cfg["SECURITY_PROMPT_ENABLED"] is True and TOKEN_KEY not in cfg


def test_provision_without_endpoint_uses_patterns_only(env):
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)                                                  # security_endpoint is None
    cfg, sec = read(pr, alice)
    assert cfg[KEYS[0]] is True and cfg[KEYS[2]] is False and KEYS[3] not in cfg and TOKEN_KEY not in sec


def test_provision_off_round_trip_leaves_the_rest_unchanged(env):
    s, db, pr, c = env
    alice = member(db)
    GS.save(db, GS.clean({"enabled": False}))
    pr.provision(alice)
    before = read(pr, alice)
    assert not any(k.startswith("SECURITY_") for k in before[0]) and TOKEN_KEY not in before[1]
    pr.security_endpoint = lambda: ENDPOINT
    GS.save(db, GS.clean({"adversary": {"members": True, "rules": "BLOCK everything risky"}}))
    pr.provision(alice)
    adv = pr.config_dir(alice) / "adversary.md"
    assert adv.read_bytes() == b"tools: shell\n---\nBLOCK everything risky\n"
    assert json.loads(pr.manifest_path(alice).read_text())["adversary"] == GS.text_hash(adv.read_text(encoding="utf-8"))
    adv.write_text("tools: nothing\n---\nALLOW all\n", encoding="utf-8")       # tampered by an agent
    assert "goose security: adversary.md" in pr.provision(alice)
    assert adv.read_bytes() == b"tools: shell\n---\nBLOCK everything risky\n"
    adv.write_text("tampered again", encoding="utf-8")
    GS.save(db, GS.clean({"enabled": False}))                               # everything off again
    changes = pr.provision(alice)
    assert "goose security: adversary.md removed" in changes and not adv.exists()   # off = gone, even when altered
    assert read(pr, alice) == before
    assert "adversary" not in json.loads(pr.manifest_path(alice).read_text())


def test_provision_keeps_an_adversary_file_it_never_wrote(env):
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    adv = pr.config_dir(alice) / "adversary.md"
    adv.write_text("placed by an administrator", encoding="utf-8")
    assert pr.provision(alice) == [] and adv.read_text(encoding="utf-8") == "placed by an administrator"


def test_provision_native_is_never_written(env, tmp_path):
    s, db, pr, c = env
    native = tmp_path / "native"
    (native / "config").mkdir(parents=True)
    admin = user(db, "root", role="admin", profile_mode="native", profile_path=str(native))
    pr.security_endpoint = lambda: ENDPOINT
    assert pr.provision(admin) == [] and list((native / "config").iterdir()) == []


def test_adversary_md_is_a_refused_file_name():
    assert "adversary.md" in HINT_FILE_NAMES


# ------------------------------------------------------------------ worker environment
def test_env_security_beats_extra_env_for_isolated_workers_only(env, tmp_path):
    s, db, pr, c = env
    s.data["goose"]["extra_env"] = {"SECURITY_PROMPT_ENABLED": "false", "KEEP": "1"}
    wm = wk.WorkerManager(s)
    sec = {"SECURITY_PROMPT_ENABLED": "true", TOKEN_KEY: "tok"}
    w = wk.Worker(key="alice", username="alice", path_root=str(tmp_path / "p"), native=False, security_env=sec)
    e = wm._env(w)
    assert e["SECURITY_PROMPT_ENABLED"] == "true" and e[TOKEN_KEY] == "tok" and e["KEEP"] == "1"
    root = tmp_path / "sb"
    root.mkdir()
    w = wk.Worker(key="bob", username="bob", path_root=str(root), native=False, security_env=sec,
                  sandbox={"name": "x", "profile_root": str(root)})
    e = wm._env(w)
    assert e["SECURITY_PROMPT_ENABLED"] == "true" and e[TOKEN_KEY] == "tok"
    w = wk.Worker(key="admin", username="admin", path_root=None, native=True, security_env=sec)
    e = wm._env(w)
    assert TOKEN_KEY not in e and e["SECURITY_PROMPT_ENABLED"] == "false"   # native: only what the admin configured


# ------------------------------------------------------------------ firewall
@pytest.mark.parametrize("key", ["SECURITY_PROMPT_ENABLED", "security_prompt_threshold", " SECURITY_PROMPT_CLASSIFIER_ENDPOINT",
                                 "SECURITY_PROMPT_CLASSIFIER_TOKEN", "SECURITY_COMMAND_CLASSIFIER_ENABLED",
                                 "SECURITY_PROMPT_ENABLED_OVERRIDE"])
def test_firewall_members_cannot_change_goose_security_keys(key):
    policy = {**pol.DEFAULT_POLICY, **ANYCHAT, "config_edit": True}
    for method in ("config/upsert", "config/remove"):
        with pytest.raises(pol.Denied, match="managed by Goose Web"):
            pol.check(pol.P + method, {"key": key, "value": False}, is_admin=False, policy=policy, roots=["/x"])
        pol.check(pol.P + method, {"key": key, "value": False}, is_admin=True, policy=policy, roots=["/x"])
    pol.check(pol.P + "config/upsert", {"key": "GOOSE_MAX_TURNS", "value": 50}, is_admin=False, policy=policy, roots=["/x"])


# ------------------------------------------------------------------ native profile (Goose's configuration API)
class GooseSays(Exception):
    """Goose answered with a JSON-RPC error (like hub.RpcError): `code` tells an answer from a failure to ask."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class FakeUp:
    """Goose's configuration API over a profile folder: parameters in config.yaml, secrets in memory."""

    def __init__(self, config_dir, fail=None, read_fails=False):
        self.dir, self.secrets, self.calls, self.fail, self.read_fails = Path(config_dir), {}, [], fail, read_fails

    def cfg(self):
        p = self.dir / "config.yaml"
        return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}

    async def request(self, method, params=None, timeout=None):
        params = dict(params or {})
        self.calls.append((method.rsplit("/", 1)[-1], params.get("key"), bool(params.get("isSecret"))))
        if self.fail:
            raise self.fail
        key, secret = params["key"], params.get("isSecret")
        store = self.secrets if secret else self.cfg()
        if method.endswith("config/read"):
            if self.read_fails and key not in store:
                raise GooseSays(-32603, "not found")
            return {"value": ("********" if secret and key in store else store.get(key))}
        if method.endswith("config/upsert"):
            store[key] = params["value"]
        elif method.endswith("config/remove"):
            if self.read_fails and key not in store:
                raise GooseSays(-32603, "not found")
            store.pop(key, None)
        if not secret:
            (self.dir / "config.yaml").write_text(yaml.safe_dump(store), encoding="utf-8")
        return {}


def native_admin(db, tmp_path):
    native = tmp_path / "native"
    (native / "config").mkdir(parents=True, exist_ok=True)
    (native / "config" / "config.yaml").write_text(yaml.safe_dump({"GOOSE_MODE": "auto", "extensions": {"x": {"enabled": True}}}),
                                                   encoding="utf-8")
    return user(db, "root", role="admin", profile_mode="native", profile_path=str(native)), native / "config"


async def apply(s, db, up, admin, cdir, endpoint=ENDPOINT, **kw):
    return await GS.apply_native(db=db, settings=s, upstream=up, config_dir=cdir, user=admin, endpoint=endpoint,
                                 goose_version="1.57.0", **kw)


async def test_native_apply_sets_reads_back_and_removes(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and st["error"] == "" and st["goose"] == "1.57.0" and st["adversary"] == "off"
    cfg = up.cfg()
    assert [cfg[k] for k in KEYS] == [True, 0.8, True, ENDPOINT] and cfg["GOOSE_MODE"] == "auto"
    assert cfg["extensions"] == {"x": {"enabled": True}} and TOKEN_KEY not in cfg
    assert up.secrets[TOKEN_KEY] == GS.token_for(db, admin["id"])
    assert set(st["changed"]) == {*KEYS, f"{TOKEN_KEY} set"} and GS.native_state(db)["ok"]
    up.calls.clear()
    st = await apply(s, db, up, admin, cdir)                              # nothing differs: only reads + the token
    assert st["changed"] == [] and [x for x in up.calls if x[0] == "upsert"] == [("upsert", TOKEN_KEY, True)]
    GS.save(db, GS.clean({"enabled": False}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and not any(k.startswith("SECURITY_") for k in up.cfg()) and up.secrets == {}
    assert up.cfg()["GOOSE_MODE"] == "auto" and f"{TOKEN_KEY} removed" in st["changed"]


async def test_native_apply_when_goose_answers_missing_keys_with_errors(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir, read_fails=True)
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()[KEYS[0]] is True and up.secrets[TOKEN_KEY]
    GS.save(db, GS.clean({"enabled": False}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and not any(k.startswith("SECURITY_") for k in up.cfg()) and up.secrets == {}
    st = await apply(s, db, up, admin, cdir)                              # already gone: still fine
    assert st["ok"] and st["changed"] == []


async def test_native_apply_failure_is_recorded_not_raised(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    before = (cdir / "config.yaml").read_bytes()
    st = await apply(s, db, FakeUp(cdir, fail=RuntimeError("method not found")), admin, cdir)
    assert st["ok"] is False and "method not found" in st["error"] and (cdir / "config.yaml").read_bytes() == before
    assert GS.native_state(db)["ok"] is False
    st = await apply(s, db, FakeUp(cdir, fail=asyncio.TimeoutError()), admin, cdir)
    assert st["ok"] is False and "TimeoutError" in st["error"]


async def test_native_adversary_file_ours_foreign_adopt_and_off(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up, adv = FakeUp(cdir), cdir / "adversary.md"
    GS.save(db, GS.clean({"adversary": {"native": True, "rules": "BLOCK a"}}))
    st = await apply(s, db, up, admin, cdir)
    assert st["adversary"] == "on" and adv.read_bytes() == b"tools: shell\n---\nBLOCK a\n"
    assert "adversary.md written" in st["changed"] and st["adversaryHash"] == GS.file_hash(adv)
    GS.save(db, GS.clean({"adversary": {"native": True, "rules": "BLOCK b"}}))    # our file: replaced, backed up
    st = await apply(s, db, up, admin, cdir)
    assert adv.read_bytes() == b"tools: shell\n---\nBLOCK b\n" and Path(st["adversaryBackup"]).read_bytes().endswith(b"BLOCK a\n")
    adv.write_text("the administrator's own rules", encoding="utf-8")                          # edited by hand since
    st = await apply(s, db, up, admin, cdir)
    assert st["adversary"] == "foreign" and st["ok"] and adv.read_text(encoding="utf-8") == "the administrator's own rules"
    GS.save(db, GS.clean({"adversary": {"native": False}}))                         # off: a foreign file stays
    st = await apply(s, db, up, admin, cdir)
    assert st["adversary"] == "foreign" and adv.exists()
    GS.save(db, GS.clean({"adversary": {"native": True, "rules": "BLOCK c"}}))
    st = await apply(s, db, up, admin, cdir, adopt=True)                            # take it over, backup first
    assert st["adversary"] == "on" and adv.read_bytes().endswith(b"BLOCK c\n")
    assert Path(st["adversaryBackup"]).read_text(encoding="utf-8") == "the administrator's own rules"
    GS.save(db, GS.clean({"adversary": {"native": False}}))
    st = await apply(s, db, up, admin, cdir)
    assert st["adversary"] == "off" and not adv.exists() and "adversary.md removed" in st["changed"]
    backups = sorted(p.name for p in (s.system_dir / "backups" / "native-security").iterdir())
    assert len(backups) == 3 and all(n.startswith("adversary.md.") for n in backups)


async def test_native_values_the_administrator_set_are_kept(env, tmp_path):
    """Review E-3: the native profile is the administrator's own Goose. Goose Web replaces or removes only what it
    wrote itself; anything else is kept and reported, unless adopt says to take it over (with a backup)."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    own = {"GOOSE_MODE": "auto", "SECURITY_PROMPT_ENABLED": True, "SECURITY_PROMPT_THRESHOLD": 0.3,
           "SECURITY_PROMPT_CLASSIFIER_ENABLED": True, "SECURITY_PROMPT_CLASSIFIER_ENDPOINT": "https://my.own/classify"}
    (cdir / "config.yaml").write_text(yaml.safe_dump(own), encoding="utf-8")
    up = FakeUp(cdir)
    up.secrets[TOKEN_KEY] = "my-own-token"
    # OFF, never applied (install.ps1 -GooseSecurity off): nothing is touched, and nothing even needs asking
    GS.save(db, GS.clean({"enabled": False}))
    plan = GS.profile_plan(GS.load(db), native=True, token=None, endpoint=ENDPOINT)
    assert GS.native_drift(cdir, plan, None) == []
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and st["changed"] == [] and up.cfg() == own and up.secrets[TOKEN_KEY] == "my-own-token"
    assert set(st["foreign"]) == set(KEYS)
    # ON (the default at an upgrade): the stricter threshold, the own endpoint, its switch and its token stay
    GS.save(db, GS.clean({"enabled": True}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and st["changed"] == [] and up.cfg() == own and up.secrets[TOKEN_KEY] == "my-own-token"
    assert set(st["foreign"]) == {KEYS[1], KEYS[3]} and st["tokenFp"] == ""      # enabled/classifier already as wanted
    tok = GS.token_for(db, admin["id"])
    assert GS.native_drift(cdir, GS.profile_plan(GS.load(db), native=True, token=tok, endpoint=ENDPOINT), st) == []
    # adopt: taken over, the previous values saved first (never the secret)
    st = await apply(s, db, up, admin, cdir, adopt=True)
    assert st["ok"] and up.cfg()[KEYS[1]] == 0.8 and up.cfg()[KEYS[3]] == ENDPOINT and up.secrets[TOKEN_KEY] == tok
    saved = json.loads(Path(st["configBackup"]).read_text(encoding="utf-8"))
    assert saved == {KEYS[1]: 0.3, KEYS[3]: "https://my.own/classify"} and "my-own-token" not in json.dumps(saved)
    # now they are Goose Web's: OFF removes them, and only them
    GS.save(db, GS.clean({"enabled": False}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg() == {"GOOSE_MODE": "auto"} and up.secrets == {} and st["written"] == {}


async def test_native_changed_by_hand_after_goose_web_wrote_it_is_put_back(env, tmp_path):
    """A key Goose Web wrote stays Goose Web's (reviews R-3, T-1): also a change that looks stricter is put back,
    because a key Goose Web let go of could be weakened later without anyone noticing. What is kept is what was
    there before Goose Web first wrote the key (test_native_values_the_administrator_set_are_kept)."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    assert (await apply(s, db, up, admin, cdir))["ok"]
    cfg = up.cfg()
    cfg["SECURITY_PROMPT_THRESHOLD"] = 0.4                                  # changed in Goose Desktop, or by anything else
    (cdir / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()["SECURITY_PROMPT_THRESHOLD"] == 0.8 and st["foreign"] == []
    assert st["reasserted"] == [KEYS[1]] and json.loads(Path(st["configBackup"]).read_text(encoding="utf-8")) == {KEYS[1]: 0.4}
    GS.save(db, GS.clean({"enabled": False}))
    st = await apply(s, db, up, admin, cdir)
    assert not any(k in up.cfg() for k in KEYS) and st["written"] == {}     # all Goose Web's: all removed


async def test_native_off_while_goose_cannot_be_asked_is_a_failure_not_done(env, tmp_path):
    """Review E-7: a read or remove that fails because Goose is down must never be recorded as applied."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    assert (await apply(s, db, up, admin, cdir))["ok"]
    GS.save(db, GS.clean({"enabled": False}))
    for err in (GooseSays(-32000, "Goose is not connected"), GooseSays(-32601, "method not found"),
                ConnectionError("worker gone"), asyncio.TimeoutError()):
        up.fail = err
        st = await apply(s, db, up, admin, cdir)
        assert st["ok"] is False and st["changed"] == [] and up.cfg()[KEYS[0]] is True
        assert st["written"][KEYS[0]] is True                             # still known as ours: the next start retries
    up.fail = None
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and not any(k.startswith("SECURITY_") for k in up.cfg())


async def test_native_adversary_file_that_cannot_be_read_is_left_alone(env, tmp_path, monkeypatch):
    """Review E-8."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    adv = cdir / "adversary.md"
    adv.write_text("locked by another program", encoding="utf-8")
    monkeypatch.setattr(GS, "file_hash", lambda p: None)
    GS.save(db, GS.clean({"adversary": {"native": True, "rules": "BLOCK x"}}))
    st = await apply(s, db, FakeUp(cdir), admin, cdir, adopt=True)
    assert st["ok"] is False and st["adversary"] == "error" and "cannot be read" in st["error"]
    assert adv.read_text(encoding="utf-8") == "locked by another program"
    assert not (s.system_dir / "backups" / "native-security").exists()


def test_member_cannot_stop_the_reviewer_file_with_a_folder(env):
    """Review E-5: a folder (or a link) where adversary.md belongs fails the provisioning (the agent does not
    start) and is audited, instead of being skipped in silence."""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    adv = pr.config_dir(alice) / "adversary.md"
    adv.mkdir()
    assert pr.provision(alice) == []                                       # adversary mode off: not Goose Web's concern
    GS.save(db, GS.clean({"adversary": {"members": True}}))
    with pytest.raises(RuntimeError, match="link or a folder"):
        pr.provision(alice)
    rows = db.query("SELECT ok, target, detail FROM audit WHERE action='goosesec.profile'")
    assert len(rows) == 1 and rows[0]["ok"] == 0 and rows[0]["target"] == "alice"
    adv.rmdir()
    assert "goose security: adversary.md" in pr.provision(alice) and adv.is_file()
    adv.unlink()
    adv.mkdir()                                                             # after the gateway wrote one: also when turned off
    GS.save(db, GS.clean({}))
    with pytest.raises(RuntimeError):
        pr.provision(alice)


def test_unreadable_profile_file_is_set_aside_and_rebuilt(env):
    """Review B-9: a config.yaml / secrets.yaml that is not YAML must not keep the member out until someone repairs
    it by hand. Nothing is lost: the file is moved to the gateway's backups and the event is audited."""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    cdir = pr.config_dir(alice)
    (cdir / "config.yaml").write_text("GOOSE_MODE: [unclosed\n  - {", encoding="utf-8")
    (cdir / "secrets.yaml").write_text("- just\n- a list\n", encoding="utf-8")
    changes = pr.provision(alice)                                           # used to raise at every start
    cfg, sec = read(pr, alice)
    assert cfg["SECURITY_PROMPT_ENABLED"] is True and cfg.get("GOOSE_MODE") == "approve" and isinstance(sec, dict)
    assert changes and pr.provision(alice) == []
    kept = sorted(p.name.split(".2")[0] for p in (s.system_dir / "backups" / "profiles" / "alice").iterdir())
    assert kept == ["config.yaml", "secrets.yaml"]
    rows = db.query("SELECT ok, detail FROM audit WHERE action='profile.file.set_aside' ORDER BY id")
    assert [r["detail"]["file"] for r in rows] == ["config.yaml", "secrets.yaml"] and not any(r["ok"] for r in rows)


def test_socket_rights_fingerprint_is_stable_and_follows_role_policy_and_folders(env):
    """Review A-1: a WebSocket keeps the rights it was opened with, so the gateway ends it when they change. The
    fingerprint must not change by itself (every socket would be closed at each re-validation)."""
    s, db, pr, c = env
    tid = team(db, "Ops", {**ANYCHAT, "allow_shell": False})
    alice = user(db, "alice")
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, alice["id"]))
    a = c.rights_fingerprint(alice)
    assert a == c.rights_fingerprint(db.user_by_id(alice["id"])) == c.rights_fingerprint(alice)      # stable
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps({**ANYCHAT, "allow_shell": True}), tid))
    b = c.rights_fingerprint(db.user_by_id(alice["id"]))
    assert b != a                                                                    # the team gained a permission
    db.update_user(alice["id"], role="admin")
    assert c.rights_fingerprint(db.user_by_id(alice["id"])) not in (a, b)             # promoted
    db.update_user(alice["id"], role="user")
    assert c.rights_fingerprint(db.user_by_id(alice["id"])) == b                      # demoted again: as before
    db.execute("DELETE FROM team_members WHERE user_id=?", (alice["id"],))
    assert c.rights_fingerprint(db.user_by_id(alice["id"])) != b                      # left the team


def test_change_password_is_rate_limited_and_checks_off_the_event_loop(env):
    """Review A-3."""
    from goose_web import api
    s, db, pr, c = env
    alice = user(db, "alice")
    api._REAUTH_LIMIT.reset(f"pw:{alice['id']}")
    api._REAUTH_AUDIT.reset(f"pw:{alice['id']}")
    with client_for(c) as tc:
        h = sign_in(tc, c, alice)
        codes = [tc.post("/api/me/password", json={"current": "wrong", "new": "x"}, headers=h).status_code
                 for _ in range(10)]
        assert codes[:8] == [400] * 8 and codes[8:] == [429, 429]
        assert tc.post("/api/me/password", json={"current": _tp.PW, "new": "x"}, headers=h).status_code == 429
        assert [tc.post("/api/me/password", json={"current": "wrong", "new": "x"}, headers=h).status_code
                for _ in range(20)] == [429] * 20
    # second review R-8: a refusal costs nothing, so it must not write an audit row each time
    rows = db.query("SELECT detail FROM audit WHERE action='user.password' AND ok=0")
    assert sum(1 for r in rows if (r["detail"] or {}).get("reason") == "rate limited") == 1
    assert sum(1 for r in rows if not (r["detail"] or {}).get("reason")) == 8
    api._REAUTH_LIMIT.reset(f"pw:{alice['id']}")
    api._REAUTH_AUDIT.reset(f"pw:{alice['id']}")


def test_other_security_keys_in_a_member_profile_are_removed(env):
    s, db, pr, c = env
    alice = member(db)
    pr.security_endpoint = lambda: ENDPOINT
    pr.provision(alice)
    cfg, _ = read(pr, alice)
    cfg.update({"SECURITY_COMMAND_CLASSIFIER_ENABLED": True, "SECURITY_COMMAND_CLASSIFIER_ENDPOINT": "http://x.example/c",
                "security_prompt_enabled_override": "false", "GOOSE_MAX_TURNS": 50})
    (pr.config_dir(alice) / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    changes = pr.provision(alice)
    cfg, _ = read(pr, alice)
    assert sorted(k for k in cfg if k.upper().startswith("SECURITY_")) == sorted(KEYS) and cfg["GOOSE_MAX_TURNS"] == 50
    assert sum("not set by Goose Web" in ch for ch in changes) == 3


def test_env_appcontainer_gets_the_relay_address_whatever_backend_was_configured(env, tmp_path):
    """Review E-6: the backend is decided at the start (MXC, or the AppContainer fallback)."""
    s, db, pr, c = env
    wm = wk.WorkerManager(s)
    root = tmp_path / "sb"
    root.mkdir()
    sec = {"SECURITY_PROMPT_ENABLED": "true", KEYS[3]: ENDPOINT, TOKEN_KEY: "tok"}
    spec = {"name": "x", "profile_root": str(root), "backend": "mxc",
            "relays": [{"target": "127.0.0.1:4000", "listen": "127.64.0.9:4000"},
                       {"target": "127.0.0.1:8711", "listen": "127.64.0.9:8711"}]}
    w = wk.Worker(key="bob", username="bob", path_root=str(root), native=False, security_env=sec, sandbox=spec)
    assert wm._env(w)[KEYS[3]] == ENDPOINT                                  # MXC: the real address, through its proxy
    w.backend = "appcontainer"                                              # the fallback was taken at this start
    e = wm._env(w)
    assert e[KEYS[3]] == "http://127.64.0.9:8711/classify" and e[TOKEN_KEY] == "tok"
    w.sandbox = {**spec, "relays": []}
    assert KEYS[3] not in wm._env(w) and wm._env(w)["SECURITY_PROMPT_ENABLED"] == "true"   # no relay: patterns only


def test_the_test_session_never_manages_a_real_native_profile(env, tmp_path):
    """A gateway started by a test must not touch the developer's Goose profile (conftest.py): with
    guard.native_profile false, sync_native asks nothing and changes nothing."""
    import os
    s, db, pr, c = env
    assert os.environ.get("GOOSE_WEB__GUARD__NATIVE_PROFILE") == "false" and GS.native_managed(s) is False
    admin, cdir = native_admin(db, tmp_path)
    before = (cdir / "config.yaml").read_bytes()
    up = FakeUp(cdir)
    fc, notices, worker = fake_ctx(s, db, pr, up, managed=False)
    assert await_(GS.sync_native(fc, force=True)) is None and await_(GS.sync_native(fc, adopt=True)) is None
    assert up.calls == [] and (cdir / "config.yaml").read_bytes() == before and GS.native_state(db) is None
    from goose_web.config import DEFAULTS, Settings
    import copy
    assert GS.native_managed(Settings(copy.deepcopy(DEFAULTS), None)) is True      # the product default is on
    for v, want in (("true", True), ("off", False), (0, False), ("", False), (None, False)):
        s.data["guard"]["native_profile"] = v
        assert GS.native_managed(s) is want


def await_(coro):
    return asyncio.run(coro)


def fake_ctx(s, db, pr, up, endpoint=ENDPOINT, managed=True):
    s.data["guard"]["native_profile"] = managed    # the test session's default is off (conftest.py)
    notices, worker = [], SimpleNamespace(state="ready", restart_pending=False)
    c = SimpleNamespace(db=db, settings=s, profiles=pr, classify=SimpleNamespace(endpoint=endpoint),
                        goose_version="1.57.0", upstream_for=lambda u: up,
                        workers=SimpleNamespace(get=lambda k: worker),
                        hub=SimpleNamespace(broadcast_admins=notices.append))
    return c, notices, worker


async def test_native_sync_applies_only_on_drift_and_restarts_the_worker(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    fc, notices, worker = fake_ctx(s, db, pr, up)
    st = await GS.sync_native(fc)
    assert st["ok"] and st["tokenFp"] and worker.restart_pending and notices == []
    audit = db.query("SELECT action, ok, detail FROM audit WHERE action='goosesec.native'")
    assert len(audit) == 1 and audit[0]["ok"] and GS.token_for(db, admin["id"]) not in json.dumps(audit[0]["detail"])
    up.calls.clear()
    worker.restart_pending = False
    assert (await GS.sync_native(fc))["ok"] and up.calls == [] and not worker.restart_pending   # no drift: Goose not asked
    cfg = up.cfg()
    cfg.pop("SECURITY_PROMPT_ENABLED")                                    # someone removed a key
    (cdir / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert GS.native_drift(cdir, GS.profile_plan(GS.load(db), native=True, token=GS.token_for(db, admin["id"]),
                                                 endpoint=ENDPOINT), GS.native_state(db)) == \
        ["SECURITY_PROMPT_ENABLED removed outside Goose Web"]
    st = await GS.sync_native(fc)
    assert st["changed"] == ["SECURITY_PROMPT_ENABLED put back (it had been removed outside Goose Web)"]
    assert up.cfg()["SECURITY_PROMPT_ENABLED"] is True and st["reasserted"] == ["SECURITY_PROMPT_ENABLED"]
    assert len(notices) == 1 and "put back: SECURITY_PROMPT_ENABLED" in notices[0]["params"]["message"]   # T-6
    GS.rotate_key(db)                                                     # new tokens: drift, the secret is rewritten
    up.calls.clear()
    assert (await GS.sync_native(fc))["ok"] and ("upsert", TOKEN_KEY, True) in up.calls
    assert up.secrets[TOKEN_KEY] == GS.token_for(db, admin["id"])


async def test_native_sync_failure_tells_administrators_and_never_raises(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    fc, notices, worker = fake_ctx(s, db, pr, FakeUp(cdir, fail=RuntimeError("boom")))
    st = await GS.sync_native(fc)
    assert st["ok"] is False and len(notices) == 1 and "boom" in notices[0]["params"]["message"]
    assert db.query("SELECT ok FROM audit WHERE action='goosesec.native'")[0]["ok"] == 0
    fc.upstream_for = lambda u: (_ for _ in ()).throw(RuntimeError("no worker"))
    assert (await GS.sync_native(fc))["ok"] is False
    assert await GS.sync_native(SimpleNamespace(settings=s, profiles=SimpleNamespace(_native_admin=lambda: None))) is None


# ------------------------------------------------------------------ second review 2026-11-12 (R-2 .. R-10)
THEIRS = "https://classifier.example/classify"


def native_plan(db, admin):
    return GS.profile_plan(GS.load(db), native=True, token=GS.token_for(db, admin["id"]), endpoint=ENDPOINT)


def rewrite(cdir, **values):
    p = cdir / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    cfg.update(values)
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")


async def test_native_value_weakened_after_goose_web_wrote_it_is_put_back(env, tmp_path):
    """R-3: anything that can write the administrator's Goose configuration could switch the protection off, and
    the ownership rule of E-3 then took the weaker value for the administrator's own choice: no drift, no notice."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and st["reasserted"] == [] and GS.native_drift(cdir, native_plan(db, admin), st) == []
    rewrite(cdir, **{KEYS[0]: False, KEYS[1]: 0.99, KEYS[2]: False})        # detection off, threshold up, classifier off
    assert GS.native_drift(cdir, native_plan(db, admin), st) == [f"{k} changed outside Goose Web" for k in KEYS[:3]]
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and [up.cfg()[k] for k in KEYS] == [True, 0.8, True, ENDPOINT]
    assert st["reasserted"] == list(KEYS[:3]) and st["foreign"] == [] and set(st["written"]) == set(KEYS)
    assert all(any(ch.startswith(f"{k} put back") for ch in st["changed"]) for k in KEYS[:3])
    assert json.loads(Path(st["configBackup"]).read_text(encoding="utf-8")) == {KEYS[0]: False, KEYS[1]: 0.99, KEYS[2]: False}
    assert GS.native_drift(cdir, native_plan(db, admin), st) == []
    rewrite(cdir, **{KEYS[1]: "not a number"})                               # Goose would fall back to its default
    st = await apply(s, db, up, admin, cdir)
    assert up.cfg()[KEYS[1]] == 0.8 and st["reasserted"] == [KEYS[1]]


async def test_native_key_goose_web_wrote_is_put_back_whatever_it_was_changed_to(env, tmp_path):
    """T-1: judging "weaker or stricter" left ways round it. Two steps (a harmless-looking change first, so that
    Goose Web let go of the key, then the real one) and the classifier group (another endpoint together with the
    switch) both ended with the protection down and nothing said."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    st = await apply(s, db, up, admin, cdir)
    tok = up.secrets[TOKEN_KEY]
    rewrite(cdir, **{KEYS[1]: 0.79})                                         # step 1: a little stricter
    st = await apply(s, db, up, admin, cdir)
    assert up.cfg()[KEYS[1]] == 0.8 and st["reasserted"] == [KEYS[1]] and KEYS[1] in st["written"]
    rewrite(cdir, **{KEYS[1]: 1.0})                                          # step 2: off in all but name
    assert GS.native_drift(cdir, native_plan(db, admin), st) == [f"{KEYS[1]} changed outside Goose Web"]
    st = await apply(s, db, up, admin, cdir)
    assert up.cfg()[KEYS[1]] == 0.8 and st["reasserted"] == [KEYS[1]]
    rewrite(cdir, **{KEYS[0]: "true"})                                       # a string where Goose wants a boolean
    st = await apply(s, db, up, admin, cdir)
    assert up.cfg()[KEYS[0]] is True and st["reasserted"] == [KEYS[0]]
    rewrite(cdir, **{KEYS[3]: ENDPOINT + "?x", KEYS[2]: False})              # the group: another endpoint + switch off
    assert GS.native_drift(cdir, native_plan(db, admin), st) == [f"{KEYS[2]} changed outside Goose Web",
                                                                 f"{KEYS[3]} changed outside Goose Web"]
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and [up.cfg()[k] for k in KEYS] == [True, 0.8, True, ENDPOINT] and st["foreign"] == []
    assert st["reasserted"] == [KEYS[2], KEYS[3]] and set(st["written"]) == set(KEYS) and up.secrets[TOKEN_KEY] == tok
    assert GS.native_drift(cdir, native_plan(db, admin), st) == []
    assert st["putBack"]["keys"] == [KEYS[2], KEYS[3]]
    st = await apply(s, db, up, admin, cdir)                                 # nothing to do: the last put-back stays on record
    assert st["reasserted"] == [] and st["changed"] == [] and st["putBack"]["keys"] == [KEYS[2], KEYS[3]]


def test_same_takes_an_integer_and_a_float_for_one_number_and_nothing_else_loosely():
    assert GS._same(1, 1.0) and GS._same(0.8, 0.8) and GS._same("a", "a") and not GS._same(0.8, 0.79)
    assert not GS._same(True, 1) and not GS._same("true", True) and not GS._same("0.8", 0.8) and not GS._same(None, 0)


async def test_native_sync_audits_and_tells_administrators_about_a_change_made_outside(env, tmp_path):
    """R-3: the sync is what runs at every gateway start."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    fc, notices, worker = fake_ctx(s, db, pr, up)
    assert (await GS.sync_native(fc))["ok"] and notices == []
    rewrite(cdir, **{KEYS[0]: False})
    st = await GS.sync_native(fc)
    assert st["ok"] and up.cfg()[KEYS[0]] is True and st["reasserted"] == [KEYS[0]]
    assert len(notices) == 1 and f"put back: {KEYS[0]}" in notices[0]["params"]["message"]
    rows = db.query("SELECT ok, detail FROM audit WHERE action='goosesec.native' ORDER BY id")
    assert len(rows) == 2 and rows[1]["ok"] and rows[1]["detail"]["reasserted"] == [KEYS[0]]
    up.calls.clear()
    assert (await GS.sync_native(fc))["ok"] and up.calls == [] and len(notices) == 1     # settled: Goose is not asked
    assert GS.native_state(db)["putBack"]["keys"] == [KEYS[0]]                            # for Admin > Prompt guard


async def test_native_put_back_is_said_even_when_a_later_step_of_the_apply_fails(env, tmp_path):
    """T-4: the notice was only sent after a completely successful apply, and never again afterwards."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    fc, notices, worker = fake_ctx(s, db, pr, FakeUp(cdir))
    assert (await GS.sync_native(fc))["ok"]

    class TokenFails(FakeUp):
        async def request(self, method, params=None, timeout=None):
            if method.endswith("config/upsert") and (params or {}).get("isSecret"):
                raise TimeoutError("goose did not answer")
            return await super().request(method, params, timeout)

    up = TokenFails(cdir)
    fc.upstream_for = lambda u: up
    rewrite(cdir, **{KEYS[2]: False})
    st = await GS.sync_native(fc)
    assert st["ok"] is False and up.cfg()[KEYS[2]] is True and st["reasserted"] == [KEYS[2]]
    said = [n["params"]["message"] for n in notices]
    assert any(f"put back: {KEYS[2]}" in m for m in said) and any("could not be applied" in m for m in said)
    row = db.query("SELECT ok, detail FROM audit WHERE action='goosesec.native' ORDER BY id DESC LIMIT 1")[0]
    assert not row["ok"] and row["detail"]["reasserted"] == [KEYS[2]]


async def test_native_read_back_mismatch_is_a_failure_of_its_own_not_a_change_made_outside(env, tmp_path):
    """T-2: `written` was recorded before the read-back, so the next apply found "its" value changed and blamed
    someone else: a false notice, or a put-back that failed again at every start with a backup file each time."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)

    class StoresAnotherType(FakeUp):
        async def request(self, method, params=None, timeout=None):
            if method.endswith("config/upsert") and (params or {}).get("key") in KEYS[:2]:
                params = {**params, "value": str(params["value"])}          # Goose keeps "0.8" where 0.8 was sent
            return await super().request(method, params, timeout)

    up = StoresAnotherType(cdir)
    for _ in range(3):   # F-8: TWO keys come back differently; every one is read back before the apply fails once
        st = await apply(s, db, up, admin, cdir)
        assert st["ok"] is False and "did not read back" in st["error"] and KEYS[0] in st["error"] and KEYS[1] in st["error"]
        assert st["reasserted"] == [] and "configBackup" not in st
        assert st["written"][KEYS[0]] == "True" and st["written"][KEYS[1]] == "0.8"
    assert not (s.system_dir / "backups" / "native-security").exists()


@pytest.mark.parametrize("how", ["the gateway stops", "the answer is lost"])
async def test_native_apply_that_is_interrupted_keeps_what_it_wrote_as_its_own(env, tmp_path, how):
    """T-3: with R-4 (an equal value Goose Web never wrote is not its own) a write that landed while the apply was
    interrupted belonged to nobody afterwards: "off" left detection on, a new threshold was never applied."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)

    during = []

    class Interrupted(FakeUp):
        async def request(self, method, params=None, timeout=None):
            r = await super().request(method, params, timeout)              # the write lands in Goose ...
            if method.endswith("config/upsert") and (params or {}).get("key") == KEYS[1]:
                during.append(GS.native_state(db))                          # what a killed process would leave behind
                raise asyncio.CancelledError() if how == "the gateway stops" else TimeoutError("no answer")
            return r

    up = Interrupted(cdir)
    if how == "the gateway stops":
        with pytest.raises(asyncio.CancelledError):
            await apply(s, db, up, admin, cdir)
        assert GS.native_state(db)["error"] == "interrupted"
    else:
        assert (await apply(s, db, up, admin, cdir))["ok"] is False
    # F-4: the record made before the write says "not finished", with what was written and the write in flight
    assert during[0]["ok"] is False and during[0]["error"] == "interrupted"
    assert during[0]["written"] == {KEYS[0]: True} and during[0]["pending"] == {KEYS[1]: 0.8}
    st = GS.native_state(db)
    assert st["ok"] is False and st["written"] == {KEYS[0]: True} and up.cfg()[KEYS[1]] == 0.8
    assert st["pending"] == {KEYS[1]: 0.8}                                  # only the write in flight (F-6)
    st = await apply(s, db, FakeUp(cdir), admin, cdir)                      # the next start finishes the job
    assert st["ok"] and set(st["written"]) == set(KEYS) and st["pending"] == {} and st["foreign"] == []
    assert st["reasserted"] == [] and sorted(st["changed"]) == sorted([KEYS[2], KEYS[3], f"{TOKEN_KEY} set"])
    GS.save(db, GS.clean({"enabled": False}))
    assert (await apply(s, db, FakeUp(cdir), admin, cdir))["ok"]
    assert not any(k in FakeUp(cdir).cfg() for k in KEYS)                   # "off" removes all of it


async def test_native_value_that_cannot_be_compared_is_put_back_not_a_reason_to_do_nothing(env, tmp_path):
    """F-1 (High): numbers were compared through float(), which raises on a huge integer in config.yaml. The drift
    check raised, the sync only logged it, and at every start nothing was applied, recorded, audited or said."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    fc, notices, worker = fake_ctx(s, db, pr, up)
    assert (await GS.sync_native(fc))["ok"]
    rewrite(cdir, **{KEYS[0]: False, KEYS[1]: 10 ** 309})
    assert not GS._same(10 ** 309, 0.8) and not GS._same(0.8, 10 ** 309) and GS._same(10 ** 309, 10 ** 309)
    assert GS.native_drift(cdir, native_plan(db, admin), GS.native_state(db)) == [
        f"{KEYS[0]} changed outside Goose Web", f"{KEYS[1]} changed outside Goose Web"]
    st = await GS.sync_native(fc)
    assert st["ok"] and up.cfg()[KEYS[0]] is True and up.cfg()[KEYS[1]] == 0.8
    assert st["reasserted"] == [KEYS[0], KEYS[1]] and len(notices) == 1


async def test_native_drift_and_sync_never_fail_silently(env, tmp_path, monkeypatch):
    """F-1, the other half: whatever goes wrong before apply_native runs must not leave "Applied" on the page."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    fc, notices, worker = fake_ctx(s, db, pr, FakeUp(cdir))
    assert (await GS.sync_native(fc))["ok"]
    good = GS.native_state(db)
    with monkeypatch.context() as m:                                        # a comparison that raises is drift
        m.setattr(GS, "_same", lambda a, b: (_ for _ in ()).throw(OverflowError("int too large")))
        assert GS.native_drift(cdir, native_plan(db, admin), good) == ["the settings could not be compared"]
    with monkeypatch.context() as m:                                        # a failure of the sync itself
        m.setattr(GS, "native_drift", lambda *a, **k: (_ for _ in ()).throw(OverflowError("int too large")))
        st = await GS.sync_native(fc)
    assert st["ok"] is False and "OverflowError" in st["error"]
    rec = GS.native_state(db)
    assert rec["ok"] is False and "OverflowError" in rec["error"] and set(rec["written"]) == set(KEYS)
    assert db.query("SELECT ok FROM audit WHERE action='goosesec.native' ORDER BY id DESC LIMIT 1")[0]["ok"] == 0
    assert len(notices) == 1 and "could not be checked" in notices[0]["params"]["message"]
    assert "the last apply failed" in GS.native_drift(cdir, native_plan(db, admin), rec)   # the next start tries again


async def test_native_apply_that_fails_before_deciding_keeps_the_write_in_flight_on_record(env, tmp_path):
    """F-2: a second apply that failed early (Goose still not answering) wiped `pending`; the write that had landed
    then belonged to nobody again."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)

    class LandsButNoAnswer(FakeUp):
        async def request(self, method, params=None, timeout=None):
            r = await super().request(method, params, timeout)
            if method.endswith("config/upsert") and (params or {}).get("key") == KEYS[0]:
                raise TimeoutError("no answer")
            return r

    assert (await apply(s, db, LandsButNoAnswer(cdir), admin, cdir))["ok"] is False
    assert GS.native_state(db)["pending"] == {KEYS[0]: True} and FakeUp(cdir).cfg()[KEYS[0]] is True
    st = await apply(s, db, FakeUp(cdir, fail=TimeoutError("still down")), admin, cdir)   # fails at the first read
    assert st["ok"] is False and st["pending"] == {KEYS[0]: True} and st["written"] == {}
    st = await apply(s, db, FakeUp(cdir), admin, cdir)
    assert st["ok"] and set(st["written"]) == set(KEYS) and st["pending"] == {} and st["reasserted"] == []
    GS.save(db, GS.clean({"enabled": False}))
    assert (await apply(s, db, FakeUp(cdir), admin, cdir))["ok"] and not any(k in FakeUp(cdir).cfg() for k in KEYS)


async def test_native_switch_goose_web_wrote_is_put_back_also_next_to_an_endpoint_it_never_wrote(env, tmp_path):
    """F-3: with the classifier unused Goose Web writes the switch (off) and no endpoint. An endpoint added outside
    made the classifier-group rule let go of that switch, without drift, audit or notice."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    GS.save(db, GS.clean({"classifier": False}))
    up = FakeUp(cdir)
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()[KEYS[2]] is False and KEYS[3] not in up.cfg() and set(st["written"]) == set(KEYS[:3])
    rewrite(cdir, **{KEYS[3]: THEIRS, KEYS[2]: True})
    assert GS.native_drift(cdir, native_plan(db, admin), st) == [f"{KEYS[2]} changed outside Goose Web"]
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()[KEYS[2]] is False and st["reasserted"] == [KEYS[2]]
    assert up.cfg()[KEYS[3]] == THEIRS and st["foreign"] == [KEYS[3]]       # the endpoint was never Goose Web's: kept
    assert GS.native_drift(cdir, native_plan(db, admin), st) == []


async def test_native_off_removes_a_key_goose_web_wrote_whatever_it_holds_now(env, tmp_path):
    """F-5: on "off" a key that had been changed outside was let go; after "off" and "on" it counted as the
    administrator's own and was kept as changed."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    up = FakeUp(cdir)
    assert (await apply(s, db, up, admin, cdir))["ok"]
    rewrite(cdir, **{KEYS[1]: 1.0})
    GS.save(db, GS.clean({"enabled": False}))
    assert f"{KEYS[1]} present" in GS.native_drift(cdir, native_plan(db, admin), GS.native_state(db))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and not any(k in up.cfg() for k in KEYS) and st["written"] == {} and st["foreign"] == []
    assert json.loads(Path(st["configBackup"]).read_text(encoding="utf-8")) == {KEYS[1]: 1.0}
    GS.save(db, GS.clean({"enabled": True}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()[KEYS[1]] == 0.8 and st["foreign"] == [] and set(st["written"]) == set(KEYS)


async def test_native_value_equal_to_the_plan_that_goose_web_never_wrote_stays_the_administrators(env, tmp_path):
    """R-4: "off" must not remove a switch the administrator had set themselves."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    rewrite(cdir, **{KEYS[0]: True})                                         # their own, before Goose Web
    up = FakeUp(cdir)
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and set(st["written"]) == set(KEYS[1:]) and st["foreign"] == []
    GS.save(db, GS.clean({"enabled": False}))
    st = await apply(s, db, up, admin, cdir)
    assert st["ok"] and up.cfg()[KEYS[0]] is True and st["foreign"] == [KEYS[0]]
    assert not any(k in up.cfg() for k in KEYS[1:]) and up.secrets == {}


async def test_native_take_over_saves_the_previous_values_before_replacing_anything(env, tmp_path):
    """R-5: a failure after the first replacement used to lose the administrator's previous values."""
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    rewrite(cdir, **{KEYS[1]: 0.3, KEYS[3]: THEIRS})

    class FailsAtTheEndpoint(FakeUp):
        async def request(self, method, params=None, timeout=None):
            if method.endswith("config/upsert") and (params or {}).get("key") == KEYS[3]:
                raise TimeoutError("goose did not answer")
            return await super().request(method, params, timeout)

    up = FailsAtTheEndpoint(cdir)
    st = await apply(s, db, up, admin, cdir, adopt=True)
    assert st["ok"] is False and "TimeoutError" in st["error"]
    assert up.cfg()[KEYS[1]] == 0.8 and up.cfg()[KEYS[3]] == THEIRS         # the first value was already replaced
    assert json.loads(Path(st["configBackup"]).read_text(encoding="utf-8")) == {KEYS[1]: 0.3, KEYS[3]: THEIRS}
    assert GS.native_state(db)["configBackup"] == st["configBackup"]


def test_env_mxc_start_after_an_appcontainer_fallback_gets_the_real_address(env, tmp_path):
    """R-2: w.backend is the PREVIOUS start's backend until the new worker is up. An MXC start after a fallback was
    given the relay forwarder's address, which no MXC worker can reach, for that worker's whole life."""
    import inspect
    s, db, pr, c = env
    wm = wk.WorkerManager(s)
    root = tmp_path / "sb"
    root.mkdir()
    sec = {"SECURITY_PROMPT_ENABLED": "true", KEYS[3]: ENDPOINT, TOKEN_KEY: "tok"}
    spec = {"name": "x", "profile_root": str(root), "backend": "mxc",
            "relays": [{"target": "127.0.0.1:8711", "listen": "127.64.0.9:8711"}]}
    w = wk.Worker(key="bob", username="bob", path_root=str(root), native=False, security_env=sec, sandbox=spec)
    w.backend = "appcontainer"                                              # left by the fallback start
    assert wm._sandbox_env(w)[KEYS[3]] == "http://127.64.0.9:8711/classify"
    assert wm._sandbox_env(w, "mxc")[KEYS[3]] == ENDPOINT                    # the MXC start says what it is
    assert 'self._sandbox_env(w, "mxc")' in inspect.getsource(wk.WorkerManager._start_mxc)
    w.backend = "mxc"
    assert wm._sandbox_env(w, "appcontainer")[KEYS[3]] == "http://127.64.0.9:8711/classify"


def test_a_socket_whose_check_fails_is_closed_not_kept():
    """R-6 / T-9: both halves of the re-validation failed open - the hub when the check raised (its sign-in part:
    the database cannot be read), and the check itself when only its rights part raised."""
    import re
    from goose_web.hub import Hub
    closed = []

    def boom():
        raise RuntimeError("database is locked")
    clients = [SimpleNamespace(still_valid=boom, closed=False, user={"username": "x"}, disconnect=closed.append),
               SimpleNamespace(still_valid=lambda: True, closed=False, user={"username": "y"}, disconnect=closed.append),
               SimpleNamespace(still_valid=lambda: False, closed=False, user={"username": "z"}, disconnect=closed.append),
               SimpleNamespace(still_valid=None, closed=False, user={"username": "n"}, disconnect=closed.append)]
    Hub.revalidate_clients(SimpleNamespace(upstreams={"k": SimpleNamespace(clients=clients)}))
    assert len(closed) == 2                                                  # the failing check and the invalid one
    # the rights part is a closure of the WebSocket handler: its except branch is checked in the source
    src = (Path(wk.__file__).parent / "app.py").read_text(encoding="utf-8")
    m = re.search(r'log\.exception\("socket re-validation \(rights\)"\)\s*\n\s*return (\w+)', src)
    assert m and m.group(1) == "False"


def test_set_aside_files_get_unique_names_and_only_the_newest_are_kept(env):
    """R-9: the member decides how often this happens; two in the same second overwrote each other."""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    cdir = pr.config_dir(alice)
    total = pr.SET_ASIDE_KEEP + 3
    for i in range(total):
        (cdir / "config.yaml").write_text(f"GOOSE_MODE: [unclosed-{i}-\n", encoding="utf-8")
        pr.provision(alice)
    kept = list((s.system_dir / "backups" / "profiles" / "alice").glob("config.yaml.*.unreadable"))
    texts = sorted(p.read_text(encoding="utf-8") for p in kept)
    assert len(kept) == pr.SET_ASIDE_KEEP and len(set(texts)) == pr.SET_ASIDE_KEEP
    assert texts == sorted(f"GOOSE_MODE: [unclosed-{i}-\n" for i in range(total - pr.SET_ASIDE_KEEP, total))
    assert len(db.query("SELECT id FROM audit WHERE action='profile.file.set_aside'")) == total


def test_set_aside_pruning_cannot_be_steered_by_the_file_s_date_or_attributes(env):
    """T-7 / T-8: the member's agent owns the file's date and attributes. A back-dated file was pruned at once (the
    log and the audit then named a path that was gone); a read-only one could never be pruned, and that ended the
    bound for good."""
    import os
    import stat
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    p = pr.config_dir(alice) / "config.yaml"
    folder = s.system_dir / "backups" / "profiles" / "alice"
    for i in range(pr.SET_ASIDE_KEEP + 2):
        p.write_text(f"GOOSE_MODE: [read-only-{i}-\n", encoding="utf-8")
        os.chmod(p, stat.S_IREAD)
        pr.provision(alice)
    assert len(list(folder.glob("config.yaml.*.unreadable"))) == pr.SET_ASIDE_KEEP
    p.write_text("GOOSE_MODE: [back-dated-\n", encoding="utf-8")
    os.utime(p, (1_000_000_000, 1_000_000_000))                              # 2001: older than everything kept
    pr.provision(alice)
    kept = [f.read_text(encoding="utf-8") for f in folder.glob("config.yaml.*.unreadable")]
    assert len(kept) == pr.SET_ASIDE_KEEP and "GOOSE_MODE: [back-dated-\n" in kept
    last = db.query("SELECT detail FROM audit WHERE action='profile.file.set_aside' ORDER BY id DESC LIMIT 1")[0]
    moved = Path(last["detail"]["movedTo"])
    assert moved.is_file() and moved.read_text(encoding="utf-8") == "GOOSE_MODE: [back-dated-\n"
    import time
    assert moved.stat().st_mtime > time.time() - 300                        # dated when it was set aside, not 2001


@pytest.mark.skipif(__import__("os").name != "nt", reason="an open file cannot be deleted on Windows")
def test_set_aside_pruning_carries_on_after_a_file_it_cannot_delete(env):
    """Pins the behaviour around T-8: a file that cannot be deleted stays, and the others are still pruned. (This
    test also passes on the code before the fix, where the order happened to put such a file last; the test that
    fails without the T-8 fix is the read-only one above.)"""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    p = pr.config_dir(alice) / "config.yaml"
    folder = s.system_dir / "backups" / "profiles" / "alice"
    for i in range(pr.SET_ASIDE_KEEP):
        p.write_text(f"GOOSE_MODE: [first-{i}-\n", encoding="utf-8")
        pr.provision(alice)
    oldest = min(folder.glob("config.yaml.*.unreadable"), key=lambda f: f.stat().st_mtime)
    with open(oldest, "rb"):                                                # held open: Windows refuses the delete
        for i in range(3):
            p.write_text(f"GOOSE_MODE: [later-{i}-\n", encoding="utf-8")
            pr.provision(alice)
        assert oldest.exists()
        kept = sorted(f.read_text(encoding="utf-8") for f in folder.glob("config.yaml.*.unreadable") if f != oldest)
    # the newest KEEP are there and the others were pruned, although one file in the way could not be deleted
    assert len(kept) == pr.SET_ASIDE_KEEP and all(f"GOOSE_MODE: [later-{i}-\n" in kept for i in range(3))
    assert "GOOSE_MODE: [first-1-\n" not in kept


@pytest.mark.parametrize("text", ["x: 2001-99-99\n", "a: " + "[" * 3000 + "]" * 3000 + "\n"])
def test_every_parser_error_leads_to_the_set_aside(env, text):
    """R-10: a bad date is a ValueError and deep nesting a RecursionError, not a YAMLError; each still blocked every
    start of that member's agent."""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    (pr.config_dir(alice) / "config.yaml").write_text(text, encoding="utf-8")
    pr.provision(alice)
    cfg, _ = read(pr, alice)
    assert cfg["SECURITY_PROMPT_ENABLED"] is True
    assert len(db.query("SELECT id FROM audit WHERE action='profile.file.set_aside'")) == 1


def test_something_that_is_not_a_file_in_place_of_config_yaml_still_fails_the_start(env):
    """Unchanged behaviour, pinned: a folder (or a link to one) is not moved anywhere; the start fails."""
    s, db, pr, c = env
    alice = member(db)
    pr.provision(alice)
    p = pr.config_dir(alice) / "config.yaml"
    p.unlink()
    p.mkdir()
    with pytest.raises(OSError):
        pr.provision(alice)
    assert p.is_dir() and not (s.system_dir / "backups" / "profiles" / "alice").exists()


# ------------------------------------------------------------------ API
def test_api_get_put_validate_and_audit(env, tmp_path):
    s, db, pr, c = env
    admin, cdir = native_admin(db, tmp_path)
    alice = member(db)
    up = FakeUp(cdir)
    s.data["guard"]["native_profile"] = True       # this test is about the native apply (temporary profile)
    c.upstream_for = lambda u: up
    c.hub = SimpleNamespace(broadcast_admins=lambda m: None)
    c.classify = SimpleNamespace(endpoint=ENDPOINT, describe=lambda: {"state": "listening", "port": 8711},
                                 invalidate=lambda: None, listening=True, in_use=lambda: True, bound_port=8711)
    pr.security_endpoint = lambda: ENDPOINT
    with client_for(c) as tc:
        assert tc.get("/api/admin/goose-security").status_code == 401
        h = sign_in(tc, c, admin)
        g = tc.get("/api/admin/goose-security").json()
        assert g["settings"] == GS.DEFAULTS and g["chosen"] is False and g["hasNative"] and g["members"] == 1
        assert g["listener"]["state"] == "listening" and g["native"] is None
        r = tc.put("/api/admin/goose-security", json={"threshold": 7}, headers=h)
        assert r.status_code == 400 and r.json()["error"] == "bad_settings"
        r = tc.put("/api/admin/goose-security", headers=h, json={"settings": {
            "threshold": 0.6, "adversary": {"members": True, "native": True, "rules": "BLOCK secret-rule-text"}}})
        j = r.json()
        assert r.status_code == 200 and j["chosen"] and j["settings"]["threshold"] == 0.6
        assert j["applied"]["native"]["ok"] and j["applied"]["members"] == {"alice": j["applied"]["members"]["alice"]}
        assert j["native"]["adversary"] == "on"
        assert (cdir / "adversary.md").read_text(encoding="utf-8").endswith("BLOCK secret-rule-text\n")
        assert (pr.config_dir(alice) / "adversary.md").exists() and up.cfg()["SECURITY_PROMPT_THRESHOLD"] == 0.6
        rows = db.query("SELECT detail FROM audit WHERE action='goosesec.update'")
        assert len(rows) == 1 and "secret-rule-text" not in json.dumps(rows[0]["detail"])
        old = GS.token_for(db, alice["id"])
        assert tc.post("/api/admin/goose-security/rotate", headers=h).status_code == 200
        assert GS.token_for(db, alice["id"]) != old and read(pr, alice)[1][TOKEN_KEY] == GS.token_for(db, alice["id"])
        tc.cookies.clear()
        h2 = sign_in(tc, c, alice)                                         # a member: none of it
        assert tc.get("/api/admin/goose-security").status_code == 403
        assert tc.put("/api/admin/goose-security", json={"enabled": False}, headers=h2).status_code == 403
        assert tc.post("/api/admin/goose-security/rotate", headers=h2).status_code == 403
        assert tc.post("/api/admin/goose-security/check", headers=h2).status_code == 403


# ------------------------------------------------------------------ CLI
def test_cli_security_status_on_off_rotate(env, capsys, monkeypatch):
    s, db, pr, c = env
    # the command line reads its own settings; these commands only read and write Goose Web's database (no gateway,
    # no Goose), so the test session's "never manage a native profile" default can be lifted for what they print
    monkeypatch.setenv("GOOSE_WEB__GUARD__NATIVE_PROFILE", "true")
    (s.system_dir).mkdir(parents=True, exist_ok=True)
    assert cli(["security", "status"]) == 2 and "init" in capsys.readouterr().err   # no database yet
    from goose_web.db import Database
    Database(s.system_dir / "goose-web.db").close()
    assert cli(["security", "status"]) == 0
    out = capsys.readouterr().out
    assert "prompt injection detection: on" in out and "no choice stored yet" in out
    assert "adversary mode: members off, native profile off" in out and "http://127.0.0.1:8711/classify" in out
    live = Database(s.system_dir / "goose-web.db")
    GS.save(live, GS.clean({"adversary": {"members": True, "native": True}}))
    assert cli(["security", "off"]) == 0 and "OFF" in capsys.readouterr().out
    cfg = GS.load(live)
    assert cfg["enabled"] is False and cfg["adversary"]["members"] is False and cfg["adversary"]["native"] is False
    assert cli(["security", "on"]) == 0
    assert GS.load(live)["enabled"] is True and GS.load(live)["adversary"]["native"] is False   # adversary stays off
    t = GS.token_for(live, 3)
    assert cli(["security", "rotate-tokens"]) == 0 and GS.token_for(live, 3) != t
    assert [r["action"] for r in live.query("SELECT action FROM audit ORDER BY id")] == \
        ["goosesec.update", "goosesec.update", "goosesec.rotate"]
    # with a recorded native apply (the branch that formats the time), applied and failed
    live.set_setting(GS.STATE_SETTING, {"native": {"ok": True, "at": 1794500000.0, "goose": "1.57.0", "adversary": "off",
                                                   "error": "", "changed": []}})
    live.close()
    assert GS.read_only(s.system_dir / "goose-web.db")[2] is True
    capsys.readouterr()
    assert cli(["security", "status"]) == 0
    out = capsys.readouterr().out
    assert "native profile: applied 20" in out and "goose 1.57.0" in out and "adversary.md: off" in out
    assert cli(["check"]) in (0, 1)                      # other lines depend on the machine; these must be there
    out = capsys.readouterr().out
    assert "goose security, native profile: applied 20" in out and "cannot read the settings" not in out
    assert "[OK] goose security: prompt injection detection on" in out and "classification endpoint: 127.0.0.1:8711" in out
    live = Database(s.system_dir / "goose-web.db")
    live.set_setting(GS.STATE_SETTING, {"native": {"ok": False, "at": 1794500000.0, "goose": "1.59.0",
                                                   "error": "method not found", "changed": []}})
    live.close()
    assert cli(["security", "status"]) == 0
    out = capsys.readouterr().out
    assert "native profile: NOT applied" in out and "error: method not found" in out
    monkeypatch.setenv("GOOSE_WEB__GUARD__NATIVE_PROFILE", "false")
    assert cli(["security", "status"]) == 0
    assert "native profile: not managed (guard.native_profile is false)" in capsys.readouterr().out
