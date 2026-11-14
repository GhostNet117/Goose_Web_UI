"""Security assessment 2026-11-09, slice B (agent firewall, hub, profiles) and C-3 / C-11: regression tests.

B-1  recipes on session/new (recipeDeeplink / recipeId), schedules and session imports start their extensions
B-2  extensionmanager / dormant developer; Goose enables bundled extensions missing from config.yaml
B-3  direct tools/call to extensionmanager
B-4  audit of recipe use and of the model starting extensions / sub-agents
C-3  provisioning manifest in the user's profile drove the gateway's deletes
C-11 dangerous team folders (allowed_roots / share_folder)
"""
import asyncio
import json
import os
import sys

import pytest
import websockets
import yaml

from goose_web import policy as pol
from goose_web.hub import Client, Hub, agent_tool_event
from goose_web.workers import Worker

P = "_goose/unstable/"
MEMBER = {**pol.LEGACY_DEFAULT_POLICY, **{k: [pol.ANY] for k in pol.CHAT_LISTS}, "team": {"id": 1, "name": "t"}}
ROOT = os.path.abspath(os.sep + "profiles" + os.sep + "alice" + os.sep + "workspace")
STDIO = {"type": "stdio", "name": "evil", "cmd": "cmd.exe", "args": ["/c", "whoami"], "timeout": 20}


def chk(method, params=None, policy=None, admin=False):
    pol.check(method, params if params is not None else {}, is_admin=admin,
              policy=policy if policy is not None else dict(MEMBER), roots=[ROOT])


# ====================================================================== policy (sync firewall)
def test_member_session_new_meta_is_allow_listed():
    params = {"cwd": ROOT, "_meta": {"recipeDeeplink": "abc", "recipeId": "r1", "hidden": True, "evil": {"x": 1},
                                     "sessionType": "scheduled", "client": "spoofed"}}
    chk("session/new", params)
    assert params["_meta"] == {"recipeDeeplink": "abc", "recipeId": "r1", "client": "goose-web"}
    with pytest.raises(pol.Denied):
        chk("session/new", {"cwd": ROOT, "_meta": {"recipeDeeplink": {"recipe": {}}}})
    admin = {"cwd": "/x", "_meta": {"recipeDeeplink": "abc", "other": 1, "hidden": True}}
    chk("session/new", admin, admin=True)
    assert admin["_meta"] == {"recipeDeeplink": "abc", "other": 1, "client": "goose-web"}


def test_member_load_and_resume_drop_meta():
    for m in ("session/load", "session/resume"):
        params = {"sessionId": "s", "cwd": ROOT, "_meta": {"recipeDeeplink": "abc"}}
        chk(m, params)
        assert "_meta" not in params


def test_enabled_extensions_need_shell_for_guarded_names():
    p = {**MEMBER, "extensions_edit": True}
    with pytest.raises(pol.Denied, match="extensions_edit"):
        chk("session/new", {"cwd": ROOT, "_meta": {"enabledExtensions": ["todo"]}})
    chk("session/new", {"cwd": ROOT, "_meta": {"enabledExtensions": ["todo"]}}, policy=p)
    for value in (["developer"], ["Extension Manager"], {"summon": True}, [{"name": "scheduler"}], [STDIO]):
        with pytest.raises(pol.Denied):
            chk("session/new", {"cwd": ROOT, "_meta": {"enabledExtensions": value}}, policy=p)
    chk("session/new", {"cwd": ROOT, "_meta": {"enabledExtensions": ["developer", "summon"]}},
        policy={**p, "allow_shell": True})
    # a configured command entry named by key needs allow_shell too (hub passes the config map)
    with pytest.raises(pol.Denied):
        pol.check_enabled_extensions(["mytool"], p, {"mytool": STDIO})


def test_recipe_problems_rules():
    enabled = {"todo": {"type": "platform", "name": "todo"}}
    base = {"title": "t", "instructions": "x"}

    def probs(recipe, policy=None, en=enabled):
        return pol.recipe_problems({**base, **recipe}, policy or dict(MEMBER), en)

    assert probs({}) == []
    assert probs({"extensions": [{"type": "platform", "name": "todo"}]}) == []
    assert "extensions_edit" in probs({"extensions": [{"type": "platform", "name": "memory"}]})[0]
    assert "allow_shell" in probs({"extensions": [STDIO]})[0]
    assert "allow_shell" in probs({"extensions": [{"type": "inline_python", "name": "x", "code": "1"}]})[0]
    for n in ("developer", "computercontroller", "code_execution", "orchestrator", "summon", "scheduler",
              "extensionmanager"):
        assert probs({"extensions": [{"type": "platform", "name": n}]}), n
    assert probs({"extensions": [{"type": "streamable_http", "name": "r", "uri": "https://x"}]})
    assert probs({"sub_recipes": [{"name": "s", "path": "s.yaml"}]})
    assert probs({"retry": {"max_retries": 1, "checks": [{"type": "shell", "command": "x"}]}})
    assert probs({"retry": {"max_retries": 1, "on_failure": "del x"}})
    narrow = {**MEMBER, "allowed_providers": ["p1"], "allowed_models": ["m1"]}
    assert probs({"settings": {"goose_provider": "evil"}}, narrow)
    assert probs({"settings": {"goose_model": "big"}}, narrow)
    full = {**MEMBER, "allow_shell": True, "extensions_edit": True}
    assert probs({"extensions": [STDIO, {"type": "platform", "name": "developer"}],
                  "sub_recipes": [{"name": "s", "path": "s"}], "retry": {"checks": [{"type": "shell"}]}}, full) == []
    # a stdio entry identical to an enabled config entry needs allow_shell but not extensions_edit
    assert probs({"extensions": [STDIO]}, {**MEMBER, "allow_shell": True}, {"evil": dict(STDIO)}) == []
    # a same-named entry with another command is not "already enabled"
    assert probs({"extensions": [{**STDIO, "args": ["/c", "del"]}]}, {**MEMBER, "allow_shell": True},
                 {"evil": dict(STDIO)})
    assert pol.recipe_problems("not a recipe", dict(MEMBER), enabled)
    assert pol.recipe_problems({**base, "extensions": "x"}, dict(MEMBER), enabled)


def test_tools_call_extensionmanager_and_agent_starters():
    """B-3: apps alone must not reach extensionmanager (it enables developer -> shell) nor summon / scheduler."""
    calls = [{"sessionId": "s", "extensionName": "extensionmanager", "name": "extensionmanager__manage_extensions",
              "arguments": {"action": "enable", "extension_name": "developer"}},
             {"sessionId": "s", "extensionName": "extensionmanager", "name": "manage_extensions"},
             {"sessionId": "s", "extensionName": "Extension Manager", "name": "manage_extensions"},
             {"sessionId": "s", "name": "extensionmanager__manage_extensions"},
             {"sessionId": "s", "extensionName": "summon", "name": "delegate", "arguments": {"source": "x"}},
             {"sessionId": "s", "extensionName": "scheduler", "name": "scheduler__manage_schedule"},
             {"sessionId": "s", "extensionName": "developer", "name": "shell"}]
    for c in calls:
        with pytest.raises(pol.Denied):
            chk(P + "tools/call", dict(c))
        with pytest.raises(pol.Denied):   # extensions_edit is not enough: enabling developer = shell
            chk(P + "tools/call", dict(c), policy={**MEMBER, "extensions_edit": True})
    for c in calls:
        chk(P + "tools/call", dict(c), policy={**MEMBER, "extensions_edit": True, "allow_shell": True})
        chk(P + "tools/call", dict(c), admin=True)
    with pytest.raises(pol.Denied, match="must name its extension"):
        chk(P + "tools/call", {"sessionId": "s", "name": "shell"})
    chk(P + "tools/call", {"sessionId": "s", "extensionName": "todo", "name": "todo__todo_write"})


def test_config_routes_that_turn_guarded_extensions_on():
    p = {**MEMBER, "extensions_edit": True, "config_edit": True}
    for key in ("developer", "extensionmanager", "summon", "scheduler"):
        with pytest.raises(pol.Denied):   # removing the pinned entry lets Goose enable its default
            chk(P + "config/extensions/remove", {"configKey": key}, policy=p)
        with pytest.raises(pol.Denied):
            chk(P + "config/extensions/set-enabled", {"configKey": key, "enabled": True}, policy=p)
    chk(P + "config/extensions/remove", {"configKey": "todo"}, policy=p)
    chk(P + "config/extensions/set-enabled", {"configKey": "developer", "enabled": False}, policy=p)
    for k in ("extensions", "EXTENSIONS", "extensions.developer"):
        with pytest.raises(pol.Denied):
            chk(P + "config/upsert", {"key": k, "value": {"developer": {"enabled": True}}}, policy=p)
        with pytest.raises(pol.Denied):
            chk(P + "config/remove", {"key": k}, policy=p)
    chk(P + "config/upsert", {"key": "extensions", "value": {}}, policy={**p, "allow_shell": True})
    with pytest.raises(pol.Denied):
        chk(P + "config/extensions/add", {"extension": {"type": "platform", "name": "summon"}}, policy=p)
    with pytest.raises(pol.Denied):
        chk(P + "config/extensions/add", {"extension": {"type": "inline_python", "name": "x", "code": "1"}}, policy=p)


def test_scheduled_inline_recipe_with_command_denied():
    rec = {"title": "s", "instructions": "x", "extensions": [STDIO]}
    with pytest.raises(pol.Denied, match="allow_shell"):
        chk(P + "schedules/create", {"id": "x", "recipe": rec, "cron": "0 0 * * *"})
    with pytest.raises(pol.Denied):
        chk(P + "schedules/update", {"id": "x", "recipe": {**rec, "extensions": [], "sub_recipes": [{"path": "a"}]}})
    chk(P + "schedules/create", {"id": "x", "recipe": {**rec, "extensions": []}, "cron": "0 0 * * *"})


def test_session_import_strips_extension_state():
    todo = {"type": "platform", "name": "todo"}
    data = {"id": "x", "name": "n", "extension_data": {
        "enabled_extensions.v0": {"extensions": [STDIO, todo, {"type": "platform", "name": "Extension Manager"},
                                                 {"type": "platform", "name": "developer"},
                                                 {"type": "streamable_http", "name": "r", "uri": "https://x"},
                                                 {"type": "builtin", "name": "computercontroller"}]},
        "todo.v0": {"items": []}},
            "container": {"image": "x"}, "system_prompt_override": "be evil", "conversation": []}
    params = {"input": json.dumps(data), "extra": 1}
    chk(P + "session/import", params)
    out = json.loads(params["input"])
    assert out["extension_data"] == {"todo.v0": {"items": []}, "enabled_extensions.v0": {"extensions": [todo]}}
    assert "container" not in out and "system_prompt_override" not in out and "extra" not in params
    keep = {"input": json.dumps(data)}
    chk(P + "session/import", keep, policy={**MEMBER, "prompts_edit": True})
    assert json.loads(keep["input"])["system_prompt_override"] == "be evil"
    for bad in ({"input": "not json"}, {"input": "[1]"}, {}):
        with pytest.raises(pol.Denied):
            chk(P + "session/import", bad)
    admin = {"input": json.dumps(data)}
    chk(P + "session/import", admin, admin=True)
    assert json.loads(admin["input"])["extension_data"]["enabled_extensions.v0"]


# ====================================================================== C-11: dangerous folder grants
@pytest.mark.skipif(sys.platform != "win32", reason="Windows paths")
def test_folder_grant_problem(tmp_path, monkeypatch):
    profiles = tmp_path / "profiles"
    system = profiles / "_system"
    users = tmp_path / "Users"
    me = users / "me"
    native = tmp_path / "nativegoose"
    for d in (system, profiles / "_teams" / "1", profiles / "bob" / "workspace", me / "Documents" / "Shared",
              users / "other" / "Documents", native / "config", me / "AppData" / "Roaming"):
        d.mkdir(parents=True, exist_ok=True)
    where = dict(profiles_root=str(profiles), system_dir=str(system), native_roots=[str(native)],
                 users_root=str(users), own_home=str(me))
    bad = ["C:\\", "C:/", "\\\\?\\C:\\", "\\\\server\\share", "\\\\?\\UNC\\server\\share\\", "\\\\.\\PhysicalDrive0",
           "relative\\path", str(profiles), str(tmp_path), str(profiles / "bob"), str(profiles / "bob" / "workspace"),
           str(profiles / "_teams"), str(system), str(system / "x"), str(native), str(native / "config"),
           os.environ.get("SystemRoot", "C:\\Windows"), os.environ.get("ProgramFiles", "C:\\Program Files"),
           os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "App"), str(users), str(me),
           str(users / "other"), str(users / "other" / "Documents"), str(me / "AppData" / "Roaming"),
           str(me / "Documents") + ":ads", "\\\\?\\" + str(profiles)]
    for b in bad:
        assert pol.folder_grant_problem(b, **where), b
    for good in (str(profiles / "_teams" / "1"), str(me / "Documents" / "Shared"), str(me / "Documents")):
        assert pol.folder_grant_problem(good, **where) == "", good
    # a junction inside an allowed place that points at the profiles root is refused too
    import _winapi
    link = me / "Documents" / "sneaky"
    _winapi.CreateJunction(str(profiles), str(link))
    try:
        assert pol.folder_grant_problem(str(link), **where)
    finally:
        os.rmdir(link)
    with pytest.raises(ValueError, match="profiles root"):
        pol.check_team_folders({"allowed_roots": [str(me / "Documents"), str(profiles)]}, **where)
    with pytest.raises(ValueError):
        pol.check_team_folders({"share_folder": "C:\\"}, **where)
    pol.check_team_folders({"allowed_roots": [str(me / "Documents")], "share_folder": str(profiles / "_teams" / "1")},
                           **where)


# ====================================================================== hub (B-1, B-4) against a fake agent
class FakeAgent:
    def __init__(self):
        self.calls = []
        self.recipes = {}           # deeplink -> recipe
        self.listed = []            # recipes/list entries
        self.config = [{"extension": {"type": "platform", "name": "todo"}, "enabled": True, "configKey": "todo"},
                       {"extension": {"type": "platform", "name": "developer"}, "enabled": False,
                        "configKey": "developer"}]

    async def handler(self, ws):
        async for raw in ws:
            m = json.loads(raw)
            meth, mid, p = m.get("method"), m.get("id"), m.get("params") or {}
            if meth is None:
                continue
            self.calls.append((meth, p))
            res = {}
            if meth == "initialize":
                res = {"protocolVersion": 1, "agentInfo": {"version": "1.57.0"}}
            elif meth == "session/new":
                res = {"sessionId": f"s{len(self.calls)}", "_meta": {"echo": p.get("_meta")}}
            elif meth == P + "recipes/decode":
                if p.get("deeplink") not in self.recipes:
                    await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "bad"}}))
                    continue
                res = {"recipe": self.recipes[p["deeplink"]]}
            elif meth == P + "recipes/list":
                res = {"recipes": self.listed}
            elif meth == P + "config/extensions/list":
                res = {"extensions": self.config}
            elif meth == P + "tools/list":
                res = {"tools": [{"name": "manage_extensions"}]}
            if mid is not None:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}))

    def forwarded(self, method):
        return [p for m, p in self.calls if m == method]


class FakeWorkers:
    def __init__(self, port):
        self.workers = {"alice": Worker(key="alice", username="alice", path_root=None, native=False, port=port,
                                        secret="x", state="ready")}
        self.activity = None
        self.on_restart = None

    async def ensure(self, key):
        return self.workers[key]


class Sink:
    def __init__(self):
        self.msgs = []
        self.event = asyncio.Event()

    async def send(self, raw):
        self.msgs.append(json.loads(raw))
        self.event.set()

    async def reply(self, mid, timeout=5):
        end = asyncio.get_running_loop().time() + timeout
        while True:
            for m in self.msgs:
                if m.get("id") == mid and "method" not in m:
                    return m
            self.event.clear()
            left = end - asyncio.get_running_loop().time()
            if left <= 0:
                raise AssertionError(f"no reply {mid}; got {self.msgs}")
            try:
                await asyncio.wait_for(self.event.wait(), left)
            except asyncio.TimeoutError:
                pass


@pytest.fixture
async def hubenv():
    agent = FakeAgent()
    server = await websockets.serve(agent.handler, "127.0.0.1", 0)
    hub = Hub(FakeWorkers(server.sockets[0].getsockname()[1]))
    audit = []
    hub.on_audit = lambda client, action, target, detail, ok: audit.append((action, target, detail, ok))
    hub.start()
    yield agent, hub, audit
    server.close()
    await server.wait_closed()


def mk(policy=None, role="user"):
    sink = Sink()
    c = Client(sink.send, {"id": 1, "username": "alice", "role": role}, dict(policy or MEMBER),
               [os.path.abspath("/ws")])
    c.start()
    return c, sink


async def _new(up, c, sink, mid, meta, cwd=None):
    await up.from_client(c, {"jsonrpc": "2.0", "id": mid, "method": "session/new",
                             "params": {"cwd": cwd or os.path.abspath("/ws"), "mcpServers": [], "_meta": meta}})
    return await sink.reply(mid)


async def test_member_recipe_deeplink_with_command_or_shell_is_refused(hubenv):
    """B-1: the PoC (stdio entry + developer in a deeplink recipe) is refused before Goose sees session/new."""
    agent, hub, audit = hubenv
    agent.recipes = {"L1": {"title": "evil", "extensions": [STDIO]},
                     "L2": {"title": "dev", "extensions": [{"type": "platform", "name": "developer"}]},
                     "L3": {"title": "ok", "extensions": [{"type": "platform", "name": "todo"}]},
                     "L4": {"title": "subs", "sub_recipes": [{"name": "s", "path": "s.yaml"}]}}
    up = hub.upstream("alice", "alice")
    c, s = mk()
    hub.attach(up, c)
    for i, link in enumerate(("L1", "L2", "L4", "missing"), start=1):
        r = await _new(up, c, s, i, {"recipeDeeplink": link})
        assert r["error"]["code"] == -32003, (link, r)
    assert agent.forwarded("session/new") == []
    r = await _new(up, c, s, 10, {"recipeDeeplink": "L3", "junk": 1})
    assert "result" in r
    assert agent.forwarded("session/new")[-1]["_meta"] == {"recipeDeeplink": "L3", "client": "goose-web"}
    recs = [a for a in audit if a[0] == "agent.recipe"]
    assert [a[3] for a in recs] == [False, False, False, False, True]
    assert recs[0][2]["title"] == "evil" and recs[0][2]["extensions"] == ["evil"]
    assert recs[-1][2]["title"] == "ok" and recs[-1][2]["via"] == "deeplink"
    assert any(a[0] == "acp.denied" for a in audit)


async def test_member_recipe_id_resolved_by_the_gateway(hubenv, tmp_path):
    agent, hub, audit = hubenv
    sub = tmp_path / "sub.yaml"
    sub.write_text(yaml.safe_dump({"title": "sub", "instructions": "x", "extensions": [STDIO]}), encoding="utf-8")
    agent.listed = [{"id": "good", "recipe": {"title": "g", "extensions": [{"type": "platform", "name": "todo"}]},
                     "file_path": str(tmp_path / "g.yaml")},
                    {"id": "bad", "recipe": {"title": "b", "extensions": [STDIO]}, "file_path": "x"},
                    {"id": "nested", "recipe": {"title": "n", "sub_recipes": [{"name": "s", "path": "sub.yaml"}]},
                     "file_path": "\\\\?\\" + str(tmp_path / "n.yaml")},
                    {"id": "gone", "recipe": {"title": "x", "sub_recipes": [{"name": "s", "path": "nope.yaml"}]},
                     "file_path": str(tmp_path / "x.yaml")}]
    hub.profile_root_for = lambda u: str(tmp_path)      # her recipes are files of her own profile
    up = hub.upstream("alice", "alice")
    c, s = mk()
    hub.attach(up, c)
    assert "result" in await _new(up, c, s, 1, {"recipeId": "good"})
    assert (await _new(up, c, s, 2, {"recipeId": "bad"}))["error"]["code"] == -32003
    assert (await _new(up, c, s, 3, {"recipeId": "unknown"}))["error"]["code"] == -32003   # fail closed
    # allow_shell + extensions_edit: sub-recipes are checked recursively; an unreadable one is refused
    full = {**MEMBER, "allow_shell": True, "extensions_edit": True}
    c2, s2 = mk(full)
    hub.attach(up, c2)
    assert "result" in await _new(up, c2, s2, 4, {"recipeId": "nested"})
    assert (await _new(up, c2, s2, 5, {"recipeId": "gone"}))["error"]["code"] == -32003
    sub.write_text(yaml.safe_dump({"title": "sub", "settings": {"goose_provider": "evil"}}), encoding="utf-8")
    c3, s3 = mk({**full, "allowed_providers": ["p1"]})
    hub.attach(up, c3)
    r = await _new(up, c3, s3, 6, {"recipeId": "nested"})
    assert r["error"]["code"] == -32003 and "sub-recipe" in r["error"]["message"]


async def test_the_sub_recipe_check_reads_only_the_members_own_files(hubenv, tmp_path):
    """Review 2026-11-12, B-8: the gateway reads the file a sub-recipe names with ITS rights. A member with
    allow_shell could name another member's recipe and read its title and extensions in the refusal, or a file of
    any size, or a share on another machine."""
    agent, hub, audit = hubenv
    mine, other = tmp_path / "alice", tmp_path / "bob"
    mine.mkdir()
    other.mkdir()
    (other / "secret.yaml").write_text(yaml.safe_dump({"title": "BOBS-SECRET-TITLE", "extensions": [STDIO]}),
                                       encoding="utf-8")
    (mine / "big.yaml").write_text("title: big\n" + "# x\n" * 300_000, encoding="utf-8")
    (mine / "folder.yaml").mkdir()
    (mine / "fine.yaml").write_text(yaml.safe_dump({"title": "fine", "instructions": "x"}), encoding="utf-8")
    hub.profile_root_for = lambda u: str(mine)

    def nested(rid, path):
        return {"id": rid, "recipe": {"title": rid, "sub_recipes": [{"name": "s", "path": path}]},
                "file_path": str(mine / f"{rid}.yaml")}
    agent.listed = [nested("abs", str(other / "secret.yaml")), nested("rel", "..\\bob\\secret.yaml"),
                    nested("unc", "\\\\server\\share\\x.yaml"), nested("big", "big.yaml"),
                    nested("dir", "folder.yaml"), nested("fine", "fine.yaml")]
    up = hub.upstream("alice", "alice")
    c, s = mk({**MEMBER, "allow_shell": True, "extensions_edit": True})
    hub.attach(up, c)
    for i, rid in enumerate(("abs", "rel", "unc", "big", "dir"), start=1):
        r = await _new(up, c, s, i, {"recipeId": rid})
        assert r["error"]["code"] == -32003, (rid, r)
        assert "BOBS-SECRET-TITLE" not in json.dumps(r) and "evil" not in json.dumps(r), (rid, r)
    assert "not in one of your folders" in (await _new(up, c, s, 8, {"recipeId": "abs"}))["error"]["message"]
    assert "result" in await _new(up, c, s, 9, {"recipeId": "fine"})
    assert not any("BOBS-SECRET-TITLE" in json.dumps(a, default=str) for a in audit)
    # a recipe her team gave her lives in the team's folder, outside her profile: its sub-recipes are hers to use
    # (review of 1.23.0, T-2) - and only once the gateway knows the folder as one of hers
    team = tmp_path / "library" / "teams" / "7" / "recipes"
    team.mkdir(parents=True)
    (team / "part.yaml").write_text(yaml.safe_dump({"title": "part", "instructions": "x"}), encoding="utf-8")
    agent.listed = [{"id": "team", "recipe": {"title": "team", "sub_recipes": [{"name": "s", "path": "part.yaml"}]},
                     "file_path": str(team / "team.yaml")}]
    assert (await _new(up, c, s, 10, {"recipeId": "team"}))["error"]["code"] == -32003
    hub.recipe_dirs_for = lambda u: [str(team)]
    assert "result" in await _new(up, c, s, 11, {"recipeId": "team"})


async def test_member_enabled_extensions_checked_against_config(hubenv):
    agent, hub, audit = hubenv
    agent.config.append({"extension": dict(STDIO), "enabled": False, "configKey": "mytool"})
    up = hub.upstream("alice", "alice")
    c, s = mk({**MEMBER, "extensions_edit": True})
    hub.attach(up, c)
    assert (await _new(up, c, s, 1, {"enabledExtensions": ["mytool"]}))["error"]["code"] == -32003
    assert (await _new(up, c, s, 2, {"enabledExtensions": ["developer"]}))["error"]["code"] == -32003
    assert "result" in await _new(up, c, s, 3, {"enabledExtensions": ["todo"]})


async def test_admin_recipe_allowed_but_audited(hubenv):
    agent, hub, audit = hubenv
    agent.recipes = {"L1": {"title": "evil", "extensions": [STDIO]}}
    up = hub.upstream("alice", "alice")
    c, s = mk(pol.ADMIN_POLICY, role="admin")
    hub.attach(up, c)
    assert "result" in await _new(up, c, s, 1, {"recipeDeeplink": "L1"})
    rec = [a for a in audit if a[0] == "agent.recipe"]
    assert len(rec) == 1 and rec[0][1] == "session/new" and rec[0][3] is True
    assert rec[0][2]["extensions"] == ["evil"]


async def test_member_schedule_and_import_recipes(hubenv):
    agent, hub, audit = hubenv
    agent.listed = [{"id": "bad", "recipe": {"title": "b", "extensions": [STDIO]}, "file_path": "x"},
                    {"id": "good", "recipe": {"title": "g"}, "file_path": "x"}]
    up = hub.upstream("alice", "alice")
    c, s = mk()
    hub.attach(up, c)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": P + "recipes/schedule",
                             "params": {"id": "bad", "cron_schedule": "0 0 * * *"}})
    assert (await s.reply(1))["error"]["code"] == -32003
    await up.from_client(c, {"jsonrpc": "2.0", "id": 2, "method": P + "recipes/schedule",
                             "params": {"id": "good", "cron_schedule": "0 0 * * *"}})
    assert "result" in await s.reply(2)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 3, "method": P + "schedules/create",
                             "params": {"id": "x", "cron": "0 0 * * *",
                                        "recipe": {"title": "m", "extensions": [{"type": "platform", "name": "memory"}]}}})
    assert (await s.reply(3))["error"]["code"] == -32003      # not enabled in config, no extensions_edit
    data = {"id": "x", "extension_data": {"enabled_extensions.v0": {"extensions": [STDIO]}}, "conversation": []}
    await up.from_client(c, {"jsonrpc": "2.0", "id": 4, "method": P + "session/import",
                             "params": {"input": json.dumps(data)}})
    assert "result" in await s.reply(4)
    sent = json.loads(agent.forwarded(P + "session/import")[-1]["input"])
    assert sent["extension_data"]["enabled_extensions.v0"]["extensions"] == []
    data["recipe"] = {"title": "r", "extensions": [STDIO]}
    await up.from_client(c, {"jsonrpc": "2.0", "id": 5, "method": P + "session/import",
                             "params": {"input": json.dumps(data)}})
    assert (await s.reply(5))["error"]["code"] == -32003


async def test_runtime_extension_starts_are_audited(hubenv):
    """B-4: the model enabling an extension / delegating is recorded when the hub forwards the tool_call."""
    agent, hub, audit = hubenv
    up = hub.upstream("alice", "alice")
    c, s = mk()
    hub.attach(up, c)
    st = up.sess("s1")
    up._herd_from_update(st, "session/update", {
        "sessionUpdate": "tool_call", "toolCallId": "t1", "title": "extensionmanager: manage extensions",
        "rawInput": {"action": "enable", "extension_name": "developer"}}, False)
    up._herd_from_update(st, "session/update", {
        "sessionUpdate": "tool_call", "toolCallId": "t2", "title": "delegate \u00b7 evil",
        "rawInput": {"source": "evil", "extensions": ["developer"]},
        "_meta": {"goose": {"toolCall": {"toolName": "delegate", "extensionName": "summon"}}}}, False)
    up._herd_from_update(st, "session/update", {
        "sessionUpdate": "tool_call", "toolCallId": "t3", "title": "shell \u00b7 echo delegate"}, False)
    up._herd_from_update(st, "session/update", {
        "sessionUpdate": "tool_call", "toolCallId": "t4", "title": "extensionmanager: manage extensions"}, True)
    ev = [a for a in audit if a[0].startswith("agent.")]
    assert [a[0] for a in ev] == ["agent.extension", "agent.delegate"]
    assert ev[0][2]["extensionName"] == "developer" and ev[0][2]["action"] == "enable"
    assert ev[1][2]["source"] == "evil" and ev[1][2]["extensions"] == ["developer"]
    assert agent_tool_event({"title": "scheduler__manage_schedule", "rawInput": {"action": "create"}})[0] == \
        "agent.schedule"
    assert agent_tool_event({"title": "todo__todo_write"}) is None


async def test_direct_tools_call_audits_arguments(hubenv):
    agent, hub, audit = hubenv
    up = hub.upstream("alice", "alice")
    c, s = mk(pol.ADMIN_POLICY, role="admin")
    hub.attach(up, c)
    await up.from_client(c, {"jsonrpc": "2.0", "id": 1, "method": P + "tools/call", "params": {
        "sessionId": "s1", "name": "manage_extensions", "extensionName": "extensionmanager",
        "arguments": {"action": "enable", "extension_name": "developer"}}})
    await s.reply(1)
    rec = [a for a in audit if a[0] == "acp.tools/call"][-1]
    assert rec[2]["arguments"] == {"action": "enable", "extension_name": "developer"}


# ====================================================================== profiles (B-2, C-3)
def _profiles(tmp_path, monkeypatch, team_policy=None, native_exts=None):
    from goose_web.config import load_settings
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    db = Database(tmp_path / "db.sqlite")
    native = tmp_path / "native"
    (native / "config").mkdir(parents=True)
    exts = native_exts or {
        "todo": {"enabled": True, "type": "platform", "name": "todo"},
        "developer": {"enabled": True, "type": "platform", "name": "developer"},
        "extensionmanager": {"enabled": True, "type": "platform", "name": "Extension Manager"},
        "summon": {"enabled": True, "type": "platform", "name": "summon"},
        "fetch": {"enabled": True, "type": "stdio", "name": "fetch", "cmd": "uvx", "args": ["x"]}}
    (native / "config" / "config.yaml").write_text(yaml.safe_dump({"extensions": exts}), encoding="utf-8")
    db.create_user(username="admin", role="admin", profile_mode="native", profile_path=str(native))
    uid = db.create_user(username="alice", role="user")
    tid = db.execute("INSERT INTO teams(name, policy, created_at) VALUES('t', ?, 0)",
                     (json.dumps(team_policy or {"allowed_providers": ["*"], "allowed_models": ["*"],
                                                 "allowed_modes": ["*"]}),))
    db.execute("INSERT INTO team_members(team_id, user_id) VALUES(?,?)", (tid, uid))
    return s, db, Profiles(s, db), db.user_by_id(uid), tid


def _exts(pr, user):
    return (yaml.safe_load((pr.config_dir(user) / "config.yaml").read_text(encoding="utf-8")) or {})["extensions"]


def _set_policy(db, tid, **kw):
    base = {"allowed_providers": ["*"], "allowed_models": ["*"], "allowed_modes": ["*"], **kw}
    db.execute("UPDATE teams SET policy=? WHERE id=?", (json.dumps(base), tid))


def test_guarded_extensions_pinned_off_never_removed(tmp_path, monkeypatch):
    """B-2: without allow_shell every shell-capable / extension-starting extension is PINNED `enabled: false`
    (Goose 1.57 enables a bundled extension that is missing from config.yaml); extensionmanager needs
    extensions_edit and allow_shell."""
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    pr.provision(alice)
    ex = _exts(pr, alice)
    for k in pol.GUARDED_EXTENSIONS:
        assert ex[k]["enabled"] is False, k
    assert ex["todo"]["enabled"] is True
    assert "fetch" not in ex
    _set_policy(db, tid, extensions_edit=True)
    pr.provision(alice)
    assert _exts(pr, alice)["extensionmanager"]["enabled"] is False     # extensions_edit alone: still off
    # both directions: allow_shell + extensions_edit restores what Goose Web pinned
    _set_policy(db, tid, extensions_edit=True, allow_shell=True)
    changes = pr.provision(alice)
    ex = _exts(pr, alice)
    assert ex["developer"]["enabled"] is True and ex["extensionmanager"]["enabled"] is True
    assert ex["summon"]["enabled"] is True
    for k in ("scheduler", "code_execution", "orchestrator", "computercontroller"):
        assert k not in ex, k                     # not in the admin's config: Goose's default applies again
    assert any("restored" in c for c in changes)
    _set_policy(db, tid)
    pr.provision(alice)
    ex = _exts(pr, alice)
    for k in pol.GUARDED_EXTENSIONS:
        assert ex[k]["enabled"] is False, k


def test_other_bundled_extensions_denied_by_default(tmp_path, monkeypatch):
    exts = {"todo": {"enabled": True, "type": "platform", "name": "todo", "bundled": True},
            "newthing": {"enabled": True, "type": "platform", "name": "newthing", "bundled": True},
            "autovisualiser": {"enabled": True, "type": "builtin", "name": "autovisualiser", "bundled": True},
            "scheduler": {"enabled": True, "type": "platform", "name": "scheduler", "bundled": True},
            "wiki": {"enabled": True, "type": "stdio", "name": "wiki", "cmd": "x"}}
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch, native_exts=exts)
    pr.provision(alice)
    ex = _exts(pr, alice)
    assert ex["todo"]["enabled"] is True
    assert ex["newthing"]["enabled"] is False and ex["autovisualiser"]["enabled"] is False
    assert ex["scheduler"]["enabled"] is False and "wiki" not in ex
    _set_policy(db, tid, allow_shell=True)
    pr.provision(alice)
    ex = _exts(pr, alice)
    assert ex["scheduler"]["enabled"] is True                 # restored as in the admin's config
    assert ex["newthing"]["enabled"] is False                 # not a guarded one: stays as provisioned


def test_command_extensions_parked_and_restored(tmp_path, monkeypatch):
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    _set_policy(db, tid, allow_shell=True)
    pr.provision(alice)
    cfg_path = pr.config_dir(alice) / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    cfg["extensions"]["mine"] = {"enabled": True, "type": "stdio", "name": "mine", "cmd": "x.exe", "args": []}
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    _set_policy(db, tid)
    pr.provision(alice)
    assert "mine" not in _exts(pr, alice)
    man = json.loads(pr.manifest_path(alice).read_text(encoding="utf-8"))
    assert man["parked"]["mine"]["cmd"] == "x.exe"
    _set_policy(db, tid, allow_shell=True)
    pr.provision(alice)
    assert _exts(pr, alice)["mine"]["cmd"] == "x.exe"


def test_team_command_item_not_provisioned_without_shell(tmp_path, monkeypatch):
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
               (tid, "extension", "fetch", json.dumps({"key": "fetch", "entry": {
                   "enabled": True, "type": "stdio", "name": "fetch", "cmd": "uvx", "args": ["x"]}})))
    db.execute("INSERT INTO team_items(team_id, kind, name, payload, created_at) VALUES(?,?,?,?,0)",
               (tid, "extension", "developer", json.dumps({"key": "developer", "entry": {
                   "enabled": True, "type": "platform", "name": "developer"}})))
    pr.provision(alice)
    ex = _exts(pr, alice)
    assert "fetch" not in ex and ex["developer"]["enabled"] is False
    _set_policy(db, tid, allow_shell=True)
    pr.provision(alice)
    assert _exts(pr, alice)["fetch"]["enabled"] is True
    _set_policy(db, tid)
    pr.provision(alice)
    assert "fetch" not in _exts(pr, alice)


def test_manifest_lives_in_system_dir(tmp_path, monkeypatch):
    """C-3: the manifest is gateway-owned; the in-profile file is only a content-free marker and is ignored."""
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    assert not pr.provisioned(alice)
    pr.provision(alice)
    assert pr.manifest_path(alice) == s.system_dir / "manifests" / f"{alice['id']}.json"
    assert pr.manifest_path(alice).is_file() and pr.provisioned(alice)
    legacy = pr.legacy_manifest_path(alice)
    assert "providers" not in json.loads(legacy.read_text(encoding="utf-8"))
    victim = tmp_path / "profiles" / "_system" / "sandbox"
    victim.mkdir(parents=True)
    (victim / "grant.json").write_text("{}", encoding="utf-8")
    legacy.write_text(json.dumps({"providers": ["..\\..\\..\\_system\\sandbox\\grant"]}), encoding="utf-8")
    pr.provision(alice)
    assert (victim / "grant.json").exists()


def test_legacy_manifest_ids_validated_and_deletes_confined(tmp_path, monkeypatch):
    """C-3 PoC: a planted legacy manifest with traversal ids must not delete anything outside the profile."""
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    other = tmp_path / "profiles" / "bob"
    (other / "workspace").mkdir(parents=True)
    (other / "workspace" / ".goose-web-managed").write_text("x", encoding="utf-8")
    sb = tmp_path / "profiles" / "_system" / "sandbox"
    sb.mkdir(parents=True)
    (sb / "GooseWeb.x.bob.json").write_text("{}", encoding="utf-8")
    pr.ensure_layout(alice)
    own = pr.config_dir(alice) / "custom_providers"
    own.mkdir(parents=True)
    (own / "oldp.json").write_text("{}", encoding="utf-8")
    pr.legacy_manifest_path(alice).write_text(json.dumps({
        "providers": ["..\\..\\..\\_system\\sandbox\\GooseWeb.x.bob", "../../../_system/sandbox/GooseWeb.x.bob",
                      "C:evil", "x:ads", "oldp", 5],
        "skills": ["..\\..\\..\\bob\\workspace", "CON"],
        "extensions": ["developer", "todo"]}), encoding="utf-8")
    changes = pr.provision(alice)
    assert (sb / "GooseWeb.x.bob.json").exists() and (other / "workspace").is_dir()
    assert not (own / "oldp.json").exists() and "provider oldp removed" in changes
    ex = _exts(pr, alice)
    assert ex["developer"]["enabled"] is False          # a guarded key in the manifest is never removed


@pytest.mark.skipif(sys.platform != "win32", reason="junctions")
def test_deletes_never_follow_junctions(tmp_path, monkeypatch):
    import _winapi
    s, db, pr, alice, tid = _profiles(tmp_path, monkeypatch)
    pr.provision(alice)
    outside = tmp_path / "outside"
    (outside / "skill").mkdir(parents=True)
    (outside / "skill" / ".goose-web-managed").write_text("x", encoding="utf-8")
    (outside / "p.json").write_text("{}", encoding="utf-8")
    skills = pr.config_dir(alice) / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    _winapi.CreateJunction(str(outside / "skill"), str(skills / "victim"))
    _winapi.CreateJunction(str(outside), str(pr.config_dir(alice) / "custom_providers"))
    man = json.loads(pr.manifest_path(alice).read_text(encoding="utf-8"))
    man.update(skills=["victim"], providers=["p"])
    pr.manifest_path(alice).write_text(json.dumps(man), encoding="utf-8")
    try:
        pr.provision(alice)
        assert (outside / "skill" / ".goose-web-managed").exists()
        assert (outside / "p.json").exists()
    finally:
        os.rmdir(skills / "victim")
        os.rmdir(pr.config_dir(alice) / "custom_providers")


async def test_session_states_nobody_needs_are_dropped_beyond_the_cap(hubenv, monkeypatch):
    """Review 2026-11-12, B-7: a state per session id a client names, never dropped - memory without bound."""
    import goose_web.hub as hubmod
    agent, hub, audit = hubenv
    monkeypatch.setattr(hubmod, "SESSION_STATES_MAX", 50)
    up = hub.upstream("alice", "alice")
    c, s = mk()
    hub.attach(up, c)
    up.sess("running").prompts = 1
    up.sess("queued").queue.append({"id": "q1"})
    up.sess("watched")
    c.watch.add("watched")
    up.asks["7"] = {"msg": {"id": 7}, "sessionId": "asked", "ts": 0, "guarded": False}
    up.sess("asked")
    up.pending[99] = (c, 1, None, "session/load", {"sessionId": "loading"})    # Goose has not answered yet (T-4)
    up.sess("loading")
    up.sess("junk0").buffer_bytes = 100             # what a dropped state had buffered leaves the count too (T-3)
    hub.total_buffer = 100
    for i in range(1, 500):
        up.sess(f"junk{i}")
    assert len(up.sessions) <= 50, len(up.sessions)
    assert {"running", "queued", "watched", "asked", "loading", "junk499"} <= set(up.sessions)
    assert "junk0" not in up.sessions and hub.total_buffer == 0
    up.pending.pop(99)

