"""Spec 024 (1.18.0): provider groups and model labels (Settings > Models & Providers > Provider groups).
A per-user display alias stored with the preferences: several providers shown as one entry in the chat pickers, each
member's models labelled `<prefix>-<model display name>`; a pick still sets the real provider and model."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import goose_web
from goose_web import api
from test_sec_web import build, mk_user, sign_in

JS = Path(goose_web.__file__).parent / "static" / "js"


@pytest.fixture
def gw(tmp_path):
    app, c = build(tmp_path)
    with TestClient(app) as client:
        yield client, c
    c.db.close()


# ------------------------------------------------------------------ server: stored per user, cleaned
def test_clean_provider_groups():
    c = api._clean_provider_groups
    assert c(None) == {"groups": [], "modelNames": {}} and c("x") == {"groups": [], "modelNames": {}}
    v = c({"groups": [
        {"id": "lab", "name": "  Lab  ", "members": [{"provider": "custom_a", "prefix": " A "}, {"provider": "custom_b"},
                                                    {"provider": "custom_a", "prefix": "dup"}, "bad", {"provider": ""}]},
        {"id": "lab", "name": "", "members": [{"provider": "custom_b", "prefix": "B"}, {"provider": "custom_c", "prefix": 5}]},
        {"id": "no spaces!", "name": "X" * 100, "members": "custom_d"},
        7],
        "modelNames": {"m-1": "  Model One ", "m-2": "", "m-3": 3, "": "x", "m-4": "y" * 200}, "extra": 1})
    assert v["groups"] == [
        {"id": "lab", "name": "Lab", "members": [{"provider": "custom_a", "prefix": "A"}, {"provider": "custom_b", "prefix": ""}]},
        # repeated id -> a new one; custom_b is already in "lab" (a provider is in one group only); bad prefix -> ""
        {"id": "g2", "name": "Group", "members": [{"provider": "custom_c", "prefix": ""}]},
        {"id": "g3", "name": "X" * 80, "members": []}]
    assert v["modelNames"] == {"m-1": "Model One", "m-4": "y" * 120}
    big = c({"groups": [{"id": f"g{i}", "members": [{"provider": f"p{i}_{j}"} for j in range(150)]} for i in range(60)],
             "modelNames": {f"m{i}": "n" for i in range(1500)}})
    assert len(big["groups"]) == 50 and len(big["groups"][0]["members"]) == 100 and len(big["modelNames"]) == 1000


def test_prefs_round_trip_per_user(gw):
    client, c = gw
    admin = mk_user(c.db, "boss", role="admin")
    member = mk_user(c.db, "bob")
    h = sign_in(client, c, member)
    groups = {"groups": [{"id": "g1", "name": "Lab", "members": [{"provider": "custom_a", "prefix": "A"}, {"provider": "custom_b", "prefix": "B"}]}],
              "modelNames": {"model-x": "Model X"}}
    r = client.put("/api/me/prefs", headers=h, json={"theme": "dark", "providerGroups": groups})
    assert r.status_code == 200
    assert client.get("/api/me/prefs").json()["providerGroups"] == groups      # a member may set it (own profile)
    h2 = sign_in(client, c, admin)
    assert "providerGroups" not in client.get("/api/me/prefs").json()          # per user
    assert client.put("/api/me/prefs", headers=h2, json={"providerGroups": {"groups": "all"}}).status_code == 200
    assert c.db.user_by_id(admin["id"])["prefs"]["providerGroups"] == {"groups": [], "modelNames": {}}
    assert c.db.user_by_id(member["id"])["prefs"]["providerGroups"] == groups


# ------------------------------------------------------------------ the picker rules, run in node
def _node():
    n = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    return n if Path(n).is_file() else None


def _pure(name):
    src = (JS / name).read_text(encoding="utf-8")
    return src.split("// ----- pure rules", 1)[1].split("\n", 1)[1].split("// ----- end pure rules", 1)[0].replace("export ", "")


def test_group_rules_in_node():
    node = _node()
    if not node:
        pytest.skip("node not available")
    script = _pure("providervis.js") + _pure("providergroups.js") + """
const M = [{id:'m-flash', name:'m-flash'}, {id:'m-pro', name:'m-pro'}];
const P = [
  {id:'p_max', name:'Lab - max', models:M, defaultModel:'m-flash'},
  {id:'p_low', name:'Lab - low', models:M, defaultModel:'m-flash'},
  {id:'p_high', name:'Lab - high', models:M, defaultModel:'m-pro'},
  {id:'solo', name:'Solo', models:[{id:'m-pro', name:'m-pro'}], defaultModel:'m-pro'},
  {id:'var', name:'Variant', models:M, variantOf:'solo'},
];
const cfg = normGroups({ groups: [{ id:'lab', name:'Lab', members:[{provider:'p_max', prefix:'Max'}, {provider:'p_high', prefix:'High'},
  {provider:'p_low', prefix:'Low'}, {provider:'gone', prefix:'X'}] }, { id:'dup', name:'', members:[{provider:'p_max'}] }],
  modelNames: { 'm-flash': 'Flash v1', 'm-pro': ' ' } });
const brief = (l) => l.map((e) => e.group ? [e.id, e.name, e.members.map((m) => m.provider + (m.hiddenInSettings ? '*' : '')), e.models.map((m) => m.label + '=' + m.value + (m.hidden ? '*' : ''))] : [e.id, e.models.map((m) => m.name)]);
const all = groupPicker(P, cfg, { hidden: new Set() });
const hid = groupPicker(P, cfg, { hidden: new Set(['p_low', 'solo']) });
const cur = groupPicker(P, cfg, { hidden: new Set(['p_low']), current: 'p_low' });
const none = groupPicker(P, cfg, { hidden: new Set(['p_max', 'p_low', 'p_high']) });
const defd = groupPicker(P, cfg, { hidden: new Set(['p_max', 'p_low', 'p_high']), defaultProvider: 'p_high' });
const lab = all.find((e) => e.group);
const hp = headerPickers([{value:'solo', label:'Solo'}, {value:'p_low', label:'Lab - low'}, {value:'p_max', label:'Lab - max'}, {value:'goose', label:'Goose'}],
  'p_low', 'm-pro', [{value:'m-flash', label:'m-flash'}, {value:'m-pro', label:'m-pro'}], all, cfg);
const hpNoInv = headerPickers([{value:'p_max', label:'Lab - max'}], 'p_max', 'm-flash', [{value:'m-flash', label:'m-flash'}], [], cfg);
const hpSolo = headerPickers([{value:'solo', label:'Solo'}], 'solo', 'm-pro', [{value:'m-pro', label:'m-pro'}, {value:'m-flash', label:'m-flash'}], all, cfg);
console.log(JSON.stringify([
  cfg.groups.map((g) => [g.id, g.name, g.members.map((m) => m.provider + ':' + m.prefix)]), cfg.modelNames,
  brief(all), brief(hid), brief(cur), brief(none), brief(defd),
  entryOfProvider(all, 'p_high').id, entryOfProvider(all, 'solo').id, entryOfProvider(all, 'nope'),
  groupDefault(lab, 'p_high', 'm-flash'), groupDefault(lab, 'other', 'x'), groupDefault(null, 'a', 'b'),
  labelIn(lab, 'p_low', 'm-pro', cfg), labelIn(lab, 'p_low', 'm-new', cfg), labelIn(all.find((e) => e.id === 'solo'), 'solo', 'm-pro', cfg),
  splitValue('p_max|m-flash'), splitValue('m'), isGroupValue('group:lab'), isGroupValue('p_max'),
  modelLabel('', 'm-flash', 'x', cfg.modelNames), modelLabel('High', 'zz', 'Zed', cfg.modelNames),
  hp.provider, hp.model.value, hp.model.options.map((o) => o.label),
  [hpNoInv.provider, hpNoInv.model],
  hpSolo.model,
]));
"""
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    labs = ["High-Flash v1=p_high|m-flash", "High-m-pro=p_high|m-pro", "Low-Flash v1=p_low|m-flash", "Low-m-pro=p_low|m-pro",
            "Max-Flash v1=p_max|m-flash", "Max-m-pro=p_max|m-pro"]
    assert out == [
        # a provider is in its first group only; an empty name -> "Group"; blank display names are dropped
        [["lab", "Lab", ["p_max:Max", "p_high:High", "p_low:Low", "gone:X"]], ["dup", "Group", []]], {"m-flash": "Flash v1"},
        # one entry for the group (members in the group's order, labels sorted by prefix then model); the variant is not
        # offered; ungrouped providers get display names
        [["group:lab", "Lab", ["p_max", "p_high", "p_low"], labs], ["solo", ["m-pro"]]],
        # a hidden member leaves the group; a hidden ungrouped provider leaves the picker
        [["group:lab", "Lab", ["p_max", "p_high"], [x for x in labs if "p_low" not in x]]],
        # the chat's own provider stays (flagged), also inside its group
        [["group:lab", "Lab", ["p_max", "p_high", "p_low*"], [x + ("*" if "p_low" in x else "") for x in labs]], ["solo", ["m-pro"]]],
        # every member hidden -> no group entry; the default provider is never hidden (so its group stays)
        [["solo", ["m-pro"]]],
        [["group:lab", "Lab", ["p_high"], [x for x in labs if "p_high" in x]], ["solo", ["m-pro"]]],
        "group:lab", "solo", None,
        # a group's default: the default provider when it is a member, else the first member with its default model
        {"provider": "p_high", "model": "m-flash"}, {"provider": "p_max", "model": "m-flash"}, {"provider": "", "model": ""},
        "Low-m-pro", "Low-m-new", "m-pro",
        {"provider": "p_max", "model": "m-flash"}, {"provider": "", "model": "m"}, True, False,
        "Flash v1", "High-Zed",
        # chat header: members collapse into the group (once, where the first one was), the group is selected
        {"options": [{"value": "solo", "label": "Solo"}, {"value": "group:lab", "label": "Lab", "title": "Provider group"},
                     {"value": "goose", "label": "Goose"}], "value": "group:lab"},
        "p_low|m-pro", [x.split("=")[0] for x in labs],
        # no inventory yet: still one group entry, and the chat's own models with its prefix
        [{"options": [{"value": "group:lab", "label": "Lab", "title": "Provider group"}], "value": "group:lab"},
         {"options": [{"value": "p_max|m-flash", "label": "Max-Flash v1"}], "value": "p_max|m-flash"}],
        # an ungrouped chat: Goose's model list with display names, real ids as values
        {"options": [{"value": "m-pro", "label": "m-pro"}, {"value": "m-flash", "label": "Flash v1"}], "value": "m-pro"},
    ]


# ------------------------------------------------------------------ wiring
def _js(rel):
    return (JS / rel).read_text(encoding="utf-8")


def test_frontend_wiring():
    assert "providerGroups: { groups: [], modelNames: {} }" in _js("prefs.js")
    co = _js("chatoptions.js")
    load = co.split("export async function loadNewChatOptions", 1)[1].split("\n}", 1)[0]
    assert "rememberInventory(p.entries || [])" in load                      # the header needs no request per dropdown
    home = _js("views/home.js")
    opts = home.split("const renderOpts = () => {", 1)[1].split("\n  };", 1)[0]
    # policy first (allProviders is policy-filtered), then visibility + grouping; choices hold the REAL ids
    assert "groupPicker(optData.allProviders, gcfg, visibilityContext(optData.defaultProvider))" in opts
    assert "const s = splitValue(v); choice.provider = s.provider; choice.model = s.model;" in opts
    assert "groupDefault(g, optData.defaultProvider, '')" in opts
    assert "applyNewChatOptions(chat, { ...choice })" in home                 # provider switch, then model (unchanged)
    chat = _js("views/chat.js")
    sel = chat.split("const renderSelects = () => {", 1)[1].split("\n  };", 1)[0]
    assert "headerPickers(pOpts, curP, curM, mOpts, entries, gcfg)" in sel
    assert "allowedValue('allowed_providers', x.value)" in sel and "allowedValue('allowed_models', x.value)" in sel
    # a label switches the provider first, then the model
    sw = sel.split("const switchTo = async (p, m) => {", 1)[1].split("};", 1)[0]
    assert sw.index("chat.setConfig('provider', p)") < sw.index("chat.setConfig('model', m)")
    assert "const s = splitValue(v); await switchTo(s.provider, s.model);" in sel
    assert "loadInventoryOnce()" in sel and "groupOfProvider(curP, gcfg)" in sel   # at most one list per page
    st = _js("views/settings.js")
    tab = st.split("function providersTab(body)", 1)[1].split("\n// =====", 1)[0]
    assert "section('Provider groups', btn('New group'" in tab
    grp = tab.split("const drawGroups = () => {", 1)[1].split("\n  };", 1)[0]
    assert "providers_edit" not in grp and "canEdit" not in grp                 # members may group their providers
    assert "grp-prefix" in grp and "'Model display names'" in grp and "{ disabled: !!owner && !mine }" in grp
    vis = tab.split("const drawVis = () => {", 1)[1].split("\n  };", 1)[0]
    assert "gcb.dataset.group = g.id" in vis and "else if (e.providerId !== def) ids.add(e.providerId)" in vis
    assert "rememberInventory(p.entries || [])" in tab
    # admin pages are not grouped
    assert "providergroups" not in _js("views/admin.js")
