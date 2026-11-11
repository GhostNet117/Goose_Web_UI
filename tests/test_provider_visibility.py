"""Spec 023 (1.17.0): providers a user leaves out of the chat pickers (Settings > Models & Providers > Chat pickers).
A per-user display preference stored with the other preferences; applied after the team policy, never to admin pages."""
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
def test_clean_provider_visibility():
    c = api._clean_provider_visibility
    assert c({"hidden": ["b", "a", "b", "", 3, None, "x" * 201]}) == {"hidden": ["b", "a"]}
    assert c({"hidden": "custom_x"}) == {"hidden": []}          # a string is not a list of ids
    assert c(None) == {"hidden": []} and c([1]) == {"hidden": []}
    assert c({"hidden": ["p"], "other": 1}) == {"hidden": ["p"]}   # only the known key is kept
    assert len(c({"hidden": [f"p{i}" for i in range(900)]})["hidden"]) == 500


def test_prefs_round_trip_per_user(gw):
    client, c = gw
    admin = mk_user(c.db, "boss", role="admin")
    member = mk_user(c.db, "bob")
    h = sign_in(client, c, member)
    r = client.put("/api/me/prefs", headers=h, json={"theme": "dark",
                                                    "providerVisibility": {"hidden": ["custom_a", "custom_a", 7, "custom_b"]}})
    assert r.status_code == 200
    assert client.get("/api/me/prefs").json()["providerVisibility"] == {"hidden": ["custom_a", "custom_b"]}
    # another user (and another browser of that user) sees only their own choice
    h2 = sign_in(client, c, admin)
    assert "providerVisibility" not in client.get("/api/me/prefs").json()
    client.put("/api/me/prefs", headers=h2, json={"providerVisibility": {"hidden": ["openai"]}})
    assert c.db.user_by_id(admin["id"])["prefs"]["providerVisibility"] == {"hidden": ["openai"]}
    assert c.db.user_by_id(member["id"])["prefs"]["providerVisibility"] == {"hidden": ["custom_a", "custom_b"]}
    # malformed value from a client: stored as an empty list, other prefs untouched
    h = sign_in(client, c, member)
    assert client.put("/api/me/prefs", headers=h, json={"theme": "light", "providerVisibility": "all"}).status_code == 200
    assert client.get("/api/me/prefs").json() == {"theme": "light", "providerVisibility": {"hidden": []}}


# ------------------------------------------------------------------ the picker rules, run in node
def _node():
    n = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    return n if Path(n).is_file() else None


def test_picker_rules_in_node():
    node = _node()
    if not node:
        pytest.skip("node not available")
    src = (JS / "providervis.js").read_text(encoding="utf-8")
    block = src.split("// ----- pure rules", 1)[1].split("\n", 1)[1].split("// ----- end pure rules", 1)[0].replace("export ", "")
    script = block + """
const L = [{id:'a'},{id:'b'},{id:'c'},{id:'d', variantOf:'a'},{id:'e'}];
const ctx = (o) => ({ hidden: new Set(['b','c']), defaultProvider: 'c', ...o });
const ids = (l) => l.map((p) => p.id + (p.hiddenInSettings ? '*' : ''));
console.log(JSON.stringify([
  ids(pickerProviders(L, ctx())),                       // b hidden, c is the default (kept), d is a variant
  ids(pickerProviders(L, ctx({ current: 'b' }))),       // the chat's provider stays, marked
  ids(pickerProviders(L, ctx({ current: 'd' }))),       // a variant in use stays (not 'hidden in settings')
  ids(pickerProviders(L, { hidden: hiddenIds(undefined) })),   // no preference: all but the variant
  pickerHidden('b', ctx()), pickerHidden('c', ctx()), pickerHidden('x', ctx({ variants: { x: 'a' } })), pickerHidden('', ctx()),
  // the chat header's list from Goose has every provider: unconfigured ones go, the default and unknown ids stay
  ['u', 'c', 'goose', 'a'].map((id) => pickerHidden(id, ctx({ unconfigured: new Set(['u', 'c']) }))),
  [...hiddenIds({ hidden: ['a', '', 3, 'a'] })],
  cleanHidden(['z', 'c', 'a', 'z', '', 5], 'c'),
  hideAllExcept(['a', 'b', 'c', 'e'], 'c'),
]));
"""
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == [
        ["a", "c", "e"], ["a", "b*", "c", "e"], ["a", "c", "d", "e"], ["a", "b", "c", "e"],
        "user", "", "variant", "",
        ["unconfigured", "", "", ""],
        ["a"], ["a", "z"], ["a", "b", "e"]]


# ------------------------------------------------------------------ wiring
def _js(rel):
    return (JS / rel).read_text(encoding="utf-8")


def test_frontend_wiring():
    prefs = _js("prefs.js")
    assert "providerVisibility: { hidden: [] }" in prefs                     # default: everything shown
    co = _js("chatoptions.js")
    load = co.split("export async function loadNewChatOptions", 1)[1].split("\n}", 1)[0]
    # policy first, then the user's choice; the full list stays available (spec 022 variants are valid targets)
    assert load.index("allowedValue('allowed_providers'") < load.index("pickerProviders(allProviders, visibilityContext(defaultProvider))")
    assert "allProviders," in load and "variantOf: e.gwVariantOf" in load
    assert "rememberProviderMeta({ defaultProvider, entries: p.entries || [] })" in load   # the header needs no request
    home = _js("views/home.js")
    # New chat offers the filtered list (1.18.0: grouped by spec 024's groupPicker, which applies the same visibility)
    assert "groupPicker(optData.allProviders, gcfg, visibilityContext(optData.defaultProvider))" in home
    chat = _js("views/chat.js")
    sel = chat.split("const renderSelects = () => {", 1)[1].split("\n  };", 1)[0]
    assert "x.value === o.currentValue || !pickerHidden(x.value, vis)" in sel and "HIDDEN_LABEL" in sel
    assert "o.id === 'provider' ? visibilityContext() : null" in sel        # only the provider picker is filtered
    st = _js("views/settings.js")
    tab = st.split("function providersTab(body)", 1)[1].split("\n// =====", 1)[0]
    assert "section('Chat pickers', null, visBox)" in tab
    assert "'Show all'" in tab and "'Hide all except default'" in tab and "hideAllExcept(" in tab
    assert "if (!v && isDef) { keepDefault(e); return; }" in tab             # the default provider cannot be hidden
    vis = tab.split("const drawVis = () => {", 1)[1].split("\n  };", 1)[0]
    assert "providers_edit" not in vis and "canEdit" not in vis             # members may choose too
    # admin pages are not filtered
    assert "providervis" not in _js("views/admin.js") and "pickerHidden" not in _js("views/admin.js")
