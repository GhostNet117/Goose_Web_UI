"""FIX menu-steer-extension-2026-11-19 (1.25.0), three things found in use:

1. On a phone the home page's menu button did nothing: the strip that holds it had `min-height: 10px`, was shrunk
   to that when the page was taller than the screen, and the content below was painted over the button.
2. A steer was shown twice when Goose's echo of it reached the tab before the answer to the steer call.
3. A team's library item for an extension that starts a program (stdio) is not delivered without the Shell
   permission - and the team page did not say so. An item whose source is gone was not marked either."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import goose_web
from goose_web import policy as pol
from tests.test_team_profiles import ANYCHAT, client_for, env, sign_in, team, user  # noqa: F401  (env: fixture)

STATIC = Path(goose_web.__file__).parent / "static"
JS = STATIC / "js"


def _node():
    n = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    return n if Path(n).is_file() else None


# ------------------------------------------------------------------ 1. the menu button
def test_the_home_page_menu_strip_cannot_be_shrunk_under_the_page():
    css = (STATIC / "css" / "app.css").read_text(encoding="utf-8")
    rule = re.search(r"^\.home-top \{([^}]*)\}", css, re.M).group(1)
    assert "flex: none" in rule and "min-height" not in rule
    mobile = css.split("@media (max-width: 860px) {", 1)[1]
    assert ".btn.only-mobile { flex: none; }" in mobile             # nor is the button itself squeezed
    # the strip is a child of a flex column that scrolls: that is where a min-height shrinks it
    assert re.search(r"^\.view-home \{ overflow-y: auto; \}", css, re.M)
    home = (JS / "views" / "home.js").read_text(encoding="utf-8")
    assert "h('div', { class: 'home-top' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }))" in home


# ------------------------------------------------------------------ 2. the steer's echo
def test_an_echo_adopts_this_tabs_own_steer_bubble_in_node():
    node = _node()
    if not node:
        pytest.skip("node not available")
    script = f"const {{ ownSteerFor, sameBlock, awaitsId }} = await import({json.dumps((JS / 'steerecho.js').as_uri())});" + """
const T = (text) => ({ type: 'text', text });
const own = (text, state = 'sending', extra = {}) => ({ kind: 'user', steer: true, local: true, steerState: state, blocks: [T(text)], ...extra });
const items = [
  { kind: 'user', blocks: [T('go left')], local: false, messageId: 'm1' },                 // the prompt
  own('go left'),                                                                            // 1: my steer, same words as the prompt
  { kind: 'agent' },
  own('faster', 'sending'),                                                                  // 3
  own('faster', 'sending'),                                                                  // 4: the same words again
  own('known', 'pending', { messageId: 'steer_9' }),                                         // has its id already
  own('done', 'delivered'), own('back', 'returned'),
  { kind: 'user', steer: true, local: false, steerState: 'pending', blocks: [T('theirs')] }, // somebody else's (from the gateway)
  { kind: 'user', steer: true, local: true, steerState: 'sending', blocks: [{ type: 'resource_link', uri: 'file:///a.txt' }, T('see file')] },
];
const idx = (b) => items.indexOf(ownSteerFor(items, b));
console.log(JSON.stringify([
  idx([T('go left')]), idx([T('faster')]), idx([T('  faster\\r\\n')]), idx([T('slower')]), idx([T('known')]), idx([T('done')]),
  idx([T('back')]), idx([T('theirs')]), idx([{ type: 'resource_link', uri: 'file:///a.txt' }]), idx([{ type: 'resource_link', uri: 'file:///b.txt' }]),
  idx([]), idx(null), ownSteerFor(null, [T('x')]),
  sameBlock({ type: 'image', data: 'AA', mimeType: 'image/png' }, { type: 'image', data: 'AA', mimeType: 'image/png' }),
  sameBlock({ type: 'image', data: 'AA' }, { type: 'image', data: 'AB' }), sameBlock(T('a'), { type: 'image', data: 'a' }), sameBlock(null, T('a')),
  awaitsId(items[3]), awaitsId(items[0]), awaitsId(items[5]),
]));
"""
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == [
        1,            # my steer bubble, not the prompt with the same words
        3, 3,         # the oldest of two equal ones (Goose reads steers in order); white space does not matter
        -1,           # other words: not mine - a second bubble is right
        -1, -1, -1,   # a bubble that has its id, was delivered or came back is not waiting
        -1,           # somebody else's steer is never adopted
        9, -1,        # an attachment first: matched by the file it points to
        -1, -1, None,
        True, False, False, False,
        True, False, False,
    ]


def test_the_transcript_and_the_session_use_the_rule():
    tr = (JS / "transcript.js").read_text(encoding="utf-8")
    add = tr.split("  addUser(blocks,", 1)[1].split("\n  }\n", 1)[0]
    # before the prompt-echo adoption, only for a steer, never while a transcript is replayed
    assert add.index("if (messageId && steer && !this.bulk) {") < add.index("if (messageId && !this.bulk && !steer) {")
    assert "const own = ownSteerFor(this.items, blocks);" in add and "this.setSteerState(own, 'delivered');" in add
    assert "removeItem(item) {" in tr
    cs = (JS / "chatsession.js").read_text(encoding="utf-8")
    steer = cs.split("  async steer(blocks) {", 1)[1].split("\n  }\n", 1)[0]
    # never two bubbles; a steer Goose already echoed is not queued again; a dropped connection does not resend
    assert "if (shown && shown !== item) { this.transcript.removeItem(item); return; }" in steer
    assert "if (item.messageId || item.steerState === 'delivered') { this.transcript.markUserSent(item); return; }" in steer
    lost = steer.split("if (e && e.disconnected) {", 1)[1].split("\n      }", 1)[0]
    assert "held: true" in lost and "this.enqueue(" not in lost and "return;" in lost
    assert steer.index("if (e && e.disconnected) {") < steer.index("this.enqueue(blocks);")


# ------------------------------------------------------------------ 3. extension items
def test_a_program_starting_extension_item_without_shell_is_said():
    kw = dict(hints=1, members=1, provider_items=set())
    base = {**ANYCHAT, "default_provider": "p", "default_model": "m"}
    said = lambda ws: [w["text"] for w in ws if w["text"].startswith("Members do not get the extension")]  # noqa: E731
    got = said(pol.team_warnings(base, extension_items={"fetchx", "webapi", "developer"},
                                 command_items={"fetchx", "developer"}, **kw))
    assert len(got) == 2
    assert "'fetchx'" in got[0] and "starts a program on the server" in got[0] and "Shell permission" in got[0]
    assert "'developer'" in got[1] and "starts a program" not in got[1]         # said once, with what it needs
    assert said(pol.team_warnings({**base, "allow_shell": True}, extension_items={"fetchx", "webapi"},
                                  command_items={"fetchx"}, **kw)) == []
    assert said(pol.team_warnings(base, extension_items={"webapi"}, command_items=set(), **kw)) == []


def test_team_view_warns_and_marks_a_gone_source(env, tmp_path):
    s, db, pr, c = env
    boss = user(db, "boss", role="admin")
    tid = team(db, "A", ANYCHAT)
    stdio = {"key": "fetchx", "entry": {"type": "stdio", "name": "fetchx", "cmd": "uvx", "args": ["mcp-server-fetch"], "enabled": True}}
    http = {"key": "webapi", "entry": {"type": "streamable_http", "name": "webapi", "uri": "https://example.com/mcp", "enabled": True}}
    for name, payload, source in (("fetchx", stdio, "boss:fetchx"), ("webapi", http, "manual"), ("gone", http, "nobody:gone")):
        db.execute("INSERT INTO team_items(team_id, kind, name, payload, source, created_at) VALUES(?,?,?,?,?,0)",
                   (tid, "extension", name, json.dumps(payload), source))
    with client_for(c) as tc:
        sign_in(tc, c, boss)
        w = [x["text"] for x in tc.get(f"/api/admin/teams/{tid}").json()["warnings"]]
        assert any("'fetchx'" in x and "starts a program" in x for x in w) and not any("'webapi'" in x for x in w)
        items = {i["name"]: i for i in tc.get(f"/api/admin/teams/{tid}/items").json()}
        # boss has no such extension in the profile; "nobody" is no account; a hand-made item has no source to lose
        assert items["fetchx"]["sourceGone"] is True and items["gone"]["sourceGone"] is True
        assert items["webapi"]["sourceGone"] is False
    adm = (JS / "views" / "admin.js").read_text(encoding="utf-8")
    assert "badge('source removed', 'warn')" in adm


def test_the_team_page_saves_only_what_is_finished():
    """Review 20261119_5, R-10: a pane that has been drawn again never saves (its debounced save used to overwrite
    what a provider switch had just stored); a folder path is taken when the field is left, not letter by letter
    (a half-typed path that names a folder must not be given to anyone)."""
    adm = (JS / "views" / "admin.js").read_text(encoding="utf-8")
    assert "const gen = ++paneGen;" in adm and "if (gen !== paneGen) return;" in adm
    give = adm.split("const giveProvider = async (id, item) => {", 1)[1].split("};", 1)[0]
    take = adm.split("const takeProvider = async (id, item) => {", 1)[1].split("};", 1)[0]
    assert give.lstrip().startswith("await save();") and take.lstrip().startswith("await save();")
    fl = adm.split("function folderList(rw, ro) {", 1)[1].split("\n}\n", 1)[0]
    assert "inp.addEventListener('change'," in fl and "addEventListener('input'" not in fl


def test_the_upload_folder_is_looked_at_again_before_each_file():
    """Review 20261119_5, R-5: the checks run before the body is read, and the sender decides how long that takes."""
    import goose_web.api as api_mod
    import inspect
    src = inspect.getsource(api_mod.fs_upload)
    loop = src.split("for f, name in files:", 1)[1]
    assert loop.index("_check_path(c, u, str(d), write=True)") < loop.index("_create_exclusive(d, name)")
