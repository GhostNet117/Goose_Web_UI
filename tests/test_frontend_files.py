"""Spec 041 in the browser app: the Files page (views/files.js), its route and sidebar entry, the contract routes it
uses, safe previews, the upload client shared with the message box (uploader.js, target "folder", Retry that goes on),
"Ask Goose about this" / "Add to a chat" (?attach=) and the two team switches in Admin > Teams. Node runs the upload
client with a fake transport (skipped when Node is not installed); the rest is checked in the sources, like
tests/test_frontend_uploads.py."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import goose_web

JS = Path(goose_web.__file__).parent / "static" / "js"
DOCS = Path(goose_web.__file__).parent.parent / "docs"


def _js(rel: str) -> str:
    return (JS / rel).read_text(encoding="utf-8")


def _block(src: str, start: str, end: str = "\n  }\n") -> str:
    assert start in src, start
    return src.split(start, 1)[1].split(end, 1)[0]


def _node() -> str:
    node = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    if not Path(node).is_file():
        pytest.skip("node not available")
    return node


# ------------------------------------------------------------------ route, sidebar, policy
def test_route_and_sidebar_entry_under_herd_gated_by_policy():
    app = _js("app.js")
    assert "import { renderFiles } from './views/files.js';" in app
    assert "files: (q) => renderFiles(ctx, q.query)," in app
    side = _js("views/sidebar.js")
    nav = side.split("export const NAV = [", 1)[1].split("];", 1)[0]
    ids = re.findall(r"\{ id: '(\w+)'", nav)
    assert ids[ids.index("herd") + 1] == "files"                       # right under Herd
    assert "{ id: 'files', label: 'Files', icon: 'folder', path: '/files', key: 'f', policy: 'files' }" in nav
    assert "folder:" in _js("icons.js")
    render_nav = _block(side, "const renderNav = () => {", "\n  };\n")
    assert "(!n.policy || policy(n.policy))" in render_nav
    # the command palette and the "g f" shortcut follow the same switch
    assert "(!n.policy || policy(n.policy))" in app and "(!x.policy || policy(x.policy))" in app
    assert "import { store, bus, policy } from './store.js';" in app
    # store.policy: administrators always pass
    store = _js("store.js")
    assert "if (me.isAdmin) return true;" in _block(store, "export function policy(key) {", "\n}\n")


def test_page_checks_the_switch_before_any_request():
    files = _js("views/files.js")
    body = files.split("export function renderFiles(ctx, query = {}) {", 1)[1]
    assert body.index("if (!policy('files'))") < body.index("GET(")
    assert "Files is not available to you" in body
    # every request answer about the switch is shown in words, not as a raw code
    assert "e.code === 'files_off'" in body


# ------------------------------------------------------------------ the contract routes
def test_every_contract_route_is_used_with_its_method():
    files = _js("views/files.js")
    expect = [
        "GET('/api/files/locations')",
        "GET('/api/files/list' + qs({ path: folder, offset, limit, sort: opts.sort, order: opts.order, q, hidden: opts.hidden ? 1 : 0 })",
        "GET('/api/files/info' + qs({ path }))",
        "POST('/api/files/hash', { path: i.path })",
        "api('GET', '/api/files/preview' + qs({ path: i.path }), undefined, { raw: true })",
        "POST('/api/files/mkdir', { path: listing.path, name: name.trim() })",
        "POST('/api/files/rename', { path, name: name.trim() })",
        "POST('/api/files/move', { paths, to })",
        "POST('/api/files/delete', { paths })",
        "GET('/api/files/recycle' + qs({ location: loc.path }))",
        "POST('/api/files/restore', { id: x.id })",
        "POST('/api/files/restore', { id })",
        "GET('/api/files/activity' + qs({ path: folder, limit: 50 }))",
    ]
    for s in expect:
        assert s in files, s
    # the move chooser lists folders through the same route, 500 at most (the contract's largest page)
    assert "GET('/api/files/list' + qs({ path: p, offset: 0, limit: 500, sort: 'name', order: 'asc' }))" in files
    assert "export const PAGE = 200;" in files and "const REFRESH_MAX = 500;" in files
    # Download is a plain link the browser follows (5 GB files are never fetched into the page)
    assert "href: '/api/files/download' + qs({ path: i.path }), download: i.name" in files
    for bad in ("GET('/api/files/download'", "api('GET', '/api/files/download'", "fetch("):
        assert bad not in files, bad
    # the locations answer: manage and recycleDays are used
    assert "manage = !!r.manage; recycleDays = r.recycleDays || 30;" in files
    # every mutation goes through api.js POST, which sends the CSRF header
    assert "if (csrf) opts.headers['X-CSRF-Token'] = csrf;" in _js("api.js")


def test_read_only_folders_and_the_manage_switch_hide_the_changes():
    files = _js("views/files.js")
    assert "const writable = () => !!listing && listing.access === 'write';" in files
    assert "const canManage = () => manage && writable();" in files
    tools = _block(files, "const renderTools = () => {", "\n  };\n")
    assert "uploadBtn.hidden = !w; mkdirBtn.hidden = !w;" in tools and "binBtn.hidden = !canManage();" in tools
    sel = _block(files, "const renderSelection = () => {", "\n  };\n")
    for s in ("can && n === 1 ? btn('Rename'", "can ? btn('Move…'", "can ? btn('Delete…'"):
        assert s in sel, s
    det = _block(files, "const renderDetail = () => {", "\n  };\n")
    assert "const can = manage && i.access === 'write';" in det
    for s in ("can ? btn('Rename'", "can ? btn('Move…'", "can ? btn('Delete…'"):
        assert s in det, s
    # drops into a read-only folder are refused in the page too; the server refuses anyway (read_only_folder)
    assert "if (!writable()) { toast('This folder is read only" in files
    # Move offers only folders the person may write, never into the moved items themselves
    choose = _block(files, "function chooseFolder(", "\n}\n")
    assert "locations.filter((l) => l.access === 'write')" in choose
    assert "ok.disabled = access !== 'write' || blocked(cur);" in choose and "exclude.some((x) => isInside(p, x))" in choose
    # Delete asks first and says where the items go
    dele = _block(files, "async function deleteItems(paths) {")
    assert "await confirmDialog(" in dele and "recycle bin" in dele and "danger: true" in dele
    assert dele.index("await confirmDialog(") < dele.index("POST('/api/files/delete'")


def test_listing_pages_sorts_filters_and_refreshes_while_visible():
    files = _js("views/files.js")
    assert "export const REFRESH_MS = 15000;" in files
    assert "setInterval(() => { if (document.visibilityState === 'visible'" in files
    assert "clearInterval(timer);" in _block(files, "destroy() {", "\n    },\n")
    assert "btn('Load more', () => load({ more: true })" in files
    assert "const offset = more ? entries.length : 0;" in files
    assert "filterInp.addEventListener('input', debounce(" in files
    assert "checkbox(opts.hidden, 'Show hidden'" in files
    for key in ("'name'", "'size'", "'mtime'"):
        assert "sortTh(" + key in files, key
    # the automatic refresh does not redraw an unchanged list (keyboard focus stays where it is)
    assert "if (changed || !quiet)" in files and "focusPath" in files
    assert "r.truncated ?" in files                                    # the 20,000-entry cap is said
    # links to a folder or a file a teammate can open
    assert "export function fileLink(p, dir = parentOf(p))" in files and "'#/files' + qs({ path: dir, file: p })" in files
    assert "history.replaceState(null, '', target)" in files


# ------------------------------------------------------------------ previews
def test_previews_are_text_or_a_revoked_blob_url():
    files = _js("views/files.js")
    assert "innerHTML" not in files and "insertAdjacentHTML" not in files and "mdElement" not in files
    prev = _block(files, "async function preview(i) {", "\n  }\n")
    assert "h('pre'," in prev and "pre.textContent = String((d && d.content) || '');" in prev
    assert "/^image\\/(png|jpeg|gif|webp)$/.test(ct)" in prev and "svg" not in prev.lower()
    assert "previewUrl = URL.createObjectURL(blob);" in prev
    assert prev.index("closePreview();") < prev.index("URL.createObjectURL")
    close = _block(files, "const closePreview = () => {", "\n  };\n")
    assert "URL.revokeObjectURL(previewUrl); previewUrl = null;" in close
    # closed with the details, before another file is shown, and when the page goes
    assert "closePreview();" in _block(files, "const closeDetail = () => {", "\n  };\n")
    show = _block(files, "async function showFile(path, { scroll = false, focus = false } = {}) {", "\n  }\n")
    assert "closePreview();" in show
    # keyboard and screen reader users land on the details they opened; Esc closes them and goes back to the row
    assert "if (focus) { const t = detailEl.querySelector('.files-detail-title'); if (t) t.focus(); }" in show
    assert "showFile(e.path, { focus: true })" in files and "if (e.key === 'Escape') { e.stopPropagation(); closeDetail(); }" in files
    assert "closePreview();" in _block(files, "destroy() {", "\n    },\n")
    assert "res.status === 415" in prev                                 # no_preview: said in words


# ------------------------------------------------------------------ uploads
def test_upload_client_is_shared_with_the_composer():
    up = _js("uploader.js")
    api_js = _js("api.js")
    assert "export async function uploadFile(dir, file, opts = {})" in up
    assert "export async function uploadFile" not in api_js and "new XMLHttpRequest()" not in api_js   # moved, not copied
    assert "export function csrfToken() { return csrf; }" in api_js and "const csrf = csrfToken();" in up
    assert "import { uploadFile, uploadLimits } from './uploader.js';" in _js("composer.js")
    files = _js("views/files.js")
    assert "import { uploadFile, uploadLimits, isCancelled, abortUpload } from '../uploader.js';" in files
    call = _block(files, "uploadFile(it.dir, it.file, {", "\n  })")
    assert "target: 'folder'" in call and "keep: true" in call and "resume: it.resume || null" in call
    assert "signal: it.controller.signal" in call and "onProgress" in call
    # only with a target does the start carry one: the message box's uploads stay spec 039 chat attachments
    assert "if (target) body.target = target;" in up
    # at most 2 at a time on the whole page, shared by the message box and the Files page
    assert "export const UPLOAD_PARALLEL = 2;" in up
    # cancel, retry, remove; progress per file; uploads survive leaving the page, closing the tab asks first
    assert "it.controller.abort()" in files and "btn('Retry', () => startUpload(it)" in files
    assert "role: 'progressbar'" in files and "'aria-valuenow'" in files
    assert "window.addEventListener('beforeunload'" in files and "listeners.delete(onUpload);" in files
    # drag and drop onto the page; folders are not uploaded
    assert "['drop', onDrop]" in files and "en.isDirectory" in files


UPLOADER_HARNESS = """
const { ApiError } = await import(%s);
const up = await import(%s);
const file = (size) => ({ name: 'f.bin', size, type: '', slice: (a, b) => ({ size: b - a }) });
function srv(size, { failFrom = -1 } = {}) {
  const s = { received: 0, log: [], puts: 0 };
  s.t = {
    start: async (b) => { s.log.push(['start', b]); return { id: 'U'.repeat(43), chunkBytes: 4, received: 0, size: b.size }; },
    put: async (id, off, blob, onSent) => {
      s.log.push(['put', off, blob.size]);
      if (failFrom >= 0 && s.puts++ >= failFrom) throw new ApiError(0, 'network', 'down');
      s.received = off + blob.size; onSent(blob.size);
      const done = s.received === size;
      return { received: s.received, size, done, file: done ? { name: 'f (1).bin', path: 'D:\\\\T\\\\f (1).bin', size } : undefined };
    },
    status: async () => { s.log.push(['status']); return { received: s.received, size, state: 'open', done: false }; },
    abort: async () => { s.log.push(['abort']); },
  };
  return s;
}
const out = {};
{ const s = srv(6); await up.uploadFile('D:\\\\T', file(6), { transport: s.t, target: 'folder' }); out.withTarget = s.log[0][1]; }
{ const s = srv(6); await up.uploadFile('C:\\\\w', file(6), { transport: s.t }); out.without = s.log[0][1]; }
{ const s = srv(10, { failFrom: 1 }); let err = null;
  try { await up.uploadFile('D:\\\\T', file(10), { transport: s.t, target: 'folder', keep: true, sleep: async () => {} }); } catch (e) { err = e; }
  out.kept = { uploadId: err.uploadId, chunkBytes: err.chunkBytes, aborted: s.log.some((x) => x[0] === 'abort') };
  const s2 = srv(10); s2.received = 4;
  s2.t.start = async () => { throw new Error('a new start was not expected'); };
  const f = await up.uploadFile('D:\\\\T', file(10), { transport: s2.t, target: 'folder', resume: { id: err.uploadId, chunkBytes: err.chunkBytes } });
  out.resumed = { log: s2.log, path: f.path, id: f.id }; }
{ const s = srv(10); s.t.put = async () => { throw new ApiError(403, 'read_only_folder', 'no'); };
  try { await up.uploadFile('D:\\\\T', file(10), { transport: s.t, keep: true }); } catch (e) { out.refused = { uploadId: e.uploadId || null, code: e.code, aborted: s.log.some((x) => x[0] === 'abort') }; } }
{ const s = srv(6); s.t.status = async () => { throw new ApiError(404, 'not_found', 'gone'); };
  await up.uploadFile('D:\\\\T', file(6), { transport: s.t, target: 'folder', resume: { id: 'OLD', chunkBytes: 4 } });
  out.fresh = s.log.filter((x) => x[0] === 'start').length; }
{ const s = srv(10, { failFrom: 0 }); const ac = new AbortController(); ac.abort();
  try { await up.uploadFile('D:\\\\T', file(10), { transport: s.t, keep: true, signal: ac.signal }); } catch (e) { out.cancelled = { name: e.name, cancelled: up.isCancelled(e), log: s.log.length }; } }
out.slots = up.uploadSlots();
console.log(JSON.stringify(out));
"""


def test_uploader_target_folder_keep_and_resume():
    script = UPLOADER_HARNESS % (json.dumps((JS / "api.js").as_uri()), json.dumps((JS / "uploader.js").as_uri()))
    r = subprocess.run([_node(), "--input-type=module", "-e", script], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    o = json.loads(r.stdout.strip().splitlines()[-1])
    assert o["withTarget"]["target"] == "folder" and o["withTarget"]["dir"] == "D:\\T" and o["withTarget"]["session"] is None
    assert "target" not in o["without"]                                   # the message box: unchanged (spec 039)
    # keep: given up on the network -> the pieces stay on the server, the error says which upload; Retry goes on there
    assert o["kept"] == {"uploadId": "U" * 43, "chunkBytes": 4, "aborted": False}
    assert o["resumed"]["log"] == [["status"], ["put", 4, 4], ["put", 8, 2]]
    assert o["resumed"]["path"] == "D:\\T\\f (1).bin" and o["resumed"]["id"] == "U" * 43
    # a refusal is never kept; an upload the server no longer has starts again; a cancel stops before anything
    assert o["refused"] == {"uploadId": None, "code": "read_only_folder", "aborted": True}
    assert o["fresh"] == 1
    assert o["cancelled"] == {"name": "AbortError", "cancelled": True, "log": 0}
    assert o["slots"] == {"active": 0, "waiting": 0}


# ------------------------------------------------------------------ hand a file to Goose
def test_attach_parameters_open_a_chip_without_upload():
    comp = _js("composer.js")
    att = _block(comp, "  attachPath(path, info = {}) {")
    assert "att.link = { type: 'resource_link', uri: fileUri(path), name };" in att
    assert "status: 'ready'" in att and "id: null" in att                   # nothing uploaded, nothing linked (spec 040)
    assert "uploadFile" not in att and "this.attachments.some((a) => a.path === path)" in att
    ex = _block(comp, "  async attachExisting(path) {")
    assert "GET('/api/files/info' + qs({ path }))" in ex and "this.removeAtt(att);" in ex and "i.dir" in ex
    home = _js("views/home.js")
    blk = _block(home, "  if (query.attach) {", "\n  }\n")
    assert "composer.attachExisting(query.attach);" in blk and "delete rest.attach;" in blk
    assert "history.replaceState(null, '', '#/new' + qs(rest));" in blk
    assert "let cwd = query.cwd || '';" in home                             # the chat starts in the file's folder
    chat = _js("views/chat.js")
    assert "export function renderChat(ctx, sessionId, query = {}) {" in chat
    blk = _block(chat, "  if (query.attach) {", "\n  }\n")
    assert "composer.attachExisting(query.attach);" in blk and "history.replaceState(null, '', '#/chat/' + encodeURIComponent(sessionId));" in blk
    assert "chat: (q) => q.args[0] ? renderChat(ctx, q.args[0], q.query) : renderHome(ctx, q.query)," in _js("app.js")
    files = _js("views/files.js")
    assert "router.go('/new' + qs({ cwd: dir, attach: i.path }))" in files
    add = _block(files, "function addToChatDialog(path) {", "\n}\n")
    assert "sessionsState.items.values()" in add and "!isArchived(s)" in add and "activityTime(b) - activityTime(a)" in add
    assert "router.go('/chat/' + encodeURIComponent(s.sessionId) + qs({ attach: path }))" in add
    for label in ("'Ask Goose about this'", "'Add to a chat'", "'Copy path'", "'Copy link'", "'Download'"):
        assert label in files, label


# ------------------------------------------------------------------ Admin > Teams
def test_team_switches_and_user_overrides():
    admin = _js("views/admin.js")
    flags = admin.split("export const POLICY_FLAGS = [", 1)[1].split("];", 1)[0]
    assert "['files', 'Files: browse, download and upload']" in flags
    assert "['files_manage', 'Rename, move and delete files']" in flags
    assert "{ id: 'folders', title: 'Folders', flags: ['files', 'files_manage'] }" in admin
    assert "const parts = g.flags.map(flagRow);" in admin                  # drawn like the other switches
    assert "POLICY_FLAGS.map((f) => f[0]).join(', ')" in admin              # the user dialog names the switches
    assert "and the two Files switches" in admin                             # a new team starts with both on


def test_files_styles():
    css = (JS.parent / "css" / "app.css").read_text(encoding="utf-8")
    for sel in (".files-layout", ".files-locs", ".files-tbl", ".files-detail", ".files-pre", ".files-img",
                ".files-drop.drag", ".files-up-bar", ".files-selbar"):
        assert sel in css, sel
    narrow = css.split("/* ---------- Files page (spec 041) ---------- */", 1)[1].split("@media (max-width: 860px) {", 1)[1]
    assert ".files-detail { position: fixed; inset: 0;" in narrow           # a phone: the details fill the screen


# ------------------------------------------------------------------ documentation
def test_docs_describe_the_files_page():
    ug = (DOCS / "USER-GUIDE.md").read_text(encoding="utf-8")
    sec = ug.split("## 9. Files", 1)[1].split("\n## 10. ", 1)[0]
    for s in ("Upload", "Download", "SHA-256", "Preview", "Ask Goose about this", "Add to a chat", "Recycle bin",
              "Rename", "read only", "Files: browse, download and upload", "Rename, move and delete files"):
        assert s in sec, s
    assert "9. [Files](#9-files)" in ug and "17. [FAQ](#17-faq)" in ug
    assert "| `g` `f` | Files |" in ug
    arch = (DOCS / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "| `js/uploader.js` |" in arch and "| `js/views/files.js` |" in arch
