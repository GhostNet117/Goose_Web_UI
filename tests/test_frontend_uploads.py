"""Specs 039 / 040 in the browser app: chunked uploads (retry with backoff, resume, cancel, two at a time, progress),
the copy of an image the model sees (downscale steps, per-message budget), links of uploads to new and forked chats,
Admin > Settings > Files and chats. Node runs the pure parts with fakes (skipped when Node is not installed); the
rest is checked in the sources, like tests/test_frontend_modules.py."""
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


def _node() -> str:
    node = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    if not Path(node).is_file():
        pytest.skip("node not available")
    return node


def _run(script: str):
    r = subprocess.run([_node(), "--input-type=module", "-e", script], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------ the upload client (uploader.js; in api.js before spec 041)
UPLOAD_HARNESS = """
const api = { ...(await import(%s)), ...(await import(%s)) };
const file = (size, name = 'f.bin') => ({ name, size, type: 'application/octet-stream', slice: (a, b) => ({ a, b, size: b - a }) });
function server(size, { failPuts = [], failWith = () => new api.ApiError(0, 'network', 'down'), gate = null } = {}) {
  const s = { received: 0, log: [], puts: 0, open: 0, maxOpen: 0 };
  s.t = {
    start: async (b) => { s.log.push(['start', b.name, b.size, b.session, b.profile]); return { id: 'U'.repeat(43), chunkBytes: 4, received: 0, size: b.size }; },
    put: async (id, off, blob, onSent, signal) => {
      s.log.push(['put', off, blob.size]);
      s.open++; s.maxOpen = Math.max(s.maxOpen, s.open);
      try {
        if (gate) await gate(signal);
        if (failPuts.includes(s.puts++)) throw failWith();
        if (off !== s.received) throw new api.ApiError(409, 'offset_mismatch', 'x', { received: s.received });
        onSent(blob.size / 2); s.received += blob.size; onSent(blob.size);
        const done = s.received === size;
        return { received: s.received, size, done, file: done ? { name: 'f.bin', path: 'C:\\\\w\\\\Web_Uploads\\\\f.bin', size } : undefined };
      } finally { s.open--; }
    },
    status: async () => { s.log.push(['status']); return { received: s.received, size, state: 'open', done: false }; },
    abort: async (id) => { s.log.push(['abort']); },
  };
  return s;
}
const out = {};
"""


def test_upload_client_retries_resumes_and_cancels():
    script = UPLOAD_HARNESS % (json.dumps((JS / "api.js").as_uri()), json.dumps((JS / "uploader.js").as_uri())) + """
// 1. a piece fails once: wait 1 s, ask the server, continue from what it has
{ const s = server(10, { failPuts: [1] }); const sleeps = [], prog = [];
  const f = await api.uploadFile('C:\\\\w', file(10), { transport: s.t, session: 'S1', profile: 'dee', onProgress: (n) => prog.push(n), sleep: async (ms) => sleeps.push(ms) });
  out.retry = { f, log: s.log, sleeps, prog }; }
// 2. a server error every time: 3 more tries after 1, 2, 4 s, then the error; the partial file is released
{ const s = server(10, { failPuts: [0, 1, 2, 3, 4, 5], failWith: () => new api.ApiError(503, 'server_error', 'busy') }); const sleeps = [];
  try { await api.uploadFile('C:\\\\w', file(10), { transport: s.t, sleep: async (ms) => sleeps.push(ms) }); out.giveup = 'no error'; }
  catch (e) { out.giveup = { status: e.status, sleeps, log: s.log }; } }
// 3. refused (403): no retry
{ const s = server(10, { failPuts: [0], failWith: () => new api.ApiError(403, 'read_only_folder', 'no') }); const sleeps = [];
  try { await api.uploadFile('C:\\\\w', file(10), { transport: s.t, sleep: async (ms) => sleeps.push(ms) }); }
  catch (e) { out.refused = { code: e.code, sleeps, log: s.log }; } }
// 4. cancel while a piece is on its way: the request stops and the server is told
{ const ac = new AbortController();
  const gate = (signal) => new Promise((resolve, reject) => { signal.addEventListener('abort', () => { const e = new Error('x'); e.name = 'AbortError'; reject(e); }); setTimeout(() => ac.abort(), 10); });
  const s = server(10, { gate });
  try { await api.uploadFile('C:\\\\w', file(10), { transport: s.t, signal: ac.signal }); out.cancel = 'no error'; }
  catch (e) { out.cancel = { name: e.name, log: s.log, slots: api.uploadSlots() }; } }
// 5. three files at once: two go up, the third waits for a slot
{ let release; const opened = new Promise((r) => { release = r; }); let waiting = 0;
  const shared = { open: 0, maxOpen: 0, starts: 0 };
  const mk = () => { const s = server(4, { gate: async () => { shared.open++; shared.maxOpen = Math.max(shared.maxOpen, shared.open); if (++waiting === 2) release(); await new Promise((r) => setTimeout(r, 30)); shared.open--; } });
    const start = s.t.start; s.t.start = async (b) => { shared.starts++; return start(b); }; return s; };
  const ps = [mk(), mk(), mk()].map((s) => api.uploadFile('C:\\\\w', file(4), { transport: s.t }));
  await opened; const startsWhileTwoOpen = shared.starts; const slots = api.uploadSlots();
  await Promise.all(ps);
  out.parallel = { maxOpen: shared.maxOpen, startsWhileTwoOpen, slots, after: api.uploadSlots(), max: api.UPLOAD_PARALLEL }; }
out.retryable = [[0, 'network'], [503, 'x'], [429, 'x'], [408, 'x'], [409, 'offset_mismatch'], [409, 'upload_busy'], [409, 'upload_ended'], [403, 'csrf'], [404, 'not_found'], [413, 'too_large'], [507, 'disk_full']]
  .map(([s, c]) => api.retryable(new api.ApiError(s, c, 'x')));
console.log(JSON.stringify(out));
"""
    o = _run(script)
    r = o["retry"]
    assert r["f"]["path"].endswith("Web_Uploads\\f.bin") and r["f"]["id"] == "U" * 43
    assert r["log"][0] == ["start", "f.bin", 10, "S1", "dee"]
    assert [x for x in r["log"] if x[0] in ("put", "status")] == [["put", 0, 4], ["put", 4, 4], ["status"], ["put", 4, 4], ["put", 8, 2]]
    assert r["sleeps"] == [1000] and r["prog"] == sorted(r["prog"]) and r["prog"][-1] == 10
    g = o["giveup"]
    assert g["status"] == 503 and g["sleeps"] == [1000, 2000, 4000] and g["log"][-1] == ["abort"]
    assert sum(1 for x in g["log"] if x[0] == "put") == 4
    assert o["refused"] == {"code": "read_only_folder", "sleeps": [], "log": [["start", "f.bin", 10, None, None], ["put", 0, 4], ["abort"]]}
    c = o["cancel"]
    assert c["name"] == "AbortError" and c["log"][-1] == ["abort"] and c["slots"] == {"active": 0, "waiting": 0}
    p = o["parallel"]
    assert p["max"] == 2 and p["maxOpen"] == 2 and p["startsWhileTwoOpen"] == 2 and p["slots"] == {"active": 2, "waiting": 1}
    assert p["after"] == {"active": 0, "waiting": 0}
    assert o["retryable"] == [True, True, True, True, True, True, False, False, False, False, False]


# ------------------------------------------------------------------ images (images.js)
def test_image_downscale_steps_and_inline_budget():
    script = f"const im = await import({json.dumps((JS / 'images.js').as_uri())});" + """
const MiB = 1024 * 1024; const out = {};
const run = async (file, img, size, read = async () => 'ORIGINAL') => { const calls = [];
  const r = await im.prepareInline(file, { decode: async () => { if (!img) throw new Error('cannot'); return img; },
    encode: async (i, w, h, type, q) => { calls.push([w, h, type, q ?? null]); return 'x'.repeat(size(w, h, type, q)); }, readBase64: read });
  return { r: r.data ? { ...r, data: r.data.length } : r, calls }; };
// a 4000x3000 photo: 1600 px, then lower JPEG quality until it fits
out.photo = await run({ type: 'image/jpeg', size: 5e6 }, { width: 4000, height: 3000 }, (w, h, t, q) => (q >= 0.75 ? 1.5 * MiB : 0.9 * MiB));
// a small JPEG that fits: sent as it is
out.small = await run({ type: 'image/jpeg', size: 300000 }, { width: 800, height: 600 }, () => 0, async () => 'y'.repeat(400000));
// a transparent screenshot: PNG when the PNG fits, JPEG when it does not
out.png = await run({ type: 'image/png', size: 2e6 }, { width: 1200, height: 800, alpha: true }, (w, h, t) => (t === 'image/png' ? 0.8 * MiB : 0.5 * MiB));
out.pngBig = await run({ type: 'image/png', size: 9e6 }, { width: 1200, height: 800, alpha: true }, (w, h, t) => (t === 'image/png' ? 3 * MiB : 0.5 * MiB));
// nothing fits at 1600 px: 3/4 of the size, and again
out.shrink = await run({ type: 'image/png', size: 3e6 }, { width: 3200, height: 2400 }, (w, h) => w * h);
// HEIC the browser cannot read; an image that never gets small enough
out.heic = await run({ type: 'image/heic', size: 1e6 }, null, () => 0);
out.never = await run({ type: 'image/jpeg', size: 1e7 }, { width: 2000, height: 2000 }, () => 2 * MiB);
out.plan = im.planInline([{ inline: { bytes: 4 * MiB } }, { inline: { bytes: 4 * MiB } }, { inline: { bytes: 4 * MiB } }, { inline: null }, {}, { inline: { bytes: 1 * MiB } }]);
out.consts = [im.INLINE_MAX_SIDE, im.INLINE_TARGET, im.MESSAGE_INLINE_BUDGET, im.JPEG_QUALITIES];
console.log(JSON.stringify(out));
"""
    o = _run(script)
    mib = 1024 * 1024
    assert o["consts"] == [1600, mib, 10 * mib, [0.85, 0.75, 0.65, 0.55]]
    assert o["photo"]["calls"] == [[1600, 1200, "image/jpeg", 0.85], [1600, 1200, "image/jpeg", 0.75], [1600, 1200, "image/jpeg", 0.65]]
    assert o["photo"]["r"]["mimeType"] == "image/jpeg" and o["photo"]["r"]["width"] == 1600 and o["photo"]["r"]["scaled"]
    assert o["small"]["calls"] == [] and o["small"]["r"] == {"data": 400000, "mimeType": "image/jpeg", "width": 800, "height": 600,
                                                            "bytes": 400000, "scaled": False}
    assert o["png"]["r"]["mimeType"] == "image/png" and o["png"]["calls"] == [[1200, 800, "image/png", None]]
    assert o["pngBig"]["r"]["mimeType"] == "image/jpeg" and o["pngBig"]["calls"][:2] == [[1200, 800, "image/png", None], [1200, 800, "image/jpeg", 0.85]]
    widths = sorted({c[0] for c in o["shrink"]["calls"]}, reverse=True)
    assert widths == [1600, 1200, 900] and o["shrink"]["r"]["width"] == 900 and o["shrink"]["r"]["bytes"] <= mib
    assert o["heic"] == {"r": {"skip": "undecodable"}, "calls": []}
    assert o["never"]["r"] == {"skip": "too_large"} and min(c[0] for c in o["never"]["calls"]) >= 320
    assert o["plan"] == [True, True, False, False, False, True]


# ------------------------------------------------------------------ wiring in the sources
def test_composer_uses_chunked_uploads_and_the_image_budget():
    comp = _js("composer.js")
    assert "import { uploadFile, uploadLimits } from './uploader.js'" in comp
    assert "import { prepareInline, planInline, NOTES } from './images.js'" in comp
    assert "IMAGE_MAX" not in comp and "readFileBase64" not in comp and "upload(cwd" not in comp
    assert "const MAX_FILES = 20;" in comp and "'At most ' + MAX_FILES + ' files at once'" in comp
    add = comp.split("async addFile(f, cwd, limits)", 1)[1].split("\n  }\n", 1)[0]
    assert "new AbortController()" in add and "signal: att.controller.signal" in add and "onProgress" in add
    assert "session: (this.o.getSessionId && this.o.getSessionId()) || null" in add and "profile: rpc.profileParam" in add
    assert "prepareInline(f)" in add and "limits.maxBytes" in add
    assert "a.controller.abort()" in comp and "'Cancel upload'" in comp and "progressText" in comp
    build = comp.split("buildBlocks() {", 1)[1].split("\n  }\n", 1)[0]
    assert "planInline(this.attachments)" in build
    assert build.index("type: 'image'") < build.index("blocks.push(a.link)")          # text, image, resource_link
    sub = comp.split("submit(steer = false) {", 1)[1].split("\n  }\n", 1)[0]
    assert "a.status === 'loading'" in sub and "{ uploads }" in sub                   # still waits for uploads
    api_js = _js("uploader.js")   # spec 041: the client moved from api.js into uploader.js (shared with the Files page)
    assert "new XMLHttpRequest()" in api_js and "file.slice(offset, end)" in api_js
    assert "x.setRequestHeader('X-CSRF-Token', csrf)" in api_js and "x.upload.onprogress" in api_js
    # a piece without progress is stopped before the server's own idle limit and tried again as a network error
    assert "export const UPLOAD_STALL_MS = 90 * 1000;" in api_js and "new ApiError(0, 'network', 'The upload stalled')" in api_js
    assert "export const UPLOAD_PARALLEL = 2;" in api_js and "export const UPLOAD_RETRIES = 3;" in api_js
    assert "export async function upload(dir, files)" in _js("api.js")                  # the old call stays
    css = (JS.parent / "css" / "app.css").read_text(encoding="utf-8")
    assert ".att-progress" in css and ".att-bar" in css and ".att-note" in css


def test_front_end_links_uploads_to_new_and_forked_chats():
    home = _js("views/home.js")
    send = home.split("onSend: async (blocks, meta = {}) => {", 1)[1].split("\n    },\n", 1)[0]
    assert "linkUploads(chat.id, { ids: meta.uploads || [], profile: rpc.profileParam || null })" in send
    assert send.index("createSession(") < send.index("linkUploads(") < send.index("chat.send(blocks)")
    chat = _js("views/chat.js")
    fork = chat.split("async function fork()", 1)[1].split("\n  }\n", 1)[0]
    assert "linkUploads(id, { from: chat.id, profile: rpc.profileParam || null })" in fork
    cs = _js("chatsession.js")
    branch = cs.split("if (mode === 'branch') {", 1)[1].split("\n    }\n", 1)[0]
    assert "linkUploads(id, { from: this.id, profile: rpc.profileParam || null })" in branch
    api_js = _js("api.js")
    assert "export async function linkUploads(session, { ids = [], from = null, profile = null } = {})" in api_js


def test_settings_page_has_files_and_chats():
    admin = _js("views/admin.js")
    assert "import { filesAndChatsSection } from './filesettings.js';" in admin
    tab = admin.split("function settingsTab(body)", 1)[1].split("\n}\n", 1)[0]
    assert "const files = filesAndChatsSection(s);" in tab and "files.el," in tab and "...files.values()" in tab
    fs = _js("views/filesettings.js")
    for s in ("'Largest file upload (MB)'", "'Delete chats and their attachments after (days without use)'",
              "'/api/admin/retention/preview' + qs({ days: daysValue() })", "POST('/api/admin/retention/run', {})",
              "confirmDialog(", "s.maxUploadMbStored", "s.retentionDaysStored", "'0 = never. From 1 to '"):
        assert s in fs, s


def test_user_guide_explains_vision():
    ug = (DOCS / "USER-GUIDE.md").read_text(encoding="utf-8")
    assert "Images up to 8 MB are sent to the model as images" not in ug
    assert "Images up to 8 MB are also shown to the model directly" not in ug
    assert '"supports_vision": true' in ug and "1600" in ug and "10 MB" in ug
    for doc in ("CONFIGURATION.md", "ADMINISTRATION.md", "ARCHITECTURE.md", "API.md", "TROUBLESHOOTING.md"):
        text = (DOCS / doc).read_text(encoding="utf-8")
        assert "/api/fs/uploads" in text or "Largest file upload" in text or "max_upload_mb" in text, doc
    conf = (DOCS / "CONFIGURATION.md").read_text(encoding="utf-8")
    assert "chat_days" in conf and re.search(r"5120", conf)
