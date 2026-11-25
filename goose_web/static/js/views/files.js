// Files (spec 041): the folders a person may use - their workspace, the team folder and the team's other folders
// (administrators: what the folder picker shows them). Browse in pages, upload (chunked and resumable: uploader.js with
// target "folder", 2 at a time, progress, cancel, retry), download (a plain link: the browser streams the file to disk
// and can resume it; never fetched into the page), details with SHA-256, safe previews (text set with textContent in
// a <pre>; PNG/JPEG/GIF/WebP as a blob: URL, revoked when the preview closes), hand a file to Goose, rename / move /
// delete (recycle bin, restore) and the folder's activity. Route: #/files?path=<folder>&file=<file>.
// The /api/files/* routes decide every right; this page only leaves out what the person may not do.
import { h, btn, iconBtn, pageHeader, input, select, toast, toastError, confirmDialog, promptDialog, modal, empty, skeleton, relTime, banner, errMsg, fmtDateTime, fmtBytes, baseName, spinner, copyText, pickFile, debounce, menu, table, actionBtn, checkbox } from '../ui.js';
import { icon } from '../icons.js';
import { GET, POST, api, qs } from '../api.js';
import { uploadFile, uploadLimits, isCancelled, abortUpload } from '../uploader.js';
import { router } from '../router.js';
import { policy } from '../store.js';
import { sessionsState, sessionTitle, activityTime, isArchived } from '../sessions.js';
import { setBaseTitle } from '../herd.js';
import { joinPath } from '../composer.js';

export const PAGE = 200;            // entries per request; "Load more" asks for the next ones
export const REFRESH_MS = 15000;    // automatic refresh while the page is visible
const REFRESH_MAX = 500;            // the server's largest page: a longer list is only reloaded by Refresh
const KIND_ICON = { workspace: 'user', team: 'users', extra: 'folder', home: 'user', drive: 'database' };
const ACTIONS = {
  'files.upload': 'Uploaded', 'files.download': 'Downloaded', 'files.preview': 'Previewed', 'files.mkdir': 'New folder',
  'files.rename': 'Renamed', 'files.move': 'Moved', 'files.delete': 'Deleted', 'files.restore': 'Restored',
  'files.purge': 'Removed for good', 'files.hash': 'SHA-256 computed', 'files.read': 'Read',
  'files.recycle_conflict': 'Recycle folder name freed',
};
const REFUSED = {
  exists: 'a file or folder with that name is already there', read_only_folder: 'the folder is read only',
  not_found: 'it is gone', denied: 'not allowed', bad_name: 'not a valid name', bad_request: 'not possible here',
  files_off: 'Files is switched off for your team', has_link: 'it holds a link (junction), which is not copied to another drive',
};
const SORTS = [
  { value: 'name|asc', label: 'Name A-Z' }, { value: 'name|desc', label: 'Name Z-A' },
  { value: 'mtime|desc', label: 'Newest first' }, { value: 'mtime|asc', label: 'Oldest first' },
  { value: 'size|desc', label: 'Largest first' }, { value: 'size|asc', label: 'Smallest first' },
];

// ------------------------------------------------------------------ paths
const norm = (p) => String(p || '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
export function samePath(a, b) { return norm(a) === norm(b); }
export function isInside(p, dir) { const a = norm(p), d = norm(dir); return a === d || a.startsWith(d + '\\'); }
export function parentOf(p) {
  const s = String(p || '').replace(/[\\/]+$/, '');
  const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'));
  if (i < 0) return '';
  const head = s.slice(0, i);
  return /^[A-Za-z]:$/.test(head) ? head + '\\' : (head || '/');
}
export function folderLink(p) { return '#/files' + qs({ path: p }); }
// A link a teammate with the same rights can open (Copy link).
export function fileLink(p, dir = parentOf(p)) { return location.origin + location.pathname + '#/files' + qs({ path: dir, file: p }); }
const refusal = (f) => (f && (f.message || REFUSED[f.error] || f.error)) || 'refused';
function reportFailed(failed, what) {
  const list = failed || [];
  if (!list.length) return;
  toast(list.length + ' ' + what + ': ' + list.slice(0, 5).map((f) => baseName(f.path) + ' (' + refusal(f) + ')').join(', ') + (list.length > 5 ? ', …' : ''), { kind: 'error', timeout: 10000 });
}
const validName = (v) => {
  const s = v.trim();
  if (!s) return 'Required';
  if (/[\\/:*?"<>|]/.test(s)) return 'A name cannot contain \\ / : * ? " < > |';
  if (s === '.' || s === '..') return 'Not a valid name';
  return null;
};

// ------------------------------------------------------------------ uploads (kept while the person works elsewhere)
const queue = [];
const listeners = new Set();
let upSeq = 0;
function notify(it, kind) {
  for (const fn of [...listeners]) { try { fn(it, kind); } catch (e) { console.error(e); } }
  // nobody looks at the Files page: say it in a toast
  if (!listeners.size && (kind === 'done' || (kind === 'state' && it.status === 'failed'))) {
    const open = () => router.go('/files' + qs({ path: it.dir, file: it.status === 'done' ? it.path : null }));
    if (it.status === 'done') toast('Uploaded ' + it.name + ' to ' + baseName(it.dir), { kind: 'success', actions: [{ label: 'Show', onClick: open }] });
    else toast('Upload of ' + it.name + ' failed: ' + it.error, { kind: 'error', timeout: 10000, actions: [{ label: 'Files', onClick: open }] });
  }
}
export function activeUploads() { return queue.filter((it) => it.status === 'waiting' || it.status === 'uploading').length; }
function startUpload(it) {
  it.controller = new AbortController();
  it.status = 'waiting'; it.error = '';
  if (!it.resume) it.sent = 0;
  notify(it, 'state');
  uploadFile(it.dir, it.file, {
    target: 'folder', keep: true, resume: it.resume || null, signal: it.controller.signal,
    onStart: (id, start) => { it.id = id; it.status = 'uploading'; notify(it, 'state'); },
    onProgress: (sent) => { it.sent = sent; notify(it, 'progress'); },
  }).then((f) => {
    it.status = 'done'; it.resume = null; it.path = f.path || joinPath(it.dir, it.name); it.saved = f.name || it.name;
    it.file = null;   // nothing to retry
    notify(it, 'done');
  }).catch((e) => {
    if (isCancelled(e)) { it.status = 'cancelled'; it.resume = null; }
    else { it.status = 'failed'; it.error = errMsg(e); it.resume = e.uploadId ? { id: e.uploadId, chunkBytes: e.chunkBytes } : null; }
    notify(it, 'state');
  });
}
async function enqueue(dir, files) {
  let limits = null;
  try { limits = await uploadLimits(); } catch { /* the server refuses at the start, with the limit in its message */ }
  for (const f of files) {
    const it = { key: ++upSeq, file: f, dir, name: f.name, size: f.size, sent: 0, status: 'waiting', error: '', id: null, resume: null };
    queue.push(it);
    if (limits && f.size > limits.maxBytes) {
      it.status = 'failed'; it.file = null; it.error = 'larger than the upload limit of ' + fmtBytes(limits.maxBytes);
      notify(it, 'state');
      continue;
    }
    startUpload(it);
  }
}
function dropUpload(it) {
  const i = queue.indexOf(it);
  if (i >= 0) queue.splice(i, 1);
  if (it.resume) abortUpload(it.resume.id);   // the pieces kept for Retry
  notify(it, 'removed');
}
window.addEventListener('beforeunload', (e) => {
  if (activeUploads()) { e.preventDefault(); e.returnValue = ''; }   // closing the tab stops the uploads
});

// ------------------------------------------------------------------ dialogs
// Move: a folder the person may write (locations with write access, then their sub-folders); never the items moved
// themselves or a folder inside one of them.
function chooseFolder({ title, start, exclude = [], locations = [] }) {
  return new Promise((resolve) => {
    let cur = null; let access = 'read';
    const listEl = h('div', { class: 'fp-list', role: 'list', 'aria-label': 'Folders' });
    const where = h('div', { class: 'files-choose-path mono small' });
    const ro = h('div', { class: 'fp-ro', hidden: true }, icon('lock', 13), ' Read only: nothing can be moved here.');
    const blocked = (p) => exclude.some((x) => isInside(p, x));
    let m;
    const ok = btn('Move here', () => { if (cur && access === 'write' && !blocked(cur)) m.close(cur); }, { variant: 'primary', icon: 'check', disabled: true });
    const go = async (p) => {
      listEl.replaceChildren(h('div', { class: 'fp-loading' }, spinner(16)));
      try {
        const r = await GET('/api/files/list' + qs({ path: p, offset: 0, limit: 500, sort: 'name', order: 'asc' }));
        cur = r.path; access = r.access || 'read';
        where.textContent = cur;
        ro.hidden = access === 'write';
        ok.disabled = access !== 'write' || blocked(cur);
        const dirs = (r.entries || []).filter((e) => e.dir);
        listEl.replaceChildren(
          r.parent ? h('button', { type: 'button', class: 'fp-item fp-up', onclick: () => go(r.parent) }, icon('chevronUp', 14), h('span', null, '..')) : null,
          ...dirs.map((d) => h('button', { type: 'button', class: 'fp-item', disabled: blocked(d.path), title: d.path, onclick: () => go(d.path) }, icon('folder', 14), h('span', { class: 'fp-name' }, d.name))),
          dirs.length ? null : h('div', { class: 'fp-empty' }, 'No sub-folders'));
      } catch (e) { listEl.replaceChildren(h('div', { class: 'fp-err' }, icon('alert', 14), ' ', errMsg(e))); }
    };
    const locs = locations.filter((l) => l.access === 'write');
    m = modal({
      title, size: 'lg', className: 'fp-modal',
      body: h('div', { class: 'stack-sm' },
        h('div', { class: 'files-choose-locs', role: 'group', 'aria-label': 'Locations you may write' }, ...locs.map((l) => h('button', { type: 'button', class: 'chip', title: l.path, onclick: () => go(l.path) }, icon(KIND_ICON[l.kind] || 'folder', 13), h('span', null, l.label || baseName(l.path))))),
        where, ro, listEl),
      footer: [btn('Cancel', () => m.close(null)), ok],
      onClose: (r) => resolve(r || null),
    });
    go(start || (locs[0] && locs[0].path) || '');
  });
}

// "Add to a chat": the person's recent chats (the sidebar's list) -> #/chat/<id>?attach=<path>
function addToChatDialog(path) {
  const chats = [...sessionsState.items.values()].filter((s) => !isArchived(s)).sort((a, b) => activityTime(b) - activityTime(a)).slice(0, 15);
  let m;
  const go = (s) => { m.close(); router.go('/chat/' + encodeURIComponent(s.sessionId) + qs({ attach: path })); };
  m = modal({
    title: 'Add ' + baseName(path) + ' to a chat', size: 'md',
    body: chats.length ? h('div', { class: 'files-chats', role: 'list' }, ...chats.map((s) => h('button', { type: 'button', class: 'litem', role: 'listitem', onclick: () => go(s) },
      icon('chat', 14), h('div', { class: 'litem-main' }, h('div', { class: 'litem-title' }, sessionTitle(s)), h('div', { class: 'litem-sub' }, relTime(activityTime(s)) + (s.cwd ? ' · ' + s.cwd : ''))))))
      : empty('chat', 'No chats yet', 'Use "Ask Goose about this" to start one with this file.'),
    footer: [btn('Cancel', () => m.close())],
  });
}

function detailText(d) {
  let v = d;
  if (typeof v === 'string') { try { v = JSON.parse(v); } catch { return v; } }
  if (!v || typeof v !== 'object') return v === null || v === undefined ? '' : String(v);
  const bits = [];
  if (v.size !== undefined && v.size !== null) bits.push(fmtBytes(v.size));
  if (v.from && v.to) bits.push(baseName(v.from) + ' → ' + v.to);
  else if (v.to) bits.push('→ ' + v.to);
  if (v.sha256) bits.push('SHA-256 ' + String(v.sha256).slice(0, 12) + '…');
  return bits.length ? bits.join(' · ') : JSON.stringify(v);
}
function activityDialog(folder) {
  const body = h('div', null, spinner(16));
  let m;
  m = modal({ title: 'Activity in ' + (baseName(folder) || folder), size: 'lg', body, footer: [btn('Close', () => m.close())] });
  GET('/api/files/activity' + qs({ path: folder, limit: 50 })).then((r) => {
    body.replaceChildren(h('p', { class: 'muted small' }, 'Uploads, downloads, previews and changes in this folder and its sub-folders, newest first.'), table([
      { label: 'When', render: (x) => h('span', { title: fmtDateTime(x.ts) }, relTime(x.ts)) },
      { label: 'Who', render: (x) => x.username || '' },
      { label: 'What', render: (x) => ACTIONS[x.action] || x.action || '' },
      { label: 'Item', render: (x) => h('span', { class: 'mono small files-break', title: x.target || '' }, x.target && isInside(x.target, folder) && !samePath(x.target, folder) ? String(x.target).slice(String(folder).replace(/[\\/]+$/, '').length + 1) : (x.target || '')) },
      { label: 'Details', render: (x) => h('span', { class: 'small', title: typeof x.detail === 'string' ? x.detail : JSON.stringify(x.detail || '') }, detailText(x.detail)) },
    ], r.items || [], { empty: 'Nothing recorded in this folder yet' }));
  }).catch((e) => body.replaceChildren(banner('error', errMsg(e))));
}

// The recycle bin of a location: what was deleted there (by anyone), restored to its folder until it expires.
function recycleDialog(loc, days, onRestored) {
  const body = h('div', null, spinner(16));
  let m;
  m = modal({ title: 'Recycle bin · ' + (loc.label || baseName(loc.path)), size: 'lg', body, footer: [btn('Close', () => m.close())] });
  const draw = () => GET('/api/files/recycle' + qs({ location: loc.path })).then((r) => {
    const items = r.items || [];
    // what the bin holds; an administrator can empty it before its time (a full disk) - assessment F-13
    const emptyBtn = r.canEmpty && items.length ? actionBtn('Empty now', async () => {
      const ok = await confirmDialog({ title: 'Empty this recycle bin?', confirmText: 'Remove for good', danger: true, message: 'Everything in it (' + items.length + ' item' + (items.length === 1 ? '' : 's') + ', ' + fmtBytes(r.size || 0) + ') is removed for good now and cannot be restored.' });
      if (!ok) return;
      const res = await POST('/api/files/recycle/empty', { location: loc.path });
      toast('Removed for good: ' + res.purged + (res.failed ? '; ' + res.failed + ' could not be removed now (in use)' : ''), { kind: res.failed ? 'warn' : 'success' });
      await draw();
    }, { size: 'sm', icon: 'trash', variant: 'ghost', errorPrefix: 'Empty' }) : null;
    body.replaceChildren(h('div', { class: 'row files-bin-head' }, h('p', { class: 'muted small' }, 'Deleted files and folders stay here for ' + days + ' days, then they are removed for good. Anyone who may change this location can restore them.' + (items.length ? ' Now: ' + items.length + ' item' + (items.length === 1 ? '' : 's') + ', ' + fmtBytes(r.size || 0) + '.' : '')), emptyBtn), table([
      { label: 'Name', render: (x) => h('span', { class: 'row' }, icon(x.dir ? 'folder' : 'file', 14), h('span', { class: 'files-break' }, x.name)) },
      { label: 'From', render: (x) => h('span', { class: 'mono small files-break', title: x.originalPath || '' }, parentOf(x.originalPath || '')) },
      { label: 'Size', class: 'right', render: (x) => (x.dir ? '' : fmtBytes(x.size)) },
      { label: 'Deleted', render: (x) => h('span', { title: fmtDateTime(x.deletedAt) }, relTime(x.deletedAt) + (x.deletedBy ? ' by ' + x.deletedBy : '')) },
      { label: 'Removed for good', render: (x) => h('span', { title: fmtDateTime(x.expiresAt) }, relTime(x.expiresAt)) },
      { label: '', class: 'right', render: (x) => actionBtn('Restore', async () => {
        const res = await POST('/api/files/restore', { id: x.id });
        toast('Restored: ' + (res.path || x.name), { kind: 'success' });
        await draw();
        if (onRestored) onRestored(res.path);
      }, { size: 'sm', icon: 'refresh', errorPrefix: 'Restore' }) },
    ], items, { empty: 'The recycle bin is empty' }));
  }).catch((e) => body.replaceChildren(banner('error', errMsg(e))));
  draw();
}

// ------------------------------------------------------------------ the page
const opts = { sort: 'name', order: 'asc', hidden: false, folder: '' };   // kept while the app is open

export function renderFiles(ctx, query = {}) {
  setBaseTitle('Files · Goose');
  const pageHead = (actions) => pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Files'),
    'Your folders and your team\'s: upload, download, and hand files to Goose.', actions);
  if (!policy('files')) {
    return { el: h('div', { class: 'view view-page' }, pageHead(null), h('div', { class: 'page-body' },
      banner('info', 'Files is not available to you. Your administrator decides who may use it (Admin > Teams > Folders).'))) };
  }
  let alive = true;
  let locations = []; let manage = false; let recycleDays = 30;
  let folder = query.path || (query.file ? parentOf(query.file) : '') || opts.folder || '';
  let fileSel = query.file || '';
  let listing = null; let entries = []; let sig = '';
  const selected = new Set();
  let q = ''; let loading = false; let reqSeq = 0; let lastLoad = 0; let firstLoad = true;
  let info = null; let previewUrl = null;

  // ----- elements
  const msgEl = h('div', { class: 'files-msg' });
  const locEl = h('nav', { class: 'files-locs', 'aria-label': 'Locations' });
  const upBtn = iconBtn('chevronUp', 'Up one folder', () => { if (listing && listing.parent) router.go(folderLink(listing.parent).slice(1)); });
  const crumbsEl = h('nav', { class: 'files-crumbs', 'aria-label': 'Folder' });
  const uploadBtn = btn('Upload', () => pickAndUpload(), { icon: 'upload', variant: 'primary', size: 'sm', title: 'Upload files into this folder (or drop them on the list)' });
  const mkdirBtn = btn('New folder', () => newFolder(), { icon: 'folderPlus', size: 'sm' });
  const refreshBtn = iconBtn('refresh', 'Refresh', () => { load(); if (fileSel) showFile(fileSel); });
  const filterInp = input({ type: 'search', placeholder: 'Filter', 'aria-label': 'Filter this folder', class: 'inp inp-sm files-filter' });
  const sortSel = select(SORTS, opts.sort + '|' + opts.order, { class: 'inp inp-sm files-sort-sel', 'aria-label': 'Sort' });
  const hiddenChk = checkbox(opts.hidden, 'Show hidden', (v) => { opts.hidden = v; load(); });
  const actBtn = btn('Activity', () => { if (listing) activityDialog(listing.path); }, { icon: 'activity', size: 'sm', title: 'Who uploaded, downloaded or changed what in this folder' });
  const binBtn = btn('Recycle bin', () => { const l = currentLoc(); if (l) recycleDialog(l, recycleDays, () => load()); }, { icon: 'trash', size: 'sm', title: 'Deleted items of this location' });
  const moreBtn = iconBtn('more', 'More', () => menu(moreBtn, [
    { label: 'Ask Goose in this folder', icon: 'chat', onClick: () => router.go('/new' + qs({ cwd: listing ? listing.path : folder })) },
    { label: 'Copy folder path', icon: 'copy', onClick: () => copyText(listing ? listing.path : folder, 'Path copied') },
    { label: 'Copy link to this folder', icon: 'link', onClick: () => copyText(location.origin + location.pathname + folderLink(listing ? listing.path : folder), 'Link copied') },
  ], { align: 'right' }));
  const selBar = h('div', { class: 'files-selbar', role: 'region', 'aria-label': 'Selected items', hidden: true });
  const allCb = h('input', { type: 'checkbox', 'aria-label': 'Select all listed items', onchange: (e) => {
    if (e.target.checked) entries.forEach((x) => selected.add(x.path)); else selected.clear();
    renderTable(); renderSelection();
  } });
  const sortTh = (key, label, cls) => {
    const on = opts.sort === key;
    return h('th', { class: cls, 'aria-sort': on ? (opts.order === 'asc' ? 'ascending' : 'descending') : 'none' },
      h('button', { type: 'button', class: 'files-sortbtn', title: 'Sort by ' + label.toLowerCase(), onclick: () => setSort(key) }, label, on ? icon(opts.order === 'asc' ? 'chevronUp' : 'chevronDown', 12) : null));
  };
  const theadRow = h('tr');
  const tbody = h('tbody');
  const tableEl = h('table', { class: 'tbl files-tbl' }, h('thead', null, theadRow), tbody);
  const dropZone = h('div', { class: 'tbl-wrap files-drop' }, tableEl, h('div', { class: 'files-drop-hint', 'aria-hidden': 'true' }, icon('upload', 22), h('span', null, 'Drop files to upload them here')));
  const footEl = h('div', { class: 'files-foot row', role: 'status' });
  const upEl = h('section', { class: 'files-uploads', 'aria-label': 'Uploads', hidden: true });
  const detailEl = h('aside', { class: 'files-detail', 'aria-label': 'File details', hidden: true });
  const previewEl = h('div', { class: 'files-preview' });

  const writable = () => !!listing && listing.access === 'write';
  const canManage = () => manage && writable();
  const currentLoc = () => {
    if (!listing) return null;
    const top = listing.location || listing.path;
    return locations.find((l) => samePath(l.path, top)) || { path: top, label: baseName(top) || top, access: listing.access };
  };

  // ----- loading
  async function loadLocations() {
    try {
      const r = await GET('/api/files/locations');
      if (!alive) return;
      locations = r.locations || []; manage = !!r.manage; recycleDays = r.recycleDays || 30;
      if (!folder && locations.length) { folder = locations[0].path; load(); }
      else if (!locations.length) msgEl.replaceChildren(banner('info', 'You have no folders yet. Your administrator gives your team its folders (Admin > Teams > Folders).'));
      renderLocs(); renderTools(); renderSelection();
    } catch (e) {
      if (!alive) return;
      msgEl.replaceChildren(banner(e.code === 'files_off' ? 'info' : 'error', e.code === 'files_off' ? 'Files is switched off for your team. Your administrator can switch it on (Admin > Teams > Folders).' : errMsg(e)));
    }
  }
  const signature = (list, total) => total + '|' + list.map((e) => [e.path, e.size, e.mtime, e.hidden ? 1 : 0, e.uploadedBy || '', e.sha256 || ''].join('\u0001')).join('\u0002');
  // more: the next page; quiet: the automatic refresh (the pages loaded so far, no spinner, no error shown)
  async function load({ more = false, quiet = false } = {}) {
    if (!folder || !alive) return;
    if (quiet && loading) return;
    const seq = ++reqSeq;
    const offset = more ? entries.length : 0;
    const limit = quiet ? Math.min(REFRESH_MAX, Math.max(PAGE, entries.length)) : PAGE;
    loading = true;
    if (!more && !quiet) { tbody.replaceChildren(h('tr', null, h('td', { colspan: 5 }, skeleton(4)))); footEl.replaceChildren(); }
    try {
      const r = await GET('/api/files/list' + qs({ path: folder, offset, limit, sort: opts.sort, order: opts.order, q, hidden: opts.hidden ? 1 : 0 }), quiet ? { quiet: true } : undefined);
      if (seq !== reqSeq || !alive) return;
      lastLoad = Date.now();
      const got = r.entries || [];
      const list = more ? entries.concat(got) : got;
      const s = signature(list, r.total);
      const changed = s !== sig || !listing || !samePath(listing.path, r.path) || listing.access !== r.access || !!listing.truncated !== !!r.truncated;
      listing = r; entries = list; sig = s;
      folder = r.path || folder; opts.folder = folder;
      msgEl.replaceChildren(r.truncated ? banner('info', 'This folder holds more than 20,000 items: only the first 20,000 are listed. Use the filter to find the others.') : null);
      for (const p of [...selected]) if (!entries.some((x) => x.path === p)) selected.delete(p);
      setUrl();
      if (changed || !quiet) { renderLocs(); renderCrumbs(); renderTools(); renderTable(); renderSelection(); }
      renderFoot();
      if (firstLoad) {
        firstLoad = false;
        if (fileSel) showFile(fileSel, { scroll: true });
        const a = document.activeElement;
        if (!a || a === document.body || a.id === 'main') { const f = tbody.querySelector('.files-name'); if (f) f.focus(); }
      }
    } catch (e) {
      if (seq !== reqSeq || !alive) return;
      if (quiet) return;   // the next automatic refresh tries again
      listing = null; entries = []; sig = '';
      const text = e.code === 'files_off' ? 'Files is switched off for your team. Your administrator can switch it on (Admin > Teams > Folders).'
        : e.status === 404 ? 'This folder does not exist (any more).'
          : e.status === 403 ? 'You may not open this folder. ' + errMsg(e) : errMsg(e);
      msgEl.replaceChildren(banner(e.status === 404 || e.code === 'files_off' ? 'info' : 'error', text));
      tbody.replaceChildren(); footEl.replaceChildren(); renderCrumbs(); renderTools(); renderSelection();
    } finally {
      if (seq === reqSeq) loading = false;
    }
  }
  const setUrl = () => {
    const target = '#/files' + qs({ path: folder, file: fileSel || null });
    if (location.hash !== target) history.replaceState(null, '', target);
  };
  const setSort = (key) => {
    if (opts.sort === key) opts.order = opts.order === 'asc' ? 'desc' : 'asc';
    else { opts.sort = key; opts.order = key === 'name' ? 'asc' : 'desc'; }   // sizes and dates: largest / newest first
    sortSel.value = opts.sort + '|' + opts.order;
    load();
  };
  sortSel.addEventListener('change', () => { const [s, o] = sortSel.value.split('|'); opts.sort = s; opts.order = o; load(); });
  filterInp.addEventListener('input', debounce(() => { q = filterInp.value.trim(); load(); }, 250));
  filterInp.addEventListener('keydown', (e) => { if (e.key === 'Escape' && filterInp.value) { e.stopPropagation(); filterInp.value = ''; q = ''; load(); } });

  // ----- rendering
  const renderLocs = () => {
    const cur = currentLoc();
    locEl.replaceChildren(h('div', { class: 'files-locs-head' }, 'Locations'), ...locations.map((l) => h('a', {
      class: ['files-loc', cur && samePath(cur.path, l.path) ? 'active' : ''], href: folderLink(l.path), title: l.path + (l.access === 'read' ? ' (read only)' : ''),
      'aria-current': cur && samePath(cur.path, l.path) ? 'true' : null,
    }, icon(l.access === 'read' ? 'lock' : (KIND_ICON[l.kind] || 'folder'), 14), h('span', { class: 'files-loc-name' }, l.label || baseName(l.path)), l.access === 'read' ? h('span', { class: 'fp-ro-tag' }, 'read only') : null)));
  };
  const renderCrumbs = () => {
    upBtn.hidden = !(listing && listing.parent);
    if (!listing) { crumbsEl.replaceChildren(h('span', { class: 'crumb crumb-cur' }, folder)); return; }
    const loc = currentLoc();
    const top = loc.path;
    const base = top.replace(/[\\/]+$/, '');
    const rel = isInside(listing.path, top) && !samePath(listing.path, top) ? listing.path.slice(base.length).replace(/^[\\/]+/, '') : '';
    const parts = rel ? rel.split(/[\\/]+/).filter(Boolean) : [];
    const crumb = (p, text, last) => (last ? h('span', { class: 'crumb crumb-cur', 'aria-current': 'page', title: p }, text) : h('a', { class: 'crumb', href: folderLink(p), title: p }, text));
    const nodes = [crumb(top, loc.label || baseName(top) || top, !parts.length)];
    let acc = top;
    parts.forEach((p, i) => { acc = joinPath(acc, p); nodes.push(h('span', { class: 'crumb-sep', 'aria-hidden': 'true' }, '›'), crumb(acc, p, i === parts.length - 1)); });
    crumbsEl.replaceChildren(...nodes, listing.access === 'read' ? h('span', { class: 'fp-ro-tag files-ro', title: 'Your team may read this folder, not change it' }, icon('lock', 11), ' read only') : null);
  };
  const renderTools = () => {
    const w = writable();
    uploadBtn.hidden = !w; mkdirBtn.hidden = !w;
    binBtn.hidden = !canManage();
    actBtn.disabled = !listing;
    dropZone.classList.toggle('files-drop-on', w);
  };
  const renderTable = () => {
    const n = entries.length;
    allCb.checked = n > 0 && entries.every((x) => selected.has(x.path));
    allCb.indeterminate = selected.size > 0 && !allCb.checked;
    theadRow.replaceChildren(h('th', { class: 'files-cbcell' }, allCb), sortTh('name', 'Name', 'files-namecol'), sortTh('size', 'Size', 'right files-sizecol'), sortTh('mtime', 'Modified', 'files-datecol'), h('th', { class: 'files-bycol' }, 'Uploaded by'));
    const a = document.activeElement;
    const focusRow = a && tbody.contains(a) ? a.closest('tr') : null;
    const focusPath = focusRow ? focusRow.dataset.path : null;
    const focusCb = !!(a && a.type === 'checkbox');
    const rows = entries.map((e) => {
      const on = selected.has(e.path);
      const cb = h('input', { type: 'checkbox', checked: on, 'aria-label': 'Select ' + e.name, onchange: (ev) => {
        if (ev.target.checked) selected.add(e.path); else selected.delete(e.path);
        tr.classList.toggle('selected', ev.target.checked);
        allCb.checked = entries.length > 0 && entries.every((x) => selected.has(x.path));
        allCb.indeterminate = selected.size > 0 && !allCb.checked;
        renderSelection();
      } });
      const name = e.dir
        ? h('a', { class: 'files-name', href: folderLink(e.path), title: e.name }, icon('folder', 15), h('span', null, e.name))
        : h('button', { type: 'button', class: 'files-name', title: 'Details of ' + e.name, onclick: () => showFile(e.path, { focus: true }) }, icon('file', 15), h('span', null, e.name));
      const tr = h('tr', { class: [on ? 'selected' : '', !e.dir && samePath(e.path, fileSel) ? 'active' : '', e.hidden ? 'files-hidden' : ''], dataset: { path: e.path } },
        h('td', { class: 'files-cbcell' }, cb),
        h('td', { class: 'files-namecell' }, name),
        h('td', { class: 'right files-sizecol' }, e.dir ? '' : fmtBytes(e.size)),
        h('td', { class: 'files-datecol', title: fmtDateTime(e.mtime) }, relTime(e.mtime)),
        h('td', { class: 'files-bycol', title: e.uploadedAt ? 'Uploaded ' + fmtDateTime(e.uploadedAt) : '' }, e.uploadedBy || ''));
      return tr;
    });
    tbody.replaceChildren(...(rows.length ? rows : [h('tr', null, h('td', { colspan: 5, class: 'tbl-empty' }, q ? 'Nothing here matches “' + q + '”' : writable() ? 'This folder is empty. Drop files here or use Upload.' : 'This folder is empty.'))]));
    if (focusPath) {
      const row = [...tbody.rows].find((r) => r.dataset.path === focusPath);
      const f = row && row.querySelector(focusCb ? 'input[type=checkbox]' : '.files-name');
      if (f) f.focus();
    }
  };
  const renderFoot = () => {
    if (!listing) { footEl.replaceChildren(); return; }
    const total = listing.total ?? entries.length;
    footEl.replaceChildren(h('span', { class: 'muted small grow' }, (total === entries.length ? total + ' item' + (total === 1 ? '' : 's') : entries.length + ' of ' + total + ' items') + (q ? ' matching “' + q + '”' : '')),
      entries.length < total ? btn('Load more', () => load({ more: true }), { size: 'sm', icon: 'chevronDown' }) : null);
  };
  const renderSelection = () => {
    const n = selected.size;
    selBar.hidden = !n;
    if (!n) { selBar.replaceChildren(); return; }
    const paths = [...selected];
    const can = canManage();
    selBar.replaceChildren(h('span', { class: 'strong' }, n + ' selected'),
      can && n === 1 ? btn('Rename', () => renameItem(paths[0]), { size: 'sm', icon: 'edit' }) : null,
      can ? btn('Move…', () => moveItems(paths), { size: 'sm', icon: 'folder' }) : null,
      can ? btn('Delete…', () => deleteItems(paths), { size: 'sm', icon: 'trash', variant: 'danger' }) : null,
      can ? null : h('span', { class: 'muted small' }, writable() ? 'Your team may not rename, move or delete files.' : 'This folder is read only.'),
      h('span', { class: 'grow' }),
      btn('Clear selection', () => { selected.clear(); renderTable(); renderSelection(); }, { size: 'sm', variant: 'ghost' }));
  };

  // ----- details of a file
  const closePreview = () => {
    if (previewUrl) { URL.revokeObjectURL(previewUrl); previewUrl = null; }   // the image's bytes go with it
    previewEl.replaceChildren();
  };
  const closeDetail = () => {
    closePreview();
    const was = fileSel;
    fileSel = ''; info = null;
    detailEl.hidden = true; detailEl.replaceChildren();
    setUrl();
    const row = [...tbody.rows].find((r) => samePath(r.dataset.path, was));
    if (row) { row.classList.remove('active'); const f = row.querySelector('.files-name'); if (f) f.focus(); }
  };
  detailEl.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.stopPropagation(); closeDetail(); } });
  // focus: opened by the person (keyboard and screen reader users land on the details; Esc goes back to the row)
  async function showFile(path, { scroll = false, focus = false } = {}) {
    closePreview();
    fileSel = path; info = null;
    setUrl();
    for (const r of tbody.rows) r.classList.toggle('active', samePath(r.dataset.path, path));
    if (scroll) { const row = [...tbody.rows].find((r) => samePath(r.dataset.path, path)); if (row) row.scrollIntoView({ block: 'nearest' }); }
    detailEl.hidden = false;
    detailEl.replaceChildren(detailHead(baseName(path)), h('div', { class: 'files-detail-body' }, spinner(16)));
    try {
      const i = await GET('/api/files/info' + qs({ path }));
      if (!alive || fileSel !== path) return;
      info = i;
      renderDetail();
      if (focus) { const t = detailEl.querySelector('.files-detail-title'); if (t) t.focus(); }
    } catch (e) {
      if (!alive || fileSel !== path) return;
      detailEl.replaceChildren(detailHead(baseName(path)), h('div', { class: 'files-detail-body' }, banner('error', errMsg(e))));
    }
  }
  const detailHead = (name) => h('div', { class: 'files-detail-head' }, icon('file', 16), h('h2', { class: 'files-detail-title', title: name, tabindex: '-1' }, name), iconBtn('x', 'Close details (Esc)', () => closeDetail()));
  const renderDetail = () => {
    const i = info;
    const can = manage && i.access === 'write';
    const dir = parentOf(i.path);
    const hashEl = h('dd', { class: 'files-hash' });
    // where a shown SHA-256 comes from (assessment F-5): taken when the upload finished, or computed on request - with
    // the time; it is shown only while the file's size and modification time are exactly what they were then
    const hashSource = (x) => (x.sha256Source === 'upload' ? 'recorded at upload ' + fmtDateTime(x.recordedAt)
      : x.sha256Source === 'computed' ? 'computed ' + fmtDateTime(x.recordedAt) : '');
    const drawHash = () => hashEl.replaceChildren(...(i.sha256
      ? [h('span', { class: 'row' }, h('code', { class: 'files-sha' }, i.sha256), iconBtn('copy', 'Copy SHA-256', () => copyText(i.sha256, 'SHA-256 copied'), { size: 'sm' }),
        // a stored SHA-256 is reused while size and date are unchanged; someone who may write the folder can change a
        // file and keep both, so this reads the whole file anew (force)
        iconBtn('refresh', 'Compute again (reads the whole file)', (e) => computeHash(e.currentTarget, true), { size: 'sm' })),
      h('div', { class: 'muted small files-hash-source', title: 'A stored SHA-256 is shown while the size and modification time of the file are unchanged; "Compute again" reads the file now.' }, hashSource(i))]
      : [btn('Compute', (e) => computeHash(e.currentTarget), { size: 'sm', icon: 'shield', title: 'Compute the SHA-256 of this file (large files take a while)' })]));
    const computeHash = async (b, force = false) => {
      b.disabled = true; b.replaceChildren(spinner(12), h('span', null, 'Computing…'));
      try {
        const r = await POST('/api/files/hash', force ? { path: i.path, force: true } : { path: i.path });
        Object.assign(i, { sha256: r.sha256, sha256Source: r.sha256Source, recordedAt: r.recordedAt });
        const row = entries.find((x) => x.path === i.path);
        if (row) Object.assign(row, { sha256: r.sha256, sha256Source: r.sha256Source, recordedAt: r.recordedAt });
      } catch (e) { toastError(e, 'SHA-256'); }
      if (alive && info === i) drawHash();
    };
    drawHash();
    const kv = (k, v) => (v === null || v === undefined || v === '' ? null : [h('dt', null, k), h('dd', null, v)]);
    // Download: a plain link - the browser saves the file as it arrives (5 GB is fine) and can resume it (Range)
    const dl = h('a', { class: 'btn btn-sm btn-primary', href: '/api/files/download' + qs({ path: i.path }), download: i.name, title: 'Download ' + i.name }, icon('download', 15), h('span', null, 'Download'));
    detailEl.replaceChildren(detailHead(i.name),
      h('div', { class: 'files-detail-body' },
        h('div', { class: 'files-actions' }, dl,
          btn('Preview', () => preview(i), { size: 'sm', icon: 'eye', title: 'Text and PNG, JPEG, GIF or WebP images' }),
          btn('Ask Goose about this', () => router.go('/new' + qs({ cwd: dir, attach: i.path })), { size: 'sm', icon: 'chat', title: 'A new chat in this folder with this file attached' }),
          btn('Add to a chat', () => addToChatDialog(i.path), { size: 'sm', icon: 'plus', title: 'Attach this file in one of your chats' })),
        h('dl', { class: 'kv-grid files-kv' },
          kv('Size', fmtBytes(i.size) + (i.size >= 1024 ? ' (' + Number(i.size).toLocaleString() + ' bytes)' : '')),
          kv('Type', i.type),
          kv('Modified', fmtDateTime(i.mtime)),
          kv('Created', fmtDateTime(i.ctime)),
          i.uploadedBy || i.uploadedAt ? kv('Uploaded', [i.uploadedBy ? 'by ' + i.uploadedBy : '', i.uploadedAt ? fmtDateTime(i.uploadedAt) : ''].filter(Boolean).join(', ')) : null,
          h('dt', null, 'SHA-256'), hashEl,
          kv('Path', h('span', { class: 'mono small files-break' }, i.path))),
        h('div', { class: 'files-actions' },
          btn('Copy path', () => copyText(i.path, 'Path copied'), { size: 'sm', icon: 'copy', variant: 'ghost' }),
          btn('Copy link', () => copyText(fileLink(i.path, dir), 'Link copied'), { size: 'sm', icon: 'link', variant: 'ghost', title: 'A link teammates with the same rights can open' }),
          can ? btn('Rename', () => renameItem(i.path), { size: 'sm', icon: 'edit', variant: 'ghost' }) : null,
          can ? btn('Move…', () => moveItems([i.path]), { size: 'sm', icon: 'folder', variant: 'ghost' }) : null,
          can ? btn('Delete…', () => deleteItems([i.path]), { size: 'sm', icon: 'trash', variant: 'ghost', class: 'files-del' }) : null),
        previewEl));
  };
  // Preview: text comes as JSON and is set with textContent (never as markup); an image (PNG/JPEG/GIF/WebP, never
  // SVG) as its bytes, shown from a blob: URL that is revoked when the preview closes. Anything else: no preview.
  async function preview(i) {
    closePreview();
    previewEl.replaceChildren(h('div', { class: 'files-preview-head' }, spinner(14), h('span', null, 'Loading preview…')));
    let res;
    try { res = await api('GET', '/api/files/preview' + qs({ path: i.path }), undefined, { raw: true }); }
    catch (e) { if (info === i) previewEl.replaceChildren(banner('error', errMsg(e))); return; }
    if (!alive || info !== i) return;
    const head = (text) => h('div', { class: 'files-preview-head' }, h('span', { class: 'strong grow' }, text), iconBtn('x', 'Close preview', () => closePreview(), { size: 'sm' }));
    if (!res.ok) {
      let d = null; try { d = await res.json(); } catch { d = null; }
      const none = res.status === 415;
      previewEl.replaceChildren(banner(none ? 'info' : 'error', none ? 'No preview for this kind of file: download it, or ask Goose about it.' : ((d && (d.message || d.error)) || ('HTTP ' + res.status))));
      return;
    }
    const ct = (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (ct === 'application/json') {
      let d = null; try { d = await res.json(); } catch { d = null; }
      if (!alive || info !== i) return;
      const pre = h('pre', { class: 'files-pre', tabindex: '0', 'aria-label': 'Text of ' + i.name });
      pre.textContent = String((d && d.content) || '');
      previewEl.replaceChildren(head(d && d.truncated ? 'Preview: the first 256 KB' : 'Preview'), pre);
      return;
    }
    if (/^image\/(png|jpeg|gif|webp)$/.test(ct)) {
      const blob = await res.blob();
      if (!alive || info !== i) return;
      closePreview();
      previewUrl = URL.createObjectURL(blob);
      previewEl.replaceChildren(head('Preview'), h('img', { class: 'files-img', src: previewUrl, alt: 'Preview of ' + i.name }));
      return;
    }
    previewEl.replaceChildren(banner('info', 'No preview for this kind of file: download it, or ask Goose about it.'));
  }

  // ----- changes
  async function newFolder() {
    const name = await promptDialog({ title: 'New folder', label: 'Folder name', confirmText: 'Create', validate: validName });
    if (!name || !listing) return;
    try { await POST('/api/files/mkdir', { path: listing.path, name: name.trim() }); toast('Folder created: ' + name.trim(), { kind: 'success' }); load(); }
    catch (e) { toastError(e, 'New folder'); }
  }
  async function renameItem(path) {
    const old = baseName(path);
    const name = await promptDialog({ title: 'Rename', label: 'New name', value: old, confirmText: 'Rename', validate: validName });
    if (!name || name.trim() === old) return;
    try {
      const r = await POST('/api/files/rename', { path, name: name.trim() });
      toast('Renamed to ' + baseName(r.path), { kind: 'success' });
      selected.delete(path);
      if (samePath(fileSel, path)) showFile(r.path);
      load();
    } catch (e) { toastError(e, 'Rename'); }
  }
  async function moveItems(paths) {
    const to = await chooseFolder({ title: 'Move ' + (paths.length === 1 ? baseName(paths[0]) : paths.length + ' items') + ' to…', start: listing ? listing.path : folder, exclude: paths, locations });
    if (!to) return;
    try {
      const r = await POST('/api/files/move', { paths, to });
      const moved = r.moved || [];
      if (moved.length) toast('Moved ' + (moved.length === 1 ? baseName(moved[0].from) : moved.length + ' items') + ' to ' + (baseName(to) || to), { kind: 'success', actions: [{ label: 'Open', onClick: () => router.go(folderLink(to).slice(1)) }] });
      reportFailed(r.failed, 'not moved');
      // across drives the copy is in place; what of the original could not be deleted is said (assessment F-10)
      for (const x of moved) if (x.warning) toast(baseName(x.from) + ': ' + x.warning, { kind: 'warn', timeout: 12000 });
      for (const x of moved) selected.delete(x.from);
      if (moved.some((x) => samePath(x.from, fileSel))) closeDetail();
      load();
    } catch (e) { toastError(e, 'Move'); }
  }
  async function deleteItems(paths) {
    const names = paths.map(baseName);
    const ok = await confirmDialog({
      title: paths.length === 1 ? 'Delete “' + names[0] + '”?' : 'Delete ' + paths.length + ' items?', confirmText: 'Delete', danger: true,
      message: 'Deleted items go to the recycle bin of this location for ' + recycleDays + ' days; until then anyone who may change this location can restore them.',
      extra: paths.length > 1 ? h('ul', { class: 'files-dellist' }, ...names.slice(0, 10).map((n) => h('li', null, n)), names.length > 10 ? h('li', null, '… and ' + (names.length - 10) + ' more') : null) : null,
    });
    if (!ok) return;
    try {
      const r = await POST('/api/files/delete', { paths });
      const done = r.deleted || [];
      if (done.length) toast((done.length === 1 ? baseName(done[0].path) : done.length + ' items') + ' moved to the recycle bin', { kind: 'success', timeout: 8000, actions: [{ label: 'Undo', onClick: () => restoreIds(done.map((d) => d.id)) }] });
      reportFailed(r.failed, 'not deleted');
      for (const d of done) selected.delete(d.path);
      if (done.some((d) => samePath(d.path, fileSel))) closeDetail();
      load();
    } catch (e) { toastError(e, 'Delete'); }
  }
  async function restoreIds(ids) {
    let n = 0;
    for (const id of ids) { try { await POST('/api/files/restore', { id }); n++; } catch (e) { toastError(e, 'Restore'); } }
    if (n) toast('Restored ' + n + ' item' + (n === 1 ? '' : 's'), { kind: 'success' });
    if (alive) load();
  }

  // ----- uploads
  async function pickAndUpload() {
    if (!writable()) return;
    const dir = listing.path;
    const files = await pickFile({ multiple: true });
    if (files.length) enqueue(dir, files);
  }
  const pct = (it) => (it.size ? Math.floor((it.sent || 0) * 100 / it.size) : (it.status === 'done' ? 100 : 0));
  const upText = (it) => {
    if (it.status === 'waiting') return it.sent ? 'waiting to go on…' : 'waiting…';
    if (it.status === 'uploading') return pct(it) + '% · ' + fmtBytes(it.sent || 0) + ' of ' + fmtBytes(it.size);
    if (it.status === 'done') return fmtBytes(it.size) + (it.saved && it.saved !== it.name ? ' · saved as ' + it.saved : ' · uploaded');
    if (it.status === 'cancelled') return 'cancelled';
    return 'failed: ' + it.error + (it.resume ? ' · Retry goes on from ' + fmtBytes(it.sent || 0) : '');
  };
  const upRow = (it) => {
    const going = it.status === 'waiting' || it.status === 'uploading';
    it.barEl = h('span', { class: 'att-bar', style: { width: pct(it) + '%' } });
    it.barWrap = going ? h('span', { class: 'files-up-bar', role: 'progressbar', 'aria-label': 'Upload of ' + it.name, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct(it)) }, it.barEl) : null;
    it.textEl = h('span', { class: 'files-up-text muted small' }, upText(it));
    return h('li', { class: ['files-up', 'files-up-' + it.status] },
      icon(it.status === 'done' ? 'check' : it.status === 'failed' ? 'alert' : it.status === 'cancelled' ? 'x' : 'upload', 14),
      h('div', { class: 'files-up-main' },
        h('div', { class: 'files-up-name', title: joinPath(it.dir, it.name) }, h('span', null, it.name), h('span', { class: 'muted small' }, ' → ' + (baseName(it.dir) || it.dir))),
        it.barWrap, it.textEl),
      going ? iconBtn('x', 'Cancel the upload of ' + it.name, () => { if (it.controller) it.controller.abort(); }, { size: 'sm' }) : null,
      it.status === 'failed' && it.file ? btn('Retry', () => startUpload(it), { size: 'sm', icon: 'refresh' }) : null,
      it.status === 'done' && it.path ? btn('Show', () => router.go('/files' + qs({ path: it.dir, file: it.path })), { size: 'sm', variant: 'ghost' }) : null,
      going ? null : iconBtn('x', 'Remove ' + it.name + ' from this list', () => dropUpload(it), { size: 'sm' }));
  };
  const renderUploads = () => {
    upEl.hidden = !queue.length;
    if (!queue.length) { upEl.replaceChildren(); return; }
    const going = activeUploads();
    const ended = queue.filter((it) => it.status === 'done' || it.status === 'cancelled').length;
    upEl.replaceChildren(h('div', { class: 'files-up-head row' }, h('h3', null, 'Uploads'),
      h('span', { class: 'muted small grow' }, going ? going + ' going on, 2 at a time - they keep going while you use other pages; closing the tab stops them' : ''),
      ended ? btn('Clear finished', () => { for (const it of queue.filter((x) => x.status === 'done' || x.status === 'cancelled')) dropUpload(it); }, { size: 'sm', variant: 'ghost' }) : null),
    h('ul', { class: 'files-up-list' }, ...queue.map(upRow)));
  };
  const refreshSoon = debounce(() => load({ quiet: true }), 400);
  const onUpload = (it, kind) => {
    if (kind === 'progress') {
      if (it.barEl) it.barEl.style.width = pct(it) + '%';
      if (it.barWrap) it.barWrap.setAttribute('aria-valuenow', String(pct(it)));
      if (it.textEl) it.textEl.textContent = upText(it);
      return;
    }
    renderUploads();
    if (kind === 'done' && listing && samePath(it.dir, listing.path)) refreshSoon();
  };
  listeners.add(onUpload);

  // drag and drop: files dropped anywhere on the page go into the folder shown (folders are not uploaded)
  const hasFiles = (e) => !!e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
  let dragDepth = 0;
  const onDragEnter = (e) => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; if (writable()) dropZone.classList.add('drag'); };
  const onDragOver = (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = writable() ? 'copy' : 'none'; };
  const onDragLeave = (e) => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dropZone.classList.remove('drag'); };
  const onDrop = (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); dragDepth = 0; dropZone.classList.remove('drag');
    if (!writable()) { toast('This folder is read only: nothing can be uploaded here.', { kind: 'warn' }); return; }
    const files = []; let folders = 0;
    const items = [...(e.dataTransfer.items || [])];
    if (items.length && typeof items[0].webkitGetAsEntry === 'function') {
      for (const it of items) {
        if (it.kind !== 'file') continue;
        const en = it.webkitGetAsEntry();
        if (en && en.isDirectory) { folders++; continue; }
        const f = it.getAsFile();
        if (f) files.push(f);
      }
    } else files.push(...e.dataTransfer.files);
    if (folders) toast('Folders are not uploaded: create the folder (New folder), open it and drop its files there.', { kind: 'warn', timeout: 8000 });
    if (files.length) enqueue(listing.path, files);
  };

  // ----- layout
  const el = h('div', { class: 'view view-page view-files' },
    pageHead([actBtn, binBtn]),
    h('div', { class: 'page-body files-body' },
      h('div', { class: 'files-layout' },
        locEl,
        h('section', { class: 'files-main', 'aria-label': 'Folder contents' },
          h('div', { class: 'files-pathbar row' }, upBtn, crumbsEl),
          msgEl,
          h('div', { class: 'files-toolbar' }, uploadBtn, mkdirBtn, refreshBtn, h('span', { class: 'grow' }), filterInp, sortSel, hiddenChk, moreBtn),
          upEl,
          selBar,
          dropZone,
          footEl),
        detailEl)));
  for (const [ev, fn] of [['dragenter', onDragEnter], ['dragover', onDragOver], ['dragleave', onDragLeave], ['drop', onDrop]]) el.addEventListener(ev, fn);

  renderTable(); renderCrumbs(); renderTools(); renderUploads();
  loadLocations();
  if (folder) load();
  // automatic refresh every 15 s while the page is visible (and when it becomes visible again after that long)
  const timer = setInterval(() => { if (document.visibilityState === 'visible' && entries.length <= REFRESH_MAX) load({ quiet: true }); }, REFRESH_MS);
  const onVisible = () => { if (document.visibilityState === 'visible' && Date.now() - lastLoad > REFRESH_MS) load({ quiet: true }); };
  document.addEventListener('visibilitychange', onVisible);
  return {
    el,
    destroy() {
      alive = false;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
      listeners.delete(onUpload);
      closePreview();
    },
  };
}
