// REST client: same-origin cookies + CSRF header on non-GET.
import { bus } from './store.js';

let csrf = null;
export function setCsrf(t) { csrf = t || null; }

export class ApiError extends Error {
  constructor(status, code, message, data) { super(message || code || ('HTTP ' + status)); this.status = status; this.code = code; this.data = data; }
}

export async function api(method, path, body, { quiet = false, raw = false, headers = {} } = {}) {
  const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json', ...headers } };
  if (method !== 'GET' && method !== 'HEAD') {
    if (csrf) opts.headers['X-CSRF-Token'] = csrf;
    if (body instanceof FormData) opts.body = body;
    else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  }
  let res;
  try { res = await fetch(path, opts); }
  catch (e) { throw new ApiError(0, 'network', 'Network error: ' + e.message); }
  if (raw) return res;
  let data = null;
  const ct = res.headers.get('content-type') || '';
  if (res.status !== 204) {
    if (ct.includes('application/json')) { try { data = await res.json(); } catch { data = null; } }
    else { const t = await res.text(); data = t; }
  }
  if (!res.ok) {
    const code = data && typeof data === 'object' ? data.error : null;
    const msg = data && typeof data === 'object' ? (data.message || data.error) : (typeof data === 'string' && data.length < 300 ? data : res.statusText);
    const err = new ApiError(res.status, code, msg, data);
    if (!quiet) {
      if (res.status === 401 && !path.startsWith('/api/auth/')) bus.emit('unauthorized', err);
      if (res.status === 403 && code === 'password_change_required') bus.emit('password-change-required', err);
      if (res.status === 403 && code === 'totp_enrolment_required') bus.emit('totp-enrolment-required', err);
    }
    throw err;
  }
  return data;
}

export const GET = (p, o) => api('GET', p, undefined, o);
export const POST = (p, b = {}, o) => api('POST', p, b, o);
export const PUT = (p, b = {}, o) => api('PUT', p, b, o);
export const PATCH = (p, b = {}, o) => api('PATCH', p, b, o);
export const DEL = (p, o) => api('DELETE', p, undefined, o);

// Attach files to a chat: `dir` is the chat's folder; the server writes them to <dir>\Web_Uploads (spec 031) and
// answers 403 read_only_folder when this person may not write there. Single request (small files, older pages);
// the message box uses uploadFile below.
export async function upload(dir, files) {
  const fd = new FormData();
  for (const f of files) fd.append('file', f, f.name);
  return api('POST', '/api/fs/upload?dir=' + encodeURIComponent(dir), fd);
}

// ---------------------------------------------------------------- spec 039: chunked, resumable uploads
// A file goes up in pieces (the server says how big: chunkBytes, 16 MB) straight from disk (File.slice, so the
// browser never holds the file). A piece that fails is tried again RETRIES times after 1, 2, 4 s, each time from what
// the server reports it has (GET /api/fs/uploads/{id}). At most UPLOAD_PARALLEL files go up at the same time.
// Cancel = the AbortSignal: the request in flight stops and the server deletes the partial file (DELETE).
export const UPLOAD_PARALLEL = 2;
export const UPLOAD_RETRIES = 3;
export const UPLOAD_STALL_MS = 90 * 1000;   // below the server's 120 s per-piece idle limit
const slots = { active: 0, waiters: [] };
function acquireSlot(signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) { reject(abortError()); return; }
    if (slots.active < UPLOAD_PARALLEL) { slots.active++; resolve(); return; }
    const w = () => { if (signal) signal.removeEventListener('abort', onAbort); resolve(); };
    const onAbort = () => { slots.waiters = slots.waiters.filter((x) => x !== w); reject(abortError()); };
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    slots.waiters.push(w);
  });
}
function releaseSlot() { const next = slots.waiters.shift(); if (next) next(); else slots.active = Math.max(0, slots.active - 1); }
export function uploadSlots() { return { active: slots.active, waiting: slots.waiters.length }; }
function abortError() { const e = new Error('Upload cancelled'); e.name = 'AbortError'; e.code = 'cancelled'; return e; }
const wait = (ms, signal) => new Promise((resolve, reject) => {
  if (signal && signal.aborted) { reject(abortError()); return; }
  const t = setTimeout(() => { if (signal) signal.removeEventListener('abort', onAbort); resolve(); }, ms);
  const onAbort = () => { clearTimeout(t); reject(abortError()); };
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
});
// Worth another try: the network, the server's own trouble, a piece it is still taking (409 busy / offset). Not: a
// refusal (4xx), a full disk (507) or something the server cannot do (501).
export function retryable(e) {
  if (!e || e.name === 'AbortError') return false;
  const s = e.status;
  return s === 0 || s === 408 || s === 429 || (s >= 500 && s !== 501 && s !== 507) ||
    (s === 409 && (e.code === 'offset_mismatch' || e.code === 'upload_busy'));
}

const UPLOADS = '/api/fs/uploads';
export const xhrTransport = {
  start: (body) => api('POST', UPLOADS, body),
  status: (id) => api('GET', UPLOADS + '/' + encodeURIComponent(id), undefined, { quiet: true }),
  abort: (id) => api('DELETE', UPLOADS + '/' + encodeURIComponent(id), undefined, { quiet: true }),
  // One piece with XMLHttpRequest: the browser reads the Blob slice from disk while it sends, and reports progress.
  // A piece that makes no progress for UPLOAD_STALL_MS is stopped and counts as a network error (tried again).
  put: (id, offset, blob, onSent, signal) => new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    let last = Date.now(), stalled = false;
    const watch = setInterval(() => { if (Date.now() - last > UPLOAD_STALL_MS) { stalled = true; x.abort(); } }, 5000);
    const done = (fn, v) => { clearInterval(watch); fn(v); };
    x.open('PUT', UPLOADS + '/' + encodeURIComponent(id) + '?offset=' + offset);
    if (csrf) x.setRequestHeader('X-CSRF-Token', csrf);
    x.setRequestHeader('Content-Type', 'application/octet-stream');
    x.setRequestHeader('Accept', 'application/json');
    x.upload.onprogress = (e) => { last = Date.now(); if (onSent) onSent(e.loaded); };
    x.onload = () => {
      let d = null; try { d = JSON.parse(x.responseText); } catch { d = null; }
      if (x.status >= 200 && x.status < 300) { done(resolve, d); return; }
      const err = new ApiError(x.status, d && d.error, d && (d.message || d.error), d);
      if (x.status === 401) bus.emit('unauthorized', err);
      done(reject, err);
    };
    x.onerror = () => done(reject, new ApiError(0, 'network', 'Network error while uploading'));
    x.ontimeout = () => done(reject, new ApiError(0, 'network', 'The upload timed out'));
    x.onabort = () => done(reject, stalled ? new ApiError(0, 'network', 'The upload stalled') : abortError());
    if (signal) signal.addEventListener('abort', () => x.abort(), { once: true });
    x.send(blob);
  }),
};

// Upload one file into <dir>\Web_Uploads. opts: session (the chat it belongs to, spec 040), profile (an administrator
// working in another profile), onProgress(bytesSent, size), onStart(id), signal (AbortSignal: cancel), transport and
// sleep (tests). Returns the server's file: {name, path, size, mime} plus id.
export async function uploadFile(dir, file, opts = {}) {
  const { session = null, profile = null, onProgress = null, onStart = null, signal = null, transport = xhrTransport,
    sleep = wait, retries = UPLOAD_RETRIES, backoffMs = 1000 } = opts;
  const progress = (n) => { if (onProgress) onProgress(Math.min(n, file.size), file.size); };
  await acquireSlot(signal);
  let id = null;
  try {
    const start = await transport.start({ dir, name: file.name, size: file.size, mime: file.type || '', session, profile });
    id = start.id;
    if (onStart) onStart(id);
    if (start.done) { progress(file.size); return { ...start.file, id }; }
    const chunk = Math.max(1, start.chunkBytes || 16 * 1024 * 1024);
    let offset = start.received || 0;
    let tries = 0;
    progress(offset);
    while (offset < file.size) {
      if (signal && signal.aborted) throw abortError();
      const end = Math.min(file.size, offset + chunk);
      let res;
      try {
        res = await transport.put(id, offset, file.slice(offset, end), (sent) => progress(offset + sent), signal);
      } catch (e) {
        if (!retryable(e) || tries >= retries) throw e;
        tries += 1;
        await sleep(backoffMs * 2 ** (tries - 1), signal);
        const st = await transport.status(id);   // resume from what the server has
        if (st.done) { progress(file.size); return { ...st.file, id }; }
        if (st.state && st.state !== 'open') throw new ApiError(409, 'upload_ended', 'The upload ended on the server', st);
        offset = st.received || 0;
        progress(offset);
        continue;
      }
      tries = 0;
      offset = res.received;
      progress(offset);
      if (res.done) return { ...res.file, id };
    }
    const st = await transport.status(id);   // an empty remainder: the server finished with the last piece
    if (st.done) return { ...st.file, id };
    throw new ApiError(409, 'upload_ended', 'The upload did not finish on the server', st);
  } catch (e) {
    // cancelled, or given up: the server deletes what it had (best effort; idle partial files also go after 24 h)
    if (id) { try { await transport.abort(id); } catch { /* gone already, or the network is down */ } }
    throw e;
  } finally {
    releaseSlot();
  }
}

// The limits for the page (largest file, piece size); fetched once per page.
let limitsCache = null;
export function uploadLimits() {
  if (!limitsCache) limitsCache = api('GET', UPLOADS, undefined, { quiet: true }).catch((e) => { limitsCache = null; throw e; });
  return limitsCache;
}

// Spec 040: the chat these uploads belong to (files attached on New chat, before the chat existed), or every file of
// another chat (`from`: a fork or a branch shares the files of its chat). Never fails the caller.
export async function linkUploads(session, { ids = [], from = null, profile = null } = {}) {
  if (!session || (!ids.length && !from)) return null;
  try { return await api('POST', UPLOADS + '/link', { session, ids, from, profile }, { quiet: true }); }
  catch (e) { console.warn('linking uploads to the chat failed', e); return null; }
}

export function qs(params) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v !== undefined && v !== null && v !== '') u.set(k, v);
  const s = u.toString();
  return s ? '?' + s : '';
}
