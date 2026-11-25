// Chunked, resumable uploads (spec 039), shared by the message box (composer.js) and the Files page (spec 041,
// views/files.js). A file goes up in pieces (the server says how big: chunkBytes, 16 MB) straight from disk
// (File.slice, so the browser never holds the file). A piece that fails is tried again RETRIES times after 1, 2, 4 s,
// each time from what the server reports it has (GET /api/fs/uploads/{id}). At most UPLOAD_PARALLEL files go up at the
// same time on the whole page (the message box and the Files page share the slots).
// Cancel = the AbortSignal: the request in flight stops and the server deletes the partial file (DELETE).
// Where the file lands: a chat attachment goes to <dir>\Web_Uploads (spec 031/039); with target "folder" (the Files
// page) into the folder <dir> itself, never over an existing file (the server names it "name (1).ext").
// No DOM here (Node runs this module in tests/test_frontend_uploads.py).
import { api, ApiError, csrfToken } from './api.js';
import { bus } from './store.js';

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
export function isCancelled(e) { return !!e && (e.name === 'AbortError' || e.code === 'cancelled'); }
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
    const csrf = csrfToken();
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

// Upload one file. dir: a chat's folder (the file goes to <dir>\Web_Uploads), or with target "folder" the folder the
// file lands in. opts: session (the chat it belongs to, spec 040), profile (an administrator working in another
// profile), target ("folder": the Files page, spec 041), onProgress(bytesSent, size), onStart(id, start), signal
// (AbortSignal: cancel), keep (the Files page: when the pieces fail for good on the network or the server's trouble,
// the partial file stays on the server and the error carries uploadId and chunkBytes for `resume`), resume ({id,
// chunkBytes}: continue that upload from what the server has; a fresh start when it is gone), transport and sleep
// (tests). Returns the server's file: {name, path, size, mime} plus id.
export async function uploadFile(dir, file, opts = {}) {
  const { session = null, profile = null, target = null, keep = false, resume = null, onProgress = null, onStart = null,
    signal = null, transport = xhrTransport, sleep = wait, retries = UPLOAD_RETRIES, backoffMs = 1000 } = opts;
  const progress = (n) => { if (onProgress) onProgress(Math.min(n, file.size), file.size); };
  await acquireSlot(signal);
  let id = null;
  let chunk = 16 * 1024 * 1024;
  try {
    let start = resume && resume.id ? await resumeFrom(transport, resume) : null;
    if (!start) {
      const body = { dir, name: file.name, size: file.size, mime: file.type || '', session, profile };
      if (target) body.target = target;
      start = await transport.start(body);
    }
    id = start.id;
    if (onStart) onStart(id, start);
    if (start.done) { progress(file.size); return { ...start.file, id }; }
    chunk = Math.max(1, start.chunkBytes || 16 * 1024 * 1024);
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
    // kept for Retry (Files page): the server still has the pieces; an idle partial file goes after 24 h
    if (id && keep && retryable(e)) { e.uploadId = id; e.chunkBytes = chunk; throw e; }
    // cancelled, or given up: the server deletes what it had (best effort; idle partial files also go after 24 h)
    if (id) { try { await transport.abort(id); } catch { /* gone already, or the network is down */ } }
    throw e;
  } finally {
    releaseSlot();
  }
}

// Retry on the Files page: where an upload the server still holds stands, as a start answer; null when it is gone or
// ended (the file then starts again).
async function resumeFrom(transport, resume) {
  try {
    const st = await transport.status(resume.id);
    if (st.done) return { ...st, id: resume.id };
    if (st.state && st.state !== 'open') return null;
    return { id: resume.id, received: st.received || 0, chunkBytes: resume.chunkBytes || st.chunkBytes, done: false };
  } catch { return null; }
}

// The partial file of an upload kept for Retry, when the person gives it up (best effort).
export async function abortUpload(id, transport = xhrTransport) {
  if (!id) return;
  try { await transport.abort(id); } catch { /* gone already */ }
}

// The limits for the page (largest file, piece size); fetched once per page.
let limitsCache = null;
export function uploadLimits() {
  if (!limitsCache) limitsCache = api('GET', UPLOADS, undefined, { quiet: true }).catch((e) => { limitsCache = null; throw e; });
  return limitsCache;
}
