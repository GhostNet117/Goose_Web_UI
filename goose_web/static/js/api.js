// REST client: same-origin cookies + CSRF header on non-GET.
import { bus } from './store.js';

let csrf = null;
export function setCsrf(t) { csrf = t || null; }
// The token for requests made without api() (uploader.js sends the pieces with XMLHttpRequest).
export function csrfToken() { return csrf; }

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
// the message box and the Files page use uploader.js.
export async function upload(dir, files) {
  const fd = new FormData();
  for (const f of files) fd.append('file', f, f.name);
  return api('POST', '/api/fs/upload?dir=' + encodeURIComponent(dir), fd);
}

// Spec 039/041: the chunked, resumable upload client (uploadFile, uploadLimits) is in uploader.js.

// Spec 040: the chat these uploads belong to (files attached on New chat, before the chat existed), or every file of
// another chat (`from`: a fork or a branch shares the files of its chat). Never fails the caller.
export async function linkUploads(session, { ids = [], from = null, profile = null } = {}) {
  if (!session || (!ids.length && !from)) return null;
  try { return await api('POST', '/api/fs/uploads/link', { session, ids, from, profile }, { quiet: true }); }
  catch (e) { console.warn('linking uploads to the chat failed', e); return null; }
}

export function qs(params) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) if (v !== undefined && v !== null && v !== '') u.set(k, v);
  const s = u.toString();
  return s ? '?' + s : '';
}
