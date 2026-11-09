// DOM helpers, modals, toasts, menus, formatting. No innerHTML of untrusted strings here.
import { icon } from './icons.js';

// Views build child lists with `cond ? node : null`. Native replaceChildren/append/prepend would turn
// null/undefined/booleans into literal "null"/"true" text, so filter them (and flatten arrays) once here.
for (const proto of [Element.prototype, DocumentFragment.prototype]) {
  for (const name of ['replaceChildren', 'append', 'prepend']) {
    const orig = proto[name];
    if (!orig || orig.__gwSafe) continue;
    const safe = function (...nodes) {
      return orig.apply(this, nodes.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false && n !== true));
    };
    safe.__gwSafe = true;
    proto[name] = safe;
  }
}

// URL-valued attributes are checked before they are set: only http(s), mailto, blob, data (on <img src>
// only) and relative / hash / same-origin URLs pass; anything else (javascript:, vbscript:, file:, …)
// is dropped with a console warning.
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);
const SAFE_URL_SCHEMES = new Set(['http:', 'https:', 'mailto:', 'blob:']);
export function isSafeUrlAttr(tag, attr, value) {
  let u;
  try { u = new URL(String(value), location.href); } catch { return false; }
  if (SAFE_URL_SCHEMES.has(u.protocol)) return true;
  if (u.protocol === 'data:') return String(tag).toLowerCase() === 'img' && attr === 'src';
  return u.origin === location.origin && u.origin !== 'null';
}

export function h(tag, props, ...children) {
  const el = tag === 'frag' ? document.createDocumentFragment() : document.createElement(tag);
  if (props && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) {
    children.unshift(props);
    props = null;
  }
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class' || k === 'className') el.className = Array.isArray(v) ? v.filter(Boolean).join(' ') : v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'style') el.setAttribute('style', v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k === 'text') el.textContent = v;
      else if (k === 'ref' && typeof v === 'function') v(el);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected' || k === 'indeterminate') el[k] = v;
      else if (URL_ATTRS.has(k.toLowerCase()) && !isSafeUrlAttr(tag, k.toLowerCase(), v === true ? '' : v)) console.warn('h(): dropped unsafe ' + k + ' on <' + tag + '>', String(v).slice(0, 80));
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  appendChildren(el, children);
  return el;
}

function appendChildren(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) appendChildren(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...children) { clear(el); appendChildren(el, children); return el; }

export function btn(label, onClick, opts = {}) {
  const b = h('button', {
    type: opts.type || 'button',
    class: ['btn', opts.variant ? 'btn-' + opts.variant : '', opts.size ? 'btn-' + opts.size : '', opts.class || ''],
    title: opts.title, 'aria-label': opts.aria || opts.title || (typeof label === 'string' ? label : undefined),
    disabled: opts.disabled,
    onclick: onClick ? (e) => onClick(e) : undefined,
  }, opts.icon ? icon(opts.icon, opts.iconSize || 15) : null, label ? h('span', null, label) : null);
  if (!label) b.classList.add('btn-icon');
  return b;
}

export function iconBtn(name, title, onClick, opts = {}) {
  return btn(null, onClick, { ...opts, icon: name, title, variant: opts.variant || 'ghost' });
}

export function badge(text, kind = '') { return h('span', { class: 'badge ' + (kind ? 'badge-' + kind : '') }, text); }
export function dot(status) { return h('span', { class: 'sdot s-' + (status || 'none'), title: status || '' }); }
export function spinner(size = 14) { return h('span', { class: 'spinner', style: { width: size + 'px', height: size + 'px' } }); }
export function kbd(...keys) { return h('span', { class: 'kbds' }, keys.map((k) => h('kbd', null, k))); }

export function empty(iconName, title, text, ...actions) {
  return h('div', { class: 'empty' }, icon(iconName, 30), h('div', { class: 'empty-title' }, title), text ? h('div', { class: 'empty-text' }, text) : null, actions.length ? h('div', { class: 'empty-actions' }, actions) : null);
}

export function skeleton(rows = 4) {
  return h('div', { class: 'skel-wrap' }, Array.from({ length: rows }, (_, i) => h('div', { class: 'skel', style: { width: (60 + ((i * 37) % 40)) + '%' } })));
}

export function field(label, input, hint, opts = {}) {
  const id = input && input.id ? input.id : (input && input.tagName ? (input.id = 'f' + Math.random().toString(36).slice(2, 9)) : null);
  return h('div', { class: ['field', opts.inline ? 'field-inline' : '', opts.class || ''] },
    label ? h('label', { for: id || undefined, class: 'field-label' }, label) : null,
    input,
    hint ? h('div', { class: 'field-hint' }, hint) : null);
}

export function input(props = {}) { return h('input', { class: 'inp', type: 'text', autocomplete: 'off', spellcheck: 'false', ...props }); }
export function textarea(props = {}) { return h('textarea', { class: 'inp', spellcheck: 'false', ...props }); }
export function select(options, value, props = {}) {
  const s = h('select', { class: 'inp', ...props });
  for (const o of options) {
    const opt = typeof o === 'object' ? o : { value: o, label: o };
    s.appendChild(h('option', { value: opt.value, title: opt.title }, opt.label ?? opt.value));
  }
  if (value !== undefined && value !== null) s.value = value;
  return s;
}
export function toggle(checked, onChange, props = {}) {
  const inp = h('input', { type: 'checkbox', class: 'tgl-in', checked: !!checked, disabled: props.disabled, 'aria-label': props.label, onchange: (e) => onChange && onChange(e.target.checked, e) });
  return h('label', { class: ['tgl', props.disabled ? 'is-disabled' : ''], title: props.title }, inp, h('span', { class: 'tgl-track' }, h('span', { class: 'tgl-thumb' })), props.text ? h('span', { class: 'tgl-text' }, props.text) : null);
}
export function checkbox(checked, label, onChange, props = {}) {
  return h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: !!checked, disabled: props.disabled, onchange: (e) => onChange && onChange(e.target.checked) }), h('span', null, label));
}

export function tabs(items, active, onChange, opts = {}) {
  const bar = h('div', { class: ['tabs', opts.class || ''], role: 'tablist' });
  for (const it of items) {
    if (it.hidden) continue;
    bar.appendChild(h('button', {
      type: 'button', role: 'tab', class: ['tab', it.id === active ? 'active' : ''], 'aria-selected': it.id === active ? 'true' : 'false',
      onclick: () => onChange(it.id),
    }, it.icon ? icon(it.icon, 14) : null, h('span', null, it.label), it.count !== undefined ? h('span', { class: 'tab-count' }, String(it.count)) : null));
  }
  return bar;
}

// ---------- modal ----------
const modalStack = [];
export function modal({ title, body, footer, size = 'md', onClose, closable = true, className = '' } = {}) {
  const prevFocus = document.activeElement;
  let closed = false;
  const close = (result) => {
    if (closed) return; closed = true;
    overlay.classList.add('closing');
    const idx = modalStack.indexOf(api); if (idx >= 0) modalStack.splice(idx, 1);
    setTimeout(() => overlay.remove(), 120);
    if (prevFocus && prevFocus.focus) try { prevFocus.focus(); } catch { /* */ }
    onClose && onClose(result);
  };
  const dialog = h('div', { class: ['modal', 'modal-' + size, className], role: 'dialog', 'aria-modal': 'true', 'aria-label': typeof title === 'string' ? title : 'Dialog' },
    title !== undefined ? h('div', { class: 'modal-head' }, h('div', { class: 'modal-title' }, title), closable ? iconBtn('x', 'Close', () => close(undefined)) : null) : null,
    h('div', { class: 'modal-body' }, body),
    footer ? h('div', { class: 'modal-foot' }, footer) : null);
  const overlay = h('div', { class: 'overlay', onmousedown: (e) => { if (e.target === overlay && closable) close(undefined); } }, dialog);
  document.body.appendChild(overlay);
  const api = { close, el: dialog, overlay, closable };
  modalStack.push(api);
  requestAnimationFrame(() => {
    const f = dialog.querySelector('[autofocus], .modal-body input:not([type=checkbox]):not([disabled]), .modal-body textarea, .modal-body select, .modal-foot .btn-primary');
    if (f) f.focus(); else dialog.focus();
  });
  dialog.tabIndex = -1;
  dialog.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') trapFocus(e, dialog);
  });
  return api;
}
function trapFocus(e, root) {
  const f = [...root.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter((x) => !x.disabled && x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
  else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
}
export function topModal() { return modalStack[modalStack.length - 1]; }
export function closeTopModal() { const m = topModal(); if (m && m.closable) { m.close(undefined); return true; } return false; }

export function confirmDialog({ title = 'Are you sure?', message = '', confirmText = 'Confirm', danger = false, extra = null } = {}) {
  return new Promise((resolve) => {
    let m;
    const ok = btn(confirmText, () => { m.close(true); }, { variant: danger ? 'danger' : 'primary' });
    m = modal({
      title, size: 'sm',
      body: h('div', { class: 'confirm-body' }, typeof message === 'string' ? h('p', null, message) : message, extra),
      footer: [btn('Cancel', () => m.close(false)), ok],
      onClose: (r) => resolve(!!r),
    });
    setTimeout(() => ok.focus(), 30);
  });
}

export function promptDialog({ title, label, value = '', placeholder = '', confirmText = 'Save', multiline = false, hint = '', validate, type = 'text', autocomplete = 'off' } = {}) {
  return new Promise((resolve) => {
    // type: 'password' for secrets (masked, D-5); autocomplete e.g. 'current-password'
    const inp = multiline ? textarea({ value, placeholder, rows: 8 }) : input({ value, placeholder, type, autocomplete });
    const err = h('div', { class: 'field-error' });
    let m;
    const submit = () => {
      const v = inp.value;
      const e = validate ? validate(v) : null;
      if (e) { err.textContent = e; return; }
      m.close({ value: v });
    };
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (!multiline || e.ctrlKey || e.metaKey)) { e.preventDefault(); submit(); } });
    m = modal({
      title, size: 'sm',
      body: h('div', null, field(label, inp, hint), err),
      footer: [btn('Cancel', () => m.close()), btn(confirmText, submit, { variant: 'primary' })],
      onClose: (r) => resolve(r ? r.value : null),
    });
  });
}

// ---------- toast ----------
let toastRoot;
export function toast(message, { kind = 'info', timeout = 4200, actions = [], title } = {}) {
  if (!toastRoot) { toastRoot = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.appendChild(toastRoot); }
  const ic = { info: 'info', success: 'check', error: 'alert', warn: 'alert' }[kind] || 'info';
  let timer;
  const close = () => { clearTimeout(timer); t.classList.add('closing'); setTimeout(() => t.remove(), 160); };
  const t = h('div', { class: 'toast toast-' + kind },
    icon(ic, 16),
    h('div', { class: 'toast-main' }, title ? h('div', { class: 'toast-title' }, title) : null, h('div', { class: 'toast-msg' }, message),
      actions.length ? h('div', { class: 'toast-actions' }, actions.map((a) => btn(a.label, () => { a.onClick(); close(); }, { size: 'sm', variant: a.variant || '' }))) : null),
    iconBtn('x', 'Dismiss', close, { size: 'sm' }));
  toastRoot.appendChild(t);
  while (toastRoot.children.length > 5) toastRoot.firstChild.remove();
  if (timeout) { timer = setTimeout(close, timeout); t.addEventListener('mouseenter', () => clearTimeout(timer)); t.addEventListener('mouseleave', () => { timer = setTimeout(close, 2000); }); }
  return { close };
}
export function toastError(e, prefix = '') {
  const msg = errMsg(e);
  toast(prefix ? prefix + ': ' + msg : msg, { kind: 'error', timeout: 7000 });
}
export function errMsg(e) {
  if (!e) return 'Unknown error';
  if (typeof e === 'string') return e;
  let m = e.message || e.error || String(e);
  if (e.data && typeof e.data === 'string' && !m.includes(e.data)) m += ' (' + e.data + ')';
  else if (e.data && e.data.problems) m += ': ' + e.data.problems.join(', ');
  return m;
}

// ---------- popover menu ----------
let openMenu = null;
export function closeMenu() { if (openMenu) { openMenu.remove(); openMenu = null; } }
// The app's own open menu, tracked by reference: never ask the DOM for '.menu' (untrusted content could match it, D-7).
export function isMenuOpen() { return !!(openMenu && openMenu.isConnected); }
export function menu(anchor, items, { align = 'left' } = {}) {
  closeMenu();
  const m = h('div', { class: 'menu', role: 'menu' });
  for (const it of items) {
    if (!it || it.hidden) continue;
    if (it === '-' || it.sep) { m.appendChild(h('div', { class: 'menu-sep' })); continue; }
    if (it.header) { m.appendChild(h('div', { class: 'menu-head' }, it.header)); continue; }
    m.appendChild(h('button', {
      type: 'button', role: 'menuitem', class: ['menu-item', it.danger ? 'danger' : '', it.active ? 'active' : ''], disabled: it.disabled, title: it.title,
      onclick: (e) => { e.stopPropagation(); closeMenu(); it.onClick && it.onClick(); },
    }, it.icon ? icon(it.icon, 14) : h('span', { class: 'menu-noicon' }), h('span', { class: 'menu-label' }, it.label), it.hint ? h('span', { class: 'menu-hint' }, it.hint) : null, it.active ? icon('check', 13) : null));
  }
  document.body.appendChild(m);
  const r = anchor.getBoundingClientRect();
  const mw = m.offsetWidth, mh = m.offsetHeight;
  let left = align === 'right' ? r.right - mw : r.left;
  left = Math.max(6, Math.min(left, window.innerWidth - mw - 6));
  let top = r.bottom + 4;
  if (top + mh > window.innerHeight - 6) top = Math.max(6, r.top - mh - 4);
  m.style.left = left + 'px'; m.style.top = top + 'px';
  openMenu = m;
  const first = m.querySelector('.menu-item:not([disabled])'); if (first) first.focus();
  m.addEventListener('keydown', (e) => {
    const items = [...m.querySelectorAll('.menu-item:not([disabled])')];
    const i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { items[(i + 1) % items.length].focus(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { items[(i - 1 + items.length) % items.length].focus(); e.preventDefault(); }
    else if (e.key === 'Escape') { closeMenu(); anchor.focus && anchor.focus(); e.stopPropagation(); }
  });
  return m;
}
document.addEventListener('mousedown', (e) => { if (openMenu && !openMenu.contains(e.target)) closeMenu(); });
window.addEventListener('resize', closeMenu);
window.addEventListener('blur', closeMenu);

// ---------- formatting ----------
export function toDate(v) {
  if (v === null || v === undefined || v === '') return null;
  if (v instanceof Date) return v;
  if (typeof v === 'number') return new Date(v < 1e12 ? v * 1000 : v);
  const d = new Date(v);
  return isNaN(d) ? null : d;
}
export function relTime(v) {
  const d = toDate(v); if (!d) return '';
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  const a = Math.abs(s);
  const fut = s < 0;
  let out;
  if (a < 45) out = 'just now';
  else if (a < 3600) out = Math.round(a / 60) + 'm';
  else if (a < 86400) out = Math.round(a / 3600) + 'h';
  else if (a < 86400 * 7) out = Math.round(a / 86400) + 'd';
  else return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: d.getFullYear() !== new Date().getFullYear() ? 'numeric' : undefined });
  if (out === 'just now') return out;
  return fut ? 'in ' + out : out + ' ago';
}
export function fmtDateTime(v) { const d = toDate(v); return d ? d.toLocaleString() : ''; }
export function elapsed(v) {
  const d = toDate(v); if (!d) return '';
  let s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  const hh = Math.floor(s / 3600); s -= hh * 3600; const mm = Math.floor(s / 60); s -= mm * 60;
  return hh ? `${hh}h ${mm}m` : mm ? `${mm}m ${s}s` : `${s}s`;
}
export function fmtNum(n) {
  if (n === null || n === undefined || isNaN(n)) return '–';
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k';
  return String(n);
}
export function fmtCost(c, currency = 'USD') {
  if (c === null || c === undefined || isNaN(c)) return '';
  const sym = currency === 'USD' ? '$' : currency + ' ';
  if (c === 0) return sym + '0.00';
  if (c < 0.01) return sym + c.toFixed(4);
  return sym + c.toFixed(2);
}
export function fmtBytes(b) {
  if (b === null || b === undefined) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let n = b;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}
export function shortPath(p, max = 42) {
  if (!p) return '';
  if (p.length <= max) return p;
  const parts = p.split(/[\\/]+/);
  let out = parts[parts.length - 1];
  for (let i = parts.length - 2; i >= 0; i--) {
    const cand = parts[i] + '/' + out;
    if (cand.length + 2 > max) break;
    out = cand;
  }
  return '…/' + out;
}
export function baseName(p) { const n = String(p || '').replace(/[\\/]+$/, ''); const parts = n.split(/[\\/]+/); return parts[parts.length - 1] || n; }

export function debounce(fn, ms = 250) {
  let t; const d = (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  d.cancel = () => clearTimeout(t); d.flush = (...a) => { clearTimeout(t); fn(...a); };
  return d;
}
export function throttleRaf(fn) {
  let queued = false;
  return () => { if (queued) return; queued = true; requestAnimationFrame(() => { queued = false; fn(); }); };
}

export async function copyText(text, label = 'Copied') {
  try {
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
    else {
      const ta = h('textarea', { style: { position: 'fixed', opacity: '0' } }); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    toast(label, { kind: 'success', timeout: 1500 });
  } catch (e) { toastError(e, 'Copy failed'); }
}
export function copyBtn(getText, title = 'Copy') {
  return iconBtn('copy', title, async (e) => {
    e.stopPropagation();
    await copyText(typeof getText === 'function' ? getText() : getText);
  }, { size: 'sm' });
}
export function downloadBlob(data, filename, mime = 'text/plain') {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime + ';charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename, style: { display: 'none' } });
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}
export function pickFile({ accept = '', multiple = false } = {}) {
  return new Promise((resolve) => {
    const inp = h('input', { type: 'file', accept, multiple, style: { display: 'none' } });
    inp.addEventListener('change', () => { resolve([...inp.files]); inp.remove(); });
    document.body.appendChild(inp); inp.click();
  });
}
export function readFileText(file) { return file.text(); }
export function readFileBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => { const s = String(r.result); resolve(s.slice(s.indexOf(',') + 1)); };
    r.onerror = reject; r.readAsDataURL(file);
  });
}
export function prettyJson(v) { try { return JSON.stringify(v, null, 2); } catch { return String(v); } }
export function autosize(ta, max = 320) {
  const fit = () => { ta.style.height = 'auto'; ta.style.height = Math.min(max, ta.scrollHeight + 2) + 'px'; };
  ta.addEventListener('input', fit); requestAnimationFrame(fit); return fit;
}
export function slug(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60); }
export function card(...children) { return h('div', { class: 'card' }, ...children); }
export function section(title, actions, ...children) {
  return h('section', { class: 'sect' }, h('div', { class: 'sect-head' }, h('h3', null, title), actions ? h('div', { class: 'sect-actions' }, actions) : null), ...children);
}
export function pageHeader(title, subtitle, actions) {
  return h('header', { class: 'page-head' }, h('div', { class: 'page-titles' }, h('h1', null, title), subtitle ? h('div', { class: 'page-sub' }, subtitle) : null), actions ? h('div', { class: 'page-actions' }, actions) : null);
}
export function banner(kind, text, ...extra) { return h('div', { class: 'banner banner-' + kind }, icon(kind === 'error' ? 'alert' : kind === 'warn' ? 'alert' : 'info', 16), h('div', { class: 'banner-text' }, text, ...extra)); }

export function table(columns, rows, { empty: emptyText = 'Nothing here yet', rowClass } = {}) {
  const t = h('table', { class: 'tbl' },
    h('thead', null, h('tr', null, columns.map((c) => h('th', { style: c.width ? { width: c.width } : null, class: c.class }, c.label)))),
    h('tbody', null, rows.length ? rows.map((r) => h('tr', { class: rowClass ? rowClass(r) : null }, columns.map((c) => h('td', { class: c.class }, c.render ? c.render(r) : String(r[c.key] ?? '')))))
      : h('tr', null, h('td', { colspan: columns.length, class: 'tbl-empty' }, emptyText))));
  return h('div', { class: 'tbl-wrap' }, t);
}

export function busy(button, promiseFn) {
  return async (...args) => {
    if (button.disabled) return;
    const prev = button.disabled; button.disabled = true; button.classList.add('is-busy');
    try { return await promiseFn(...args); } finally { button.disabled = prev; button.classList.remove('is-busy'); }
  };
}
// action button: runs async fn with busy state + toast on error
export function actionBtn(label, fn, opts = {}) {
  const b = btn(label, null, opts);
  b.addEventListener('click', async (e) => {
    if (b.disabled) return;
    b.disabled = true; b.classList.add('is-busy');
    try { await fn(e); if (opts.success) toast(opts.success, { kind: 'success', timeout: 2000 }); }
    catch (err) { toastError(err, opts.errorPrefix || ''); }
    finally { b.disabled = !!opts.disabled; b.classList.remove('is-busy'); }
  });
  return b;
}
