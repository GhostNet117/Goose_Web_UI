// Composer: autosizing input with slash commands, @mentions, attachments, send/stop/steer.
import { h, btn, iconBtn, autosize, toast, toastError, pickFile, fmtBytes, kbd, baseName } from './ui.js';
import { icon } from './icons.js';
import { uploadFile, uploadLimits } from './uploader.js';
import { GET, qs } from './api.js';
import { rpc, G } from './rpc.js';
import { prefs } from './prefs.js';
import { prepareInline, planInline, NOTES } from './images.js';

// Spec 039: files go up in resumable pieces (uploader.js uploadFile, 2 at a time) with progress and cancel; images are
// also shown to the model as a smaller copy (images.js), within a per-message budget. At most MAX_FILES at once.
const MAX_FILES = 20;
const cancelled = (e) => !!e && (e.name === 'AbortError' || e.code === 'cancelled');
function progressText(a) {
  if (!a.id && !a.sent) return 'waiting…';
  const pct = a.size ? Math.floor((a.sent || 0) * 100 / a.size) : 100;
  return pct + '% · ' + fmtBytes(a.sent || 0) + ' of ' + fmtBytes(a.size);
}

export function fileUri(p) {
  let s = String(p).replace(/\\/g, '/');
  if (/^\/\/\?\//.test(s)) s = s.slice(4);
  if (/^[A-Za-z]:\//.test(s)) return 'file:///' + encodeURI(s).replace(/#/g, '%23').replace(/\?/g, '%3F');
  return 'file://' + encodeURI(s).replace(/#/g, '%23').replace(/\?/g, '%3F');
}
export function joinPath(dir, name) {
  const sep = dir.includes('\\') ? '\\' : '/';
  return dir.replace(/[\\/]+$/, '') + sep + name;
}

export class Composer {
  // opts: { placeholder, getCwd(), getSessionId(), getCommands(), onSend(blocks), onStop(), onSteer(blocks), isRunning(), leading:[nodes], trailing:[nodes] }
  constructor(opts) {
    this.o = opts;
    this.attachments = [];
    this.menuItems = [];
    this.menuIndex = 0;
    this.menuMode = null;
    this.ta = h('textarea', { class: 'composer-input', rows: 1, placeholder: opts.placeholder || 'Message Goose…', 'aria-label': 'Message', spellcheck: 'true' });
    this.fit = autosize(this.ta, 360);
    this.attRow = h('div', { class: 'composer-atts', hidden: true });
    this.menu = h('div', { class: 'composer-menu', role: 'listbox', hidden: true });
    this.sendBtn = btn(null, () => this.submit(), { icon: 'send', variant: 'primary', title: 'Send (Enter)', class: 'send-btn' });
    this.stopBtn = btn(null, () => this.o.onStop && this.o.onStop(), { icon: 'stop', variant: 'danger', title: 'Stop (Ctrl+.)', class: 'stop-btn' });
    this.steerBtn = btn('Steer', () => this.submit(true), { icon: 'steer', size: 'sm', title: 'Send now to the running agent (Ctrl+Enter)', class: 'steer-btn' });
    this.attachBtn = iconBtn('clip', 'Attach files or images', () => this.pick());
    this.queueRow = h('div', { class: 'composer-queue', hidden: true });
    this.progress = h('div', { class: 'composer-progress', hidden: true });
    this.el = h('div', { class: 'composer' },
      this.progress,
      this.queueRow,
      h('div', { class: 'composer-box' },
        this.menu,
        this.attRow,
        this.ta,
        h('div', { class: 'composer-bar' },
          h('div', { class: 'composer-left' }, this.attachBtn, ...(opts.leading || [])),
          h('div', { class: 'composer-right' }, ...(opts.trailing || []), h('span', { class: 'composer-hint' }, kbd(prefs().enterToSend !== false ? '↵' : 'Ctrl ↵'), ' send'), this.steerBtn, this.stopBtn, this.sendBtn))));
    this.bind();
    this.setRunning(false);
    uploadLimits().then((l) => { this.attachBtn.title = 'Attach files or images (up to ' + fmtBytes(l.maxBytes) + ' each)'; }).catch(() => {});
  }

  bind() {
    const ta = this.ta;
    ta.addEventListener('keydown', (e) => this.onKey(e));
    ta.addEventListener('input', () => { this.updateMenu(); this.o.onInput && this.o.onInput(ta.value); });
    ta.addEventListener('click', () => this.updateMenu());
    ta.addEventListener('blur', () => setTimeout(() => this.hideMenu(), 150));
    ta.addEventListener('paste', (e) => {
      const files = [...(e.clipboardData ? e.clipboardData.files : [])];
      if (files.length) { e.preventDefault(); this.addFiles(files); }
    });
    const box = this.el;
    box.addEventListener('dragover', (e) => { if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) { e.preventDefault(); box.classList.add('drag'); } });
    box.addEventListener('dragleave', () => box.classList.remove('drag'));
    box.addEventListener('drop', (e) => { box.classList.remove('drag'); if (e.dataTransfer && e.dataTransfer.files.length) { e.preventDefault(); this.addFiles([...e.dataTransfer.files]); } });
  }

  focus() { this.ta.focus(); }
  get value() { return this.ta.value; }
  set value(v) { this.ta.value = v || ''; this.fit(); }

  setRunning(running) {
    this.running = running;
    this.el.classList.toggle('is-running', !!running);
    this.stopBtn.hidden = !running;
    this.steerBtn.hidden = !running || !this.o.onSteer;
    this.sendBtn.title = running ? 'Queue message (Enter) — sent when the current run finishes' : 'Send (Enter)';
    this.sendBtn.replaceChildren(icon(running ? 'queue' : 'send', 15));
  }
  setProgress(text) { this.progress.hidden = !text; this.progress.replaceChildren(text ? h('span', { class: 'spinner', style: { width: '11px', height: '11px' } }) : '', text ? h('span', null, text) : ''); }
  // queue: [{blocks, held?, steer?, note?}] (spec 019: kept by the gateway). A held item is a steer the agent never
  // read (the run ended first): it is not sent automatically; the user sends it, edits it or removes it.
  // The gateway sends rows (preview, size, author), not the messages (security review 2026-11-11, SC-2); a row
  // someone else queued (an administrator in your chat, or yours seen by an administrator) is never sent by itself.
  setQueue(queue, { onRemove, onSteer, onSend, onEdit, me = '', foreignOnly = false }) {
    this.queueRow.hidden = !queue.length;
    this.queueRow.replaceChildren(...queue.map((q, i) => {
      const blocks = Array.isArray(q) ? q : (q.blocks || null);
      const text = blocks ? (blocks.filter((b) => b.type === 'text').map((b) => b.text).join(' ') || '[attachment]')
        : ((q.preview || '') + (q.attachments ? ' [+' + q.attachments + ' attachment' + (q.attachments > 1 ? 's' : '') + ']' : '') || '[attachment]');
      const foreign = !q.local && (foreignOnly || (!!q.by && !!me && q.by.toLowerCase() !== me.toLowerCase()));
      const held = !!q.held || foreign;
      const tag = q.held ? (q.tag || (q.steer ? 'Steer not delivered' : 'Not sent yet')) : foreign ? 'Queued by ' + (q.by || 'someone else') : null;
      return h('div', { class: ['queued', held ? 'held' : ''], title: q.held ? (q.note || '') : foreign ? 'Not sent automatically: send it, edit it or remove it' : 'Sent when the current run finishes' },
        icon(held ? 'alert' : 'queue', 13), tag ? h('span', { class: 'queued-tag' }, tag) : null,
        h('span', { class: 'queued-text' }, text),
        held && onSend ? btn(onSteer ? 'Steer now' : 'Send', () => onSend(i), { size: 'sm', variant: 'ghost', icon: onSteer ? 'steer' : 'send' }) : null,
        !held && onSteer ? btn('Send now', () => onSteer(i), { size: 'sm', variant: 'ghost', icon: 'steer' }) : null,
        onEdit ? iconBtn('edit', 'Edit in the message box', () => onEdit(i), { size: 'sm' }) : null,
        iconBtn('x', 'Remove from queue', () => onRemove(i), { size: 'sm' }));
    }));
  }

  onKey(e) {
    if (!this.menu.hidden && this.menuItems.length) {
      if (e.key === 'ArrowDown') { this.menuIndex = (this.menuIndex + 1) % this.menuItems.length; this.renderMenu(); e.preventDefault(); return; }
      if (e.key === 'ArrowUp') { this.menuIndex = (this.menuIndex - 1 + this.menuItems.length) % this.menuItems.length; this.renderMenu(); e.preventDefault(); return; }
      if (e.key === 'Enter' || e.key === 'Tab') { this.pickMenu(this.menuIndex); e.preventDefault(); return; }
      if (e.key === 'Escape') { this.hideMenu(); e.preventDefault(); e.stopPropagation(); return; }
    }
    const enterSends = prefs().enterToSend !== false;
    if (e.key === 'Enter' && !e.isComposing) {
      if ((e.ctrlKey || e.metaKey) && this.running && this.o.onSteer) { e.preventDefault(); this.submit(true); return; }
      if (enterSends ? (!e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey) : (e.ctrlKey || e.metaKey)) { e.preventDefault(); this.submit(); return; }
    }
    if (e.key === 'Escape' && this.ta.value === '' && this.running) { /* no-op: avoid accidental stops */ }
  }

  // ----- slash / mention menu -----
  tokenAtCursor() {
    const v = this.ta.value, pos = this.ta.selectionStart;
    const before = v.slice(0, pos);
    const slash = /^\/([\w:.-]*)$/.exec(before);
    if (slash) return { mode: 'slash', q: slash[1], start: 0, end: pos };
    const at = /(^|\s)@([\w./-]*)$/.exec(before);
    if (at) return { mode: 'mention', q: at[2], start: pos - at[2].length - 1, end: pos };
    return null;
  }
  async updateMenu() {
    const tok = this.tokenAtCursor();
    if (!tok) { this.hideMenu(); return; }
    this.menuTok = tok;
    let items = [];
    if (tok.mode === 'slash') {
      let cmds = (this.o.getCommands && this.o.getCommands()) || [];
      if (!cmds.length) cmds = await this.fetchCommands();
      items = cmds.filter((c) => c.name.toLowerCase().includes(tok.q.toLowerCase())).slice(0, 30).map((c) => ({ label: '/' + c.name, desc: c.description, tag: c._meta && c._meta.commandType, insert: '/' + c.name + ' ' }));
    } else {
      const ag = await this.fetchMentions();
      items = ag.filter((a) => (a.name + ' ' + (a.mention || '')).toLowerCase().includes(tok.q.toLowerCase())).slice(0, 30).map((a) => ({ label: a.mention || '@' + a.name, desc: a.description, tag: a.sourceType, insert: (a.mention || '@' + a.name) + ' ' }));
    }
    const cur = this.tokenAtCursor();
    if (!cur || cur.mode !== tok.mode || cur.q !== tok.q) return;
    this.menuItems = items;
    this.menuIndex = 0;
    this.menuMode = tok.mode;
    if (!items.length) { this.hideMenu(); return; }
    this.renderMenu();
  }
  async fetchCommands() {
    if (this._cmdCache && Date.now() - this._cmdCache.t < 60000) return this._cmdCache.v;
    try {
      const r = await rpc.call(G('slash-commands/list'), { cwd: this.o.getCwd ? this.o.getCwd() || null : null, sessionId: this.o.getSessionId ? this.o.getSessionId() || null : null });
      this._cmdCache = { t: Date.now(), v: r.availableCommands || [] };
      return this._cmdCache.v;
    } catch { return []; }
  }
  async fetchMentions() {
    if (this._menCache && Date.now() - this._menCache.t < 60000) return this._menCache.v;
    try {
      const r = await rpc.call(G('agent-mentions/list'), { cwd: this.o.getCwd ? this.o.getCwd() || null : null, sessionId: this.o.getSessionId ? this.o.getSessionId() || null : null });
      this._menCache = { t: Date.now(), v: r.agents || [] };
      return this._menCache.v;
    } catch { return []; }
  }
  renderMenu() {
    this.menu.hidden = false;
    this.menu.replaceChildren(h('div', { class: 'cmenu-head' }, this.menuMode === 'slash' ? 'Commands' : 'Mention'),
      ...this.menuItems.map((it, i) => h('div', {
        class: ['cmenu-item', i === this.menuIndex ? 'active' : ''], role: 'option', 'aria-selected': i === this.menuIndex ? 'true' : 'false',
        onmousedown: (e) => { e.preventDefault(); this.pickMenu(i); },
      }, h('span', { class: 'cmenu-label' }, it.label), it.tag ? h('span', { class: 'badge' }, it.tag) : null, h('span', { class: 'cmenu-desc' }, it.desc || ''))));
    const a = this.menu.querySelector('.active'); if (a) a.scrollIntoView({ block: 'nearest' });
  }
  pickMenu(i) {
    const it = this.menuItems[i]; const tok = this.menuTok;
    if (!it || !tok) return;
    const v = this.ta.value;
    this.ta.value = v.slice(0, tok.start) + it.insert + v.slice(tok.end);
    const pos = tok.start + it.insert.length;
    this.ta.setSelectionRange(pos, pos);
    this.hideMenu(); this.fit(); this.ta.focus();
  }
  hideMenu() { this.menu.hidden = true; this.menuItems = []; }

  // ----- attachments -----
  async pick() { const files = await pickFile({ multiple: true }); if (files.length) this.addFiles(files); }
  async addFiles(files) {
    // Spec 031: every attached file is written to <chat folder>\Web_Uploads - the server names that folder and
    // refuses when this person may not write there (a read-only folder): then nothing is attached.
    const cwd = this.o.getCwd && this.o.getCwd();
    if (!cwd) { toastError(new Error('Choose a working folder first'), 'Attach'); return; }
    const room = MAX_FILES - this.attachments.length;
    if (room < files.length) toast('At most ' + MAX_FILES + ' files at once' + (room > 0 ? ': ' + (files.length - room) + ' not added' : ''), { kind: 'warn' });
    if (room <= 0) return;
    let limits = null;
    try { limits = await uploadLimits(); } catch { /* the server refuses at the start with the limit in its message */ }
    await Promise.all(files.slice(0, room).map((f) => this.addFile(f, cwd, limits)));
  }
  async addFile(f, cwd, limits) {
    if (limits && f.size > limits.maxBytes) { toastError(new Error(f.name + ' (' + fmtBytes(f.size) + ') is larger than the upload limit of ' + fmtBytes(limits.maxBytes)), 'Attach'); return; }
    const att = { name: f.name, size: f.size, mime: f.type, status: 'loading', sent: 0, id: null, controller: new AbortController(), inline: null, note: '' };
    this.attachments.push(att);
    this.renderAtts();
    // the copy the model sees is made while the original goes up unchanged (images.js)
    const inline = (f.type || '').startsWith('image/') ? prepareInline(f).catch(() => ({ skip: 'undecodable' })) : null;
    try {
      const up = await uploadFile(cwd, f, {
        session: (this.o.getSessionId && this.o.getSessionId()) || null,   // spec 040: the chat the file belongs to
        profile: rpc.profileParam || null,
        signal: att.controller.signal,
        onStart: (id) => { att.id = id; this.renderProgress(att); },
        onProgress: (sent) => { att.sent = sent; this.renderProgress(att); },
      });
      att.id = up.id || att.id;
      att.path = up.path;
      // the link says where the file is, for the agent's tools; an image also goes inline (buildBlocks, budget)
      att.link = { type: 'resource_link', uri: fileUri(up.path), name: up.name || f.name, mimeType: up.mime || f.type || undefined, size: up.size ?? f.size };
      if (inline) {
        const r = await inline;
        if (r && r.data) { att.inline = { data: r.data, mimeType: r.mimeType, bytes: r.bytes }; att.preview = URL.createObjectURL(f); }
        else att.note = NOTES[(r && r.skip) || 'undecodable'] || NOTES.undecodable;
      }
      att.status = 'ready';
    } catch (e) {
      if (!cancelled(e)) toastError(e, 'Attach ' + f.name);
      this.attachments = this.attachments.filter((x) => x !== att);
    }
    this.renderAtts();
  }
  // Spec 041: a file that already lies where the agent can read it (Files page: "Ask Goose about this", "Add to a
  // chat"): a chip with its link (resource_link), nothing is uploaded and nothing is linked to the chat (spec 040).
  attachPath(path, info = {}) {
    if (!path || this.attachments.some((a) => a.path === path)) return null;
    if (this.attachments.length >= MAX_FILES) { toast('At most ' + MAX_FILES + ' files at once', { kind: 'warn' }); return null; }
    const name = info.name || baseName(path);
    const att = { name, size: info.size ?? null, mime: '', status: 'ready', sent: 0, id: null, controller: null, inline: null, note: '', path, existing: true };
    att.link = { type: 'resource_link', uri: fileUri(path), name };
    if (att.size !== null) att.link.size = att.size;
    this.attachments.push(att);
    this.renderAtts();
    return att;
  }
  // The chip at once, then the file's details from the server (GET /api/files/info): the size, or the chip goes
  // again when this person may not read the file (or it is a folder, or gone).
  async attachExisting(path) {
    const att = this.attachPath(path);
    if (!att) return;
    try {
      const i = await GET('/api/files/info' + qs({ path }));
      if (i.dir) throw new Error('Only a file can be attached, not a folder');
      if (!this.attachments.includes(att)) return;
      att.name = i.name || att.name; att.size = i.size ?? null;
      att.link.name = att.name;
      if (att.size !== null) att.link.size = att.size;
      this.renderAtts();
    } catch (e) {
      toastError(e, 'Attach ' + att.name);
      this.removeAtt(att);
    }
  }
  removeAtt(a) {
    if (a.status === 'loading' && a.controller) a.controller.abort();   // stops the upload; the server deletes what it had
    this.attachments = this.attachments.filter((x) => x !== a);
    if (a.preview) URL.revokeObjectURL(a.preview);
    this.renderAtts();
  }
  renderProgress(a) {
    const pct = a.size ? Math.floor((a.sent || 0) * 100 / a.size) : 100;
    if (a.barEl) a.barEl.style.width = pct + '%';
    if (a.pctEl) a.pctEl.textContent = progressText(a);
  }
  renderAtts() {
    const plan = planInline(this.attachments);
    this.attRow.hidden = !this.attachments.length;
    this.attRow.replaceChildren(...this.attachments.map((a, i) => {
      const note = a.inline && !plan[i] ? NOTES.budget : a.note;
      const loading = a.status === 'loading';
      a.barEl = loading ? h('span', { class: 'att-bar', style: { width: (a.size ? Math.floor((a.sent || 0) * 100 / a.size) : 0) + '%' } }) : null;
      a.pctEl = loading ? h('span', { class: 'att-size att-pct' }, progressText(a)) : null;
      return h('div', { class: ['att', 'att-' + a.status, note ? 'att-link-only' : ''], title: (a.path || a.name) + (note ? '\n' + note : '') },
        a.preview ? h('img', { src: a.preview, alt: '' }) : icon(loading ? 'upload' : 'file', 14),
        h('span', { class: 'att-name' }, a.name), loading ? a.pctEl : h('span', { class: 'att-size' }, fmtBytes(a.size)),
        note ? h('span', { class: 'att-note', title: note }, 'link only') : null,
        loading ? h('span', { class: 'att-progress', role: 'progressbar', 'aria-label': 'Upload progress' }, a.barEl) : null,
        iconBtn('x', loading ? 'Cancel upload' : 'Remove', () => this.removeAtt(a), { size: 'sm' }));
    }));
  }

  buildBlocks() {
    const text = this.ta.value.replace(/\s+$/, '');
    const blocks = [];
    if (text.trim()) blocks.push({ type: 'text', text });
    // text, then per file: [image (the smaller copy, within the per-message budget)], resource_link
    const plan = planInline(this.attachments);
    this.attachments.forEach((a, i) => {
      if (a.status !== 'ready' || !a.link) return;
      if (a.inline && plan[i]) blocks.push({ type: 'image', data: a.inline.data, mimeType: a.inline.mimeType });
      blocks.push(a.link);
    });
    return blocks;
  }

  submit(steer = false) {
    if (this.attachments.some((a) => a.status === 'loading')) { toast('Waiting for uploads to finish…'); return; }
    const blocks = this.buildBlocks();
    if (!blocks.length) return;
    if (this.o.validate && !this.o.validate(blocks)) return;
    const uploads = this.attachments.map((a) => a.id).filter(Boolean);   // spec 040: New chat links them to the chat
    this.ta.value = ''; this.fit(); this.o.onInput && this.o.onInput('');
    for (const a of this.attachments) if (a.preview) setTimeout(() => URL.revokeObjectURL(a.preview), 60000);
    this.attachments = []; this.renderAtts();
    this.hideMenu();
    if (steer && this.o.onSteer) this.o.onSteer(blocks, { uploads }); else this.o.onSend(blocks, { uploads });
  }
}
