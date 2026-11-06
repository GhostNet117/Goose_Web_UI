// Composer: autosizing input with slash commands, @mentions, attachments, send/stop/steer.
import { h, btn, iconBtn, autosize, toast, toastError, readFileBase64, pickFile, fmtBytes, kbd } from './ui.js';
import { icon } from './icons.js';
import { upload } from './api.js';
import { rpc, G } from './rpc.js';
import { prefs } from './prefs.js';

const IMAGE_MAX = 8 * 1024 * 1024;

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
  setQueue(queue, { onRemove, onSteer }) {
    this.queueRow.hidden = !queue.length;
    this.queueRow.replaceChildren(...queue.map((blocks, i) => {
      const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join(' ') || '[attachment]';
      return h('div', { class: 'queued' }, icon('queue', 13), h('span', { class: 'queued-text' }, text),
        onSteer ? btn('Send now', () => onSteer(i), { size: 'sm', variant: 'ghost', icon: 'steer' }) : null,
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
    for (const f of files) {
      const att = { name: f.name, size: f.size, mime: f.type, status: 'loading' };
      this.attachments.push(att);
      this.renderAtts();
      try {
        if (f.type.startsWith('image/') && f.size <= IMAGE_MAX) {
          att.block = { type: 'image', data: await readFileBase64(f), mimeType: f.type };
          att.preview = URL.createObjectURL(f);
        } else {
          const cwd = this.o.getCwd && this.o.getCwd();
          if (!cwd) throw new Error('Choose a working folder first');
          const dir = joinPath(cwd, '.goose-web-uploads');
          const res = await upload(dir, [f]);
          const up = (res.files || [])[0];
          if (!up) throw new Error('Upload returned no file');
          att.block = { type: 'resource_link', uri: fileUri(up.path), name: up.name || f.name, mimeType: up.mime || f.type || undefined, size: up.size ?? f.size };
          att.path = up.path;
        }
        att.status = 'ready';
      } catch (e) {
        att.status = 'error'; toastError(e, 'Attach ' + f.name);
        this.attachments = this.attachments.filter((x) => x !== att);
      }
      this.renderAtts();
    }
  }
  renderAtts() {
    this.attRow.hidden = !this.attachments.length;
    this.attRow.replaceChildren(...this.attachments.map((a) => h('div', { class: ['att', 'att-' + a.status], title: a.path || a.name },
      a.preview ? h('img', { src: a.preview, alt: '' }) : icon(a.status === 'loading' ? 'upload' : 'file', 14),
      h('span', { class: 'att-name' }, a.name), h('span', { class: 'att-size' }, fmtBytes(a.size)),
      a.status === 'loading' ? h('span', { class: 'spinner', style: { width: '11px', height: '11px' } }) : null,
      iconBtn('x', 'Remove', () => { this.attachments = this.attachments.filter((x) => x !== a); if (a.preview) URL.revokeObjectURL(a.preview); this.renderAtts(); }, { size: 'sm' }))));
  }

  buildBlocks() {
    const text = this.ta.value.replace(/\s+$/, '');
    const blocks = [];
    if (text.trim()) blocks.push({ type: 'text', text });
    for (const a of this.attachments) if (a.block) blocks.push(a.block);
    return blocks;
  }

  submit(steer = false) {
    if (this.attachments.some((a) => a.status === 'loading')) { toast('Waiting for uploads to finish…'); return; }
    const blocks = this.buildBlocks();
    if (!blocks.length) return;
    if (this.o.validate && !this.o.validate(blocks)) return;
    this.ta.value = ''; this.fit(); this.o.onInput && this.o.onInput('');
    for (const a of this.attachments) if (a.preview) setTimeout(() => URL.revokeObjectURL(a.preview), 60000);
    this.attachments = []; this.renderAtts();
    this.hideMenu();
    if (steer && this.o.onSteer) this.o.onSteer(blocks); else this.o.onSend(blocks);
  }
}
