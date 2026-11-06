// Transcript: incremental, windowed rendering of a session's update stream.
// Items are built lazily; only the last WINDOW items are attached to the DOM until "show earlier".
import { h, prettyJson, copyBtn, iconBtn, toDate, fmtNum, fmtCost, btn } from './ui.js';
import { icon, logo } from './icons.js';
import { setMarkdown } from './markdown.js';
import { askCard } from './asks.js';
import { prefs, activityPrefs } from './prefs.js';

const WINDOW = 80;
const PAGE = 60;
const MAX_LIVE = 200000;

const KIND_ICON = { read: 'file', edit: 'edit', delete: 'trash', move: 'file', search: 'search', execute: 'terminal', think: 'brain', fetch: 'globe', switch_mode: 'sliders', other: 'tool' };

function timeOf(meta) {
  const c = meta && meta.goose && meta.goose.created;
  return c ? toDate(c) : null;
}

export class Transcript {
  constructor(chat) {
    this.chat = chat;
    this.root = h('div', { class: 'transcript', role: 'log', 'aria-live': 'polite', 'aria-relevant': 'additions' });
    this.moreBtn = h('div', { class: 'tr-more' }, btn('Show earlier messages', () => this.showEarlier(), { size: 'sm', icon: 'chevronUp' }));
    this.list = h('div', { class: 'tr-list' });
    // Live activity bar (Desktop's "goose is thinking / working on it" line): phase, tool count, elapsed time.
    this.activityBar = h('div', { class: 'tr-activity', role: 'status', title: 'Jump to the current step' });
    this.activityBar.addEventListener('click', () => {
      const t = this.turn && this.turn.target;
      if (t && t.el && t.el.isConnected) t.el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
    this.activityEl = h('div', { class: 'tr-item tr-agent-side tr-activity-wrap', hidden: true }, this.activityBar);
    this.turn = null;
    this.root.append(this.moreBtn, this.list, this.activityEl);
    this.clear();
  }

  // ---------- live activity (one "turn" = one run of the agent) ----------
  startTurn() {
    if (this.turn) return;
    this.turn = { start: Date.now(), tools: 0, phase: 'thinking', label: '', target: null, thoughts: new Set() };
    this.activityTimer = setInterval(() => this.renderActivity(), 1000);
    this.renderActivity();
  }
  endTurn() {
    const t = this.turn;
    if (!t) return;
    this.turn = null;
    clearInterval(this.activityTimer); this.activityTimer = 0;
    if (activityPrefs().thinking === 'auto') {
      for (const it of t.thoughts) if (!it.userToggled && it.details) it.details.open = false;
    }
    this.activityEl.hidden = true;
  }
  setPhase(phase, label = '', target = null) {
    const t = this.turn;
    if (!t || this.bulk) return;
    if (t.phase === phase && t.label === label && (!target || t.target === target)) return;
    t.phase = phase; t.label = label;
    if (target) t.target = target;
    this.renderActivity();
  }
  askResolved(id) {
    if (id) this.resolvedAsks.add(id);
    const t = this.turn;
    if (!t || t.phase !== 'waiting') return;
    // Another approval of this turn still open: show that one. Otherwise show what the tool is doing now.
    const next = [...this.asks.values()].find((a) => !this.resolvedAsks.has(a.ask.id) && a.time.getTime() >= t.start);
    if (next) { t.phase = ''; this.setPhase('waiting', next.askTitle, next); return; }
    const tool = t.target && t.target.kind === 'ask' ? t.target.tool : t.target;
    const st = tool && tool.data && tool.data.status;
    if (tool && st !== 'completed' && st !== 'failed') this.setPhase('tool', this.toolTitle(tool), tool);
    else this.setPhase('working', '', tool || null);
  }
  renderActivity() {
    const t = this.turn;
    if (!t || !activityPrefs().statusBar) { this.activityEl.hidden = true; return; }
    const text = t.phase === 'tool' ? 'Running ' + (t.label || 'a tool')
      : t.phase === 'waiting' ? 'Waiting for your approval: ' + (t.label || 'tool call')
        : t.phase === 'writing' ? 'Writing the reply\u2026'
          : t.phase === 'progress' ? t.label
            : t.phase === 'working' ? 'Working\u2026' : 'Thinking\u2026';
    const meta = [];
    if (t.tools) meta.push(t.tools + (t.tools === 1 ? ' tool call' : ' tool calls'));
    meta.push(fmtElapsed(Date.now() - t.start));
    this.activityEl.hidden = false;
    this.activityBar.dataset.phase = t.phase;
    this.activityBar.replaceChildren(
      t.phase === 'waiting' ? icon('alert', 13) : h('span', { class: 'spinner', style: { width: '12px', height: '12px' } }),
      h('span', { class: 'tr-act-label' }, text),
      h('span', { class: 'tr-act-meta' }, meta.join(' \u00b7 ')));
  }

  clear() {
    if (this.bridges) for (const b of this.bridges) b.destroy();
    this.bridges = new Set();
    this.items = [];
    this.byMsg = new Map();     // messageId -> agent text item
    this.thoughts = new Map();
    this.tools = new Map();     // toolCallId -> tool item
    this.users = new Map();
    this.asks = new Map();
    this.resolvedAsks = new Set();
    this.firstAttached = 0;
    this.lastPlan = null;
    this.list.replaceChildren();
    this.moreBtn.hidden = true;
    this.usage = new Map();
  }

  get length() { return this.items.length; }

  // ---------- item plumbing ----------
  push(item) {
    const prev = this.items[this.items.length - 1];
    item.agentSide = item.kind !== 'user' && item.kind !== 'sys';
    item.first = item.agentSide && (!prev || !prev.agentSide);
    this.items.push(item);
    if (prev && prev.kind === 'agent' && item.kind !== 'agent') this.finalizeItem(prev);
    if (this.items.length - this.firstAttached > WINDOW * 2) this.trimTop();
    this.attach(item);
    this.chat.emit('transcript:append', item);
    return item;
  }
  attach(item, before = null) {
    if (!item.el) item.el = this.build(item);
    if (before) this.list.insertBefore(item.el, before); else this.list.appendChild(item.el);
  }
  trimTop() {
    const target = this.items.length - WINDOW;
    for (let i = this.firstAttached; i < target; i++) { const it = this.items[i]; if (it.el && it.el.parentNode) it.el.remove(); }
    this.firstAttached = target;
    this.moreBtn.hidden = false;
  }
  showEarlier() {
    const start = Math.max(0, this.firstAttached - PAGE);
    const anchor = this.list.firstChild;
    const scroller = this.root.closest('.chat-scroll');
    const prevH = scroller ? scroller.scrollHeight : 0;
    for (let i = start; i < this.firstAttached; i++) { const it = this.items[i]; this.attach(it, anchor); if (it.kind === 'tool') this.renderTool(it); }
    this.firstAttached = start;
    this.moreBtn.hidden = start === 0;
    if (scroller) scroller.scrollTop += scroller.scrollHeight - prevH;
  }
  // replay: build window only at the end
  beginBulk() { this.bulk = true; }
  endBulk() {
    this.bulk = false;
    const start = Math.max(0, this.items.length - WINDOW);
    this.list.replaceChildren();
    for (let i = start; i < this.items.length; i++) {
      const it = this.items[i];
      if (it.kind === 'agent') it.final = true;
      if (it.el) it.el.remove();
      this.attach(it);
      if (it.kind === 'agent') this.renderAgent(it, true);
      // Tool cards may have been built before their final update arrived during replay (status, MCP App).
      else if (it.kind === 'tool') this.renderTool(it);
    }
    this.firstAttached = start;
    this.moreBtn.hidden = start === 0;
  }

  // ---------- builders ----------
  build(item) {
    switch (item.kind) {
      case 'user': return this.buildUser(item);
      case 'agent': return this.buildAgent(item);
      case 'thought': return this.buildThought(item);
      case 'tool': return this.buildTool(item);
      case 'plan': return this.buildPlan(item);
      case 'ask': return this.wrapAgent(item, askCard(item.ask));
      case 'sys': return h('div', { class: 'tr-sys tr-sys-' + (item.level || 'info') }, icon(item.level === 'error' ? 'alert' : 'info', 13), h('span', null, item.text));
      default: return h('div', null, '?');
    }
  }
  wrapAgent(item, inner) {
    const el = h('div', { class: ['tr-item', 'tr-agent-side', item.first ? 'tr-first' : ''] });
    if (item.first) {
      const t = item.time;
      el.appendChild(h('div', { class: 'tr-who' }, logo(20), h('span', { class: 'tr-name' }, 'Goose'), t ? h('span', { class: 'tr-time', title: t.toLocaleString() }, t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : null));
    }
    el.appendChild(inner);
    return el;
  }

  buildUser(item) {
    const body = h('div', { class: 'bubble' });
    item.body = body;
    this.renderUserBlocks(item);
    const t = item.time;
    const el = h('div', { class: ['tr-item', 'tr-user', item.steer ? 'is-steer' : '', item.pending ? 'is-pending' : ''] },
      h('div', { class: 'tr-user-meta' }, item.steer ? h('span', { class: 'badge badge-accent' }, 'steer') : null,
        prefs().showTimestamps && t ? h('span', { class: 'tr-time' }, t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : null),
      body,
      h('div', { class: 'tr-actions' }, copyBtn(() => item.blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n'))));
    return el;
  }
  renderUserBlocks(item) {
    const body = item.body; if (!body) return;
    body.replaceChildren();
    for (const b of item.blocks) {
      if (b.type === 'text') body.appendChild(h('div', { class: 'u-text' }, b.text));
      else if (b.type === 'image') body.appendChild(h('img', { class: 'u-img', src: b.uri && /^data:|^blob:/.test(b.uri) ? b.uri : 'data:' + (b.mimeType || 'image/png') + ';base64,' + b.data, alt: 'attached image' }));
      else if (b.type === 'resource_link') body.appendChild(h('div', { class: 'u-file' }, icon('file', 14), h('span', null, b.name || b.uri)));
      else if (b.type === 'resource') body.appendChild(h('div', { class: 'u-file' }, icon('file', 14), h('span', null, (b.resource && b.resource.uri) || 'resource')));
      else if (b.type === 'audio') body.appendChild(h('div', { class: 'u-file' }, icon('mic', 14), 'audio'));
    }
  }

  buildAgent(item) {
    item.md = h('div', { class: 'md' });
    item.foot = h('div', { class: 'tr-foot' });
    const inner = h('div', { class: 'agent-msg' }, item.md, h('div', { class: 'tr-actions' }, copyBtn(() => item.text, 'Copy message')), item.foot);
    const el = this.wrapAgent(item, inner);
    this.renderAgent(item, item.final);
    this.renderUsage(item);
    return el;
  }
  renderAgent(item, final) {
    if (!item.md) return;
    setMarkdown(item.md, item.text, { final: !!final });
    item.renderedLen = item.text.length;
  }
  scheduleAgent(item) {
    if (this.bulk || !item.el) return;
    if (item.raf) return;
    item.raf = requestAnimationFrame(() => {
      item.raf = 0;
      if (item.renderedLen === item.text.length && !item.dirtyFinal) return;
      this.renderAgent(item, item.final);
      this.chat.emit('transcript:grow');
    });
  }
  finalizeItem(item) {
    if (!item || item.kind !== 'agent' || item.final) return;
    item.final = true;
    if (item.raf) { cancelAnimationFrame(item.raf); item.raf = 0; }
    if (!this.bulk && item.el) this.renderAgent(item, true);
  }
  finalizeAll() {
    for (let i = Math.max(0, this.items.length - 10); i < this.items.length; i++) this.finalizeItem(this.items[i]);
  }
  renderUsage(item) {
    if (!item.foot) return;
    const u = this.usage.get(item.messageId);
    item.foot.replaceChildren();
    if (!u) return;
    const parts = [];
    if (u.outputTokens !== undefined && u.outputTokens !== null) parts.push(fmtNum(u.inputTokens) + ' in · ' + fmtNum(u.outputTokens) + ' out');
    if (u.cost) parts.push(fmtCost(u.cost));
    if (u.elapsedMs) parts.push((u.elapsedMs / 1000).toFixed(1) + 's');
    item.foot.textContent = parts.join(' · ');
  }

  buildThought(item) {
    item.pre = h('div', { class: 'thought-text md' });
    setMarkdown(item.pre, item.text, { final: true });
    const summary = h('summary', null, icon('brain', 14), h('span', null, 'Thinking'), h('span', { class: 'thought-len muted' }, item.text ? fmtNum(item.text.length) + ' chars' : ''));
    summary.addEventListener('click', () => { item.userToggled = true; });
    item.details = h('details', { class: 'thought' }, summary, item.pre);
    const mode = activityPrefs().thinking;
    item.details.open = mode === 'expanded' || (mode === 'auto' && !!item.live && !!this.turn);
    return this.wrapAgent(item, item.details);
  }

  buildTool(item) {
    const head = h('button', { type: 'button', class: 'tool-head', 'aria-expanded': 'false' });
    const body = h('div', { class: 'tool-body', hidden: true });
    const el = h('div', { class: 'tool' }, head, body);
    item.head = head; item.body = body; item.card = el;
    head.addEventListener('click', () => { item.userToggled = true; this.setToolOpen(item, body.hidden); });
    this.renderTool(item);
    const mode = activityPrefs().tools;
    const st = item.data.status;
    if (mode === 'detailed') this.setToolOpen(item, true);
    else if (mode === 'auto' && item.liveTurn && this.turn && st !== 'completed' && st !== 'failed') { this.setToolOpen(item, true); item.autoOpened = true; }
    return this.wrapAgent(item, el);
  }
  setToolOpen(item, open) {
    item.open = open;
    item.body.hidden = !open;
    item.head.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) this.renderToolBody(item);
  }
  renderTool(item) {
    if (!item.head) return;
    const tc = item.data;
    const st = tc.status || (tc.content || tc.rawOutput ? 'completed' : 'pending');
    item.card.dataset.status = st;
    const ext = tc._meta && tc._meta.goose && tc._meta.goose.toolCall ? tc._meta.goose.toolCall.extensionName : item.ext;
    if (ext) item.ext = ext;
    const statusEl = st === 'completed' ? icon('check', 14, 'ok') : st === 'failed' ? icon('x', 14, 'err') : h('span', { class: 'spinner', style: { width: '12px', height: '12px' } });
    const exit = tc.rawOutput && typeof tc.rawOutput === 'object' && tc.rawOutput.exit_code !== undefined && tc.rawOutput.exit_code !== 0 ? h('span', { class: 'badge badge-err' }, 'exit ' + tc.rawOutput.exit_code) : null;
    item.head.replaceChildren(
      h('span', { class: 'tool-status' }, statusEl),
      icon(KIND_ICON[tc.kind] || 'tool', 14),
      h('span', { class: 'tool-title' }, tc.title || (tc._meta && tc._meta.goose && tc._meta.goose.toolCall && tc._meta.goose.toolCall.toolName) || 'Tool call'),
      exit,
      item.ext ? h('span', { class: 'tool-ext' }, item.ext) : null,
      item.live && !item.open && st === 'in_progress' ? h('span', { class: 'tool-tail' }, lastLine(item.live)) : null,
      icon('chevronDown', 14, 'tool-chev'));
    if (item.open) this.renderToolBody(item);
    if (item.app && st === 'completed' && !item.appEl) this.mountApp(item);
  }
  // Inline MCP App (Desktop parity): sandboxed, opaque-origin frame served by the gateway from the
  // tool's ui:// resource, talking to the host through the same postMessage bridge as the Apps page.
  mountApp(item) {
    const a = item.app;
    const tc = item.data;
    item.appEl = h('div', { class: 'tool-app' });
    item.card.appendChild(item.appEl);
    if (a.readError) { item.appEl.appendChild(h('div', { class: 'muted small' }, icon('alert', 12), ' App UI unavailable: ' + a.readError)); return; }
    const sid = this.chat.id;
    const src = '/api/apps/frame?sessionId=' + encodeURIComponent(sid) + '&ext=' + encodeURIComponent(a.extensionName) + '&uri=' + encodeURIComponent(a.resourceUri);
    const iframe = h('iframe', { class: 'app-frame tool-app-frame', title: (a.toolName || 'App') + ' (' + a.extensionName + ')', sandbox: 'allow-scripts allow-forms allow-popups', src, referrerpolicy: 'no-referrer', loading: 'lazy' });
    item.appEl.appendChild(iframe);
    import('./views/apps.js').then(({ createAppBridge }) => {
      if (!item.appEl) return;
      const toolInput = tc.rawInput && typeof tc.rawInput === 'object' ? tc.rawInput : {};
      item.bridge = createAppBridge(iframe, {
        app: { name: a.toolName || a.extensionName, description: '' },
        extensionName: a.extensionName,
        ensureSession: () => Promise.resolve(sid),
        onMessage: (text) => { if (this.chat.send) this.chat.send([{ type: 'text', text }]); },
        toolInput, toolResult: appToolResult(tc),
      });
      this.bridges.add(item.bridge);
    }).catch((e) => console.warn('app bridge', e));
  }
  renderToolBody(item) {
    const tc = item.data;
    const b = item.body;
    b.replaceChildren();
    if (tc.rawInput !== undefined && tc.rawInput !== null && !(typeof tc.rawInput === 'object' && !Object.keys(tc.rawInput).length)) {
      const cmd = typeof tc.rawInput === 'object' && typeof tc.rawInput.command === 'string' ? tc.rawInput.command : null;
      b.appendChild(h('div', { class: 'tool-sec' }, h('div', { class: 'tool-sec-head' }, 'Input', copyBtn(() => cmd || prettyJson(tc.rawInput))),
        cmd && Object.keys(tc.rawInput).length === 1 ? h('pre', { class: 'term' }, '$ ' + cmd) : h('pre', { class: 'json' }, prettyJson(tc.rawInput))));
    }
    if (item.live) {
      item.livePre = h('pre', { class: 'term live' }, item.live);
      b.appendChild(h('div', { class: 'tool-sec' }, h('div', { class: 'tool-sec-head' }, 'Live output', item.liveTrunc ? h('span', { class: 'muted' }, ' (truncated)') : null), item.livePre));
      requestAnimationFrame(() => { if (item.livePre) item.livePre.scrollTop = item.livePre.scrollHeight; });
    } else item.livePre = null;
    const out = h('div', { class: 'tool-sec' });
    let has = false;
    const ro = tc.rawOutput;
    if (ro && typeof ro === 'object' && ('stdout' in ro || 'stderr' in ro)) {
      has = true;
      out.appendChild(h('div', { class: 'tool-sec-head' }, 'Output', ro.exit_code !== undefined ? h('span', { class: ro.exit_code === 0 ? 'badge badge-ok' : 'badge badge-err' }, 'exit ' + ro.exit_code) : null, copyBtn(() => (ro.stdout || '') + (ro.stderr || ''))));
      if (ro.stdout) out.appendChild(clip(h('pre', { class: 'term' }), ro.stdout));
      if (ro.stderr) out.appendChild(clip(h('pre', { class: 'term stderr' }), ro.stderr));
      if (!ro.stdout && !ro.stderr) out.appendChild(h('div', { class: 'muted small' }, '(no output)'));
    } else if (Array.isArray(tc.content) && tc.content.length) {
      has = true;
      out.appendChild(h('div', { class: 'tool-sec-head' }, 'Result'));
      for (const c of tc.content) out.appendChild(renderToolContent(c));
    } else if (ro !== undefined && ro !== null) {
      has = true;
      out.appendChild(h('div', { class: 'tool-sec-head' }, 'Result', copyBtn(() => typeof ro === 'string' ? ro : prettyJson(ro))));
      out.appendChild(clip(h('pre', { class: 'json' }), typeof ro === 'string' ? ro : prettyJson(ro)));
    }
    if (has) b.appendChild(out);
    if (Array.isArray(tc.locations) && tc.locations.length) b.appendChild(h('div', { class: 'tool-sec small muted' }, tc.locations.map((l) => h('div', null, icon('file', 12), ' ', l.path + (l.line ? ':' + l.line : '')))));
    if (!b.childNodes.length) b.appendChild(h('div', { class: 'muted small' }, 'No details yet.'));
  }

  buildPlan(item) {
    item.box = h('div', { class: 'plan' });
    this.renderPlan(item);
    return this.wrapAgent(item, item.box);
  }
  renderPlan(item) {
    if (!item.box) return;
    const entries = item.entries || [];
    const done = entries.filter((e) => e.status === 'completed').length;
    item.box.replaceChildren(h('div', { class: 'plan-head' }, icon('list', 14), h('span', null, 'Plan'), h('span', { class: 'muted' }, done + '/' + entries.length)),
      h('ol', { class: 'plan-list' }, entries.map((e) => h('li', { class: 'plan-' + (e.status || 'pending') }, h('span', { class: 'plan-mark' }, e.status === 'completed' ? icon('check', 12) : e.status === 'in_progress' ? h('span', { class: 'spinner', style: { width: '10px', height: '10px' } }) : ''), h('span', null, e.content), e.priority === 'high' ? h('span', { class: 'badge badge-warn' }, 'high') : null))));
  }

  // ---------- public API used by ChatSession ----------
  addUser(blocks, { messageId = null, time = null, steer = false, pending = false } = {}) {
    if (messageId && this.users.has(messageId)) {
      const it = this.users.get(messageId);
      it.blocks.push(...blocks);
      this.renderUserBlocks(it);
      return it;
    }
    // adopt a local echo
    if (messageId && !this.bulk) {
      for (let i = this.items.length - 1; i >= Math.max(0, this.items.length - 6); i--) {
        const it = this.items[i];
        if (it.kind === 'user' && it.local && !it.messageId) {
          it.messageId = messageId; it.local = false; it.pending = false; if (it.el) it.el.classList.remove('is-pending');
          this.users.set(messageId, it);
          return it;
        }
      }
    }
    const item = { kind: 'user', blocks: [...blocks], messageId, time: time || new Date(), steer, local: !messageId, pending };
    if (messageId) this.users.set(messageId, item);
    this.finalizeAll();
    this.lastPlan = null;
    return this.push(item);
  }
  markUserSent(item) { if (item) { item.pending = false; if (item.el) item.el.classList.remove('is-pending'); } }

  agentChunk(content, messageId, meta) {
    if (!content) return;
    if (content.type !== 'text') {
      return this.agentText('\n\n' + (content.type === 'image' ? '![image](data:' + content.mimeType + ';base64,' + content.data + ')' : '`[' + content.type + ']`') + '\n\n', messageId, meta);
    }
    return this.agentText(content.text || '', messageId, meta);
  }
  agentText(text, messageId, meta) {
    const last = this.items[this.items.length - 1];
    let item = null;
    if (last && last.kind === 'agent' && (!messageId || last.messageId === messageId)) item = last;
    if (!item) {
      item = { kind: 'agent', text: '', messageId, time: timeOf(meta) || new Date(), final: false };
      this.push(item);
      if (messageId) this.byMsg.set(messageId, item);
    }
    item.text += text;
    this.scheduleAgent(item);
    if (text.trim()) this.setPhase('writing', '', item);
    return item;
  }
  thoughtChunk(content, messageId, meta) {
    const text = content && content.text ? content.text : '';
    const last = this.items[this.items.length - 1];
    let item = last && last.kind === 'thought' && (!messageId || last.messageId === messageId) ? last : null;
    if (!item) {
      item = { kind: 'thought', text: '', messageId, time: timeOf(meta) || new Date(), live: !this.bulk && !!this.turn };
      if (item.live) this.turn.thoughts.add(item);
      this.push(item);
    }
    item.text += text;
    if (item.pre && !this.bulk) { setMarkdown(item.pre, item.text, { final: true }); const l = item.details.querySelector('.thought-len'); if (l) l.textContent = fmtNum(item.text.length) + ' chars'; this.chat.emit('transcript:grow'); }
    this.setPhase('thinking', '', item);
    return item;
  }
  toolCall(u) {
    let item = this.tools.get(u.toolCallId);
    // A finished tool call re-announced with the same id (e.g. id reuse by a provider) starts a new card.
    const st = item && item.data && item.data.status;
    if (item && (st === 'completed' || st === 'failed')) item = null;
    if (item) { item.data = { ...item.data, ...strip(u) }; takeApp(item, u); if (!this.bulk) { this.renderTool(item); this.toolPhase(item); } return item; }
    item = { kind: 'tool', data: strip(u), id: u.toolCallId, live: '', time: timeOf(u._meta) || new Date(), liveTurn: !this.bulk && !!this.turn };
    takeApp(item, u);
    this.tools.set(u.toolCallId, item);
    if (item.liveTurn) this.turn.tools++;
    this.push(item);
    this.toolPhase(item);
    return item;
  }
  toolTitle(item) {
    const tc = item.data || {};
    return tc.title || (tc._meta && tc._meta.goose && tc._meta.goose.toolCall && tc._meta.goose.toolCall.toolName) || 'a tool';
  }
  toolPhase(item) {
    const t = this.turn;
    if (!t || this.bulk || t.phase === 'waiting') return;   // askResolved() moves on from an approval
    const st = item.data.status;
    if (st === 'completed' || st === 'failed') { if (t.target === item) this.setPhase('working', '', item); }
    else this.setPhase('tool', this.toolTitle(item), item);
  }
  toolUpdate(u) {
    let item = this.tools.get(u.toolCallId);
    if (!item) item = this.toolCall({ toolCallId: u.toolCallId, title: u.title || 'Tool call', status: u.status });
    takeApp(item, u);
    const tn = u._meta && u._meta.toolNotification;
    if (tn && tn.type === 'live_output' && tn.params) {
      for (const ch of tn.params.chunks || []) item.live += ch.output || '';
      if (item.live.length > MAX_LIVE) { item.live = item.live.slice(-MAX_LIVE); item.liveTrunc = true; }
      if (tn.params.truncated) item.liveTrunc = true;
    }
    const patch = strip(u);
    delete patch._meta;
    item.data = { ...item.data, ...patch };
    if (this.bulk) return item;
    this.toolPhase(item);
    if (item.live && item.data.status === 'in_progress' && !item.userToggled && !item.open && item.el && activityPrefs().tools !== 'concise') { this.setToolOpen(item, true); item.autoOpened = true; }
    if ((item.data.status === 'completed' || item.data.status === 'failed') && item.autoOpened && !item.userToggled && item.el) { this.setToolOpen(item, false); item.autoOpened = false; }
    if (item.livePre && tn && item.open && item.data.status === 'in_progress') {
      item.livePre.textContent = item.live;
      item.livePre.scrollTop = item.livePre.scrollHeight;
      const tail = item.head && item.head.querySelector('.tool-tail'); if (tail) tail.textContent = lastLine(item.live);
    } else this.renderTool(item);
    this.chat.emit('transcript:grow');
    return item;
  }
  plan(entries) {
    if (this.lastPlan) { this.lastPlan.entries = entries; this.renderPlan(this.lastPlan); return this.lastPlan; }
    this.lastPlan = { kind: 'plan', entries, time: new Date() };
    return this.push(this.lastPlan);
  }
  sys(text, level = 'info') { return this.push({ kind: 'sys', text, level }); }
  messageUsage(messageId, usage) {
    this.usage.set(messageId, usage);
    const it = this.byMsg.get(messageId);
    if (it && it.foot) this.renderUsage(it);
  }
  addAsk(ask) {
    if (this.asks.has(ask.id)) return this.asks.get(ask.id);
    const item = { kind: 'ask', ask, time: new Date() };
    this.asks.set(ask.id, item);
    const tcId = ask.params && ask.params.toolCall && ask.params.toolCall.toolCallId;
    const tool = tcId ? this.tools.get(tcId) : null;
    const p = ask.params || {};
    item.tool = tool;
    item.askTitle = (p.toolCall && p.toolCall.title) || (tool && this.toolTitle(tool)) || p.message || 'a request';
    if (this.turn && !this.bulk && !this.resolvedAsks.has(ask.id)) this.setPhase('waiting', item.askTitle, item);
    if (tool && !this.bulk) {
      item.agentSide = true; item.first = false;
      const idx = this.items.indexOf(tool);
      this.items.splice(idx + 1, 0, item);
      item.el = this.build(item);
      if (tool.el && tool.el.parentNode) tool.el.after(item.el);
      else this.list.appendChild(item.el);
      this.chat.emit('transcript:append', item);
      return item;
    }
    return this.push(item);
  }
}

function strip(u) { const o = { ...u }; delete o.sessionUpdate; return o; }
// Goose attaches a TRUSTED `_meta.goose.mcpApp` {resourceUri, extensionName, toolName, ...} to tool calls whose
// tool declares an MCP App UI (untrusted copies from MCP servers are stripped by Goose). Keep only what we need.
function takeApp(item, u) {
  const a = u && u._meta && u._meta.goose && u._meta.goose.mcpApp;
  if (a && typeof a.resourceUri === 'string' && a.resourceUri.startsWith('ui://') && a.extensionName) {
    item.app = { resourceUri: a.resourceUri, extensionName: String(a.extensionName), toolName: a.toolName || '', readError: a.readError || null };
  }
}
// MCP CallToolResult for the app's ui/notifications/tool-result, rebuilt from the ACP tool call.
function appToolResult(tc) {
  const ro = tc.rawOutput;
  if (ro && typeof ro === 'object' && Array.isArray(ro.content)) return ro;
  const content = (tc.content || []).filter((c) => c && c.type === 'content' && c.content).map((c) => c.content);
  const res = { content, isError: tc.status === 'failed' };
  if (ro && typeof ro === 'object' && ro.structuredContent) res.structuredContent = ro.structuredContent;
  return res;
}
function fmtElapsed(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
  return Math.floor(m / 60) + 'h ' + String(m % 60).padStart(2, '0') + 'm';
}
function lastLine(s) { const t = String(s).replace(/\s+$/, ''); const i = t.lastIndexOf('\n'); return (i >= 0 ? t.slice(i + 1) : t).slice(0, 140); }

function clip(pre, text, max = 20000) {
  const s = String(text);
  if (s.length <= max) { pre.textContent = s; return pre; }
  pre.textContent = s.slice(0, max);
  const more = btn('Show all (' + fmtNum(s.length) + ' chars)', () => { pre.textContent = s; more.remove(); }, { size: 'sm', variant: 'ghost' });
  return h('div', null, pre, more);
}

function renderToolContent(c) {
  if (!c) return h('span');
  if (c.type === 'content' && c.content) {
    const cc = c.content;
    if (cc.type === 'text') return clip(h('pre', { class: 'term' }), cc.text || '');
    if (cc.type === 'image') return h('img', { class: 'tool-img', src: 'data:' + (cc.mimeType || 'image/png') + ';base64,' + cc.data, alt: 'tool image' });
    if (cc.type === 'resource_link') return h('div', { class: 'u-file' }, icon('file', 13), cc.name || cc.uri);
    if (cc.type === 'resource') return clip(h('pre', { class: 'term' }), (cc.resource && (cc.resource.text || cc.resource.uri)) || '');
    return h('pre', { class: 'json' }, prettyJson(cc));
  }
  if (c.type === 'diff') return renderDiff(c);
  if (c.type === 'terminal') return h('div', { class: 'muted small' }, 'Terminal ' + c.terminalId);
  return h('pre', { class: 'json' }, prettyJson(c));
}

export function renderDiff(c) {
  const oldL = String(c.oldText || '').split('\n');
  const newL = String(c.newText || '').split('\n');
  let pre = 0;
  while (pre < oldL.length && pre < newL.length && oldL[pre] === newL[pre]) pre++;
  let suf = 0;
  while (suf < oldL.length - pre && suf < newL.length - pre && oldL[oldL.length - 1 - suf] === newL[newL.length - 1 - suf]) suf++;
  const rows = [];
  const ctx = 3;
  for (let i = Math.max(0, pre - ctx); i < pre; i++) rows.push(h('div', { class: 'dl' }, '  ' + oldL[i]));
  for (let i = pre; i < oldL.length - suf; i++) rows.push(h('div', { class: 'dl del' }, '- ' + oldL[i]));
  for (let i = pre; i < newL.length - suf; i++) rows.push(h('div', { class: 'dl add' }, '+ ' + newL[i]));
  for (let i = newL.length - suf; i < Math.min(newL.length, newL.length - suf + ctx); i++) rows.push(h('div', { class: 'dl' }, '  ' + newL[i]));
  return h('div', { class: 'diff' }, h('div', { class: 'diff-head' }, icon('file', 13), c.path || 'file', c.oldText === null || c.oldText === undefined ? h('span', { class: 'badge badge-ok' }, 'new') : null), h('div', { class: 'diff-body' }, rows));
}

export { iconBtn };
