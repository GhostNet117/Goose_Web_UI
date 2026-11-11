// ChatSession: per-session controller (state + update stream -> Transcript). Cached while open/running.
import { Emitter, store, bus } from './store.js';
import { rpc, G } from './rpc.js';
import { Transcript } from './transcript.js';
import { asksForSession } from './asks.js';
import { getSession, upsertSession, patchSession } from './sessions.js';
import { agentFor } from './herd.js';
import { errMsg, toast } from './ui.js';

const chats = new Map();
const MAX_CACHED = 10;
let currentId = null;
// Spec 019: the gateway keeps each chat's composer queue and the steers the agent has not read yet, so a refresh,
// another tab or another device shows the same state. Kept here for chats this tab has not opened.
const serverQueues = new Map();   // sessionId -> [{id, blocks, held?, steer?, note?}]
const serverSteers = new Map();   // sessionId -> Map(messageId -> {messageId, blocks, state, at})
let localSeq = 0;

// Drafts stay on this device (localStorage, cleared at sign-out and when the sign-in expires): typing is never sent
// to the gateway. Security review 2026-11-11 (SC-5): keyed by the signed-in user AND the profile shown (Goose session
// ids are per-profile counters, so an administrator's draft must never appear in a member's chat with the same id),
// and dropped after a week.
const DRAFT_PREFIX = 'gw.draft|';
const DRAFT_MAX_AGE = 7 * 86400 * 1000;
const draftTimers = new Map();
export function myName() { const me = store.get('me'); return (me && me.user && me.user.username) || ''; }
function draftKey(id) { return DRAFT_PREFIX + myName().toLowerCase() + '|' + String(rpc.profileParam || myName()).toLowerCase() + '|' + id; }
function loadDraft(id) {
  try {
    const raw = localStorage.getItem(draftKey(id));
    if (!raw) return '';
    const d = JSON.parse(raw);
    if (!d || typeof d.v !== 'string' || !(Date.now() - (d.t || 0) < DRAFT_MAX_AGE)) { localStorage.removeItem(draftKey(id)); return ''; }
    return d.v;
  } catch { return ''; }
}
export function saveDraft(id, text) {
  clearTimeout(draftTimers.get(id));
  const key = draftKey(id);
  draftTimers.set(id, setTimeout(() => {
    draftTimers.delete(id);
    try { if (text) localStorage.setItem(key, JSON.stringify({ t: Date.now(), v: String(text).slice(0, 100000) })); else localStorage.removeItem(key); } catch { /* storage full or disabled */ }
  }, 400));
}
// Old (1.15.0, keyed by session id only) and expired drafts go; every draft goes when the sign-in expires (app.js).
export function clearDrafts(all = false) {
  try {
    const drop = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k || !k.startsWith('gw.draft')) continue;
      if (all || !k.startsWith(DRAFT_PREFIX)) { drop.push(k); continue; }
      try { const d = JSON.parse(localStorage.getItem(k) || 'null'); if (!d || !(Date.now() - (d.t || 0) < DRAFT_MAX_AGE)) drop.push(k); } catch { drop.push(k); }
    }
    for (const k of drop) localStorage.removeItem(k);
  } catch { /* storage disabled */ }
}
clearDrafts();
// SC-1/SC-6: a tab sends a queued message by itself only if it is this user's own profile and this user queued it.
function mine(q) { return !!q && (q.local || (!!q.by && q.by.toLowerCase() === myName().toLowerCase())); }

export function applyHelloState(hello) {
  serverQueues.clear();
  for (const [sid, items] of Object.entries((hello && hello.queues) || {})) if (Array.isArray(items)) serverQueues.set(sid, items);
  serverSteers.clear();
  for (const st of (hello && hello.steers) || []) noteSteer(st);
  for (const c of chats.values()) c.setServerQueue(serverQueues.get(c.id) || []);
  // no drain here: app.js applies this BEFORE the hello's herd, whose change event drains against fresh run states
}
export function queueUpdated(p) {
  if (!p || !p.sessionId) return;
  const items = Array.isArray(p.items) ? p.items : [];
  if (items.length) serverQueues.set(p.sessionId, items); else serverQueues.delete(p.sessionId);
  const c = chats.get(p.sessionId);
  if (c) c.setServerQueue(items);
  drainIdleQueues();
}
function noteSteer(st) {
  if (!st || !st.sessionId || !st.messageId) return;
  let m = serverSteers.get(st.sessionId);
  if (st.state === 'pending') { if (!m) serverSteers.set(st.sessionId, m = new Map()); m.set(st.messageId, st); }
  else if (m) { m.delete(st.messageId); if (!m.size) serverSteers.delete(st.sessionId); }
}
export function steerUpdated(p) {
  if (!p || !p.sessionId) return;
  noteSteer(p);
  const c = chats.get(p.sessionId);
  if (c && c.loaded) c.onSteerState(p);
}
export function pendingSteers(sid) { return [...((serverSteers.get(sid) || new Map()).values())]; }
export function hasLocalQueue() { return [...chats.values()].some((c) => c.queue.some((q) => q.local)); }
// A queued message waits for its chat's run to end. Any tab may send it (the gateway hands each item to one tab);
// chats this tab has not opened are opened in the background for that.
function drainIdleQueues() {
  if (rpc.profileParam) return;   // an administrator viewing someone else's profile never sends their messages
  for (const [sid, items] of serverQueues) {
    if (!items.some((q) => !q.held && mine(q))) continue;
    const a = agentFor(sid);
    if (a && (a.status === 'working' || a.status === 'needs_you')) continue;
    const c = chats.get(sid);
    if (c && (c.running || c.promptPending)) continue;
    (c || getChat(sid)).drainQueue();
  }
}

export function getChat(id, info) {
  let c = chats.get(id);
  if (!c) { c = new ChatSession(id, info); chats.set(id, c); evict(); syncWatch(); }
  else if (info) c.applyInfo(info);
  c.touched = Date.now();
  return c;
}
export function peekChat(id) { return chats.get(id) || null; }
export function allChats() { return [...chats.values()]; }
export function setCurrentChat(id) {
  currentId = id;
  if (id) { const c = chats.get(id); if (c) c.touched = Date.now(); rpc.ready && rpc.call('_gw/seen', { sessionId: id }).catch(() => {}); }
  syncWatch();
}
export function currentChat() { return currentId ? chats.get(currentId) : null; }
export function dropChat(id) { chats.delete(id); syncWatch(); }

function evict() {
  if (chats.size <= MAX_CACHED) return;
  const victims = [...chats.values()].filter((c) => c.id !== currentId && !c.running && !c.queue.length).sort((a, b) => a.touched - b.touched);
  while (chats.size > MAX_CACHED && victims.length) chats.delete(victims.shift().id);
}
function syncWatch() { rpc.setWatched([...chats.keys()]); }

export function routeNotification(method, params) {
  const sid = params && params.sessionId;
  if (!sid) return;
  const c = chats.get(sid);
  const u = params.update || {};
  if (method === 'session/update' && u.sessionUpdate === 'session_info_update') {
    const patch = {};
    if (u.title !== undefined) patch.title = u.title;
    if (u.updatedAt) patch.updatedAt = u.updatedAt;
    if (u._meta && (u._meta.messageCount !== undefined)) patch._meta = { messageCount: u._meta.messageCount };
    if (Object.keys(patch).length) { if (getSession(sid)) patchSession(sid, patch); }
  }
  if (!c) return;
  if (method === 'session/update') c.onUpdate(u);
  else c.onGooseUpdate(u);
}

// Another Goose process (Desktop, CLI, a schedule) wrote this session: the gateway dropped its buffer.
// The gateway stamps each live prompt with the server time (spec 010); Edit needs it to cut the conversation there.
export function promptCreated(p) {
  const c = p && p.sessionId && chats.get(p.sessionId);
  if (c && c.lastSent && !c.lastSent.created && Number.isInteger(p.created)) c.lastSent.created = p.created;
}

export function sessionChangedElsewhere(p) {
  const sid = p && p.sessionId;
  if (!sid) return;
  const patch = {};
  if (p.title) patch.title = p.title;
  if (p.updatedAt) patch.updatedAt = p.updatedAt;
  if (p.messageCount !== undefined && p.messageCount !== null) patch._meta = { messageCount: p.messageCount };
  if (getSession(sid) && Object.keys(patch).length) patchSession(sid, patch);
  const c = chats.get(sid);
  if (!c || c.running || c.promptPending || c.loading) return;
  if (sid === currentId) c.refreshFromElsewhere();
  else c.loaded = false;   // reloads when opened next
}

export class ChatSession extends Emitter {
  constructor(id, info) {
    super();
    this.id = id;
    this.info = { sessionId: id, ...(info || getSession(id) || {}) };
    this.title = this.info.title || '';
    this.cwd = this.info.cwd || '';
    this.modes = null;
    this.configOptions = [];
    this.usage = { used: 0, size: 0, cost: null, currency: 'USD' };
    this.running = false;
    this.promptPending = false;
    this.activeRunId = null;
    this.queue = (serverQueues.get(id) || []).slice();   // [{id, blocks, held?, steer?, note?, local?}]
    this.commands = [];
    this.loaded = false;
    this.loading = false;
    this.error = null;
    this.progress = null;
    this.touched = Date.now();
    this.transcript = new Transcript(this);
    this.draft = loadDraft(id);
  }

  // ---- composer queue, mirrored from the gateway (spec 019)
  setServerQueue(items) {
    this.queue = [...(items || []), ...this.queue.filter((q) => q.local)];
    this.emit('queue');
  }
  async enqueue(blocks) {
    const local = { id: 'local-' + (++localSeq), blocks, local: true };
    this.queue.push(local); this.emit('queue');
    try {
      const r = await rpc.call('_gw/queue', { sessionId: this.id, op: 'add', blocks });
      this.queue = this.queue.filter((q) => q !== local);
      if (r && Array.isArray(r.items)) this.queue = [...r.items, ...this.queue.filter((q) => q.local)];
      this.emit('queue');
      if (!this.running && !this.promptPending) this.drainQueue();   // the run ended meanwhile
    } catch (e) {
      this.transcript.sys('This message is queued in this tab only (' + errMsg(e) + '): it is lost if you close the tab.', 'warn');
    }
  }
  // Claim a queued item before sending it: with several tabs open, the gateway gives each item to one tab only.
  async takeQueued(item, manual = false) {
    if (!item) return null;
    if (item.local) { this.queue = this.queue.filter((q) => q !== item); this.emit('queue'); return item; }
    this.queue = this.queue.filter((q) => q !== item); this.emit('queue');
    try {
      const r = await rpc.call('_gw/queue', { sessionId: this.id, op: 'take', id: item.id, manual });
      return r && r.ok ? (r.item || item) : null;
    } catch {
      this.setServerQueue(serverQueues.get(this.id) || []);
      return null;
    }
  }

  applyInfo(info) {
    if (!info) return;
    this.info = { ...this.info, ...info };
    if (info.title) this.title = info.title;
    if (info.cwd) this.cwd = info.cwd;
    this.emit('state');
  }

  applySessionResult(res) {
    if (!res) return;
    if (res.modes) this.modes = res.modes;
    if (Array.isArray(res.configOptions)) this.configOptions = res.configOptions;
    const meta = res._meta || {};
    if (meta.workingDir) this.cwd = meta.workingDir;
    if (meta.recipe) this.recipe = meta.recipe;
    if (meta.extensionResults) this.extensionResults = meta.extensionResults;
    if (meta.gw && meta.gw.running !== undefined) this.setRunning(!!meta.gw.running || this.promptPending);
    this.emit('state');
  }

  async ensureLoaded() {
    if (this.loaded || this.loading) return this.loadPromise;
    return this.load();
  }

  async load() {
    this.loading = true; this.error = null;
    this.emit('state');
    this.loadPromise = (async () => {
      try {
        if (!this.cwd) {
          const r = await rpc.call(G('session/info'), { sessionId: this.id });
          if (r && r.session) { this.applyInfo(r.session); upsertSession(r.session); }
        }
        this.transcript.clear();
        this.transcript.beginBulk();
        this.replaying = true;
        let res;
        try {
          res = await rpc.call('session/load', { sessionId: this.id, cwd: this.cwd, mcpServers: [] });
        } finally {
          this.replaying = false;
          this.transcript.endBulk();
        }
        this.applySessionResult(res);
        for (const a of asksForSession(this.id)) this.transcript.addAsk(a);
        for (const st of pendingSteers(this.id)) this.onSteerState(st);   // sent from another tab / before a refresh
        const ag = agentFor(this.id);
        if (ag && (ag.status === 'working' || ag.status === 'needs_you')) this.setRunning(true);
        this.loaded = true;
        this.emit('loaded');
      } catch (e) {
        this.error = e;
        this.emit('error', e);
      } finally {
        this.loading = false;
        this.emit('state');
      }
    })();
    return this.loadPromise;
  }

  reload() { this.loaded = false; return this.load(); }

  async refreshFromElsewhere() {
    if (this.running || this.promptPending || this.loading) return;
    await this.reload();
    this.emit('external');
  }

  setRunning(v) {
    const was = this.running;
    this.running = !!v;
    if (was !== this.running) {
      if (this.running) this.transcript.startTurn();
      if (!this.running) { this.transcript.endTurn(); this.transcript.finalizeAll(); this.progress = null; this.emit('run:end'); this.drainQueue(); }
      this.emit('state');
    }
  }

  onUpdate(u) {
    const t = this.transcript;
    const meta = u._meta;
    switch (u.sessionUpdate) {
      case 'user_message_chunk': {
        const g = (meta && meta.goose) || {};
        const mid = u.messageId || g.messageId || null;
        // Goose marks a steer the agent has just read with _meta.goose.steer (its id starts with "steer_")
        const steer = !!g.steer || (typeof mid === 'string' && mid.startsWith('steer_'));
        t.addUser([u.content], { messageId: mid, steer, delivered: steer, time: g.created ? new Date(g.created * 1000) : null, created: g.created || null });
        break;
      }
      case 'agent_message_chunk':
        t.agentChunk(u.content, u.messageId || (meta && meta.goose && meta.goose.messageId), meta);
        if (!this.replaying && !this.running) this.setRunning(true);
        break;
      case 'agent_thought_chunk':
        t.thoughtChunk(u.content, u.messageId || (meta && meta.goose && meta.goose.messageId), meta);
        break;
      case 'tool_call':
        t.toolCall(u);
        break;
      case 'tool_call_update':
        t.toolUpdate(u);
        break;
      case 'plan':
        t.plan(u.entries || []);
        break;
      case 'available_commands_update':
        this.commands = u.availableCommands || [];
        this.emit('commands');
        break;
      case 'current_mode_update':
        if (this.modes) this.modes = { ...this.modes, currentModeId: u.currentModeId };
        this.configOptions = this.configOptions.map((o) => (o.category === 'mode' || o.id === 'mode' ? { ...o, currentValue: u.currentModeId } : o));
        this.emit('state');
        break;
      case 'config_option_update':
        if (Array.isArray(u.configOptions)) { this.configOptions = u.configOptions; this.emit('state'); }
        break;
      case 'session_info_update': {
        if (u.title !== undefined && u.title !== null) { this.title = u.title; }
        const g = meta && meta.goose;
        if (g && 'activeRunId' in g) {
          this.activeRunId = g.activeRunId;
          if (!this.replaying) this.setRunning(!!g.activeRunId || this.promptPending);
        }
        this.emit('state');
        break;
      }
      case 'usage_update':
        this.usage.used = u.used ?? this.usage.used;
        this.usage.size = u.size ?? this.usage.size;
        if (u.cost) { this.usage.cost = u.cost.amount; this.usage.currency = u.cost.currency || 'USD'; }
        this.emit('usage');
        break;
      default:
        break;
    }
  }

  onGooseUpdate(u) {
    switch (u.sessionUpdate) {
      case 'usage_update':
        this.usage.used = u.used ?? this.usage.used;
        if (u.contextLimit) this.usage.size = u.contextLimit;
        if (u.accumulatedCost !== undefined && u.accumulatedCost !== null) this.usage.cost = u.accumulatedCost;
        this.usage.inTokens = u.accumulatedInputTokens; this.usage.outTokens = u.accumulatedOutputTokens;
        this.emit('usage');
        break;
      case 'message_usage':
        if (u.messageId && u.usage) this.transcript.messageUsage(u.messageId, u.usage);
        break;
      case 'status_message': {
        const s = u.status || {};
        if (s.type === 'progress') { this.progress = s.message; this.emit('progress', s.message); if (s.message) this.transcript.setPhase('progress', s.message); }
        else if (s.message) this.transcript.sys(s.message, 'info');
        break;
      }
      case 'live_voice_interaction_ended':
        break;
      default:
        break;
    }
  }

  async send(blocks) {
    if (this.running || this.promptPending) { this.enqueue(blocks); return; }
    const item = this.transcript.addUser(blocks, { pending: true });
    this.lastSent = item;
    this.promptPending = true;
    this.setRunning(true);
    this.emit('sent');
    try {
      if (!this.loaded && !this.loading) await this.load();
      const p = rpc.call('session/prompt', { sessionId: this.id, prompt: blocks });
      this.transcript.markUserSent(item);
      const res = await p;
      const reason = res && res.stopReason;
      if (reason === 'cancelled') this.transcript.sys('Stopped', 'info');
      else if (reason === 'max_tokens') this.transcript.sys('Stopped: output token limit reached', 'warn');
      else if (reason === 'max_turn_requests') this.transcript.sys('Stopped: maximum turns reached', 'warn');
      else if (reason === 'refusal') this.transcript.sys('The model refused to continue', 'warn');
      patchSession(this.id, { updatedAt: new Date().toISOString() });
    } catch (e) {
      if (e && (e.disconnected || e.code === 'disconnected')) {
        this.transcript.sys('Connection lost. The agent keeps working on the server; the transcript will resync when reconnected.', 'warn');
      } else if (e && (e.code === -32010 || e.code === -32011)) {
        // -32010: the gateway drains before a restart for an update; -32011: another program (Goose Desktop, the
        // CLI, a scheduled job) is running this chat (spec 020). Nothing was sent: the text goes back into the box.
        if (item && item.el) item.el.remove();
        this.transcript.sys(errMsg(e) + ' Your message was not sent; it is back in the box.', 'warn');
        this.emit('edit', blocks);
      } else {
        this.transcript.sys('Error: ' + errMsg(e), 'error');
      }
    } finally {
      this.promptPending = false;
      this.transcript.markUserSent(item);
      if (!this.activeRunId) this.setRunning(false);
      else this.emit('state');
    }
  }

  // Edit a sent prompt (spec 010), like Goose Desktop. mode 'replace': delete this message and everything after it
  // in this chat (conversation/truncate), then send the edited text here. mode 'branch': a new chat with the history
  // before this message (session/fork + conversationBefore), then the edited text there; this chat is untouched.
  // Both cut at "created >= item.created" (whole seconds, Goose's clock). Returns the chat id the prompt went to.
  async editAndRerun(item, text, mode) {
    if (this.running || this.promptPending) throw new Error('Stop the current run before editing a message.');
    const created = item && item.created;
    if (!Number.isInteger(created)) throw new Error('This message has no server time yet. Use Reload transcript in the chat menu, then try again.');
    const items = this.transcript.items;
    const idx = items.indexOf(item);
    if (idx < 0) throw new Error('This message is no longer in the transcript. Reload it and try again.');
    let prev = 0;
    for (let i = 0; i < idx; i++) if (Number.isInteger(items[i].created) && items[i].created > prev) prev = items[i].created;
    if (prev >= created) throw new Error('The reply before this message was saved in the same second, so the chat cannot be cut exactly here. Edit an earlier message, or use Fork conversation.');
    const blocks = [{ type: 'text', text }, ...item.blocks.filter((b) => b.type !== 'text')];
    if (mode === 'branch') {
      const res = await rpc.call('session/fork', { sessionId: this.id, cwd: this.cwd, _meta: { conversationBefore: created } });
      const id = res && res.sessionId;
      if (!id) throw new Error('Goose did not return the new chat');
      const title = (this.title || 'Chat') + ' (edited)';
      upsertSession({ sessionId: id, cwd: this.cwd, title, updatedAt: new Date().toISOString() });
      const c = getChat(id, { cwd: this.cwd, title });
      await c.ensureLoaded();
      c.send(blocks);
      return id;
    }
    await rpc.call(G('session/conversation/truncate'), { sessionId: this.id, truncateFrom: created });
    await this.reload();
    this.send(blocks);
    return this.id;
  }

  // The run ended: send the first queued message that is not held (returned steers wait for the user). Never in an
  // administrator's view of another profile, and never someone else's message (SC-1/SC-6: those need a click).
  async drainQueue() {
    if (rpc.profileParam || this.running || this.promptPending || this.draining) return;
    const next = this.queue.find((q) => !q.held && mine(q));
    if (!next) return;
    this.draining = true;
    try {
      const item = await this.takeQueued(next);
      if (item && item.blocks) setTimeout(() => this.send(item.blocks), 50);
    } finally { this.draining = false; }
  }
  async removeQueued(i) {
    const q = this.queue[i];
    if (!q) return;
    if (q.local) { this.queue.splice(i, 1); this.emit('queue'); return; }
    this.queue.splice(i, 1); this.emit('queue');
    try { await rpc.call('_gw/queue', { sessionId: this.id, op: 'remove', id: q.id }); } catch (e) { this.transcript.sys('Could not remove the queued message: ' + errMsg(e), 'warn'); this.setServerQueue(serverQueues.get(this.id) || []); }
  }
  // A queued message the user sends by hand: as a steer while the run is active, otherwise as the next prompt.
  async sendQueued(i) {
    const item = await this.takeQueued(this.queue[i], true);
    if (!item || !item.blocks) return;
    if (this.running && this.activeRunId) this.steer(item.blocks); else this.send(item.blocks);
  }
  steerQueued(i) { return this.sendQueued(i); }
  // Move a queued message back into the composer for editing.
  async editQueued(i) {
    const item = await this.takeQueued(this.queue[i], true);
    if (item && item.blocks) this.emit('edit', item.blocks);
  }

  cancel() {
    if (!rpc.notify('session/cancel', { sessionId: this.id })) {
      this.transcript.sys('Not connected: Stop was not sent. Try again when the connection is back.', 'warn');
      rpc.reconnectNow && rpc.reconnectNow();
      return;
    }
    this.emit('cancel');
  }

  // Goose answers a steer at once, but the agent reads it only at its next step (after the model's reply or a tool
  // call). The bubble shows that state; if the run ends first, the gateway puts the steer back in the queue.
  async steer(blocks) {
    if (!this.activeRunId) { return this.send(blocks); }
    const item = this.transcript.addUser(blocks, { steer: true, pending: true });
    this.transcript.setSteerState(item, 'sending');
    try {
      const res = await rpc.call(G('session/steer'), { sessionId: this.id, prompt: blocks, expectedRunId: this.activeRunId });
      this.transcript.markUserSent(item);
      if (res && res.messageId) {
        item.messageId = res.messageId; this.transcript.users.set(res.messageId, item);
        if (item.steerState === 'sending') this.transcript.setSteerState(item, 'pending');
      }
    } catch (e) {
      if (item.el) item.el.remove();
      if (e && e.code === -32003) { this.transcript.sys('Steer refused: ' + errMsg(e), 'error'); return; }
      this.transcript.sys('Steer failed: ' + errMsg(e) + ' (queued instead)', 'warn');
      this.enqueue(blocks);
    }
  }
  // _gw/steer_update from the gateway (also replayed after a load): pending / delivered / returned.
  onSteerState(p) {
    const t = this.transcript;
    let item = p.messageId ? t.users.get(p.messageId) : null;
    if (p.state === 'pending') {
      if (!item) { item = t.addUser(p.blocks || [], { steer: true, time: p.at ? new Date(p.at * 1000) : null }); item.local = false; item.messageId = p.messageId; t.users.set(p.messageId, item); }
      if (item.steerState !== 'delivered') t.setSteerState(item, 'pending');
    } else if (p.state === 'delivered') {
      if (item) t.setSteerState(item, 'delivered');
    } else if (p.state === 'returned') {
      if (item) t.setSteerState(item, 'returned');
      const msg = 'Steer not delivered. ' + (p.note || '') + ' It is back in the queue below: send it, edit it, or remove it.';
      t.sys(msg, 'warn');
      if (currentId === this.id) toast(msg, { kind: 'warn', timeout: 12000 });
    } else if (p.state === 'dropped') {   // the queue was full (SC-4): the steer could not come back
      if (item) t.setSteerState(item, 'returned');
      t.sys('Steer not delivered, and the chat\'s queue is full, so it was dropped. ' + (p.note || ''), 'warn');
    }
  }

  async setMode(modeId) {
    await rpc.call('session/set_mode', { sessionId: this.id, modeId });
    if (this.modes) this.modes = { ...this.modes, currentModeId: modeId };
    this.configOptions = this.configOptions.map((o) => (o.category === 'mode' || o.id === 'mode' ? { ...o, currentValue: modeId } : o));
    this.emit('state');
  }
  async setConfig(configId, value) {
    const res = await rpc.call('session/set_config_option', { sessionId: this.id, configId, value });
    if (res && Array.isArray(res.configOptions)) this.configOptions = res.configOptions;
    else this.configOptions = this.configOptions.map((o) => (o.id === configId ? { ...o, currentValue: value } : o));
    this.emit('state');
  }
  async rename(title) {
    await rpc.call(G('session/rename'), { sessionId: this.id, title });
    this.title = title;
    patchSession(this.id, { title, _meta: { userSetName: true } });
    this.emit('state');
  }
  async setCwd(dir) {
    await rpc.call(G('session/working-dir/update'), { sessionId: this.id, workingDir: dir });
    this.cwd = dir;
    patchSession(this.id, { cwd: dir });
    this.emit('state');
  }
}

bus.on('ask:new', (ask) => {
  const c = ask.sessionId && chats.get(ask.sessionId);
  if (c && c.loaded) c.transcript.addAsk(ask);
});
bus.on('ask:resolved', (ev) => {
  for (const c of chats.values()) c.transcript.askResolved(ev && ev.id);
});
store.on('change:herd', () => {
  for (const c of chats.values()) {
    const a = agentFor(c.id);
    if (!a) continue;
    if ((a.status === 'done' || a.status === 'idle' || a.status === 'error') && c.running && !c.promptPending) { c.activeRunId = null; c.setRunning(false); }
    else if ((a.status === 'working' || a.status === 'needs_you') && !c.running && c.loaded) c.setRunning(true);
    if (a.title && a.title !== c.title) { c.title = a.title; c.emit('state'); }
  }
  if (serverQueues.size) drainIdleQueues();
});
