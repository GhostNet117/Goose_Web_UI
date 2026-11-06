// ChatSession: per-session controller (state + update stream -> Transcript). Cached while open/running.
import { Emitter, store, bus } from './store.js';
import { rpc, G } from './rpc.js';
import { Transcript } from './transcript.js';
import { asksForSession } from './asks.js';
import { getSession, upsertSession, patchSession } from './sessions.js';
import { agentFor } from './herd.js';
import { errMsg } from './ui.js';

const chats = new Map();
const MAX_CACHED = 10;
let currentId = null;

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
    this.queue = [];
    this.commands = [];
    this.loaded = false;
    this.loading = false;
    this.error = null;
    this.progress = null;
    this.touched = Date.now();
    this.transcript = new Transcript(this);
    this.draft = '';
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
      if (!this.running) { this.transcript.finalizeAll(); this.progress = null; this.emit('run:end'); this.drainQueue(); }
      this.emit('state');
    }
  }

  onUpdate(u) {
    const t = this.transcript;
    const meta = u._meta;
    switch (u.sessionUpdate) {
      case 'user_message_chunk':
        t.addUser([u.content], { messageId: u.messageId || (meta && meta.goose && meta.goose.messageId) || null, time: meta && meta.goose && meta.goose.created ? new Date(meta.goose.created * 1000) : null });
        break;
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
        if (s.type === 'progress') { this.progress = s.message; this.emit('progress', s.message); }
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
    if (this.running) { this.queue.push(blocks); this.emit('queue'); return; }
    const item = this.transcript.addUser(blocks, { pending: true });
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

  drainQueue() {
    if (this.running || !this.queue.length) return;
    const next = this.queue.shift();
    this.emit('queue');
    setTimeout(() => this.send(next), 50);
  }
  removeQueued(i) { this.queue.splice(i, 1); this.emit('queue'); }

  cancel() {
    rpc.notify('session/cancel', { sessionId: this.id });
    this.emit('cancel');
  }

  async steer(blocks) {
    if (!this.activeRunId) { return this.send(blocks); }
    const item = this.transcript.addUser(blocks, { steer: true, pending: true });
    try {
      const res = await rpc.call(G('session/steer'), { sessionId: this.id, prompt: blocks, expectedRunId: this.activeRunId });
      this.transcript.markUserSent(item);
      if (res && res.messageId) { item.messageId = res.messageId; this.transcript.users.set(res.messageId, item); }
    } catch (e) {
      this.transcript.sys('Steer failed: ' + errMsg(e) + ' (queued instead)', 'warn');
      if (item.el) item.el.remove();
      this.queue.unshift(blocks); this.emit('queue');
    }
  }
  steerQueued(i) {
    const b = this.queue.splice(i, 1)[0];
    this.emit('queue');
    if (b) this.steer(b);
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
store.on('change:herd', () => {
  for (const c of chats.values()) {
    const a = agentFor(c.id);
    if (!a) continue;
    if ((a.status === 'done' || a.status === 'idle' || a.status === 'error') && c.running && !c.promptPending) { c.activeRunId = null; c.setRunning(false); }
    else if ((a.status === 'working' || a.status === 'needs_you') && !c.running && c.loaded) c.setRunning(true);
    if (a.title && a.title !== c.title) { c.title = a.title; c.emit('state'); }
  }
});
