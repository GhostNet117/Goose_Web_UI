// WebSocket JSON-RPC 2.0 client for /ws with auto-reconnect, _gw/hello resync, pending map and timeouts.
import { Emitter, store } from './store.js';

const LONG_METHODS = new Set(['session/prompt', 'session/new', '_goose/unstable/schedules/run-now', '_goose/unstable/providers/config/authenticate', '_goose/unstable/session/steer']);
// FIX chat-open-replay-overflow: opening a chat gives up after this long (the gateway's own watchdog,
// goose.session_load_timeout_seconds, answers by then); it used to wait forever.
export const LOAD_TIMEOUT_MS = 180000;
const METHOD_TIMEOUTS = { 'session/load': LOAD_TIMEOUT_MS };
// A socket counts as working only once it stayed up this long: one that dies right after hello keeps backing off
// instead of reconnecting every 0.7 s.
export const STABLE_MS = 10000;

export class RpcError extends Error {
  constructor(err) {
    super(err && err.message ? err.message : 'RPC error');
    this.code = err && err.code; this.data = err && err.data;
  }
}

class Rpc extends Emitter {
  constructor() {
    super();
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.waiters = [];
    this.ready = false;     // socket open and hello done
    this.attempt = 0;
    this.stopped = true;
    this.retryTimer = null;
    this.hello = null;
    this.watched = new Set();
    this.current = '';      // the chat this tab shows: the gateway never unloads it (FIX idle-sessions-keep-mcp-servers)
  }

  url(extra = '') {
    return (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws' + extra;
  }

  start() { this.stopped = false; this.connect(); }
  stop() {
    this.stopped = true; clearTimeout(this.retryTimer);
    if (this.ws) { try { this.ws.close(1000, 'logout'); } catch { /* */ } }
    this.ws = null; this.ready = false; store.set('conn', 'idle');
  }

  connect() {
    if (this.stopped) return;
    clearTimeout(this.retryTimer);
    store.set('conn', this.attempt ? 'reconnecting' : 'connecting');
    let ws;
    try { ws = new WebSocket(this.url(this.profileParam ? '?profile=' + encodeURIComponent(this.profileParam) : '')); }
    catch (e) { this.scheduleReconnect(); return; }
    this.ws = ws;
    ws.addEventListener('open', () => this.onOpen(ws));
    ws.addEventListener('message', (ev) => this.onMessage(ev));
    ws.addEventListener('close', (ev) => this.onClose(ws, ev));
    ws.addEventListener('error', () => { /* close follows */ });
  }

  async onOpen(ws) {
    if (ws !== this.ws) return;
    try {
      const hello = await this._send('_gw/hello', {}, 20000, true);
      this.hello = hello;
      this.ready = true;
      this.readyAt = Date.now();   // the backoff (attempt) is reset in onClose, once the socket stayed up STABLE_MS
      store.set('conn', 'open');
      if (hello && hello.upstream) store.set('upstream', hello.upstream.state || 'ready');
      if (hello && hello.agent) store.set('agentInfo', hello.agent);
      if (hello && hello.gooseCaps) store.set('gooseCaps', hello.gooseCaps);
      this.emit('hello', hello);
      if (this.watched.size || this.current) this._send('_gw/watch', { sessionIds: [...this.watched], current: this.current }, 15000, true).catch(() => {});
      const w = this.waiters; this.waiters = [];
      w.forEach((fn) => fn.resolve());
    } catch (e) {
      console.warn('[rpc] hello failed', e);
      try { ws.close(4000, 'hello failed'); } catch { /* */ }
    }
  }

  onClose(ws, ev) {
    if (ws !== this.ws) return;
    const wasReady = this.ready;
    this.ready = false; this.ws = null;
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(Object.assign(new RpcError({ code: 'disconnected', message: 'Connection lost' }), { disconnected: true }));
      this.pending.delete(id);
    }
    if (wasReady) this.emit('disconnected', ev);
    else this.emit('handshake_failed', ev);
    if (wasReady && Date.now() - (this.readyAt || 0) >= STABLE_MS) this.attempt = 0;
    if (this.stopped) return;
    this.scheduleReconnect(ev);
  }

  scheduleReconnect() {
    this.attempt++;
    const base = Math.min(30000, 500 * Math.pow(1.8, this.attempt - 1));
    const delay = Math.round(base * (0.75 + Math.random() * 0.5));
    store.set('conn', this.attempt > 6 ? 'down' : 'reconnecting');
    this.nextRetryAt = Date.now() + delay;
    this.emit('retry', { attempt: this.attempt, delay });
    this.retryTimer = setTimeout(() => this.connect(), delay);
  }
  reconnectNow() { if (this.ready) return; this.attempt = Math.max(0, this.attempt - 1); clearTimeout(this.retryTimer); this.connect(); }

  onMessage(ev) {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { console.warn('[rpc] bad frame'); return; }
    if (Array.isArray(msg)) { msg.forEach((m) => this.dispatch(m)); return; }
    this.dispatch(msg);
  }

  dispatch(msg) {
    if (msg.method && msg.id !== undefined && msg.id !== null) {
      // agent -> client request
      this.emit('request', msg);
      return;
    }
    if (msg.method) {
      this.emit(msg.method, msg.params || {}, msg);
      this.emit('*', msg);
      return;
    }
    if (msg.id !== undefined) {
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new RpcError(msg.error));
      else p.resolve(msg.result);
    }
  }

  _send(method, params, timeout, bypass) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== 1 || (!bypass && !this.ready)) { reject(new RpcError({ code: 'disconnected', message: 'Not connected' })); return; }
      const id = this.nextId++;
      const timer = timeout ? setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new RpcError({ code: 'timeout', message: method + ' timed out' })); }
      }, timeout) : null;
      this.pending.set(id, { resolve, reject, timer, method });
      this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }

  waitReady(timeout = 20000) {
    if (this.ready) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const w = { resolve: () => { clearTimeout(t); resolve(); } };
      const t = setTimeout(() => { this.waiters = this.waiters.filter((x) => x !== w); reject(new RpcError({ code: 'disconnected', message: 'Not connected to the gateway' })); }, timeout);
      this.waiters.push(w);
    });
  }

  async call(method, params = {}, { timeout } = {}) {
    if (!this.ready) await this.waitReady();
    const to = timeout !== undefined ? timeout : (method in METHOD_TIMEOUTS ? METHOD_TIMEOUTS[method] : (LONG_METHODS.has(method) ? 0 : 60000));
    return this._send(method, params, to);
  }

  notify(method, params = {}) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    this.ws.send(JSON.stringify({ jsonrpc: '2.0', method, params }));
    return true;
  }

  respond(id, result) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, result }));
    return true;
  }
  respondError(id, code, message) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }));
    return true;
  }

  setWatched(ids, current = '') {
    const next = new Set(ids);
    const same = next.size === this.watched.size && [...next].every((x) => this.watched.has(x)) && (current || '') === this.current;
    this.watched = next;
    this.current = current || '';
    if (!same && this.ready) this._send('_gw/watch', { sessionIds: [...next], current: this.current }, 15000).catch(() => {});
  }
}

export const rpc = new Rpc();
export const G = (m) => '_goose/unstable/' + m;
