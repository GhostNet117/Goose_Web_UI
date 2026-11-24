// Tiny reactive store + event emitter.
export class Emitter {
  constructor() { this._h = new Map(); }
  on(ev, fn) { if (!this._h.has(ev)) this._h.set(ev, new Set()); this._h.get(ev).add(fn); return () => this.off(ev, fn); }
  off(ev, fn) { const s = this._h.get(ev); if (s) s.delete(fn); }
  once(ev, fn) { const off = this.on(ev, (...a) => { off(); fn(...a); }); return off; }
  emit(ev, ...args) {
    const s = this._h.get(ev);
    if (s) for (const fn of [...s]) { try { fn(...args); } catch (e) { console.error('[emit ' + ev + ']', e); } }
  }
}

class Store extends Emitter {
  constructor(initial) { super(); this.state = { ...initial }; }
  get(k) { return this.state[k]; }
  set(k, v) {
    if (typeof k === 'object') { for (const [kk, vv] of Object.entries(k)) this.set(kk, vv); return; }
    const prev = this.state[k];
    this.state[k] = v;
    if (prev !== v || typeof v === 'object') this.emit('change:' + k, v, prev);
  }
  update(k, fn) { this.set(k, fn(this.state[k])); }
  watch(k, fn, immediate = true) { const off = this.on('change:' + k, fn); if (immediate) fn(this.state[k]); return off; }
}

export const store = new Store({
  me: null,            // /api/me result
  authConfig: null,    // /api/auth/config
  prefs: {},           // /api/me/prefs
  conn: 'idle',        // websocket: idle|connecting|open|reconnecting|down
  upstream: 'unknown', // goose worker: starting|ready|down
  route: null,
  herd: new Map(),     // sessionId -> Agent
  asks: new Map(),     // request id -> ask
  agentInfo: null,     // initialize result from _gw/hello
  gooseCaps: null,     // what the worker's Goose version supports (_gw/hello)
});

export const bus = new Emitter();

export function policy(key) {
  const me = store.get('me');
  if (!me) return false;
  if (me.isAdmin) return true;
  const p = me.policy || {};
  return !!p[key];
}
export function policyList(key) {
  const me = store.get('me');
  if (!me || me.isAdmin) return [];
  const v = (me.policy || {})[key];
  return Array.isArray(v) ? v : [];
}
// Spec 009: "*" = any value; an empty list allows nothing. Admins are never restricted.
// Spec 038: a model an administrator gave this person with ONE provider (policy.granted_models) is allowed with that
// provider only - pass the provider the model is listed for (the gateway holds the same pair at the prompt).
export function allowedValue(listKey, value, provider) {
  const me = store.get('me');
  if (!me || me.isAdmin) return true;
  const l = policyList(listKey);
  if (l.includes('*') || l.includes(value)) return true;
  if (listKey !== 'allowed_models' || provider == null) return false;
  const g = (me.policy || {}).granted_models;
  const given = g && typeof g === 'object' && Array.isArray(g[provider]) ? g[provider] : [];
  return given.includes('*') || given.includes(value);
}
// Why this user cannot start or continue chats ('' = they can). Set by the gateway (policy.chat_block).
export function chatBlocked() {
  const me = store.get('me');
  if (!me || me.isAdmin) return '';
  return String((me.policy || {}).chat_blocked || '');
}
