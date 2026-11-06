// Session list state (session/list pagination) and Desktop-compatible folder grouping.
import { rpc } from './rpc.js';
import { bus } from './store.js';
import { prefs } from './prefs.js';

export const sessionsState = {
  items: new Map(),   // sessionId -> SessionInfo (+ local fields)
  nextCursor: null,
  loading: false,
  loaded: false,
  error: null,
  query: '',
  gen: 0,
};

function listTypes() {
  const p = prefs();
  const inc = p.sidebar && p.sidebar.includeScheduled !== undefined ? p.sidebar.includeScheduled : true;
  return inc ? ['user', 'acp', 'scheduled'] : ['user', 'acp'];
}

export async function loadSessions({ reset = true } = {}) {
  if (sessionsState.loading && !reset) return;
  const gen = reset ? ++sessionsState.gen : sessionsState.gen;
  sessionsState.loading = true;
  bus.emit('sessions');
  try {
    const meta = { types: listTypes(), goose: { includeLastMessageSnippet: true } };
    if (sessionsState.query.trim()) meta.query = sessionsState.query.trim();
    const params = { _meta: meta };
    if (!reset && sessionsState.nextCursor) params.cursor = sessionsState.nextCursor;
    const res = await rpc.call('session/list', params);
    if (gen !== sessionsState.gen) return;
    if (reset) sessionsState.items = new Map();
    for (const s of res.sessions || []) sessionsState.items.set(s.sessionId, { ...(sessionsState.items.get(s.sessionId) || {}), ...s });
    sessionsState.nextCursor = res.nextCursor || null;
    sessionsState.loaded = true;
    sessionsState.error = null;
  } catch (e) {
    if (gen === sessionsState.gen) sessionsState.error = e;
  } finally {
    if (gen === sessionsState.gen) { sessionsState.loading = false; bus.emit('sessions'); }
  }
}

// Merge the newest page into the list without clearing it (sessions changed in Goose Desktop/CLI/schedules).
let refreshTimer = null;
export function refreshSessionsSoon(delay = 1200) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refreshSessions, delay);
}
export async function refreshSessions() {
  if (!sessionsState.loaded || sessionsState.loading || sessionsState.query.trim()) return;
  try {
    const res = await rpc.call('session/list', { _meta: { types: listTypes(), goose: { includeLastMessageSnippet: true } } });
    let n = 0;
    for (const s of res.sessions || []) {
      const prev = sessionsState.items.get(s.sessionId);
      if (prev && prev.updatedAt === s.updatedAt && prev.title === s.title) continue;
      sessionsState.items.set(s.sessionId, { ...(prev || {}), ...s, _meta: { ...((prev && prev._meta) || {}), ...(s._meta || {}) } });
      n++;
    }
    if (n) bus.emit('sessions');
  } catch (e) { /* best effort; the next change retries */ }
}

export function loadMore() { if (sessionsState.nextCursor && !sessionsState.loading) return loadSessions({ reset: false }); }

export function setQuery(q) { sessionsState.query = q; return loadSessions({ reset: true }); }

export function getSession(id) { return sessionsState.items.get(id) || null; }

export function upsertSession(info) {
  if (!info || !info.sessionId) return;
  const prev = sessionsState.items.get(info.sessionId) || {};
  const merged = { ...prev, ...info, _meta: { ...(prev._meta || {}), ...(info._meta || {}) } };
  sessionsState.items.set(info.sessionId, merged);
  bus.emit('sessions');
}
export function patchSession(id, patch) {
  const prev = sessionsState.items.get(id);
  if (!prev) return;
  const metaPatch = patch._meta || {};
  sessionsState.items.set(id, { ...prev, ...patch, _meta: { ...(prev._meta || {}), ...metaPatch } });
  bus.emit('sessions');
}
export function removeSession(id) { sessionsState.items.delete(id); bus.emit('sessions'); }

// ----- grouping (port of goose ui/desktop/src/utils/projectSessions.ts) -----
export function normalizeProjectPath(dir) {
  const n = String(dir || '').trim();
  if (!n) return '';
  return n.replace(/[\\/]+$/, '') || n;
}
export function projectLabel(dir) {
  const n = String(dir || '').trim();
  if (!n) return 'Unknown';
  const w = normalizeProjectPath(n);
  if (!w) return n;
  const parts = w.split(/[\\/]+/);
  return parts[parts.length - 1] || n;
}
function disambiguated(dir, depth) {
  const w = normalizeProjectPath(dir);
  if (!w) return 'Unknown';
  const parts = w.split(/[\\/]+/).filter(Boolean);
  if (parts.length >= 2) return parts.slice(-Math.min(depth, parts.length)).join('/');
  return projectLabel(dir);
}
export function activityTime(s) {
  const m = s._meta || {};
  return new Date(m.lastMessageAt || s.updatedAt || m.createdAt || 0).getTime() || 0;
}
export function isArchived(s) { return !!(s._meta && s._meta.archivedAt); }

export function groupSessions(list) {
  const groups = new Map();
  for (const s of list) {
    const p = normalizeProjectPath(s.cwd);
    if (!groups.has(p)) groups.set(p, []);
    groups.get(p).push(s);
  }
  let out = [...groups.entries()].map(([path, ss]) => {
    ss.sort((a, b) => activityTime(b) - activityTime(a));
    return { path, label: projectLabel(path), sessions: ss, last: activityTime(ss[0] || {}) };
  });
  // disambiguate duplicate labels by adding parent segments until unique
  for (let depth = 2; depth <= 6; depth++) {
    const counts = new Map();
    out.forEach((g) => counts.set(g.label, (counts.get(g.label) || 0) + 1));
    if (![...counts.values()].some((c) => c > 1)) break;
    out = out.map((g) => (counts.get(g.label) > 1 ? { ...g, label: disambiguated(g.path, depth) } : g));
  }
  return out.sort((a, b) => b.last - a.last);
}

export function sessionTitle(s) { return (s && (s.title || (s._meta && s._meta.name))) || 'Untitled chat'; }
