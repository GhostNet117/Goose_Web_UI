// UI preferences (/api/me/prefs) and theme application via CSS variables.
import { GET, PATCH } from './api.js';
import { store, bus } from './store.js';
import { debounce, toast, toastError } from './ui.js';

export const THEMES = [
  { id: 'system', label: 'System' },
  { id: 'dark', label: 'Dark' },
  { id: 'light', label: 'Light' },
  { id: 'midnight', label: 'Midnight' },
  { id: 'nord', label: 'Nord' },
  { id: 'solarized-dark', label: 'Solarized Dark' },
  { id: 'solarized-light', label: 'Solarized Light' },
  { id: 'dracula', label: 'Dracula' },
  { id: 'high-contrast', label: 'High contrast' },
];
const LIGHT_THEMES = new Set(['light', 'solarized-light']);
export const ACCENTS = ['#7c5cff', '#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#ec4899', '#a3e635'];

export const DEFAULT_PREFS = {
  theme: 'system', accent: '', density: 'comfortable', fontSize: 14, codeTheme: 'auto',
  enterToSend: true, showTimestamps: false, pinned: [], recentFolders: [], lastCwd: '',
  // Chat history shown at once (items; 0 = all) and whether scrolling to the top loads earlier messages.
  historyWindow: 300, autoLoadEarlier: true,
  notifications: { browser: false, sound: false, events: ['needs_you', 'done', 'error'] },
  sidebar: { collapsed: {}, showArchived: false, includeScheduled: true, width: 288 },
  herd: { all: false },
  // Live agent activity in chat. thinking: auto|expanded|collapsed; tools: auto|detailed|concise.
  activity: { thinking: 'auto', tools: 'auto', statusBar: true },
  // New chat screen choices (spec 008); '' = profile default.
  newChat: { provider: '', model: '', effort: '', mode: '' },
  // Providers left out of the chat pickers (spec 023, providervis.js); only the hidden ids, so new providers show.
  providerVisibility: { hidden: [] },
  // Provider groups and model display names for the chat pickers (spec 024, providergroups.js); display only.
  providerGroups: { groups: [], modelNames: {} },
};

export function prefs() { return { ...DEFAULT_PREFS, ...(store.get('prefs') || {}) }; }
export function pref(k) { return prefs()[k]; }
export function activityPrefs() {
  const a = { ...DEFAULT_PREFS.activity, ...((store.get('prefs') || {}).activity || {}) };
  if (!['auto', 'expanded', 'collapsed'].includes(a.thinking)) a.thinking = 'auto';
  if (!['auto', 'detailed', 'concise'].includes(a.tools)) a.tools = 'auto';
  a.statusBar = a.statusBar !== false;
  return a;
}

// ----- server sync (1.18.2, bug prefs-stale-tab-overwrite) -----
// A tab sends only the keys it changed, with the server revision its copy is based on (PATCH /api/me/prefs
// {baseRev, set, unset, client}). The server merges, rejects a change to a key that changed after baseRev (409),
// and broadcasts every save to the user's tabs (_gw/prefs), so no tab keeps an old copy. Reconnects re-read.
const TAB = 'tab-' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
const THEME_KEYS = ['theme', 'accent', 'density', 'fontSize', 'codeTheme'];
const PREF_LABELS = { providerGroups: 'provider groups', providerVisibility: 'chat picker providers', newChat: 'New chat choices',
  sidebar: 'sidebar', notifications: 'notifications', activity: 'chat activity', pinned: 'pinned chats', theme: 'theme' };
let baseRev = 0;            // the server revision the shown prefs are based on
let loaded = false;         // the server copy was read at least once (before that nothing is sent)
const ownRevs = new Set();  // revisions this tab created (its own change is never a conflict with itself)
let pending = new Map();    // key -> {value, patch, del}: changed here, not sent yet
let inflight = null;        // the batch being sent
let retries = 0;

export function prefsClientId() { return TAB; }
export function prefsRevision() { return baseRev; }

function cacheLocal() { try { localStorage.setItem('gw.prefs', JSON.stringify(store.get('prefs') || {})); } catch { /* */ } }

function overlay(p) {
  const next = { ...p };
  for (const m of [inflight, pending]) {
    if (!m) continue;
    for (const [k, ch] of m) { if (ch.del) delete next[k]; else next[k] = ch.value; }
  }
  return next;
}

// Show a server copy. A change still pending here for a key the server changed after our base came from
// another tab/browser: a sub-key edit (patchPref) is re-applied on the newer value, a whole-value edit is dropped
// and the user is told - the other side's newer value is never overwritten from an old base.
function adopt(p, { initial = false } = {}) {
  if (!p || typeof p !== 'object') return;
  const rev = Number(p._rev) || 0;
  if (loaded && rev < baseRev) return;   // an older copy than the one shown (out-of-order reply)
  const kr = p._keyRev || {};
  const lost = [];
  if (loaded && !initial) {
    for (const [k, ch] of [...pending]) {
      const r = Number(kr[k]) || 0;
      if (r <= baseRev || ownRevs.has(r)) continue;
      if (ch.patch && !ch.del) ch.value = { ...(DEFAULT_PREFS[k] || {}), ...(p[k] || {}), ...ch.patch };
      else { pending.delete(k); lost.push(k); }
    }
  } else {
    for (const [k, ch] of pending) if (ch.patch && !ch.del) ch.value = { ...(DEFAULT_PREFS[k] || {}), ...(p[k] || {}), ...ch.patch };
  }
  baseRev = rev;
  loaded = true;
  const before = store.get('prefs') || {};
  const next = overlay(p);
  store.set('prefs', next);
  // views that show prefs (New chat pickers, Settings > Provider groups) redraw when a value really changed
  const changed = [...new Set([...Object.keys(before), ...Object.keys(next)])]
    .filter((k) => !k.startsWith('_') && JSON.stringify(before[k]) !== JSON.stringify(next[k]));
  if (changed.length) bus.emit('prefs:changed', changed);
  cacheLocal();
  applyTheme();
  if (lost.length) toast('Changed in another tab or browser: ' + lost.map((k) => PREF_LABELS[k] || k).join(', ') + '. This tab now shows that version; repeat your change if you still want it.', { kind: 'warn', timeout: 9000 });
  if (pending.size) saveSoon();
}

export async function loadPrefs() {
  try {
    adopt(await GET('/api/me/prefs'), { initial: true });
  } catch (e) {
    // offline: the cached copy is shown, nothing is sent until the server copy was read (refreshPrefs on reconnect)
    try { store.set('prefs', overlay(JSON.parse(localStorage.getItem('gw.prefs') || '{}'))); } catch { store.set('prefs', overlay({})); }
    applyTheme();
  }
}

// Re-read the server copy (socket reconnect, a 409, a missed broadcast).
export async function refreshPrefs() {
  try { adopt(await GET('/api/me/prefs'), { initial: !loaded }); } catch { /* next reconnect */ }
}

// A save by any tab of this user (server broadcast _gw/prefs).
export function prefsChanged(params) {
  if (!params || !params.prefs) return;
  if (params.client === TAB && params.rev) ownRevs.add(Number(params.rev));
  adopt(params.prefs);
}

// Logout / another user: forget everything this tab knew.
export function resetPrefsSync() { baseRev = 0; loaded = false; pending = new Map(); inflight = null; ownRevs.clear(); retries = 0; }

async function flush() {
  if (inflight || !pending.size || !loaded) return;
  const batch = pending; pending = new Map(); inflight = batch;
  const body = { baseRev, client: TAB, set: {}, unset: [] };
  for (const [k, ch] of batch) { if (ch.del) body.unset.push(k); else body.set[k] = ch.value; }
  let again = false;
  try {
    const r = await PATCH('/api/me/prefs', body);
    if (r && r.rev) ownRevs.add(Number(r.rev));
    inflight = null; retries = 0;
    if (r && r.prefs) adopt(r.prefs);
  } catch (e) {
    inflight = null;
    for (const [k, ch] of batch) if (!pending.has(k)) pending.set(k, ch);   // a newer change of the same key wins
    if (e.status === 409 && retries++ < 3) { await refreshPrefs(); again = true; }
    else if (e.status === 400 || e.status === 413 || e.status === 409) { for (const k of batch.keys()) pending.delete(k); retries = 0; toastError(e, 'Saving preferences failed'); }
    else if (e.status && e.status !== 401) toastError(e, 'Saving preferences failed');
    // network errors and 401: kept, sent after the next reconnect (refreshPrefs -> adopt -> saveSoon)
  }
  if (again || (pending.size && !inflight)) saveSoon();
}
const saveSoon = debounce(flush, 600);

function queue(k, ch) {
  pending.set(k, ch);
  store.set('prefs', overlay(store.get('prefs') || {}));
  cacheLocal();
  saveSoon();
  if (THEME_KEYS.includes(k)) applyTheme();
}
export function setPref(k, v) { queue(k, { value: v, patch: null, del: false }); }
export function patchPref(k, patch) {
  const prev = pending.get(k);
  const cur = { ...(DEFAULT_PREFS[k] || {}), ...((store.get('prefs') || {})[k] || {}) };
  queue(k, { value: { ...cur, ...patch }, patch: prev && !prev.patch ? null : { ...((prev && prev.patch) || {}), ...patch }, del: false });
}
// Remove a preference on the server (it falls back to its default). Only an explicit removal deletes a key.
export function removePref(k) { queue(k, { value: undefined, patch: null, del: true }); }

const mq = window.matchMedia('(prefers-color-scheme: light)');
mq.addEventListener('change', () => applyTheme());

export function resolvedTheme() {
  const t = pref('theme') || 'system';
  if (t === 'system') return mq.matches ? 'light' : 'dark';
  return t;
}
export function isLight() { return LIGHT_THEMES.has(resolvedTheme()); }

export function applyTheme() {
  const root = document.documentElement;
  const p = prefs();
  const t = resolvedTheme();
  root.dataset.theme = t;
  root.dataset.scheme = isLight() ? 'light' : 'dark';
  root.dataset.density = p.density || 'comfortable';
  root.style.colorScheme = isLight() ? 'light' : 'dark';
  if (p.accent) root.style.setProperty('--accent', p.accent); else root.style.removeProperty('--accent');
  root.style.setProperty('--fs', (Number(p.fontSize) || 14) + 'px');
  const ct = p.codeTheme === 'auto' || !p.codeTheme ? (isLight() ? 'light' : 'dark') : p.codeTheme;
  const dark = document.getElementById('hljs-dark'), light = document.getElementById('hljs-light');
  if (dark && light) { dark.disabled = ct !== 'dark'; light.disabled = ct !== 'light'; }
  const meta = document.querySelector('meta[name=theme-color]');
  if (meta) meta.setAttribute('content', getComputedStyle(root).getPropertyValue('--bg').trim() || '#0b0b0f');
}

export function addRecentFolder(path) {
  if (!path) return;
  const r = (pref('recentFolders') || []).filter((x) => x !== path);
  r.unshift(path);
  setPref('recentFolders', r.slice(0, 12));
  setPref('lastCwd', path);
}

export function isPinned(id) { return (pref('pinned') || []).includes(id); }
export function togglePin(id) {
  const p = pref('pinned') || [];
  setPref('pinned', p.includes(id) ? p.filter((x) => x !== id) : [id, ...p]);
}
