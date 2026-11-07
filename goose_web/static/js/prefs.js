// UI preferences (/api/me/prefs) and theme application via CSS variables.
import { GET, PUT } from './api.js';
import { store } from './store.js';
import { debounce, toastError } from './ui.js';

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
  notifications: { browser: false, sound: false, events: ['needs_you', 'done', 'error'] },
  sidebar: { collapsed: {}, showArchived: false, includeScheduled: true, width: 288 },
  herd: { all: false },
  // Live agent activity in chat. thinking: auto|expanded|collapsed; tools: auto|detailed|concise.
  activity: { thinking: 'auto', tools: 'auto', statusBar: true },
  // New chat screen choices (spec 008); '' = profile default.
  newChat: { provider: '', model: '', effort: '', mode: '' },
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

export async function loadPrefs() {
  try {
    const p = await GET('/api/me/prefs');
    store.set('prefs', p && typeof p === 'object' ? p : {});
  } catch (e) {
    try { store.set('prefs', JSON.parse(localStorage.getItem('gw.prefs') || '{}')); } catch { store.set('prefs', {}); }
  }
  applyTheme();
}

const saveRemote = debounce(async () => {
  const p = store.get('prefs') || {};
  try { localStorage.setItem('gw.prefs', JSON.stringify(p)); } catch { /* */ }
  try { await PUT('/api/me/prefs', p); } catch (e) { if (e.status !== 401) toastError(e, 'Saving preferences failed'); }
}, 600);

export function setPref(k, v) {
  const p = { ...(store.get('prefs') || {}) };
  p[k] = v;
  store.set('prefs', p);
  saveRemote();
  if (['theme', 'accent', 'density', 'fontSize', 'codeTheme'].includes(k)) applyTheme();
}
export function patchPref(k, patch) {
  const cur = { ...(DEFAULT_PREFS[k] || {}), ...((store.get('prefs') || {})[k] || {}) };
  setPref(k, { ...cur, ...patch });
}

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
