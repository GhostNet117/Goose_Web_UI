// Herd state (live agents) + attention signals: title badge, favicon badge, browser notifications, sound.
import { store, bus } from './store.js';
import { prefs } from './prefs.js';
import { router } from './router.js';
import { toast } from './ui.js';

export const STATUS_ORDER = ['needs_you', 'working', 'error', 'done', 'idle', 'offline'];
export const STATUS_LABEL = { needs_you: 'Needs you', working: 'Working', done: 'Done', idle: 'Idle', error: 'Error', offline: 'Offline' };

const key = (a) => (a.profile ? a.profile + ':' : '') + a.sessionId;
let myProfile = null;
export function setMyProfile(p) { myProfile = p; }

export function herdList() { return [...store.get('herd').values()]; }
export function agentFor(sessionId) {
  for (const a of store.get('herd').values()) if (a.sessionId === sessionId && (!myProfile || !a.profile || a.profile === myProfile)) return a;
  return null;
}
export function statusFor(sessionId) { const a = agentFor(sessionId); return a ? a.status : null; }

export function setHerd(list) {
  const m = new Map();
  for (const a of list || []) if (a && a.sessionId) m.set(key(a), a);
  store.set('herd', m);
  bus.emit('herd');
  refreshBadges();
}

export function upsertAgent(agent) {
  if (!agent || !agent.sessionId) return;
  const m = store.get('herd');
  const k = key(agent);
  const prev = m.get(k);
  m.set(k, { ...(prev || {}), ...agent });
  store.set('herd', m);
  bus.emit('herd', agent, prev);
  if (!prev || prev.status !== agent.status) onTransition(agent, prev);
  refreshBadges();
}

export function counts() {
  const c = { needs_you: 0, working: 0, done: 0, idle: 0, error: 0, offline: 0 };
  for (const a of store.get('herd').values()) if (!myProfile || !a.profile || a.profile === myProfile) c[a.status] = (c[a.status] || 0) + 1;
  return c;
}

function viewing(sessionId) {
  const r = router.current();
  return r.view === 'chat' && r.args[0] === sessionId && document.visibilityState === 'visible';
}

function onTransition(agent, prev) {
  if (agent.profile && myProfile && agent.profile !== myProfile) return;
  const st = agent.status;
  if (!['needs_you', 'done', 'error'].includes(st)) return;
  if (prev && prev.status === st) return;
  if (viewing(agent.sessionId)) return;
  const p = prefs();
  const events = (p.notifications && p.notifications.events) || ['needs_you', 'done', 'error'];
  if (!events.includes(st)) return;
  const title = agent.title || 'Goose session';
  const text = st === 'needs_you' ? (agent.ask && agent.ask.title ? 'Needs you: ' + agent.ask.title : 'Waiting for your approval')
    : st === 'done' ? 'Finished' + (agent.lastText ? ': ' + agent.lastText.slice(0, 120) : '') : 'Error';
  if (document.visibilityState !== 'visible') browserNotify(title, text, agent.sessionId);
  else if (st !== 'needs_you') toast(text, { title, kind: st === 'error' ? 'error' : 'success', actions: [{ label: 'Open', onClick: () => router.go('/chat/' + encodeURIComponent(agent.sessionId)) }] });
  if (p.notifications && p.notifications.sound) chime(st);
}

export function browserNotify(title, body, sessionId) {
  const p = prefs();
  if (!(p.notifications && p.notifications.browser) || !('Notification' in window) || Notification.permission !== 'granted') return;
  try {
    const n = new Notification(title, { body, tag: 'gw-' + (sessionId || 'x'), icon: '/static/icons/goose.svg', renotify: true });
    n.onclick = () => { window.focus(); if (sessionId) router.go('/chat/' + encodeURIComponent(sessionId)); n.close(); };
  } catch { /* some browsers need SW notifications */ }
}

let audioCtx;
export function chime(kind = 'done') {
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const notes = kind === 'needs_you' ? [660, 880] : kind === 'error' ? [440, 330] : [523, 784];
    notes.forEach((f, i) => {
      const o = audioCtx.createOscillator(); const g = audioCtx.createGain();
      o.type = 'sine'; o.frequency.value = f;
      const t = audioCtx.currentTime + i * 0.13;
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.08, t + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.25);
      o.connect(g).connect(audioCtx.destination); o.start(t); o.stop(t + 0.3);
    });
  } catch { /* */ }
}

// ---- title + favicon badge ----
let baseTitle = 'Goose';
export function setBaseTitle(t) { baseTitle = t || 'Goose'; refreshBadges(); }
let faviconHref = null;
let lastBadge = -1;
export function refreshBadges() {
  const c = counts();
  const asks = store.get('asks').size;
  const n = Math.max(c.needs_you, asks) + c.done + c.error;
  document.title = (n ? '(' + n + ') ' : '') + baseTitle;
  const urgent = Math.max(c.needs_you, asks) > 0;
  const badge = n ? (urgent ? 2 : 1) : 0;
  if (badge === lastBadge) return;
  lastBadge = badge;
  setFavicon(badge);
}
function setFavicon(state) {
  const link = document.querySelector('link[rel=icon]');
  if (!link) return;
  if (!faviconHref) faviconHref = link.getAttribute('href');
  if (!state) { link.setAttribute('href', faviconHref); return; }
  const img = new Image();
  img.onload = () => {
    const c = document.createElement('canvas'); c.width = 64; c.height = 64;
    const x = c.getContext('2d');
    x.drawImage(img, 0, 0, 64, 64);
    x.beginPath(); x.arc(50, 14, 13, 0, Math.PI * 2);
    x.fillStyle = state === 2 ? '#f59e0b' : '#22c55e'; x.fill();
    x.lineWidth = 4; x.strokeStyle = '#0b0b0f'; x.stroke();
    try { link.setAttribute('href', c.toDataURL('image/png')); } catch { /* */ }
  };
  img.src = faviconHref;
}

store.on('change:asks', () => refreshBadges());
