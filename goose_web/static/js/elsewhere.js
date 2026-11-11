// Working elsewhere + Done elsewhere (spec 020): sessions of the native profile that Goose Desktop, the goose CLI or a
// scheduled job is running (read-only here: Goose Web cannot stop, steer or message them), and the ones that finished
// there - grouped per job - which stay Done until opened in Goose Web or cleared. Administrators only; the gateway
// sends names, ids and times (no folders, no content).
import { bus } from './store.js';
import { rpc } from './rpc.js';

let items = [];
let done = [];
let enabled = false;
const bySession = new Map();   // sessionId -> { item, session } (working)
const doneBySession = new Map();   // sessionId -> done group

export function setElsewhere(list, on = true, doneList = null) {
  enabled = !!on;
  items = Array.isArray(list) ? list : [];
  if (doneList !== null) done = Array.isArray(doneList) ? doneList : [];
  if (!enabled) done = [];
  bySession.clear();
  doneBySession.clear();
  for (const it of items) {
    for (const s of it.sessions || []) bySession.set(s.sessionId, { item: it, session: s });
    if (!bySession.has(it.sessionId)) bySession.set(it.sessionId, { item: it, session: { sessionId: it.sessionId, status: it.status, last: it.last, title: it.latestTitle } });
  }
  for (const g of done) for (const s of g.sessions || []) doneBySession.set(s.sessionId, g);
  bus.emit('elsewhere');
}
export function elsewhereEnabled() { return enabled; }
export function elsewhereList() { return items; }
export function elsewhereDone() { return done; }
export function elsewhereFor(sessionId) { return bySession.get(sessionId) || null; }
export function elsewhereDoneFor(sessionId) { return doneBySession.get(sessionId) || null; }
export function runningElsewhere(sessionId) { const e = bySession.get(sessionId); return !!(e && e.session.status === 'running'); }
export function elsewhereRunningCount() { return items.reduce((n, it) => n + (it.running || 0), 0); }
export function elsewhereDoneCount() { return done.length; }
// Clear one Done group (key) or all of them ("mark all read"); the gateway pushes the new list to every tab.
export function clearElsewhereDone(key = null) {
  done = key ? done.filter((g) => g.key !== key) : [];
  setElsewhere(items, enabled, done);
  return rpc.call('_gw/elsewhere_clear', key ? { key } : {});
}
export function sourceLabel(it) {
  if (it && it.source === 'schedule') return 'Scheduled job' + (it.scheduler ? ' (' + it.scheduler + ' scheduler)' : '');
  return 'Goose Desktop, the goose CLI or a scheduled task';
}
