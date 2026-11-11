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
const jobs = new Set();   // name prefixes of jobs that run elsewhere in several sessions (sidebar grouping, D5)

// The gateway's grouping rule (elsewhere.py name_prefix): the name without its trailing date/number.
// 'Hourly-Report 2026-11-11 04:00' -> 'Hourly-Report'; 'Report (3)' -> 'Report'; 'Weekly' -> 'Weekly'.
const TRAIL = /(?:[\s\-_:#.,/]*(?:\d[\d\-_:./]*(?:[Tt ]\d[\d:.]*)?[Zz]?|\(\d+\)|#\d+))+$/;
export function namePrefix(name) {
  const n = String(name || '').trim();
  return n.replace(TRAIL, '').replace(/^[ \-_:#.,/]+|[ \-_:#.,/]+$/g, '') || n;
}
// A job: a group with several sessions, or a session name with a trailing date/number (one run of a job).
export function jobPrefixes(list, doneList) {
  const out = new Set();
  const add = (title, count) => {
    const t = String(title || '').trim();
    const p = namePrefix(t);
    if (p && (count > 1 || p !== t)) out.add(p);
  };
  for (const it of list || []) {
    add(it.title, it.count || 1);
    for (const s of it.sessions || []) add(s.title, it.count || 1);
  }
  for (const g of doneList || []) {
    add(g.title, g.count || 1);
    for (const s of g.sessions || []) add(s.title, g.count || 1);
  }
  return out;
}
// Sidebar folder rows: sessions of one elsewhere job (same name prefix, same folder) become one group, in list order
// (the group sits where its newest session was). Returns [{session} | {job, sessions}]. Pure (tests run it in node).
export function groupJobRows(sessions, titleOf, jobSet) {
  const out = []; const at = new Map();
  for (const s of sessions || []) {
    const p = jobSet && jobSet.size ? namePrefix(titleOf(s)) : '';
    if (!p || !jobSet.has(p)) { out.push({ session: s }); continue; }
    let g = at.get(p);
    if (!g) { g = { job: p, sessions: [] }; at.set(p, g); out.push(g); }
    g.sessions.push(s);
  }
  return out.map((x) => (x.job && x.sessions.length === 1 ? { session: x.sessions[0] } : x));
}

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
  jobs.clear();
  if (enabled) for (const p of jobPrefixes(items, done)) jobs.add(p);
  bus.emit('elsewhere');
}
export function elsewhereJobs() { return jobs; }
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
