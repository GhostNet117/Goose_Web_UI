// Herd view: every live agent grouped by status, with inline approvals and peers.
import { h, btn, iconBtn, pageHeader, relTime, elapsed, fmtCost, fmtNum, shortPath, empty, toggle, banner, toastError, errMsg, spinner } from '../ui.js';
import { icon } from '../icons.js';
import { store, bus } from '../store.js';
import { rpc } from '../rpc.js';
import { GET } from '../api.js';
import { router } from '../router.js';
import { STATUS_ORDER, STATUS_LABEL, setHerd, setBaseTitle } from '../herd.js';
import { askCard } from '../asks.js';
import { prefs, patchPref } from '../prefs.js';
import { elsewhereEnabled, elsewhereList, elsewhereDone, clearElsewhereDone, sourceLabel } from '../elsewhere.js';

export function renderHerd(ctx) {
  setBaseTitle('Herd · Goose');
  const me = store.get('me');
  const isAdmin = me && me.isAdmin;
  let all = !!(prefs().herd && prefs().herd.all) && isAdmin;
  let peers = []; let machine = null; let peerErr = null; let loadingPeers = true;
  const groupsEl = h('div', { class: 'herd-groups' });
  const peersEl = h('div', { class: 'herd-peers' });
  const tick = h('span', { class: 'muted small' });

  const actions = [
    isAdmin ? toggle(all, async (v) => { all = v; patchPref('herd', { all: v }); await refreshAll(); }, { text: 'All users' }) : null,
    btn('Refresh', () => refreshAll(), { icon: 'refresh', size: 'sm' }),
  ];

  const card = (a, { peer = null } = {}) => {
    const asks = [...store.get('asks').values()].filter((x) => x.sessionId === a.sessionId && !peer && (!a.profile || !me || a.profile === (me.user && me.user.username) || !all));
    const open = () => {
      if (peer) { window.open(peer.url.replace(/\/$/, '') + '/#/chat/' + encodeURIComponent(a.sessionId), '_blank', 'noopener'); return; }
      if (a.profile && me && me.user && a.profile !== me.user.username) { window.open('/?profile=' + encodeURIComponent(a.profile) + '#/chat/' + encodeURIComponent(a.sessionId), '_blank', 'noopener'); return; }
      router.go('/chat/' + encodeURIComponent(a.sessionId));
    };
    const u = a.usage || {};
    const pct = u.contextLimit ? Math.min(100, (u.used / u.contextLimit) * 100) : 0;
    return h('article', { class: ['hcard', 'hs-' + a.status], tabindex: 0, onkeydown: (e) => { if (e.key === 'Enter' && e.target === e.currentTarget) open(); } },
      h('div', { class: 'hcard-top' },
        h('span', { class: 'sdot s-' + a.status + (a.status === 'working' || a.status === 'needs_you' ? ' pulse' : '') }),
        h('button', { type: 'button', class: 'hcard-title', onclick: open, title: 'Open' }, a.title || 'Untitled chat'),
        h('span', { class: 'hcard-time', title: a.since ? new Date(typeof a.since === 'number' && a.since < 1e12 ? a.since * 1000 : a.since).toLocaleString() : '' }, a.status === 'working' || a.status === 'needs_you' ? elapsed(a.since) : relTime(a.since))),
      h('div', { class: 'hcard-meta' },
        h('span', { class: 'chip chip-sm', title: a.cwd || '' }, icon('folder', 11), shortPath(a.cwd || '', 34)),
        a.profile && (all || peer) ? h('span', { class: 'chip chip-sm' }, icon('user', 11), a.username || a.profile) : null,
        u.cost ? h('span', { class: 'chip chip-sm' }, fmtCost(u.cost)) : null,
        u.contextLimit ? h('span', { class: 'chip chip-sm', title: fmtNum(u.used) + ' / ' + fmtNum(u.contextLimit) + ' tokens' }, h('span', { class: 'mini-bar' }, h('span', { style: { width: pct + '%' } })), Math.round(pct) + '%') : null),
      a.status === 'error' && a.error ? h('div', { class: 'hcard-ask hcard-err' }, icon('alert', 13), h('span', null, a.error.slice(0, 280))) : null,
      a.lastText ? h('div', { class: 'hcard-text' }, a.lastText.slice(0, 280)) : null,
      a.ask && !asks.length ? h('div', { class: 'hcard-ask' }, icon('shield', 13), h('span', null, a.ask.title || a.ask.kind || 'Waiting for input')) : null,
      ...asks.map((x) => askCard(x, { compact: true })),
      h('div', { class: 'hcard-actions' },
        btn(peer ? 'Open on ' + peer.name : 'Open', open, { size: 'sm', icon: peer ? 'external' : 'chat' }),
        !peer && (a.status === 'working' || a.status === 'needs_you') ? btn('Stop', () => { rpc.notify('session/cancel', { sessionId: a.sessionId }); }, { size: 'sm', variant: 'danger-soft', icon: 'stop' }) : null));
  };

  // Spec 020: sessions another program runs in the native profile (Working elsewhere: read-only, no Stop, no steering),
  // and the ones that finished there (Done until opened here or cleared). One card per job, however many sessions.
  const elseCard = (it, { finished = false } = {}) => {
    const open = (sid) => router.go('/chat/' + encodeURIComponent(sid));
    return h('article', { class: ['hcard', finished ? 'hs-done' : 'hs-elsewhere'], tabindex: 0, onkeydown: (e) => { if (e.key === 'Enter' && e.target === e.currentTarget) open(it.sessionId); } },
      h('div', { class: 'hcard-top' },
        h('span', { class: finished ? 'sdot s-done' : 'sdot s-elsewhere pulse' }),
        h('button', { type: 'button', class: 'hcard-title', onclick: () => open(it.sessionId), title: finished ? 'Open (clears it from Done)' : 'View read-only' }, it.title || 'Untitled session'),
        h('span', { class: 'hcard-time', title: new Date(it.last * 1000).toLocaleString() }, relTime(it.last * 1000))),
      h('div', { class: 'hcard-meta' },
        h('span', { class: 'badge ' + (finished ? '' : 'badge-ok') }, finished ? 'finished elsewhere' : 'working elsewhere'),
        h('span', { class: 'chip chip-sm' }, icon('monitor', 11), sourceLabel(it)),
        it.count > 1 ? h('span', { class: 'chip chip-sm', title: finished ? 'Sessions of this job that finished since you last opened one' : 'Sessions of this job running now' }, it.count + ' sessions' + (finished ? ' finished' : ' running')) : null),
      it.count > 1 ? h('ul', { class: 'hcard-list' }, (it.sessions || []).map((s) => h('li', null,
        h('a', { href: '#/chat/' + encodeURIComponent(s.sessionId) }, s.title || s.sessionId), ' ',
        h('span', { class: 'muted small' }, relTime(s.last * 1000))))) : null,
      h('div', { class: 'hcard-text muted small' }, finished ? 'Stays here until you open it in Goose Web or clear it.' : 'Read-only here: Goose Web cannot stop, steer or message it.'),
      h('div', { class: 'hcard-actions' },
        btn(finished ? (it.count > 1 ? 'Open newest' : 'Open') : (it.count > 1 ? 'View newest (read-only)' : 'View (read-only)'), () => open(it.sessionId), { size: 'sm', icon: finished ? 'chat' : 'eye' }),
        finished ? btn('Clear', () => clearElsewhereDone(it.key).catch((e) => toastError(e, 'Clear')), { size: 'sm', variant: 'ghost', icon: 'check' }) : null));
  };
  const markAllRead = async (doneAgents) => {
    for (const a of doneAgents) rpc.call('_gw/seen', { sessionId: a.sessionId }).catch(() => {});
    if (elsewhereDone().length) { try { await clearElsewhereDone(); } catch (e) { toastError(e, 'Mark all read'); } }
  };

  const renderGroups = () => {
    let list = [...store.get('herd').values()];
    if (!all && me && me.user) list = list.filter((a) => !a.profile || a.profile === me.user.username || a.username === me.user.username);
    const by = {};
    for (const a of list) (by[a.status] = by[a.status] || []).push(a);
    const working = isAdmin && elsewhereEnabled() ? elsewhereList() : [];
    const doneElse = isAdmin && elsewhereEnabled() ? elsewhereDone() : [];
    const head = (dot, label, n, ...extra) => h('div', { class: 'herd-sect-head' }, h('span', { class: 'sdot ' + dot }), h('h3', null, label), h('span', { class: 'count' }, String(n)), ...extra);
    const sections = [];
    for (const s of STATUS_ORDER) {
      const items = (by[s] || []).sort((x, y) => String(y.since || '').localeCompare(String(x.since || '')));
      const extra = s === 'done' ? doneElse : [];
      if (items.length || extra.length) {
        const mine = items.filter((a) => !a.profile || !me || !me.user || a.profile === me.user.username);
        sections.push(h('section', { class: 'herd-sect' + (s === 'done' ? ' herd-done' : '') },
          head('s-' + s, STATUS_LABEL[s] || s, items.length + extra.length,
            s === 'done' ? btn('Mark all read', () => markAllRead(mine), { size: 'sm', variant: 'ghost', icon: 'check', class: 'herd-markall' }) : null),
          h('div', { class: 'hgrid' }, items.map((a) => card(a)), extra.map((g) => elseCard(g, { finished: true })))));
      }
      if (s === 'working' && working.length) {   // Working elsewhere, right after Working
        sections.push(h('section', { class: 'herd-sect herd-elsewhere' },
          head('s-elsewhere', 'Working elsewhere', working.length, h('span', { class: 'muted small' }, 'Goose Desktop, the goose CLI and scheduled jobs in your native profile')),
          h('div', { class: 'hgrid' }, working.map((g) => elseCard(g)))));
      }
    }
    groupsEl.replaceChildren(...(sections.length ? sections : [empty('herd', 'No live agents', 'Agents appear here while they run. They keep working when you close the tab.', btn('Start a chat', () => router.go('/new'), { icon: 'plus', variant: 'primary' }))]));
  };

  const renderPeers = () => {
    const nodes = [];
    if (loadingPeers) nodes.push(h('div', { class: 'muted small' }, spinner(12), ' Checking other machines…'));
    if (peerErr) nodes.push(banner('warn', 'Could not load peers: ' + peerErr));
    for (const p of peers) {
      nodes.push(h('section', { class: 'herd-sect peer' },
        h('div', { class: 'herd-sect-head' }, icon('monitor', 14), h('h3', null, p.name), h('a', { class: 'muted small', href: p.url, target: '_blank', rel: 'noopener' }, p.url),
          h('span', { class: 'badge ' + (p.ok ? 'badge-ok' : 'badge-err') }, p.ok ? 'online' : 'unreachable'), p.error ? h('span', { class: 'muted small' }, p.error) : null),
        p.agents && p.agents.length ? h('div', { class: 'hgrid' }, p.agents.map((a) => card(a, { peer: p }))) : h('div', { class: 'muted small pad' }, p.ok ? 'No live agents' : '')));
    }
    peersEl.replaceChildren(...(nodes.length ? [h('h2', { class: 'herd-h2' }, 'Other machines'), ...nodes] : []));
  };

  async function refreshAll() {
    try {
      const r = await rpc.call('_gw/herd', all ? { all: true } : {});
      setHerd(r.agents || []);
    } catch (e) { toastError(e, 'Herd'); }
    loadingPeers = true; renderPeers();
    try {
      const r = await GET('/api/herd' + (all ? '?all=1' : ''));
      peers = r.peers || []; machine = r.machine || null; peerErr = null;
      if (r.agents && !rpc.ready) setHerd(r.agents);
    } catch (e) { peerErr = errMsg(e); }
    loadingPeers = false;
    renderPeers(); renderGroups();
    tick.textContent = machine ? 'This machine: ' + (typeof machine === 'string' ? machine : machine.name || '') : '';
  }

  const el = h('div', { class: 'view view-page view-herd' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Herd'), h('span', null, 'See which agent needs you. They keep working when you close the tab. ', tick), actions),
    h('div', { class: 'page-body' }, groupsEl, peersEl));

  renderGroups(); renderPeers();
  refreshAll();
  const timer = setInterval(() => { renderGroups(); }, 15000);
  const peerTimer = setInterval(async () => {
    try { const r = await GET('/api/herd' + (all ? '?all=1' : ''), { quiet: true }); peers = r.peers || []; peerErr = null; renderPeers(); } catch { /* */ }
  }, 30000);
  const offs = [bus.on('herd', renderGroups), bus.on('elsewhere', renderGroups), store.on('change:asks', renderGroups)];
  return { el, destroy() { clearInterval(timer); clearInterval(peerTimer); offs.forEach((f) => f()); } };
}
