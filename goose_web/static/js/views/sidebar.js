// Sidebar: brand, new chat, search, herd summary, nav, sessions grouped by working folder.
import { h, btn, iconBtn, menu, relTime, debounce, kbd, toast, toastError, confirmDialog, promptDialog, input } from '../ui.js';
import { icon, logo } from '../icons.js';
import { store, bus, policy } from '../store.js';
import { router } from '../router.js';
import { rpc, G } from '../rpc.js';
import { sessionsState, loadSessions, loadMore, setQuery, groupSessions, isArchived, sessionTitle, removeSession, patchSession } from '../sessions.js';
import { counts, statusFor, agentFor } from '../herd.js';
import { prefs, patchPref, isPinned, togglePin, setPref, THEMES, resolvedTheme } from '../prefs.js';
import { dropChat, peekChat } from '../chatsession.js';
import { elsewhereEnabled, elsewhereList, elsewhereRunningCount, runningElsewhere, elsewhereDoneFor, sourceLabel } from '../elsewhere.js';

export const NAV = [
  { id: 'new', label: 'New chat', icon: 'chat', path: '/new', key: 'c' },
  { id: 'herd', label: 'Herd', icon: 'herd', path: '/herd', key: 'h' },
  { id: 'recipes', label: 'Recipes', icon: 'recipe', path: '/recipes', key: 'r' },
  { id: 'skills', label: 'Skills', icon: 'skill', path: '/skills', key: 'k' },
  { id: 'schedules', label: 'Schedules', icon: 'schedule', path: '/schedules', key: 's' },
  { id: 'apps', label: 'Apps', icon: 'apps', path: '/apps', key: 'a' },
  { id: 'extensions', label: 'Extensions', icon: 'ext', path: '/extensions', key: 'e' },
  { id: 'settings', label: 'Settings', icon: 'settings', path: '/settings', key: ',' },
  { id: 'admin', label: 'Admin', icon: 'admin', path: '/admin', key: 'd', admin: true },
];

export function renderSidebar(ctx) {
  const me = store.get('me');
  const brand = (store.get('authConfig') && store.get('authConfig').brand) || {};
  const search = input({ type: 'search', placeholder: 'Search chats', class: 'inp side-search', 'aria-label': 'Search chats' });
  search.addEventListener('input', debounce(() => setQuery(search.value), 300));
  search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { search.value = ''; setQuery(''); search.blur(); } });

  const filterBtn = iconBtn('sliders', 'List options', () => {
    const sb = prefs().sidebar || {};
    menu(filterBtn, [
      { header: 'Show' },
      { label: 'Archived chats', icon: 'archive', active: !!sb.showArchived, onClick: () => { patchPref('sidebar', { showArchived: !sb.showArchived }); renderList(); } },
      { label: 'Scheduled runs', icon: 'schedule', active: sb.includeScheduled !== false, onClick: () => { patchPref('sidebar', { includeScheduled: sb.includeScheduled === false }); loadSessions(); } },
      '-',
      { label: 'Collapse all folders', icon: 'chevronUp', onClick: () => { const c = {}; groupSessions([...sessionsState.items.values()]).forEach((g) => { c[g.path] = true; }); patchPref('sidebar', { collapsed: c }); renderList(); } },
      { label: 'Expand all folders', icon: 'chevronDown', onClick: () => { patchPref('sidebar', { collapsed: {} }); renderList(); } },
      { label: 'Refresh', icon: 'refresh', onClick: () => loadSessions() },
    ], { align: 'right' });
  });

  const herdBox = h('a', { class: 'side-herd', href: '#/herd', title: 'Herd: live agents' });
  const renderHerd = () => {
    const c = counts();
    const n = Math.max(c.needs_you, store.get('asks').size);
    herdBox.replaceChildren(
      h('span', { class: 'sh-item' + (n ? ' hot' : '') }, h('span', { class: 'sdot s-needs_you' + (n ? ' pulse' : '') }), h('b', null, String(n)), h('span', null, 'need you')),
      h('span', { class: 'sh-item' }, h('span', { class: 'sdot s-working' + (c.working ? ' pulse' : '') }), h('b', null, String(c.working)), h('span', null, 'working')),
      c.done ? h('span', { class: 'sh-item' }, h('span', { class: 'sdot s-done' }), h('b', null, String(c.done)), h('span', null, 'done')) : null,
      elsewhereEnabled() && elsewhereRunningCount() ? h('span', { class: 'sh-item', title: 'Working elsewhere: Goose Desktop, the goose CLI or scheduled jobs (read-only here)' },
        h('span', { class: 'sdot s-elsewhere pulse' }), h('b', null, String(elsewhereRunningCount())), h('span', null, 'elsewhere')) : null);
  };
  // Spec 020: what other programs are running in the native profile, newest first; read-only here.
  const elsewhereRow = (it) => {
    const r = router.current();
    const active = r.view === 'chat' && r.args[0] === it.sessionId;
    const many = it.count > 1;
    const tip = (many ? it.title + ' - ' + it.count + ' sessions, newest: ' + (it.latestTitle || it.sessionId) : it.title)
      + '\nWorking elsewhere: ' + sourceLabel(it) + '\nRead-only in Goose Web: it cannot be stopped or steered from here.';
    return h('a', { class: ['srow', 'srow-elsewhere', active ? 'active' : ''], href: '#/chat/' + encodeURIComponent(it.sessionId), role: 'treeitem', title: tip },
      h('span', { class: 'sdot s-elsewhere' + (it.status === 'running' ? ' pulse' : ' done') }), h('span', { class: 'srow-title' }, it.title),
      many ? h('span', { class: 'sgroup-count', title: it.count + ' sessions' }, '\u00d7' + it.count) : null,
      icon('eye', 11, 'srow-pin'),
      h('span', { class: 'srow-time' }, relTime(it.last * 1000).replace(' ago', '')));
  };

  const navEl = h('nav', { class: 'side-nav', 'aria-label': 'Main' });
  const renderNav = () => {
    const r = router.current();
    navEl.replaceChildren(...NAV.filter((n) => n.id !== 'new' && (!n.admin || (me && me.isAdmin))).map((n) => h('a', {
      class: ['nav-item', r.view === n.id ? 'active' : ''], href: '#' + n.path, title: n.label + ' (g ' + n.key + ')',
    }, icon(n.icon, 16), h('span', null, n.label))));
  };

  const listEl = h('div', { class: 'side-list', role: 'tree', 'aria-label': 'Chats' });
  const sentinel = h('div', { class: 'side-sentinel' });
  const io = new IntersectionObserver((ents) => { if (ents.some((e) => e.isIntersecting)) loadMore(); }, { root: listEl, rootMargin: '200px' });

  const sessionRow = (s) => {
    const r = router.current();
    const active = r.view === 'chat' && r.args[0] === s.sessionId;
    const chat = peekChat(s.sessionId);
    const st = runningElsewhere(s.sessionId) ? 'elsewhere' : statusFor(s.sessionId) || (chat && chat.running ? 'working' : null) || (elsewhereDoneFor(s.sessionId) ? 'done' : null);
    const more = iconBtn('more', 'Chat actions', (e) => { e.preventDefault(); e.stopPropagation(); rowMenu(more, s); }, { size: 'sm', class: 'row-more' });
    return h('a', {
      class: ['srow', active ? 'active' : '', isArchived(s) ? 'archived' : ''], href: '#/chat/' + encodeURIComponent(s.sessionId), role: 'treeitem', title: sessionTitle(s) + '\n' + (s.cwd || ''),
    }, h('span', { class: 'sdot s-' + (st || 'none') + (st === 'working' || st === 'needs_you' || st === 'elsewhere' ? ' pulse' : ''), title: st === 'elsewhere' ? 'Working elsewhere (read-only here)' : st === 'error' ? ((agentFor(s.sessionId) || {}).error || 'Error') : null }), h('span', { class: 'srow-title' }, sessionTitle(s)),
      isPinned(s.sessionId) ? icon('pin', 11, 'srow-pin') : null,
      h('span', { class: 'srow-time' }, relTime((s._meta && s._meta.lastMessageAt) || s.updatedAt).replace(' ago', '')), more);
  };

  const rowMenu = (anchor, s) => {
    const archived = isArchived(s);
    menu(anchor, [
      { label: isPinned(s.sessionId) ? 'Unpin' : 'Pin to top', icon: 'pin', onClick: () => { togglePin(s.sessionId); renderList(); } },
      { label: 'Rename', icon: 'edit', onClick: async () => {
        const v = await promptDialog({ title: 'Rename chat', label: 'Title', value: sessionTitle(s), confirmText: 'Rename' });
        if (v && v.trim()) { try { await rpc.call(G('session/rename'), { sessionId: s.sessionId, title: v.trim() }); patchSession(s.sessionId, { title: v.trim() }); const c = peekChat(s.sessionId); if (c) { c.title = v.trim(); c.emit('state'); } } catch (e) { toastError(e, 'Rename'); } }
      } },
      { label: archived ? 'Unarchive' : 'Archive', icon: 'archive', onClick: async () => {
        try { await rpc.call(G(archived ? 'session/unarchive' : 'session/archive'), { sessionId: s.sessionId }); patchSession(s.sessionId, { _meta: { archivedAt: archived ? null : new Date().toISOString() } }); } catch (e) { toastError(e, 'Archive'); }
      } },
      { label: 'Open in new tab', icon: 'external', onClick: () => window.open('#/chat/' + encodeURIComponent(s.sessionId), '_blank', 'noopener') },
      '-',
      { label: 'Delete…', icon: 'trash', danger: true, onClick: async () => {
        if (!(await confirmDialog({ title: 'Delete chat?', message: '“' + sessionTitle(s) + '” will be permanently deleted.', confirmText: 'Delete', danger: true }))) return;
        try { await rpc.call('session/delete', { sessionId: s.sessionId }); removeSession(s.sessionId); dropChat(s.sessionId); toast('Deleted', { kind: 'success' }); const r = router.current(); if (r.view === 'chat' && r.args[0] === s.sessionId) router.go('/new'); } catch (e) { toastError(e, 'Delete'); }
      } },
    ]);
  };

  const renderList = () => {
    const p = prefs();
    const sb = p.sidebar || {};
    const collapsed = sb.collapsed || {};
    let all = [...sessionsState.items.values()];
    if (!sb.showArchived) all = all.filter((s) => !isArchived(s));
    const pinnedIds = p.pinned || [];
    const pinned = pinnedIds.map((id) => sessionsState.items.get(id)).filter(Boolean);
    const rest = all.filter((s) => !pinnedIds.includes(s.sessionId));
    const nodes = [];
    if (pinned.length) {
      nodes.push(h('div', { class: 'sgroup' }, h('div', { class: 'sgroup-head static' }, icon('pin', 12), h('span', { class: 'sgroup-label' }, 'Pinned'), h('span', { class: 'sgroup-count' }, String(pinned.length))), ...pinned.map(sessionRow)));
    }
    const elsewhere = elsewhereEnabled() && !sessionsState.query ? elsewhereList() : [];
    if (elsewhere.length) {
      const EK = '\u0000elsewhere';
      const isCol = !!collapsed[EK];
      const head = h('button', { type: 'button', class: 'sgroup-head sgroup-elsewhere', 'aria-expanded': isCol ? 'false' : 'true', title: 'Sessions Goose Desktop, the goose CLI or scheduled jobs are working on in your native profile (read-only here)', onclick: () => {
        const c = { ...((prefs().sidebar || {}).collapsed || {}) };
        if (c[EK]) delete c[EK]; else c[EK] = true;
        patchPref('sidebar', { collapsed: c }); renderList();
      } }, icon(isCol ? 'chevronRight' : 'chevronDown', 12), icon('monitor', 13), h('span', { class: 'sgroup-label' }, 'Working elsewhere'), h('span', { class: 'sgroup-count' }, String(elsewhere.length)));
      nodes.push(h('div', { class: 'sgroup' }, head, isCol ? null : elsewhere.map(elsewhereRow)));
    }
    for (const g of groupSessions(rest)) {
      const isCol = !!collapsed[g.path] && !sessionsState.query;
      const head = h('button', { type: 'button', class: 'sgroup-head', 'aria-expanded': isCol ? 'false' : 'true', title: g.path || 'Unknown folder', onclick: () => {
        const c = { ...((prefs().sidebar || {}).collapsed || {}) };
        if (c[g.path]) delete c[g.path]; else c[g.path] = true;
        patchPref('sidebar', { collapsed: c }); renderList();
      } }, icon(isCol ? 'chevronRight' : 'chevronDown', 12), icon('folder', 13), h('span', { class: 'sgroup-label' }, g.label), h('span', { class: 'sgroup-count' }, String(g.sessions.length)),
      iconBtn('plus', 'New chat in ' + g.label, (e) => { e.preventDefault(); e.stopPropagation(); router.go('/new?cwd=' + encodeURIComponent(g.path)); }, { size: 'sm', class: 'sgroup-new' }));
      nodes.push(h('div', { class: 'sgroup' }, head, isCol ? null : g.sessions.map(sessionRow)));
    }
    if (!nodes.length) {
      if (sessionsState.loading) nodes.push(h('div', { class: 'skel-wrap' }, ...Array.from({ length: 6 }, (_, i) => h('div', { class: 'skel', style: { width: (55 + ((i * 29) % 40)) + '%' } }))));
      else if (sessionsState.error) nodes.push(h('div', { class: 'side-empty' }, 'Could not load chats. ', h('button', { type: 'button', class: 'linkbtn', onclick: () => loadSessions() }, 'Retry')));
      else nodes.push(h('div', { class: 'side-empty' }, sessionsState.query ? 'No chats match “' + sessionsState.query + '”' : 'No chats yet. Start one!'));
    }
    if (sessionsState.loading && nodes.length && sessionsState.items.size) nodes.push(h('div', { class: 'side-more' }, h('span', { class: 'spinner' }), ' Loading…'));
    else if (sessionsState.nextCursor) nodes.push(h('button', { type: 'button', class: 'side-more linkbtn', onclick: () => loadMore() }, 'Load more'));
    listEl.replaceChildren(...nodes, sentinel);
  };

  const connPill = h('button', { type: 'button', class: 'conn-pill', onclick: () => rpc.reconnectNow() });
  const renderConn = () => {
    const c = store.get('conn'); const up = store.get('upstream');
    let label = 'Connected', cls = 'ok';
    if (c === 'connecting') { label = 'Connecting…'; cls = 'warn'; }
    else if (c === 'reconnecting') { label = 'Reconnecting…'; cls = 'warn'; }
    else if (c === 'down') { label = 'Offline — retrying'; cls = 'err'; }
    else if (c === 'open' && up === 'starting') { label = 'Goose starting…'; cls = 'warn'; }
    else if (c === 'open' && up === 'down') { label = 'Goose down'; cls = 'err'; }
    connPill.className = 'conn-pill conn-' + cls;
    connPill.title = c === 'open' ? 'Gateway connected; Goose ' + up : 'Click to retry now';
    connPill.replaceChildren(h('span', { class: 'conn-dot' }), h('span', null, label));
  };

  const userBtn = h('button', { type: 'button', class: 'side-user', 'aria-label': 'Account menu' });
  const renderUser = () => {
    const u = (me && me.user) || {};
    const nm = u.displayName || u.username || 'User';
    userBtn.replaceChildren(h('span', { class: 'avatar' }, nm.slice(0, 1).toUpperCase()), h('span', { class: 'side-user-name' }, h('span', null, nm), h('span', { class: 'muted small' }, me && me.isAdmin ? 'Administrator' : (u.username || ''))), icon('more', 14));
  };
  userBtn.addEventListener('click', () => {
    const cur = prefs().theme || 'system';
    menu(userBtn, [
      { header: (me && me.user && me.user.username) || '' },
      { label: 'Account', icon: 'user', onClick: () => router.go('/settings/account') },
      { label: 'Settings', icon: 'settings', hint: 'g ,', onClick: () => router.go('/settings') },
      { label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', onClick: () => ctx.showShortcuts() },
      '-',
      { header: 'Theme' },
      ...THEMES.slice(0, 3).map((t) => ({ label: t.label, icon: t.id === 'light' ? 'sun' : t.id === 'dark' ? 'moon' : 'monitor', active: cur === t.id, onClick: () => setPref('theme', t.id) })),
      { label: 'More themes…', icon: 'palette', onClick: () => router.go('/settings/appearance') },
      '-',
      { label: 'Sign out', icon: 'logout', onClick: () => ctx.logout() },
    ]);
  });

  const el = h('aside', { class: 'sidebar', 'aria-label': 'Sidebar' },
    h('div', { class: 'side-top' },
      h('a', { class: 'brand', href: '#/new' }, logo(26), h('span', { class: 'brand-text' }, h('span', { class: 'brand-name' }, brand.name || 'Goose Web'), brand.tagline ? h('span', { class: 'brand-tag' }, brand.tagline) : null)),
      iconBtn('x', 'Close sidebar', () => ctx.toggleSidebar(false), { class: 'only-mobile' })),
    h('div', { class: 'side-actions' },
      btn('New chat', () => router.go('/new'), { icon: 'plus', variant: 'primary', class: 'side-new', title: 'New chat (Alt+N)' }),
      iconBtn('command', 'Command palette (Ctrl+K)', () => ctx.openPalette())),
    herdBox,
    navEl,
    h('div', { class: 'side-search-row' }, search, filterBtn),
    listEl,
    h('div', { class: 'side-foot' }, userBtn, connPill));

  io.observe(sentinel);
  renderHerd(); renderNav(); renderList(); renderConn(); renderUser();
  const rerenderList = debounce(renderList, 50);
  const offs = [
    bus.on('sessions', rerenderList),
    bus.on('herd', () => { renderHerd(); rerenderList(); }),
    bus.on('elsewhere', () => { renderHerd(); rerenderList(); }),
    store.on('change:asks', renderHerd),
    store.on('change:conn', renderConn),
    store.on('change:upstream', renderConn),
    router.on('route', () => { renderNav(); rerenderList(); }),
    store.on('change:prefs', rerenderList),
  ];
  return { el, search, destroy() { offs.forEach((f) => f()); io.disconnect(); } };
}
