// Goose Web SPA entry: auth flow, app shell, router, RPC wiring, command palette, shortcuts.
import { h, btn, iconBtn, modal, toast, closeTopModal, closeMenu, isMenuOpen, topModal, kbd, copyBtn, empty, errMsg, banner, debounce } from './ui.js';
import { icon, logo } from './icons.js';
import { GET, POST, setCsrf } from './api.js';
import { rpc, G } from './rpc.js';
import { store, bus } from './store.js';
import { router } from './router.js';
import { loadPrefs, applyTheme, setPref, prefs, resolvedTheme } from './prefs.js';
import { addAsk, resetAsks, resolvedElsewhere, ASK_METHODS, gotoAsk, noteToolCallSource } from './asks.js';
import { setHerd, upsertAgent, setMyProfile, refreshBadges, browserNotify, chime, setBaseTitle } from './herd.js';
import { loadSessions, sessionsState, sessionTitle, activityTime, isArchived, refreshSessionsSoon } from './sessions.js';
import { routeNotification, allChats, currentChat, sessionChangedElsewhere, promptCreated } from './chatsession.js';
import { renderLogin, renderChangePassword } from './views/login.js';
import { renderSidebar, NAV } from './views/sidebar.js';
import { renderHome } from './views/home.js';
import { renderChat } from './views/chat.js';
import { renderHerd } from './views/herd.js';
import { renderRecipes, renderRecipeEditor } from './views/recipes.js';
import { renderSkills } from './views/skills.js';
import { renderSchedules } from './views/schedules.js';
import { renderApps } from './views/apps.js';
import { renderExtensions } from './views/extensions.js';
import { renderSettings } from './views/settings.js';
import { renderAdmin } from './views/admin.js';
import qrcode from '../vendor/qrcode.esm.js';

const root = document.getElementById('app');
let shell = null;          // {el, main, sidebar}
let view = null;           // current view {el, destroy, canLeave, focus}
let lastHash = '';
let started = false;
let firstHello = true;

// Apply cached theme immediately (avoid flash) before /api/me/prefs arrives.
try { store.set('prefs', JSON.parse(localStorage.getItem('gw.prefs') || '{}')); } catch { /* */ }
applyTheme();

// ------------------------------------------------------------------ boot / auth
async function boot() {
  root.replaceChildren(h('div', { class: 'boot' }, logo(48), h('div', { class: 'spinner' })));
  const [cfg] = await Promise.all([GET('/api/auth/config', { quiet: true }).catch(() => null)]);
  store.set('authConfig', cfg || { brand: { name: 'Goose Web' }, local: true, oidc: [], ldap: { enabled: false } });
  try {
    const me = await GET('/api/me', { quiet: true });
    if (me && me.user && me.user.mustChangePassword) { showChangePassword(me); return; }
    if (me && me.totpEnrolmentRequired) { showTotpEnrol(me); return; }
    await startApp(me);
  } catch (e) {
    if (e.status === 403 && e.code === 'password_change_required') { showChangePassword(null); return; }
    if (e.status === 403 && e.code === 'totp_enrolment_required') { showTotpEnrol(null); return; }
    if (e.status === 401 || e.status === 403) { showLogin(); return; }
    root.replaceChildren(h('div', { class: 'auth-screen' }, h('div', { class: 'auth-card' }, logo(40), h('h1', null, 'Gateway unreachable'), h('p', { class: 'muted' }, errMsg(e)), btn('Retry', () => boot(), { variant: 'primary', icon: 'refresh' }))));
  }
}

function showLogin() {
  teardown();
  setBaseTitle('Sign in · Goose');
  renderLogin(root, {
    authConfig: store.get('authConfig'),
    onLoggedIn: async (res) => {
      if (res && res.csrf) setCsrf(res.csrf);
      if (res && res.mustChangePassword) { showChangePassword({ user: res.user || {} }); return; }
      try {
        const me = await GET('/api/me', { quiet: true });
        if (me && me.totpEnrolmentRequired) { showTotpEnrol(me); return; }
        await startApp(me);
      } catch (e) {
        if (e.code === 'password_change_required') showChangePassword({ user: res.user || {} });
        else if (e.code === 'totp_enrolment_required') showTotpEnrol(null);
        else toast(errMsg(e), { kind: 'error' });
      }
    },
  });
}

function showChangePassword(me) {
  teardown();
  if (me && me.csrf) setCsrf(me.csrf);
  setBaseTitle('Change password · Goose');
  renderChangePassword(root, {
    me: me || { user: {} }, authConfig: store.get('authConfig'),
    onDone: async () => { toast('Password changed', { kind: 'success' }); boot(); },
    onLogout: () => logout(),
  });
}

// Two-factor is required for this account (Admin > Auth: require it for administrators) and not set up yet: the
// server allows only enrolment until it is (security assessment 2026-11-09 A-8). Same steps as Settings > Two-factor.
async function showTotpEnrol(me) {
  teardown();
  if (me && me.csrf) setCsrf(me.csrf);
  setBaseTitle('Set up two-factor - Goose');
  const card = h('div', { class: 'auth-card' }, logo(40), h('h1', null, 'Set up two-factor sign-in'), h('div', { class: 'spinner' }));
  root.replaceChildren(h('div', { class: 'auth-screen' }, card));
  let r;
  try { r = await POST('/api/me/totp/setup', {}, { quiet: true }); }
  catch (e) { card.replaceChildren(logo(40), h('h1', null, 'Two-factor setup failed'), h('p', { class: 'muted' }, errMsg(e)), btn('Sign out', () => logout())); return; }
  const qr = qrcode(0, 'M'); qr.addData(r.uri); qr.make();
  const code = h('input', { class: 'inp totp-inp', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', placeholder: '123456', 'aria-label': 'Six-digit code' });
  const err = h('div', { class: 'field-error' });
  const verify = async () => {
    err.textContent = '';
    try { await POST('/api/me/totp/enable', { code: code.value.trim() }, { quiet: true }); toast('Two-factor enabled', { kind: 'success' }); boot(); }
    catch (e) { err.textContent = e.status === 400 || e.code === 'invalid_code' ? 'That code is not valid - try the next one.' : errMsg(e); }
  };
  code.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });
  card.replaceChildren(logo(40), h('h1', null, 'Set up two-factor sign-in'),
    h('p', { class: 'muted' }, 'Your administrator requires an authenticator app for this account. Scan the code with Microsoft Authenticator, Google Authenticator or 1Password, then enter the 6-digit code.'),
    h('img', { class: 'qr', alt: 'QR code for your authenticator app', src: qr.createDataURL(5, 8), width: 220, height: 220 }),
    h('div', { class: 'row' }, h('code', { class: 'mono small' }, r.secret), copyBtn(r.secret, 'Copy secret')),
    code, err,
    h('div', { class: 'row' }, btn('Verify & continue', verify, { variant: 'primary' }), btn('Sign out', () => logout())));
  code.focus();
}

async function logout() {
  try { await POST('/api/auth/logout', {}, { quiet: true }); } catch { /* */ }
  teardown();
  store.set('me', null);
  await clearClientState();
  // a fresh page load also drops everything held in memory (chat caches, drafts, asks, ?profile=)
  location.replace('/');
}

// Sign-out on a shared browser: forget folder paths, last folder, pinned chats, effort cache and the
// service-worker shell cache. Only the cosmetic theme settings survive (avoids a flash of the wrong theme).
// Security assessment 2026-11-09 D-8.
const KEEP_PREFS = ['theme', 'accent', 'density', 'fontSize', 'codeTheme', 'reduceMotion'];
async function clearClientState() {
  try {
    let keep = {};
    try { const p = JSON.parse(localStorage.getItem('gw.prefs') || '{}') || {}; for (const k of KEEP_PREFS) if (k in p) keep[k] = p[k]; } catch { keep = {}; }
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k && /^gw[.\-_]/.test(k)) keys.push(k); }
    for (const k of keys) localStorage.removeItem(k);
    if (Object.keys(keep).length) localStorage.setItem('gw.prefs', JSON.stringify(keep));
  } catch { /* storage disabled */ }
  try { sessionStorage.clear(); } catch { /* */ }
  try {
    if (window.caches) { const names = await caches.keys(); await Promise.all(names.filter((n) => n.startsWith('gw-')).map((n) => caches.delete(n))); }
  } catch { /* */ }
}

function teardown() {
  rpc.stop();
  if (view && view.destroy) { try { view.destroy(); } catch { /* */ } }
  view = null;
  if (shell && shell.sidebar && shell.sidebar.destroy) shell.sidebar.destroy();
  shell = null;
  started = false;
}

// ------------------------------------------------------------------ app start
async function startApp(me) {
  store.set('me', me);
  setCsrf(me.csrf);
  await loadPrefs();
  setMyProfile((me.user && me.user.username) || null);
  const qp = new URLSearchParams(location.search);
  rpc.profileParam = me.isAdmin && qp.get('profile') ? qp.get('profile') : null;
  buildShell();
  started = true;
  firstHello = true;
  rpc.start();
  if (!location.hash || location.hash === '#' || location.hash.startsWith('#/login')) history.replaceState(null, '', location.pathname + location.search + '#/new');
  router.start();
  registerSW();
}

const ctx = {
  toggleSidebar(force) {
    if (!shell) return;
    const mobile = window.matchMedia('(max-width: 860px)').matches;
    const cls = mobile ? 'drawer-open' : 'side-hidden';
    const on = force === undefined ? !shell.el.classList.contains(cls) : (mobile ? force : !force);
    shell.el.classList.toggle(cls, on);
    if (mobile && on) { const s = shell.el.querySelector('.sidebar .srow.active, .sidebar .side-new'); if (s) s.focus(); }
  },
  openPalette: () => openPalette(),
  showShortcuts: () => showShortcuts(),
  logout: () => logout(),
};

function buildShell() {
  const sidebar = renderSidebar(ctx);
  const main = h('main', { class: 'main', id: 'main', tabindex: '-1' });
  const upstream = h('div', { class: 'upstream-bar', hidden: true, role: 'status' });
  const backdrop = h('div', { class: 'backdrop', onclick: () => ctx.toggleSidebar(false) });
  const profileBar = rpc.profileParam ? h('div', { class: 'impersonate-bar' }, icon('shield', 14), ' Admin view of ', h('strong', null, rpc.profileParam), '’s profile – actions are audited. ', h('a', { href: '/#/herd' }, 'Back to my profile')) : null;
  // Spec 018: administrators see this bar on every page while a prompt guard is on and its classifier is down.
  const guardBar = h('div', { class: 'upstream-bar warn guard-bar', hidden: true, role: 'status' });
  const el = h('div', { class: 'shell' }, h('div', { class: 'side-wrap' }, sidebar.el), backdrop, h('div', { class: 'main-wrap' }, profileBar, upstream, guardBar, main));
  root.replaceChildren(el);
  shell = { el, main, sidebar, upstream };
  const renderUp = () => {
    const st = store.get('upstream'); const conn = store.get('conn');
    let text = '';
    if (conn === 'down') text = 'Cannot reach the gateway. Retrying…';
    else if (st === 'starting') text = 'Starting your Goose agent…';
    else if (st === 'down') text = 'Your Goose agent is not running. The gateway restarts it automatically.';
    upstream.hidden = !text;
    upstream.replaceChildren(text ? icon(st === 'starting' ? 'activity' : 'alert', 14) : '', text, conn === 'down' ? h('button', { type: 'button', class: 'linkbtn', onclick: () => rpc.reconnectNow() }, 'Retry now') : '');
    upstream.className = 'upstream-bar ' + (st === 'starting' ? 'info' : 'warn');
  };
  store.on('change:upstream', renderUp); store.on('change:conn', renderUp); renderUp();
  const renderGuard = () => {
    const g = store.get('guardHealth'); const me = store.get('me');
    const show = !!(me && me.isAdmin && g && g.inUse && !g.healthy);
    guardBar.hidden = !show;
    guardBar.replaceChildren(...(show ? [icon('shield', 14), ' Prompt guard: the classifier is unavailable' + (g.reason ? ' (' + String(g.reason).replace(/\.+$/, '') + ')' : '') + '. Prompts and tool calls are allowed without it (fail open); rules still apply. ', h('a', { href: '#/admin/guard' }, 'Admin > Prompt guard')] : []));
  };
  store.on('change:guardHealth', renderGuard); store.on('change:me', renderGuard); renderGuard();
}

// ------------------------------------------------------------------ routing
const ROUTES = {
  '': (q) => renderHome(ctx, q.query),
  new: (q) => renderHome(ctx, q.query),
  chat: (q) => q.args[0] ? renderChat(ctx, q.args[0]) : renderHome(ctx, q.query),
  herd: () => renderHerd(ctx),
  recipes: (q) => q.args[0] === 'edit' ? renderRecipeEditor(ctx, q.args[1] || 'new') : renderRecipes(ctx),
  skills: () => renderSkills(ctx),
  schedules: () => renderSchedules(ctx),
  apps: (q) => renderApps(ctx, q.args[0]),
  extensions: () => renderExtensions(ctx),
  settings: (q) => renderSettings(ctx, q.args[0]),
  admin: (q) => renderAdmin(ctx, q.args[0]),
  login: () => { router.go('/new', { replace: true }); return null; },
};

let routing = false; let routePending = false;
router.on('route', async (r) => {
  if (!started || !shell) return;
  if (routing) { routePending = true; return; }
  routing = true;
  try {
    if (view && view.canLeave && location.hash !== lastHash) {
      let ok = true;
      try { ok = await view.canLeave(); } catch { ok = true; }
      if (!ok) { history.replaceState(null, '', lastHash || '#/new'); return; }
    }
    lastHash = location.hash;
    store.set('route', r);
    if (view && view.destroy) { try { view.destroy(); } catch (e) { console.error(e); } }
    view = null;
    closeMenu();
    const fn = Object.prototype.hasOwnProperty.call(ROUTES, r.view) ? ROUTES[r.view] : null;
    let v;
    try {
      v = fn ? fn(r) : { el: h('div', { class: 'view view-page' }, h('div', { class: 'page-body' }, empty('alert', 'Page not found', 'Nothing lives at ' + r.path, btn('New chat', () => router.go('/new'), { variant: 'primary' })))) };
    } catch (e) {
      console.error(e);
      v = { el: h('div', { class: 'view view-page' }, h('div', { class: 'page-body' }, banner('error', 'This page failed to render: ' + errMsg(e)))) };
    }
    if (!v) return;
    view = v;
    shell.main.replaceChildren(v.el);
    shell.main.scrollTop = 0;
    if (window.matchMedia('(max-width: 860px)').matches) shell.el.classList.remove('drawer-open');
    requestAnimationFrame(() => { if (v.focus) v.focus(); });
  } finally {
    routing = false;
    if (routePending) { routePending = false; router.emit('route', router.current()); }
  }
});

window.addEventListener('beforeunload', (e) => {
  const busy = allChats().some((c) => c.queue && c.queue.length);
  if (busy) { e.preventDefault(); e.returnValue = ''; }
});

// ------------------------------------------------------------------ RPC wiring
rpc.on('hello', (hello) => {
  if (!hello) return;
  if (hello.profile) setMyProfile(hello.profile);
  store.set('guardHealth', hello.guard || null);
  resetAsks(hello.asks || []);
  setHerd(hello.herd || []);
  loadSessions({ reset: true });
  if (!firstHello) {
    const cur = currentChat();
    for (const c of allChats()) {
      if (c === cur) c.reload().catch(() => {});
      else c.loaded = false;
    }
  }
  firstHello = false;
  refreshBadges();
});
// A handshake that never reached _gw/hello may mean the session expired: probe /api/me (a 401 there routes to login).
let lastAuthProbe = 0;
rpc.on('handshake_failed', () => {
  if (Date.now() - lastAuthProbe < 10000) return;
  lastAuthProbe = Date.now();
  GET('/api/me').catch(() => {});
});
rpc.on('request', (msg) => {
  if (ASK_METHODS[msg.method]) { addAsk(msg); return; }
  rpc.respondError(msg.id, -32601, 'Goose Web does not support ' + msg.method);
});
rpc.on('session/update', (p) => { noteToolCallSource(p); routeNotification('session/update', p); });
rpc.on(G('session/update'), (p) => routeNotification(G('session/update'), p));
rpc.on('_gw/ask_resolved', (p) => resolvedElsewhere(p || {}));
rpc.on('_gw/session_changed', (p) => sessionChangedElsewhere(p || {}));
rpc.on('_gw/prompt_created', (p) => promptCreated(p || {}));
rpc.on('_gw/sessions_changed', () => refreshSessionsSoon());
rpc.on('_gw/herd_update', (p) => { const a = p && (p.agent || p); if (a && a.sessionId) upsertAgent(a); });
rpc.on('_gw/upstream', (p) => {
  const prev = store.get('upstream');
  store.set('upstream', (p && p.state) || 'unknown');
  if (p && p.state === 'down' && p.error) toast('Goose agent stopped: ' + p.error, { kind: 'error', timeout: 8000 });
  if (p && p.state === 'ready' && prev === 'down') toast('Goose agent is back', { kind: 'success' });
});
rpc.on('_gw/guard', (p) => store.set('guardHealth', p || null));
rpc.on('_gw/notice', (p) => {
  const lvl = (p && p.level) || 'info';
  toast((p && p.message) || '', { kind: lvl === 'warning' ? 'warn' : lvl === 'error' ? 'error' : lvl === 'success' ? 'success' : 'info', timeout: lvl === 'error' ? 10000 : 6000 });
});
rpc.on(G('providers/authentication/device-code'), (p) => {
  let left = Number(p.expiresIn) || 600;
  const verifyUrl = httpsUrl(p.verificationUri); // only an https: URL becomes a link; anything else is shown as text
  const timer = h('span', { class: 'muted small' });
  const tick = () => { timer.textContent = 'Expires in ' + Math.floor(left / 60) + ':' + String(left % 60).padStart(2, '0'); left--; if (left < 0) { clearInterval(iv); m.close(); } };
  const iv = setInterval(tick, 1000);
  const m = modal({ title: 'Sign in to ' + (p.providerId || 'provider'), size: 'sm', onClose: () => clearInterval(iv),
    body: h('div', { class: 'stack center' }, h('p', { class: 'muted' }, 'Open the link below and enter this code:'), h('div', { class: 'device-code mono' }, p.userCode), copyBtn(p.userCode, 'Copy code'),
      verifyUrl ? h('a', { href: verifyUrl, target: '_blank', rel: 'noopener noreferrer', class: 'btn btn-primary' }, icon('external', 14), ' Open ', safeHost(verifyUrl))
        : h('div', { class: 'mono small' }, String(p.verificationUri || '')), timer),
    footer: [btn('Close', () => m.close())] });
  tick();
});
function safeHost(u) { try { return new URL(u).host; } catch { return 'link'; } }
function httpsUrl(u) { try { const x = new URL(String(u || '')); return x.protocol === 'https:' ? x.href : null; } catch { return null; } }

bus.on('ask:new', (ask, opts) => {
  refreshBadges();
  if ((opts && opts.silent) || ask.kind === 'recipe_params') return;
  const p = prefs();
  const events = (p.notifications && p.notifications.events) || ['needs_you', 'done', 'error'];
  const r = router.current();
  const viewing = r.view === 'chat' && r.args[0] === ask.sessionId && document.visibilityState === 'visible';
  if (viewing) return;
  const s = ask.sessionId && sessionsState.items.get(ask.sessionId);
  const where = s ? sessionTitle(s) : 'A chat';
  const what = ask.kind === 'permission' ? 'wants to run ' + ask.title : ask.title;
  if (document.visibilityState === 'visible') {
    toast(what, { title: where + ' needs you', kind: 'warn', timeout: 12000, actions: [{ label: 'Review', variant: 'primary', onClick: () => gotoAsk(ask) }] });
  } else if (events.includes('needs_you')) browserNotify(where + ' needs you', what, ask.sessionId);
  if (p.notifications && p.notifications.sound && events.includes('needs_you')) chime('needs_you');
});
bus.on('ask:resolved', () => refreshBadges());
store.on('change:asks', () => refreshBadges());

let authLost = false;
bus.on('unauthorized', () => {
  if (authLost || !started) return;
  authLost = true;
  toast('Your sign-in expired. Please sign in again.', { kind: 'warn' });
  teardown(); showLogin();
  setTimeout(() => { authLost = false; }, 1500);
});
bus.on('password-change-required', () => { showChangePassword(store.get('me')); });
bus.on('totp-enrolment-required', () => { showTotpEnrol(null); });

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    const c = currentChat();
    if (c && rpc.ready) rpc.call('_gw/seen', { sessionId: c.id }).catch(() => {});
    refreshBadges();
    if (started && rpc.ready) refreshSessionsSoon(300);
    if (started && !rpc.ready) rpc.reconnectNow();
  }
});

// ------------------------------------------------------------------ command palette
// Open palette / shortcuts dialogs are tracked by reference, never found with document.querySelector:
// untrusted markup could carry the same class names (security assessment 2026-11-09 D-7).
let paletteModal = null;
let shortcutsModal = null;
function openPalette(initial = '') {
  if (!started) return;
  if (paletteModal) return;
  const inp = h('input', { class: 'palette-input', type: 'text', placeholder: 'Jump to a chat, page or action…', 'aria-label': 'Command palette', autocomplete: 'off', spellcheck: 'false', value: initial });
  const list = h('div', { class: 'palette-list', role: 'listbox' });
  let items = []; let sel = 0; let recipes = null;
  const me = store.get('me') || {};
  const actions = () => {
    const a = [
      { group: 'Actions', label: 'New chat', icon: 'plus', hint: 'Alt+N', run: () => router.go('/new') },
      { group: 'Actions', label: 'New chat in folder…', icon: 'folderPlus', run: async () => { const { pickFolder } = await import('./views/folderpicker.js'); const p = await pickFolder({ title: 'Start a chat in…' }); if (p) router.go('/new?cwd=' + encodeURIComponent(p)); } },
      { group: 'Actions', label: 'Toggle sidebar', icon: 'menu', run: () => ctx.toggleSidebar() },
      { group: 'Actions', label: 'Switch to ' + (resolvedTheme() === 'light' ? 'dark' : 'light') + ' theme', icon: resolvedTheme() === 'light' ? 'moon' : 'sun', run: () => setPref('theme', resolvedTheme() === 'light' ? 'dark' : 'light') },
      { group: 'Actions', label: 'Reload chat list', icon: 'refresh', run: () => loadSessions({ reset: true }) },
      { group: 'Actions', label: 'Keyboard shortcuts', icon: 'keyboard', hint: '?', run: () => showShortcuts() },
      { group: 'Actions', label: 'Sign out', icon: 'logout', run: () => logout() },
    ];
    for (const n of NAV) if (!n.admin || me.isAdmin) a.push({ group: 'Go to', label: n.label, icon: n.icon, hint: 'g ' + n.key, run: () => router.go(n.path) });
    const st = [['settings/providers', 'Models & Providers'], ['settings/prompts', 'System prompts'], ['settings/appearance', 'Appearance'], ['settings/notifications', 'Notifications'], ['settings/account', 'Account & security']];
    for (const [p, l] of st) a.push({ group: 'Go to', label: 'Settings › ' + l, icon: 'settings', run: () => router.go('/' + p) });
    if (me.isAdmin) for (const [p, l] of [['users', 'Users'], ['teams', 'Teams & policy'], ['system', 'System'], ['audit', 'Audit log'], ['logs', 'Logs']]) a.push({ group: 'Go to', label: 'Admin › ' + l, icon: 'admin', run: () => router.go('/admin/' + p) });
    return a;
  };
  const sessionItems = () => [...sessionsState.items.values()].filter((s) => !isArchived(s)).sort((a, b) => activityTime(b) - activityTime(a)).slice(0, 300)
    .map((s) => ({ group: 'Chats', label: sessionTitle(s), sub: s.cwd || '', icon: 'chat', run: () => router.go('/chat/' + encodeURIComponent(s.sessionId)) }));
  const askItems = () => [...store.get('asks').values()].map((a) => ({ group: 'Needs you', label: a.title, sub: (sessionsState.items.get(a.sessionId) && sessionTitle(sessionsState.items.get(a.sessionId))) || '', icon: 'alert', run: () => gotoAsk(a) }));
  const recipeItems = () => (recipes || []).map((r) => ({ group: 'Recipes', label: 'Run recipe: ' + ((r.recipe && r.recipe.title) || r.id), sub: (r.recipe && r.recipe.description) || '', icon: 'recipe', run: () => router.go('/new?recipe=' + encodeURIComponent(r.id)) }));
  const score = (it, toks) => {
    const hay = (it.label + ' ' + (it.sub || '') + ' ' + it.group).toLowerCase();
    let s = 0;
    for (const t of toks) { const i = hay.indexOf(t); if (i < 0) return -1; s += i === 0 ? 3 : hay[i - 1] === ' ' ? 2 : 1; }
    return s;
  };
  const draw = () => {
    const q = inp.value.trim().toLowerCase();
    const toks = q.split(/\s+/).filter(Boolean);
    const all = [...askItems(), ...(q ? sessionItems() : sessionItems().slice(0, 8)), ...actions(), ...recipeItems()];
    items = toks.length ? all.map((it) => ({ it, s: score(it, toks) })).filter((x) => x.s >= 0).sort((a, b) => b.s - a.s).slice(0, 60).map((x) => x.it) : all.slice(0, 60);
    if (toks.length) { const order = ['Needs you', 'Chats', 'Go to', 'Actions', 'Recipes']; items.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group)); }
    sel = Math.min(sel, Math.max(0, items.length - 1));
    const nodes = []; let g = null;
    items.forEach((it, i) => {
      if (it.group !== g) { g = it.group; nodes.push(h('div', { class: 'palette-group' }, g)); }
      nodes.push(h('div', { class: ['palette-item', i === sel ? 'active' : ''], role: 'option', 'aria-selected': String(i === sel), dataset: { i: String(i) }, onmousemove: () => { if (sel !== i) { sel = i; mark(); } }, onclick: () => choose(i) },
        icon(it.icon || 'dot', 15), h('div', { class: 'palette-main' }, h('div', { class: 'palette-label' }, it.label), it.sub ? h('div', { class: 'palette-sub' }, it.sub) : null), it.hint ? h('span', { class: 'menu-hint' }, it.hint) : null));
    });
    list.replaceChildren(...(nodes.length ? nodes : [h('div', { class: 'palette-empty' }, 'No results')]));
  };
  const mark = () => { list.querySelectorAll('.palette-item').forEach((n) => { const on = Number(n.dataset.i) === sel; n.classList.toggle('active', on); n.setAttribute('aria-selected', String(on)); if (on) n.scrollIntoView({ block: 'nearest' }); }); };
  const choose = (i) => { const it = items[i]; if (!it) return; m.close(); setTimeout(() => it.run(), 0); };
  inp.addEventListener('input', debounce(() => { sel = 0; draw(); }, 40));
  inp.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(sel); }
  });
  const m = modal({ body: h('div', { class: 'palette' }, h('div', { class: 'palette-head' }, icon('search', 16), inp, kbd('Esc')), list), size: 'md', className: 'palette-modal', onClose: () => { if (paletteModal === m) paletteModal = null; } });
  paletteModal = m;
  draw();
  setTimeout(() => inp.focus(), 0);
  rpc.call(G('recipes/list'), {}).then((r) => { recipes = r.recipes || []; if (document.body.contains(list)) draw(); }).catch(() => {});
}

// ------------------------------------------------------------------ shortcuts
const SHORTCUTS = [
  ['General', [[['Ctrl', 'K'], 'Command palette'], [['?'], 'Keyboard shortcuts'], [['Alt', 'N'], 'New chat'], [['/'], 'Search chats'], [['Alt', '↑/↓'], 'Previous / next chat'], [['Esc'], 'Close dialog or menu'], [['Ctrl', 'B'], 'Toggle sidebar']]],
  ['Go to', NAV.map((n) => [['g', n.key], n.label])],
  ['Chat', [[['Enter'], 'Send (configurable)'], [['Shift', 'Enter'], 'New line'], [['Ctrl', 'Enter'], 'Send / steer while running'], [['Ctrl', '.'], 'Stop the agent'], [['F2'], 'Rename chat'], [['/'], 'Slash commands (in composer)'], [['@'], 'Mention an agent (in composer)']]],
  ['Editors', [[['Ctrl', 'S'], 'Save recipe']]],
];
function showShortcuts() {
  if (shortcutsModal) return;
  const m = shortcutsModal = modal({ onClose: () => { shortcutsModal = null; }, title: 'Keyboard shortcuts', size: 'lg', body: h('div', { class: 'shortcuts grid2' }, ...SHORTCUTS.map(([g, rows]) => h('div', { class: 'sc-group' }, h('h4', null, g), ...rows.map(([keys, label]) => h('div', { class: 'sc-row' }, h('span', null, label), kbd(...keys)))))), footer: [btn('Close', () => m.close())] });
}

const isTyping = (t) => t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
let gPending = 0;
document.addEventListener('keydown', (e) => {
  if (!started) return;
  const mod = e.ctrlKey || e.metaKey;
  if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') { e.preventDefault(); if (paletteModal) paletteModal.close(); else openPalette(); return; }
  if (e.key === 'Escape') {
    if (isMenuOpen()) { closeMenu(); e.preventDefault(); return; }
    if (topModal()) { if (closeTopModal()) e.preventDefault(); return; }
    if (shell && shell.el.classList.contains('drawer-open')) { shell.el.classList.remove('drawer-open'); return; }
    return;
  }
  if (topModal()) return;
  if (e.altKey && !mod && (e.key === 'n' || e.key === 'N' || e.code === 'KeyN')) { e.preventDefault(); router.go('/new'); return; }
  if (mod && !e.shiftKey && e.key.toLowerCase() === 'b') { e.preventDefault(); ctx.toggleSidebar(); return; }
  if (e.altKey && !mod && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
    const rows = shell && shell.sidebar && shell.sidebar.el ? [...shell.sidebar.el.querySelectorAll('.srow')] : [];
    if (!rows.length) return;
    e.preventDefault();
    let i = rows.findIndex((r) => r.classList.contains('active'));
    i = e.key === 'ArrowDown' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
    rows[i].click();
    return;
  }
  if (isTyping(e.target) || mod || e.altKey) return;
  if (e.key === '?') { e.preventDefault(); showShortcuts(); return; }
  if (e.key === '/') { if (shell && shell.sidebar.search) { e.preventDefault(); if (window.matchMedia('(max-width: 860px)').matches) ctx.toggleSidebar(true); shell.sidebar.search.focus(); } return; }
  if (gPending && Date.now() - gPending < 1200) {
    gPending = 0;
    const n = NAV.find((x) => x.key === e.key.toLowerCase() && (!x.admin || (store.get('me') || {}).isAdmin));
    if (n) { e.preventDefault(); router.go(n.path); }
    return;
  }
  if (e.key === 'g') { gPending = Date.now(); }
});

// ------------------------------------------------------------------ PWA
function registerSW() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch((e) => console.warn('SW registration failed', e));
}

// Badge refresh as herd counts change
bus.on('herd', () => refreshBadges());

boot();
