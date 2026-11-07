// Admin console: users, teams (+policy, items), hints library, auth providers, settings, system, ownership, host tasks, audit, logs.
import { h, btn, iconBtn, pageHeader, toast, toastError, confirmDialog, modal, empty, skeleton, banner, errMsg, input, textarea, field, tabs, toggle, select, checkbox, table, section, debounce, prettyJson, relTime, fmtDateTime, copyBtn, spinner, actionBtn, menu, badge } from '../ui.js';
import { icon } from '../icons.js';
import { GET, POST, PUT, PATCH, DEL, qs } from '../api.js';
import { store } from '../store.js';
import { setBaseTitle } from '../herd.js';
import { router } from '../router.js';
import { mdElement } from '../markdown.js';

const TABS = [
  { id: 'users', label: 'Users', icon: 'users' },
  { id: 'teams', label: 'Teams & policy', icon: 'shield' },
  { id: 'hints', label: 'Hints library', icon: 'hint' },
  { id: 'auth', label: 'Auth providers', icon: 'key' },
  { id: 'settings', label: 'Settings', icon: 'sliders' },
  { id: 'system', label: 'System', icon: 'cpu' },
  { id: 'ownership', label: 'Ownership check', icon: 'lock' },
  { id: 'hosttasks', label: 'Host tasks', icon: 'schedule' },
  { id: 'ipblocks', label: 'Blocked addresses', icon: 'shield' },
  { id: 'audit', label: 'Audit log', icon: 'scroll' },
  { id: 'logs', label: 'Logs', icon: 'terminal' },
];

const arr = (r, k) => Array.isArray(r) ? r : (r && Array.isArray(r[k]) ? r[k] : []);

export function renderAdmin(ctx, tab) {
  const me = store.get('me');
  if (!me || !me.isAdmin) {
    return { el: h('div', { class: 'view view-page' }, h('div', { class: 'page-body' }, empty('lock', 'Administrators only', 'You do not have access to the admin console.'))) };
  }
  const cur = TABS.find((t) => t.id === tab) || TABS[0];
  setBaseTitle(cur.label + ' · Admin · Goose');
  const nav = h('nav', { class: 'settings-nav', 'aria-label': 'Admin sections' },
    ...TABS.map((t) => h('a', { href: '#/admin/' + t.id, class: ['snav-item', t.id === cur.id ? 'active' : ''] }, icon(t.icon, 15), h('span', null, t.label))));
  const body = h('div', { class: 'settings-body' });
  const mob = select(TABS.map((t) => ({ value: t.id, label: t.label })), cur.id, { class: 'inp only-mobile', 'aria-label': 'Admin section', onchange: (e) => router.go('/admin/' + e.target.value) });
  const el = h('div', { class: 'view view-page view-settings' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Admin'), null, [mob]),
    h('div', { class: 'page-body settings-layout' }, nav, body));
  const R = { users: usersTab, teams: teamsTab, hints: hintsLibTab, auth: authTab, settings: settingsTab, system: systemTab, ownership: ownershipTab, hosttasks: hostTasksTab, ipblocks: ipBlocksTab, audit: auditTab, logs: logsTab };
  let inner = null;
  try { inner = R[cur.id](body) || null; } catch (e) { console.error(e); body.replaceChildren(banner('error', errMsg(e))); }
  return { el, destroy() { if (inner && inner.destroy) inner.destroy(); } };
}

// shared caches
async function loadTeams() { return arr(await GET('/api/admin/teams'), 'teams'); }
async function loadHints() { return arr(await GET('/api/admin/hints'), 'hints'); }
async function loadUsers() { return arr(await GET('/api/admin/users'), 'users'); }

function multiPick(options, selected, { empty: emptyText = 'None available' } = {}) {
  // options [{value,label,sub}] -> checkbox list; returns {el, get()}
  const sel = new Set(selected || []);
  const el = h('div', { class: 'chk-list' }, options.length ? options.map((o) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: sel.has(o.value), onchange: (e) => { if (e.target.checked) sel.add(o.value); else sel.delete(o.value); } }), h('span', null, o.label, o.sub ? h('span', { class: 'muted small' }, ' ' + o.sub) : null))) : h('div', { class: 'muted small' }, emptyText));
  return { el, get: () => [...sel] };
}
function showSecretOnce(title, label, value) {
  const m = modal({ title, size: 'md', body: h('div', { class: 'stack' }, banner('warn', 'Shown only once. Give it to the user over a secure channel; they must change it at next sign-in.'), h('div', { class: 'row' }, h('code', { class: 'mono token-show' }, value), copyBtn(value, 'Copy ' + label))), footer: [btn('Done', () => m.close(), { variant: 'primary' })] });
}

// ===================================================================== Users
function usersTab(body) {
  let users = [], teams = [], hints = [], q = '';
  const out = h('div', null, skeleton(6));
  const search = input({ type: 'search', placeholder: 'Search users…', class: 'inp inp-sm' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); draw(); }, 120));
  body.replaceChildren(h('div', { class: 'row' }, search, h('span', { class: 'grow' }), btn('New user', () => userDialog(null), { icon: 'plus', variant: 'primary', size: 'sm' })), out);
  const teamName = (id) => (teams.find((t) => t.id === id) || {}).name || id;
  const draw = () => {
    const rows = users.filter((u) => !q || (u.username + ' ' + (u.displayName || '') + ' ' + (u.email || '')).toLowerCase().includes(q));
    out.replaceChildren(table([
      { label: 'User', render: (u) => h('div', { class: 'row' }, h('span', { class: 'avatar' }, (u.displayName || u.username || '?').slice(0, 1).toUpperCase()), h('div', null, h('div', { class: 'strong' }, u.displayName || u.username), h('div', { class: 'muted small' }, u.username + (u.email ? ' · ' + u.email : '')))) },
      { label: 'Role', render: (u) => u.role === 'admin' ? badge('admin', 'accent') : badge('user') },
      { label: 'Team', render: (u) => u.team ? h('span', { class: 'small' }, teamName(u.team)) : u.role === 'admin' ? h('span', { class: 'muted small' }, '—') : badge('no team', 'warn') },
      { label: 'Auth', render: (u) => h('span', { class: 'row' }, badge(u.authSource || 'local'), u.totpEnabled ? badge('2FA', 'ok') : null) },
      { label: 'Profile', render: (u) => badge(u.profileMode || 'isolated') },
      { label: 'Status', render: (u) => u.disabled ? badge('disabled', 'err') : u.locked || u.lockedUntil ? badge('locked', 'warn') : u.mustChangePassword ? badge('must change pw', 'warn') : badge('active', 'ok') },
      { label: 'Last sign-in', render: (u) => u.lastLogin ? h('span', { title: fmtDateTime(u.lastLogin) }, relTime(u.lastLogin)) : h('span', { class: 'muted' }, 'never') },
      { label: '', class: 'right', render: (u) => iconBtn('more', 'Actions', (ev) => menu(ev.currentTarget, [
        { label: 'Edit…', icon: 'edit', onClick: () => userDialog(u) },
        { label: 'Reset password', icon: 'key', hidden: (u.authSource || 'local') !== 'local', onClick: async () => {
          if (!(await confirmDialog({ title: 'Reset password for ' + u.username + '?', message: 'A temporary password is generated; the user must change it at next sign-in.', confirmText: 'Reset' }))) return;
          try { const r = await POST('/api/admin/users/' + encodeURIComponent(u.id) + '/reset-password', {}); showSecretOnce('Temporary password', 'password', r.tempPassword); load(); } catch (e) { toastError(e); }
        } },
        { label: 'Unlock', icon: 'lock', onClick: async () => { try { await POST('/api/admin/users/' + encodeURIComponent(u.id) + '/unlock', {}); toast('Unlocked', { kind: 'success' }); load(); } catch (e) { toastError(e); } } },
        { label: 'Reset two-factor', icon: 'shield', hidden: !u.totpEnabled || u.id === (store.get('me').user || {}).id, onClick: async () => {
          if (!(await confirmDialog({ title: 'Reset two-factor for ' + u.username + '?', message: 'Use this when the user lost their authenticator. Two-factor is removed, the account is unlocked, all of their sessions end and their API tokens are revoked. They sign in with their password only and should enrol a new authenticator straight away.', confirmText: 'Reset two-factor', danger: true }))) return;
          try { const r = await POST('/api/admin/users/' + encodeURIComponent(u.id) + '/reset-totp', {}); toast('Two-factor removed for ' + u.username + (r.tokensRevoked ? ' (' + r.tokensRevoked + ' API token(s) revoked)' : ''), { kind: 'success' }); load(); } catch (e) { toastError(e); }
        } },
        { label: 'View effective hints', icon: 'hint', onClick: () => effectiveHints(u) },
        { label: 'Re-provision profile', icon: 'refresh', onClick: async () => {
          try { const r = await POST('/api/admin/users/' + encodeURIComponent(u.id) + '/provision', {}); modal({ title: 'Provisioned ' + u.username, body: h('div', { class: 'stack' }, (r.changes || []).length ? h('ul', { class: 'plain-list small' }, ...r.changes.map((c) => h('li', null, typeof c === 'string' ? c : prettyJson(c)))) : h('div', { class: 'muted' }, 'No changes needed.'), r.restartPending ? banner('info', 'The worker restarts when the user is idle.') : null) }); } catch (e) { toastError(e); }
        } },
        { label: u.disabled ? 'Enable account' : 'Disable account', icon: u.disabled ? 'check' : 'x', onClick: async () => {
          try { await PATCH('/api/admin/users/' + encodeURIComponent(u.id), { disabled: !u.disabled }); toast(u.disabled ? 'Enabled' : 'Disabled', { kind: 'success' }); load(); } catch (e) { toastError(e); }
        } },
        { label: 'Open their Herd / chats', icon: 'external', onClick: () => window.open('/?profile=' + encodeURIComponent(u.username) + '#/herd', '_blank', 'noopener') },
        '-',
        { label: 'Delete…', icon: 'trash', danger: true, hidden: u.id === (store.get('me').user || {}).id, onClick: () => deleteUser(u) },
      ], { align: 'right' })) },
    ], rows, { empty: 'No users', rowClass: (u) => u.disabled ? 'muted-row' : '' }));
  };
  const effectiveHints = async (u) => {
    try {
      const r = await GET('/api/admin/users/' + encodeURIComponent(u.id) + '/hints');
      modal({ title: 'Effective hints: ' + u.username, size: 'lg', body: h('div', { class: 'stack' },
        h('div', { class: 'muted small' }, (r.team ? 'Team: ' + r.team + ' · ' : '') + (r.path || '')),
        r.note ? banner('info', r.note) : null,
        r.personalDropped ? banner('warn', 'This user has personal hints, but their team does not allow personal hints, so Goose does not get them.') : null,
        h('pre', { class: 'json tall' }, r.effective || '(empty)')) });
    } catch (e) { toastError(e); }
  };
  const deleteUser = async (u) => {
    let purge = false;
    const ok = await confirmDialog({ title: 'Delete ' + u.username + '?', message: 'The account is removed and its Goose worker stopped.', confirmText: 'Delete user', danger: true,
      extra: h('div', { class: 'stack-sm' }, checkbox(false, 'Also permanently delete the profile folder (sessions, recipes, config)', (v) => { purge = v; }), h('div', { class: 'muted small' }, 'Otherwise the folder is archived to _deleted\\' + u.username + '-<timestamp>.')) });
    if (!ok) return;
    try { await DEL('/api/admin/users/' + encodeURIComponent(u.id) + (purge ? '?purgeProfile=1' : '')); toast('User deleted', { kind: 'success' }); load(); } catch (e) { toastError(e); }
  };
  const userDialog = (u) => {
    const isNew = !u;
    const username = input({ value: u ? u.username : '', placeholder: 'jdoe', disabled: !isNew, autocomplete: 'off' });
    const dn = input({ value: (u && u.displayName) || '' });
    const em = input({ value: (u && u.email) || '', type: 'email' });
    const role = select([{ value: 'user', label: 'User' }, { value: 'admin', label: 'Administrator' }], (u && u.role) || 'user');
    const src = select([{ value: 'local', label: 'Local password' }, { value: 'ldap', label: 'LDAP / AD' }, { value: 'oidc', label: 'OIDC / SSO' }], (u && u.authSource) || 'local');
    const mode = select([{ value: 'isolated', label: 'Isolated profile (recommended)' }, { value: 'native', label: 'Native profile (the service account’s own %APPDATA% Goose)' }], (u && u.profileMode) || 'isolated');
    const pw = input({ type: 'password', autocomplete: 'new-password', placeholder: 'leave blank to generate a temporary password' });
    const defTeam = store.get('adminDefaultTeam');
    const tp = select([{ value: '', label: 'No team (can sign in, cannot chat)' }, ...teams.map((t) => ({ value: String(t.id), label: t.name }))], u ? String(u.team || '') : String(defTeam || ''));
    const hp = multiPick(hints.map((x) => ({ value: x.id, label: x.name, sub: x.description || '' })), u ? u.hints : [], { empty: 'Hints library is empty' });
    const ov = textarea({ rows: 4, class: 'inp mono', value: u && u.policyOverrides && Object.keys(u.policyOverrides).length ? prettyJson(u.policyOverrides) : '', placeholder: '{ "allow_shell": false }' });
    const err = h('div', { class: 'field-error' });
    const m = modal({ title: isNew ? 'New user' : 'Edit ' + u.username, size: 'lg',
      body: h('div', { class: 'stack' },
        h('div', { class: 'grid2' }, field('Username', username), field('Display name', dn), field('Email', em), field('Role', role), field('Sign-in', src), field('Profile mode', mode, 'Native maps to the Windows user’s real Goose profile – use for one admin at most.')),
        isNew ? field('Initial password', pw, 'The user must change it at the first sign-in. At least 12 characters with upper- and lower-case letters, a number and a symbol.') : null,
        field('Team', tp, 'One team per user. The team decides hints, providers, models, approval modes and folders. Administrators are not restricted.'), field('Extra hints for this user', hp.el, 'Hints documents for this user only. They come before the team hints, which take precedence.'),
        !isNew ? h('details', null, h('summary', null, 'Policy overrides (advanced)'), field(null, ov, 'JSON object merged over the team policy for this user only.')) : null, err),
      footer: [btn('Cancel', () => m.close()), btn(isNew ? 'Create user' : 'Save', async () => {
        err.textContent = '';
        const b = { displayName: dn.value.trim() || undefined, email: em.value.trim() || undefined, role: role.value, team: tp.value ? Number(tp.value) : null, hints: hp.get(), profileMode: mode.value, authSource: src.value };
        if (!isNew && ov.value.trim()) { try { b.policyOverrides = JSON.parse(ov.value); } catch { err.textContent = 'Policy overrides must be valid JSON'; return; } } else if (!isNew) b.policyOverrides = {};
        try {
          if (isNew) {
            if (!/^[A-Za-z0-9._-]{2,64}$/.test(username.value.trim())) { err.textContent = 'Username: 2–64 letters, digits, . _ -'; return; }
            b.username = username.value.trim();
            if (pw.value && src.value === 'local') b.password = pw.value;
            const r = await POST('/api/admin/users', b, { quiet: true });
            m.close(); toast('User created', { kind: 'success' });
            if (r && r.tempPassword) showSecretOnce('Temporary password for ' + b.username, 'password', r.tempPassword);
          } else {
            await PATCH('/api/admin/users/' + encodeURIComponent(u.id), b, { quiet: true });
            m.close(); toast('Saved', { kind: 'success' });
          }
          load();
        } catch (e) { err.textContent = errMsg(e); }
      }, { variant: 'primary' })] });
  };
  async function load() {
    try { [users, teams, hints] = await Promise.all([loadUsers(), loadTeams().catch(() => []), loadHints().catch(() => [])]); draw(); }
    catch (e) { out.replaceChildren(banner('error', errMsg(e))); }
  }
  load();
}

// ===================================================================== Teams
// Spec 009: least privilege. A switch that is off, or a list that is empty, grants nothing; "Any" (*) grants all.
export const POLICY_FLAGS = [
  ['recipes_edit', 'Edit recipes'], ['skills_edit', 'Edit skills'], ['extensions_edit', 'Edit extensions'], ['providers_edit', 'Edit providers & models'],
  ['schedules', 'Manage schedules'], ['apps', 'Manage apps'], ['prompts_edit', 'Edit system prompts'], ['hints_edit', 'Members may add personal hints'],
  ['tools_permissions', 'Set tool permissions'], ['config_edit', 'Edit raw config'], ['allow_shell', 'Allow shell / stdio extensions'], ['notify_webhook', 'Notification webhooks'],
];
const FLAG_LABEL = Object.fromEntries(POLICY_FLAGS);
const EXPERIENCE = [
  { id: 'hints', title: 'Hints', flags: ['hints_edit'] },
  { id: 'models', title: 'Providers & models', flags: ['providers_edit'], kinds: ['provider'] },
  { id: 'modes', title: 'Approval modes', flags: [] },
  { id: 'folders', title: 'Folders', flags: [] },
  { id: 'ext', title: 'Extensions & tools', flags: ['allow_shell', 'extensions_edit', 'tools_permissions', 'apps'], kinds: ['extension'] },
  { id: 'recipes', title: 'Recipes, skills & schedules', flags: ['recipes_edit', 'skills_edit', 'schedules'], kinds: ['recipe', 'skill'] },
  { id: 'other', title: 'Other', flags: ['prompts_edit', 'config_edit', 'notify_webhook'] },
];
const MODE_CHOICES = [['auto', 'Auto'], ['approve', 'Approve'], ['smart_approve', 'Smart approve'], ['chat', 'Chat only']];
const WARN_KIND = { err: 'error', warn: 'warn', info: 'info' };

// An allow-list with an explicit "Any" switch. modes = tick boxes instead of free text.
function anyList(label, values, hint, modes) {
  let any = (values || []).includes('*');
  const sel = new Set(any ? [] : values || []);
  const ta = textarea({ rows: 2, class: 'inp mono', value: any ? '' : (values || []).join(', '), placeholder: 'nothing allowed - add ids, or switch on Any' });
  const box = modes ? h('div', { class: 'chk-list' }, ...modes.map(([v, l]) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: sel.has(v), onchange: (e) => { if (e.target.checked) sel.add(v); else sel.delete(v); } }), h('span', null, l)))) : ta;
  const sync = () => { box.hidden = any; };
  const tg = toggle(any, (v) => { any = v; sync(); }, { text: 'Any' });
  sync();
  return { el: field(label, h('div', { class: 'stack-sm' }, tg, box), hint), get: () => (any ? ['*'] : modes ? [...sel] : ta.value.split(/[,\n]/).map((s) => s.trim()).filter(Boolean)) };
}

function teamsTab(body) {
  let teams = [], users = [], hints = [], selId = null;
  const listEl = h('div', { class: 'split-list' }, skeleton(4));
  const detail = h('div', { class: 'split-detail' });
  body.replaceChildren(h('div', { class: 'row' }, h('p', { class: 'muted grow' }, 'Each user belongs to one team. The team decides their experience: hints, providers and models, approval modes, folders, extensions, recipes and skills. Least privilege: nothing is allowed until you allow it.'), btn('New team', () => newTeam(), { icon: 'plus', variant: 'primary', size: 'sm' })), h('div', { class: 'split' }, listEl, detail));
  const teamName = (id) => (teams.find((t) => t.id === id) || {}).name || '';
  const drawList = () => listEl.replaceChildren(...(teams.length ? teams.map((t) => h('button', { type: 'button', class: ['litem', t.id === selId ? 'active' : ''], onclick: () => { selId = t.id; drawList(); drawDetail(); } },
    icon('users', 14), h('div', { class: 'litem-main' }, h('div', { class: 'litem-title' }, t.name, (t.warnings || []).some((w) => w.level === 'err') ? h('span', { class: 'muted small' }, ' · cannot chat') : null), h('div', { class: 'litem-sub' }, ((t.members || []).length) + ' members' + (t.description ? ' · ' + t.description : ''))))) : [empty('users', 'No teams')]));
  const newTeam = async () => {
    const n = input({ placeholder: 'InfoSec Ops' }); const d = input({ placeholder: 'optional' });
    const m = modal({ title: 'New team', size: 'sm', body: h('div', { class: 'stack' }, field('Name', n), field('Description', d), h('div', { class: 'muted small' }, 'A new team starts with everything off and nothing allowed. Then choose its providers, models, approval modes and hints.')), footer: [btn('Cancel', () => m.close()), btn('Create', async () => {
      if (!n.value.trim()) return;
      try { const r = await POST('/api/admin/teams', { name: n.value.trim(), description: d.value.trim(), policy: {} }); m.close(); selId = (r && (r.id || (r.team && r.team.id))) || null; load(); } catch (e) { toastError(e); }
    }, { variant: 'primary' })] });
  };
  const drawDetail = () => {
    const t = teams.find((x) => x.id === selId);
    if (!t) { detail.replaceChildren(empty('shield', 'Select a team')); return; }
    const pol = { ...(t.policy || {}) };
    const name = input({ value: t.name }); const desc = input({ value: t.description || '' });
    const flagRow = (k) => h('div', { class: 'set-row' }, h('div', { class: 'grow' }, h('div', null, FLAG_LABEL[k]), h('div', { class: 'muted small mono' }, k)), toggle(!!pol[k], (v) => { pol[k] = v; }));
    const providers = anyList('Allowed providers', pol.allowed_providers, 'Provider ids, e.g. openai, anthropic, or a custom provider id.');
    const models = anyList('Allowed models', pol.allowed_models, 'Model ids, e.g. gpt-4o-mini.');
    const modes = anyList('Allowed approval modes', pol.allowed_modes, 'Chat only = no tool calls; Approve = ask before every tool call.', MODE_CHOICES);
    const dProv = input({ value: pol.default_provider || '', placeholder: 'e.g. openai' });
    const dModel = input({ value: pol.default_model || '', placeholder: 'e.g. gpt-4o-mini' });
    const share = input({ value: pol.share_folder || '', placeholder: t.teamFolder || '' });
    const roots = textarea({ rows: 3, class: 'inp mono', value: (pol.allowed_roots || []).join('\n'), placeholder: 'none - one absolute path per line' });
    const maxRuns = input({ type: 'number', min: '0', value: pol.max_concurrent_runs ?? '', placeholder: '3', class: 'inp inp-sm' });
    const members = multiPick(users.filter((u) => u.role !== 'admin' || (t.members || []).includes(u.id)).map((u) => ({ value: u.id, label: u.displayName || u.username, sub: u.username + (u.team && u.team !== t.id ? ' · now in ' + teamName(u.team) + ' (moves here)' : '') })), t.members || [], { empty: 'No users' });
    const hp = multiPick(hints.map((x) => ({ value: x.id, label: x.name, sub: x.description || '' })), t.hints || [], { empty: 'Hints library is empty' });
    const itemBoxes = {};
    const groupBody = (g) => {
      const parts = g.flags.map(flagRow);
      if (g.id === 'hints') parts.unshift(field('Team hints', hp.el, 'Team hints come last in every member\'s hints and take precedence over personal hints.'));
      if (g.id === 'models') parts.unshift(h('div', { class: 'grid2' }, providers.el, models.el, field('Default provider', dProv, 'New chats start here. Must be allowed above.'), field('Default model', dModel, 'Members\' profile default follows this.')));
      if (g.id === 'modes') parts.push(modes.el);
      if (g.id === 'folders') parts.push(h('div', { class: 'stack-sm' }, h('div', { class: 'muted small' }, 'Members can always reach their own workspace and the team folder. Nothing else unless listed here.'), field('Team folder', share, 'Shared by all members. Leave empty for the default: ' + (t.teamFolder || '')), field('Extra folders', roots, 'Absolute paths, one per line.'), field('Max concurrent runs', maxRuns, 'Per user. Empty = the default (3). 0 = unlimited.')));
      if (g.kinds) {
        itemBoxes[g.id] = h('div', null, spinner(14));
        parts.push(h('div', { class: 'row' }, h('span', { class: 'muted small grow' }, 'Library items: ' + g.kinds.join(', ') + 's copied into members\' profiles.'), btn('Add from library', () => libraryPicker(t, loadItems, g.kinds[0]), { icon: 'plus', size: 'sm' })), itemBoxes[g.id]);
      }
      return parts;
    };
    detail.replaceChildren(
      h('div', { class: 'detail-head' }, h('h2', null, t.name), h('div', { class: 'row' },
        actionBtn('Save team', async () => {
          const p = { ...pol, allowed_providers: providers.get(), allowed_models: models.get(), allowed_modes: modes.get(),
            allowed_roots: roots.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
            default_provider: dProv.value.trim(), default_model: dModel.value.trim(), share_folder: share.value.trim(),
            max_concurrent_runs: maxRuns.value === '' ? null : Number(maxRuns.value) };
          const r = await PATCH('/api/admin/teams/' + encodeURIComponent(t.id), { name: name.value.trim(), description: desc.value.trim(), policy: p, members: members.get(), hints: hp.get() });
          if (r && (r.moved || []).length) toast('Moved to ' + t.name + ': ' + r.moved.join(', '), { kind: 'info', timeout: 8000 });
          await load();
        }, { variant: 'primary', size: 'sm', success: 'Team saved' }),
        iconBtn('trash', 'Delete team', async () => {
          if (!(await confirmDialog({ title: 'Delete team ' + t.name + '?', message: 'Members are left without a team and cannot chat until you move them to another team. The team folder is kept on disk.', confirmText: 'Delete', danger: true }))) return;
          try { await DEL('/api/admin/teams/' + encodeURIComponent(t.id)); selId = null; load(); } catch (e) { toastError(e); }
        }, { variant: 'danger-soft' }))),
      h('div', { class: 'grid2' }, field('Name', name), field('Description', desc)),
      (t.warnings || []).length ? h('div', { class: 'stack-sm' }, ...t.warnings.map((w) => banner(WARN_KIND[w.level] || 'info', w.text))) : null,
      section('Members', null, members.el, h('div', { class: 'muted small' }, 'One team per user: ticking someone from another team moves them here.')),
      h('h3', { class: 'exp-title' }, 'Experience'),
      ...EXPERIENCE.map((g) => section(g.title, null, ...groupBody(g))));
    const loadItems = async () => {
      try {
        const items = arr(await GET('/api/admin/teams/' + encodeURIComponent(t.id) + '/items'), 'items');
        for (const g of EXPERIENCE.filter((x) => x.kinds)) {
          const mine = items.filter((i) => g.kinds.includes(i.kind));
          itemBoxes[g.id].replaceChildren(mine.length ? table([
            { label: 'Kind', render: (i) => badge(i.kind) }, { label: 'Name', render: (i) => h('span', { class: 'strong' }, i.name) },
            { label: 'Source', render: (i) => h('span', { class: 'muted small' }, i.fromProfile || i.source || '') },
            { label: '', class: 'right', render: (i) => iconBtn('trash', 'Remove', async () => { try { await DEL('/api/admin/teams/' + encodeURIComponent(t.id) + '/items/' + encodeURIComponent(i.id)); loadItems(); } catch (e) { toastError(e); } }, { variant: 'danger-soft' }) },
          ], mine) : h('div', { class: 'muted small' }, 'None.'));
        }
      } catch (e) { for (const b of Object.values(itemBoxes)) b.replaceChildren(banner('error', errMsg(e))); }
    };
    loadItems();
  };
  const libraryPicker = (t, onDone, startKind = 'recipe') => {
    let kind = startKind; let profile = (store.get('me').user || {}).username || '';
    const pSel = select(users.map((u) => ({ value: u.username, label: (u.displayName || u.username) + (u.role === 'admin' ? ' (admin)' : '') })), profile, { class: 'inp' });
    const res = h('div', { class: 'lib-res' });
    const kinds = h('div');
    const load2 = async () => {
      kinds.replaceChildren(tabs([{ id: 'recipe', label: 'Recipes' }, { id: 'skill', label: 'Skills' }, { id: 'extension', label: 'Extensions' }, { id: 'provider', label: 'Providers' }], kind, (v) => { kind = v; load2(); }));
      res.replaceChildren(spinner(14));
      try {
        const items = arr(await GET('/api/admin/library' + qs({ profile: pSel.value, kind })), 'items');
        res.replaceChildren(items.length ? table([
          { label: 'Name', render: (i) => h('div', null, h('div', { class: 'strong' }, i.name), h('div', { class: 'muted small' }, i.description || '')) },
          { label: 'Source', render: (i) => h('span', { class: 'muted small mono' }, i.source || '') },
          { label: '', class: 'right', render: (i) => actionBtn('Add', async () => { await POST('/api/admin/teams/' + encodeURIComponent(t.id) + '/items', { kind: i.kind || kind, fromProfile: pSel.value, ref: i.ref }); onDone(); }, { size: 'sm', icon: 'plus', success: 'Added ' + i.name }) },
        ], items) : empty('list', 'Nothing in this profile'));
      } catch (e) { res.replaceChildren(banner('error', errMsg(e))); }
    };
    pSel.addEventListener('change', load2);
    const m = modal({ title: 'Add to ' + t.name + ' from a profile library', size: 'lg', body: h('div', { class: 'stack' }, field('Profile', pSel, 'Copy an item that exists in this user’s Goose profile.'), kinds, res), footer: [btn('Done', () => m.close(), { variant: 'primary' })] });
    load2();
  };
  async function load() {
    try {
      [teams, users, hints] = await Promise.all([loadTeams(), loadUsers().catch(() => []), loadHints().catch(() => [])]);
      if (!selId && teams.length) selId = teams[0].id;
      drawList(); drawDetail();
    } catch (e) { listEl.replaceChildren(banner('error', errMsg(e))); }
  }
  load();
}

// ===================================================================== Hints library
function hintsLibTab(body) {
  let docs = [], sel = null;
  const listEl = h('div', { class: 'split-list' }, skeleton(4));
  const detail = h('div', { class: 'split-detail' });
  body.replaceChildren(h('div', { class: 'row' }, h('p', { class: 'muted grow' }, 'Shared .goosehints documents. Assign them to teams or individual users; they are merged into each profile’s hints.'), btn('New document', () => { sel = { id: null, name: '', description: '', content: '# Hints\n' }; drawDetail(); }, { icon: 'plus', variant: 'primary', size: 'sm' })), h('div', { class: 'split' }, listEl, detail));
  const drawList = () => listEl.replaceChildren(...(docs.length ? docs.map((d) => h('button', { type: 'button', class: ['litem', sel && sel.id === d.id ? 'active' : ''], onclick: async () => { try { sel = await GET('/api/admin/hints/' + encodeURIComponent(d.id)); if (sel && sel.hint) sel = sel.hint; drawList(); drawDetail(); } catch (e) { toastError(e); } } },
    icon('hint', 14), h('div', { class: 'litem-main' }, h('div', { class: 'litem-title' }, d.name), h('div', { class: 'litem-sub' }, d.description || '')))) : [empty('hint', 'No documents')]));
  const drawDetail = () => {
    if (!sel) { detail.replaceChildren(empty('hint', 'Select a document')); return; }
    const d = sel;
    const n = input({ value: d.name || '' }); const ds = input({ value: d.description || '' });
    const ta = textarea({ value: d.content || '', rows: 22, class: 'inp mono' });
    let t = 'edit'; const pane = h('div');
    const drawPane = () => pane.replaceChildren(tabs([{ id: 'edit', label: 'Write' }, { id: 'preview', label: 'Preview' }], t, (v) => { t = v; drawPane(); }), t === 'edit' ? ta : h('div', { class: 'md-preview' }, mdElement(ta.value || '*empty*')));
    drawPane();
    detail.replaceChildren(h('div', { class: 'detail-head' }, h('h2', null, d.id ? d.name : 'New document'), h('div', { class: 'row' },
      actionBtn('Save', async () => {
        const b = { name: n.value.trim(), description: ds.value.trim(), content: ta.value };
        if (!b.name) throw new Error('Name is required');
        const r = d.id ? await PUT('/api/admin/hints/' + encodeURIComponent(d.id), b) : await POST('/api/admin/hints', b);
        sel = { ...d, ...b, id: d.id || (r && (r.id || (r.hint && r.hint.id))) };
        await load();
      }, { variant: 'primary', size: 'sm', success: 'Saved' }),
      d.id ? iconBtn('trash', 'Delete', async () => {
        if (!(await confirmDialog({ title: 'Delete ' + d.name + '?', message: 'It is removed from every team and user it is assigned to.', confirmText: 'Delete', danger: true }))) return;
        try { await DEL('/api/admin/hints/' + encodeURIComponent(d.id)); sel = null; load(); } catch (e) { toastError(e); }
      }, { variant: 'danger-soft' }) : null)),
    h('div', { class: 'grid2' }, field('Name', n), field('Description', ds)), pane);
  };
  async function load() { try { docs = await loadHints(); drawList(); drawDetail(); } catch (e) { listEl.replaceChildren(banner('error', errMsg(e))); } }
  load(); drawDetail();
}

// ===================================================================== Auth providers
function authTab(body) {
  body.replaceChildren(skeleton(6));
  (async () => {
    let cfg, teams = [];
    try { [cfg, teams] = await Promise.all([GET('/api/admin/auth'), loadTeams().catch(() => [])]); } catch (e) { body.replaceChildren(banner('error', errMsg(e))); return; }
    const l = { enabled: false, url: '', bindDn: '', userBase: '', userFilter: '(sAMAccountName={username})', adminGroupDn: '', groupTeamMap: {}, startTls: false, allowInsecure: false, label: 'Active Directory', ...(cfg.ldap || {}) };
    let localEnabled = cfg.localEnabled !== false;
    const oidc = (cfg.oidc || []).map((o) => ({ ...o }));
    const I = (k, ph, type = 'text') => { const i = input({ value: l[k] ?? '', placeholder: ph, type, class: 'inp mono', autocomplete: 'new-password' }); i.addEventListener('input', () => { l[k] = i.value; }); return i; };
    const bindPw = input({ type: 'password', placeholder: l.bindPassword ? '******** (set – leave to keep)' : 'not set', autocomplete: 'new-password' });
    const gmap = textarea({ rows: 3, class: 'inp mono', value: Object.entries(l.groupTeamMap || {}).map(([g, t]) => g + ' = ' + t).join('\n'), placeholder: 'CN=Goose Users,OU=Groups,DC=corp,DC=local = <teamId>' });
    const oidcBox = h('div', { class: 'stack' });
    const drawOidc = () => oidcBox.replaceChildren(...oidc.map((o, i) => {
      const F = (k, ph, type = 'text') => { const x = input({ value: o[k] ?? '', placeholder: ph, type, class: 'inp mono', autocomplete: 'new-password' }); x.addEventListener('input', () => { o[k] = x.value; }); return x; };
      const sec = input({ type: 'password', autocomplete: 'new-password', placeholder: o.clientSecret ? '******** (set – leave to keep)' : 'client secret' });
      sec.addEventListener('input', () => { o._newSecret = sec.value; });
      return h('div', { class: 'card stack' }, h('div', { class: 'row' }, h('strong', { class: 'grow' }, o.label || o.id || 'New provider'), iconBtn('trash', 'Remove', () => { oidc.splice(i, 1); drawOidc(); }, { variant: 'danger-soft' })),
        h('div', { class: 'grid2' }, field('ID (URL slug)', F('id', 'entra')), field('Button label', F('label', 'Sign in with Microsoft')), field('Issuer URL', F('issuer', 'https://login.microsoftonline.com/<tenant>/v2.0')), field('Client ID', F('clientId', '')), field('Client secret', sec), field('Scopes', F('scopes', 'openid profile email')),
          field('Admin claim', F('adminClaim', 'groups')), field('Admin claim value', F('adminValue', '<group id>')), field('Team claim', F('teamClaim', 'groups'))),
        checkbox(!!o.autoCreate, 'Create users automatically on first sign-in', (v) => { o.autoCreate = v; }),
        h('div', { class: 'muted small' }, 'Redirect URI: ', h('code', null, location.origin + '/api/auth/oidc/' + (o.id || '<id>') + '/callback')));
    }));
    drawOidc();
    body.replaceChildren(
      banner('info', 'Secrets are write-only: they show as ******** when set. Leave a secret field empty to keep the current value.'),
      section('Local accounts', null, h('div', { class: 'card' }, h('div', { class: 'set-row' }, h('div', { class: 'grow' }, h('div', { class: 'strong' }, 'Allow local username/password sign-in'), h('div', { class: 'muted small' }, 'Keep at least one local admin as a break-glass account.')), toggle(localEnabled, (v) => { localEnabled = v; })))),
      section('LDAP / Active Directory', null, h('div', { class: 'card stack' },
        h('div', { class: 'set-row' }, h('div', { class: 'grow strong' }, 'Enable LDAP sign-in'), toggle(!!l.enabled, (v) => { l.enabled = v; })),
        h('div', { class: 'grid2' }, field('Server URL', I('url', 'ldaps://dc01.corp.local:636')), field('Login screen label', I('label', 'Active Directory')), field('Bind DN', I('bindDn', 'CN=svc-goose,OU=Service,DC=corp,DC=local')), field('Bind password', bindPw),
          field('User search base', I('userBase', 'OU=Users,DC=corp,DC=local')), field('User filter', I('userFilter', '(sAMAccountName={username})')), field('Admin group DN', I('adminGroupDn', 'CN=Goose Admins,…'))),
        checkbox(!!l.startTls, 'Use StartTLS (for ldap://)', (v) => { l.startTls = v; }),
        checkbox(!!l.allowInsecure, 'Allow unencrypted LDAP (not recommended)', (v) => { l.allowInsecure = v; }),
        h('div', { class: 'muted small' }, 'Plain ldap:// without StartTLS sends the bind password and user passwords in clear text and is refused unless this is on. Prefer ldaps:// or StartTLS.'),
        field('Group → team mapping', gmap, 'One per line: <group DN> = <team id>. Teams: ' + (teams.map((t) => t.name + ' = ' + t.id).join(', ') || 'none')))),
      section('OpenID Connect providers', btn('Add provider', () => { oidc.push({ id: '', label: '', issuer: '', clientId: '', scopes: 'openid profile email', autoCreate: false }); drawOidc(); }, { icon: 'plus', size: 'sm' }), oidcBox),
      h('div', { class: 'row sticky-foot' }, actionBtn('Save auth settings', async () => {
        const map = {}; for (const line of gmap.value.split(/\r?\n/)) { const i = line.lastIndexOf('='); if (i > 0) map[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
        const ldap = { ...l, groupTeamMap: map }; delete ldap.bindPassword; if (bindPw.value) ldap.bindPassword = bindPw.value;
        const oo = oidc.map((o) => { const x = { ...o }; delete x._newSecret; delete x.clientSecret; if (o._newSecret) x.clientSecret = o._newSecret; return x; });
        if (oo.some((o) => !o.id || !/^[a-z0-9-]+$/.test(o.id))) throw new Error('Each OIDC provider needs a lowercase id (a-z, 0-9, -)');
        await PUT('/api/admin/auth', { ldap, oidc: oo, localEnabled });
      }, { variant: 'primary', success: 'Auth settings saved' })));
  })();
}

// ===================================================================== Settings
function settingsTab(body) {
  body.replaceChildren(skeleton(5));
  (async () => {
    let s, teams = [];
    try { [s, teams] = await Promise.all([GET('/api/admin/settings'), loadTeams().catch(() => [])]); } catch (e) { body.replaceChildren(banner('error', errMsg(e))); return; }
    const brand = { name: 'Goose Web', tagline: '', ...(s.brand || {}) };
    const bn = input({ value: brand.name }); const bt = input({ value: brand.tagline || '', placeholder: 'Your AI agent, anywhere' });
    const dt = select([{ value: '', label: '— none —' }, ...teams.map((t) => ({ value: t.id, label: t.name }))], s.defaultTeamId || '');
    const hrs = input({ type: 'number', min: '1', max: '720', value: s.sessionHours ?? 12, class: 'inp inp-sm' });
    let allowSelfTotp = s.allowSelfTotp !== false, reqTotp = !!s.requireTotpForAdmins;
    const peers = (s.peers || []).map((p) => ({ ...p }));
    const peersBox = h('div', { class: 'stack-sm' });
    const drawPeers = () => peersBox.replaceChildren(...peers.map((p, i) => {
      const n = input({ value: p.name || '', placeholder: 'build-box', class: 'inp inp-sm' }); n.addEventListener('input', () => { p.name = n.value; });
      const u = input({ value: p.url || '', placeholder: 'https://build-box:8443', class: 'inp inp-sm mono' }); u.addEventListener('input', () => { p.url = u.value; });
      const t = input({ type: 'password', placeholder: p.token ? '******** (set)' : 'API token (gwt_…)', class: 'inp inp-sm', autocomplete: 'new-password' }); t.addEventListener('input', () => { p._tok = t.value; });
      return h('div', { class: 'row kv-row' }, n, u, t, iconBtn('x', 'Remove', () => { peers.splice(i, 1); drawPeers(); }));
    }), btn('Add peer', () => { peers.push({ name: '', url: '' }); drawPeers(); }, { size: 'sm', icon: 'plus', variant: 'ghost' }));
    drawPeers();
    body.replaceChildren(
      section('Branding', null, h('div', { class: 'card grid2' }, field('Name', bn), field('Tagline', bt))),
      section('Accounts', null, h('div', { class: 'card stack' }, h('div', { class: 'grid2' }, field('Default team for new users', dt), field('Sign-in lifetime (hours)', hrs)),
        h('div', { class: 'set-row' }, h('div', { class: 'grow' }, 'Users may enable two-factor themselves'), toggle(allowSelfTotp, (v) => { allowSelfTotp = v; })),
        h('div', { class: 'set-row' }, h('div', { class: 'grow' }, 'Require two-factor for administrators'), toggle(reqTotp, (v) => { reqTotp = v; })))),
      section('Herd peers', null, h('p', { class: 'muted small' }, 'Other Goose Web gateways shown in everyone’s Herd (“every machine in one sidebar”). The token must belong to a user on that machine.'), peersBox),
      h('div', { class: 'row sticky-foot' }, actionBtn('Save settings', async () => {
        const pp = peers.filter((p) => p.url).map((p) => { const x = { name: p.name || p.url, url: p.url }; if (p._tok) x.token = p._tok; else if (p.token) x.token = p.token; return x; });
        await PUT('/api/admin/settings', { brand: { name: bn.value.trim() || 'Goose Web', tagline: bt.value.trim() }, defaultTeamId: dt.value || null, sessionHours: Number(hrs.value) || 12, allowSelfTotp, requireTotpForAdmins: reqTotp, peers: pp });
        const ac = store.get('authConfig'); if (ac) store.set('authConfig', { ...ac, brand: { name: bn.value.trim(), tagline: bt.value.trim() } });
      }, { variant: 'primary', success: 'Settings saved' })));
  })();
}

// ===================================================================== System
function systemTab(body) {
  let timer = null;
  const load = async () => {
    try {
      const s = await GET('/api/admin/system');
      const kv = (k, v) => h('div', { class: 'kv-row2' }, h('div', { class: 'muted small' }, k), h('div', { class: 'mono small' }, v ?? '—'));
      body.replaceChildren(
        s.integrity && String(s.integrity).toLowerCase() !== 'medium' ? banner('warn', 'The gateway runs at ' + s.integrity + ' integrity' + (s.elevated ? ' (elevated)' : '') + '. Files it creates may be owned by Administrators and lock out the normal user. Run it un-elevated at medium integrity.') : null,
        s.desktopRunning ? banner('info', 'Goose Desktop is running on this machine' + (s.scheduler && s.scheduler.owner ? '; scheduler owner: ' + s.scheduler.owner : '') + '. Only one process should own the scheduler for a profile.') : null,
        section('Versions', iconBtn('refresh', 'Refresh', () => load()), h('div', { class: 'card kv-grid' },
          kv('Gateway', s.version), kv('Goose', s.gooseVersion), kv('Goose binary', s.gooseBinary), kv('Runs as', s.user), kv('Integrity', (s.integrity || '') + (s.elevated ? ' · elevated' : '')),
          kv('Profiles root', s.profilesRoot), kv('Native root', s.nativeRoot), kv('Desktop running', s.desktopRunning ? 'yes' : 'no'), kv('Scheduler owner', s.scheduler && s.scheduler.owner))),
        section('Workers', null, table([
          { label: 'Profile', render: (w) => h('div', null, h('div', { class: 'strong' }, w.username || w.key), h('div', { class: 'muted small mono' }, w.key)) },
          { label: 'State', render: (w) => h('span', { class: 'row' }, h('span', { class: 'sdot s-' + (w.state === 'ready' ? 'done' : w.state === 'starting' ? 'working' : w.state === 'error' || w.state === 'down' ? 'error' : 'idle') }), w.state) },
          { label: 'PID / port', render: (w) => h('span', { class: 'mono small' }, (w.pid || '—') + ' / ' + (w.port || '—')) },
          { label: 'Up', render: (w) => w.startedAt ? relTime(w.startedAt) : '—' },
          { label: 'Clients', key: 'clients' }, { label: 'Runs', key: 'activeRuns' },
          { label: 'Scheduler', render: (w) => w.scheduler ? badge('owner', 'accent') : '' },
          { label: 'Restarts', render: (w) => h('span', { title: w.lastError || '' }, String(w.restarts || 0), w.lastError ? h('span', { class: 'badge badge-err' }, 'error') : null) },
          { label: '', class: 'right', render: (w) => h('span', { class: 'row' },
            btn('Restart', async () => { if (w.activeRuns && !(await confirmDialog({ title: 'Restart ' + (w.username || w.key) + '?', message: w.activeRuns + ' run(s) are active and will be interrupted.', confirmText: 'Restart', danger: true }))) return; try { await POST('/api/admin/system/workers/' + encodeURIComponent(w.key) + '/restart', {}); toast('Restarting', { kind: 'success' }); setTimeout(load, 1500); } catch (e) { toastError(e); } }, { size: 'sm' }),
            btn('Stop', async () => { if (!(await confirmDialog({ title: 'Stop worker ' + (w.username || w.key) + '?', message: 'It starts again when the user connects.', confirmText: 'Stop', danger: true }))) return; try { await POST('/api/admin/system/workers/' + encodeURIComponent(w.key) + '/stop', {}); toast('Stopped', { kind: 'success' }); setTimeout(load, 800); } catch (e) { toastError(e); } }, { size: 'sm', variant: 'danger-soft' })) },
        ], s.workers || [], { empty: 'No workers running' })));
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  };
  body.replaceChildren(skeleton(6));
  load();
  timer = setInterval(() => { if (document.visibilityState === 'visible') load(); }, 10000);
  return { destroy() { clearInterval(timer); } };
}

// ===================================================================== Ownership
function ownershipTab(body) {
  const out = h('div');
  const pSel = select([], '', { class: 'inp' });
  body.replaceChildren(
    banner('warn', h('span', null, h('strong', null, 'Why this matters: '), 'files created by an elevated process (Run as administrator, a SYSTEM scheduled task, or an installer) are owned by Administrators or SYSTEM. The normal Windows user running the gateway – and Goose Desktop – may then be unable to read or change them, which silently breaks sessions, recipes or config. Fix ownership with ', h('code', null, 'icacls <path> /setowner <user> /T'), ' from an elevated prompt, then avoid running Goose elevated.')),
    h('div', { class: 'row' }, field('Profile', pSel), actionBtn('Scan', async () => {
      out.replaceChildren(spinner(16));
      const r = await GET('/api/admin/ownership' + qs({ profile: pSel.value }));
      out.replaceChildren(
        h('div', { class: 'muted small' }, 'Scanned ' + (r.scanned ?? '?') + ' items under ', h('code', null, r.root || ''), r.truncated ? ' (truncated)' : ''),
        (r.foreign || []).length ? banner('error', (r.foreign.length) + ' item(s) are not owned by the gateway user.') : banner('info', 'All scanned files are owned by the gateway user.'),
        (r.foreign || []).length ? table([{ label: 'Path', render: (f) => h('span', { class: 'mono small' }, f.path) }, { label: 'Owner', render: (f) => h('span', { class: 'badge badge-warn' }, f.owner) }, { label: '', class: 'right', render: (f) => copyBtn(f.path, 'Copy path') }], r.foreign) : null);
    }, { variant: 'primary', icon: 'search' })), out);
  loadUsers().then((us) => { pSel.replaceChildren(h('option', { value: '' }, 'Gateway / native profile'), ...us.map((u) => h('option', { value: u.username }, u.displayName ? u.displayName + ' (' + u.username + ')' : u.username))); }).catch(() => {});
}

// ===================================================================== Host tasks
function hostTasksTab(body) {
  const out = h('div', null, skeleton(5));
  const q = input({ type: 'search', placeholder: 'Filter tasks…', class: 'inp inp-sm' });
  let tasks = [];
  body.replaceChildren(h('p', { class: 'muted' }, 'Windows scheduled tasks on this host. Tasks that run elevated (highest privileges or as SYSTEM) can create files owned by Administrators – see Ownership check.'),
    h('div', { class: 'row' }, q, iconBtn('refresh', 'Refresh', () => load())), out);
  const act = async (t, action) => {
    const danger = action === 'end' || action === 'disable';
    if (!(await confirmDialog({ title: action[0].toUpperCase() + action.slice(1) + ' task “' + t.name + '”?', message: t.path + (t.elevated ? '\n\nThis task runs elevated.' : ''), confirmText: action[0].toUpperCase() + action.slice(1), danger }))) return;
    try { await POST('/api/admin/hosttasks/action', { path: t.path, action }); toast('Done', { kind: 'success' }); setTimeout(load, 800); } catch (e) { toastError(e); }
  };
  const draw = () => {
    const f = q.value.toLowerCase();
    out.replaceChildren(table([
      { label: 'Task', render: (t) => h('div', null, h('div', { class: 'strong' }, t.name, t.elevated ? h('span', { class: 'badge badge-warn', title: 'Runs with highest privileges or as SYSTEM' }, icon('alert', 10), ' elevated') : null), h('div', { class: 'muted small mono' }, t.path), t.actions ? h('div', { class: 'muted small mono clamp2', title: String(t.actions) }, String(t.actions)) : null) },
      { label: 'State', render: (t) => badge(t.state || '?', /running/i.test(t.state) ? 'accent' : /disabled/i.test(t.state) ? 'err' : /ready/i.test(t.state) ? 'ok' : '') },
      { label: 'Run as', render: (t) => h('div', { class: 'small' }, t.runAs || '', h('div', { class: 'muted small' }, [t.runLevel, t.logonType].filter(Boolean).join(' · '))) },
      { label: 'Last run', render: (t) => h('div', { class: 'small' }, t.lastRun ? relTime(t.lastRun) : '—', t.lastResult !== undefined && t.lastResult !== null ? h('div', { class: 'muted small mono' }, 'result ' + t.lastResult) : null) },
      { label: 'Next run', render: (t) => t.nextRun ? h('span', { class: 'small', title: fmtDateTime(t.nextRun) }, relTime(t.nextRun)) : '—' },
      { label: '', class: 'right', render: (t) => iconBtn('more', 'Actions', (ev) => menu(ev.currentTarget, [
        { label: 'Run now', icon: 'play', onClick: () => act(t, 'run') }, { label: 'End', icon: 'stop', onClick: () => act(t, 'end') },
        /disabled/i.test(t.state) ? { label: 'Enable', icon: 'check', onClick: () => act(t, 'enable') } : { label: 'Disable', icon: 'pause', danger: true, onClick: () => act(t, 'disable') },
      ], { align: 'right' })) },
    ], tasks.filter((t) => !f || (t.name + ' ' + t.path + ' ' + (t.runAs || '')).toLowerCase().includes(f)), { empty: 'No tasks', rowClass: (t) => t.elevated ? 'warn-row' : '' }));
  };
  q.addEventListener('input', debounce(draw, 120));
  async function load() { try { tasks = arr(await GET('/api/admin/hosttasks'), 'tasks'); draw(); } catch (e) { out.replaceChildren(banner('error', errMsg(e))); } }
  load();
}

// ===================================================================== Audit
// ===================================================================== Blocked addresses (spec 007)
function ipBlocksTab(body) {
  const out = h('div', null, skeleton(4));
  const unblock = async (b, label) => {
    try { await POST('/api/admin/ip-blocks/unblock', b); toast(label, { kind: 'success' }); load(); } catch (e) { toastError(e); }
  };
  const days = (d) => (Math.round(d * 100) / 100) + (d === 1 ? ' day' : ' days');
  async function load() {
    let r;
    try { r = await GET('/api/admin/ip-blocks'); } catch (e) { out.replaceChildren(banner('error', errMsg(e))); return; }
    const items = r.items || [];
    const rule = r.threshold > 0
      ? 'An address is blocked after ' + r.threshold + ' failed sign-ins in a row within ' + days(r.windowDays) + ' (a successful sign-in resets the count). Blocks last ' + (r.blockDays > 0 ? days(r.blockDays) : 'until unblocked here') + '. IPv6 addresses are grouped by /64. Trusted proxies' + ((r.exempt || []).length ? ' and ' + r.exempt.join(', ') : '') + ' are never blocked.'
      : 'Address blocking is turned off (auth.ip_block_threshold is 0).';
    out.replaceChildren(
      banner('info', rule),
      h('div', { class: 'row' }, h('span', { class: 'grow muted small' }, items.filter((x) => x.blocked).length + ' blocked, ' + items.filter((x) => !x.blocked).length + ' counting'),
        btn('Refresh', () => load(), { icon: 'refresh', size: 'sm' }),
        items.length ? btn('Unblock all', async () => {
          if (!(await confirmDialog({ title: 'Unblock every address?', message: 'All blocks end and every failure count is cleared.', confirmText: 'Unblock all', danger: true }))) return;
          unblock({ all: true }, 'All addresses unblocked');
        }, { icon: 'check', size: 'sm' }) : null),
      table([
        { label: 'Address', render: (x) => h('code', null, x.ip) },
        { label: 'Status', render: (x) => x.blocked ? badge('blocked', 'err') : badge('counting', 'warn') },
        { label: 'Failures', render: (x) => String(x.failures) },
        { label: 'Last user name tried', render: (x) => x.lastUsername ? h('span', { class: 'mono small' }, x.lastUsername) : h('span', { class: 'muted' }, '—') },
        { label: 'Last failure', render: (x) => x.lastFailureAt ? h('span', { title: fmtDateTime(x.lastFailureAt * 1000) }, relTime(x.lastFailureAt * 1000)) : h('span', { class: 'muted' }, '—') },
        { label: 'Blocked until', render: (x) => !x.blocked ? h('span', { class: 'muted' }, '—') : x.blockedUntil ? h('span', { title: fmtDateTime(x.blockedUntil * 1000) }, fmtDateTime(x.blockedUntil * 1000)) : 'until unblocked' },
        { label: '', class: 'right', render: (x) => btn(x.blocked ? 'Unblock' : 'Clear', () => unblock({ ip: x.ip }, (x.blocked ? 'Unblocked ' : 'Cleared ') + x.ip), { size: 'sm' }) },
      ], items, { empty: 'No blocked addresses and no failed sign-ins being counted.' }));
  }
  body.replaceChildren(out);
  load();
}

function auditTab(body) {
  let rows = [], loading = false, done = false;
  const user = input({ placeholder: 'user', class: 'inp inp-sm' });
  const action = input({ placeholder: 'action (e.g. login, rpc)', class: 'inp inp-sm' });
  const tbody = h('tbody');
  const sentinel = h('div', { class: 'side-sentinel' });
  const status = h('div', { class: 'muted small center pad' });
  const t = h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', null, h('tr', null, ...['Time', 'User', 'IP', 'Action', 'Target', 'Detail', ''].map((x) => h('th', null, x)))), tbody));
  body.replaceChildren(h('div', { class: 'row' }, user, action, btn('Apply', () => reset(), { size: 'sm' }), iconBtn('refresh', 'Refresh', () => reset())), t, status, sentinel);
  const rowEl = (r) => h('tr', { class: r.ok === false ? 'err-row' : '' },
    h('td', { title: fmtDateTime(r.ts) }, h('span', { class: 'small' }, fmtDateTime(r.ts))), h('td', null, r.username || '—'), h('td', { class: 'mono small' }, r.ip || ''),
    h('td', null, badge(r.action || '', r.ok === false ? 'err' : '')), h('td', { class: 'mono small' }, r.target || ''),
    h('td', { class: 'small clamp2', title: typeof r.detail === 'string' ? r.detail : prettyJson(r.detail) }, typeof r.detail === 'string' ? r.detail : r.detail ? JSON.stringify(r.detail) : ''),
    h('td', null, r.ok === false ? icon('x', 12) : icon('check', 12)));
  const more = async () => {
    if (loading || done) return;
    loading = true; status.textContent = 'Loading…';
    try {
      const last = rows[rows.length - 1];
      const r = arr(await GET('/api/admin/audit' + qs({ limit: 100, before: last ? (last.id ?? last.ts) : '', user: user.value.trim(), action: action.value.trim() })), 'entries');
      rows.push(...r); tbody.append(...r.map(rowEl));
      if (r.length < 100) done = true;
      status.textContent = done ? (rows.length ? rows.length + ' entries' : 'No entries') : '';
    } catch (e) { status.textContent = errMsg(e); done = true; }
    loading = false;
  };
  const reset = () => { rows = []; done = false; tbody.replaceChildren(); more(); };
  [user, action].forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') reset(); }));
  const io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) more(); });
  io.observe(sentinel);
  reset();
  return { destroy() { io.disconnect(); } };
}

// ===================================================================== Logs
function logsTab(body) {
  let auto = true; let timer = null;
  const wSel = select([{ value: '', label: 'Gateway' }], '', { class: 'inp inp-sm' });
  const lines = select(['200', '500', '1000', '2000'], '500', { class: 'inp inp-sm' });
  const q = input({ type: 'search', placeholder: 'Filter…', class: 'inp inp-sm' });
  const pre = h('pre', { class: 'term logs' });
  let data = [];
  body.replaceChildren(h('div', { class: 'row wrap' }, field('Source', wSel, null, { inline: true }), field('Lines', lines, null, { inline: true }), q, toggle(auto, (v) => { auto = v; }, { text: 'Auto-refresh' }), iconBtn('refresh', 'Refresh', () => load()), copyBtn(() => data.join('\n'), 'Copy log')), pre);
  const draw = () => {
    const f = q.value.toLowerCase();
    const stick = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
    pre.textContent = (f ? data.filter((l) => l.toLowerCase().includes(f)) : data).join('\n') || '(empty)';
    if (stick) pre.scrollTop = pre.scrollHeight;
  };
  q.addEventListener('input', debounce(draw, 120));
  async function load() {
    try { const r = await GET('/api/admin/logs' + qs({ worker: wSel.value, lines: lines.value })); data = arr(r, 'lines').map(String); draw(); }
    catch (e) { pre.textContent = errMsg(e); }
  }
  wSel.addEventListener('change', load); lines.addEventListener('change', load);
  GET('/api/admin/system').then((s) => { for (const w of s.workers || []) wSel.appendChild(h('option', { value: w.key }, 'Worker · ' + (w.username || w.key))); }).catch(() => {});
  load();
  timer = setInterval(() => { if (auto && document.visibilityState === 'visible') load(); }, 3000);
  return { destroy() { clearInterval(timer); } };
}
