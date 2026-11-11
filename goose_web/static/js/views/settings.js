// Settings: providers, prompts, preferences, hints, tool permissions, advanced config, appearance, notifications, account.
import { h, btn, iconBtn, pageHeader, toast, toastError, confirmDialog, promptDialog, modal, empty, skeleton, banner, errMsg, input, textarea, field, tabs, toggle, select, checkbox, table, section, debounce, prettyJson, relTime, fmtDateTime, copyBtn, spinner, actionBtn } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { GET, POST, PUT, PATCH, DEL } from '../api.js';
import { store, policy, allowedValue } from '../store.js';
import { setBaseTitle, chime } from '../herd.js';
import { router } from '../router.js';
import { THEMES, ACCENTS, prefs, pref, setPref, patchPref, activityPrefs } from '../prefs.js';
import { mdElement } from '../markdown.js';
import { hiddenList, setHiddenProviders, hideAllExcept, rememberProviderMeta } from '../providervis.js';
import { groupsConfig, setGroups, newGroupId, groupOfProvider, groupPicker, rememberInventory } from '../providergroups.js';
import { passwordForm } from './login.js';
import { sessionsState, sessionTitle } from '../sessions.js';
import { currentChat } from '../chatsession.js';
import qrcode from '../../vendor/qrcode.esm.js';

const TABS = [
  { id: 'providers', label: 'Models & Providers', icon: 'cpu' },
  { id: 'prompts', label: 'System prompts', icon: 'scroll' },
  { id: 'preferences', label: 'Preferences', icon: 'sliders' },
  { id: 'hints', label: 'Goose hints', icon: 'hint' },
  { id: 'tools', label: 'Tool permissions', icon: 'shield' },
  { id: 'advanced', label: 'Advanced config', icon: 'database', perm: 'config_edit' },
  { id: 'appearance', label: 'Appearance', icon: 'palette' },
  { id: 'notifications', label: 'Notifications', icon: 'bell' },
  { id: 'account', label: 'Account', icon: 'user' },
];

export function renderSettings(ctx, tab) {
  const visible = TABS.filter((t) => !t.perm || policy(t.perm));
  const cur = visible.find((t) => t.id === tab) || visible[0];
  setBaseTitle(cur.label + ' · Settings · Goose');
  const nav = h('nav', { class: 'settings-nav', 'aria-label': 'Settings sections' },
    ...visible.map((t) => h('a', { href: '#/settings/' + t.id, class: ['snav-item', t.id === cur.id ? 'active' : ''] }, icon(t.icon, 15), h('span', null, t.label))));
  const body = h('div', { class: 'settings-body' });
  const tabsMobile = select(visible.map((t) => ({ value: t.id, label: t.label })), cur.id, { class: 'inp only-mobile', 'aria-label': 'Settings section', onchange: (e) => router.go('/settings/' + e.target.value) });
  const el = h('div', { class: 'view view-page view-settings' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Settings'), null, [tabsMobile]),
    h('div', { class: 'page-body settings-layout' }, nav, body));
  const R = { providers: providersTab, prompts: promptsTab, preferences: preferencesTab, hints: hintsTab, tools: toolsTab, advanced: advancedTab, appearance: appearanceTab, notifications: notificationsTab, account: accountTab };
  let inner = null;
  try { inner = R[cur.id](body) || null; } catch (e) { console.error(e); body.replaceChildren(banner('error', errMsg(e))); }
  return { el, destroy() { if (inner && inner.destroy) inner.destroy(); } };
}

const ro = (key, what) => policy(key) ? null : banner('info', 'Read-only: your policy does not allow changing ' + what + '.');

// ===================================================================== Providers
function providersTab(body) {
  const canEdit = policy('providers_edit');
  let entries = []; let defaults = {}; let q = ''; let showAll = false;
  const defBox = h('div', { class: 'card' }, skeleton(2));
  const visBox = h('div', { class: 'card', 'data-section': 'chat-pickers' }, skeleton(3));
  const grpBox = h('div', { class: 'card', 'data-section': 'provider-groups' }, skeleton(3));
  const list = h('div', { class: 'prov-list' }, skeleton(6));
  const secretsBox = h('div');
  const search = input({ type: 'search', placeholder: 'Search providers…', class: 'inp inp-sm' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); draw(); }, 120));
  body.replaceChildren(
    ro('providers_edit', 'providers'),
    section('Default model', null, defBox),
    section('Chat pickers', null, visBox),
    section('Provider groups', btn('New group', () => newGroup(), { size: 'sm', icon: 'plus' }), grpBox),
    section('Providers', [search, toggle(showAll, (v) => { showAll = v; draw(); }, { text: 'Show unconfigured' }),
      canEdit ? btn('Refresh models', async () => { try { const r = await rpc.call(G('providers/inventory/refresh'), {}); toast('Refreshing ' + (r.started || []).length + ' provider(s)', { kind: 'info' }); setTimeout(load, 2500); } catch (e) { toastError(e); } }, { size: 'sm', icon: 'refresh' }) : null,
      canEdit ? btn('Custom provider', () => customDialog(null), { size: 'sm', icon: 'plus', variant: 'primary' }) : null], list),
    section('Stored secrets', null, secretsBox));

  const allowed = (e) => allowedValue('allowed_providers', e.providerId);   // "*" = any, empty = none (spec 009)
  const drawDefaults = () => {
    const configured = entries.filter((e) => e.configured && allowed(e));
    const pSel = select([{ value: '', label: '— none —' }, ...configured.map((e) => ({ value: e.providerId, label: e.providerName }))], defaults.providerId || '', { class: 'inp' });
    const mSel = select([], '', { class: 'inp' });
    const fillModels = () => {
      const e = entries.find((x) => x.providerId === pSel.value);
      const models = e ? e.models || [] : [];
      const opts = models.map((m) => ({ value: m.id, label: (m.name || m.id) + (m.recommended ? ' ★' : '') + (m.contextLimit ? ' · ' + Math.round(m.contextLimit / 1000) + 'k' : '') }));
      if (defaults.modelId && !opts.find((o) => o.value === defaults.modelId) && pSel.value === defaults.providerId) opts.unshift({ value: defaults.modelId, label: defaults.modelId });
      mSel.replaceChildren(...[{ value: '', label: e ? 'Provider default (' + (e.defaultModel || '?') + ')' : '—' }, ...opts].map((o) => h('option', { value: o.value }, o.label)));
      mSel.value = pSel.value === defaults.providerId ? (defaults.modelId || '') : '';
    };
    pSel.addEventListener('change', fillModels); fillModels();
    pSel.disabled = mSel.disabled = !canEdit;
    defBox.replaceChildren(h('div', { class: 'grid2' }, field('Provider', pSel), field('Model', mSel, 'Used for new chats. Each chat can switch model from its header.')),
      canEdit ? h('div', { class: 'row' },
        actionBtn('Save default', async () => { if (!pSel.value) throw new Error('Choose a provider'); defaults = await rpc.call(G('defaults/save'), { providerId: pSel.value, modelId: mSel.value || null }); drawDefaults(); }, { variant: 'primary', success: 'Default saved' }),
        actionBtn('Clear', async () => { defaults = await rpc.call(G('defaults/clear'), {}); drawDefaults(); }, { success: 'Default cleared' }),
        pSel.value ? actionBtn('Check readiness', async () => { const r = await rpc.call(G('providers/readiness/check'), { providerId: pSel.value }); toast(r.ready ? 'Provider is ready' : 'Not ready: ' + (r.error || 'unknown'), { kind: r.ready ? 'success' : 'error' }); }, { icon: 'activity' }) : null) : null);
    rememberProviderMeta({ defaultProvider: defaults.providerId || '' });
    drawVis();
  };
  // Spec 023: which configured providers the chat pickers (New chat, chat header) offer. A display preference of this
  // user (saved with the preferences on the server), so it needs no providers_edit permission and applies after the
  // policy. The default provider is always shown. Effort variants (spec 022, gwVariantOf) are not listed here.
  const drawVis = () => {
    const def = defaults.providerId || '';
    const rows = entries.filter((e) => e.configured && allowed(e) && !e.gwVariantOf);
    if (!rows.length) { visBox.replaceChildren(h('div', { class: 'muted' }, 'No configured providers yet.')); return; }
    const hidden = new Set(hiddenList());
    const shown = (e) => e.providerId === def || !hidden.has(e.providerId);
    const save = (ids) => { setHiddenProviders(ids, def); drawVis(); };
    const keepDefault = (e) => {
      toast(e.providerName + ' is your default provider for new chats, so it is always shown. Choose another default above first to hide it.', { kind: 'warn', timeout: 8000 });
      drawVis();
    };
    const rowCb = (e) => {
      const isDef = e.providerId === def;
      const cb = checkbox(shown(e), h('span', null, e.providerName, ' ', h('span', { class: 'muted small mono' }, e.providerId),
        isDef ? h('span', { class: 'badge badge-accent', title: 'The default provider is always shown' }, 'default') : null), (v) => {
        if (!v && isDef) { keepDefault(e); return; }
        const ids = new Set(hiddenList());
        if (v) ids.delete(e.providerId); else ids.add(e.providerId);
        save([...ids]);
      });
      cb.dataset.provider = e.providerId;
      cb.title = isDef ? 'Default provider: always shown in chat pickers' : 'Show in chat pickers';
      return cb;
    };
    const gcfg = groupsConfig();
    const grouped = gcfg.groups.map((g) => ({ g, members: g.members.map((m) => rows.find((e) => e.providerId === m.provider)).filter(Boolean) })).filter((x) => x.members.length);
    const inGroup = new Set(grouped.flatMap((x) => x.members.map((e) => e.providerId)));
    visBox.replaceChildren(
      h('div', { class: 'row wrap' },
        h('div', { class: 'muted small grow' }, rows.filter(shown).length + ' of ' + rows.length + ' shown. Unticked providers are left out of the provider pickers on the New chat screen and in the chat header. They stay configured, and a chat that already uses one still shows it. Only you see this choice; it follows you to every browser.'),
        btn('Show all', () => save([]), { size: 'sm' }),
        btn('Hide all except default', () => {
          if (!def) { toast('Set a default provider above first: it is the one that stays.', { kind: 'warn' }); return; }
          save(hideAllExcept(rows.map((e) => e.providerId), def));
        }, { size: 'sm' })),
      h('div', { class: 'vis-list', role: 'group', 'aria-label': 'Show in chat pickers' }, ...rows.filter((e) => !inGroup.has(e.providerId)).map(rowCb)),
      // spec 024: a group is one row (hides or shows all its members) with its members under it
      ...grouped.map(({ g, members }) => {
        const gcb = checkbox(members.some(shown), h('span', null, h('strong', null, g.name), ' ', h('span', { class: 'muted small' }, 'group of ' + members.length)), (v) => {
          const ids = new Set(hiddenList());
          for (const e of members) { if (v) ids.delete(e.providerId); else if (e.providerId !== def) ids.add(e.providerId); }
          if (!v && members.some((e) => e.providerId === def)) toast('The group holds your default provider, which is always shown.', { kind: 'warn', timeout: 8000 });
          save([...ids]);
        });
        gcb.dataset.group = g.id;
        gcb.title = 'Show this group in chat pickers (all its providers)';
        return h('div', { class: 'vis-group' }, gcb, h('div', { class: 'vis-list vis-members', role: 'group', 'aria-label': g.name + ' providers' }, ...members.map(rowCb)));
      }),
      def && hidden.has(def) ? h('div', { class: 'muted small' }, 'Your default provider was hidden earlier; it is shown while it is the default.') : null);
  };
  // ----- spec 024: provider groups (a display alias for the chat pickers; per user, saved with the preferences) -----
  const saveGroups = (cfg) => { setGroups(cfg); drawGroups(); drawVis(); };
  const newGroup = async () => {
    const name = await promptDialog({ title: 'New provider group', label: 'Name shown in the chat pickers', placeholder: 'e.g. Team gateway', confirmText: 'Create',
      validate: (x) => (!x.trim() ? 'Name required' : x.trim().length > 80 ? 'At most 80 characters' : null) });
    if (!name) return;
    const cfg = groupsConfig();
    cfg.groups.push({ id: newGroupId(), name: name.trim(), members: [] });
    saveGroups(cfg);
  };
  let showAllModels = false;
  const drawGroups = () => {
    const cfg = groupsConfig();
    const rows = entries.filter((e) => e.configured && allowed(e) && !e.gwVariantOf);
    const byId = new Map(entries.map((e) => [e.providerId, e]));
    const groupCard = (g) => {
      const nameInp = input({ value: g.name, class: 'inp inp-sm', 'aria-label': 'Group name', maxlength: '80' });
      nameInp.addEventListener('change', () => { const c = groupsConfig(); const x = c.groups.find((y) => y.id === g.id); if (x && nameInp.value.trim()) { x.name = nameInp.value.trim(); saveGroups(c); } else nameInp.value = g.name; });
      const memberRow = (e) => {
        const owner = groupOfProvider(e.providerId, cfg);
        const mine = owner && owner.id === g.id;
        const m = mine ? g.members.find((x) => x.provider === e.providerId) : null;
        const cb = checkbox(!!mine, h('span', null, e.providerName, ' ', h('span', { class: 'muted small mono' }, e.providerId),
          owner && !mine ? h('span', { class: 'muted small' }, ' (in ' + owner.name + ')') : null), (v) => {
          const c = groupsConfig(); const x = c.groups.find((y) => y.id === g.id); if (!x) return;
          if (v) { if (!groupOfProvider(e.providerId, c)) x.members.push({ provider: e.providerId, prefix: '' }); } else x.members = x.members.filter((y) => y.provider !== e.providerId);
          saveGroups(c);
        }, { disabled: !!owner && !mine });
        cb.dataset.provider = e.providerId;
        const pre = mine ? input({ value: m.prefix, class: 'inp inp-sm mono grp-prefix', placeholder: 'prefix (optional)', 'aria-label': 'Model label prefix for ' + e.providerName, maxlength: '40' }) : null;
        if (pre) {
          pre.dataset.provider = e.providerId;
          pre.addEventListener('change', () => { const c = groupsConfig(); const x = c.groups.find((y) => y.id === g.id); const mm = x && x.members.find((y) => y.provider === e.providerId); if (mm) { mm.prefix = pre.value.trim(); saveGroups(c); } });
        }
        return h('div', { class: 'grp-member' }, cb, pre);
      };
      // members that are no longer configured (or not allowed): listed so they can be removed
      const gone = g.members.filter((m) => !rows.some((e) => e.providerId === m.provider));
      const picker = groupPicker(rows.map((e) => ({ id: e.providerId, name: e.providerName, defaultModel: e.defaultModel || '', models: (e.models || []).map((x) => ({ id: x.id, name: x.name || x.id })) })),
        { groups: [g], modelNames: cfg.modelNames }, {}).find((x) => x.group);
      const labels = picker ? picker.models.map((x) => x.label) : [];
      return h('div', { class: 'grp-card', 'data-group': g.id },
        h('div', { class: 'row wrap' }, field('Name', nameInp, null, { inline: true }), h('span', { class: 'grow' }),
          btn('Delete group', async () => {
            if (!(await confirmDialog({ title: 'Delete the group "' + g.name + '"?', message: 'Its providers show separately again. Nothing else changes.', confirmText: 'Delete', danger: true }))) return;
            const c = groupsConfig(); c.groups = c.groups.filter((y) => y.id !== g.id); saveGroups(c);
          }, { size: 'sm', icon: 'trash' })),
        h('div', { class: 'muted small' }, 'Tick the providers to show as "' + g.name + '". Each model is listed as <prefix>-<model name>; leave the prefix empty to list the plain name.'),
        h('div', { class: 'grp-members', role: 'group', 'aria-label': g.name + ' members' }, ...rows.map(memberRow),
          ...gone.map((m) => h('div', { class: 'grp-member' }, checkbox(true, h('span', null, (byId.get(m.provider) || {}).providerName || m.provider, ' ', h('span', { class: 'muted small' }, '(not available)')), () => {
            const c = groupsConfig(); const x = c.groups.find((y) => y.id === g.id); if (x) { x.members = x.members.filter((y) => y.provider !== m.provider); saveGroups(c); }
          })))),
        labels.length ? h('div', { class: 'muted small grp-preview', title: labels.join('\n') }, 'Model list: ' + labels.slice(0, 8).join(', ') + (labels.length > 8 ? ', … (' + labels.length + ' in all)' : '')) : null);
    };
    // model display names: the models of grouped providers (and names already set); all models on request
    const grouped = new Set(cfg.groups.flatMap((g) => g.members.map((m) => m.provider)));
    const models = new Map();
    for (const e of rows) for (const m of e.models || []) if ((showAllModels || grouped.has(e.providerId) || cfg.modelNames[m.id]) && !models.has(m.id)) models.set(m.id, m.name || m.id);
    for (const id of Object.keys(cfg.modelNames)) if (!models.has(id)) models.set(id, id);
    const nameRow = (id, gooseName) => {
      const inp = input({ value: cfg.modelNames[id] || '', class: 'inp inp-sm', placeholder: gooseName, 'aria-label': 'Display name for ' + id, maxlength: '120' });
      inp.dataset.model = id;
      inp.addEventListener('change', () => { const c = groupsConfig(); const v = inp.value.trim(); if (v) c.modelNames[id] = v; else delete c.modelNames[id]; saveGroups(c); });
      return h('div', { class: 'grp-name-row' }, h('span', { class: 'mono small' }, id), inp);
    };
    grpBox.replaceChildren(
      h('div', { class: 'muted small' }, 'Show several providers as one entry in the New chat and chat header pickers (for example providers that serve the same models). Picking a model label still uses the real provider and model. Only the display changes; only you see it, and it follows you to every browser.'),
      cfg.groups.length ? h('div', { class: 'stack' }, ...cfg.groups.map(groupCard)) : h('div', { class: 'muted' }, 'No groups yet. Use "New group".'),
      h('div', { class: 'grp-names' },
        h('div', { class: 'row wrap' }, h('strong', null, 'Model display names'), h('span', { class: 'muted small grow' }, 'Optional friendly names, used in the chat pickers for every provider.'),
          toggle(showAllModels, (v) => { showAllModels = v; drawGroups(); }, { text: 'All models' })),
        models.size ? h('div', { class: 'grp-name-list' }, ...[...models.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([id, n]) => nameRow(id, n)))
          : h('div', { class: 'muted small' }, 'Models of grouped providers are listed here. Turn on "All models" for the others.')));
  };
  const draw = () => {
    const items = entries.filter((e) => allowed(e) && (showAll || e.configured || e.providerType === 'Custom') && (!q || (e.providerName + ' ' + e.providerId + ' ' + e.description).toLowerCase().includes(q)));
    if (!items.length) { list.replaceChildren(empty('cpu', entries.length ? 'No providers match' : 'No providers', showAll ? '' : 'Turn on “Show unconfigured” to set one up.')); return; }
    list.replaceChildren(...items.map(providerRow));
  };
  const providerRow = (e) => {
    const detail = h('div', { class: 'prov-detail', hidden: true });
    let open = false;
    const head = h('button', { type: 'button', class: 'prov-head', 'aria-expanded': 'false', onclick: () => { open = !open; head.setAttribute('aria-expanded', String(open)); detail.hidden = !open; if (open && !detail.firstChild) providerDetail(e, detail); } },
      icon('chevronRight', 14, 'prov-chev'),
      h('div', { class: 'grow' }, h('div', { class: 'strong' }, e.providerName, ' ', h('span', { class: 'muted small mono' }, e.providerId)), h('div', { class: 'muted small' }, e.description || '')),
      e.deprecated ? h('span', { class: 'badge badge-warn' }, 'deprecated') : null,
      e.refreshing ? spinner(12) : null,
      e.lastRefreshError ? h('span', { class: 'badge badge-err', title: e.lastRefreshError }, 'refresh error') : null,
      h('span', { class: 'badge' }, e.providerType || ''),
      h('span', { class: 'badge' }, (e.models || []).length + ' models'),
      e.providerId === defaults.providerId ? h('span', { class: 'badge badge-accent' }, 'default') : null,
      e.configured ? h('span', { class: 'badge badge-ok' }, icon('check', 11), ' configured') : h('span', { class: 'badge' }, 'not configured'));
    return h('div', { class: ['prov', open ? 'open' : ''] }, head, detail);
  };
  const providerDetail = async (e, box) => {
    box.replaceChildren(spinner(16));
    const keys = e.configKeys || [];
    const oauth = keys.some((k) => k.oauthFlow || k.deviceCodeFlow);
    let fields = [];
    try { fields = keys.length ? (await rpc.call(G('providers/config/read'), { providerId: e.providerId })).fields || [] : []; } catch (err) { box.replaceChildren(banner('error', errMsg(err))); return; }
    const inputs = new Map();
    const rows = keys.map((k) => {
      const f = fields.find((x) => x.key === k.name) || { key: k.name, isSet: false, isSecret: k.secret, required: k.required };
      const secret = f.isSecret || k.secret;
      const inp = input({ type: secret ? 'password' : 'text', autocomplete: 'new-password', class: 'inp mono', value: secret ? '' : (f.value ?? ''), placeholder: secret ? (f.isSet ? '•••••••• (set – leave blank to keep)' : 'not set') : (k.default || ''), disabled: !canEdit });
      inputs.set(k.name, { inp, f, secret });
      return field(h('span', null, k.name, k.required ? h('span', { class: 'req' }, ' *') : null, secret ? h('span', { class: 'badge' }, icon('lock', 10), ' secret') : null, f.isSet ? h('span', { class: 'badge badge-ok' }, 'set') : null), inp, k.oauthFlow ? 'Filled by signing in' : k.deviceCodeFlow ? 'Filled by device sign-in' : null);
    });
    const models = (e.models || []);
    box.replaceChildren(
      (e.setupSteps || []).length ? h('ol', { class: 'setup-steps' }, ...e.setupSteps.map((s) => h('li', null, mdElement(s, 'md md-inline')))) : null,
      rows.length ? h('div', { class: 'grid2' }, ...rows) : h('div', { class: 'muted' }, 'This provider has no configuration keys.'),
      canEdit ? h('div', { class: 'row wrap' },
        rows.length ? actionBtn('Save', async () => {
          const upd = [];
          for (const [key, { inp, secret, f }] of inputs) { const v = inp.value; if (secret && !v) continue; if (!secret && v === (f.value ?? '')) continue; upd.push({ key, value: v }); }
          if (!upd.length) { toast('Nothing changed'); return; }
          await rpc.call(G('providers/config/save'), { providerId: e.providerId, fields: upd });
          toast('Saved ' + e.providerName, { kind: 'success' }); load();
        }, { variant: 'primary' }) : null,
        oauth ? actionBtn('Sign in', async () => { toast('Follow the sign-in prompt…', { timeout: 6000 }); await rpc.call(G('providers/config/authenticate'), { providerId: e.providerId }); toast('Signed in to ' + e.providerName, { kind: 'success' }); load(); }, { icon: 'key' }) : null,
        actionBtn('Check', async () => { const r = await rpc.call(G('providers/readiness/check'), { providerId: e.providerId }); toast(r.ready ? e.providerName + ' is ready' : 'Not ready: ' + (r.error || 'unknown'), { kind: r.ready ? 'success' : 'error' }); }, { icon: 'activity' }),
        e.supportsRefresh ? actionBtn('Refresh models', async () => { await rpc.call(G('providers/inventory/refresh'), { providerIds: [e.providerId] }); setTimeout(load, 2000); }, { icon: 'refresh', success: 'Refresh started' }) : null,
        btn('Supported models', () => supportedModels(e), { icon: 'list' }),
        e.providerType === 'Custom' ? btn('Edit custom', () => customDialog(e.providerId), { icon: 'edit' }) : null,
        e.providerType === 'Custom' ? btn('Delete', async () => {
          if (!(await confirmDialog({ title: 'Delete custom provider ' + e.providerName + '?', confirmText: 'Delete', danger: true }))) return;
          try { await rpc.call(G('providers/custom/delete'), { providerId: e.providerId }); toast('Deleted', { kind: 'success' }); load(); } catch (err) { toastError(err); }
        }, { variant: 'danger-soft', icon: 'trash' }) : (e.configured && rows.length ? btn('Remove configuration', async () => {
          if (!(await confirmDialog({ title: 'Remove configuration for ' + e.providerName + '?', message: 'Stored keys for this provider will be deleted.', confirmText: 'Remove', danger: true }))) return;
          try { await rpc.call(G('providers/config/delete'), { providerId: e.providerId }); toast('Removed', { kind: 'success' }); load(); } catch (err) { toastError(err); }
        }, { variant: 'danger-soft' }) : null)) : null,
      models.length ? h('details', { class: 'prov-models' }, h('summary', null, models.length + ' models' + (e.lastUpdatedAt ? ' · updated ' + relTime(e.lastUpdatedAt) : '')),
        table([{ label: 'Model', render: (m) => h('span', null, m.name || m.id, m.recommended ? h('span', { class: 'badge badge-accent' }, 'recommended') : null) }, { label: 'ID', render: (m) => h('span', { class: 'mono small' }, m.id) }, { label: 'Context', render: (m) => m.contextLimit ? Math.round(m.contextLimit / 1000) + 'k' : '' }, { label: 'Reasoning', render: (m) => m.reasoning ? icon('brain', 13) : '' }], models)) : null);
  };
  const supportedModels = async (e) => {
    const b = h('div', null, spinner(16));
    const m = modal({ title: 'Supported models · ' + e.providerName, size: 'md', body: b, footer: [btn('Close', () => m.close())] });
    try { const r = await rpc.call(G('providers/supported-models/list'), { providerId: e.providerId }); b.replaceChildren((r.models || []).length ? h('ul', { class: 'plain-list mono small' }, ...r.models.map((x) => h('li', null, x))) : empty('cpu', 'No models reported')); }
    catch (err) { b.replaceChildren(banner('error', errMsg(err))); }
  };
  const customDialog = async (providerId) => {
    let cur = null;
    if (providerId) { try { cur = (await rpc.call(G('providers/custom/read'), { providerId })).provider; } catch (e) { toastError(e); return; } }
    const engine = select([{ value: 'openai', label: 'OpenAI compatible' }, { value: 'anthropic', label: 'Anthropic compatible' }, { value: 'ollama', label: 'Ollama' }], (cur && cur.engine) || 'openai');
    const name = input({ value: (cur && cur.displayName) || '', placeholder: 'My provider' });
    const url = input({ value: (cur && cur.apiUrl) || '', placeholder: 'https://api.example.com/v1', class: 'inp mono' });
    const basePath = input({ value: (cur && cur.basePath) || '', placeholder: 'optional, e.g. v1/chat/completions', class: 'inp mono' });
    const key = input({ type: 'password', autocomplete: 'new-password', placeholder: cur && cur.apiKeySet ? '•••••••• (set – leave blank to keep)' : 'API key' });
    const models = input({ value: ((cur && cur.models) || []).join(', '), placeholder: 'model-a, model-b', class: 'inp mono' });
    const headers = textarea({ rows: 3, class: 'inp mono', value: cur && cur.headers ? Object.entries(cur.headers).map(([k, v]) => k + ': ' + v).join('\n') : '', placeholder: 'X-Header: value' });
    let requiresAuth = cur ? cur.requiresAuth : true; let streaming = cur ? cur.supportsStreaming !== false : true; let toolshim = cur ? !!cur.toolshim : false; let thinking = cur ? !!cur.preservesThinking : false;
    const err = h('div', { class: 'field-error' });
    const m = modal({ title: cur ? 'Edit ' + cur.displayName : 'New custom provider', size: 'lg',
      body: h('div', { class: 'stack' }, h('div', { class: 'grid2' }, field('Engine', engine), field('Display name', name)), field('API URL', url), field('Base path', basePath), field('API key', key),
        field('Models', models, 'Comma separated'), field('Extra headers', headers, 'One per line'),
        h('div', { class: 'row wrap' }, checkbox(requiresAuth, 'Requires API key', (v) => { requiresAuth = v; }), checkbox(streaming, 'Supports streaming', (v) => { streaming = v; }), (store.get('gooseCaps') || {}).toolshim === false ? null : checkbox(toolshim, 'Tool shim', (v) => { toolshim = v; }), checkbox(thinking, 'Preserve thinking', (v) => { thinking = v; })), err),
      footer: [btn('Cancel', () => m.close()), btn(cur ? 'Save' : 'Create', async () => {
        err.textContent = '';
        const hdr = {}; for (const line of headers.value.split('\n')) { const i = line.indexOf(':'); if (i > 0) hdr[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
        const req = { engine: engine.value, displayName: name.value.trim(), apiUrl: url.value.trim(), models: models.value.split(',').map((s) => s.trim()).filter(Boolean), supportsStreaming: streaming, headers: hdr, requiresAuth, basePath: basePath.value.trim() || null, preservesThinking: thinking, toolshim };
        if (key.value) req.apiKey = key.value;
        if (!req.displayName || !req.apiUrl) { err.textContent = 'Name and URL are required'; return; }
        try {
          if (cur) await rpc.call(G('providers/custom/update'), { providerId: cur.providerId, ...req, catalogProviderId: cur.catalogProviderId || null });
          else await rpc.call(G('providers/custom/create'), req);
          toast('Provider saved', { kind: 'success' }); m.close(); load();
        } catch (e) { err.textContent = errMsg(e); }
      }, { variant: 'primary' })] });
  };
  const loadSecrets = async () => {
    try {
      const r = await rpc.call(G('providers/secrets/list'), {});
      secretsBox.replaceChildren(table([
        { label: 'Provider', render: (s) => s.providerDisplayName || s.provider },
        { label: 'Name', render: (s) => h('span', { class: 'mono small' }, s.name) },
        { label: 'Storage', render: (s) => h('span', { class: 'badge' }, s.storage) },
        { label: 'Status', render: (s) => h('span', { class: 'badge ' + (s.status === 'valid' ? 'badge-ok' : s.status === 'expired' ? 'badge-err' : '') }, s.status) },
        { label: 'Expires', render: (s) => s.expiresAt ? relTime(s.expiresAt) : '' },
        { label: '', class: 'right', render: (s) => canEdit && s.canDelete ? iconBtn('trash', 'Delete secret', async () => {
          if (!(await confirmDialog({ title: 'Delete secret ' + s.name + '?', confirmText: 'Delete', danger: true }))) return;
          try { await rpc.call(G('providers/secrets/delete'), { id: s.id }); toast('Deleted', { kind: 'success' }); loadSecrets(); load(); } catch (e) { toastError(e); }
        }, { variant: 'danger-soft' }) : null },
      ], r.secrets || [], { empty: 'No stored provider secrets' }));
    } catch (e) { secretsBox.replaceChildren(banner('error', errMsg(e))); }
  };
  async function load() {
    try {
      const [p, d] = await Promise.all([rpc.call(G('providers/list'), {}), rpc.call(G('defaults/read'), {}).catch(() => ({}))]);
      entries = (p.entries || []).filter((e) => !e.deprecated || e.configured).sort((a, b) => (b.configured - a.configured) || a.providerName.localeCompare(b.providerName));
      defaults = d || {};
      rememberProviderMeta({ defaultProvider: defaults.providerId || '', entries: p.entries || [] });
      rememberInventory(p.entries || []);   // spec 024: model lists for a grouped chat header
      drawDefaults(); draw(); drawGroups();
    } catch (e) { list.replaceChildren(banner('error', errMsg(e))); defBox.replaceChildren(); visBox.replaceChildren(); grpBox.replaceChildren(); }
  }
  load(); loadSecrets();
}

// ===================================================================== Prompts
function promptsTab(body) {
  const canEdit = policy('prompts_edit');
  let prompts = []; let sel = null; let view = 'edit';
  const listEl = h('div', { class: 'split-list' }, skeleton(5));
  const detail = h('div', { class: 'split-detail' });
  body.replaceChildren(ro('prompts_edit', 'system prompts'), h('p', { class: 'muted' }, 'Templates Goose uses to build its system prompts. Customizations are saved in your profile and override the built-in default.'), h('div', { class: 'split' }, listEl, detail));
  const drawList = () => listEl.replaceChildren(...prompts.map((p) => h('button', { type: 'button', class: ['litem', sel && sel.name === p.name ? 'active' : ''], onclick: () => open(p.name) },
    icon('scroll', 14), h('div', { class: 'litem-main' }, h('div', { class: 'litem-title' }, p.name, p.isCustomized ? h('span', { class: 'badge badge-accent' }, 'customized') : null), h('div', { class: 'litem-sub' }, p.description || '')))));
  const open = async (name) => {
    detail.replaceChildren(spinner(16));
    try {
      const r = await rpc.call(G('config/prompts/get'), { name });
      sel = r; drawList(); drawDetail();
    } catch (e) { detail.replaceChildren(banner('error', errMsg(e))); }
  };
  const drawDetail = () => {
    const p = sel; if (!p) { detail.replaceChildren(empty('scroll', 'Select a prompt')); return; }
    const ta = textarea({ value: p.content, rows: 28, class: 'inp mono prompt-ed', disabled: !canEdit, 'aria-label': 'Prompt template' });
    const pane = h('div');
    const drawPane = () => pane.replaceChildren(view === 'edit' ? ta : view === 'diff' ? diffView(p.defaultContent, ta.value) : h('pre', { class: 'json tall' }, p.defaultContent));
    detail.replaceChildren(
      h('div', { class: 'detail-head' }, h('div', null, h('h2', null, p.name), p.isCustomized ? h('span', { class: 'badge badge-accent' }, 'customized') : h('span', { class: 'badge' }, 'default')),
        canEdit ? h('div', { class: 'row' },
          p.isCustomized ? btn('Reset to default', async () => {
            if (!(await confirmDialog({ title: 'Reset ' + p.name + '?', message: 'Your customization will be deleted.', confirmText: 'Reset', danger: true }))) return;
            try { await rpc.call(G('config/prompts/reset'), { name: p.name }); toast('Reset', { kind: 'success' }); await reload(); open(p.name); } catch (e) { toastError(e); }
          }, { size: 'sm' }) : null,
          actionBtn('Save', async () => { await rpc.call(G('config/prompts/save'), { name: p.name, content: ta.value }); await reload(); open(p.name); }, { variant: 'primary', size: 'sm', success: 'Prompt saved' })) : null),
      tabs([{ id: 'edit', label: 'Edit' }, { id: 'diff', label: 'Diff vs default' }, { id: 'default', label: 'Default' }], view, (v) => { view = v; drawDetail(); }),
      pane);
    drawPane();
  };
  const reload = async () => { const r = await rpc.call(G('config/prompts/list'), {}); prompts = r.prompts || []; drawList(); };
  reload().then(() => { if (prompts.length) open(prompts[0].name); else detail.replaceChildren(empty('scroll', 'No prompts')); }).catch((e) => listEl.replaceChildren(banner('error', errMsg(e))));
}

// Line diff (LCS) between a and b.
export function diffView(a, b) {
  const A = String(a || '').split(/\r?\n/), B = String(b || '').split(/\r?\n/);
  if (A.length * B.length > 4e6) return banner('warn', 'Too large to diff');
  const n = A.length, m = B.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0, changes = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { out.push(['', A[i]]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push(['del', A[i++]]); changes++; } else { out.push(['add', B[j++]]); changes++; }
  }
  while (i < n) { out.push(['del', A[i++]]); changes++; }
  while (j < m) { out.push(['add', B[j++]]); changes++; }
  if (!changes) return h('div', { class: 'muted pad' }, 'No differences from the default.');
  return h('div', { class: 'diff' }, h('div', { class: 'diff-head' }, changes + ' changed line(s)'),
    h('div', { class: 'diff-body' }, ...out.map(([k, t]) => h('div', { class: ['dl', k] }, (k === 'add' ? '+ ' : k === 'del' ? '- ' : '  ') + t))));
}

// ===================================================================== Preferences
const PREF_META = {
  autoCompactThreshold: { label: 'Auto-compact threshold', hint: 'Fraction of the context window (0–1) at which Goose summarizes the conversation. Empty = Goose default (0.8). 0 disables.', type: 'number' },
  gooseThinkingEffort: { label: 'Default thinking effort', hint: 'For models that support extended thinking.', type: 'select', options: ['', 'off', 'low', 'medium', 'high', 'max'] },
  voiceAutoSubmitPhrases: { label: 'Voice auto-submit phrases', hint: 'Comma separated phrases that send a dictated message.', type: 'list' },
  voiceDictationProvider: { label: 'Dictation provider', hint: 'Provider used for speech-to-text.', type: 'text' },
  voiceDictationPreferredMic: { label: 'Preferred microphone', hint: 'Device name or id.', type: 'text' },
};
function preferencesTab(body) {
  const goose = h('div', { class: 'card' }, skeleton(4));
  const p = prefs();
  const ap = activityPrefs();
  body.replaceChildren(
    section('Chat', null, h('div', { class: 'card stack' },
      settingRow('Enter sends the message', 'When off, use Ctrl+Enter to send and Enter for a new line.', toggle(p.enterToSend !== false, (v) => setPref('enterToSend', v))),
      settingRow('Show message timestamps', null, toggle(!!p.showTimestamps, (v) => setPref('showTimestamps', v))),
      settingRow('Messages shown in a chat', 'How much of a long chat is on screen when you open it. Older messages stay in the chat; this only limits what the page draws at once. Applies when you next open a chat.',
        select([{ value: '100', label: 'Last 100' }, { value: '300', label: 'Last 300' }, { value: '1000', label: 'Last 1000' }, { value: '0', label: 'All (can be slow)' }], String(p.historyWindow ?? 300), { class: 'inp inp-sm', onchange: (e) => setPref('historyWindow', Number(e.target.value)) })),
      settingRow('Load earlier messages when scrolling up', 'When off, use the "Show earlier messages" button at the top of the chat.', toggle(p.autoLoadEarlier !== false, (v) => setPref('autoLoadEarlier', v))),
      settingRow('Thinking', 'Goose\'s reasoning before each step. Auto keeps it open while Goose works and folds it when the turn ends.',
        select([{ value: 'auto', label: 'Auto' }, { value: 'expanded', label: 'Always expanded' }, { value: 'collapsed', label: 'Collapsed' }], ap.thinking, { class: 'inp inp-sm', 'aria-label': 'Thinking', onchange: (e) => patchPref('activity', { thinking: e.target.value }) })),
      settingRow('Tool details', 'Auto opens a tool call while it runs (input, live output, approval) and folds it when done. Detailed keeps every call open; Concise shows headers only.',
        select([{ value: 'auto', label: 'Auto' }, { value: 'detailed', label: 'Detailed' }, { value: 'concise', label: 'Concise' }], ap.tools, { class: 'inp inp-sm', 'aria-label': 'Tool details', onchange: (e) => patchPref('activity', { tools: e.target.value }) })),
      settingRow('Live activity bar', 'While Goose works, show what it is doing, how many tool calls it has made and for how long, under the last message.',
        toggle(ap.statusBar, (v) => patchPref('activity', { statusBar: v }))))),
    section('Goose preferences', null, goose));
  (async () => {
    try {
      const r = await rpc.call(G('preferences/read'), {});
      const vals = r.values || [];
      const inputs = [];
      const rows = vals.map((v) => {
        const meta = PREF_META[v.key] || { label: v.key, type: typeof v.value === 'number' ? 'number' : 'text' };
        let inp;
        if (meta.type === 'select') inp = select(meta.options.map((o) => ({ value: o, label: o || 'Goose default' })), v.value ?? '');
        else if (meta.type === 'number') inp = input({ type: 'number', step: '0.05', min: '0', max: '1', value: v.value ?? '', placeholder: 'default' });
        else if (meta.type === 'list' || Array.isArray(v.value)) inp = input({ value: Array.isArray(v.value) ? v.value.join(', ') : (v.value ?? ''), placeholder: 'e.g. send it, over' });
        else inp = input({ value: v.value ?? '', placeholder: 'default' });
        inputs.push({ key: v.key, inp, meta, orig: v.value });
        return field(meta.label, inp, meta.hint);
      });
      goose.replaceChildren(...rows, h('div', { class: 'row' }, actionBtn('Save preferences', async () => {
        const values = inputs.map(({ key, inp, meta, orig }) => {
          const raw = inp.value.trim();
          let value = raw === '' ? null : raw;
          if (value !== null && meta.type === 'number') value = Number(raw);
          if (value !== null && (meta.type === 'list' || Array.isArray(orig))) value = raw.split(',').map((s) => s.trim()).filter(Boolean);
          return { key, value };
        });
        await rpc.call(G('preferences/save'), { values });
      }, { variant: 'primary', success: 'Preferences saved' })));
    } catch (e) { goose.replaceChildren(banner('error', errMsg(e))); }
  })();
}
function settingRow(title, hint, control) {
  return h('div', { class: 'set-row' }, h('div', { class: 'grow' }, h('div', { class: 'strong' }, title), hint ? h('div', { class: 'muted small' }, hint) : null), control);
}

// ===================================================================== Hints
function hintsTab(body) {
  body.replaceChildren(skeleton(5));
  (async () => {
    try {
      const r = await GET('/api/me/hints');
      const editable = r.editable !== false && policy('hints_edit');
      const ta = textarea({ value: r.personal || '', rows: 16, class: 'inp mono', disabled: !editable, placeholder: '# My hints\n- Prefer PowerShell 7\n- Our repos live in C:\\src' });
      let t = 'edit';
      const pane = h('div');
      const drawPane = () => pane.replaceChildren(tabs([{ id: 'edit', label: 'Personal' }, { id: 'preview', label: 'Preview' }, { id: 'effective', label: 'Effective (what Goose sees)' }], t, (v) => { t = v; drawPane(); }),
        t === 'edit' ? ta : t === 'preview' ? h('div', { class: 'md-preview' }, mdElement(ta.value || '*empty*')) : h('pre', { class: 'json tall' }, r.effective || ''));
      drawPane();
      body.replaceChildren(
        h('p', { class: 'muted' }, 'Goose hints are extra instructions added to every chat. Your team\'s hints come last and take precedence: if a personal hint conflicts with a team hint, Goose follows the team hint.' + (r.team ? ' Team: ' + r.team.name + '.' : '')),
        r.personalDropped ? banner('warn', 'Your personal hints are not used: your team does not allow personal hints. They are kept here in case that changes.') : null,
        r.native && r.managed ? banner('info', 'Managed native hints: Goose Web writes the effective hints to ' + (r.path || 'the native .goosehints') + ', which Goose Desktop, the goose CLI and scheduled runs on this account load too. Edit team and assigned documents in Admin > Hints, your own below.') : null,
        r.native && !r.managed ? banner('info', 'Native profile: you are editing ' + (r.path || 'the native .goosehints') + ' directly (also used by Goose Desktop). Library and team hints are not applied to it unless managed native hints are turned on (goose-web native-hints).') : null,
        section('Assigned by your administrator', null, (r.assigned || []).length ? h('div', { class: 'stack-sm' }, ...r.assigned.map((a) => h('div', { class: 'card row' }, icon('lock', 14), h('div', { class: 'grow' }, h('div', { class: 'strong' }, a.name), h('div', { class: 'muted small' }, a.description || ''))))) : h('div', { class: 'muted' }, 'None assigned.')),
        section('Personal hints', editable ? actionBtn('Save', async () => { await PUT('/api/me/hints', { personal: ta.value }); r.personal = ta.value; }, { variant: 'primary', size: 'sm', success: 'Hints saved' }) : null,
          !editable ? banner('info', 'Read-only: your policy does not allow editing hints.') : null, pane));
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  })();
}

// ===================================================================== Tool permissions
function toolsTab(body) {
  const canEdit = policy('tools_permissions');
  const cc = currentChat();
  const sessions = [...sessionsState.items.values()].slice(0, 50);
  let sid = (cc && cc.id) || (sessions[0] && sessions[0].sessionId) || '';
  const sSel = select(sessions.map((s) => ({ value: s.sessionId, label: sessionTitle(s) })), sid, { class: 'inp' });
  const out = h('div');
  const q = input({ type: 'search', placeholder: 'Filter tools…', class: 'inp inp-sm' });
  let tools = []; const changes = new Map();
  body.replaceChildren(ro('tools_permissions', 'tool permissions'),
    h('p', { class: 'muted' }, 'Per-tool approval policy, used in “approve” and “smart approve” modes. Tools are listed from a chat so that its extensions are loaded.'),
    h('div', { class: 'row wrap' }, field('Load tools from chat', sSel), q), out);
  const draw = () => {
    const f = q.value.toLowerCase();
    const items = tools.filter((t) => !f || (t.name + ' ' + t.description).toLowerCase().includes(f));
    out.replaceChildren(
      canEdit ? h('div', { class: 'row' }, actionBtn('Save ' + (changes.size || '') + ' change(s)', async () => {
        if (!changes.size) return;
        await rpc.call(G('tools/permissions/set'), { toolPermissions: [...changes].map(([toolName, permission]) => ({ toolName, permission })) });
        for (const [n, p] of changes) { const t = tools.find((x) => x.name === n); if (t) t.permission = p; }
        changes.clear(); draw();
      }, { variant: 'primary', size: 'sm', success: 'Permissions saved', disabled: !changes.size })) : null,
      table([
        { label: 'Tool', render: (t) => h('div', null, h('div', { class: 'mono small strong' }, t.name), h('div', { class: 'muted small clamp2' }, t.description || '')) },
        { label: 'Permission', width: '180px', render: (t) => {
          const s = select([{ value: '', label: 'Mode default' }, { value: 'always_allow', label: 'Always allow' }, { value: 'ask_before', label: 'Ask before' }, { value: 'never_allow', label: 'Never allow' }], changes.get(t.name) ?? t.permission ?? '', { class: 'inp inp-sm', disabled: !canEdit });
          s.addEventListener('change', () => { if (s.value) changes.set(t.name, s.value); else changes.delete(t.name); draw(); });
          return s;
        } },
      ], items, { empty: 'No tools' }));
  };
  q.addEventListener('input', debounce(draw, 120));
  const load = async () => {
    if (!sid) { out.replaceChildren(empty('tool', 'No chat available', 'Open or start a chat first; tools are listed from a running session.')); return; }
    out.replaceChildren(spinner(16));
    try { const r = await rpc.call(G('tools/list'), { sessionId: sid }); tools = (r.tools || []).sort((a, b) => a.name.localeCompare(b.name)); changes.clear(); draw(); }
    catch (e) { out.replaceChildren(banner('error', errMsg(e) + ' – open the chat once so it is loaded, then retry.')); }
  };
  sSel.addEventListener('change', () => { sid = sSel.value; load(); });
  load();
}

// ===================================================================== Advanced config
function advancedTab(body) {
  const out = h('div', null, skeleton(6));
  const q = input({ type: 'search', placeholder: 'Filter keys…', class: 'inp inp-sm' });
  let cfg = {};
  body.replaceChildren(banner('warn', 'Raw Goose config.yaml values for your profile. Wrong values can break Goose; prefer the dedicated settings pages.'),
    h('div', { class: 'row' }, q, btn('Add key', () => edit(null), { icon: 'plus', size: 'sm', variant: 'primary' }), iconBtn('refresh', 'Reload', () => load())), out);
  const edit = (key) => {
    const k = input({ value: key || '', placeholder: 'GOOSE_SOMETHING', class: 'inp mono', disabled: !!key });
    const v = textarea({ value: key ? prettyJson(cfg[key]) : '', rows: 10, class: 'inp mono', placeholder: '"string" or 42 or {"json": true}' });
    let secret = false;
    const err = h('div', { class: 'field-error' });
    const m = modal({ title: key ? 'Edit ' + key : 'Add config key', size: 'lg', body: h('div', { class: 'stack' }, field('Key', k), field('Value (JSON; bare text is saved as a string)', v), checkbox(false, 'Store as secret (keyring)', (x) => { secret = x; }), err),
      footer: [btn('Cancel', () => m.close()), btn('Save', async () => {
        let value; const raw = v.value.trim();
        try { value = JSON.parse(raw); } catch { value = raw; }
        if (!k.value.trim()) { err.textContent = 'Key required'; return; }
        try { await rpc.call(G('config/upsert'), { key: k.value.trim(), value, isSecret: secret }); toast('Saved ' + k.value.trim(), { kind: 'success' }); m.close(); load(); } catch (e) { err.textContent = errMsg(e); }
      }, { variant: 'primary' })] });
  };
  const draw = () => {
    const f = q.value.toLowerCase();
    const rows = Object.keys(cfg).sort().filter((k) => !f || k.toLowerCase().includes(f)).map((k) => ({ k, v: cfg[k] }));
    out.replaceChildren(table([
      { label: 'Key', width: '30%', render: (r) => h('span', { class: 'mono small strong' }, r.k) },
      { label: 'Value', render: (r) => typeof r.v === 'object' && r.v !== null ? h('details', null, h('summary', { class: 'muted small' }, Array.isArray(r.v) ? r.v.length + ' items' : Object.keys(r.v).length + ' keys'), h('pre', { class: 'json' }, prettyJson(r.v))) : h('span', { class: 'mono small' }, String(r.v)) },
      { label: '', class: 'right', width: '90px', render: (r) => h('span', { class: 'row' }, iconBtn('edit', 'Edit', () => edit(r.k)), iconBtn('trash', 'Remove', async () => {
        if (!(await confirmDialog({ title: 'Remove ' + r.k + '?', confirmText: 'Remove', danger: true }))) return;
        try { await rpc.call(G('config/remove'), { key: r.k }); toast('Removed', { kind: 'success' }); load(); } catch (e) { toastError(e); }
      }, { variant: 'danger-soft' })) },
    ], rows, { empty: 'No keys' }));
  };
  q.addEventListener('input', debounce(draw, 120));
  async function load() { try { cfg = (await rpc.call(G('config/read-all'), {})).config || {}; draw(); } catch (e) { out.replaceChildren(banner('error', errMsg(e))); } }
  load();
}

// ===================================================================== Appearance
const THEME_SWATCH = {
  system: ['#0b0b0f', '#f7f7f8'], dark: ['#0b0b0f', '#16161d'], light: ['#ffffff', '#f2f2f5'], midnight: ['#05060f', '#0e1130'], nord: ['#2e3440', '#3b4252'],
  'solarized-dark': ['#002b36', '#073642'], 'solarized-light': ['#fdf6e3', '#eee8d5'], dracula: ['#282a36', '#44475a'], 'high-contrast': ['#000000', '#ffffff'],
};
function appearanceTab(body) {
  const draw = () => {
    const p = prefs();
    const accentInput = h('input', { type: 'color', class: 'color-inp', value: p.accent || '#7c5cff', 'aria-label': 'Custom accent color', onchange: (e) => { setPref('accent', e.target.value); draw(); } });
    body.replaceChildren(
      section('Theme', null, h('div', { class: 'theme-grid' }, ...THEMES.map((t) => h('button', { type: 'button', class: ['theme-tile', p.theme === t.id ? 'active' : ''], 'aria-pressed': String(p.theme === t.id), onclick: () => { setPref('theme', t.id); draw(); } },
        h('span', { class: 'theme-sw', style: { background: 'linear-gradient(135deg,' + THEME_SWATCH[t.id][0] + ' 50%,' + THEME_SWATCH[t.id][1] + ' 50%)' } }), h('span', null, t.label), p.theme === t.id ? icon('check', 13) : null)))),
      section('Accent color', null, h('div', { class: 'row wrap' },
        h('button', { type: 'button', class: ['swatch', !p.accent ? 'active' : ''], title: 'Theme default', 'aria-label': 'Theme default accent', onclick: () => { setPref('accent', ''); draw(); } }, icon('refresh', 12)),
        ...ACCENTS.map((c) => h('button', { type: 'button', class: ['swatch', p.accent === c ? 'active' : ''], style: { background: c }, title: c, 'aria-label': 'Accent ' + c, onclick: () => { setPref('accent', c); draw(); } })),
        h('label', { class: 'row small muted' }, accentInput, 'Custom'))),
      section('Layout', null, h('div', { class: 'card stack' },
        settingRow('Density', 'Compact fits more on screen.', select([{ value: 'comfortable', label: 'Comfortable' }, { value: 'compact', label: 'Compact' }], p.density, { class: 'inp inp-sm', onchange: (e) => setPref('density', e.target.value) })),
        settingRow('Font size', String(p.fontSize || 14) + ' px', h('input', { type: 'range', min: '12', max: '18', step: '1', value: String(p.fontSize || 14), 'aria-label': 'Font size', oninput: (e) => setPref('fontSize', Number(e.target.value)), onchange: () => draw() })),
        settingRow('Code theme', 'Syntax highlighting in code blocks.', select([{ value: 'auto', label: 'Match theme' }, { value: 'dark', label: 'GitHub Dark' }, { value: 'light', label: 'GitHub Light' }], p.codeTheme || 'auto', { class: 'inp inp-sm', onchange: (e) => setPref('codeTheme', e.target.value) })))),
      section('Preview', null, h('div', { class: 'card' }, mdElement('**Bold**, `inline code`, [a link](https://goose-docs.ai)\n\n```python\ndef hello(name: str) -> str:\n    return f"Hello {name}"  # comment\n```'))));
    import('../markdown.js').then(({ decorate }) => decorate(body, true)).catch(() => {});
  };
  draw();
}

// ===================================================================== Notifications
function notificationsTab(body) {
  const EVENTS = [['needs_you', 'An agent needs me (permission or question)'], ['done', 'An agent finished'], ['error', 'An agent failed']];
  const webhookBox = h('div', { class: 'card' }, skeleton(2));
  const draw = () => {
    const n = { ...prefs().notifications };
    const perm = 'Notification' in window ? Notification.permission : 'unsupported';
    body.replaceChildren(
      section('Browser notifications', null, h('div', { class: 'card stack' },
        settingRow('Show desktop notifications', perm === 'denied' ? 'Blocked in this browser – allow notifications for this site in the browser settings.' : perm === 'unsupported' ? 'Not supported by this browser.' : 'Shown when this tab is in the background.',
          perm === 'granted' ? toggle(!!n.browser, (v) => { patchPref('notifications', { browser: v }); draw(); }) : perm === 'default' ? btn('Allow notifications', async () => { const r = await Notification.requestPermission(); if (r === 'granted') patchPref('notifications', { browser: true }); draw(); }, { variant: 'primary', size: 'sm', icon: 'bell' }) : h('span', { class: 'badge badge-err' }, perm)),
        settingRow('Play a sound', 'A soft chime for background events.', h('span', { class: 'row' }, btn('Test', () => chime('needs_you'), { size: 'sm', variant: 'ghost' }), toggle(!!n.sound, (v) => patchPref('notifications', { sound: v })))),
        h('div', { class: 'strong' }, 'Notify me when'),
        ...EVENTS.map(([id, label]) => checkbox((n.events || []).includes(id), label, (v) => { const ev = new Set(prefs().notifications.events || []); if (v) ev.add(id); else ev.delete(id); patchPref('notifications', { events: [...ev] }); })),
        perm === 'granted' ? btn('Send a test notification', () => { try { new Notification('Goose', { body: 'Notifications are working.', icon: '/static/icons/goose.svg' }); } catch (e) { toastError(e); } }, { size: 'sm', icon: 'bell' }) : null)),
      section('Webhook', null, webhookBox));
  };
  const loadWebhook = async () => {
    try {
      const r = await GET('/api/me/notify');
      const can = policy('notify_webhook');
      const url = input({ value: r.webhook || '', placeholder: 'https://hooks.slack.com/…', class: 'inp mono', disabled: !can, type: 'url' });
      const ev = new Set(r.events || ['needs_you', 'done', 'error']);
      webhookBox.replaceChildren(
        h('p', { class: 'muted small' }, 'The gateway POSTs a JSON event to this URL even when no browser is open (works with Slack/Teams/ntfy style webhooks).'),
        !can ? banner('info', 'Your policy does not allow webhooks.') : null,
        field('Webhook URL', url),
        h('div', { class: 'row wrap' }, ...EVENTS.map(([id, label]) => checkbox(ev.has(id), label, (v) => { if (v) ev.add(id); else ev.delete(id); }, { disabled: !can }))),
        can ? h('div', { class: 'row' }, actionBtn('Save webhook', async () => { await PUT('/api/me/notify', { webhook: url.value.trim() || null, events: [...ev] }); }, { variant: 'primary', size: 'sm', success: 'Webhook saved' })) : null);
    } catch (e) { webhookBox.replaceChildren(banner('error', errMsg(e))); }
  };
  draw();
  loadWebhook();
}

// ===================================================================== Account
function accountTab(body) {
  const me = store.get('me') || {};
  const u = me.user || {};
  const name = input({ value: u.displayName || '', placeholder: 'Your name', autocomplete: 'name' });
  const email = input({ value: u.email || '', placeholder: 'you@example.com', type: 'email', autocomplete: 'email' });
  const totpBox = h('div', { class: 'card' });
  const loginsBox = h('div', null, skeleton(2));
  const tokensBox = h('div', null, skeleton(2));
  const isLocal = !u.authSource || u.authSource === 'local';
  body.replaceChildren(
    section('Profile', null, h('div', { class: 'card stack' },
      h('div', { class: 'row' }, h('span', { class: 'avatar lg' }, (u.displayName || u.username || '?').slice(0, 1).toUpperCase()), h('div', null, h('div', { class: 'strong' }, u.username || ''), h('div', { class: 'muted small' }, (me.isAdmin ? 'Administrator' : 'User') + (u.authSource ? ' · ' + u.authSource : '') + ((me.teams || []).length ? ' · ' + me.teams.map((t) => t.name).join(', ') : '')))),
      h('div', { class: 'grid2' }, field('Display name', name), field('Email', email)),
      h('div', { class: 'row' }, actionBtn('Save profile', async () => { const r = await PATCH('/api/me', { displayName: name.value.trim(), email: email.value.trim() }); store.set('me', { ...me, user: { ...u, displayName: name.value.trim(), email: email.value.trim(), ...((r && r.user) || {}) } }); }, { variant: 'primary', size: 'sm', success: 'Profile saved' })))),
    isLocal ? section('Password', null, h('div', { class: 'card narrow' }, passwordForm({ username: u.username || '', onDone: () => toast('Password changed', { kind: 'success' }) }))) : section('Password', null, h('div', { class: 'muted' }, 'Your password is managed by ' + u.authSource.toUpperCase() + '.')),
    section('Two-factor authentication', null, totpBox),
    section('Active sign-ins', iconBtn('refresh', 'Refresh', () => loadLogins()), loginsBox),
    section('API tokens', btn('New token', () => newToken(), { icon: 'plus', size: 'sm', variant: 'primary' }), h('p', { class: 'muted small' }, 'Tokens let scripts call the gateway API and WebSocket as you. Send the token in the Authorization: Bearer gwt_… header (for the WebSocket: in the handshake, from a non-browser client without an Origin header).'), tokensBox));

  const drawTotp = () => {
    const on = !!(u.totpEnabled ?? u.totp);
    totpBox.replaceChildren(h('div', { class: 'set-row' },
      h('div', { class: 'grow' }, h('div', { class: 'strong' }, 'Authenticator app (TOTP)'), h('div', { class: 'muted small' }, on ? 'Enabled – a 6-digit code is required when you sign in.' : 'Add a second step to sign-in with an authenticator app.')),
      on ? h('span', { class: 'row' }, h('span', { class: 'badge badge-ok' }, 'enabled'), btn('Disable', disableTotp, { size: 'sm', variant: 'danger-soft' })) : btn('Set up', setupTotp, { size: 'sm', variant: 'primary', icon: 'shield' })));
  };
  const setupTotp = async () => {
    let r; try { r = await POST('/api/me/totp/setup', {}); } catch (e) { toastError(e, 'TOTP setup'); return; }
    const qr = qrcode(0, 'M'); qr.addData(r.uri); qr.make();
    const img = h('img', { class: 'qr', alt: 'QR code for your authenticator app', src: qr.createDataURL(5, 8), width: 220, height: 220 });
    const code = input({ inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6', placeholder: '123456', class: 'inp totp-inp' });
    const err = h('div', { class: 'field-error' });
    const m = modal({ title: 'Set up two-factor authentication', size: 'md',
      body: h('div', { class: 'stack center' }, h('p', { class: 'muted' }, 'Scan with Microsoft Authenticator, Google Authenticator, 1Password…'), img,
        h('div', { class: 'row' }, h('code', { class: 'mono small' }, r.secret), copyBtn(r.secret, 'Copy secret')), field('Enter the 6-digit code', code), err),
      footer: [btn('Cancel', () => m.close()), btn('Verify & enable', async () => {
        err.textContent = '';
        try { await POST('/api/me/totp/enable', { code: code.value.trim() }, { quiet: true }); u.totpEnabled = true; store.set('me', { ...me, user: u }); toast('Two-factor enabled', { kind: 'success' }); m.close(); drawTotp(); }
        catch (e) { err.textContent = e.status === 400 || e.code === 'invalid_code' ? 'That code is not valid – try the next one.' : errMsg(e); }
      }, { variant: 'primary' })] });
    code.addEventListener('keydown', (e) => { if (e.key === 'Enter') m.el.querySelector('.modal-foot .btn-primary').click(); });
  };
  const disableTotp = async () => {
    const pw = await promptDialog({ title: 'Disable two-factor', label: 'Confirm with your password', confirmText: 'Disable', type: 'password', autocomplete: 'current-password', validate: (v) => v ? '' : 'Required' });
    if (pw === null) return;
    try { await POST('/api/me/totp/disable', { password: pw }, { quiet: true }); u.totpEnabled = false; store.set('me', { ...me, user: u }); toast('Two-factor disabled', { kind: 'success' }); drawTotp(); } catch (e) { toastError(e); }
  };
  const loadLogins = async () => {
    try {
      const rows = await GET('/api/me/logins');
      loginsBox.replaceChildren(table([
        { label: 'Device', render: (l) => h('div', null, h('div', { class: 'small' }, uaLabel(l.userAgent)), h('div', { class: 'muted small' }, l.ip || '')) },
        { label: 'Signed in', render: (l) => h('span', { title: fmtDateTime(l.createdAt) }, relTime(l.createdAt)) },
        { label: 'Last seen', render: (l) => h('span', { title: fmtDateTime(l.lastSeen) }, relTime(l.lastSeen)) },
        { label: '', class: 'right', render: (l) => l.current ? h('span', { class: 'badge badge-accent' }, 'this browser') : btn('Revoke', async () => { try { await DEL('/api/me/logins/' + encodeURIComponent(l.id)); toast('Signed out that session', { kind: 'success' }); loadLogins(); } catch (e) { toastError(e); } }, { size: 'sm', variant: 'danger-soft' }) },
      ], Array.isArray(rows) ? rows : rows.logins || [], { empty: 'No active sign-ins' }));
    } catch (e) { loginsBox.replaceChildren(banner('error', errMsg(e))); }
  };
  const loadTokens = async () => {
    try {
      const rows = await GET('/api/me/tokens');
      tokensBox.replaceChildren(table([
        { label: 'Name', render: (t) => h('span', { class: 'strong' }, t.name) },
        { label: 'Prefix', render: (t) => h('span', { class: 'mono small' }, (t.prefix || '') + '…') },
        { label: 'Created', render: (t) => relTime(t.createdAt) },
        { label: 'Last used', render: (t) => t.lastUsed ? relTime(t.lastUsed) : h('span', { class: 'muted' }, 'never') },
        { label: 'Expires', render: (t) => t.expiresAt ? relTime(t.expiresAt) : h('span', { class: 'muted' }, 'never') },
        { label: '', class: 'right', render: (t) => btn('Revoke', async () => {
          if (!(await confirmDialog({ title: 'Revoke token “' + t.name + '”?', message: 'Scripts using it will stop working.', confirmText: 'Revoke', danger: true }))) return;
          try { await DEL('/api/me/tokens/' + encodeURIComponent(t.id)); toast('Token revoked', { kind: 'success' }); loadTokens(); } catch (e) { toastError(e); }
        }, { size: 'sm', variant: 'danger-soft' }) },
      ], Array.isArray(rows) ? rows : rows.tokens || [], { empty: 'No API tokens' }));
    } catch (e) { tokensBox.replaceChildren(banner('error', errMsg(e))); }
  };
  const newToken = () => {
    const n = input({ placeholder: 'ci-script' });
    const days = select([{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '365', label: '1 year' }, { value: '', label: 'Never expires' }], '90');
    const m = modal({ title: 'New API token', size: 'sm', body: h('div', { class: 'stack' }, field('Name', n), field('Expires', days)),
      footer: [btn('Cancel', () => m.close()), btn('Create', async () => {
        if (!n.value.trim()) { toast('Name required', { kind: 'warn' }); return; }
        try {
          const body2 = { name: n.value.trim() }; if (days.value) body2.days = Number(days.value);
          const r = await POST('/api/me/tokens', body2);
          m.close(); loadTokens();
          const mm = modal({ title: 'Copy your token now', size: 'md', closable: true,
            body: h('div', { class: 'stack' }, banner('warn', 'This token is shown only once. Store it in a password manager.'), h('div', { class: 'row' }, h('code', { class: 'mono token-show' }, r.token), copyBtn(r.token, 'Copy token'))),
            footer: [btn('Done', () => mm.close(), { variant: 'primary' })] });
        } catch (e) { toastError(e); }
      }, { variant: 'primary' })] });
  };
  drawTotp(); loadLogins(); loadTokens();
}

export function uaLabel(ua) {
  ua = String(ua || '');
  const b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : ua ? 'Browser' : 'Unknown';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : '';
  return b + (os ? ' on ' + os : '');
}
