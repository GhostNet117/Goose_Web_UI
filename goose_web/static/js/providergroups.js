// Spec 024: provider groups and model labels - a display alias for the chat pickers (New chat, chat header).
// Several providers (for example one per person or per effort level, all serving the same models) can be shown as ONE
// provider entry. Its model list is the union of the members' models, each labelled `<prefix>-<model display name>`
// (prefix per member, optional). Picking a label sets the REAL provider and model of the chat. Nothing in Goose's
// configuration changes: the groups are a per-user preference stored with the others (prefs.providerGroups,
// PUT /api/me/prefs, cleaned by the server, api._clean_provider_groups).
//
// Data model:
//   prefs.providerGroups = {
//     groups: [{ id, name, members: [{ provider, prefix }] }],   - a provider is in at most one group
//     modelNames: { modelId: 'Friendly name' },                 - optional display names, for every provider
//   }
// Order of the rules: team policy on the real ids (the caller filters), then spec 023 visibility per member (a hidden
// member is left out of its group, the default provider and the provider an open chat uses are always kept), then the
// grouping. A group whose members are all hidden is not offered.
import { pref, setPref } from './prefs.js';
import { store } from './store.js';
import { rpc, G } from './rpc.js';
import { pickerHidden } from './providervis.js';

export const GROUPS_PREF = 'providerGroups';

// ----- pure rules (no DOM, no storage; run in node by tests/test_provider_groups.py together with providervis.js) -----
export const GROUP_PREFIX = 'group:';   // value of a group's entry in a provider picker
const SEP = '|';                        // value of a group's model option: '<provider id>|<model id>'
const cmpText = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });

// The stored preference -> {groups, modelNames}, tolerant of a missing or malformed value (the server cleans it too).
export function normGroups(v) {
  const groups = []; const seen = new Set();
  for (const g of v && Array.isArray(v.groups) ? v.groups : []) {
    if (!g || typeof g !== 'object' || typeof g.id !== 'string' || !g.id) continue;
    const members = [];
    for (const m of Array.isArray(g.members) ? g.members : []) {
      if (!m || typeof m.provider !== 'string' || !m.provider || seen.has(m.provider)) continue;
      seen.add(m.provider);
      members.push({ provider: m.provider, prefix: typeof m.prefix === 'string' ? m.prefix.trim() : '' });
    }
    groups.push({ id: g.id, name: (typeof g.name === 'string' && g.name.trim()) || 'Group', members });
  }
  const modelNames = {};
  const mn = v && v.modelNames && typeof v.modelNames === 'object' && !Array.isArray(v.modelNames) ? v.modelNames : {};
  for (const [k, x] of Object.entries(mn)) if (k && typeof x === 'string' && x.trim()) modelNames[k] = x.trim();
  return { groups, modelNames };
}
export function groupOfProvider(id, cfg) {
  for (const g of (cfg && cfg.groups) || []) if (g.members.some((m) => m.provider === id)) return g;
  return null;
}
export const isGroupValue = (v) => typeof v === 'string' && v.startsWith(GROUP_PREFIX);
export const joinValue = (provider, model) => provider + SEP + model;
export function splitValue(v) {
  const s = String(v || ''); const i = s.indexOf(SEP);
  return i < 0 ? { provider: '', model: s } : { provider: s.slice(0, i), model: s.slice(i + 1) };
}
// A model's display name: the user's name for the id, else Goose's name, else the id.
export function modelName(id, name, names) { return (names && names[id]) || name || id; }
// The label in a group's model list: `<prefix>-<display name>`, or the display name without a prefix.
export function modelLabel(prefix, id, name, names) {
  const n = modelName(id, name, names);
  return prefix ? prefix + '-' + n : n;
}

// The entries a provider picker offers. `providers` = [{id, name, models: [{id, name}], defaultModel, engine,
// variantOf}], already filtered by the team policy (incl. providers the user hid: their visibility is decided here).
// ctx = providervis visibilityContext() (+ `current`: the provider an open chat uses).
// Ungrouped provider -> itself (models with display names; `hiddenInSettings` when kept only as `current`).
// Group -> { id: 'group:<id>', group: true, groupId, name, members: [{provider, prefix, name, defaultModel, engine,
// hiddenInSettings}] in the group's order, models: [{value, provider, model, prefix, label, hidden}] sorted by
// prefix then label }. Entries sorted by name.
export function groupPicker(providers, cfg, ctx = {}) {
  cfg = cfg || { groups: [], modelNames: {} };
  const list = (providers || []).filter((p) => p && p.id);
  const byId = new Map(list.map((p) => [p.id, p]));
  const why = (p) => pickerHidden(p.id, { ...ctx, variants: p.variantOf ? { ...(ctx.variants || {}), [p.id]: p.variantOf } : ctx.variants });
  const out = []; const doneGroups = new Set();
  for (const p of list) {
    const g = groupOfProvider(p.id, cfg);
    if (!g) {
      const w = why(p);
      if (w && p.id !== ctx.current) continue;
      out.push({ ...p, hiddenInSettings: w === 'user', models: (p.models || []).map((m) => ({ ...m, name: modelName(m.id, m.name, cfg.modelNames) })) });
      continue;
    }
    if (doneGroups.has(g.id)) continue;
    doneGroups.add(g.id);
    const members = [];
    for (const m of g.members) {
      const mp = byId.get(m.provider);
      if (!mp) continue;
      const w = why(mp);
      if (w && m.provider !== ctx.current) continue;
      members.push({ provider: m.provider, prefix: m.prefix, name: mp.name, defaultModel: mp.defaultModel || '', engine: mp.engine || '',
        hiddenInSettings: w === 'user', models: mp.models || [] });
    }
    if (!members.length) continue;
    const models = [];
    for (const m of members) {
      for (const x of m.models) {
        models.push({ value: joinValue(m.provider, x.id), provider: m.provider, model: x.id, prefix: m.prefix,
          label: modelLabel(m.prefix, x.id, x.name, cfg.modelNames), sortName: modelName(x.id, x.name, cfg.modelNames), hidden: m.hiddenInSettings });
      }
    }
    models.sort((a, b) => cmpText(a.prefix, b.prefix) || cmpText(a.sortName, b.sortName) || cmpText(a.provider, b.provider));
    out.push({ id: GROUP_PREFIX + g.id, group: true, groupId: g.id, name: g.name, members: members.map(({ models: _m, ...r }) => r), models });
  }
  return out.sort((a, b) => cmpText(a.name, b.name));
}
// The picker entry that shows a real provider: its group's entry, else its own.
export function entryOfProvider(entries, providerId) {
  if (!providerId) return null;
  return (entries || []).find((e) => (e.group ? e.members.some((m) => m.provider === providerId) : e.id === providerId)) || null;
}
// What choosing a group (without a model) selects: the default provider when it is a member (with the default
// model), else the group's first member (its own default model, '' = Goose's).
export function groupDefault(entry, defaultProvider, defaultModel) {
  if (!entry || !entry.group || !entry.members.length) return { provider: '', model: '' };
  const d = entry.members.find((m) => m.provider === defaultProvider);
  if (d) return { provider: d.provider, model: defaultModel || d.defaultModel || '' };
  return { provider: entry.members[0].provider, model: entry.members[0].defaultModel || '' };
}
// The label of a real provider+model inside a picker entry (group: its prefixed label; else the display name).
export function labelIn(entry, provider, model, cfg) {
  if (!model) return '';
  const names = cfg && cfg.modelNames;
  if (entry && entry.group) {
    const hit = entry.models.find((m) => m.provider === provider && m.model === model);
    if (hit) return hit.label;
    const mem = entry.members.find((m) => m.provider === provider);
    return modelLabel(mem ? mem.prefix : '', model, '', names);
  }
  const hit = entry && (entry.models || []).find((m) => m.id === model);
  return hit ? hit.name : modelName(model, '', names);
}
// The chat header: Goose's provider option (already filtered by policy and spec 023) with group members collapsed into
// their group, and the model option of a grouped chat as the group's labelled list. provOptions = [{value, label,
// title}]; curModels = the current provider's models from Goose's model option ([{value, label}]); entries =
// groupPicker(inventory, cfg, ctx with current). Returns { provider: {options, value}, model: {options, value}, entry }.
export function headerPickers(provOptions, curProvider, curModel, curModels, entries, cfg) {
  const entry = entryOfProvider(entries, curProvider);
  const groupOpt = new Map();   // provider id -> group entry
  for (const e of entries || []) if (e.group) for (const m of e.members) groupOpt.set(m.provider, e);
  // members the inventory does not list (not loaded yet): still collapse by the stored groups
  const options = []; const seen = new Set();
  for (const o of provOptions || []) {
    const g = groupOpt.get(o.value) || null;
    const raw = g ? null : groupOfProvider(o.value, cfg);
    if (g || raw) {
      const id = GROUP_PREFIX + (g ? g.groupId : raw.id);
      if (seen.has(id)) continue;
      seen.add(id);
      options.push({ value: id, label: g ? g.name : raw.name, title: 'Provider group' });
    } else options.push(o);
  }
  const curGroup = groupOfProvider(curProvider, cfg);
  const value = curGroup ? GROUP_PREFIX + curGroup.id : curProvider;
  if (!curGroup) {
    const names = cfg && cfg.modelNames;
    return { entry, provider: { options, value }, model: { options: (curModels || []).map((m) => ({ ...m, label: modelName(m.value, m.label, names) })), value: curModel } };
  }
  const prefix = (curGroup.members.find((m) => m.provider === curProvider) || {}).prefix || '';
  let models = entry && entry.group ? entry.models.map((m) => ({ value: m.value, label: m.label + (m.hidden ? ' (hidden in settings)' : '') })) : [];
  // the chat's own models are always there (inventory not loaded yet, or a model the inventory does not list)
  const have = new Set(models.map((m) => m.value));
  const own = (curModels || []).filter((m) => !have.has(joinValue(curProvider, m.value)))
    .map((m) => ({ value: joinValue(curProvider, m.value), label: modelLabel(prefix, m.value, m.label, cfg && cfg.modelNames) }));
  if (own.length) models = models.concat(own);
  return { entry, provider: { options, value }, model: { options: models, value: curModel ? joinValue(curProvider, curModel) : '' } };
}
// ----- end pure rules -----

export function groupsConfig() { return normGroups(pref(GROUPS_PREF)); }
export function setGroups(cfg) { setPref(GROUPS_PREF, normGroups(cfg)); }
export function newGroupId() { return 'g' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5); }

// ----- the providers' model lists for the chat header (no request per dropdown) -----
// Remembered from the providers/list New chat and Settings already load (ids and names only; per signed-in user).
// A chat header opened before that (fresh browser, direct link) loads the list once per page.
const INV_KEY = 'gw-provider-models';
const userKey = () => { const me = store.get('me'); const u = me && me.user; return u ? String(u.id ?? u.username ?? '') : ''; };
let memInv = null; let invPromise = null;
// entries: Goose's providers/list entries. Only configured providers are kept.
export function rememberInventory(entries) {
  const list = [];
  for (const e of entries || []) {
    if (!e || !e.providerId || !e.configured) continue;
    list.push({ id: e.providerId, name: e.providerName || e.providerId, defaultModel: e.defaultModel || '', engine: e.gwEngine || '',
      variantOf: e.gwVariantOf || '', models: (e.models || []).map((m) => ({ id: m.id, name: m.name || m.id })) });
  }
  memInv = list;
  try { localStorage.setItem(INV_KEY, JSON.stringify({ user: userKey(), providers: list })); } catch { /* storage full or disabled */ }
}
export function inventory() {
  if (memInv) return memInv;
  try { const c = JSON.parse(localStorage.getItem(INV_KEY) || '{}') || {}; if (c.user === userKey() && Array.isArray(c.providers)) memInv = c.providers; } catch { /* */ }
  return memInv;
}
// Resolves when the inventory is known; at most one providers/list per page, and only when nothing is remembered.
export function loadInventoryOnce() {
  if (inventory()) return Promise.resolve(memInv);
  if (!invPromise) invPromise = rpc.call(G('providers/list'), {}).then((p) => { rememberInventory((p && p.entries) || []); return memInv; }).catch(() => null);
  return invPromise;
}
