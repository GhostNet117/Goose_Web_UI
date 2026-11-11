// Spec 023: which providers the chat pickers (New chat, chat header) offer.
// The user's choice is a UI preference, stored on the server with the other preferences (prefs.providerVisibility,
// PUT /api/me/prefs), so it follows the user to every browser. It is applied AFTER the team policy (allowed_providers):
// hiding is not a policy and blocks nothing. Admin pages and the Settings lists are not filtered.
//
// Data model:
//   prefs.providerVisibility = { hidden: [providerId, ...] }   - only the user's explicit "do not show" choices, so a
//                                                                provider that appears later is shown.
//   provider entry .variantOf = '<base provider id>'           - a provider ROLE, not a user choice (spec 022 hook:
//                                                                e.g. a gateway annotation gwVariantOf on providers/list,
//                                                                like spec 021's gwEngine). A variant is never offered in
//                                                                a provider picker but stays in the full list
//                                                                (loadNewChatOptions().allProviders) so an effort picker
//                                                                can switch a chat to it. Nothing sets it yet.
// Never hidden: the user's default provider, and (in a chat header) the provider the chat uses.
import { pref, setPref } from './prefs.js';
import { store } from './store.js';

export const VIS_PREF = 'providerVisibility';
export const HIDDEN_LABEL = ' (hidden in settings)';

// ----- pure rules (no DOM, no storage; run in node by tests/test_provider_visibility.py) -----
const MAX_HIDDEN = 500;
// The stored preference -> Set of hidden provider ids (tolerates a missing or malformed value).
export function hiddenIds(vis) {
  const list = vis && Array.isArray(vis.hidden) ? vis.hidden : [];
  return new Set(list.filter((x) => typeof x === 'string' && x));
}
// Why a provider is not offered in a chat picker: '' = offered, 'user' = hidden in settings, 'variant' = an effort
// variant of another provider (spec 022), 'unconfigured' = Goose lists it but it is not set up (the chat header's
// list from Goose has every provider Goose knows; New chat already offers configured ones only). The default provider
// is always offered. Ids Goose's provider list does not know (e.g. Goose's own "goose" entry) are kept.
export function pickerHidden(id, ctx = {}) {
  if (!id) return '';
  if (ctx.defaultProvider && id === ctx.defaultProvider) return '';
  if (ctx.variants && ctx.variants[id]) return 'variant';
  if (ctx.unconfigured && ctx.unconfigured.has(id)) return 'unconfigured';
  return ctx.hidden && ctx.hidden.has(id) ? 'user' : '';
}
// The providers a picker offers, in order. `current` (the provider an open chat uses) is always kept and flagged
// hiddenInSettings when the user hid it. Entries need {id}; a variantOf on the entry counts like ctx.variants.
export function pickerProviders(list, ctx = {}) {
  const out = [];
  for (const p of list || []) {
    if (!p || !p.id) continue;
    const variants = p.variantOf ? { ...(ctx.variants || {}), [p.id]: p.variantOf } : ctx.variants;
    const why = pickerHidden(p.id, { ...ctx, variants });
    if (!why) out.push(p);
    else if (ctx.current && p.id === ctx.current) out.push({ ...p, hiddenInSettings: why === 'user' });
  }
  return out;
}
// What is stored: unique non-empty ids, sorted, never the default provider, bounded.
export function cleanHidden(ids, defaultProvider) {
  const s = new Set();
  for (const x of ids || []) if (typeof x === 'string' && x && x.length <= 200 && x !== defaultProvider) s.add(x);
  return [...s].sort().slice(0, MAX_HIDDEN);
}
// "Hide all except default": every listed id except the one to keep.
export function hideAllExcept(ids, keep) {
  return cleanHidden((ids || []).filter((x) => x !== keep), keep);
}
// ----- end pure rules -----

// Default provider, unconfigured providers and variant roles, remembered from the last providers/list + defaults/read
// (New chat, Settings) so a chat header applies the same rules without another request. Ids only; per signed-in user.
const META_KEY = 'gw-provider-vis';
const userKey = () => { const me = store.get('me'); const u = me && me.user; return u ? String(u.id ?? u.username ?? '') : ''; };
function metaCache() {
  try { const c = JSON.parse(localStorage.getItem(META_KEY) || '{}') || {}; return c.user === userKey() ? c : {}; } catch { return {}; }
}
// entries: Goose's providers/list entries ({providerId, configured, gwVariantOf}).
export function rememberProviderMeta({ defaultProvider, entries } = {}) {
  const c = metaCache();
  const next = { user: userKey(), defaultProvider: defaultProvider !== undefined ? (defaultProvider || '') : (c.defaultProvider || ''),
    variants: c.variants || {}, unconfigured: c.unconfigured || [] };
  if (entries) {
    next.variants = {}; next.unconfigured = [];
    for (const e of entries) {
      if (!e || !e.providerId) continue;
      if (e.gwVariantOf) next.variants[e.providerId] = e.gwVariantOf;
      if (!e.configured) next.unconfigured.push(e.providerId);
    }
  }
  try { localStorage.setItem(META_KEY, JSON.stringify(next)); } catch { /* storage full or disabled */ }
}
export function knownDefaultProvider() { return metaCache().defaultProvider || ''; }

// The rules' context for this user: hidden ids from the preference, default provider (given, else remembered),
// unconfigured providers and variant roles (remembered; empty until New chat or Settings has loaded once).
export function visibilityContext(defaultProvider) {
  const c = metaCache();
  return { hidden: hiddenIds(pref(VIS_PREF)), defaultProvider: defaultProvider !== undefined ? defaultProvider : (c.defaultProvider || ''),
    variants: c.variants || {}, unconfigured: new Set(Array.isArray(c.unconfigured) ? c.unconfigured : []) };
}
export function hiddenList() { return [...hiddenIds(pref(VIS_PREF))]; }
// Save the hidden list (server-side, debounced by prefs.js). The default provider is never stored as hidden.
export function setHiddenProviders(ids, defaultProvider) {
  setPref(VIS_PREF, { hidden: cleanHidden(ids, defaultProvider) });
}
