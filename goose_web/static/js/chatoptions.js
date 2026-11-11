// Per-chat options (provider, model, thinking effort, approval mode): shared by the chat header and the
// New chat screen. Goose returns them as configOptions from session/new and session/load; changing them with
// session/set_config_option / session/set_mode affects only that chat (Goose's config.yaml is not written).
import { h, select } from './ui.js';
import { icon } from './icons.js';
import { rpc, G } from './rpc.js';
import { allowedValue } from './store.js';
import { pickerProviders, visibilityContext, rememberProviderMeta } from './providervis.js';

// Goose's approval modes (goose-provider-types GooseMode), with Goose's own descriptions.
export const MODES = [
  { value: 'auto', label: 'Auto', title: 'Automatically approve tool calls' },
  { value: 'approve', label: 'Approve', title: 'Ask before every tool call' },
  { value: 'smart_approve', label: 'Smart approve', title: 'Ask only for sensitive tool calls' },
  { value: 'chat', label: 'Chat only', title: 'Chat only, no tool calls' },
];
// Goose's generic thinking-effort values; the real list depends on the provider and model.
export const EFFORTS = ['off', 'low', 'medium', 'high', 'max'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) }));

export function pillSelect(ic, label, options, value, onChange) {
  const s = select(options, value ?? '', { class: 'pill-select', 'aria-label': label, title: label });
  if (value && !options.some((o) => o.value === value)) s.prepend(h('option', { value }, value));
  s.value = value ?? '';
  s.addEventListener('change', () => onChange(s.value));
  return h('label', { class: 'pill', title: label }, icon(ic, 13), s);
}

export const optionById = (opts, id) => (opts || []).find((o) => o.id === id);
export const effortOption = (opts) => (opts || []).find((o) => o.category === 'thought_level' || o.id === 'thinking_effort');
const flat = (o) => (Array.isArray(o && o.options) ? o.options.flatMap((x) => (Array.isArray(x.options) ? x.options : [x])) : []);
const offers = (o, v) => flat(o).some((x) => x.value === v);

// ----- effort values learned from real chats (option names only; not sensitive) -----
const EFFORT_KEY = 'gw-effort-options';
function effortCache() { try { return JSON.parse(localStorage.getItem(EFFORT_KEY) || '{}') || {}; } catch { return {}; } }
export function rememberEffortOptions(configOptions) {
  const p = optionById(configOptions, 'provider'), m = optionById(configOptions, 'model'), e = effortOption(configOptions);
  if (!p || !m || !e || !p.currentValue || !m.currentValue) return;
  const vals = flat(e).map((x) => ({ value: x.value, label: x.name || x.value }));
  if (!vals.length) return;
  const c = effortCache();
  const key = p.currentValue + '|' + m.currentValue;
  delete c[key];
  c[key] = vals;
  const keys = Object.keys(c);
  for (const k of keys.slice(0, Math.max(0, keys.length - 40))) delete c[k];
  try { localStorage.setItem(EFFORT_KEY, JSON.stringify(c)); } catch { /* storage full or disabled */ }
}
export function knownEfforts(provider, model) {
  const v = provider && model ? effortCache()[provider + '|' + model] : null;
  return Array.isArray(v) && v.length ? v : EFFORTS;
}
// True when Goose offered this provider+model's list in a real chat (not the generic fallback).
export function effortsKnown(provider, model) {
  const v = provider && model ? effortCache()[provider + '|' + model] : null;
  return Array.isArray(v) && v.length > 0;
}

// ----- spec 021: the highest effort by default -----
// Lowest first; the same ranking as goose_web/effort.py (Goose's levels plus provider names Goose may offer).
export const EFFORT_RANK = ['off', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'];
// The highest offered value ({value} objects or strings); unknown names only if nothing is known (then the last).
export function topEffort(list) {
  const vals = (list || []).map((x) => (x && typeof x === 'object' ? x.value : x)).filter((v) => v);
  let best = '', rank = -1;
  for (const v of vals) { const r = EFFORT_RANK.indexOf(String(v).toLowerCase()); if (r > rank) { rank = r; best = v; } }
  return rank >= 0 ? best : (vals.length ? vals[vals.length - 1] : '');
}
// Does Goose put an effort field on the wire? On the OpenAI engine only for OpenAI reasoning models and xAI Grok
// (Goose 1.50-1.59, assessment effort-translation); other engines translate the effort themselves. Unknown engine:
// assume it is sent (no note).
export function effortSent(engine, model) {
  if (String(engine || '').toLowerCase() !== 'openai') return true;
  const m = String(model || '').toLowerCase();
  return /gpt-|codex|grok|(^|[^a-z0-9])o[1-9]/.test(m);
}
const ENGINE_KEY = 'gw-provider-engines';   // provider id -> engine (names only; not sensitive)
function engineCache() { try { return JSON.parse(localStorage.getItem(ENGINE_KEY) || '{}') || {}; } catch { return {}; } }
export function rememberEngines(providers) {
  const c = {};
  for (const p of providers || []) if (p && p.id && p.engine) c[p.id] = p.engine;
  try { localStorage.setItem(ENGINE_KEY, JSON.stringify(c)); } catch { /* storage full or disabled */ }
}
export const NOT_SENT_NOTE = 'Goose sends no thinking effort for this model: its effort is set by the provider configuration (request_params), not per chat.';
export function effortNote(provider, model, engine) {
  const eng = engine !== undefined ? engine : engineCache()[provider];
  return provider && model && !effortSent(eng, model) ? NOT_SENT_NOTE : '';
}

// ----- data for the New chat screen (no session needed) -----
// Provider and model lists come from Goose's provider inventory; the defaults from the user's profile config.
export async function loadNewChatOptions() {
  // GOOSE_MODE / GOOSE_THINKING_EFFORT are on the gateway's readable-key list for every user (policy.py).
  const cfg = (key) => rpc.call(G('config/read'), { key, isSecret: false }).then((r) => (r && r.value) || '').catch(() => '');
  const [p, d, mode, effort] = await Promise.all([
    rpc.call(G('providers/list'), {}).catch(() => ({ entries: [] })),
    rpc.call(G('defaults/read'), {}).catch(() => ({})),
    cfg('GOOSE_MODE'),
    cfg('GOOSE_THINKING_EFFORT'),
  ]);
  // Team policy first; then the user's own picker choice (spec 023, providervis.js; the default provider is kept).
  const allProviders = (p.entries || [])
    .filter((e) => e.configured && allowedValue('allowed_providers', e.providerId))
    .map((e) => ({
      id: e.providerId, name: e.providerName || e.providerId, defaultModel: e.defaultModel || '',
      engine: e.gwEngine || '',   // spec 021: added by the gateway (custom_providers/*.json)
      variantOf: e.gwVariantOf || '',   // spec 022 hook (not set yet): an effort variant of another provider
      models: (e.models || []).filter((m) => allowedValue('allowed_models', m.id)).map((m) => ({ id: m.id, name: m.name || m.id })),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  rememberEngines(allProviders);
  const defaultProvider = (d && d.providerId) || '';
  rememberProviderMeta({ defaultProvider, entries: p.entries || [] });   // for the chat header (no extra request)
  const providers = pickerProviders(allProviders, visibilityContext(defaultProvider));
  return {
    providers,          // what the provider picker offers
    allProviders,       // every provider the policy allows, incl. hidden ones (valid targets, e.g. spec 022 variants)
    defaultProvider,
    defaultModel: (d && d.modelId) || '',
    defaultMode: String(mode || 'auto'),          // Goose's own default mode is auto
    defaultEffort: String(effort || ''),
  };
}

// Apply the New chat choices to a freshly created chat, before its first prompt. Order matters: the provider
// switch rebuilds the model and effort lists, so each step checks the chat's current (refreshed) options.
// Without an effort choice the chat gets the highest effort it offers (spec 021).
// Returns warnings for choices this chat does not offer; the chat starts regardless.
export async function applyNewChatOptions(chat, choice = {}) {
  const warn = [];
  const step = async (label, fn) => { try { await fn(); } catch (e) { warn.push(label + ': ' + ((e && (e.data || e.message)) || e)); } };
  const opts = () => chat.configOptions || [];
  if (choice.provider) {
    const o = optionById(opts(), 'provider');
    if (o && o.currentValue !== choice.provider) {
      if (!offers(o, choice.provider)) warn.push('Provider "' + choice.provider + '" is not available');
      else await step('Provider', () => chat.setConfig('provider', choice.provider));
    }
  }
  if (choice.model) {
    const o = optionById(opts(), 'model');
    if (o && o.currentValue !== choice.model) {
      if (!offers(o, choice.model)) warn.push('Model "' + choice.model + '" is not offered by this provider');
      else await step('Model', () => chat.setConfig('model', choice.model));
    }
  }
  if (choice.effort) {
    const o = effortOption(opts());
    if (o && o.currentValue !== choice.effort) {
      if (!offers(o, choice.effort)) warn.push('Thinking effort "' + choice.effort + '" is not offered for this model');
      else await step('Thinking effort', () => chat.setConfig(o.id, choice.effort));
    }
  } else {
    // spec 021: no explicit pick -> the highest level this provider+model offers (max, else the top of the list).
    const o = effortOption(opts());
    const top = o ? topEffort(flat(o)) : '';
    if (top && o.currentValue !== top) await step('Thinking effort', () => chat.setConfig(o.id, top));
  }
  if (choice.mode) {
    const cur = chat.modes ? chat.modes.currentModeId : (optionById(opts(), 'mode') || {}).currentValue;
    if (cur !== choice.mode) await step('Approval mode', () => chat.setMode(choice.mode));
  }
  rememberEffortOptions(opts());
  return warn;
}
