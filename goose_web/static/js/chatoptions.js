// Per-chat options (provider, model, thinking effort, approval mode): shared by the chat header and the
// New chat screen. Goose returns them as configOptions from session/new and session/load; changing them with
// session/set_config_option / session/set_mode affects only that chat (Goose's config.yaml is not written).
import { h, select } from './ui.js';
import { icon } from './icons.js';
import { rpc, G } from './rpc.js';
import { allowedValue } from './store.js';

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
  const providers = (p.entries || [])
    .filter((e) => e.configured && allowedValue('allowed_providers', e.providerId))
    .map((e) => ({
      id: e.providerId, name: e.providerName || e.providerId, defaultModel: e.defaultModel || '',
      models: (e.models || []).filter((m) => allowedValue('allowed_models', m.id)).map((m) => ({ id: m.id, name: m.name || m.id })),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return {
    providers,
    defaultProvider: (d && d.providerId) || '',
    defaultModel: (d && d.modelId) || '',
    defaultMode: String(mode || 'auto'),          // Goose's own default mode is auto
    defaultEffort: String(effort || ''),
  };
}

// Apply the New chat choices to a freshly created chat, before its first prompt. Order matters: the provider
// switch rebuilds the model and effort lists, so each step checks the chat's current (refreshed) options.
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
  }
  if (choice.mode) {
    const cur = chat.modes ? chat.modes.currentModeId : (optionById(opts(), 'mode') || {}).currentValue;
    if (cur !== choice.mode) await step('Approval mode', () => chat.setMode(choice.mode));
  }
  rememberEffortOptions(opts());
  return warn;
}
