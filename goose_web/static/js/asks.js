// Agent -> client requests ("asks"): permission prompts, elicitation forms, recipe parameter requests.
import { rpc } from './rpc.js';
import { store, bus } from './store.js';
import { h, btn, modal, toast, prettyJson, input, select, textarea, field, toggle } from './ui.js';
import { icon } from './icons.js';
import { router } from './router.js';

export const ASK_METHODS = {
  'session/request_permission': 'permission',
  'elicitation/create': 'elicitation',
  '_goose/unstable/session/recipe/request-params': 'recipe_params',
};

function normalize(msg) {
  if (!msg) return null;
  const m = msg.request && msg.request.method ? { ...msg.request, ...(msg.id !== undefined && msg.request.id === undefined ? { id: msg.id } : {}) } : msg;
  const kind = ASK_METHODS[m.method];
  if (!kind || m.id === undefined || m.id === null) return null;
  const params = m.params || {};
  let title = 'Request';
  if (kind === 'permission') title = (params.toolCall && params.toolCall.title) || 'Tool permission';
  else if (kind === 'elicitation') title = params.message || 'Goose needs information';
  else title = 'Recipe parameters';
  return { id: m.id, method: m.method, params, kind, sessionId: params.sessionId || msg.sessionId || null, title, at: Date.now() };
}

export function addAsk(msg, { silent = false } = {}) {
  const ask = normalize(msg);
  if (!ask) return null;
  const asks = store.get('asks');
  if (asks.has(ask.id)) return asks.get(ask.id);
  asks.set(ask.id, ask);
  store.set('asks', asks);
  bus.emit('ask:new', ask, { silent });
  if (ask.kind === 'recipe_params') openRecipeParamsModal(ask);
  return ask;
}

export function resetAsks(list) {
  const old = store.get('asks');
  const next = new Map();
  for (const raw of list || []) { const a = normalize(raw); if (a) next.set(a.id, old.get(a.id) || a); }
  for (const id of old.keys()) if (!next.has(id)) bus.emit('ask:resolved', { id, by: 'gateway' });
  store.set('asks', next);
  for (const a of next.values()) if (!old.has(a.id)) { bus.emit('ask:new', a, { silent: true }); if (a.kind === 'recipe_params') openRecipeParamsModal(a); }
}

export function asksForSession(sid) { return [...store.get('asks').values()].filter((a) => a.sessionId === sid); }

export function answerAsk(id, result) {
  const asks = store.get('asks');
  const ask = asks.get(id);
  const ok = rpc.respond(id, result);
  if (!ok) { toast('Not connected - answer not sent', { kind: 'error' }); return false; }
  asks.delete(id);
  store.set('asks', asks);
  bus.emit('ask:resolved', { id, by: 'me', result, ask });
  return true;
}

export function resolvedElsewhere({ id, by }) {
  const asks = store.get('asks');
  if (!asks.has(id)) return;
  const ask = asks.get(id);
  asks.delete(id);
  store.set('asks', asks);
  bus.emit('ask:resolved', { id, by: by || 'another client', ask });
}

// ---------- rendering ----------
const OPTION_LABEL = { allow_once: 'Allow once', allow_always: 'Always allow', reject_once: 'Deny', reject_always: 'Always deny' };
const OPTION_VARIANT = { allow_once: 'primary', allow_always: '', reject_once: 'danger-soft', reject_always: 'danger-soft' };

function resolvedText(result) {
  if (!result) return 'Answered';
  if (result.outcome) {
    if (result.outcome.outcome === 'cancelled') return 'Cancelled';
    return OPTION_LABEL[result.outcome.optionId] || ('Selected ' + result.outcome.optionId);
  }
  if (result.action) return { accept: 'Submitted', submit: 'Submitted', decline: 'Declined', cancel: 'Cancelled' }[result.action] || result.action;
  return 'Answered';
}

export function askCard(ask, { compact = false, showSession = false } = {}) {
  const el = h('div', { class: ['ask', 'ask-' + ask.kind, compact ? 'ask-compact' : ''], dataset: { askId: String(ask.id) } });
  const body = h('div', { class: 'ask-body' });
  const head = h('div', { class: 'ask-head' }, h('span', { class: 'ask-pulse' }), icon(ask.kind === 'permission' ? 'shield' : ask.kind === 'elicitation' ? 'info' : 'recipe', 15),
    h('span', { class: 'ask-kind' }, ask.kind === 'permission' ? 'Permission needed' : ask.kind === 'elicitation' ? 'Input needed' : 'Recipe parameters'),
    showSession && ask.sessionId ? h('a', { class: 'ask-session', href: '#/chat/' + encodeURIComponent(ask.sessionId) }, 'open chat') : null);
  el.append(head, body);
  const finish = (txt) => {
    el.classList.add('ask-done');
    body.replaceChildren(h('div', { class: 'ask-resolved' }, icon('check', 14), txt));
  };
  const off = bus.on('ask:resolved', (ev) => {
    if (ev.id !== ask.id) return;
    off();
    finish(ev.by === 'me' ? resolvedText(ev.result) : 'Answered by ' + ev.by);
  });

  if (ask.kind === 'permission') {
    const tc = ask.params.toolCall || {};
    const raw = tc.rawInput;
    body.appendChild(h('div', { class: 'ask-title' }, tc.title || 'Tool call'));
    if (raw !== undefined && raw !== null) {
      const cmd = raw && typeof raw === 'object' && typeof raw.command === 'string' ? raw.command : null;
      if (cmd) body.appendChild(h('pre', { class: 'ask-cmd' }, cmd));
      if (!cmd || Object.keys(raw).length > 1) {
        const det = h('details', { class: 'ask-raw', open: !compact && !cmd }, h('summary', null, 'Arguments'), h('pre', { class: 'json' }, prettyJson(raw)));
        body.appendChild(det);
      }
    }
    const opts = ask.params.options && ask.params.options.length ? ask.params.options : [
      { optionId: 'allow_once', kind: 'allow_once' }, { optionId: 'reject_once', kind: 'reject_once' }];
    const order = ['allow_once', 'allow_always', 'reject_once', 'reject_always'];
    const sorted = [...opts].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
    body.appendChild(h('div', { class: 'ask-actions' }, sorted.map((o) => btn(OPTION_LABEL[o.kind] || o.name || o.optionId, () => {
      answerAsk(ask.id, { outcome: { outcome: 'selected', optionId: o.optionId } });
    }, { variant: OPTION_VARIANT[o.kind] || '', size: compact ? 'sm' : '', icon: o.kind && o.kind.startsWith('allow') ? 'check' : 'x' }))));
  } else if (ask.kind === 'elicitation') {
    body.appendChild(h('div', { class: 'ask-title' }, ask.params.message || 'Goose needs some information'));
    if (compact) {
      body.appendChild(h('div', { class: 'ask-actions' }, btn('Answer…', () => openElicitationModal(ask), { variant: 'primary', size: 'sm' }), btn('Decline', () => answerAsk(ask.id, { action: 'decline' }), { size: 'sm' })));
    } else {
      const form = schemaForm(ask.params.requestedSchema || {});
      body.appendChild(form.el);
      body.appendChild(h('div', { class: 'ask-actions' },
        btn('Submit', () => { const v = form.values(); if (v) answerAsk(ask.id, { action: 'accept', content: v }); }, { variant: 'primary', icon: 'check' }),
        btn('Decline', () => answerAsk(ask.id, { action: 'decline' })),
        btn('Cancel', () => answerAsk(ask.id, { action: 'cancel' }), { variant: 'ghost' })));
    }
  } else {
    const params = ask.params.parameters || [];
    body.appendChild(h('div', { class: 'ask-title' }, params.length + ' parameter' + (params.length === 1 ? '' : 's') + ' required to start this recipe'));
    body.appendChild(h('div', { class: 'ask-actions' }, btn('Fill in parameters', () => openRecipeParamsModal(ask, true), { variant: 'primary', size: compact ? 'sm' : '' }), btn('Cancel', () => answerAsk(ask.id, { action: 'cancel' }), { size: compact ? 'sm' : '' })));
  }
  return el;
}

// Build a simple form from a JSON-schema-ish object schema (MCP elicitation restricted schema).
export function schemaForm(schema) {
  const props = schema.properties || {};
  const required = new Set(schema.required || []);
  const getters = {};
  const err = h('div', { class: 'field-error' });
  const el = h('div', { class: 'schema-form' });
  for (const [key, s] of Object.entries(props)) {
    const label = (s.title || key) + (required.has(key) ? ' *' : '');
    let ctl, get;
    const enumVals = s.enum || (s.oneOf && s.oneOf.map((o) => o.const));
    if (enumVals) {
      const names = s.enumNames || (s.oneOf && s.oneOf.map((o) => o.title || o.const)) || enumVals;
      ctl = select([{ value: '', label: '—' }, ...enumVals.map((v, i) => ({ value: String(v), label: String(names[i] ?? v) }))], s.default !== undefined ? String(s.default) : '');
      get = () => (ctl.value === '' ? undefined : (typeof enumVals[0] === 'number' ? Number(ctl.value) : ctl.value));
    } else if (s.type === 'boolean') {
      let val = !!s.default;
      ctl = toggle(val, (v) => { val = v; });
      get = () => val;
    } else if (s.type === 'number' || s.type === 'integer') {
      ctl = input({ type: 'number', value: s.default ?? '', min: s.minimum, max: s.maximum, step: s.type === 'integer' ? 1 : 'any' });
      get = () => (ctl.value === '' ? undefined : Number(ctl.value));
    } else if (s.type === 'array' && s.items && s.items.enum) {
      const chosen = new Set(s.default || []);
      ctl = h('div', { class: 'chk-list' }, s.items.enum.map((v) => h('label', { class: 'chk' }, h('input', { type: 'checkbox', checked: chosen.has(v), onchange: (e) => (e.target.checked ? chosen.add(v) : chosen.delete(v)) }), h('span', null, String(v)))));
      get = () => [...chosen];
    } else {
      const long = (s.maxLength && s.maxLength > 200) || s.format === 'textarea';
      const typ = s.format === 'email' ? 'email' : s.format === 'uri' ? 'url' : s.format === 'date' ? 'date' : s.format === 'date-time' ? 'datetime-local' : 'text';
      ctl = long ? textarea({ rows: 4, value: s.default ?? '' }) : input({ type: typ, value: s.default ?? '', placeholder: s.examples ? String(s.examples[0]) : '' });
      get = () => (ctl.value === '' ? undefined : ctl.value);
    }
    getters[key] = get;
    el.appendChild(field(label, ctl, s.description));
  }
  if (!Object.keys(props).length) el.appendChild(h('div', { class: 'muted' }, 'No fields requested.'));
  el.appendChild(err);
  return {
    el,
    values() {
      const out = {};
      for (const [k, g] of Object.entries(getters)) {
        const v = g();
        if (v === undefined) { if (required.has(k)) { err.textContent = 'Please fill in: ' + ((props[k] && props[k].title) || k); return null; } continue; }
        out[k] = v;
      }
      err.textContent = '';
      return out;
    },
  };
}

export function openElicitationModal(ask) {
  const form = schemaForm(ask.params.requestedSchema || {});
  let m;
  const off = bus.on('ask:resolved', (ev) => { if (ev.id === ask.id) { off(); m && m.close(); } });
  m = modal({
    title: 'Goose needs information',
    body: h('div', null, h('p', { class: 'lead' }, ask.params.message || ''), form.el),
    footer: [btn('Cancel', () => { answerAsk(ask.id, { action: 'cancel' }); }), btn('Decline', () => answerAsk(ask.id, { action: 'decline' })),
      btn('Submit', () => { const v = form.values(); if (v) answerAsk(ask.id, { action: 'accept', content: v }); }, { variant: 'primary' })],
    onClose: () => off(),
  });
}

const openParamModals = new Set();
export function openRecipeParamsModal(ask, force = false) {
  if (openParamModals.has(ask.id) && !force) return;
  openParamModals.add(ask.id);
  const params = ask.params.parameters || [];
  const getters = {};
  const err = h('div', { class: 'field-error' });
  const fields = params.map((p) => {
    let ctl, get;
    const label = p.key + (p.requirement === 'required' || p.requirement === 'user_prompt' ? ' *' : '');
    if (p.input_type === 'boolean') { let v = p.default === 'true'; ctl = toggle(v, (x) => { v = x; }); get = () => String(v); }
    else if (p.input_type === 'select' && Array.isArray(p.options)) { ctl = select(p.options.map(String), p.default ?? p.options[0]); get = () => ctl.value; }
    else if (p.input_type === 'number') { ctl = input({ type: 'number', value: p.default ?? '' }); get = () => ctl.value; }
    else if (p.input_type === 'date') { ctl = input({ type: 'date', value: p.default ?? '' }); get = () => ctl.value; }
    else if (p.input_type === 'file') { ctl = input({ value: p.default ?? '', placeholder: 'Absolute path to a file on the server' }); get = () => ctl.value; }
    else { ctl = input({ value: p.default ?? '' }); get = () => ctl.value; }
    getters[p.key] = { get, p };
    return field(label, ctl, p.description);
  });
  let m;
  let answered = false;
  const off = bus.on('ask:resolved', (ev) => { if (ev.id === ask.id) { answered = true; off(); m && m.close(); } });
  const submit = () => {
    const values = {};
    for (const [k, { get, p }] of Object.entries(getters)) {
      const v = get();
      if ((v === '' || v === undefined) && p.requirement !== 'optional' && !p.default) { err.textContent = 'Please fill in ' + k; return; }
      if (v !== '' && v !== undefined) values[k] = v;
    }
    answered = true;
    answerAsk(ask.id, { action: 'submit', values });
  };
  m = modal({
    title: 'Recipe parameters', size: 'md',
    body: h('div', null, h('p', { class: 'muted' }, 'This recipe needs a few values before it starts.'), ...fields, err),
    footer: [btn('Cancel run', () => { answered = true; answerAsk(ask.id, { action: 'cancel' }); }), btn('Start', submit, { variant: 'primary', icon: 'play' })],
    onClose: () => { off(); openParamModals.delete(ask.id); if (!answered) toast('Recipe parameters are still pending', { actions: [{ label: 'Open', onClick: () => openRecipeParamsModal(ask, true) }] }); },
  });
}

export function gotoAsk(ask) { if (ask.sessionId) router.go('/chat/' + encodeURIComponent(ask.sessionId)); }
