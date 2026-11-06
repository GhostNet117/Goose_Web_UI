// Extensions: config/extensions/list with enable toggles, remove, add/edit (MCP stdio, streamable HTTP, built-in).
import { h, btn, iconBtn, pageHeader, toast, toastError, confirmDialog, modal, empty, skeleton, banner, errMsg, input, field, tabs, toggle, menu, debounce, prettyJson } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { policy } from '../store.js';
import { setBaseTitle } from '../herd.js';

const BUILTINS = ['developer', 'computercontroller', 'memory', 'autovisualiser', 'tutorial', 'chatrecall', 'extensionmanager', 'todo', 'apps', 'summarize'];

export function extKind(ext) {
  if (!ext) return '?';
  if (ext.type === 'mcp') return ext.server && ext.server.url ? (ext.server.type === 'sse' ? 'sse' : 'http') : 'stdio';
  return ext.type || '?';
}
export function extName(ext) { return (ext && (ext.display_name || ext.name || (ext.server && ext.server.name))) || 'extension'; }

export function renderExtensions(ctx) {
  setBaseTitle('Extensions · Goose');
  const canEdit = policy('extensions_edit');
  let all = []; let warnings = []; let q = ''; let filter = 'all';
  const listEl = h('div', { class: 'ext-list' }, skeleton(6));
  const warnEl = h('div');
  const search = input({ type: 'search', placeholder: 'Search extensions…', 'aria-label': 'Search extensions' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); draw(); }, 120));
  const filterBar = h('div');

  const draw = () => {
    warnEl.replaceChildren(...warnings.map((w) => banner('warn', w)));
    const counts = { all: all.length, enabled: all.filter((e) => e.enabled).length, disabled: all.filter((e) => !e.enabled).length };
    filterBar.replaceChildren(tabs([{ id: 'all', label: 'All', count: counts.all }, { id: 'enabled', label: 'Enabled', count: counts.enabled }, { id: 'disabled', label: 'Disabled', count: counts.disabled }], filter, (v) => { filter = v; draw(); }));
    const items = all.filter((e) => (filter === 'all' || (filter === 'enabled') === !!e.enabled)
      && (!q || (extName(e.extension) + ' ' + (e.extension.name || '') + ' ' + (e.extension.description || '')).toLowerCase().includes(q)));
    if (!items.length) {
      listEl.replaceChildren(all.length ? empty('search', 'No matches') : empty('ext', 'No extensions', 'Extensions give Goose tools (MCP servers).', canEdit ? btn('Add extension', () => extensionDialog(null, load), { icon: 'plus', variant: 'primary' }) : null));
      return;
    }
    listEl.replaceChildren(...items.map((e) => extRow(e)));
  };

  const extRow = (e) => {
    const x = e.extension; const kind = extKind(x); const key = e.configKey || x.name;
    const tgl = toggle(e.enabled, async (on) => {
      try { await rpc.call(G('config/extensions/set-enabled'), { configKey: key, enabled: on }); e.enabled = on; toast((on ? 'Enabled ' : 'Disabled ') + extName(x), { kind: 'success', timeout: 1800 }); draw(); }
      catch (err) { toastError(err, 'Toggle'); load(); }
    }, { disabled: !canEdit, label: 'Enable ' + extName(x) });
    const detail = kind === 'stdio' ? [x.server.command, ...(x.server.args || [])].join(' ') : (kind === 'http' || kind === 'sse') ? x.server.url : '';
    return h('div', { class: ['ext-row', e.enabled ? 'on' : 'off'] },
      h('span', { class: 'ext-icon' }, icon(kind === 'stdio' ? 'terminal' : kind === 'http' || kind === 'sse' ? 'globe' : 'zap', 16)),
      h('div', { class: 'ext-main' },
        h('div', { class: 'ext-title' }, extName(x), h('span', { class: 'badge' }, kind), x.bundled ? h('span', { class: 'badge' }, 'bundled') : null),
        h('div', { class: 'muted small' }, x.description || ''),
        detail ? h('div', { class: 'mono small muted ext-cmd', title: detail }, detail) : null),
      h('div', { class: 'ext-actions' }, tgl,
        iconBtn('more', 'More', (ev) => menu(ev.currentTarget, [
          { label: 'View configuration', icon: 'code', onClick: () => modal({ title: extName(x), size: 'lg', body: h('pre', { class: 'json' }, prettyJson(e)) }) },
          { label: 'Edit…', icon: 'edit', hidden: !canEdit || x.type !== 'mcp', onClick: () => extensionDialog(e, load) },
          '-',
          { label: 'Remove', icon: 'trash', danger: true, hidden: !canEdit, onClick: async () => {
            if (!(await confirmDialog({ title: 'Remove ' + extName(x) + '?', message: 'It will be removed from your Goose configuration. Running chats keep it until they reload.', confirmText: 'Remove', danger: true }))) return;
            try { await rpc.call(G('config/extensions/remove'), { configKey: key }); toast('Removed', { kind: 'success' }); load(); } catch (err) { toastError(err, 'Remove'); }
          } },
        ], { align: 'right' }))));
  };

  async function load() {
    try {
      const r = await rpc.call(G('config/extensions/list'), {});
      all = (r.extensions || []).sort((a, b) => (b.enabled - a.enabled) || extName(a.extension).localeCompare(extName(b.extension)));
      warnings = r.warnings || [];
      draw();
    } catch (e) { listEl.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Extensions'), 'MCP servers and built-ins that give Goose its tools.',
      [search, iconBtn('refresh', 'Refresh', () => load()), canEdit ? btn('Add extension', () => extensionDialog(null, load), { icon: 'plus', variant: 'primary' }) : null]),
    h('div', { class: 'page-body' }, !canEdit ? banner('info', 'Read-only: your policy does not allow changing extensions.') : null, warnEl, filterBar, listEl));
  load();
  return { el };
}

// Key/value rows editor -> [{name, value}]
function kvEditor(rows, { keyPh = 'NAME', valPh = 'value', secret = false } = {}) {
  const wrap = h('div', { class: 'kv-ed' });
  const list = h('div', { class: 'stack-sm' });
  const add = (k = '', v = '') => {
    const ki = input({ value: k, placeholder: keyPh, class: 'inp inp-sm mono' });
    const vi = input({ value: v, placeholder: valPh, class: 'inp inp-sm mono', type: secret ? 'password' : 'text', autocomplete: 'new-password' });
    const row = h('div', { class: 'row kv-row' }, ki, vi, iconBtn('x', 'Remove', () => row.remove()));
    list.appendChild(row);
  };
  (rows || []).forEach((r) => add(r.name, r.value));
  wrap.append(list, btn('Add', () => add(), { size: 'sm', icon: 'plus', variant: 'ghost' }));
  return {
    el: wrap,
    get: () => [...list.querySelectorAll('.kv-row')].map((r) => { const [a, b] = r.querySelectorAll('input'); return { name: a.value.trim(), value: b.value }; }).filter((r) => r.name),
  };
}

export function extensionDialog(existing, onDone) {
  const allowShell = policy('allow_shell');
  const x = existing ? existing.extension : null;
  let kind = x ? extKind(x) : (allowShell ? 'stdio' : 'http');
  if (kind === 'sse') kind = 'http';
  const name = input({ value: x ? (x.server ? x.server.name : x.name) : '', placeholder: 'my-extension', disabled: !!existing });
  const desc = input({ value: (x && x.description) || '', placeholder: 'What does it do?' });
  const timeout = input({ type: 'number', min: '1', value: (x && x.timeout) || 300, class: 'inp inp-sm' });
  const cmd = input({ value: x && x.server && x.server.command ? [x.server.command, ...(x.server.args || [])].map(quoteArg).join(' ') : '', placeholder: 'npx -y @modelcontextprotocol/server-everything', class: 'inp mono' });
  const env = kvEditor(x && x.server && x.server.env, { secret: true });
  const url = input({ value: (x && x.server && x.server.url) || '', placeholder: 'https://example.com/mcp', class: 'inp mono' });
  const headers = kvEditor(x && x.server && x.server.headers, { keyPh: 'Header', valPh: 'value', secret: true });
  const bname = input({ value: x && x.type === 'builtin' ? x.name : '', placeholder: 'developer', list: 'gw-builtins' });
  const dl = h('datalist', { id: 'gw-builtins' }, BUILTINS.map((b) => h('option', { value: b })));
  const pane = h('div', { class: 'stack' });
  const err = h('div', { class: 'field-error' });
  const drawPane = () => {
    const items = [{ id: 'stdio', label: 'Command (stdio)', icon: 'terminal', hidden: !allowShell && kind !== 'stdio' }, { id: 'http', label: 'Streamable HTTP', icon: 'globe' }, { id: 'builtin', label: 'Built-in', icon: 'zap', hidden: !!existing }];
    let body;
    if (kind === 'stdio') body = [!allowShell ? banner('warn', 'Your policy does not allow command (stdio) extensions; saving will be refused.') : null,
      field('Command', cmd, 'Full command line; arguments are split on spaces (use quotes for spaces).'), field('Environment variables', env.el, 'Passed to the process. Values are stored in your Goose config.')];
    else if (kind === 'http') body = [field('URL', url), field('Headers', headers.el, 'For example Authorization: Bearer …')];
    else body = [field('Built-in name', bname, 'Name of a Goose built-in extension'), dl];
    pane.replaceChildren(tabs(items, kind, (v) => { kind = v; drawPane(); }),
      kind !== 'builtin' ? h('div', { class: 'grid2' }, field('Name', name), field('Timeout (s)', timeout)) : field('Timeout (s)', timeout),
      kind !== 'builtin' ? field('Description', desc) : null, ...body);
  };
  drawPane();
  const build = () => {
    const to = parseInt(timeout.value, 10) || null;
    if (kind === 'builtin') {
      const n = bname.value.trim(); if (!n) throw new Error('Choose a built-in name');
      return { type: 'builtin', name: n, description: null, display_name: null, timeout: to, bundled: null, available_tools: null };
    }
    const n = name.value.trim(); if (!n) throw new Error('Name is required');
    if (!/^[A-Za-z0-9_.-]+$/.test(n)) throw new Error('Name may only contain letters, numbers, - _ .');
    const base = { type: 'mcp', envKeys: (x && x.envKeys) || [], description: desc.value.trim() || null, timeout: to, socket: null, clientId: (x && x.clientId) || null, clientSecretKey: (x && x.clientSecretKey) || null, scopes: (x && x.scopes) || [], bundled: null, available_tools: (x && x.available_tools) || null };
    if (kind === 'stdio') {
      const parts = splitArgs(cmd.value.trim()); if (!parts.length) throw new Error('Command is required');
      return { ...base, server: { name: n, command: parts[0], args: parts.slice(1), env: env.get() } };
    }
    const u = url.value.trim(); try { new URL(u); } catch { throw new Error('Enter a valid URL'); }
    return { ...base, server: { type: 'http', name: n, url: u, headers: headers.get() } };
  };
  const m = modal({ title: existing ? 'Edit ' + extName(x) : 'Add extension', size: 'lg', body: h('div', { class: 'stack' }, pane, err),
    footer: [btn('Cancel', () => m.close()), btn(existing ? 'Save' : 'Add', async () => {
      err.textContent = '';
      let ext; try { ext = build(); } catch (e) { err.textContent = e.message; return; }
      try {
        await rpc.call(G('config/extensions/add'), { extension: ext, enabled: existing ? !!existing.enabled : true });
        toast(existing ? 'Extension saved' : 'Extension added', { kind: 'success' }); m.close(); onDone && onDone();
      } catch (e) { err.textContent = errMsg(e); }
    }, { variant: 'primary' })] });
}

function quoteArg(a) { a = String(a); return /\s|"/.test(a) ? '"' + a.replace(/"/g, '\\"') + '"' : a; }
export function splitArgs(s) {
  const out = []; let cur = ''; let q = null; let has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && s[i + 1] === q) { cur += q; i++; } else if (c === q) q = null; else cur += c; }
    else if (c === '"' || c === "'") { q = c; has = true; }
    else if (/\s/.test(c)) { if (cur || has) { out.push(cur); cur = ''; has = false; } }
    else cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}
