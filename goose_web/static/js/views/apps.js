// Apps: MCP Apps grid, sandboxed frame (served by the gateway, opaque origin) + postMessage bridge.
import { h, btn, iconBtn, pageHeader, toast, toastError, confirmDialog, modal, empty, skeleton, banner, errMsg, input, textarea, field, tabs, downloadBlob, pickFile, readFileText, menu, debounce } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { policy } from '../store.js';
import { setBaseTitle } from '../herd.js';
import { isLight } from '../prefs.js';
import { router } from '../router.js';
import { defaultCwd } from './home.js';

const PROTOCOL = '2025-06-18';

export function renderApps(ctx, name) {
  if (name) return renderAppRunner(ctx, name);
  setBaseTitle('Apps · Goose');
  const canEdit = policy('apps');
  let all = []; let q = '';
  const grid = h('div', { class: 'cgrid' }, skeleton(4));
  const search = input({ type: 'search', placeholder: 'Search apps…', 'aria-label': 'Search apps' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); draw(); }, 120));

  const draw = () => {
    const items = all.filter((a) => !q || ((a.name || '') + ' ' + (a.description || '')).toLowerCase().includes(q));
    if (!items.length) {
      grid.replaceChildren(all.length ? empty('search', 'No matches') : empty('apps', 'No apps yet', 'Apps are small HTML tools (MCP Apps) that can call Goose tools. Ask Goose to build one, or import an HTML file.', canEdit ? btn('Import app', importDialog, { icon: 'upload', variant: 'primary' }) : null));
      return;
    }
    grid.replaceChildren(...items.map((a) => h('div', { class: 'ccard app-card' },
      h('div', { class: 'ccard-head' }, h('span', { class: 'ccard-icon' }, icon('apps', 18)),
        h('div', { class: 'grow' }, h('div', { class: 'ccard-title' }, prettyName(a.name)), h('div', { class: 'muted small mono' }, a.uri || '')),
        iconBtn('more', 'More', (ev) => menu(ev.currentTarget, [
          { label: 'Open', icon: 'play', onClick: () => router.go('/apps/' + encodeURIComponent(a.name)) },
          { label: 'Open in new tab', icon: 'external', onClick: () => window.open('/#/apps/' + encodeURIComponent(a.name), '_blank', 'noopener') },
          { label: 'Export HTML', icon: 'download', onClick: () => exportApp(a.name) },
          a.prd ? { label: 'View description', icon: 'file', onClick: () => prdDialog(a) } : null,
          '-',
          { label: 'Delete', icon: 'trash', danger: true, hidden: !canEdit, onClick: () => deleteApp(a.name) },
        ].filter(Boolean)))),
      h('div', { class: 'ccard-desc' }, a.description || 'No description'),
      h('div', { class: 'ccard-tags' }, ...(a.mcpServers || []).map((s) => h('span', { class: 'badge' }, s)), a.width && a.height ? h('span', { class: 'badge' }, a.width + '×' + a.height) : null),
      h('div', { class: 'ccard-foot' }, btn('Open', () => router.go('/apps/' + encodeURIComponent(a.name)), { icon: 'play', size: 'sm', variant: 'primary' })))));
  };

  const exportApp = async (n) => {
    try { const r = await rpc.call(G('apps/export'), { name: n }); downloadBlob(r.html, n + '.html', 'text/html'); } catch (e) { toastError(e, 'Export'); }
  };
  const deleteApp = async (n) => {
    if (!(await confirmDialog({ title: 'Delete app “' + prettyName(n) + '”?', message: 'This removes the app from your Goose profile.', confirmText: 'Delete', danger: true }))) return;
    try { await rpc.call(G('apps/delete'), { name: n }); toast('App deleted', { kind: 'success' }); load(); } catch (e) { toastError(e, 'Delete'); }
  };
  const prdDialog = (a) => {
    import('../markdown.js').then(({ mdElement }) => modal({ title: prettyName(a.name), size: 'lg', body: mdElement(a.prd) }));
  };
  const importDialog = () => {
    let mode = 'file';
    const ta = textarea({ rows: 14, class: 'inp mono', placeholder: '<!DOCTYPE html>…' });
    const fileInfo = h('div', { class: 'muted small' }, 'No file selected');
    let fileHtml = '';
    const drop = h('div', { class: 'dropzone', tabindex: '0', role: 'button' }, icon('upload', 20), h('div', null, 'Choose an .html file'), fileInfo);
    const choose = async () => { const [f] = await pickFile({ accept: '.html,.htm,text/html' }); if (f) { fileHtml = await readFileText(f); fileInfo.textContent = f.name + ' · ' + fileHtml.length + ' chars'; } };
    drop.addEventListener('click', choose);
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); } });
    const pane = h('div');
    const drawPane = () => pane.replaceChildren(tabs([{ id: 'file', label: 'Upload file' }, { id: 'paste', label: 'Paste HTML' }], mode, (v) => { mode = v; drawPane(); }), mode === 'file' ? drop : ta);
    drawPane();
    const m = modal({ title: 'Import app', size: 'lg', body: h('div', { class: 'stack' }, h('div', { class: 'muted' }, 'The HTML must be an MCP App (it may contain an apps metadata block). It runs in a sandbox with no access to this site.'), pane),
      footer: [btn('Cancel', () => m.close()), btn('Import', async () => {
        const html = mode === 'file' ? fileHtml : ta.value;
        if (!html.trim()) { toast('Nothing to import', { kind: 'warn' }); return; }
        try { const r = await rpc.call(G('apps/import'), { html }); toast(r.message || ('Imported ' + r.name), { kind: 'success' }); m.close(); load(); } catch (e) { toastError(e, 'Import'); }
      }, { variant: 'primary', icon: 'upload' })] });
  };

  async function load() {
    try {
      const r = await rpc.call(G('apps/list'), {});
      all = (r.apps || []).sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      draw();
    } catch (e) { grid.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Apps'), 'Small interactive tools that run in a sandbox and can call Goose.',
      [search, iconBtn('refresh', 'Refresh', () => load()), canEdit ? btn('Import', importDialog, { icon: 'upload' }) : null]),
    h('div', { class: 'page-body' }, !canEdit ? banner('info', 'Your policy does not allow importing or deleting apps.') : null, grid));
  load();
  return { el };
}

export function prettyName(n) {
  return String(n || 'app').replace(/[-_]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------- app runner -------------------------------------------------------
function renderAppRunner(ctx, name) {
  setBaseTitle(prettyName(name) + ' · Goose');
  let app = null; let sessionId = null; let sessionPromise = null; let bridge = null;
  const frameWrap = h('div', { class: 'app-frame-wrap' }, skeleton(3));
  const status = h('span', { class: 'muted small' }, 'Loading…');
  const el = h('div', { class: 'view view-page view-app' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), iconBtn('chevronLeft', 'Back to apps', () => router.go('/apps')), prettyName(name)), status,
      [iconBtn('refresh', 'Reload app', () => mountFrame()), iconBtn('external', 'Open in new tab', () => window.open('/#/apps/' + encodeURIComponent(name), '_blank', 'noopener'))]),
    h('div', { class: 'page-body app-body' }, frameWrap));

  const ensureSession = () => {
    if (sessionId) return Promise.resolve(sessionId);
    if (!sessionPromise) {
      sessionPromise = defaultCwd().then((cwd) => rpc.call('session/new', { cwd, mcpServers: [], _meta: {} })).then((r) => { sessionId = r.sessionId; return sessionId; })
        .catch((e) => { sessionPromise = null; throw e; });
    }
    return sessionPromise;
  };

  const mountFrame = () => {
    if (bridge) bridge.destroy();
    const src = '/api/apps/frame?name=' + encodeURIComponent(name) + (sessionId ? '&sessionId=' + encodeURIComponent(sessionId) : '');
    const iframe = h('iframe', { class: 'app-frame', title: prettyName(name), sandbox: 'allow-scripts allow-forms allow-popups', src, referrerpolicy: 'no-referrer' });
    if (app && app.width) iframe.style.width = Math.max(200, app.width) + 'px';
    if (app && app.height) iframe.style.height = Math.max(150, app.height) + 'px';
    if (app && app.resizable !== false) iframe.classList.add('resizable');
    frameWrap.replaceChildren(iframe);
    bridge = createAppBridge(iframe, {
      app, extensionName: (app && app.mcpServers && app.mcpServers[0]) || 'apps', ensureSession,
      onInitialized: () => { status.textContent = 'Running · sandboxed'; },
      onMessage: (text) => openChatWith(text),
    });
  };

  const openChatWith = async (text) => {
    try {
      const sid = await ensureSession();
      router.go('/chat/' + encodeURIComponent(sid));
      const { getChat } = await import('../chatsession.js');
      const chat = getChat(sid);
      await chat.ensureLoaded();
      chat.send([{ type: 'text', text }]);
    } catch (e) { toastError(e, 'Send to chat'); }
  };

  (async () => {
    try {
      const r = await rpc.call(G('apps/list'), {});
      app = (r.apps || []).find((a) => a.name === name) || null;
      if (!app) { frameWrap.replaceChildren(empty('apps', 'App not found', 'No app named “' + name + '” in your profile.', btn('All apps', () => router.go('/apps')))); status.textContent = ''; return; }
      status.textContent = app.description || '';
      mountFrame();
    } catch (e) { frameWrap.replaceChildren(banner('error', errMsg(e))); }
  })();

  return {
    el,
    destroy() {
      if (bridge) bridge.destroy();
      // Close the helper session (like Desktop StandaloneAppView) – best effort.
      if (sessionId) rpc.call('session/close', { sessionId }).catch(() => {});
    },
  };
}

// MCP Apps host bridge (JSON-RPC 2.0 over postMessage). The frame has an opaque origin
// ('null'), so we authenticate messages by event.source === iframe.contentWindow.
export function createAppBridge(iframe, { app, extensionName, ensureSession, onInitialized, onMessage, toolInput, toolResult }) {
  let initialized = false;
  let autoHinted = false;
  const post = (msg) => { try { iframe.contentWindow && iframe.contentWindow.postMessage(msg, '*'); } catch (e) { console.warn('postMessage failed', e); } };
  const reply = (id, result) => post({ jsonrpc: '2.0', id, result });
  const fail = (id, code, message) => post({ jsonrpc: '2.0', id, error: { code, message } });
  const hostContext = () => {
    const r = iframe.getBoundingClientRect();
    return {
      theme: isLight() ? 'light' : 'dark',
      styles: { variables: cssVars() },
      displayMode: 'inline',
      availableDisplayModes: ['inline'],
      containerDimensions: { width: Math.round(r.width), maxHeight: Math.round(window.innerHeight * 0.85) },
      locale: navigator.language,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      userAgent: 'goose-web',
      platform: matchMedia('(pointer: coarse)').matches ? 'mobile' : 'web',
      deviceCapabilities: { touch: 'ontouchstart' in window, hover: matchMedia('(hover: hover)').matches },
      safeAreaInsets: { top: 0, right: 0, bottom: 0, left: 0 },
      toolInfo: app ? { tool: { name: app.name, description: app.description || '' } } : undefined,
    };
  };

  const handlers = {
    'ui/initialize': async () => ({
      protocolVersion: PROTOCOL,
      hostInfo: { name: 'goose-web', version: '1.0.0' },
      hostCapabilities: { openLinks: {}, serverTools: {}, serverResources: {}, logging: {}, message: { text: {} } },
      hostContext: hostContext(),
    }),
    'ping': async () => ({}),
    'tools/call': async (p) => {
      const sessionId = await ensureSession();
      const toolName = String(p.name || '');
      let r;
      try {
        r = await rpc.call(G('tools/call'), { sessionId, extensionName, name: toolName.includes('__') ? toolName : extensionName + '__' + toolName, arguments: p.arguments || {} });
      } catch (e) {
        // Goose only lets apps run tools when the session is in Auto mode (same rule as Desktop); say so in the host UI.
        if (/auto mode/i.test(errMsg(e)) && !autoHinted) { autoHinted = true; toast('This app tried to run the tool "' + toolName + '". Goose only allows app tool calls when the chat is in Auto mode.', { kind: 'warn', timeout: 8000 }); }
        throw e;
      }
      return { content: r.content || [], isError: !!r.isError, structuredContent: r.structuredContent, _meta: r._meta };
    },
    'resources/read': async (p) => {
      const sessionId = await ensureSession();
      const r = await rpc.call(G('resources/read'), { sessionId, uri: p.uri, extensionName });
      return r.result || { contents: [] };
    },
    'ui/message': async (p) => {
      const text = (p.content || []).filter((c) => c && c.type === 'text').map((c) => c.text).join('\n') || (p.text || '');
      if (text && onMessage) onMessage(text);
      return {};
    },
    'ui/open-link': async (p) => {
      try {
        const u = new URL(String(p.url || ''));
        if (!/^https?:$|^mailto:$/.test(u.protocol)) return { status: 'error', message: 'Only http(s)/mailto links are allowed' };
        window.open(u.href, '_blank', 'noopener,noreferrer');
        return { status: 'success' };
      } catch { return { status: 'error', message: 'Invalid URL' }; }
    },
    'ui/request-display-mode': async () => ({ mode: 'inline' }),
  };

  const onNotification = (method, p) => {
    if (method === 'ui/notifications/initialized') {
      initialized = true;
      if (onInitialized) onInitialized();
      if (toolInput) post({ jsonrpc: '2.0', method: 'ui/notifications/tool-input', params: { arguments: toolInput } });
      if (toolResult) post({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: toolResult });
    } else if (method === 'ui/notifications/size-changed') {
      if (p && p.height > 0) iframe.style.height = Math.min(Math.max(80, Math.ceil(p.height)), 4000) + 'px';
      if (p && p.width > 0 && app && app.resizable !== false) iframe.style.width = Math.min(Math.ceil(p.width), 4000) + 'px';
    } else if (method === 'notifications/message') {
      console.debug('[app ' + (app && app.name) + ']', p && p.level, p && p.data);
    }
  };

  const onMsg = async (ev) => {
    if (ev.source !== iframe.contentWindow) return;
    const msg = ev.data;
    if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return;
    if (msg.id === undefined || msg.id === null) { onNotification(msg.method, msg.params || {}); return; }
    const fn = handlers[msg.method];
    if (!fn) { fail(msg.id, -32601, 'Method not supported by host: ' + msg.method); return; }
    try { reply(msg.id, await fn(msg.params || {})); } catch (e) { fail(msg.id, (e && e.code) || -32000, errMsg(e)); }
  };
  window.addEventListener('message', onMsg);
  const themeObs = new MutationObserver(() => {
    if (initialized) post({ jsonrpc: '2.0', method: 'ui/notifications/host-context-changed', params: { theme: isLight() ? 'light' : 'dark', styles: { variables: cssVars() } } });
  });
  themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'data-scheme'] });
  return {
    destroy() { window.removeEventListener('message', onMsg); themeObs.disconnect(); },
    sendToolInput(args) { post({ jsonrpc: '2.0', method: 'ui/notifications/tool-input', params: { arguments: args } }); },
    sendToolResult(res) { post({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: res }); },
  };
}

function cssVars() {
  const cs = getComputedStyle(document.documentElement);
  const out = {};
  for (const [k, v] of [['--color-background-primary', '--bg'], ['--color-background-secondary', '--bg-2'], ['--color-text-primary', '--fg'], ['--color-text-secondary', '--fg-2'], ['--color-border-primary', '--border'], ['--color-accent', '--accent'], ['--font-sans', '--font'], ['--font-mono', '--mono']]) {
    const val = cs.getPropertyValue(v).trim();
    if (val) out[k] = val;
  }
  return out;
}
