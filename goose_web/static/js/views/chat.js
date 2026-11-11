// Chat view: header (title, folder, mode/provider/model, usage, menu), transcript, composer.
import { h, btn, iconBtn, menu, toast, toastError, confirmDialog, promptDialog, modal, downloadBlob, prettyJson, fmtNum, fmtCost, shortPath, spinner, empty, errMsg, select, table, textarea, field, tabs, input, debounce, toggle, banner } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { router } from '../router.js';
import { getChat, setCurrentChat, dropChat, saveDraft } from '../chatsession.js';
import { Composer } from '../composer.js';
import { pickFolder } from './folderpicker.js';
import { getSession, removeSession, patchSession, sessionTitle, upsertSession, isArchived } from '../sessions.js';
import { store, policy, allowedValue } from '../store.js';
import { isPinned, togglePin } from '../prefs.js';
import { pillSelect, rememberEffortOptions } from '../chatoptions.js';
import { setBaseTitle } from '../herd.js';
import { mdElement } from '../markdown.js';

export function renderChat(ctx, sessionId) {
  const chat = getChat(sessionId);
  setCurrentChat(sessionId);
  const offs = [];

  // ----- header -----
  const titleEl = h('button', { type: 'button', class: 'chat-title', title: 'Rename (F2)' });
  const folderChip = h('button', { type: 'button', class: 'chip chip-folder', title: 'Change working folder' });
  const selects = h('div', { class: 'chat-selects' });
  const usageEl = h('div', { class: 'usage', title: 'Context usage' });
  const extChip = h('button', { type: 'button', class: 'chip chip-ext', hidden: true, onclick: () => extensionsDialog(chat) });
  const runPill = h('span', { class: 'run-pill', hidden: true }, h('span', { class: 'sdot s-working' }), 'Working');
  const moreBtn = iconBtn('more', 'Session menu', () => openMenu());
  const header = h('header', { class: 'chat-head' },
    iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }),
    h('div', { class: 'chat-head-main' }, h('div', { class: 'chat-title-row' }, titleEl, runPill), h('div', { class: 'chat-sub' }, folderChip, selects)),
    h('div', { class: 'chat-head-right' }, extChip, usageEl, moreBtn));

  titleEl.addEventListener('click', () => rename());
  folderChip.addEventListener('click', async () => {
    const dir = await pickFolder({ title: 'Change working folder', initial: chat.cwd, confirmText: 'Switch folder' });
    if (dir && dir !== chat.cwd) { try { await chat.setCwd(dir); toast('Working folder changed', { kind: 'success' }); } catch (e) { toastError(e, 'Change folder'); } }
  });

  const rename = async () => {
    const v = await promptDialog({ title: 'Rename chat', label: 'Title', value: chat.title || '', confirmText: 'Rename', validate: (x) => (!x.trim() ? 'Title required' : null) });
    if (v) { try { await chat.rename(v.trim()); } catch (e) { toastError(e, 'Rename'); } }
  };

  const renderHeader = () => {
    const info = getSession(chat.id) || {};
    const t = chat.title || info.title || 'New chat';
    titleEl.textContent = t;
    setBaseTitle(t + ' · Goose');
    folderChip.replaceChildren(icon('folder', 13), h('span', null, shortPath(chat.cwd || info.cwd || '…', 46)));
    folderChip.title = (chat.cwd || '') + ' — click to change';
    runPill.hidden = !chat.running;
    renderSelects();
    renderUsage();
    renderExt();
  };
  // Extension load status, like Desktop's "16/17 extensions loaded".
  const renderExt = () => {
    const r = Array.isArray(chat.extensionResults) ? chat.extensionResults : null;
    if (!r) {
      extChip.hidden = !chat.loading;
      extChip.className = 'chip chip-ext loading';
      extChip.replaceChildren(spinner(11), h('span', { class: 'chip-ext-label' }, 'Extensions'));
      extChip.title = 'Starting extensions';
      return;
    }
    const failed = r.filter((x) => !x.success);
    const ok = r.length - failed.length;
    extChip.hidden = !r.length;
    extChip.className = 'chip chip-ext' + (failed.length ? ' warn' : '');
    extChip.replaceChildren(icon(failed.length ? 'alert' : 'ext', 13), h('span', null, ok + '/' + r.length), h('span', { class: 'chip-ext-label' }, 'extensions'));
    extChip.title = ok + ' of ' + r.length + ' extensions loaded' + (failed.length ? '\nFailed: ' + failed.map((x) => x.name + (x.error ? ' (' + String(x.error).slice(0, 120) + ')' : '')).join('\n        ') : '') + '\nClick for details';
    const key = failed.map((x) => x.name).sort().join('|');
    if (failed.length && chat._extWarned !== key) {
      chat._extWarned = key;
      toast(failed.length === 1 ? 'Extension "' + failed[0].name + '" failed to load' : failed.length + ' extensions failed to load: ' + failed.map((x) => x.name).join(', '),
        { kind: 'warn', timeout: 9000, actions: [{ label: 'Details', onClick: () => extensionsDialog(chat) }] });
    } else if (!failed.length) chat._extWarned = '';
  };
  const renderSelects = () => {
    const nodes = [];
    const modeOpt = chat.configOptions.find((o) => o.category === 'mode' || o.id === 'mode');
    const modes = chat.modes && chat.modes.availableModes ? chat.modes.availableModes.map((m) => ({ value: m.id, label: m.name, title: m.description }))
      : modeOpt ? modeOpt.options.map((o) => ({ value: o.value, label: o.name, title: o.description })) : [];
    const curMode = chat.modes ? chat.modes.currentModeId : modeOpt ? modeOpt.currentValue : null;
    if (modes.length) {
      const opts = modes.filter((m) => allowedValue('allowed_modes', m.value) || m.value === curMode);
      nodes.push(pillSelect('shield', 'Mode', opts, curMode, async (v) => { try { await chat.setMode(v); } catch (e) { toastError(e, 'Mode'); renderSelects(); } }));
    }
    for (const o of chat.configOptions) {
      if (o === modeOpt || o.type !== 'select' || !Array.isArray(o.options)) continue;
      const listKey = o.id === 'provider' ? 'allowed_providers' : o.id === 'model' ? 'allowed_models' : null;
      const opts = o.options.filter((x) => !listKey || allowedValue(listKey, x.value) || x.value === o.currentValue).map((x) => ({ value: x.value, label: x.name || x.value, title: x.description }));
      const ic = o.id === 'provider' ? 'cpu' : o.id === 'model' ? 'zap' : o.category === 'thought_level' ? 'brain' : 'sliders';
      nodes.push(pillSelect(ic, o.name || o.id, opts, o.currentValue, async (v) => { try { await chat.setConfig(o.id, v); } catch (e) { toastError(e, o.name); renderSelects(); } }));
    }
    selects.replaceChildren(...nodes);
    rememberEffortOptions(chat.configOptions);   // the New chat screen offers the effort values seen here
  };
  const renderUsage = () => {
    const u = chat.usage;
    if (!u.size) { usageEl.replaceChildren(); return; }
    const pct = Math.min(100, (u.used / u.size) * 100);
    const r = 9, c = 2 * Math.PI * r;
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    ring.setAttribute('viewBox', '0 0 24 24'); ring.setAttribute('width', '22'); ring.setAttribute('height', '22'); ring.classList.add('usage-ring');
    const bg = document.createElementNS(ring.namespaceURI, 'circle'); bg.setAttribute('cx', '12'); bg.setAttribute('cy', '12'); bg.setAttribute('r', String(r)); bg.setAttribute('class', 'ur-bg');
    const fg = document.createElementNS(ring.namespaceURI, 'circle'); fg.setAttribute('cx', '12'); fg.setAttribute('cy', '12'); fg.setAttribute('r', String(r)); fg.setAttribute('class', 'ur-fg' + (pct > 85 ? ' hot' : pct > 60 ? ' warm' : ''));
    fg.setAttribute('stroke-dasharray', String(c)); fg.setAttribute('stroke-dashoffset', String(c * (1 - pct / 100)));
    ring.append(bg, fg);
    usageEl.title = `Context: ${u.used.toLocaleString()} / ${u.size.toLocaleString()} tokens (${pct.toFixed(1)}%)` + (u.inTokens !== undefined ? `\nTotal: ${fmtNum(u.inTokens)} in, ${fmtNum(u.outTokens)} out` : '') + (u.cost !== null && u.cost !== undefined ? `\nCost: ${fmtCost(u.cost, u.currency)}` : '');
    usageEl.replaceChildren(ring, h('span', { class: 'usage-txt' }, fmtNum(u.used) + ' / ' + fmtNum(u.size)), u.cost ? h('span', { class: 'usage-cost' }, fmtCost(u.cost, u.currency)) : null);
  };

  // ----- body -----
  const scroller = h('div', { class: 'chat-scroll' });
  const inner = h('div', { class: 'chat-inner' });
  const loadingEl = h('div', { class: 'chat-loading' }, spinner(18), h('span', null, 'Loading conversation…'));
  const errorEl = h('div', { class: 'chat-error', hidden: true });
  const jumpBtn = btn(null, () => scrollBottom(true), { icon: 'chevronDown', title: 'Jump to latest', class: 'jump-btn', variant: 'secondary' });
  jumpBtn.hidden = true;
  inner.append(loadingEl, errorEl, chat.transcript.root);
  scroller.append(inner);

  let stick = true;
  scroller.addEventListener('scroll', () => {
    const near = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80;
    stick = near; jumpBtn.hidden = near;
  }, { passive: true });
  const scrollBottom = (force) => { if (stick || force) { scroller.scrollTop = scroller.scrollHeight; stick = true; jumpBtn.hidden = true; } };
  const scrollSoon = () => requestAnimationFrame(() => scrollBottom(false));

  // ----- composer -----
  const composer = new Composer({
    placeholder: 'Message Goose…  (/ for commands, @ to mention)',
    getCwd: () => chat.cwd, getSessionId: () => chat.id, getCommands: () => chat.commands,
    onSend: (blocks) => { stick = true; chat.send(blocks); scrollSoon(); },
    onSteer: (blocks) => { stick = true; chat.steer(blocks); scrollSoon(); },
    onStop: () => chat.cancel(),
    onInput: (v) => { chat.draft = v; saveDraft(chat.id, v); },
  });
  composer.value = chat.draft || '';
  if (chat.prefill) { composer.value = chat.prefill; chat.prefill = null; }

  const renderQueue = () => composer.setQueue(chat.queue, {
    onRemove: (i) => chat.removeQueued(i), onSteer: chat.running ? (i) => chat.steerQueued(i) : null,
    onSend: (i) => { stick = true; chat.sendQueued(i); scrollSoon(); }, onEdit: (i) => chat.editQueued(i),
  });
  // A queued message moved back into the message box (Edit): its text goes in front of what is typed there.
  offs.push(chat.on('edit', (blocks) => {
    const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
    const cur = composer.value || '';
    composer.value = cur ? text + '\n' + cur : text;
    chat.draft = composer.value; saveDraft(chat.id, chat.draft);
    if (blocks.some((b) => b.type !== 'text')) toast('Attachments of the queued message were not moved: attach them again.', { kind: 'warn' });
    composer.focus();
  }));
  const renderState = () => {
    loadingEl.hidden = !chat.loading || chat.transcript.length > 0;
    composer.setRunning(chat.running);
    composer.setProgress(chat.running ? (chat.progress || null) : null);
    renderHeader(); renderQueue();
    if (chat.error && !chat.loaded) {
      errorEl.hidden = false;
      errorEl.replaceChildren(empty('alert', 'Could not open this session', errMsg(chat.error), btn('Retry', () => chat.reload(), { icon: 'refresh' }), btn('Back to herd', () => router.go('/herd'))));
    } else errorEl.hidden = true;
  };

  offs.push(chat.on('state', renderState));
  offs.push(chat.on('usage', renderUsage));
  offs.push(chat.on('queue', renderQueue));
  offs.push(chat.on('progress', (p) => composer.setProgress(chat.running ? p : null)));
  offs.push(chat.on('transcript:append', scrollSoon));
  offs.push(chat.on('transcript:grow', scrollSoon));
  offs.push(chat.on('loaded', () => { scrollBottom(true); renderState(); }));
  offs.push(chat.on('run:end', () => { renderState(); }));
  offs.push(chat.on('external', () => {
    if (Date.now() - (chat._extNoticeAt || 0) > 60000) toast('This chat was updated in another Goose app (Desktop, CLI or a schedule), so it was reloaded.', { kind: 'info', timeout: 5000 });
    chat._extNoticeAt = Date.now();
  }));

  const el = h('div', { class: 'view view-chat' }, header, h('div', { class: 'chat-body' }, scroller, jumpBtn), h('div', { class: 'chat-composer-wrap' }, composer.el));

  renderState();
  // Once per chat and page: offer to refresh extensions whose stored definition is older than the config.
  const offerRefresh = async () => {
    if (checkedExt.has(chat.id) || !policy('extensions_edit')) return;
    checkedExt.add(chat.id);
    try {
      const [sess, cfg] = await Promise.all([rpc.call(G('session/extensions/list'), { sessionId: chat.id }), rpc.call(G('config/extensions/list'), {})]);
      const todo = outdatedExtensions(sess.extensions, cfg.extensions);
      if (todo.length) toast('This chat uses older definitions of ' + todo.map((t) => t.name).join(', ') + ' than your configuration.', { kind: 'warn', timeout: 12000, actions: [{ label: 'Refresh extensions', variant: 'primary', onClick: () => refreshExtensions(chat) }] });
    } catch { /* not important enough to report */ }
  };
  if (chat.loaded) offerRefresh(); else offs.push(chat.on('loaded', offerRefresh));
  if (!chat.loaded && !chat.loading) chat.load();
  requestAnimationFrame(() => { scrollBottom(true); composer.focus(); });

  // ----- menu -----
  function openMenu() {
    const info = getSession(chat.id) || chat.info || {};
    const archived = isArchived(info);
    menu(moreBtn, [
      { label: 'Rename', icon: 'edit', hint: 'F2', onClick: rename },
      { label: isPinned(chat.id) ? 'Unpin' : 'Pin to top', icon: 'pin', onClick: () => togglePin(chat.id) },
      { label: 'Fork conversation', icon: 'fork', onClick: fork },
      '-',
      { label: 'Session extensions…', icon: 'ext', onClick: () => extensionsDialog(chat) },
      ...(policy('extensions_edit') ? [{ label: 'Refresh extensions', icon: 'refresh', onClick: () => refreshExtensions(chat) }] : []),
      { label: 'Tools…', icon: 'tool', onClick: () => toolsDialog(chat) },
      { label: 'System prompt…', icon: 'scroll', onClick: () => systemPromptDialog(chat) },
      { label: 'Diagnostics', icon: 'activity', onClick: () => diagnosticsDialog(chat) },
      '-',
      { label: 'Export as Markdown', icon: 'download', onClick: () => exportSession(chat, 'markdown') },
      { label: 'Export as JSON', icon: 'download', onClick: () => exportSession(chat, 'json') },
      { label: 'Reload transcript', icon: 'refresh', onClick: () => chat.reload() },
      '-',
      { label: archived ? 'Unarchive' : 'Archive', icon: 'archive', onClick: () => archive(!archived) },
      { label: 'Delete…', icon: 'trash', danger: true, onClick: del },
    ], { align: 'right' });
  }
  async function fork() {
    try {
      const res = await rpc.call('session/fork', { sessionId: chat.id, cwd: chat.cwd });
      const id = res.sessionId;
      upsertSession({ sessionId: id, cwd: chat.cwd, title: (chat.title || 'Chat') + ' (fork)', updatedAt: new Date().toISOString() });
      toast('Forked conversation', { kind: 'success' });
      router.go('/chat/' + encodeURIComponent(id));
    } catch (e) { toastError(e, 'Fork'); }
  }
  async function archive(on) {
    try {
      await rpc.call(G(on ? 'session/archive' : 'session/unarchive'), { sessionId: chat.id });
      patchSession(chat.id, { _meta: { archivedAt: on ? new Date().toISOString() : null } });
      toast(on ? 'Archived' : 'Unarchived', { kind: 'success' });
    } catch (e) { toastError(e, 'Archive'); }
  }
  async function del() {
    const ok = await confirmDialog({ title: 'Delete this chat?', message: '“' + (chat.title || 'Untitled') + '” and its history will be permanently deleted.', confirmText: 'Delete', danger: true });
    if (!ok) return;
    try {
      await rpc.call('session/delete', { sessionId: chat.id });
      removeSession(chat.id); dropChat(chat.id);
      toast('Chat deleted', { kind: 'success' });
      router.go('/new');
    } catch (e) { toastError(e, 'Delete'); }
  }

  const onKey = (e) => {
    if (e.key === 'F2') { e.preventDefault(); rename(); }
    if ((e.ctrlKey || e.metaKey) && e.key === '.') { e.preventDefault(); if (chat.running) chat.cancel(); }
  };
  document.addEventListener('keydown', onKey);

  return {
    el,
    focus: () => composer.focus(),
    destroy() { offs.forEach((f) => f()); document.removeEventListener('keydown', onKey); setCurrentChat(null); chat.transcript.root.remove(); },
  };
}

async function exportSession(chat, format) {
  try {
    const r = await rpc.call(G('session/export'), { sessionId: chat.id, format });
    const name = (chat.title || chat.id).replace(/[^\w.-]+/g, '_').slice(0, 60) + (format === 'json' ? '.json' : '.md');
    downloadBlob(r.data, name, format === 'json' ? 'application/json' : 'text/markdown');
  } catch (e) { toastError(e, 'Export'); }
}

// ----- refresh extensions -----
const checkedExt = new Set();
// Goose stores a chat's extension definitions when the chat is created and a reopened chat starts those, not
// the current configuration. A chat is "outdated" when one of its extensions is defined differently in the
// config now (for example a new command or wrapper). Refreshing removes the stored entry and adds the
// current definition, which Goose then stores for the chat. Goose's own database is never edited directly.
const extSig = (x) => JSON.stringify(['type', 'cmd', 'args', 'uri', 'envs', 'env_keys', 'headers', 'timeout', 'bundled']
  .map((k) => (x && x[k] !== undefined ? x[k] : null)));

export function outdatedExtensions(listed, cfgExtensions) {
  const cfgBy = new Map((cfgExtensions || []).flatMap((e) => [[e.configKey, e], [e.extension && e.extension.name, e]].filter((x) => x[0])));
  const out = [];
  for (const e of listed || []) {
    const c = cfgBy.get(e.extension && e.extension.name) || cfgBy.get(e.extensionKey);
    if (c && c.extension && extSig(c.extension) !== extSig(e.extension)) out.push({ key: e.extensionKey, name: (e.extension && e.extension.name) || e.extensionKey, extension: c.extension });
  }
  return out;
}

export async function refreshExtensions(chat, { quiet = false } = {}) {
  if (chat.running || chat.promptPending) { toast('Stop the current run before refreshing extensions.', { kind: 'warn' }); return null; }
  try {
    const [sess, cfg] = await Promise.all([rpc.call(G('session/extensions/list'), { sessionId: chat.id }), rpc.call(G('config/extensions/list'), {})]);
    const todo = outdatedExtensions(sess.extensions, cfg.extensions);
    if (!todo.length) { if (!quiet) toast('Extensions are up to date', { kind: 'success', timeout: 2000 }); return { refreshed: [], failed: [] }; }
    const refreshed = [], failed = [];
    for (const t of todo) {
      try {
        await rpc.call(G('session/extensions/remove'), { sessionId: chat.id, extensionKey: t.key });
        await rpc.call(G('session/extensions/add'), { sessionId: chat.id, extension: t.extension });
        refreshed.push(t.name);
      } catch (e) { failed.push(t.name + ': ' + errMsg(e)); }
    }
    chat.extensionResults = [];   // the dialog recomputes the header count from Goose's list
    if (failed.length) toast('Refreshed ' + refreshed.length + ', failed ' + failed.length + ': ' + failed.join('; '), { kind: 'error', timeout: 9000 });
    else toast('Refreshed ' + refreshed.join(', '), { kind: 'success' });
    return { refreshed, failed };
  } catch (e) { toastError(e, 'Refresh extensions'); return null; }
}

// ----- dialogs -----
export async function extensionsDialog(chat) {
  const body = h('div', { class: 'stack' }, spinner(16));
  const canEdit = policy('extensions_edit');
  let m;
  const load = async () => {
    try {
      const [sess, cfg] = await Promise.all([rpc.call(G('session/extensions/list'), { sessionId: chat.id }), rpc.call(G('config/extensions/list'), {}).catch(() => ({ extensions: [] }))]);
      const listed = sess.extensions || [];
      const results = Array.isArray(chat.extensionResults) ? chat.extensionResults : [];
      const startErr = new Map(results.filter((x) => !x.success).map((x) => [x.name, x.error || 'failed to start']));
      // Goose keeps an extension that failed to start in the session's extension list, so the list alone
      // over-counts: an extension is loaded only if it is listed AND did not fail.
      // MCP (stdio/http) entries come back with extension.name = null; the extensionKey is what identifies them.
      const nm = (e) => e.extension.name || e.extensionKey;
      const active = listed.filter((e) => !startErr.has(nm(e)) && !startErr.has(e.extensionKey));
      const activeNames = new Set(listed.flatMap((e) => [nm(e), e.extensionKey]));
      const keyOf = new Map(listed.flatMap((e) => [[nm(e), e.extensionKey], [e.extensionKey, e.extensionKey]]));
      const failed = [...startErr.keys()];
      const cfgByName = new Map((cfg.extensions || []).flatMap((e) => [[e.configKey, e], [e.extension.name, e]].filter((x) => x[0])));
      const avail = (cfg.extensions || []).filter((e) => ![e.extension.name, e.configKey].some((k) => k && (activeNames.has(k) || startErr.has(k))));
      // Keep the header count in step with what is really active now (adds/removes/retries).
      chat.extensionResults = [...active.map((e) => ({ name: nm(e), success: true })), ...failed.map((n) => ({ name: n, success: false, error: startErr.get(n) }))];
      chat.emit('state');
      const okCount = active.length, total = active.length + failed.length;
      const outdated = outdatedExtensions(listed, cfg.extensions);
      const stale = new Set(outdated.map((o) => o.key));
      body.replaceChildren(
        h('div', { class: 'ext-summary' + (failed.length ? ' warn' : '') }, icon(failed.length ? 'alert' : 'check', 15),
          h('span', null, okCount + ' of ' + total + ' extensions loaded' + (failed.length ? ', ' + failed.length + ' failed' : ''))),
        outdated.length ? banner('warn', outdated.length + ' extension' + (outdated.length > 1 ? 's use an older definition' : ' uses an older definition') + ' than your configuration (' + outdated.map((o) => o.name).join(', ') + '). This chat keeps the definitions it was created with. ',
          canEdit ? btn('Refresh extensions', async () => { await refreshExtensions(chat); load(); }, { size: 'sm', icon: 'refresh', variant: 'primary' }) : null) : null,
        failed.length ? h('h4', null, 'Failed to start') : null,
        failed.length ? table([
          { label: 'Extension', render: (n) => h('div', null, h('div', { class: 'strong' }, n), h('pre', { class: 'ext-error' }, String(startErr.get(n)))) },
          { label: '', class: 'right', render: (n) => canEdit && cfgByName.get(n) ? btn('Retry', async () => {
            try {
              // Drop the dead entry first (Goose keeps it listed), then start it again.
              if (keyOf.has(n)) await rpc.call(G('session/extensions/remove'), { sessionId: chat.id, extensionKey: keyOf.get(n) }).catch(() => {});
              await rpc.call(G('session/extensions/add'), { sessionId: chat.id, extension: cfgByName.get(n).extension }); startErr.delete(n); chat.extensionResults = (chat.extensionResults || []).map((x) => (x.name === n ? { name: n, success: true } : x)); toast('Started ' + n, { kind: 'success' }); load(); }
            catch (e) { const msg = errMsg(e); chat.extensionResults = (chat.extensionResults || []).map((x) => (x.name === n ? { ...x, error: msg } : x)); toastError(e, 'Retry ' + n); load(); }
          }, { size: 'sm', icon: 'refresh' }) : null },
        ], failed) : null,
        h('h4', null, 'Active in this session'),
        table([
          { label: '', render: () => h('span', { class: 'ok', title: 'Loaded' }, icon('check', 14)) },
          { label: 'Extension', render: (r) => h('div', null, h('div', { class: 'strong' }, r.extension.display_name || nm(r), stale.has(r.extensionKey) ? h('span', { class: 'badge badge-warn', title: 'Defined differently in your configuration now' }, ' outdated') : null), h('div', { class: 'muted small' }, r.extension.description || '')) },
          { label: 'Type', render: (r) => h('span', { class: 'badge' }, r.extension.type) },
          { label: '', class: 'right', render: (r) => canEdit ? btn('Remove', async () => { try { await rpc.call(G('session/extensions/remove'), { sessionId: chat.id, extensionKey: r.extensionKey }); toast('Removed ' + nm(r), { kind: 'success' }); load(); } catch (e) { toastError(e); } }, { size: 'sm', variant: 'danger-soft' }) : null },
        ], active, { empty: 'No extensions active' }),
        avail.length ? h('h4', null, 'Add from your configured extensions') : null,
        avail.length ? table([
          { label: 'Extension', render: (r) => h('div', null, h('div', { class: 'strong' }, r.extension.display_name || r.extension.name), h('div', { class: 'muted small' }, r.extension.description || '')) },
          { label: '', class: 'right', render: (r) => canEdit ? btn('Add', async () => { try { await rpc.call(G('session/extensions/add'), { sessionId: chat.id, extension: r.extension }); toast('Added ' + r.extension.name, { kind: 'success' }); load(); } catch (e) { toastError(e); } }, { size: 'sm', icon: 'plus' }) : null },
        ], avail) : null);
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  };
  m = modal({ title: 'Session extensions', size: 'lg', body, footer: [btn('Close', () => m.close())] });
  load();
}

export async function toolsDialog(chat) {
  const body = h('div', { class: 'stack' }, spinner(16));
  let m;
  const canPerm = policy('tools_permissions');
  m = modal({ title: 'Tools available in this session', size: 'lg', body, footer: [btn('Close', () => m.close())] });
  try {
    const r = await rpc.call(G('tools/list'), { sessionId: chat.id });
    const tools = r.tools || [];
    let q = '';
    const list = h('div', { class: 'tool-list' });
    const draw = () => {
      list.replaceChildren(...tools.filter((t) => !q || (t.name + ' ' + t.description).toLowerCase().includes(q)).map((t) => h('details', { class: 'tool-row' },
        h('summary', null, icon('tool', 13), h('span', { class: 'mono strong' }, t.name),
          canPerm ? permSelect(t) : t.permission ? h('span', { class: 'badge' }, t.permission) : null),
        h('div', { class: 'muted small' }, t.description || ''),
        h('pre', { class: 'json' }, prettyJson(t.inputSchema)))));
    };
    const permSelect = (t) => {
      const s = select([{ value: '', label: 'default' }, { value: 'always_allow', label: 'Always allow' }, { value: 'ask_before', label: 'Ask before' }, { value: 'never_allow', label: 'Never allow' }], t.permission || '', { class: 'inp inp-sm', onclick: (e) => e.stopPropagation() });
      s.addEventListener('change', async () => {
        if (!s.value) return;
        try { await rpc.call(G('tools/permissions/set'), { toolPermissions: [{ toolName: t.name, permission: s.value }] }); t.permission = s.value; toast('Permission saved', { kind: 'success', timeout: 1500 }); } catch (e) { toastError(e); }
      });
      return s;
    };
    const search = input({ placeholder: 'Filter ' + tools.length + ' tools…', oninput: debounce(() => { q = search.value.toLowerCase(); draw(); }, 120) });
    body.replaceChildren(search, list);
    draw();
  } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
}

export function systemPromptDialog(chat) {
  const ta = textarea({ rows: 12, placeholder: 'Extra instructions for this session…' });
  let mode = 'append';
  const modeSel = select([{ value: 'append', label: 'Append to the system prompt' }, { value: 'set', label: 'Replace (set) the session prompt' }], mode, { onchange: (e) => { mode = e.target.value; } });
  let m;
  m = modal({
    title: 'Session system prompt', size: 'lg',
    body: h('div', { class: 'stack' }, (store.get('gooseCaps') || {}).persistentSystemPrompt === false ? banner('info', 'This Goose version keeps the override only while the chat is open in this worker. Goose Web applies it again when you reopen the chat, as long as the gateway has not restarted.') : null, h('p', { class: 'muted' }, 'Applies only to this chat. Use Settings → System prompts to change the defaults.'), field('Mode', modeSel), field('Text', ta)),
    footer: [btn('Cancel', () => m.close()), btn('Apply', async () => {
      try { await rpc.call(G('session/system-prompt/set'), { sessionId: chat.id, mode, text: ta.value, ...(mode === 'append' ? { key: 'goose-web' } : {}) }); toast('System prompt updated', { kind: 'success' }); m.close(); } catch (e) { toastError(e, 'System prompt'); }
    }, { variant: 'primary' })],
  });
}

export async function diagnosticsDialog(chat) {
  const body = h('div', { class: 'stack' }, spinner(16));
  let m;
  let level = 'summary';
  const load = async () => {
    body.replaceChildren(spinner(16));
    try {
      const r = await rpc.call(G('diagnostics/get'), { sessionId: chat.id, level });
      const rep = r.report;
      const text = typeof rep === 'string' ? rep : prettyJson(rep);
      body.replaceChildren(tabs([{ id: 'summary', label: 'Summary' }, { id: 'full', label: 'Full' }], level, (v) => { level = v; load(); }),
        typeof rep === 'string' && /^#|\n#/.test(rep) ? mdElement(rep) : h('pre', { class: 'json tall' }, text),
        h('div', { class: 'row' }, btn('Download', () => downloadBlob(text, 'goose-diagnostics-' + chat.id + (typeof rep === 'string' ? '.txt' : '.json')), { icon: 'download', size: 'sm' })));
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  };
  m = modal({ title: 'Diagnostics', size: 'lg', body, footer: [btn('Close', () => m.close())] });
  load();
}

export { toggle };
