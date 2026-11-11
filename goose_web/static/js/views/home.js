// New chat / home view: hero composer with folder chip + optional recipe; creates session/new then sends.
import { h, btn, iconBtn, toast, toastError, shortPath, baseName, menu, relTime, spinner, banner, confirmDialog } from '../ui.js';
import { icon, logo } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { router } from '../router.js';
import { store } from '../store.js';
import { Composer } from '../composer.js';
import { pickFolder, fsRoots } from './folderpicker.js';
import { pref, setPref, addRecentFolder } from '../prefs.js';
import { allowedValue, chatBlocked } from '../store.js';
import { MODES, pillSelect, knownEfforts, loadNewChatOptions, applyNewChatOptions } from '../chatoptions.js';
import { getChat } from '../chatsession.js';
import { upsertSession, sessionsState, sessionTitle, activityTime } from '../sessions.js';
import { setBaseTitle, herdList } from '../herd.js';

export async function createSession({ cwd, recipeId = null, recipeDeeplink = null }) {
  const _meta = {};
  if (recipeId) _meta.recipeId = recipeId;
  if (recipeDeeplink) _meta.recipeDeeplink = recipeDeeplink;
  let res;
  try {
    try {
      res = await rpc.call('session/new', { cwd, mcpServers: [], _meta });
    } catch (e) {
      // SD-2 (security review 2026-11-11): an administrator starting a chat in a folder members can write is shown the
      // Goose plugins there (they would run as the administrator, unsandboxed) and must accept exactly that list.
      const d = e && e.data;
      if (!(d && d.confirm && Array.isArray(d.plugins))) throw e;
      const list = h('ul', null, ...d.plugins.map((n) => h('li', { class: 'mono' }, String(n))));
      const ok = await confirmDialog({
        title: 'Run the Goose plugins in this folder?', danger: true, confirmText: 'Run them and start the chat',
        message: h('div', null,
          h('p', null, 'Members can write to this folder, and it holds Goose plugins (.agents/plugins). Goose starts their programs on this computer as you, without a sandbox, when the chat starts:'),
          list,
          h('p', { class: 'muted small' }, 'Only continue if you know who put them there and what they run.')),
      });
      if (!ok) { const err = new Error('Chat not started: the plugins in this folder were not accepted.'); err.code = 'cancelled'; throw err; }
      res = await rpc.call('session/new', { cwd, mcpServers: [], _meta: { ..._meta, [d.confirm]: d.plugins } });
    }
  } catch (e) {
    // Fresh profiles have no provider yet: point the user at the place to fix it.
    if (/GOOSE_PROVIDER/.test(String((e && (e.data || e.message)) || ''))) {
      const err = new Error('No model provider is set up for your profile yet. Open Settings > Models & Providers (or ask your admin to assign one to your team).');
      err.code = e.code;
      throw err;
    }
    throw e;
  }
  const id = res.sessionId;
  const info = { sessionId: id, cwd: (res._meta && res._meta.workingDir) || cwd, title: '', updatedAt: new Date().toISOString(), _meta: { createdAt: new Date().toISOString() } };
  upsertSession(info);
  const chat = getChat(id, info);
  chat.applySessionResult(res);
  chat.loaded = true; // brand new session: nothing to replay
  addRecentFolder(cwd);
  return chat;
}

export async function defaultCwd() {
  const last = pref('lastCwd');
  if (last) return last;
  try { const r = await fsRoots(); return r.defaultCwd || r.home || (r.roots && r.roots[0] && r.roots[0].path) || ''; } catch { return ''; }
}

export function renderHome(ctx, query = {}) {
  setBaseTitle('New chat · Goose');
  let cwd = query.cwd || '';
  let recipe = null; // {id, title, prompt}
  const folderChip = h('button', { type: 'button', class: 'chip chip-folder chip-lg', title: 'Choose working folder' });
  const recipeChip = h('button', { type: 'button', class: 'chip', title: 'Start from a recipe' });
  const renderChips = () => {
    folderChip.replaceChildren(icon('folder', 14), h('span', null, cwd ? shortPath(cwd, 48) : 'Choose folder…'), icon('chevronDown', 12));
    folderChip.title = cwd || 'Choose working folder';
    recipeChip.replaceChildren(icon('recipe', 14), h('span', null, recipe ? recipe.title : 'Recipe'), recipe ? iconBtn('x', 'Clear recipe', (e) => { e.stopPropagation(); recipe = null; renderChips(); }, { size: 'sm' }) : icon('chevronDown', 12));
  };
  // ----- per-chat options (spec 008): provider, model, thinking effort, approval mode -----
  const optsRow = h('div', { class: 'home-opts', role: 'group', 'aria-label': 'Options for the new chat' });
  let optData = null;
  const choice = { provider: '', model: '', effort: '', mode: '', ...(pref('newChat') || {}) };
  const saveChoice = () => setPref('newChat', { provider: choice.provider, model: choice.model, effort: choice.effort, mode: choice.mode });
  const renderOpts = () => {
    const nodes = [];
    if (optData && optData.providers.length) {
      const provs = optData.providers;
      if (choice.provider && !provs.some((x) => x.id === choice.provider)) { choice.provider = ''; choice.model = ''; choice.effort = ''; }
      const defP = provs.find((x) => x.id === optData.defaultProvider);
      const effProvider = choice.provider || optData.defaultProvider;
      const pEntry = provs.find((x) => x.id === effProvider);
      const models = pEntry ? pEntry.models : [];
      if (choice.model && !models.some((m) => m.id === choice.model)) { choice.model = ''; choice.effort = ''; }
      const defModel = (!choice.provider || choice.provider === optData.defaultProvider) && optData.defaultModel ? optData.defaultModel : (pEntry ? pEntry.defaultModel : '');
      nodes.push(pillSelect('cpu', 'Provider', [{ value: '', label: 'Default provider' + (defP ? ' (' + defP.name + ')' : '') }, ...provs.map((x) => ({ value: x.id, label: x.name }))],
        choice.provider, (v) => { choice.provider = v; choice.model = ''; choice.effort = ''; saveChoice(); renderOpts(); }));
      nodes.push(pillSelect('zap', 'Model', [{ value: '', label: 'Default model' + (defModel ? ' (' + defModel + ')' : '') }, ...models.map((m) => ({ value: m.id, label: m.name }))],
        choice.model, (v) => { choice.model = v; choice.effort = ''; saveChoice(); renderOpts(); }));
      const efforts = knownEfforts(effProvider, choice.model || defModel);
      if (choice.effort && !efforts.some((x) => x.value === choice.effort)) choice.effort = '';
      nodes.push(pillSelect('brain', 'Thinking effort', [{ value: '', label: 'Default effort' + (optData.defaultEffort ? ' (' + optData.defaultEffort + ')' : '') }, ...efforts], choice.effort, (v) => { choice.effort = v; saveChoice(); }));
    }
    const modes = MODES.filter((m) => allowedValue('allowed_modes', m.value));
    if (choice.mode && !modes.some((m) => m.value === choice.mode)) choice.mode = '';
    const dm = optData ? MODES.find((m) => m.value === optData.defaultMode) : null;
    nodes.push(pillSelect('shield', 'Approval mode', [{ value: '', label: 'Default approval' + (dm ? ' (' + dm.label + ')' : '') }, ...modes], choice.mode, (v) => { choice.mode = v; saveChoice(); }));
    optsRow.replaceChildren(...nodes);
  };
  // Apply the non-default choices to the new chat before its first prompt; unavailable ones only warn.
  const applyChoice = async (chat) => {
    if (!choice.provider && !choice.model && !choice.effort && !choice.mode) return;
    const warn = await applyNewChatOptions(chat, { ...choice });
    if (warn.length) toast('Some chat options were not applied:\n' + warn.join('\n'), { kind: 'warn', timeout: 10000 });
  };

  folderChip.addEventListener('click', async () => { const d = await pickFolder({ initial: cwd }); if (d) { cwd = d; renderChips(); composer.focus(); } });
  recipeChip.addEventListener('click', async () => {
    let list = [];
    try { list = (await rpc.call(G('recipes/list'), {})).recipes || []; } catch (e) { toastError(e, 'Recipes'); return; }
    menu(recipeChip, list.length ? [{ header: 'Start from recipe' }, ...list.slice(0, 30).map((r) => ({ label: r.recipe.title || r.id, icon: 'recipe', hint: r.slash_command ? '/' + r.slash_command : '', onClick: () => { recipe = { id: r.id, title: r.recipe.title || r.id, prompt: r.recipe.prompt || '' }; if (recipe.prompt && !composer.value) composer.value = recipe.prompt; renderChips(); } })), '-', { label: 'Manage recipes…', icon: 'settings', onClick: () => router.go('/recipes') }]
      : [{ label: 'No recipes yet — create one', icon: 'plus', onClick: () => router.go('/recipes/edit/new') }]);
  });

  let sending = false;
  const composer = new Composer({
    placeholder: 'What should Goose work on?  (/ for commands, @ to mention)',
    getCwd: () => cwd,
    onSend: async (blocks) => {
      if (sending) return;
      if (!cwd) { const d = await pickFolder(); if (!d) { composer.value = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n'); return; } cwd = d; renderChips(); }
      sending = true; status.hidden = false;
      try {
        const chat = await createSession({ cwd, recipeId: recipe ? recipe.id : null });
        await applyChoice(chat);
        router.go('/chat/' + encodeURIComponent(chat.id));
        // Goose renders recipe parameters during session/new; swap an untouched template prompt for the rendered one.
        const rendered = chat.recipe && chat.recipe.prompt;
        if (recipe && rendered && recipe.prompt) {
          blocks = blocks.map((b) => (b.type === 'text' && b.text.trim() === recipe.prompt.trim() ? { ...b, text: rendered } : b));
        }
        chat.send(blocks);
      } catch (e) { toastError(e, 'Could not start chat'); composer.value = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n'); }
      finally { sending = false; status.hidden = true; }
    },
  });
  const status = h('div', { class: 'home-status', hidden: true }, spinner(14), 'Starting session…');
  composer.ta.rows = 3;

  const startEmpty = btn('Start without a message', async () => {
    if (!cwd) { const d = await pickFolder(); if (!d) return; cwd = d; renderChips(); }
    try {
      status.hidden = false;
      const chat = await createSession({ cwd, recipeId: recipe ? recipe.id : null });
      await applyChoice(chat);
      if (recipe && (chat.recipe && chat.recipe.prompt || recipe.prompt)) chat.prefill = (chat.recipe && chat.recipe.prompt) || recipe.prompt;
      router.go('/chat/' + encodeURIComponent(chat.id));
    } catch (e) { toastError(e, 'Could not start chat'); } finally { status.hidden = true; }
  }, { variant: 'ghost', size: 'sm' });

  const me = store.get('me');
  const name = me && me.user ? (me.user.displayName || me.user.username) : '';
  const hour = new Date().getHours();
  const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';

  const recents = h('div', { class: 'home-recent' });
  const renderRecents = () => {
    const folders = (pref('recentFolders') || []).slice(0, 6);
    const sess = [...sessionsState.items.values()].sort((a, b) => activityTime(b) - activityTime(a)).slice(0, 5);
    const needs = herdList().filter((a) => a.status === 'needs_you').slice(0, 3);
    recents.replaceChildren(
      needs.length ? h('div', { class: 'home-col' }, h('div', { class: 'home-col-head' }, h('span', { class: 'sdot s-needs_you' }), 'Needs you'), ...needs.map((a) => h('a', { class: 'home-link', href: '#/chat/' + encodeURIComponent(a.sessionId) }, h('span', null, a.title || 'Untitled'), h('span', { class: 'muted' }, a.ask ? a.ask.title || '' : '')))) : null,
      folders.length ? h('div', { class: 'home-col' }, h('div', { class: 'home-col-head' }, icon('folder', 13), 'Recent folders'), ...folders.map((f) => h('button', { type: 'button', class: 'home-link', title: f, onclick: () => { cwd = f; renderChips(); composer.focus(); } }, h('span', null, baseName(f)), h('span', { class: 'muted' }, shortPath(f, 32))))) : null,
      sess.length ? h('div', { class: 'home-col' }, h('div', { class: 'home-col-head' }, icon('chat', 13), 'Recent chats'), ...sess.map((s) => h('a', { class: 'home-link', href: '#/chat/' + encodeURIComponent(s.sessionId) }, h('span', null, sessionTitle(s)), h('span', { class: 'muted' }, relTime(s.updatedAt))))) : null);
  };

  const el = h('div', { class: 'view view-home' },
    h('div', { class: 'home-top' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' })),
    h('div', { class: 'home-center' },
      logo(52),
      h('h1', { class: 'home-title' }, greet + (name ? ', ' + name : '')),
      h('p', { class: 'home-sub' }, 'Start a conversation. Goose keeps working even if you close this tab.'),
      chatBlocked() ? banner('warn', chatBlocked()) : null,
      h('div', { class: 'home-composer' }, h('div', { class: 'home-chips' }, folderChip, recipeChip, h('span', { class: 'grow' }), startEmpty), optsRow, composer.el, status),
      recents));
  renderChips();
  renderOpts();
  loadNewChatOptions().then((d) => { optData = d; renderOpts(); }).catch(() => {});
  renderRecents();
  if (!cwd) defaultCwd().then((d) => { if (!cwd && d) { cwd = d; renderChips(); } });
  if (query.recipe) {
    rpc.call(G('recipes/list'), {}).then((r) => {
      const e = (r.recipes || []).find((x) => x.id === query.recipe);
      if (e) { recipe = { id: e.id, title: e.recipe.title || e.id, prompt: e.recipe.prompt || '' }; if (recipe.prompt) composer.value = recipe.prompt; renderChips(); }
    }).catch(() => {});
  }
  requestAnimationFrame(() => composer.focus());
  return { el, focus: () => composer.focus() };
}
