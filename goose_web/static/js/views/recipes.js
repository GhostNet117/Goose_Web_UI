// Recipes: list, editor (form + YAML), import/share/scan/schedule/slash command, run.
import { h, btn, iconBtn, pageHeader, input, textarea, select, field, tabs, toast, toastError, confirmDialog, promptDialog, modal, empty, skeleton, relTime, debounce, copyText, pickFile, downloadBlob, banner, errMsg, slug, menu, prettyJson, actionBtn } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { router } from '../router.js';
import { policy, store } from '../store.js';
import { cronEditor, describeCron } from '../cron.js';
import { setBaseTitle } from '../herd.js';
import { mdElement } from '../markdown.js';

let draft = null; // recipe imported but not saved yet

async function listRecipes() { return (await rpc.call(G('recipes/list'), {})).recipes || []; }

export function renderRecipes(ctx) {
  setBaseTitle('Recipes · Goose');
  const canEdit = policy('recipes_edit');
  let all = []; let q = '';
  const grid = h('div', { class: 'cgrid' }, skeleton(4));
  const search = input({ type: 'search', placeholder: 'Search recipes…', class: 'inp', 'aria-label': 'Search recipes' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); draw(); }, 150));

  const draw = () => {
    const items = all.filter((r) => !q || JSON.stringify([r.recipe.title, r.recipe.description, r.id, r.slash_command]).toLowerCase().includes(q));
    if (!items.length) {
      grid.replaceChildren(all.length ? empty('search', 'No matches', 'Try a different search.') : empty('recipe', 'No recipes yet', 'Recipes are reusable instructions, prompts and settings you can run, share and schedule.', canEdit ? btn('New recipe', () => router.go('/recipes/edit/new'), { icon: 'plus', variant: 'primary' }) : null, canEdit ? btn('Import', () => importDialog(), { icon: 'upload' }) : null));
      return;
    }
    grid.replaceChildren(...items.map((r) => {
      const more = iconBtn('more', 'More', (e) => { e.stopPropagation(); cardMenu(more, r); }, { size: 'sm' });
      return h('article', { class: 'ccard', tabindex: 0, onclick: () => router.go('/recipes/edit/' + encodeURIComponent(r.id)), onkeydown: (e) => { if (e.key === 'Enter') router.go('/recipes/edit/' + encodeURIComponent(r.id)); } },
        h('div', { class: 'ccard-head' }, h('span', { class: 'ccard-icon' }, icon('recipe', 16)), h('div', { class: 'ccard-title' }, r.recipe.title || r.id), more),
        h('div', { class: 'ccard-desc' }, r.recipe.description || ''),
        h('div', { class: 'ccard-tags' },
          r.slash_command ? h('span', { class: 'badge badge-accent' }, '/' + r.slash_command) : null,
          r.schedule_cron ? h('span', { class: 'badge', title: r.schedule_cron }, icon('schedule', 11), ' ', describeCron(r.schedule_cron)) : null,
          (r.recipe.parameters || []).length ? h('span', { class: 'badge' }, (r.recipe.parameters || []).length + ' params') : null),
        h('div', { class: 'ccard-foot' }, h('span', { class: 'muted small mono', title: r.file_path }, r.file_path ? r.file_path.split(/[\\/]/).pop() : ''), h('span', { class: 'muted small' }, relTime(r.last_modified)),
          btn('Run', (e) => { e.stopPropagation(); router.go('/new?recipe=' + encodeURIComponent(r.id)); }, { size: 'sm', icon: 'play', variant: 'primary' })));
    }));
  };
  const cardMenu = (anchor, r) => menu(anchor, [
    { label: 'Run in new chat', icon: 'play', onClick: () => router.go('/new?recipe=' + encodeURIComponent(r.id)) },
    { label: 'Edit', icon: 'edit', onClick: () => router.go('/recipes/edit/' + encodeURIComponent(r.id)) },
    { label: 'Copy share link', icon: 'share', onClick: () => share(r.recipe) },
    { label: 'Download YAML', icon: 'download', onClick: async () => { try { const y = await rpc.call(G('recipes/to-yaml'), { recipe: r.recipe }); downloadBlob(y.yaml, slug(r.recipe.title || r.id) + '.yaml', 'application/yaml'); } catch (e) { toastError(e); } } },
    { label: 'Schedule…', icon: 'schedule', hidden: !canEdit || !policy('schedules'), onClick: () => scheduleDialog(r, load) },
    { label: 'Slash command…', icon: 'slash', hidden: !canEdit, onClick: () => slashDialog(r, load) },
    '-',
    { label: 'Delete…', icon: 'trash', danger: true, hidden: !canEdit, onClick: async () => {
      if (!(await confirmDialog({ title: 'Delete recipe?', message: '“' + (r.recipe.title || r.id) + '” will be deleted from disk.', confirmText: 'Delete', danger: true }))) return;
      try { await rpc.call(G('recipes/delete'), { id: r.id }); toast('Recipe deleted', { kind: 'success' }); load(); } catch (e) { toastError(e, 'Delete'); }
    } },
  ], { align: 'right' });

  async function load() {
    try { all = await listRecipes(); draw(); } catch (e) { grid.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Recipes'), 'Reusable agent setups you can run, share and schedule.',
      [search, canEdit ? btn('Import', () => importDialog(), { icon: 'upload' }) : null, canEdit ? btn('New recipe', () => router.go('/recipes/edit/new'), { icon: 'plus', variant: 'primary' }) : null]),
    h('div', { class: 'page-body' }, !canEdit ? banner('info', 'Your policy does not allow editing recipes. You can still run them.') : null, grid));
  load();
  return { el };
}

export async function share(recipe) {
  try {
    const r = await rpc.call(G('recipes/encode'), { recipe });
    let m;
    const ta = textarea({ value: r.deeplink, rows: 4, readonly: true, class: 'inp mono' });
    m = modal({ title: 'Share recipe', size: 'md', body: h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Anyone with Goose can import this link (Desktop or Goose Web → Recipes → Import).'), ta),
      footer: [btn('Close', () => m.close()), btn('Copy link', () => copyText(r.deeplink, 'Link copied'), { variant: 'primary', icon: 'copy' })] });
    ta.select();
  } catch (e) { toastError(e, 'Share'); }
}

function scheduleDialog(r, after) {
  const ed = cronEditor(r.schedule_cron || '0 0 9 * * *');
  let m;
  m = modal({ title: 'Schedule “' + (r.recipe.title || r.id) + '”', size: 'md', body: h('div', { class: 'stack' }, ed.el),
    footer: [r.schedule_cron ? btn('Remove schedule', async () => { try { await rpc.call(G('recipes/schedule'), { id: r.id, cron_schedule: null }); toast('Schedule removed', { kind: 'success' }); m.close(); after && after(); } catch (e) { toastError(e); } }, { variant: 'danger-soft' }) : null,
      h('span', { class: 'grow' }), btn('Cancel', () => m.close()), btn('Save schedule', async () => {
        if (!ed.valid()) { toast('Invalid cron expression', { kind: 'error' }); return; }
        try { await rpc.call(G('recipes/schedule'), { id: r.id, cron_schedule: ed.get() }); toast('Scheduled', { kind: 'success' }); m.close(); after && after(); } catch (e) { toastError(e, 'Schedule'); }
      }, { variant: 'primary' })] });
}

async function slashDialog(r, after) {
  const v = await promptDialog({ title: 'Slash command', label: 'Command (without /). Leave empty to remove.', value: r.slash_command || '', confirmText: 'Save', validate: (x) => (x && !/^[\w-]+$/.test(x.trim()) ? 'Letters, numbers, - and _ only' : null) });
  if (v === null) return;
  try { await rpc.call(G('recipes/slash-command'), { id: r.id, slash_command: v.trim() || null }); toast('Slash command saved', { kind: 'success' }); after && after(); } catch (e) { toastError(e); }
}

export function importDialog() {
  let mode = 'yaml';
  const ta = textarea({ rows: 12, class: 'inp mono', placeholder: 'Paste recipe YAML or JSON here…' });
  const link = input({ placeholder: 'goose://recipe?config=…', class: 'inp mono' });
  const bodyEl = h('div');
  const err = h('div', { class: 'field-error' });
  const draw = () => {
    bodyEl.replaceChildren(tabs([{ id: 'yaml', label: 'Paste YAML', icon: 'code' }, { id: 'file', label: 'From file', icon: 'upload' }, { id: 'link', label: 'Deeplink', icon: 'link' }], mode, (v) => { mode = v; draw(); }),
      mode === 'yaml' ? ta : mode === 'link' ? field('Recipe deeplink', link) : h('div', { class: 'dropzone' }, btn('Choose .yaml / .json file…', async () => {
        const [f] = await pickFile({ accept: '.yaml,.yml,.json' }); if (!f) return; ta.value = await f.text(); mode = 'yaml'; draw();
      }, { icon: 'upload' })), err);
  };
  draw();
  let m;
  m = modal({ title: 'Import recipe', size: 'lg', body: bodyEl, footer: [btn('Cancel', () => m.close()), btn('Open in editor', async () => {
    err.textContent = '';
    try {
      let recipe;
      if (mode === 'link') recipe = (await rpc.call(G('recipes/decode'), { deeplink: link.value.trim() })).recipe;
      else recipe = (await rpc.call(G('recipes/parse'), { content: ta.value })).recipe;
      draft = recipe;
      m.close();
      router.go('/recipes/edit/draft');
    } catch (e) { err.textContent = errMsg(e); }
  }, { variant: 'primary' })] });
}

// ------------------------------------------------------------------ editor
export function renderRecipeEditor(ctx, id) {
  const canEdit = policy('recipes_edit');
  const isNew = id === 'new' || id === 'draft';
  let entry = null;
  let recipe = id === 'draft' && draft ? draft : (id === 'new' ? { version: '1.0.0', title: '', description: '', instructions: '', prompt: '' } : null);
  let tab = 'form';
  let yamlText = '';
  let dirty = false;
  const scanBadge = h('span');
  const titleEl = h('span', null, isNew ? 'New recipe' : 'Recipe');
  const body = h('div', { class: 'page-body recipe-ed' }, skeleton(8));
  setBaseTitle('Recipe · Goose');

  // ---- form fields ----
  const F = {};
  const mk = () => {
    F.title = input({ placeholder: 'Daily standup summary' });
    F.description = input({ placeholder: 'What this recipe does' });
    F.instructions = textarea({ rows: 8, placeholder: 'System-level instructions for the agent…', class: 'inp mono' });
    F.prompt = textarea({ rows: 5, placeholder: 'Initial user prompt (optional). Use {{ param }} for parameters.', class: 'inp mono' });
    F.version = input({ placeholder: '1.0.0' });
    F.provider = input({ placeholder: 'default' }); F.model = input({ placeholder: 'default' });
    F.temperature = input({ type: 'number', step: '0.1', min: '0', max: '2', placeholder: 'default' });
    F.max_turns = input({ type: 'number', min: '1', placeholder: 'default' });
    F.activities = textarea({ rows: 4, placeholder: 'One suggested activity per line' });
    F.extensions = textarea({ rows: 6, class: 'inp mono', placeholder: '[ ]' });
    F.sub_recipes = textarea({ rows: 5, class: 'inp mono', placeholder: '[ {"name": "...", "path": "..."} ]' });
    F.json_schema = textarea({ rows: 6, class: 'inp mono', placeholder: '{ "type": "object", "properties": { } }' });
    F.retry_max = input({ type: 'number', min: '0', placeholder: '0' });
    F.retry_timeout = input({ type: 'number', min: '0', placeholder: 'seconds' });
    F.retry_on_failure = input({ placeholder: 'Shell command to run on failure', class: 'inp mono' });
    F.retry_checks = textarea({ rows: 3, class: 'inp mono', placeholder: 'One shell success check per line' });
    F.author = input({ placeholder: 'you@example.com' });
    F.params = [];
    for (const k of Object.keys(F)) if (F[k] && F[k].addEventListener) F[k].addEventListener('input', () => { dirty = true; });
  };
  mk();
  const paramsBody = h('tbody');
  const paramRow = (p) => {
    const r = {
      key: input({ value: p.key || '', class: 'inp inp-sm mono', placeholder: 'key' }),
      input_type: select(['string', 'number', 'boolean', 'date', 'file', 'select'], p.input_type || 'string', { class: 'inp inp-sm' }),
      requirement: select(['required', 'optional', 'user_prompt'], p.requirement || 'required', { class: 'inp inp-sm' }),
      description: input({ value: p.description || '', class: 'inp inp-sm', placeholder: 'Shown to the user' }),
      default: input({ value: p.default ?? '', class: 'inp inp-sm', placeholder: 'default' }),
      options: input({ value: (p.options || []).join(', '), class: 'inp inp-sm', placeholder: 'a, b, c (select)' }),
    };
    const tr = h('tr', null, h('td', null, r.key), h('td', null, r.input_type), h('td', null, r.requirement), h('td', null, r.description), h('td', null, r.default), h('td', null, r.options),
      h('td', null, iconBtn('trash', 'Remove parameter', () => { F.params = F.params.filter((x) => x !== r); tr.remove(); dirty = true; }, { size: 'sm' })));
    r.tr = tr;
    F.params.push(r);
    paramsBody.appendChild(tr);
  };

  const fill = (rc) => {
    F.title.value = rc.title || ''; F.description.value = rc.description || '';
    F.instructions.value = rc.instructions || ''; F.prompt.value = rc.prompt || ''; F.version.value = rc.version || '1.0.0';
    const s = rc.settings || {};
    F.provider.value = s.goose_provider || ''; F.model.value = s.goose_model || '';
    F.temperature.value = s.temperature ?? ''; F.max_turns.value = s.max_turns ?? '';
    F.activities.value = (rc.activities || []).map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join('\n');
    F.extensions.value = rc.extensions && rc.extensions.length ? prettyJson(rc.extensions) : '';
    F.sub_recipes.value = rc.sub_recipes && rc.sub_recipes.length ? prettyJson(rc.sub_recipes) : '';
    F.json_schema.value = rc.response && rc.response.json_schema ? prettyJson(rc.response.json_schema) : '';
    const rt = rc.retry || {};
    F.retry_max.value = rt.max_retries ?? ''; F.retry_timeout.value = rt.timeout_seconds ?? ''; F.retry_on_failure.value = rt.on_failure || '';
    F.retry_checks.value = (rt.checks || []).map((c) => c.command).join('\n');
    F.author.value = (rc.author && rc.author.contact) || '';
    F.params = []; paramsBody.replaceChildren();
    (rc.parameters || []).forEach(paramRow);
    dirty = false;
  };
  const parseJsonField = (ta, name) => {
    const v = ta.value.trim(); if (!v) return undefined;
    try { return JSON.parse(v); } catch (e) { throw new Error(name + ' is not valid JSON: ' + e.message); }
  };
  const collect = () => {
    const rc = { version: F.version.value.trim() || '1.0.0', title: F.title.value.trim(), description: F.description.value.trim() };
    if (F.instructions.value.trim()) rc.instructions = F.instructions.value;
    if (F.prompt.value.trim()) rc.prompt = F.prompt.value;
    const settings = {};
    if (F.provider.value.trim()) settings.goose_provider = F.provider.value.trim();
    if (F.model.value.trim()) settings.goose_model = F.model.value.trim();
    if (F.temperature.value !== '') settings.temperature = Number(F.temperature.value);
    if (F.max_turns.value !== '') settings.max_turns = parseInt(F.max_turns.value, 10);
    if (Object.keys(settings).length) rc.settings = settings;
    const acts = F.activities.value.split('\n').map((x) => x.trim()).filter(Boolean);
    if (acts.length) rc.activities = acts;
    const ext = parseJsonField(F.extensions, 'Extensions'); if (ext) rc.extensions = ext;
    const sub = parseJsonField(F.sub_recipes, 'Sub-recipes'); if (sub) rc.sub_recipes = sub;
    const js = parseJsonField(F.json_schema, 'Response schema'); if (js) rc.response = { json_schema: js };
    if (F.retry_max.value !== '' && Number(F.retry_max.value) > 0) {
      rc.retry = { max_retries: parseInt(F.retry_max.value, 10), checks: F.retry_checks.value.split('\n').map((x) => x.trim()).filter(Boolean).map((command) => ({ type: 'shell', command })) };
      if (F.retry_timeout.value !== '') rc.retry.timeout_seconds = parseInt(F.retry_timeout.value, 10);
      if (F.retry_on_failure.value.trim()) rc.retry.on_failure = F.retry_on_failure.value.trim();
    }
    if (F.author.value.trim()) rc.author = { contact: F.author.value.trim() };
    const params = F.params.map((r) => {
      const p = { key: r.key.value.trim(), input_type: r.input_type.value, requirement: r.requirement.value, description: r.description.value.trim() };
      if (r.default.value !== '') p.default = r.default.value;
      if (r.input_type.value === 'select') p.options = r.options.value.split(',').map((x) => x.trim()).filter(Boolean);
      return p;
    }).filter((p) => p.key);
    if (params.length) rc.parameters = params;
    return rc;
  };
  const validate = (rc) => {
    if (!rc.title) return 'Title is required';
    if (!rc.description) return 'Description is required';
    if (!rc.instructions && !rc.prompt) return 'Provide instructions or a prompt';
    const keys = new Set();
    for (const p of rc.parameters || []) { if (keys.has(p.key)) return 'Duplicate parameter: ' + p.key; keys.add(p.key); }
    return null;
  };
  const current = async () => {
    if (tab === 'yaml') { const r = await rpc.call(G('recipes/parse'), { content: yamlEl.value }); return r.recipe; }
    return collect();
  };

  const yamlEl = textarea({ class: 'inp mono yaml-ed', rows: 30, spellcheck: 'false' });
  yamlEl.addEventListener('input', () => { dirty = true; });

  const switchTab = async (t) => {
    if (t === tab) return;
    try {
      if (t === 'yaml') { const rc = collect(); yamlEl.value = (await rpc.call(G('recipes/to-yaml'), { recipe: rc })).yaml; }
      else if (t === 'form' && tab === 'yaml') { const r = await rpc.call(G('recipes/parse'), { content: yamlEl.value }); const d = dirty; fill(r.recipe); dirty = d; }
      else if (t === 'preview') { /* collect below */ }
      tab = t; draw();
    } catch (e) { toastError(e, t === 'form' ? 'YAML has errors' : 'Convert'); }
  };

  const save = async () => {
    try {
      const rc = await current();
      const err = validate(rc);
      if (err) { toast(err, { kind: 'error' }); return; }
      const res = await rpc.call(G('recipes/save'), { recipe: rc, id: entry ? entry.id : null });
      toast('Recipe saved', { kind: 'success' });
      dirty = false; draft = null;
      if (!entry || res.id !== entry.id) router.go('/recipes/edit/' + encodeURIComponent(res.id), { replace: true });
      else { entry = { ...entry, recipe: rc, file_path: res.file_path }; draw(); }
    } catch (e) { toastError(e, 'Save'); }
  };
  const scan = async () => {
    try {
      const rc = await current();
      const r = await rpc.call(G('recipes/scan'), { recipe: rc });
      scanBadge.replaceChildren(r.has_security_warnings ? h('span', { class: 'badge badge-warn' }, icon('alert', 11), ' Security warnings') : h('span', { class: 'badge badge-ok' }, icon('check', 11), ' No warnings'));
      if (r.has_security_warnings) toast('This recipe contains content flagged by the security scanner (e.g. hidden unicode). Review it before running.', { kind: 'warn', timeout: 8000 });
    } catch (e) { toastError(e, 'Scan'); }
  };

  const extPicker = async () => {
    try {
      const r = await rpc.call(G('config/extensions/list'), {});
      menu(extBtn, (r.extensions || []).map((e) => ({ label: e.extension.display_name || e.extension.name, icon: 'ext', onClick: () => {
        let arr = []; try { arr = F.extensions.value.trim() ? JSON.parse(F.extensions.value) : []; } catch { arr = []; }
        if (!arr.some((x) => x.name === e.extension.name)) arr.push(e.extension);
        F.extensions.value = prettyJson(arr); dirty = true;
      } })));
    } catch (e) { toastError(e); }
  };
  const extBtn = btn('Add from my extensions', () => extPicker(), { size: 'sm', icon: 'plus' });

  const section = (title, ...kids) => h('section', { class: 'fsect' }, h('h3', null, title), ...kids);
  const formView = () => h('div', { class: 'recipe-form' },
    section('Basics', h('div', { class: 'grid2' }, field('Title *', F.title), field('Version', F.version)), field('Description *', F.description), field('Author contact', F.author)),
    section('Agent', field('Instructions', F.instructions, 'Added to the system prompt for sessions started from this recipe.'), field('Prompt', F.prompt, 'Pre-filled as the first message. Use {{ key }} to reference parameters.')),
    section('Parameters', h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl tbl-edit' }, h('thead', null, h('tr', null, ['Key', 'Type', 'Requirement', 'Description', 'Default', 'Options', ''].map((x) => h('th', null, x)))), paramsBody)),
      btn('Add parameter', () => { paramRow({}); dirty = true; }, { size: 'sm', icon: 'plus' })),
    section('Settings', h('div', { class: 'grid4' }, field('Provider', F.provider), field('Model', F.model), field('Temperature', F.temperature), field('Max turns', F.max_turns))),
    section('Extensions', field(null, F.extensions, 'JSON array of extension configs (same shape as config.yaml).'), extBtn),
    section('Activities', field(null, F.activities, 'Suggested starter activities shown to the user.')),
    section('Structured response', field('JSON schema', F.json_schema, 'Optional. Forces the final answer to match this schema.')),
    section('Sub-recipes', field(null, F.sub_recipes, 'JSON array of {name, path, values?, description?}.')),
    section('Retry', h('div', { class: 'grid3' }, field('Max retries', F.retry_max), field('Timeout (s)', F.retry_timeout), field('On failure', F.retry_on_failure)), field('Success checks', F.retry_checks)));

  const previewView = () => {
    let rc; try { rc = collect(); } catch (e) { return banner('error', errMsg(e)); }
    return h('div', { class: 'recipe-preview' }, h('h2', null, rc.title || 'Untitled'), h('p', { class: 'muted' }, rc.description || ''),
      rc.instructions ? h('div', null, h('h4', null, 'Instructions'), mdElement(rc.instructions)) : null,
      rc.prompt ? h('div', null, h('h4', null, 'Prompt'), h('pre', { class: 'json' }, rc.prompt)) : null,
      (rc.parameters || []).length ? h('div', null, h('h4', null, 'Parameters'), h('ul', null, rc.parameters.map((p) => h('li', null, h('code', null, p.key), ' — ', p.description || '', ' (', p.input_type, ', ', p.requirement, ')')))) : null);
  };

  const headActions = h('div', { class: 'page-actions' });
  const draw = () => {
    titleEl.textContent = entry ? (entry.recipe.title || entry.id) : (isNew ? (id === 'draft' ? 'Imported recipe' : 'New recipe') : 'Recipe');
    headActions.replaceChildren(scanBadge,
      btn('Scan', scan, { size: 'sm', icon: 'shield', title: 'Security scan' }),
      btn('Share', async () => { try { share(await current()); } catch (e) { toastError(e); } }, { size: 'sm', icon: 'share' }),
      entry ? btn('Run', () => router.go('/new?recipe=' + encodeURIComponent(entry.id)), { size: 'sm', icon: 'play' }) : null,
      entry && canEdit ? iconBtn('more', 'More', (ev) => menu(ev.currentTarget, [
        { label: 'Schedule…', icon: 'schedule', hidden: !policy('schedules'), onClick: () => scheduleDialog(entry, reload) },
        { label: 'Slash command…', icon: 'slash', onClick: () => slashDialog(entry, reload) },
        { label: 'Download YAML', icon: 'download', onClick: async () => { try { const y = await rpc.call(G('recipes/to-yaml'), { recipe: await current() }); downloadBlob(y.yaml, slug(F.title.value || 'recipe') + '.yaml', 'application/yaml'); } catch (e) { toastError(e); } } },
        '-',
        { label: 'Delete…', icon: 'trash', danger: true, onClick: async () => {
          if (!(await confirmDialog({ title: 'Delete recipe?', confirmText: 'Delete', danger: true, message: 'This deletes ' + (cleanPath(entry.file_path) || entry.id) + '.' }))) return;
          try { await rpc.call(G('recipes/delete'), { id: entry.id }); toast('Deleted', { kind: 'success' }); dirty = false; router.go('/recipes'); } catch (e) { toastError(e); }
        } },
      ], { align: 'right' })) : null,
      canEdit ? btn('Save', save, { variant: 'primary', icon: 'check', title: 'Save (Ctrl+S)' }) : null);
    body.replaceChildren(
      entry ? h('div', { class: 'recipe-meta muted small' }, icon('file', 12), ' ', cleanPath(entry.file_path), entry.schedule_cron ? h('span', { class: 'badge' }, icon('schedule', 11), ' ', describeCron(entry.schedule_cron)) : null, entry.slash_command ? h('span', { class: 'badge badge-accent' }, '/' + entry.slash_command) : null) : null,
      !canEdit ? banner('info', 'Read-only: your policy does not allow editing recipes.') : null,
      tabs([{ id: 'form', label: 'Form', icon: 'edit' }, { id: 'yaml', label: 'YAML', icon: 'code' }, { id: 'preview', label: 'Preview', icon: 'eye' }], tab, switchTab),
      tab === 'form' ? formView() : tab === 'yaml' ? yamlEl : previewView());
  };

  async function reload() {
    try {
      const list = await listRecipes();
      entry = list.find((x) => x.id === id) || null;
      if (!entry) { body.replaceChildren(empty('recipe', 'Recipe not found', 'It may have been deleted.', btn('Back to recipes', () => router.go('/recipes')))); return; }
      recipe = entry.recipe; fill(recipe); draw();
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    h('header', { class: 'page-head' }, h('div', { class: 'page-titles' }, h('div', { class: 'crumbs' }, h('a', { href: '#/recipes' }, 'Recipes'), ' / '), h('h1', null, titleEl)), headActions),
    body);
  if (recipe) { fill(recipe); draw(); } else reload();
  const onKey = (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); if (canEdit) save(); } };
  document.addEventListener('keydown', onKey);
  return {
    el,
    destroy() { document.removeEventListener('keydown', onKey); },
    canLeave: () => !dirty || !canEdit || window.confirm('Discard unsaved changes to this recipe?'),
  };
}

export { store, actionBtn };

// Goose returns Windows extended-length paths (\\?\C:\...); show them plainly.
function cleanPath(p) {
  if (!p) return '';
  const s = String(p);
  if (s.startsWith('\\\\?\\UNC\\')) return '\\\\' + s.slice(8);
  if (s.startsWith('\\\\?\\')) return s.slice(4);
  return s;
}
