// Skills: sources/list (type skill) grouped global/project; view, create/edit/delete, export/import.
import { h, btn, iconBtn, pageHeader, input, textarea, field, tabs, toast, toastError, confirmDialog, modal, empty, skeleton, debounce, pickFile, downloadBlob, banner, errMsg, shortPath } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { policy } from '../store.js';
import { mdElement } from '../markdown.js';
import { setBaseTitle } from '../herd.js';

export function renderSkills(ctx) {
  setBaseTitle('Skills · Goose');
  const canEdit = policy('skills_edit');
  let all = []; let q = ''; let sel = null;
  const listEl = h('div', { class: 'split-list' }, skeleton(6));
  const detail = h('div', { class: 'split-detail' });
  const search = input({ type: 'search', placeholder: 'Search skills…', 'aria-label': 'Search skills' });
  search.addEventListener('input', debounce(() => { q = search.value.toLowerCase(); drawList(); }, 120));

  const drawList = () => {
    const items = all.filter((s) => !q || (s.name + ' ' + s.description).toLowerCase().includes(q));
    const groups = [
      { label: 'Global', items: items.filter((s) => s.global && s.type === 'skill') },
      { label: 'Project', items: items.filter((s) => !s.global && s.type === 'skill') },
      { label: 'Built-in', items: items.filter((s) => s.type === 'builtinSkill') },
    ].filter((g) => g.items.length);
    if (!groups.length) {
      listEl.replaceChildren(all.length ? empty('search', 'No matches') : empty('skill', 'No skills yet', 'Skills are markdown instructions Goose loads on demand.', canEdit ? btn('New skill', () => editDialog(null), { icon: 'plus', variant: 'primary' }) : null));
      return;
    }
    listEl.replaceChildren(...groups.map((g) => h('div', { class: 'lgroup' }, h('div', { class: 'lgroup-head' }, g.label, h('span', { class: 'count' }, String(g.items.length))),
      ...g.items.map((s) => h('button', { type: 'button', class: ['litem', sel && sel.path === s.path ? 'active' : ''], onclick: () => { sel = s; drawList(); drawDetail(); } },
        icon('skill', 14), h('div', { class: 'litem-main' }, h('div', { class: 'litem-title' }, s.name, s.writable === false ? h('span', { class: 'badge' }, 'read-only') : null), h('div', { class: 'litem-sub' }, s.description || '')))))));
  };
  const drawDetail = () => {
    if (!sel) { detail.replaceChildren(empty('skill', 'Select a skill', 'Choose a skill on the left to view it.')); return; }
    const s = sel;
    const writable = canEdit && s.writable !== false && s.type === 'skill';
    detail.replaceChildren(
      h('div', { class: 'detail-head' }, h('div', null, h('h2', null, s.name), h('div', { class: 'muted' }, s.description || ''), h('div', { class: 'muted small mono', title: s.path }, shortPath(s.path.replace(/^\\\\\?\\/, ''), 70))),
        h('div', { class: 'row' },
          s.writable === false ? h('span', { class: 'badge' }, icon('lock', 11), ' read-only') : null,
          h('span', { class: 'badge' }, s.global ? 'global' : 'project'),
          btn('Export', async () => { try { const r = await rpc.call(G('sources/export'), { type: s.type, path: s.path }); downloadBlob(r.json, r.filename || (s.name + '.json'), 'application/json'); } catch (e) { toastError(e, 'Export'); } }, { size: 'sm', icon: 'download' }),
          writable ? btn('Edit', () => editDialog(s), { size: 'sm', icon: 'edit' }) : null,
          writable ? iconBtn('trash', 'Delete', async () => {
            if (!(await confirmDialog({ title: 'Delete skill “' + s.name + '”?', message: 'The skill folder will be removed.', confirmText: 'Delete', danger: true }))) return;
            try { await rpc.call(G('sources/delete'), { type: s.type, path: s.path }); toast('Skill deleted', { kind: 'success' }); sel = null; load(); } catch (e) { toastError(e, 'Delete'); }
          }, { variant: 'danger-soft' }) : null)),
      (s.supportingFiles || []).length ? h('div', { class: 'muted small' }, 'Supporting files: ', s.supportingFiles.join(', ')) : null,
      h('div', { class: 'detail-body' }, mdElement(s.content || '*No content*')));
  };

  const editDialog = (s) => {
    const name = input({ value: s ? s.name : '', placeholder: 'my-skill', disabled: !!s && false });
    const desc = input({ value: s ? s.description : '', placeholder: 'When should Goose use this skill?' });
    const content = textarea({ value: s ? s.content : '# My skill\n\nInstructions…', rows: 18, class: 'inp mono' });
    const prev = h('div', { class: 'md-preview' });
    let t = 'edit';
    const pane = h('div');
    const drawPane = () => {
      if (t === 'preview') prev.replaceChildren(mdElement(content.value));
      pane.replaceChildren(tabs([{ id: 'edit', label: 'Write' }, { id: 'preview', label: 'Preview' }], t, (v) => { t = v; drawPane(); }), t === 'edit' ? content : prev);
    };
    drawPane();
    let m;
    m = modal({ title: s ? 'Edit skill' : 'New skill', size: 'xl',
      body: h('div', { class: 'stack' }, h('div', { class: 'grid2' }, field('Name', name, 'Lowercase, dashes allowed'), field('Description', desc)), pane),
      footer: [btn('Cancel', () => m.close()), btn(s ? 'Save' : 'Create', async () => {
        if (!name.value.trim() || !desc.value.trim()) { toast('Name and description are required', { kind: 'error' }); return; }
        try {
          if (s) await rpc.call(G('sources/update'), { type: s.type, path: s.path, name: name.value.trim(), description: desc.value.trim(), content: content.value });
          else await rpc.call(G('sources/create'), { type: 'skill', name: name.value.trim(), description: desc.value.trim(), content: content.value, target: { scope: 'global' } });
          toast(s ? 'Skill saved' : 'Skill created', { kind: 'success' }); m.close(); load();
        } catch (e) { toastError(e, 'Save skill'); }
      }, { variant: 'primary' })] });
  };

  const importSkills = async () => {
    const [f] = await pickFile({ accept: '.json' });
    if (!f) return;
    try { const r = await rpc.call(G('sources/import'), { data: await f.text(), target: { scope: 'global' } }); toast('Imported ' + (r.sources || []).length + ' skill(s)', { kind: 'success' }); load(); } catch (e) { toastError(e, 'Import'); }
  };

  async function load() {
    try {
      const r = await rpc.call(G('sources/list'), { type: 'skill', includeProjectSources: true });
      all = (r.sources || []).sort((a, b) => a.name.localeCompare(b.name));
      if (sel) sel = all.find((x) => x.path === sel.path) || null;
      if (!sel && all.length && window.innerWidth > 800) sel = all[0];
      drawList(); drawDetail();
    } catch (e) { listEl.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Skills'), 'Markdown instructions Goose loads on demand.',
      [search, canEdit ? btn('Import', importSkills, { icon: 'upload' }) : null, canEdit ? btn('New skill', () => editDialog(null), { icon: 'plus', variant: 'primary' }) : null]),
    h('div', { class: 'page-body' }, !canEdit ? banner('info', 'Read-only: your policy does not allow editing skills.') : null, h('div', { class: 'split' }, listEl, detail)));
  drawDetail();
  load();
  return { el };
}
