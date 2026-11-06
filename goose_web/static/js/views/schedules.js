// Schedules: list/create/pause/edit/run-now/delete, runs, running-job inspect/kill.
import { h, btn, iconBtn, pageHeader, input, select, field, toast, toastError, confirmDialog, modal, empty, skeleton, relTime, banner, errMsg, fmtDateTime, slug, menu, spinner, table, elapsed } from '../ui.js';
import { icon } from '../icons.js';
import { rpc, G } from '../rpc.js';
import { router } from '../router.js';
import { store, policy } from '../store.js';
import { cronEditor, describeCron } from '../cron.js';
import { setBaseTitle } from '../herd.js';

export function renderSchedules(ctx) {
  setBaseTitle('Schedules · Goose');
  const me = store.get('me') || {};
  const sched = me.scheduler || { enabled: true };
  const canMutate = policy('schedules') && sched.enabled !== false;
  let jobs = [];
  const listEl = h('div', { class: 'stack' }, skeleton(5));

  const draw = () => {
    if (!jobs.length) { listEl.replaceChildren(empty('schedule', 'No schedules', 'Run a recipe automatically on a cron schedule.', canMutate ? btn('New schedule', () => createDialog(), { icon: 'plus', variant: 'primary' }) : null)); return; }
    listEl.replaceChildren(...jobs.map((j) => {
      const more = iconBtn('more', 'More', () => menu(more, [
        { label: 'Run now', icon: 'play', disabled: !canMutate || j.currentlyRunning, onClick: () => runNow(j) },
        { label: 'Edit schedule…', icon: 'edit', disabled: !canMutate, onClick: () => editDialog(j) },
        { label: j.paused ? 'Resume' : 'Pause', icon: j.paused ? 'play' : 'pause', disabled: !canMutate, onClick: () => pause(j) },
        { label: 'Past runs…', icon: 'list', onClick: () => runsDialog(j) },
        j.currentlyRunning ? { label: 'Inspect running job', icon: 'eye', onClick: () => inspect(j) } : null,
        j.currentlyRunning ? { label: 'Kill running job', icon: 'stop', danger: true, disabled: !canMutate, onClick: () => kill(j) } : null,
        '-',
        { label: 'Delete…', icon: 'trash', danger: true, disabled: !canMutate, onClick: () => del(j) },
      ].filter(Boolean), { align: 'right' }));
      return h('article', { class: ['srow-card', j.paused ? 'paused' : '', j.currentlyRunning ? 'running' : ''] },
        h('div', { class: 'srow-card-icon' }, j.currentlyRunning ? h('span', { class: 'sdot s-working pulse' }) : icon(j.paused ? 'pause' : 'schedule', 16)),
        h('div', { class: 'srow-card-main' },
          h('div', { class: 'srow-card-title' }, j.id, j.paused ? h('span', { class: 'badge badge-warn' }, 'paused') : null, j.currentlyRunning ? h('span', { class: 'badge badge-ok' }, 'running ' + (j.jobStartTime ? elapsed(j.jobStartTime) : '')) : null),
          h('div', { class: 'muted small' }, describeCron(j.cron), ' · ', h('code', null, j.cron)),
          h('div', { class: 'muted small mono', title: j.source }, j.source)),
        h('div', { class: 'srow-card-side muted small' }, j.lastRun ? 'Last run ' + relTime(j.lastRun) : 'Never run'),
        h('div', { class: 'row' },
          j.currentlyRunning && j.currentSessionId ? btn('Open run', () => router.go('/chat/' + encodeURIComponent(j.currentSessionId)), { size: 'sm', icon: 'chat' }) : null,
          btn('Run now', () => runNow(j), { size: 'sm', icon: 'play', disabled: !canMutate || j.currentlyRunning }),
          more));
    }));
  };

  const runNow = async (j) => {
    toast('Started ' + j.id + '…', { timeout: 2500 });
    try {
      const r = await rpc.call(G('schedules/run-now'), { scheduleId: j.id });
      toast('Run ' + r.status, { kind: r.status === 'completed' ? 'success' : 'warn', actions: r.sessionId ? [{ label: 'Open', onClick: () => router.go('/chat/' + encodeURIComponent(r.sessionId)) }] : [] });
      load();
    } catch (e) { toastError(e, 'Run now'); }
    load();
  };
  const pause = async (j) => { try { await rpc.call(G(j.paused ? 'schedules/unpause' : 'schedules/pause'), { scheduleId: j.id }); load(); } catch (e) { toastError(e); } };
  const del = async (j) => {
    if (!(await confirmDialog({ title: 'Delete schedule “' + j.id + '”?', message: 'Future runs will stop. Past run sessions are kept.', confirmText: 'Delete', danger: true }))) return;
    try { await rpc.call(G('schedules/delete'), { scheduleId: j.id }); toast('Schedule deleted', { kind: 'success' }); load(); } catch (e) { toastError(e); }
  };
  const kill = async (j) => {
    if (!(await confirmDialog({ title: 'Kill running job?', message: 'The current run of ' + j.id + ' will be terminated.', confirmText: 'Kill', danger: true }))) return;
    try { const r = await rpc.call(G('schedules/running-job/kill'), { jobId: j.id }); toast(r.message || 'Killed', { kind: 'success' }); load(); } catch (e) { toastError(e); }
  };
  const inspect = async (j) => {
    try {
      const r = await rpc.call(G('schedules/running-job/inspect'), { jobId: j.id });
      let m;
      m = modal({ title: 'Running job: ' + j.id, size: 'sm', body: h('dl', { class: 'kv' },
        h('dt', null, 'Running'), h('dd', null, r.running ? 'yes' : 'no'),
        h('dt', null, 'Started'), h('dd', null, fmtDateTime(r.jobStartTime) || '–'),
        h('dt', null, 'Duration'), h('dd', null, r.runningDurationSeconds !== null && r.runningDurationSeconds !== undefined ? r.runningDurationSeconds + ' s' : '–'),
        h('dt', null, 'Session'), h('dd', null, r.sessionId ? h('a', { href: '#/chat/' + encodeURIComponent(r.sessionId), onclick: () => m.close() }, r.sessionId) : '–')),
      footer: [btn('Close', () => m.close())] });
    } catch (e) { toastError(e); }
  };
  const runsDialog = async (j) => {
    const body = h('div', null, spinner(16));
    let m;
    m = modal({ title: 'Runs of ' + j.id, size: 'lg', body, footer: [btn('Close', () => m.close())] });
    try {
      const r = await rpc.call(G('schedules/sessions/list'), { scheduleId: j.id, limit: 50 });
      body.replaceChildren(table([
        { label: 'Session', render: (s) => h('a', { href: '#/chat/' + encodeURIComponent(s.sessionId), onclick: () => m.close() }, s.title || s.sessionId) },
        { label: 'When', render: (s) => relTime(s.updatedAt) },
        { label: 'Messages', render: (s) => String((s._meta && s._meta.messageCount) ?? '') },
      ], r.sessions || [], { empty: 'No runs yet' }));
    } catch (e) { body.replaceChildren(banner('error', errMsg(e))); }
  };
  const editDialog = (j) => {
    const ed = cronEditor(j.cron);
    let m;
    m = modal({ title: 'Edit schedule: ' + j.id, size: 'md', body: ed.el, footer: [btn('Cancel', () => m.close()), btn('Save', async () => {
      if (!ed.valid()) { toast('Invalid cron', { kind: 'error' }); return; }
      try { await rpc.call(G('schedules/update'), { scheduleId: j.id, cron: ed.get() }); toast('Schedule updated', { kind: 'success' }); m.close(); load(); } catch (e) { toastError(e); }
    }, { variant: 'primary' })] });
  };
  const createDialog = async () => {
    let recipes = [];
    try { recipes = (await rpc.call(G('recipes/list'), {})).recipes || []; } catch (e) { toastError(e, 'Recipes'); return; }
    if (!recipes.length) { toast('Create a recipe first, then schedule it.', { actions: [{ label: 'New recipe', onClick: () => router.go('/recipes/edit/new') }] }); return; }
    const rs = select(recipes.map((r) => ({ value: r.id, label: r.recipe.title || r.id })), recipes[0].id);
    const idInp = input({ value: slug(recipes[0].recipe.title || recipes[0].id), class: 'inp mono' });
    let idTouched = false;
    idInp.addEventListener('input', () => { idTouched = true; });
    rs.addEventListener('change', () => { if (!idTouched) { const r = recipes.find((x) => x.id === rs.value); idInp.value = slug(r.recipe.title || r.id); } });
    const ed = cronEditor('0 0 9 * * *');
    let m;
    m = modal({ title: 'New schedule', size: 'md', body: h('div', { class: 'stack' }, field('Recipe', rs), field('Schedule ID', idInp, 'Unique name for this schedule'), ed.el),
      footer: [btn('Cancel', () => m.close()), btn('Create', async () => {
        const r = recipes.find((x) => x.id === rs.value);
        if (!idInp.value.trim()) { toast('ID required', { kind: 'error' }); return; }
        if (!ed.valid()) { toast('Invalid cron', { kind: 'error' }); return; }
        try { await rpc.call(G('schedules/create'), { id: idInp.value.trim(), recipe: r.recipe, cron: ed.get() }); toast('Schedule created', { kind: 'success' }); m.close(); load(); } catch (e) { toastError(e, 'Create schedule'); }
      }, { variant: 'primary' })] });
  };

  async function load() {
    try { jobs = ((await rpc.call(G('schedules/list'), {})).jobs || []).sort((a, b) => a.id.localeCompare(b.id)); draw(); }
    catch (e) { listEl.replaceChildren(banner('error', errMsg(e))); }
  }

  const el = h('div', { class: 'view view-page' },
    pageHeader(h('span', { class: 'row' }, iconBtn('menu', 'Toggle sidebar', () => ctx.toggleSidebar(), { class: 'only-mobile' }), 'Schedules'), 'Run recipes automatically.',
      [btn('Refresh', () => load(), { icon: 'refresh', size: 'sm' }), btn('New schedule', () => createDialog(), { icon: 'plus', variant: 'primary', disabled: !canMutate })]),
    h('div', { class: 'page-body' },
      sched.enabled === false ? banner('warn', 'The scheduler is not active in this Goose Web instance: ' + (sched.reason || 'disabled') + (sched.owner ? ' (owner: ' + sched.owner + ')' : '') + '. Schedules are read-only here.') : null,
      !policy('schedules') ? banner('info', 'Your policy does not allow managing schedules.') : null,
      listEl));
  load();
  const t = setInterval(() => { if (jobs.some((j) => j.currentlyRunning)) load(); }, 10000);
  return { el, destroy: () => clearInterval(t) };
}
